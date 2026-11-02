"""beenuar/AiSOC as the SOC platform around the verifiable core.

AiSOC (https://github.com/beenuar/AiSOC, MIT) is an open-source autonomous SOC
with alert ingest, case management, an agentic investigation runtime, an
approval inbox and exportable *evidence bundles*. This module bridges it to
the paper's design in three places, each of which is deliberately *thin*:

1. **Alert submission** — a :class:`~aisoc.soc.CaseResult` is pushed to AiSOC
   (``POST /api/v1/alerts/submit``, or the streaming ``/v1/ingest/batch``)
   using only the generic field names AiSOC's normalizer understands
   (``time``, ``severity``, ``title``, ``description``, ``host``, ``src_ip``,
   ``external_id``, ``mitre_techniques``, ``tags``). The ledger head and
   witness root are embedded so an AiSOC analyst can check the case against
   the ledger offline.
2. **Approval bridge** — when the policy engine *reserves* an action for a
   human, the request is written to AiSOC's approval inbox
   (``POST /api/v1/approvals``) and the bridge waits for a decision. AiSOC
   approvals are **not** signed by the approving human's own key, so the
   bridge turns the decision into a :class:`~aisoc.owp.objects.HumanApproval`
   signed with the bridge's approver-role key and records the AiSOC approval
   id / user id / timestamp in ``external_ref``. Non-repudiation then rests on
   the bridge key *plus* AiSOC's audit log — weaker than the paper's native
   per-human key, and said so in :mod:`docs/INTEGRATION.md`.
3. **Evidence-bundle anchoring** — AiSOC's investigation bundle is protected
   by ``sha256(payload)`` and an **HMAC-SHA256** over the canonical payload.
   HMAC gives tamper-evidence against anyone without the key, but not
   non-repudiation (whoever can verify can also forge). This adapter verifies
   the bundle and commits its digests to the hash-chained, Ed25519-signed,
   externally witnessed ledger, which is the upgrade the paper argues for.

No AiSOC code is vendored; the wire formats were taken from AiSOC's OpenAPI
document and ``evidence_bundle.py`` (v21.x). Endpoint paths are configurable
because the API port is deployment-specific.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Callable, Dict, List, Optional, Protocol, Tuple

from ..canonical import digest
from ..crypto import Clock, Ed25519Signer, parse_iso, utc_iso
from ..idps import FlowRecord
from ..owp.objects import (
    ActionRequest,
    ExternalEvidenceRef,
    HumanApproval,
    PolicyDecision,
    Signed,
    WorkOrder,
    new_id,
)
from ..sandbox.authorization import ApprovalView
from ..soc import AISOC, CaseResult

AISOC_SYSTEM = "aisoc"
AISOC_BUNDLE_SCHEMA = "1.0"
IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")

SEVERITY_BY_STATUS = {
    "KNOWN_SUSPICIOUS": "high",
    "SUSPECTED_UNKNOWN": "high",
    "MODEL_CONFLICT": "medium",
    "UNKNOWN": "medium",
    "LOW_RISK_OBSERVE": "low",
    "INSUFFICIENT_EVIDENCE": "low",
}


class AiSOCError(Exception):
    pass


class AiSOCBundleError(AiSOCError):
    pass


# ----------------------------------------------------------------------------- transport
class HttpClient(Protocol):
    def request(self, method: str, url: str, headers: Dict[str, str], body: Optional[bytes]) -> Tuple[int, Dict[str, Any]]:
        """Return (status_code, parsed_json_or_{})."""


class UrllibHttpClient:
    def __init__(self, timeout_s: float = 10.0) -> None:
        self.timeout_s = timeout_s

    def request(self, method: str, url: str, headers: Dict[str, str], body: Optional[bytes]) -> Tuple[int, Dict[str, Any]]:
        import urllib.error
        import urllib.request

        req = urllib.request.Request(url, data=body, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:  # noqa: S310 (operator-configured URL)
                raw = resp.read()
                return resp.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                return exc.code, (json.loads(raw) if raw else {})
            except ValueError:
                return exc.code, {"detail": raw.decode("utf-8", "replace")}


@dataclass
class AiSOCConfig:
    base_url: str = "http://localhost:8000"
    token: str = ""
    ingest_url: Optional[str] = None  # e.g. http://localhost:8081/v1/ingest/batch
    ingest_token: Optional[str] = None
    connector_id: str = "owp-soc"
    connector_type: str = "custom"
    source_format: str = "generic_json"
    approval_poll_s: float = 2.0
    approval_timeout_s: float = 900.0
    approval_ttl_s: int = 900

    def headers(self, token: Optional[str] = None, idempotency_key: Optional[str] = None) -> Dict[str, str]:
        h = {"Content-Type": "application/json", "Accept": "application/json"}
        tok = token if token is not None else self.token
        if tok:
            h["Authorization"] = f"Bearer {tok}"
        if idempotency_key:
            if not IDEMPOTENCY_KEY_RE.match(idempotency_key):
                raise AiSOCError("Idempotency-Key must be 8-128 chars of [A-Za-z0-9._:-]")
            h["Idempotency-Key"] = idempotency_key
        return h


class AiSOCClient:
    def __init__(self, config: AiSOCConfig, http: Optional[HttpClient] = None) -> None:
        self.config = config
        self.http = http or UrllibHttpClient()

    def _call(self, method: str, path_or_url: str, body: Optional[Dict[str, Any]] = None, **hdr: Any) -> Dict[str, Any]:
        url = path_or_url if path_or_url.startswith("http") else f"{self.config.base_url.rstrip('/')}{path_or_url}"
        data = json.dumps(body, sort_keys=True).encode("utf-8") if body is not None else None
        status, payload = self.http.request(method, url, self.config.headers(**hdr), data)
        if status >= 400:
            raise AiSOCError(f"{method} {url} -> {status}: {payload.get('detail', payload)}")
        return payload

    def submit_alert(self, events: List[Dict[str, Any]], title: str, description: str, severity: str,
                     tags: Optional[List[str]] = None, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        body = {
            "events": events,
            "connector_id": self.config.connector_id,
            "connector_type": self.config.connector_type,
            "source_format": self.config.source_format,
            "title": title,
            "description": description,
            "severity": severity,
            "tags": tags or [],
        }
        return self._call("POST", "/api/v1/alerts/submit", body, idempotency_key=idempotency_key)

    def ingest_batch(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not self.config.ingest_url:
            raise AiSOCError("ingest_url not configured")
        body = {"connector_id": self.config.connector_id, "connector_type": self.config.connector_type, "events": events}
        return self._call("POST", self.config.ingest_url, body, token=self.config.ingest_token or self.config.token)

    def create_approval(self, title: str, summary: str, risk_level: str, action: Dict[str, Any],
                        case_id: Optional[str] = None, expires_at: Optional[str] = None) -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "requested_by": "agent",
            "title": title[:200],
            "summary": summary,
            "risk_level": risk_level,
            "action": action,
        }
        if case_id:
            body["case_id"] = case_id[:200]
        if expires_at:
            body["expires_at"] = expires_at
        return self._call("POST", "/api/v1/approvals", body)

    def get_approval(self, approval_id: str) -> Dict[str, Any]:
        return self._call("GET", f"/api/v1/approvals/{approval_id}")

    def decide_approval(self, approval_id: str, approve: bool, comment: str = "") -> Dict[str, Any]:
        return self._call("POST", f"/api/v1/approvals/{approval_id}/decide",
                          {"decision": "approve" if approve else "deny", "comment": comment})

    def get_bundle(self, run_id: str) -> Dict[str, Any]:
        return self._call("GET", f"/api/v1/investigations/{run_id}/bundle")


# ----------------------------------------------------------------------------- alert mapping
def case_to_event(result: CaseResult, flow: FlowRecord, ledger_head: Optional[str] = None,
                  witness_root: Optional[str] = None, techniques: Optional[List[str]] = None) -> Dict[str, Any]:
    """One AiSOC-normalizable event per case. Only digests and structured fields; no raw log text."""
    d = result.decision
    status = d.status.value
    techniques = [t for t in (techniques or []) if isinstance(t, str)]
    ev = {
        "time": flow.observed_at or None,
        "severity": SEVERITY_BY_STATUS.get(status, "medium"),
        "title": f"[OWP-SOC] {status} on {flow.src_host}",
        "description": "; ".join(d.reasons)[:2000],
        "host": flow.src_host,
        "src_ip": flow.src_host,
        "dest_ip": flow.dst_ip,
        "dest_port": flow.dst_port,
        "external_id": result.case_id,
        "mitre_techniques": techniques,
        "tags": ["owp-soc", status.lower(), f"tenant:{flow.tenant}"] + (["requires-human-review"] if d.requires_human_review else []),
        "aisoc_owp": {
            "case_id": result.case_id,
            "flow_id": result.flow_id,
            "model_version": d.model_version,
            "known_label": d.known_label,
            "known_score": d.known_score,
            "anomaly_score": d.anomaly_score,
            "anomaly_threshold": d.anomaly_threshold,
            "requires_human_review": d.requires_human_review,
            "verification_status": result.verification_status,
            "acceptance_status": result.acceptance_status,
            "egress_dropped": list(result.egress_dropped),
            "requests": [r.__dict__ for r in result.requests],
            "ledger_head": ledger_head,
            "witness_root": witness_root,
        },
    }
    return {k: v for k, v in ev.items() if v is not None}


def idempotency_key_for(result: CaseResult) -> str:
    return f"owp:{result.case_id}"[:128]


def ledger_anchors(soc: AISOC) -> Tuple[Optional[str], Optional[str]]:
    head = soc.ledger.entries[-1].entry_hash if soc.ledger.entries else None
    cps = soc.witness.checkpoints()
    root = cps[-1]["payload"]["merkle_root"] if cps else None
    return head, root


def push_case(client: AiSOCClient, soc: AISOC, result: CaseResult, flow: FlowRecord, streaming: bool = False) -> Dict[str, Any]:
    head, root = ledger_anchors(soc)
    event = case_to_event(result, flow, head, root)
    if streaming:
        return client.ingest_batch([event])
    return client.submit_alert([event], event["title"], event["description"], event["severity"], event["tags"],
                               idempotency_key=idempotency_key_for(result))


# ----------------------------------------------------------------------------- approval bridge
APPROVED = {"approve", "approved"}
DENIED = {"deny", "denied", "rejected", "reject"}
RISK_BY_ACTION = {"egress_connect": "critical", "block_host": "high", "add_watchlist": "low", "tag_case": "low"}


class AiSOCApprovalBridge:
    """Implements :data:`aisoc.soc.ApprovalProvider` on top of AiSOC's approval inbox.

    Fail-closed: a timeout, an expired approval, an unknown status or a transport
    error becomes a signed *reject* so the authorization signer never sees an
    unsigned or ambiguous decision.
    """

    def __init__(self, client: AiSOCClient, signer: Ed25519Signer, clock: Clock, approver_prefix: str = "aisoc",
                 sleep: Callable[[float], None] = time.sleep, wait_clock: Callable[[], float] = time.monotonic) -> None:
        self.client = client
        self.signer = signer
        self.clock = clock
        self.approver_prefix = approver_prefix
        self._sleep = sleep
        self._wait_clock = wait_clock
        self.created: List[Dict[str, Any]] = []

    def _sign(self, req: ActionRequest, order: WorkOrder, pd: PolicyDecision, approve: bool, approver_id: str,
              rationale: str, external_ref: Dict[str, Any], expires_at: str) -> Signed:
        now = self.clock.now()
        approval = HumanApproval(
            approval_id=new_id("hap"),
            case_id=req.case_id,
            request_digest=req.digest(),
            evidence_digest=order.evidence_digest,
            params_digest=digest(req.params),
            policy_decision_digest=pd.digest(),
            decision="approve" if approve else "reject",
            approver_id=approver_id,
            rationale=rationale,
            issued_at=utc_iso(now),
            expires_at=expires_at,
            external_ref=external_ref,
        )
        payload = approval.to_dict()
        return Signed(payload=payload, signatures=[self.signer.sign_payload(payload)])

    def __call__(self, view: ApprovalView, req: ActionRequest, order: WorkOrder, pd: PolicyDecision) -> Signed:
        cfg = self.client.config
        now = self.clock.now()
        local_exp = now + timedelta(seconds=cfg.approval_ttl_s)
        summary = json.dumps(view.to_dict(), sort_keys=True, default=str)
        action = {
            "type": req.action,
            "resource": req.resource,
            "destination": req.destination,
            "params": req.params,
            "request_digest": req.digest(),
            "policy_decision_digest": pd.digest(),
            "evidence_digest": order.evidence_digest,
            "case_id": req.case_id,
        }
        ext: Dict[str, Any] = {"system": AISOC_SYSTEM}
        try:
            created = self.client.create_approval(
                title=f"{req.action} {req.resource} (case {req.case_id})",
                summary=summary,
                risk_level=RISK_BY_ACTION.get(req.action, "medium"),
                action=action,
                case_id=req.case_id,
                expires_at=utc_iso(local_exp),
            )
        except AiSOCError as exc:
            return self._sign(req, order, pd, False, f"{self.approver_prefix}:bridge", f"approval inbox unavailable: {exc}", ext, utc_iso(local_exp))
        self.created.append(created)
        approval_id = str(created.get("id", ""))
        ext["approval_id"] = approval_id
        deadline = self._wait_clock() + cfg.approval_timeout_s
        record = created
        while True:
            status = str(record.get("status", "")).lower()
            if status in APPROVED or status in DENIED:
                break
            if self._wait_clock() >= deadline:
                return self._sign(req, order, pd, False, f"{self.approver_prefix}:bridge", "no decision before timeout", ext, utc_iso(local_exp))
            self._sleep(cfg.approval_poll_s)
            try:
                record = self.client.get_approval(approval_id)
            except AiSOCError as exc:
                return self._sign(req, order, pd, False, f"{self.approver_prefix}:bridge", f"approval poll failed: {exc}", ext, utc_iso(local_exp))

        ext.update({"status": record.get("status"), "decided_by_id": record.get("decided_by_id"),
                    "decided_at": record.get("decided_at"), "comment": record.get("decision_comment")})
        # The decision must be about *this* request: AiSOC echoes the action object back.
        echoed = record.get("action") or {}
        if echoed.get("request_digest") not in (None, req.digest()):
            return self._sign(req, order, pd, False, f"{self.approver_prefix}:bridge", "approval record is about a different request", ext, utc_iso(local_exp))
        exp = local_exp
        if record.get("expires_at"):
            try:
                exp = min(exp, parse_iso(str(record["expires_at"])))
            except ValueError:
                pass
        if exp <= self.clock.now():
            return self._sign(req, order, pd, False, f"{self.approver_prefix}:bridge", "approval expired before use", ext, utc_iso(exp))
        approve = status in APPROVED
        who = record.get("decided_by_id") or "unknown"
        return self._sign(req, order, pd, approve, f"{self.approver_prefix}:{who}",
                          str(record.get("decision_comment") or f"decided in AiSOC inbox ({status})"), ext, utc_iso(exp))


# ----------------------------------------------------------------------------- evidence bundles
def aisoc_canonical_bytes(payload: Dict[str, Any]) -> bytes:
    """AiSOC's canonical form (json.dumps sort_keys, compact separators, ensure_ascii=False)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def aisoc_sign_envelope(payload: Dict[str, Any], signing_key: str) -> Dict[str, Any]:
    """Build an AiSOC-compatible ``{"payload","integrity"}`` bundle (used to create test fixtures)."""
    canonical = aisoc_canonical_bytes(payload)
    sha = hashlib.sha256(canonical).hexdigest()
    sig = hmac.new(signing_key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
    return {
        "payload": payload,
        "integrity": {
            "algorithm": "HMAC-SHA256",
            "algorithm_note": "HMAC gives tamper-evidence to key holders only; it is not a non-repudiable signature.",
            "payload_sha256": sha,
            "signature": sig,
            "attestation_list": [{
                "fingerprint": {"algorithm": "SHA-256", "algorithm_id": 3, "value": sha},
                "signatures": [{"algorithm": "HMAC-SHA256", "algorithm_id": 99}],
            }],
        },
    }


@dataclass
class BundleCheck:
    run_id: str
    case_id: Optional[str]
    payload_sha256: str
    sha256_ok: bool
    hmac_checked: bool
    hmac_ok: Optional[bool]
    problems: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.sha256_ok and (self.hmac_ok is not False) and not self.problems

    def to_dict(self) -> Dict[str, Any]:
        return {**self.__dict__, "ok": self.ok}


def verify_aisoc_bundle(bundle: Dict[str, Any], signing_key: Optional[str] = None) -> BundleCheck:
    """Re-derive AiSOC's own integrity fields. HMAC is only checked when a key is supplied."""
    if not isinstance(bundle, dict) or "payload" not in bundle or "integrity" not in bundle:
        raise AiSOCBundleError("not an AiSOC bundle: expected top-level 'payload' and 'integrity'")
    payload, integrity = bundle["payload"], bundle["integrity"]
    if not isinstance(payload, dict) or not isinstance(integrity, dict):
        raise AiSOCBundleError("payload/integrity must be objects")
    problems: List[str] = []
    if str(payload.get("bundle_schema_version", "")) != AISOC_BUNDLE_SCHEMA:
        problems.append(f"unsupported bundle_schema_version {payload.get('bundle_schema_version')!r}")
    run = payload.get("run") or {}
    run_id = str(run.get("id", "")) if isinstance(run, dict) else ""
    if not run_id:
        problems.append("payload.run.id missing")
    canonical = aisoc_canonical_bytes(payload)
    sha = hashlib.sha256(canonical).hexdigest()
    claimed = str(integrity.get("payload_sha256", ""))
    sha_ok = hmac.compare_digest(sha, claimed)
    if not sha_ok:
        problems.append("payload_sha256 does not match the payload")
    hmac_ok: Optional[bool] = None
    if signing_key is not None:
        if str(integrity.get("algorithm", "")).upper() != "HMAC-SHA256":
            problems.append(f"unexpected integrity algorithm {integrity.get('algorithm')!r}")
            hmac_ok = False
        else:
            expected = hmac.new(signing_key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
            hmac_ok = hmac.compare_digest(expected, str(integrity.get("signature", "")))
            if not hmac_ok:
                problems.append("HMAC-SHA256 signature does not verify under the supplied key")
    case_id = run.get("case_id") if isinstance(run, dict) else None
    return BundleCheck(run_id, str(case_id) if case_id else None, sha, sha_ok, signing_key is not None, hmac_ok, problems)


def anchor_aisoc_bundle(soc: AISOC, bundle: Dict[str, Any], case_id: str, signing_key: Optional[str] = None) -> ExternalEvidenceRef:
    """Verify an AiSOC bundle, then commit its digests to the OWP ledger. Refuses on any problem."""
    check = verify_aisoc_bundle(bundle, signing_key)
    if not check.ok:
        raise AiSOCBundleError("; ".join(check.problems) or "bundle failed integrity check")
    ref = ExternalEvidenceRef(
        ref_id=new_id("xref"),
        case_id=case_id,
        system=AISOC_SYSTEM,
        kind="investigation_bundle",
        external_id=check.run_id,
        payload_sha256=check.payload_sha256,
        artefact_digest=digest(bundle),
        integrity_checked={"payload_sha256": True, "hmac_sha256": bool(check.hmac_ok), "bundle_schema_version": AISOC_BUNDLE_SCHEMA},
        anchored_at=soc.clock.iso(),
    )
    soc.anchor_external_evidence(ref)
    return ref


# ----------------------------------------------------------------------------- test double
class FakeAiSOCServer:
    """In-memory stand-in for the AiSOC API, driven through :class:`HttpClient`.

    ``decide(approval_id, approve)`` or an ``auto_decide`` callback plays the analyst.
    """

    def __init__(self, auto_decide: Optional[Callable[[Dict[str, Any]], Optional[bool]]] = None, token: str = "t") -> None:
        self.auto_decide = auto_decide
        self.token = token
        self.alerts: List[Dict[str, Any]] = []
        self.ingested: List[Dict[str, Any]] = []
        self.approvals: Dict[str, Dict[str, Any]] = {}
        self.idempotency: Dict[str, Dict[str, Any]] = {}
        self.calls: List[Tuple[str, str]] = []
        self._n = 0

    def _id(self, prefix: str) -> str:
        self._n += 1
        return f"{prefix}-{self._n:04d}"

    def decide(self, approval_id: str, approve: bool, user_id: str = "user-7", comment: str = "ok") -> Dict[str, Any]:
        rec = self.approvals[approval_id]
        if rec["status"] != "pending":
            raise AiSOCError("409 already decided")
        rec.update({"status": "approved" if approve else "denied", "decided_by_id": user_id,
                    "decided_at": "2026-11-01T00:00:00Z", "decision_comment": comment})
        return rec

    def request(self, method: str, url: str, headers: Dict[str, str], body: Optional[bytes]) -> Tuple[int, Dict[str, Any]]:
        self.calls.append((method, url))
        if headers.get("Authorization") != f"Bearer {self.token}":
            return 401, {"detail": "unauthorized"}
        data = json.loads(body) if body else {}
        path = url.split("//", 1)[-1].split("/", 1)[1] if "//" in url else url
        path = "/" + path
        if method == "POST" and path == "/api/v1/alerts/submit":
            key = headers.get("Idempotency-Key")
            if key and key in self.idempotency:
                return 200, self.idempotency[key]
            if not data.get("events"):
                return 422, {"detail": "events required"}
            resp = {"id": self._id("alert"), "tenant_id": "tenant-1", "title": data.get("title"), "severity": data.get("severity"),
                    "status": "new", "case_id": self._id("case"), "mitre_techniques": data["events"][0].get("mitre_techniques", []),
                    "affected_ips": [data["events"][0].get("src_ip")]}
            self.alerts.append({"request": data, "response": resp})
            if key:
                self.idempotency[key] = resp
            return 201, resp
        if method == "POST" and path.endswith("/v1/ingest/batch"):
            self.ingested.extend(data.get("events", []))
            return 202, {"accepted": len(data.get("events", []))}
        if method == "POST" and path == "/api/v1/approvals":
            rec = {"id": self._id("appr"), "status": "pending", "decided_by_id": None, "decided_at": None,
                   "decision_comment": None, "expires_at": data.get("expires_at"), "action": data.get("action"),
                   "title": data.get("title"), "risk_level": data.get("risk_level"), "case_id": data.get("case_id")}
            self.approvals[rec["id"]] = rec
            if self.auto_decide is not None:
                verdict = self.auto_decide(rec)
                if verdict is not None:
                    self.decide(rec["id"], verdict)
            return 201, dict(rec)
        m = re.match(r"^/api/v1/approvals/([^/]+)$", path)
        if method == "GET" and m:
            rec = self.approvals.get(m.group(1))
            return (200, dict(rec)) if rec else (404, {"detail": "not found"})
        m = re.match(r"^/api/v1/approvals/([^/]+)/decide$", path)
        if method == "POST" and m:
            rec = self.approvals.get(m.group(1))
            if not rec:
                return 404, {"detail": "not found"}
            if rec["status"] != "pending":
                return 409, {"detail": "already decided"}
            self.decide(rec["id"], data.get("decision") == "approve", comment=data.get("comment", ""))
            return 200, dict(rec)
        return 404, {"detail": f"no route {method} {path}"}
