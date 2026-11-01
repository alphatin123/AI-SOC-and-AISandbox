"""End-to-end AI SOC orchestrator.

Wires: dual_model detection -> frozen WorkOrder -> minimal CapabilityGrant ->
constrained agent investigation -> external PolicyDecision -> (human approval)
-> signed authorization -> PEP execution -> tool-side receipt -> ledger ->
independent verification -> human acceptance.

Five distinct signing identities are used (ledger, authorizer, executor,
verifier, approver) so that no single key can both authorize and attest.
In this reference implementation they live in one process; the paper's trust
assumptions require them to be in separately administered domains.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .canonical import digest
from .crypto import Clock, Ed25519Signer, TrustedKeys, utc_iso
from .idps import CaseDecision, CaseStatus, DualModel, FlowRecord
from .owp import (
    AcceptanceDecision,
    CapabilityGrant,
    EncryptedEvidenceStore,
    ExternalWitness,
    HashChainLedger,
    Signed,
    Verifier,
    WorkOrder,
    new_id,
)
from .sandbox import (
    ACTION_ADD_WATCHLIST,
    ACTION_BLOCK_HOST,
    ACTION_EGRESS_CONNECT,
    ACTION_TAG_CASE,
    ApprovalView,
    AuthorizationError,
    AuthorizationSigner,
    BoundedExecutor,
    HumanApprover,
    InvestigationAgent,
    PEPConfig,
    PolicyEnforcementPoint,
    PolicyEngine,
    ReadOnlyTools,
    RuntimeConstraints,
    TelemetryStore,
    ToolSideLog,
    build_approval_view,
)

HumanPolicy = Callable[[ApprovalView], Tuple[bool, str]]


def conservative_human(view: ApprovalView) -> Tuple[bool, str]:
    """Simulated approver used by the demo. A real deployment has a person here."""
    if view.injection_flags_seen:
        return False, "injection indicators present in evidence; refusing until reviewed"
    if view.action == ACTION_EGRESS_CONNECT:
        return False, "outbound transfer not justified by case"
    if view.action == ACTION_BLOCK_HOST and view.agent_verdict == "malicious" and len(view.supporting_evidence) >= 2:
        return True, "multiple independent evidence items; reversible block within ttl"
    return False, "insufficient evidence for high-impact action"


@dataclass
class RequestOutcome:
    request_id: str
    action: str
    tenant: str
    policy_status: str
    human_decision: Optional[str]
    authorized: bool
    executed: bool
    reason: str


@dataclass
class CaseResult:
    case_id: str
    flow_id: str
    decision: CaseDecision
    investigated: bool
    deduplicated: bool = False
    report: Optional[Dict[str, Any]] = None
    requests: List[RequestOutcome] = field(default_factory=list)
    verification_status: Optional[str] = None
    verification_findings: List[str] = field(default_factory=list)
    acceptance_status: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "flow_id": self.flow_id,
            "decision": self.decision.to_dict(),
            "investigated": self.investigated,
            "deduplicated": self.deduplicated,
            "report": self.report,
            "requests": [r.__dict__ for r in self.requests],
            "verification_status": self.verification_status,
            "verification_findings": self.verification_findings,
            "acceptance_status": self.acceptance_status,
        }


class AISOC:
    def __init__(
        self,
        model: DualModel,
        agent: InvestigationAgent,
        clock: Optional[Clock] = None,
        witness: Optional[ExternalWitness] = None,
        pep_config: Optional[PEPConfig] = None,
        human_policy: HumanPolicy = conservative_human,
        runtime: Optional[RuntimeConstraints] = None,
        dedup_window_s: int = 300,
    ) -> None:
        self.clock = clock or Clock()
        self.model = model
        self.agent = agent
        self.human_policy = human_policy
        self.dedup_window_s = dedup_window_s

        self.keys = {
            role: Ed25519Signer(role) for role in ("ledger", "authorizer", "executor", "verifier", "approver")
        }
        self.trusted = TrustedKeys()
        for s in self.keys.values():
            self.trusted.trust(s)

        self.witness = witness if witness is not None else ExternalWitness()
        self.ledger = HashChainLedger(self.keys["ledger"], self.clock, self.witness)
        self.evidence = EncryptedEvidenceStore()
        self.telemetry = TelemetryStore()
        self.tool_log = ToolSideLog()
        self.tools = ReadOnlyTools(self.telemetry, self.tool_log, self.clock)
        self.policy = PolicyEngine(self.clock, runtime or RuntimeConstraints())
        self.approver = HumanApprover("analyst-1", self.keys["approver"], self.clock)
        self.signer = AuthorizationSigner(self.keys["authorizer"], self.trusted, self.clock)
        self.executor = BoundedExecutor(self.keys["executor"], self.clock)
        self.pep = PolicyEnforcementPoint(self.trusted, self.executor, self.tool_log, self.clock, pep_config)
        self.verifier = Verifier(self.keys["verifier"], self.trusted, self.clock)

        self._recent: Dict[Tuple[str, str, str], Any] = {}
        self.results: List[CaseResult] = []
        # Introspection hooks used by scenarios/tests; they expose no extra authority.
        self.last_order_grant: Optional[Tuple[WorkOrder, CapabilityGrant]] = None
        self.captured_authorizations: Dict[str, Tuple[Any, Signed]] = {}

    # ------------------------------------------------------------------ pipeline
    def ingest(self, flow: FlowRecord) -> CaseResult:
        self.telemetry.add_flow(flow)
        decision = self.model.decide(flow)
        case_id = new_id("case")
        self.ledger.append("detection", case_id, decision.to_dict(), {"flow_id": flow.flow_id})
        result = CaseResult(case_id=case_id, flow_id=flow.flow_id, decision=decision, investigated=False)

        if not decision.requires_agent_investigation:
            self.results.append(result)
            return result

        key = (flow.tenant, flow.src_host, decision.status.value)
        last = self._recent.get(key)
        now = self.clock.now()
        if last is not None and (now - last).total_seconds() < self.dedup_window_s:
            result.deduplicated = True
            self.ledger.append("dedup_suppressed", case_id, {"key": list(key)})
            self.results.append(result)
            return result
        self._recent[key] = now

        order, grant = self._freeze_task(case_id, flow, decision)
        report = self.agent.investigate(order, decision, self.tools)
        self.ledger.append("investigation_report", case_id, report.to_dict())
        result.investigated = True
        result.report = report.to_dict()

        for req in report.proposed_requests:
            result.requests.append(self._handle_request(req, order, grant, report))

        self.ledger.checkpoint()
        vd = self.verifier.verify_case(case_id, self.ledger, self.tool_log.receipts)
        self.ledger.append("verification_decision", case_id, vd.payload)
        result.verification_status = vd.payload["status"]
        result.verification_findings = list(vd.payload["findings"])

        acc = self._accept(case_id, vd)
        self.ledger.append("acceptance_decision", case_id, acc.payload)
        result.acceptance_status = acc.payload["status"]
        self.results.append(result)
        return result

    def _freeze_task(self, case_id: str, flow: FlowRecord, decision: CaseDecision) -> Tuple[WorkOrder, CapabilityGrant]:
        evidence_ids = [flow.flow_id, f"hostwin:{flow.src_host}", f"ioc:{flow.dst_ip}"]
        # Sensitive originals go to the encrypted store; the order carries only the digest.
        ev_digest = self.evidence.put({"flow": flow.__dict__, "decision": decision.to_dict()})
        if decision.status == CaseStatus.KNOWN_SUSPICIOUS:
            allowed = [ACTION_TAG_CASE, ACTION_ADD_WATCHLIST, ACTION_BLOCK_HOST]
        else:
            # suspected-unknown / conflict: human review mandatory, agent limited to reversible actions
            allowed = [ACTION_TAG_CASE, ACTION_ADD_WATCHLIST]
        order = WorkOrder(
            case_id=case_id,
            tenant=flow.tenant,
            task_description=f"Investigate flow {flow.flow_id} ({decision.status.value})",
            allowed_action_types=allowed,
            evidence_ids=evidence_ids,
            evidence_digest=ev_digest,
            detection_status=decision.status.value,
            model_version=decision.model_version,
            created_at=self.clock.iso(),
        )
        self.ledger.append("work_order", case_id, order.to_dict())
        now = self.clock.now()
        grant = CapabilityGrant(
            grant_id=new_id("grant"),
            case_id=case_id,
            tenant=flow.tenant,
            task_digest=order.digest(),
            allowed_actions=list(allowed),
            resource_patterns=[f"host:{flow.src_host}", f"case:{case_id}"],
            max_uses=3,
            usage_mode="bounded",
            issued_at=utc_iso(now),
            expires_at=utc_iso(now + timedelta(hours=1)),
        )
        self.ledger.append("capability_grant", case_id, grant.to_dict(), {"task_digest": order.digest()})
        self.last_order_grant = (order, grant)
        return order, grant

    def _handle_request(self, req, order: WorkOrder, grant: CapabilityGrant, report) -> RequestOutcome:
        case_id = order.case_id
        self.ledger.append("action_request", case_id, req.to_dict())
        pd = self.policy.decide(req, order, grant)
        self.ledger.append("policy_decision", case_id, pd.to_dict(), {"request_digest": pd.request_digest})
        out = RequestOutcome(req.request_id, req.action, req.tenant, pd.status, None, False, False, "; ".join(pd.reasons))
        if pd.status == "denied":
            return out

        approval: Optional[Signed] = None
        if pd.status == "reserved":
            view = build_approval_view(req, report, pd)
            approve, rationale = self.human_policy(view)
            approval = self.approver.decide(req, order, pd, approve, rationale)
            self.ledger.append("human_approval", case_id, approval.payload, {"request_digest": pd.request_digest})
            out.human_decision = approval.payload["decision"]
            if not approve:
                out.reason = f"human rejected: {rationale}"
                return out

        try:
            auth = self.signer.issue(req, order, pd, approval)
        except AuthorizationError as exc:
            self.ledger.append("authorization_refused", case_id, {"request_digest": pd.request_digest, "error": str(exc)})
            out.reason = f"signer refused: {exc}"
            return out
        out.authorized = True
        self.ledger.append("authorization", case_id, auth.payload, {"request_digest": pd.request_digest, "nonce": auth.payload["nonce"]})

        outcome = self.pep.execute(req, auth)
        if outcome.executed:
            self.captured_authorizations[case_id] = (req, auth)
        if outcome.receipt is not None:
            self.ledger.append("action_receipt", case_id, outcome.receipt.payload, {"request_digest": pd.request_digest})
        out.executed = outcome.executed
        out.reason = outcome.reason
        return out

    def _accept(self, case_id: str, vd: Signed) -> Signed:
        status = "ACCEPTED" if vd.payload["status"] == "VERIFIED" else ("DEFERRED" if vd.payload["status"] == "UNKNOWN" else "REJECTED")
        acc = AcceptanceDecision(
            acceptance_id=new_id("acc"),
            case_id=case_id,
            verification_digest=digest(vd.payload),
            status=status,
            accepted_by=self.approver.approver_id,
            rationale="simulated acceptance follows verification status; a human must own this in production",
            accepted_at=self.clock.iso(),
        )
        payload = acc.to_dict()
        return Signed(payload=payload, signatures=[self.keys["approver"].sign_payload(payload)])

    # ------------------------------------------------------------------ export
    def export(self, out_dir: Path) -> None:
        import json

        out_dir.mkdir(parents=True, exist_ok=True)
        self.ledger.export(out_dir / "ledger.json")
        (out_dir / "trusted-keys.json").write_text(json.dumps(self.trusted.export(), indent=2, sort_keys=True))
        (out_dir / "tool-side-receipts.json").write_text(
            json.dumps([r.to_dict() for r in self.tool_log.receipts], indent=2, sort_keys=True)
        )
        (out_dir / "tool-calls.json").write_text(
            json.dumps([c.__dict__ for c in self.tool_log.calls], indent=2, sort_keys=True)
        )
        (out_dir / "witness-checkpoints.json").write_text(json.dumps(self.witness.checkpoints(), indent=2, sort_keys=True))
        (out_dir / "cases.json").write_text(json.dumps([r.to_dict() for r in self.results], indent=2, sort_keys=True))
        (out_dir / "model-card.json").write_text(json.dumps(self.model.describe(), indent=2, sort_keys=True))
