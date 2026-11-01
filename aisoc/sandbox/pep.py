"""Policy Enforcement Point and bounded executor (paper §VIII-C).

Order of checks: signature -> binding to the presented request -> expiry ->
revocation -> approval presence for reserved decisions -> atomic single-use
nonce -> idempotency -> bounded execution with egress default-deny. The
executor signs its own ActionReceipt with a key that is *not* the
authorization key, so the tool side produces independent evidence.

``PEPConfig`` flags exist only to run the ablations described in §XI-A. In
any real deployment they must all stay ``True``.
"""

from __future__ import annotations

import ipaddress
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from ..canonical import digest
from ..crypto import Clock, Ed25519Signer, TrustedKeys, parse_iso
from ..owp.objects import ActionReceipt, ActionRequest, Signed, new_id
from .agent import ACTION_ADD_WATCHLIST, ACTION_BLOCK_HOST, ACTION_EGRESS_CONNECT, ACTION_TAG_CASE, HIGH_IMPACT_ACTIONS
from .tools import ToolSideLog


@dataclass
class PEPConfig:
    verify_signature: bool = True
    verify_binding: bool = True
    verify_expiry: bool = True
    verify_revocation: bool = True
    require_approval_for_high_impact: bool = True
    single_use_nonce: bool = True
    idempotency: bool = True
    egress_default_deny: bool = True


class NonceStore:
    """Atomic consume. Multi-replica deployments must back this with a shared store."""

    def __init__(self) -> None:
        self._used: Set[str] = set()
        self._lock = threading.Lock()

    def consume(self, nonce: str) -> bool:
        with self._lock:
            if nonce in self._used:
                return False
            self._used.add(nonce)
            return True


class RevocationList:
    def __init__(self) -> None:
        self._nonces: Set[str] = set()
        self._cases: Set[str] = set()
        self._signers: Set[str] = set()

    def revoke_nonce(self, nonce: str) -> None:
        self._nonces.add(nonce)

    def revoke_case(self, case_id: str) -> None:
        self._cases.add(case_id)

    def revoke_signer(self, key_id: str) -> None:
        self._signers.add(key_id)

    def is_revoked(self, env: Dict[str, Any]) -> bool:
        return (
            env.get("nonce") in self._nonces
            or env.get("case_id") in self._cases
            or env.get("signer_identity") in self._signers
        )


@dataclass
class ExecutionOutcome:
    executed: bool
    reason: str
    receipt: Optional[Signed]
    side_effect: Optional[Dict[str, Any]] = None


@dataclass
class BoundedExecutor:
    """Simulated effectors. Each action has an explicit, bounded side effect."""

    signer: Ed25519Signer
    clock: Clock
    egress_allowlist: Set[str] = field(default_factory=set)  # "ip:port" entries authorized by envelopes
    blocked_hosts: Dict[str, int] = field(default_factory=dict)
    watchlist: Dict[str, int] = field(default_factory=dict)
    tags: Dict[str, List[str]] = field(default_factory=dict)
    egress_log: List[Dict[str, Any]] = field(default_factory=list)

    def run(self, request: ActionRequest, env: Dict[str, Any], egress_default_deny: bool) -> Dict[str, Any]:
        a = request.action
        if a == ACTION_TAG_CASE:
            self.tags.setdefault(request.resource, []).append(str(request.params.get("tag", "")))
            return {"tagged": request.resource}
        if a == ACTION_ADD_WATCHLIST:
            self.watchlist[request.resource] = int(request.params.get("ttl_s", 0))
            return {"watchlisted": request.resource}
        if a == ACTION_BLOCK_HOST:
            self.blocked_hosts[request.resource] = int(request.params["ttl_s"])
            return {"blocked": request.resource, "ttl_s": self.blocked_hosts[request.resource]}
        if a == ACTION_EGRESS_CONNECT:
            dest = env.get("destination") or {}
            key = f"{dest.get('ip')}:{dest.get('port')}"
            if egress_default_deny:
                # The envelope *is* the allow entry; nothing else is reachable.
                ipaddress.ip_address(str(dest.get("ip")))
                self.egress_allowlist.add(key)
            self.egress_log.append({"dest": key, "case_id": request.case_id, "ttl_s": dest.get("ttl_s")})
            return {"egress": key}
        raise ValueError(f"executor has no effector for {a}")


class PolicyEnforcementPoint:
    def __init__(
        self,
        trusted: TrustedKeys,
        executor: BoundedExecutor,
        tool_log: ToolSideLog,
        clock: Clock,
        config: Optional[PEPConfig] = None,
        revocations: Optional[RevocationList] = None,
    ) -> None:
        self.trusted = trusted
        self.executor = executor
        self.tool_log = tool_log
        self.clock = clock
        self.config = config or PEPConfig()
        self.revocations = revocations or RevocationList()
        self.nonces = NonceStore()
        self._idem: Dict[str, Signed] = {}
        self.rejections: List[Dict[str, str]] = []

    def execute(self, request: ActionRequest, authorization: Signed) -> ExecutionOutcome:
        env = authorization.payload
        c = self.config

        def reject(reason: str) -> ExecutionOutcome:
            self.rejections.append({"case_id": request.case_id, "request_id": request.request_id, "reason": reason})
            receipt = self._receipt(request, env, "rejected", reason)
            return ExecutionOutcome(False, reason, receipt)

        if c.verify_signature and not any(
            self.trusted.verify(env, s, expected_role="authorizer") for s in authorization.signatures
        ):
            return reject("authorization signature invalid or signer not trusted as authorizer")
        if c.verify_binding:
            if env.get("request_digest") != request.digest():
                return reject("envelope not bound to presented request")
            if env.get("params_digest") != digest(request.params):
                return reject("parameters differ from authorized parameters")
            if (env.get("action"), env.get("resource"), env.get("tenant")) != (request.action, request.resource, request.tenant):
                return reject("action/resource/tenant differ from envelope")
            if env.get("destination") != request.destination:
                return reject("destination differs from authorized destination")
        if c.verify_expiry and parse_iso(env["expires_at"]) <= self.clock.now():
            return reject("authorization expired")
        if c.verify_revocation and self.revocations.is_revoked(env):
            return reject("authorization revoked")
        if c.require_approval_for_high_impact and request.action in HIGH_IMPACT_ACTIONS and not env.get("approval_digest"):
            return reject("high impact action lacks bound human approval")
        if c.idempotency and request.idempotency_key in self._idem:
            prior = self._idem[request.idempotency_key]
            return ExecutionOutcome(False, "idempotent replay: returning prior receipt, no new side effect", prior)
        if c.single_use_nonce and not self.nonces.consume(env["nonce"]):
            return reject("nonce already consumed (replay)")

        try:
            effect = self.executor.run(request, env, c.egress_default_deny)
        except Exception as exc:
            return reject(f"executor error: {type(exc).__name__}: {exc}")
        receipt = self._receipt(request, env, "executed", str(effect))
        if c.idempotency:
            self._idem[request.idempotency_key] = receipt
        return ExecutionOutcome(True, "executed", receipt, effect)

    def _receipt(self, request: ActionRequest, env: Dict[str, Any], outcome: str, detail: str) -> Signed:
        r = ActionReceipt(
            receipt_id=new_id("rcpt"),
            case_id=request.case_id,
            request_digest=request.digest(),
            envelope_digest=digest(env) if env else None,
            action=request.action,
            resource=request.resource,
            outcome=outcome,
            detail=detail,
            executed_at=self.clock.iso(),
            executor_identity=self.executor.signer.key_id,
        )
        payload = r.to_dict()
        signed = Signed(payload=payload, signatures=[self.executor.signer.sign_payload(payload)])
        self.tool_log.record_receipt(signed)
        return signed
