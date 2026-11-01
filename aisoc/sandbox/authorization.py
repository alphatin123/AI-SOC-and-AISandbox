"""Human approval and the authorization signing service.

The signer never blind-signs agent output. It requires a PolicyDecision of
``allowed``, or ``reserved`` plus a valid HumanApproval whose digests bind the
exact request, evidence and parameters. Ed25519 + JCS only prove *who*
committed to *which bytes*; legality comes from the policy check performed
here before signing (paper §VIII-B).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Dict, List, Optional

from ..canonical import digest
from ..crypto import Clock, Ed25519Signer, TrustedKeys, parse_iso, utc_iso
from ..owp.objects import (
    ActionRequest,
    AuthorizationEnvelope,
    HumanApproval,
    PolicyDecision,
    Signed,
    WorkOrder,
    new_id,
    new_nonce,
)
from .agent import InvestigationReport


@dataclass
class ApprovalView:
    """Everything a human must see before approving (paper §IX-B)."""

    case_id: str
    action: str
    resource: str
    destination: Optional[Dict[str, Any]]
    params: Dict[str, Any]
    supporting_evidence: List[str]
    missing_evidence: List[str]
    agent_verdict: str
    agent_self_reported_confidence_uncalibrated: float
    injection_flags_seen: List[str]
    policy_reasons: List[str]
    effective_capability: Dict[str, Any]
    reversible: bool
    business_impact: str

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__.copy()


def build_approval_view(request: ActionRequest, report: InvestigationReport, decision: PolicyDecision) -> ApprovalView:
    reversible = bool(request.params.get("reversible", request.action != "egress_connect"))
    impact = {
        "block_host": "host loses connectivity for ttl; reversible by unblock",
        "egress_connect": "data leaves the environment; NOT reversible",
    }.get(request.action, "low")
    return ApprovalView(
        case_id=request.case_id,
        action=request.action,
        resource=request.resource,
        destination=request.destination,
        params=request.params,
        supporting_evidence=report.evidence_ids,
        missing_evidence=report.missing_evidence,
        agent_verdict=report.verdict,
        agent_self_reported_confidence_uncalibrated=report.self_reported_confidence,
        injection_flags_seen=report.injection_flags_seen,
        policy_reasons=decision.reasons,
        effective_capability=decision.effective_capability,
        reversible=reversible,
        business_impact=impact,
    )


class HumanApprover:
    """Represents an approver's signing key. The decision logic is supplied by the caller."""

    def __init__(self, approver_id: str, signer: Ed25519Signer, clock: Clock, ttl_s: int = 900) -> None:
        self.approver_id = approver_id
        self.signer = signer
        self.clock = clock
        self.ttl_s = ttl_s

    def decide(self, request: ActionRequest, order: WorkOrder, decision: PolicyDecision, approve: bool, rationale: str) -> Signed:
        now = self.clock.now()
        approval = HumanApproval(
            approval_id=new_id("hap"),
            case_id=request.case_id,
            request_digest=request.digest(),
            evidence_digest=order.evidence_digest,
            params_digest=digest(request.params),
            policy_decision_digest=decision.digest(),
            decision="approve" if approve else "reject",
            approver_id=self.approver_id,
            rationale=rationale,
            issued_at=utc_iso(now),
            expires_at=utc_iso(now + timedelta(seconds=self.ttl_s)),
        )
        payload = approval.to_dict()
        return Signed(payload=payload, signatures=[self.signer.sign_payload(payload)])


class AuthorizationError(Exception):
    pass


class AuthorizationSigner:
    def __init__(self, signer: Ed25519Signer, trusted: TrustedKeys, clock: Clock, ttl_s: int = 300) -> None:
        self.signer = signer
        self.trusted = trusted
        self.clock = clock
        self.ttl_s = ttl_s

    def issue(
        self,
        request: ActionRequest,
        order: WorkOrder,
        decision: PolicyDecision,
        approval: Optional[Signed] = None,
    ) -> Signed:
        if decision.request_digest != request.digest():
            raise AuthorizationError("policy decision is not about this request")
        if decision.task_digest != order.digest():
            raise AuthorizationError("policy decision is not bound to this work order")
        if decision.status == "denied":
            raise AuthorizationError("refusing to sign a denied request")
        approval_digest: Optional[str] = None
        if decision.status == "reserved":
            if approval is None:
                raise AuthorizationError("reserved request requires a human approval")
            self._check_approval(approval, request, order, decision)
            approval_digest = approval.payload_digest()
        elif decision.status != "allowed":
            raise AuthorizationError(f"unknown policy status {decision.status}")

        now = self.clock.now()
        env = AuthorizationEnvelope(
            case_id=request.case_id,
            tenant=request.tenant,
            task_digest=order.digest(),
            evidence_digest=order.evidence_digest,
            policy_version=decision.policy_version,
            policy_decision_digest=decision.digest(),
            action=request.action,
            resource=request.resource,
            destination=request.destination,
            params_digest=digest(request.params),
            request_digest=request.digest(),
            issued_at=utc_iso(now),
            expires_at=utc_iso(now + timedelta(seconds=self.ttl_s)),
            nonce=new_nonce(),
            approval_digest=approval_digest,
            signer_identity=self.signer.key_id,
        )
        payload = env.to_dict()
        return Signed(payload=payload, signatures=[self.signer.sign_payload(payload)])

    def _check_approval(self, approval: Signed, request: ActionRequest, order: WorkOrder, decision: PolicyDecision) -> None:
        p = approval.payload
        if not any(self.trusted.verify(p, s, expected_role="approver") for s in approval.signatures):
            raise AuthorizationError("approval signature invalid or signer not an approver")
        if p.get("decision") != "approve":
            raise AuthorizationError("human rejected the request")
        if p.get("request_digest") != request.digest():
            raise AuthorizationError("approval is bound to a different request")
        if p.get("params_digest") != digest(request.params):
            raise AuthorizationError("parameters changed after approval; re-authorization required")
        if p.get("evidence_digest") != order.evidence_digest:
            raise AuthorizationError("approval evidence scope mismatch")
        if p.get("policy_decision_digest") != decision.digest():
            raise AuthorizationError("approval refers to a different policy decision")
        if parse_iso(p["expires_at"]) <= self.clock.now():
            raise AuthorizationError("human approval expired")
