"""OpenWorkProof-aligned protocol objects for the SOC workflow.

Object chain (paper §VIII-A):
    WorkOrder -> CapabilityGrant -> PolicyDecision -> (HumanApproval)
    -> SignedAuthorization -> ActionReceipt -> VerificationDecision -> AcceptanceDecision

Every object is a plain dict-serialisable dataclass with a ``schema_version``
and a deterministic ``digest()`` over its canonical JSON. The schema strings
are this project's SOC-extension proposals; they are *not* claimed to be the
upstream OpenWorkProof schema.
"""

from __future__ import annotations

import secrets
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from ..canonical import digest

SCHEMA_PREFIX = "owp-soc"


def schema(name: str, version: str = "0.1") -> str:
    return f"{SCHEMA_PREFIX}/{name}/{version}"


class _Obj:
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)  # type: ignore[arg-type]

    def digest(self) -> str:
        return digest(self.to_dict())


@dataclass
class WorkOrder(_Obj):
    """Frozen case task and evidence scope. Nothing outside this scope may be requested."""

    case_id: str
    tenant: str
    task_description: str
    allowed_action_types: List[str]
    evidence_ids: List[str]
    evidence_digest: str
    detection_status: str
    model_version: str
    created_at: str
    schema_version: str = schema("work-order")


@dataclass
class CapabilityGrant(_Obj):
    """Minimal capability issued for one WorkOrder (tenant/resource/time/count bounded)."""

    grant_id: str
    case_id: str
    tenant: str
    task_digest: str
    allowed_actions: List[str]
    resource_patterns: List[str]
    max_uses: int
    usage_mode: str  # "single_use" | "bounded"
    issued_at: str
    expires_at: str
    schema_version: str = schema("capability-grant")


@dataclass
class ActionRequest(_Obj):
    """What the agent *asks* for. It carries no authority by itself."""

    request_id: str
    case_id: str
    tenant: str
    action: str
    resource: str
    destination: Optional[Dict[str, Any]]  # {"ip","port","scope":"public|private","ttl_s"} for egress
    params: Dict[str, Any]
    evidence_ids: List[str]
    idempotency_key: str
    requested_at: str
    schema_version: str = schema("action-request")


@dataclass
class PolicyDecision(_Obj):
    decision_id: str
    case_id: str
    request_digest: str
    task_digest: str
    grant_id: str
    policy_version: str
    status: str  # allowed | reserved | denied
    reasons: List[str]
    effective_capability: Dict[str, Any]
    decided_at: str
    schema_version: str = schema("policy-decision")


@dataclass
class HumanApproval(_Obj):
    """A human decision bound to the exact request, evidence and parameters."""

    approval_id: str
    case_id: str
    request_digest: str
    evidence_digest: str
    params_digest: str
    policy_decision_digest: str
    decision: str  # approve | reject
    approver_id: str
    rationale: str
    issued_at: str
    expires_at: str
    schema_version: str = schema("human-approval")


@dataclass
class AuthorizationEnvelope(_Obj):
    """SOC extension envelope signed by the authorization signer (paper §VIII-B)."""

    case_id: str
    tenant: str
    task_digest: str
    evidence_digest: str
    policy_version: str
    policy_decision_digest: str
    action: str
    resource: str
    destination: Optional[Dict[str, Any]]
    params_digest: str
    request_digest: str
    issued_at: str
    expires_at: str
    nonce: str
    approval_digest: Optional[str]
    signer_identity: str
    schema_version: str = schema("authorization-envelope")


@dataclass
class ActionReceipt(_Obj):
    """Produced by the *tool/executor side*, independently of the ledger."""

    receipt_id: str
    case_id: str
    request_digest: str
    envelope_digest: Optional[str]
    action: str
    resource: str
    outcome: str  # executed | rejected | noop_idempotent
    detail: str
    executed_at: str
    executor_identity: str
    schema_version: str = schema("action-receipt")


@dataclass
class VerificationDecision(_Obj):
    verification_id: str
    case_id: str
    status: str  # VERIFIED | FAILED | UNKNOWN
    findings: List[str]
    checked_entries: int
    verified_at: str
    verifier_identity: str
    schema_version: str = schema("verification-decision")


@dataclass
class AcceptanceDecision(_Obj):
    acceptance_id: str
    case_id: str
    verification_digest: str
    status: str  # ACCEPTED | REJECTED | DEFERRED
    accepted_by: str
    rationale: str
    accepted_at: str
    schema_version: str = schema("acceptance-decision")


@dataclass
class Signed:
    """Payload + detached signatures (JCS canonical bytes are what is signed)."""

    payload: Dict[str, Any]
    signatures: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"payload": self.payload, "signatures": self.signatures}

    def payload_digest(self) -> str:
        return digest(self.payload)


def new_id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(6)}"


def new_nonce() -> str:
    return secrets.token_hex(16)
