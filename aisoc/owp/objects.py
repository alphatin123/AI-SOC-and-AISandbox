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
from dataclasses import asdict, dataclass, field, replace
from typing import Any, Dict, List, Optional

from ..canonical import digest
from ..crypto import parse_iso

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
    parent_grant_id: Optional[str] = None
    schema_version: str = schema("capability-grant")

    def attenuate(
        self,
        allowed_actions: Optional[List[str]] = None,
        resource_patterns: Optional[List[str]] = None,
        max_uses: Optional[int] = None,
        expires_at: Optional[str] = None,
    ) -> "CapabilityGrant":
        """Derive a child grant. Capabilities can only shrink; any attempt to widen raises."""
        actions = list(allowed_actions) if allowed_actions is not None else list(self.allowed_actions)
        if not set(actions) <= set(self.allowed_actions):
            raise ValueError("attenuation cannot add actions")
        patterns = list(resource_patterns) if resource_patterns is not None else list(self.resource_patterns)
        if not set(patterns) <= set(self.resource_patterns):
            raise ValueError("attenuation cannot add resource patterns")
        uses = max_uses if max_uses is not None else self.max_uses
        if uses > self.max_uses or uses < 0:
            raise ValueError("attenuation cannot increase max_uses")
        exp = expires_at if expires_at is not None else self.expires_at
        if parse_iso(exp) > parse_iso(self.expires_at):
            raise ValueError("attenuation cannot extend expiry")
        return replace(
            self,
            grant_id=new_id("grant"),
            allowed_actions=actions,
            resource_patterns=patterns,
            max_uses=uses,
            expires_at=exp,
            parent_grant_id=self.grant_id,
        )


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
    # Set when the decision was collected from an external system (e.g. an AiSOC
    # approval inbox). Names the system and its record so the chain stays auditable.
    external_ref: Optional[Dict[str, Any]] = None
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
class ExternalEvidenceRef(_Obj):
    """Commitment to an artefact produced by another system (e.g. an AiSOC evidence bundle).

    Only digests travel into the ledger. ``integrity_checked`` records which of the
    foreign system's own integrity mechanisms this SOC verified before anchoring.
    """

    ref_id: str
    case_id: str
    system: str
    kind: str
    external_id: str
    payload_sha256: str
    artefact_digest: str
    integrity_checked: Dict[str, Any]
    anchored_at: str
    schema_version: str = schema("external-evidence")


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
