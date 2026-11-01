"""External policy engine: allowed / reserved / denied.

Effective capability (paper §IX-A):
    C_eff = C_task ∩ C_grant ∩ C_human ∩ C_runtime
The agent can only shrink this set by asking for less; it can never widen it.
``reserved`` means a human must approve a decision bound to the exact request.
"""

from __future__ import annotations

import fnmatch
import ipaddress
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..crypto import Clock, parse_iso
from ..owp.objects import ActionRequest, CapabilityGrant, PolicyDecision, WorkOrder, new_id
from .agent import FORBIDDEN_FOR_AGENT, HIGH_IMPACT_ACTIONS, LOW_IMPACT_ACTIONS, ACTION_BLOCK_HOST, ACTION_EGRESS_CONNECT

POLICY_VERSION = "soc-policy/2026-11-01.1"


@dataclass
class RuntimeConstraints:
    """C_runtime: deployment-wide ceilings independent of any one task."""

    max_block_ttl_s: int = 24 * 3600
    egress_default_deny: bool = True
    max_requests_per_case: int = 5
    high_impact_requires_evidence: bool = True


@dataclass
class PolicyEngine:
    clock: Clock
    runtime: RuntimeConstraints = field(default_factory=RuntimeConstraints)
    policy_version: str = POLICY_VERSION
    _request_count: Dict[str, int] = field(default_factory=dict)

    def decide(self, request: ActionRequest, order: WorkOrder, grant: CapabilityGrant) -> PolicyDecision:
        reasons: List[str] = []
        status = "allowed"

        def deny(msg: str) -> None:
            nonlocal status
            status = "denied"
            reasons.append(msg)

        # C_task: frozen work order
        if request.case_id != order.case_id:
            deny("request case_id does not match work order")
        if request.tenant != order.tenant:
            deny(f"tenant mismatch: request={request.tenant} order={order.tenant}")
        if request.action not in order.allowed_action_types:
            deny(f"action {request.action} outside task scope")
        if request.action in FORBIDDEN_FOR_AGENT:
            deny(f"action {request.action} can never be requested by the agent")
        if set(request.evidence_ids) - set(order.evidence_ids):
            deny("request cites evidence outside the frozen evidence scope")

        # C_grant: minimal capability
        now = self.clock.now()
        if grant.case_id != order.case_id or grant.task_digest != order.digest():
            deny("grant is not bound to this work order")
        if parse_iso(grant.expires_at) <= now:
            deny("capability grant expired")
        if request.action not in grant.allowed_actions:
            deny(f"action {request.action} not in capability grant")
        if not any(fnmatch.fnmatch(request.resource, p) for p in grant.resource_patterns):
            deny(f"resource {request.resource} not covered by grant patterns {grant.resource_patterns}")

        # C_runtime
        n = self._request_count.get(request.case_id, 0) + 1
        self._request_count[request.case_id] = n
        if n > self.runtime.max_requests_per_case:
            deny("per-case request budget exhausted")
        if request.action == ACTION_BLOCK_HOST:
            ttl = int(request.params.get("ttl_s", 0) or 0)
            if ttl <= 0 or ttl > self.runtime.max_block_ttl_s:
                deny(f"block ttl {ttl}s outside runtime ceiling")
        if request.action == ACTION_EGRESS_CONNECT:
            dest = request.destination or {}
            try:
                ip = ipaddress.ip_address(str(dest.get("ip", "")))
            except ValueError:
                ip = None
            if ip is None or not dest.get("port"):
                deny("egress request lacks a precise ip:port destination")
            else:
                actual_scope = "private" if ip.is_private else "public"
                if dest.get("scope") != actual_scope:
                    deny(f"declared scope {dest.get('scope')} does not match resolved {actual_scope}")
                if not dest.get("ttl_s") or int(dest["ttl_s"]) > 3600:
                    deny("egress ttl missing or above 3600s")
        if self.runtime.high_impact_requires_evidence and request.action in HIGH_IMPACT_ACTIONS and not request.evidence_ids:
            deny("high impact action without cited evidence")

        # C_human: anything high-impact or outbound is reserved for a human decision
        if status != "denied":
            if request.action in HIGH_IMPACT_ACTIONS or (
                request.action == ACTION_EGRESS_CONNECT and self.runtime.egress_default_deny
            ):
                status = "reserved"
                reasons.append("high impact / outbound: human approval bound to this request is required")
            elif request.action in LOW_IMPACT_ACTIONS:
                reasons.append("low impact reversible action within C_task ∩ C_grant ∩ C_runtime")
            else:
                deny("unclassified action")

        c_eff = {
            "tenant": order.tenant,
            "actions": sorted(set(order.allowed_action_types) & set(grant.allowed_actions) - FORBIDDEN_FOR_AGENT),
            "resource_patterns": list(grant.resource_patterns),
            "expires_at": grant.expires_at,
            "max_block_ttl_s": self.runtime.max_block_ttl_s,
            "egress_default_deny": self.runtime.egress_default_deny,
        }
        return PolicyDecision(
            decision_id=new_id("pd"),
            case_id=request.case_id,
            request_digest=request.digest(),
            task_digest=order.digest(),
            grant_id=grant.grant_id,
            policy_version=self.policy_version,
            status=status,
            reasons=reasons,
            effective_capability=c_eff,
            decided_at=self.clock.iso(),
        )
