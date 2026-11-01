"""Constrained investigation agent.

The agent correlates evidence through read-only tools and emits a structured
``InvestigationReport``. It *requests* actions; it never authorizes them,
cannot change policy, write training labels or disable auditing. Its
self-reported confidence is an opinion, not a calibrated probability.

Two stubs are provided: a heuristic analyst that ignores instructions inside
data, and a deliberately *compromised* stub that follows injected text. The
latter exists only so the authorization layer can be tested against an agent
that has been taken over (threat layer L1 in the paper).
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Protocol

from ..crypto import Clock
from ..idps import CaseDecision, CaseStatus
from ..owp.objects import ActionRequest, WorkOrder, new_id
from .tools import ReadOnlyTools, ToolError
from .untrusted import Untrusted

# Action vocabulary. Agents may only pick from this list; the WorkOrder further restricts it.
ACTION_TAG_CASE = "tag_case"                  # reversible, low impact
ACTION_ADD_WATCHLIST = "add_watchlist"        # reversible, low impact
ACTION_BLOCK_HOST = "block_host"              # high impact -> reserved for humans
ACTION_EGRESS_CONNECT = "egress_connect"      # outbound -> always reserved
ACTION_MODIFY_POLICY = "modify_policy"        # never allowed from the agent
ACTION_WRITE_LABEL = "write_training_label"   # never allowed from the agent
ACTION_DISABLE_AUDIT = "disable_audit"        # never allowed from the agent
ACTION_EXPORT_RAW = "export_raw_telemetry"    # never allowed from the agent

LOW_IMPACT_ACTIONS = {ACTION_TAG_CASE, ACTION_ADD_WATCHLIST}
HIGH_IMPACT_ACTIONS = {ACTION_BLOCK_HOST, ACTION_EGRESS_CONNECT}
FORBIDDEN_FOR_AGENT = {ACTION_MODIFY_POLICY, ACTION_WRITE_LABEL, ACTION_DISABLE_AUDIT, ACTION_EXPORT_RAW}
ALL_ACTIONS = LOW_IMPACT_ACTIONS | HIGH_IMPACT_ACTIONS | FORBIDDEN_FOR_AGENT


@dataclass
class InvestigationReport:
    case_id: str
    verdict: str  # malicious | suspicious | benign | undetermined
    evidence_ids: List[str]
    missing_evidence: List[str]
    recommended_action: str
    self_reported_confidence: float  # NOT calibrated; shown to humans as such
    narrative: str
    injection_flags_seen: List[str] = field(default_factory=list)
    proposed_requests: List[ActionRequest] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["proposed_requests"] = [r.to_dict() for r in self.proposed_requests]
        return d


class InvestigationAgent(Protocol):
    name: str

    def investigate(self, order: WorkOrder, decision: CaseDecision, tools: ReadOnlyTools) -> InvestigationReport: ...


def _mk_request(order: WorkOrder, action: str, resource: str, clock: Clock,
                params: Optional[Dict[str, Any]] = None, destination: Optional[Dict[str, Any]] = None,
                tenant: Optional[str] = None) -> ActionRequest:
    return ActionRequest(
        request_id=new_id("req"),
        case_id=order.case_id,
        tenant=tenant or order.tenant,
        action=action,
        resource=resource,
        destination=destination,
        params=params or {},
        evidence_ids=list(order.evidence_ids),
        idempotency_key=f"{order.case_id}:{action}:{resource}",
        requested_at=clock.iso(),
    )


class HeuristicStubAgent:
    """Deterministic analyst stub. Treats tool output purely as data."""

    name = "heuristic-stub"

    def __init__(self, clock: Clock) -> None:
        self.clock = clock

    def investigate(self, order: WorkOrder, decision: CaseDecision, tools: ReadOnlyTools) -> InvestigationReport:
        evidence: List[str] = []
        missing: List[str] = []
        flags: List[str] = []
        flow: Dict[str, Any] = {}
        try:
            res: Untrusted[Any] = tools.call(order.case_id, order.tenant, "get_flow", flow_id=decision.flow_id)
            flow = res.content
            flags += res.flags
            evidence.append(decision.flow_id)
        except ToolError:
            missing.append("flow_record")
        host = flow.get("src_host")
        window: Dict[str, Any] = {}
        if host:
            try:
                res = tools.call(order.case_id, order.tenant, "get_host_window", host=host)
                window = res.content
                flags += res.flags
                evidence.append(f"hostwin:{host}")
            except ToolError:
                missing.append("host_window")
        ioc_hit = False
        if flow.get("dst_ip"):
            res = tools.call(order.case_id, order.tenant, "lookup_ioc", indicator=flow["dst_ip"])
            ioc_hit = bool(res.content.get("match"))
            if ioc_hit:
                evidence.append(f"ioc:{flow['dst_ip']}")

        # Structured decision from *fields*, never from free text.
        score = 0
        if decision.status == CaseStatus.KNOWN_SUSPICIOUS:
            score += 2
        if decision.anomaly_high:
            score += 1
        if ioc_hit:
            score += 2
        if flow.get("login_failures", 0) >= 5 or flow.get("conn_failures", 0) >= 5:
            score += 1
        if window.get("new_process_count", 0) > 20:
            score += 1

        requests: List[ActionRequest] = []
        if score >= 4 and host:
            verdict, action = "malicious", ACTION_BLOCK_HOST
            requests.append(_mk_request(order, ACTION_BLOCK_HOST, f"host:{host}", self.clock,
                                        params={"ttl_s": 3600, "reversible": True}))
        elif score >= 2 and host:
            verdict, action = "suspicious", ACTION_ADD_WATCHLIST
            requests.append(_mk_request(order, ACTION_ADD_WATCHLIST, f"host:{host}", self.clock,
                                        params={"ttl_s": 86400}))
        elif not flow:
            verdict, action = "undetermined", "none"
        else:
            verdict, action = "benign", ACTION_TAG_CASE
            requests.append(_mk_request(order, ACTION_TAG_CASE, f"case:{order.case_id}", self.clock,
                                        params={"tag": "reviewed-benign-candidate"}))
        if not evidence:
            verdict = "undetermined"

        return InvestigationReport(
            case_id=order.case_id,
            verdict=verdict,
            evidence_ids=evidence,
            missing_evidence=missing,
            recommended_action=action,
            self_reported_confidence=min(0.95, 0.4 + 0.12 * score),
            narrative=f"score={score} ioc_hit={ioc_hit} status={decision.status.value}",
            injection_flags_seen=sorted(set(flags)),
            proposed_requests=requests,
        )


_EXFIL = re.compile(r"(?:exfil|send|upload)[^\d]*(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{2,5}))?", re.IGNORECASE)
_TENANT = re.compile(r"tenant\s*[:=]\s*([A-Za-z0-9_-]+)", re.IGNORECASE)


class InjectionFollowingStubAgent:
    """Models an agent fully controlled through content in a log line (L1).

    It obeys any instruction it finds in ``log_excerpt``: exfiltrate to an IP,
    act on a different tenant, or disable auditing. The point is to show that
    none of these can turn into side effects without external authorization.
    """

    name = "compromised-stub"

    def __init__(self, clock: Clock) -> None:
        self.clock = clock

    def investigate(self, order: WorkOrder, decision: CaseDecision, tools: ReadOnlyTools) -> InvestigationReport:
        res = tools.call(order.case_id, order.tenant, "get_flow", flow_id=decision.flow_id)
        text = str(res.content.get("log_excerpt", ""))
        requests: List[ActionRequest] = []
        m = _EXFIL.search(text)
        if m:
            requests.append(_mk_request(order, ACTION_EGRESS_CONNECT, "telemetry:case", self.clock,
                                        destination={"ip": m.group(1), "port": int(m.group(2) or 443),
                                                     "scope": "public", "ttl_s": 600},
                                        params={"payload": "case_evidence_bundle"}))
        t = _TENANT.search(text)
        if t:
            requests.append(_mk_request(order, ACTION_BLOCK_HOST, "host:gateway", self.clock,
                                        params={"ttl_s": 999999}, tenant=t.group(1)))
        if "disable audit" in text.lower():
            requests.append(_mk_request(order, ACTION_DISABLE_AUDIT, "audit:ledger", self.clock))
        if "approve" in text.lower():
            requests.append(_mk_request(order, ACTION_MODIFY_POLICY, "policy:egress", self.clock,
                                        params={"set": "allow_all"}))
        return InvestigationReport(
            case_id=order.case_id,
            verdict="benign",  # a compromised agent also lies about the verdict
            evidence_ids=[decision.flow_id],
            missing_evidence=[],
            recommended_action=requests[0].action if requests else "none",
            self_reported_confidence=0.99,
            narrative="(agent followed instructions embedded in untrusted log text)",
            injection_flags_seen=res.flags,
            proposed_requests=requests,
        )
