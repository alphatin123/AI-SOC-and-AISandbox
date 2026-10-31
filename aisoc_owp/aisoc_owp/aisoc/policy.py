"""Authority = WorkOrder ∩ CapabilityGrant ∩ HumanAgencyProfile -> allowed / reserved / denied.

Mirrors the three-state resolution OpenWorkProof describes. The names below are our own
lightweight stand-ins; when the real `openworkproof` package is used, build the real
objects from the repo examples (see owp_adapter.py)."""
import ipaddress
from dataclasses import dataclass
from enum import Enum
from typing import Mapping

READ_FEATURES = "read_features"
WRITE_VERDICT = "write_verdict"
QUARANTINE_HOST = "quarantine_host"
BLOCK_FLOW = "block_flow"
EGRESS_CONNECT = "egress_connect"
HUMAN_REQUIRED = "AGENCY_HUMAN_DECISION_REQUIRED"

ARG_KEYS = {
    READ_FEATURES: {"window_ref"},
    WRITE_VERDICT: {"case_id"},
    QUARANTINE_HOST: {"host"},
    BLOCK_FLOW: {"src_ip", "dst_ip", "dst_port", "proto"},
    EGRESS_CONNECT: {"dst_ip", "dst_port", "proto"},
}


class State(str, Enum):
    ALLOWED = "allowed"
    RESERVED = "reserved"
    DENIED = "denied"


@dataclass(frozen=True)
class Resolution:
    state: State
    code: str
    reason: str = ""


@dataclass(frozen=True)
class WorkOrder:
    work_order_id: str
    objective: str            # carries the commitment digest (signed field, NOT metadata)
    allowed_actions: frozenset
    max_ttl_s: int


@dataclass(frozen=True)
class CapabilityGrant:
    grant_id: str
    actions: frozenset

    def attenuate(self, child_id: str, subset) -> "CapabilityGrant":
        subset = frozenset(subset)
        if not subset <= self.actions:
            raise ValueError("grants only attenuate: child exceeds parent")
        return CapabilityGrant(child_id, subset)


@dataclass(frozen=True)
class HumanAgencyProfile:
    profile_id: str
    status: Mapping           # action -> "delegated" | "reserved" | "denied"


def resolve(action, wo: WorkOrder, grant: CapabilityGrant, profile: HumanAgencyProfile) -> Resolution:
    if action not in wo.allowed_actions:
        return Resolution(State.DENIED, "NOT_IN_WORK_ORDER", action)
    if action not in grant.actions:
        return Resolution(State.DENIED, "NOT_IN_GRANT", action)
    s = profile.status.get(action, "denied")
    if s == "delegated":
        return Resolution(State.ALLOWED, "OK")
    if s == "reserved":
        return Resolution(State.RESERVED, HUMAN_REQUIRED)
    return Resolution(State.DENIED, "DENIED_BY_PROFILE", action)


def validate_args(action, args) -> str:
    """Returns '' if valid, else an error code. Exact key sets: no extra fields."""
    if action not in ARG_KEYS:
        return "UNKNOWN_ACTION"
    if not isinstance(args, dict) or set(args) != ARG_KEYS[action]:
        return "BAD_ARGS"
    try:
        for k in ("dst_ip", "src_ip"):
            if k in args:
                ipaddress.ip_address(args[k])
        if "dst_port" in args and not (isinstance(args["dst_port"], int) and 0 < args["dst_port"] < 65536):
            return "BAD_ARGS"
        if "proto" in args and args["proto"] not in ("tcp", "udp"):
            return "BAD_ARGS"
    except ValueError:
        return "BAD_ARGS"
    return ""
