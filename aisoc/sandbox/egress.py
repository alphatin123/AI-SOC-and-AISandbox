"""Controlled egress proxy: the sandbox's *only* channel to the SOC control plane.

In production this sits on the host side of a vsock/unix socket and is the
single way anything leaves the agent sandbox. It implements complete mediation
and accountability (paper §VII, CISSP "complete mediation" / "fail-secure"):

* every message is written to the audit ledger **before** it is forwarded; if
  the audit write fails the message is dropped (``AUDIT_UNAVAILABLE``);
* only known message types up to a size limit pass (``REJECTED_BY_PROXY``);
* a per-minute rate limit bounds how much a compromised agent can push;
* the agent identity is bound to the channel. Whatever ``agent_id`` the
  payload claims is ignored and replaced, so an escaped agent cannot
  impersonate another agent or a human.

The proxy never adds authority: a forwarded ``action_request`` is still only a
request and goes through policy, approval, signing and the PEP as before.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Protocol

from ..canonical import canonical_bytes, digest
from ..crypto import Clock

MSG_INVESTIGATION_REPORT = "investigation_report"
MSG_ACTION_REQUEST = "action_request"
ALLOWED_MESSAGE_TYPES = frozenset({MSG_INVESTIGATION_REPORT, MSG_ACTION_REQUEST})


class AuditSink(Protocol):
    def append(self, entry_type: str, case_id: str, obj: Dict[str, Any], refs: Optional[Dict[str, str]] = None) -> Any: ...


class AuditUnavailable(Exception):
    """Raised by an audit sink that cannot persist (disk full, ledger domain down, ...)."""


@dataclass
class EgressConfig:
    max_msg_bytes: int = 32768
    max_per_minute: int = 30
    # Ablation only: when True the proxy forwards even if the audit write failed.
    fail_open_on_audit_error: bool = False


@dataclass
class EgressResult:
    ok: bool
    code: str  # OK | MALFORMED | REJECTED_BY_PROXY | RATE_LIMITED | AUDIT_UNAVAILABLE
    msg_type: Optional[str]
    msg_digest: Optional[str]
    agent_id: str
    size: int = 0


@dataclass
class ControlledEgressProxy:
    audit: AuditSink
    channel_agent_id: str
    clock: Clock
    config: EgressConfig = field(default_factory=EgressConfig)
    _times: List[datetime] = field(default_factory=list)
    dropped: List[EgressResult] = field(default_factory=list)

    def _log(self, entry_type: str, case_id: str, obj: Dict[str, Any], refs: Optional[Dict[str, str]] = None) -> bool:
        try:
            self.audit.append(entry_type, case_id, obj, refs)
            return True
        except Exception:  # any persistence failure is treated as "audit unavailable"
            return False

    def forward(self, msg_type: str, payload: Dict[str, Any], case_id: str) -> EgressResult:
        """Audit then admit ``payload``. Returns a result; the caller must honour ``ok``."""
        try:
            raw = canonical_bytes(payload)
            size = len(raw)
            mdigest = digest(payload)
        except (TypeError, ValueError):
            res = EgressResult(False, "MALFORMED", None, None, self.channel_agent_id)
            self.dropped.append(res)
            return res

        if msg_type not in ALLOWED_MESSAGE_TYPES or size > self.config.max_msg_bytes:
            self._log("egress_dropped", case_id, {"reason": "type_or_size", "msg_type": msg_type, "size": size},
                      {"agent_id": self.channel_agent_id})
            res = EgressResult(False, "REJECTED_BY_PROXY", msg_type, mdigest, self.channel_agent_id, size)
            self.dropped.append(res)
            return res

        now = self.clock.now()
        self._times = [t for t in self._times if (now - t).total_seconds() < 60]
        if len(self._times) >= self.config.max_per_minute:
            self._log("egress_dropped", case_id, {"reason": "rate_limit", "msg_type": msg_type},
                      {"agent_id": self.channel_agent_id})
            res = EgressResult(False, "RATE_LIMITED", msg_type, mdigest, self.channel_agent_id, size)
            self.dropped.append(res)
            return res
        self._times.append(now)

        # Log first. The claimed identity inside the payload is irrelevant; the channel decides.
        logged = self._log("agent_egress", case_id, {"msg_type": msg_type, "msg_digest": mdigest, "size": size},
                           {"agent_id": self.channel_agent_id, "msg_digest": mdigest})
        if not logged and not self.config.fail_open_on_audit_error:
            res = EgressResult(False, "AUDIT_UNAVAILABLE", msg_type, mdigest, self.channel_agent_id, size)
            self.dropped.append(res)
            return res
        return EgressResult(True, "OK", msg_type, mdigest, self.channel_agent_id, size)


class FailingAudit:
    """Test double: an audit sink whose writes fail (simulates the log domain being down)."""

    def __init__(self, inner: Optional[AuditSink] = None, fail: bool = True) -> None:
        self.inner = inner
        self.fail = fail
        self.attempts = 0

    def append(self, entry_type: str, case_id: str, obj: Dict[str, Any], refs: Optional[Dict[str, str]] = None) -> Any:
        self.attempts += 1
        if self.fail:
            raise AuditUnavailable("audit domain unreachable")
        if self.inner is not None:
            return self.inner.append(entry_type, case_id, obj, refs)
        return None
