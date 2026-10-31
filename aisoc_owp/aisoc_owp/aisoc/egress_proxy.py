"""Controlled egress proxy: the sandbox's ONLY way out (vsock/unix socket in production).

Complete mediation + accountability: every message is audit-logged BEFORE it is forwarded.
If the audit log cannot be written the message is dropped (fail-secure). It also enforces
message type/size allow-list and a rate limit, and it overrides agent_id with the identity
bound to the channel so the agent cannot impersonate another agent."""
from .canon import digest
from .hashchain import AuditWriteError


class ControlledEgressProxy:
    ALLOWED_TYPES = {"verdict", "decision_request"}

    def __init__(self, audit, signer, channel_agent_id, clock,
                 max_msg_bytes=16384, max_per_minute=30):
        self.audit, self.signer, self.agent_id, self.clock = audit, signer, channel_agent_id, clock
        self.max_msg_bytes, self.max_per_minute = max_msg_bytes, max_per_minute
        self.soc_queue, self.pending, self._times = [], [], []

    def _log(self, payload) -> bool:
        try:
            self.audit.append(payload)
            return True
        except AuditWriteError:
            return False

    def forward(self, msg: dict) -> dict:
        now = self.clock.now()
        try:
            size = len(repr(msg))
            mtype = msg.get("type") if isinstance(msg, dict) else None
            mdigest = digest(msg)
        except (ValueError, TypeError, AttributeError):
            return {"ok": False, "code": "MALFORMED"}
        if mtype not in self.ALLOWED_TYPES or size > self.max_msg_bytes:
            self._log({"type": "proxy_drop", "reason": "type_or_size", "msg_type": str(mtype)})
            return {"ok": False, "code": "REJECTED_BY_PROXY"}
        self._times = [t for t in self._times if now - t < 60]
        if len(self._times) >= self.max_per_minute:
            self._log({"type": "proxy_drop", "reason": "rate_limit"})
            return {"ok": False, "code": "RATE_LIMITED"}
        self._times.append(now)
        if not self._log({"type": "proxy_in", "agent": self.agent_id,
                          "msg_type": mtype, "msg_digest": mdigest}):
            return {"ok": False, "code": "AUDIT_UNAVAILABLE"}      # log first, else no forward

        if mtype == "verdict":
            self.soc_queue.append(msg)
            return {"ok": True, "code": "OK"}
        req = dict(msg)
        req.pop("type")
        req["agent_id"] = self.agent_id                              # channel-bound identity
        resp = self.signer.request(req)
        if resp["ok"]:
            self.pending.append(resp["signed"])                      # goes to analyst/executor, NOT back to agent
            self._log({"type": "proxy_out", "decision_digest": resp["signed"]["digest"]})
            return {"ok": True, "code": "OK", "resolution": resp["resolution"]}
        self._log({"type": "proxy_out", "denied": resp["code"]})
        return {"ok": False, "code": resp["code"]}
