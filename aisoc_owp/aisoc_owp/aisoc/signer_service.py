"""Agent Sign service. Runs OUTSIDE the sandbox; the private key never enters it.

Every decision the agent wants to act on gets its own signature: single-use nonce, short
expiry, scope bound to (action, args digest, evidence digest). The agent cannot sign
anything itself; it can only ask. A compromised agent therefore gets, at best, signatures
for actions already inside its WorkOrder/grant, rate limited, each recorded in the ledger."""
import re
import secrets

from .canon import digest
from .crypto import sign_payload
from .hashchain import AuditWriteError
from .policy import State, resolve, validate_args

HEX64 = re.compile(r"^[0-9a-f]{64}$")


class AgentRegistry:
    def __init__(self, agents):
        self.agents, self.revoked = set(agents), set()


class AgentSignService:
    ROLE = "agent_sign"
    REQ_KEYS = {"request_id", "agent_id", "work_order_id", "action", "args",
                "evidence_sha256", "ttl_s"}

    def __init__(self, keypair, registry, wo, grant, profile, ledger, clock, max_per_minute=10):
        self.kp, self.registry = keypair, registry
        self.wo, self.grant, self.profile = wo, grant, profile
        self.ledger, self.clock = ledger, clock
        self.max_per_minute = max_per_minute
        self._seen_requests, self._times = set(), {}

    def _deny(self, code, req=None):
        try:
            self.ledger.append({"type": "sign_denied", "code": code,
                                "agent_id": (req or {}).get("agent_id"),
                                "action": (req or {}).get("action")})
        except AuditWriteError:
            return {"ok": False, "code": "AUDIT_UNAVAILABLE", "signed": None, "resolution": None}
        return {"ok": False, "code": code, "signed": None, "resolution": None}

    def request(self, req: dict) -> dict:
        if not isinstance(req, dict) or set(req) != self.REQ_KEYS:
            return self._deny("BAD_REQUEST")
        agent = req["agent_id"]
        if agent not in self.registry.agents or agent in self.registry.revoked:
            return self._deny("AGENT_NOT_ACTIVE", req)
        now = self.clock.now()
        times = [t for t in self._times.get(agent, []) if now - t < 60]
        if len(times) >= self.max_per_minute:
            self._times[agent] = times
            return self._deny("RATE_LIMITED", req)
        self._times[agent] = times + [now]
        if req["request_id"] in self._seen_requests:
            return self._deny("REQUEST_REPLAY", req)
        self._seen_requests.add(req["request_id"])
        if req["work_order_id"] != self.wo.work_order_id:
            return self._deny("WRONG_WORK_ORDER", req)
        if not (isinstance(req["evidence_sha256"], str) and HEX64.match(req["evidence_sha256"])):
            return self._deny("BAD_EVIDENCE_HASH", req)
        ttl = req["ttl_s"]
        if not (isinstance(ttl, int) and 0 < ttl <= self.wo.max_ttl_s):
            return self._deny("BAD_TTL", req)
        bad = validate_args(req["action"], req["args"])
        if bad:
            return self._deny(bad, req)
        res = resolve(req["action"], self.wo, self.grant, self.profile)
        if res.state is State.DENIED:
            return self._deny(res.code, req)
        payload = {
            "type": "agent_decision", "agent_id": agent,
            "work_order_id": self.wo.work_order_id, "action": req["action"],
            "args": req["args"], "args_digest": digest(req["args"]),
            "evidence_sha256": req["evidence_sha256"], "resolution": res.state.value,
            "issued_at": now, "expires_at": now + ttl, "single_use": True,
            "nonce": secrets.token_hex(16),
        }
        signed = sign_payload(self.kp, payload)
        try:
            self.ledger.append({"type": "decision_signed", "signed": signed})
        except AuditWriteError:
            return {"ok": False, "code": "AUDIT_UNAVAILABLE", "signed": None, "resolution": None}
        return {"ok": True, "code": "OK", "signed": signed, "resolution": res.state.value}
