"""Policy Enforcement Point: the only place actions actually run (outside the sandbox).

It trusts nothing the agent says. It re-verifies signature, role, expiry, scope, nonce,
re-resolves authority itself, demands a bound Acceptor signature for reserved actions,
and writes an intent record BEFORE acting (write-ahead, fail closed)."""
from dataclasses import dataclass

from .canon import digest
from .crypto import verify_signed
from .hashchain import AuditWriteError
from .policy import HUMAN_REQUIRED, State, resolve


@dataclass
class Result:
    ok: bool
    code: str
    detail: object = None


class Executor:
    def __init__(self, keyring, revoked, wo, grant, profile, ledger, clock, handlers, owp_hook=None):
        self.keyring, self.revoked = keyring, revoked
        self.wo, self.grant, self.profile = wo, grant, profile
        self.ledger, self.clock, self.handlers = ledger, clock, handlers
        self.owp_hook = owp_hook   # optional extra check, e.g. OpenWorkProof policy.authorize_tool_call
        self._used = {e["payload"]["nonce"] for e in ledger.entries
                      if e["payload"].get("type") == "exec_intent"}   # survives restarts

    def _fail(self, code, signed=None):
        try:
            self.ledger.append({"type": "exec_denied", "code": code,
                                "decision_digest": (signed or {}).get("digest")})
        except AuditWriteError:
            return Result(False, "AUDIT_UNAVAILABLE")
        return Result(False, code)

    def execute(self, signed: dict, acceptance: dict = None) -> Result:
        ok, code = verify_signed(signed, self.keyring, "agent_sign", self.revoked)
        if not ok:
            return self._fail(code, signed if isinstance(signed, dict) else None)
        if signed.get("type") != "agent_decision":
            return self._fail("WRONG_TYPE", signed)
        now = self.clock.now()
        if not (signed["issued_at"] <= now <= signed["expires_at"]):
            return self._fail("EXPIRED", signed)
        if signed["work_order_id"] != self.wo.work_order_id:
            return self._fail("SCOPE_MISMATCH", signed)
        args = signed["args"]
        if digest(args) != signed["args_digest"]:
            return self._fail("DIGEST_MISMATCH", signed)
        res = resolve(signed["action"], self.wo, self.grant, self.profile)
        if res.state is State.DENIED:
            return self._fail("DENIED_BY_POLICY", signed)
        if signed["resolution"] != res.state.value:
            return self._fail("POLICY_DRIFT", signed)
        if signed["nonce"] in self._used:
            return self._fail("REPLAY", signed)

        if res.state is State.RESERVED:
            if acceptance is None:
                return self._fail(HUMAN_REQUIRED, signed)
            ok, code = verify_signed(acceptance, self.keyring, "acceptor", self.revoked)
            if not ok:
                return self._fail("ACCEPTANCE_" + code, signed)
            if acceptance.get("type") != "acceptance" or any(
                    acceptance.get(k) != signed.get(v) for k, v in (
                        ("decision_digest", "digest"), ("work_order_id", "work_order_id"),
                        ("action", "action"), ("args_digest", "args_digest"),
                        ("evidence_sha256", "evidence_sha256"))):
                return self._fail("ACCEPTANCE_MISMATCH", signed)
            if acceptance["verdict"] != "approve":
                return self._fail("ACCEPTANCE_REJECTED", signed)
            if now > acceptance["expires_at"]:
                return self._fail("ACCEPTANCE_EXPIRED", signed)

        if self.owp_hook is not None and not self.owp_hook(signed):
            return self._fail("OWP_POLICY_DENY", signed)
        handler = self.handlers.get(signed["action"])
        if handler is None:
            return self._fail("NO_HANDLER", signed)

        try:   # write-ahead: record intent first; mark nonce used even if we crash later
            self.ledger.append({"type": "exec_intent", "decision_digest": signed["digest"],
                                "nonce": signed["nonce"], "acceptance": acceptance})
        except AuditWriteError:
            return Result(False, "AUDIT_UNAVAILABLE")
        self._used.add(signed["nonce"])
        outcome = handler(args, signed["expires_at"] - now)
        try:
            self.ledger.append({"type": "exec_result", "decision_digest": signed["digest"],
                                "outcome": outcome})
        except AuditWriteError:
            return Result(True, "OK_UNLOGGED_RESULT", outcome)   # action ran; alert operators
        return Result(True, "OK", outcome)
