import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aisoc.canon import digest, sha256_hex                     # noqa: E402
from aisoc.crypto import KeyPair, register, sign_payload, verify_signed  # noqa: E402
from aisoc.demo import NORMAL, ZERO_DAY                         # noqa: E402
from aisoc.detect import ModelVerificationError, load_verified_model, release_model  # noqa: E402
from aisoc.executor import Executor                             # noqa: E402
from aisoc.hashchain import AuditWriteError, HashChain, make_anchor, verify_entries  # noqa: E402
from aisoc.policy import CapabilityGrant, State, resolve        # noqa: E402
from aisoc.verifier import verify_bundle                        # noqa: E402
from aisoc.wiring import build_world                            # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.w = build_world(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def zero_day(self):
        res = self.w.runtime.process_window(ZERO_DAY, "win-1", "10.0.0.5")
        return res, self.w.proxy.pending.pop(0)


class TestDetection(Base):
    def test_zero_day_flagged_and_normal_not(self):
        self.assertTrue(self.w.runtime.process_window(ZERO_DAY, "w", "h")["suspected"])
        self.assertFalse(self.w.runtime.process_window(NORMAL, "w2", "h")["suspected"])

    def test_tampered_model_rejected_at_release_gate(self):
        kp, ring = KeyPair(), {}
        register(ring, kp, "model_release")
        blob, manifest = release_model({"a": 1}, kp, "m", "1", sha256_hex(b"d"))
        with self.assertRaises(ModelVerificationError):
            load_verified_model(blob + b" ", manifest, ring)
        other, ring2 = KeyPair(), {}
        register(ring2, other, "agent_sign")
        with self.assertRaises(ModelVerificationError):
            load_verified_model(blob, manifest, ring2)


class TestEscapeAttacks(Base):
    def test_forged_signature_rejected(self):
        _, s = self.zero_day()
        body = {k: v for k, v in s.items() if k not in ("signature_alg", "signer_key_id", "digest", "signature")}
        self.assertEqual(self.w.executor.execute(sign_payload(KeyPair(), body)).code, "UNKNOWN_SIGNER")
        spoof = {**sign_payload(KeyPair(), body), "signer_key_id": s["signer_key_id"]}
        self.assertEqual(self.w.executor.execute(spoof).code, "BAD_SIGNATURE")

    def test_tampered_args_rejected(self):
        _, s = self.zero_day()
        t = copy.deepcopy(s); t["args"]["host"] = "10.9.9.9"
        self.assertEqual(self.w.executor.execute(t).code, "DIGEST_MISMATCH")

    def test_reserved_action_needs_human(self):
        _, s = self.zero_day()
        self.assertEqual(self.w.executor.execute(s).code, "AGENCY_HUMAN_DECISION_REQUIRED")

    def test_reject_verdict_blocks_execution(self):
        _, s = self.zero_day()
        r = self.w.executor.execute(s, self.w.acceptor.decide(s, "reject"))
        self.assertEqual(r.code, "ACCEPTANCE_REJECTED")

    def test_acceptance_bound_to_one_decision(self):
        res, _ = self.zero_day()
        ev = res["evidence_sha256"]
        self.w.runtime.request_egress("203.0.113.7", 443, "tcp", ev)
        self.w.runtime.request_egress("198.51.100.9", 443, "tcp", ev)
        a, b = self.w.proxy.pending[0], self.w.proxy.pending[1]
        acc_a = self.w.acceptor.decide(a, "approve")
        self.assertEqual(self.w.executor.execute(b, acc_a).code, "ACCEPTANCE_MISMATCH")
        r = self.w.executor.execute(a, acc_a)
        self.assertTrue(r.ok)
        self.assertEqual(r.detail["dst_ip"], "203.0.113.7")

    def test_replay_rejected_even_after_restart(self):
        _, s = self.zero_day()
        acc = self.w.acceptor.decide(s, "approve")
        self.assertTrue(self.w.executor.execute(s, acc).ok)
        self.assertEqual(self.w.executor.execute(s, acc).code, "REPLAY")
        w = self.w
        restarted = Executor(w.keyring, w.revoked, w.wo, w.executor.grant, w.executor.profile,
                             w.ledger, w.clock, w.executor.handlers)
        self.assertEqual(restarted.execute(s, acc).code, "REPLAY")

    def test_expiry(self):
        _, s = self.zero_day()
        acc = self.w.acceptor.decide(s, "approve")
        self.w.clock.advance(10_000)
        self.assertEqual(self.w.executor.execute(s, acc).code, "EXPIRED")

    def test_out_of_scope_requests_denied(self):
        ev = "0" * 64
        base = {"type": "decision_request", "agent_id": "root", "work_order_id": self.w.wo.work_order_id,
                "evidence_sha256": ev, "ttl_s": 60}
        r1 = self.w.channel.send({**base, "request_id": "a", "action": "delete_logs", "args": {}})
        r2 = self.w.channel.send({**base, "request_id": "b", "action": "block_flow", "args": {
            "src_ip": "10.0.0.5", "dst_ip": "10.0.0.9", "dst_port": 22, "proto": "tcp"}})
        r3 = self.w.channel.send({**base, "request_id": "c", "action": "egress_connect",
                                  "args": {"dst_ip": "not-an-ip", "dst_port": 443, "proto": "tcp"}})
        r4 = self.w.channel.send({**base, "request_id": "d", "action": "egress_connect", "ttl_s": 99999,
                                  "args": {"dst_ip": "203.0.113.7", "dst_port": 443, "proto": "tcp"}})
        self.assertEqual([r["code"] for r in (r1, r2, r3, r4)],
                         ["UNKNOWN_ACTION", "NOT_IN_WORK_ORDER", "BAD_ARGS", "BAD_TTL"])
        self.assertEqual(self.w.proxy.pending, [])

    def test_agent_cannot_impersonate_or_get_signed_object_back(self):
        res, _ = self.zero_day()
        self.assertNotIn("signed", res["decision"])
        s = self.w.proxy.pending
        self.w.runtime.request_egress("203.0.113.7", 443, "tcp", res["evidence_sha256"])
        self.assertEqual(self.w.proxy.pending[-1]["agent_id"], "soc-agent-01")

    def test_revoked_agent_and_revoked_key(self):
        self.w.registry.revoked.add("soc-agent-01")
        res = self.w.runtime.process_window(ZERO_DAY, "w", "h")
        self.assertEqual(res["decision"]["code"], "AGENT_NOT_ACTIVE")
        self.w.registry.revoked.clear()
        _, s = self.zero_day()
        acc = self.w.acceptor.decide(s, "approve")
        self.w.revoked.add(s["signer_key_id"])
        self.assertEqual(self.w.executor.execute(s, acc).code, "KEY_REVOKED")

    def test_rate_limit(self):
        w = build_world(self.tmp.name + "/rl", max_sign_per_minute=3)
        res = w.runtime.process_window(ZERO_DAY, "w", "h")
        codes = [w.runtime.request_egress("203.0.113.7", 443, "tcp", res["evidence_sha256"])["code"]
                 for _ in range(5)]
        self.assertIn("RATE_LIMITED", codes)

    def test_agent_runtime_holds_no_secrets(self):
        names = " ".join(vars(self.w.runtime)).lower()
        self.assertNotIn("key", names)
        self.assertFalse(hasattr(self.w.runtime, "executor"))


class TestFailClosed(Base):
    def test_audit_unavailable_blocks_forwarding(self):
        def boom(line): raise AuditWriteError("disk gone")
        self.w.audit._write_line = boom
        r = self.w.runtime.process_window(ZERO_DAY, "w", "h")
        self.assertEqual(r["decision"]["code"], "AUDIT_UNAVAILABLE")
        self.assertEqual(self.w.proxy.pending, [])
        self.assertEqual(self.w.proxy.soc_queue, [])

    def test_ledger_unavailable_blocks_execution(self):
        _, s = self.zero_day()
        acc = self.w.acceptor.decide(s, "approve")
        def boom(line): raise AuditWriteError("disk gone")
        self.w.ledger._write_line = boom
        self.assertEqual(self.w.executor.execute(s, acc).code, "AUDIT_UNAVAILABLE")


class TestOfflineVerification(Base):
    def full_run(self):
        res, _ = self.zero_day()
        self.w.runtime.process_window(ZERO_DAY, "win-1", "10.0.0.5")
        for s, acc, r in self.w.handle_pending():
            self.assertTrue(r.ok)
        return res

    def test_clean_ledger_verifies(self):
        self.full_run()
        self.assertEqual(verify_bundle(self.w.ledger.entries, self.w.keyring), [])

    def test_content_tamper_detected(self):
        self.full_run()
        e = copy.deepcopy(self.w.ledger.entries)
        i = next(n for n, x in enumerate(e) if x["payload"].get("type") == "decision_signed")
        e[i]["payload"]["signed"]["args"] = {"host": "evil"}
        self.assertTrue(verify_bundle(e, self.w.keyring))

    def test_deleted_entry_detected(self):
        self.full_run()
        e = copy.deepcopy(self.w.ledger.entries)
        del e[1]
        self.assertTrue(verify_entries(e))

    def test_coherent_rewrite_needs_external_anchor(self):
        self.full_run()
        anchor = make_anchor(self.w.ledger, self.w.kp_log, "ledger", self.w.clock)
        # attacker rebuilds a self-consistent shorter chain: internal checks pass...
        short = self.w.ledger.entries[:2]
        rebuilt = HashChain(self.tmp.name + "/rebuilt.jsonl", self.w.clock)
        for e in short:
            rebuilt.append(e["payload"])
        self.assertEqual(verify_entries(rebuilt.entries), [])
        # ...but the externally stored anchor exposes the rollback
        self.assertTrue(verify_bundle(rebuilt.entries, self.w.keyring, anchor=anchor))

    def test_execution_without_acceptance_is_flagged_offline(self):
        _, s = self.zero_day()
        led = self.w.ledger
        led.append({"type": "exec_intent", "decision_digest": s["digest"], "nonce": s["nonce"], "acceptance": None})
        findings = verify_bundle(led.entries, self.w.keyring)
        self.assertTrue(any("reserved action without valid acceptance" in f for f in findings))

    def test_egress_destination_mismatch_flagged(self):
        res, _ = self.zero_day()
        self.w.runtime.request_egress("203.0.113.7", 443, "tcp", res["evidence_sha256"])
        s = self.w.proxy.pending.pop(0)
        acc = self.w.acceptor.decide(s, "approve")
        self.assertTrue(self.w.executor.execute(s, acc).ok)
        self.w.ledger.append({"type": "exec_result", "decision_digest": s["digest"],
                              "outcome": {"dst_ip": "198.51.100.9", "dst_port": 443, "proto": "tcp"}})
        self.assertTrue(any("not in the signed decision" in f
                            for f in verify_bundle(self.w.ledger.entries, self.w.keyring)))

    def test_evidence_substitution_flagged(self):
        res = self.full_run()
        store = {res["evidence_sha256"]: {**res["output"], "case_id": "swapped"}}
        self.assertTrue(any("evidence" in f for f in
                            verify_bundle(self.w.ledger.entries, self.w.keyring, evidence_store=store)))


class TestPolicy(unittest.TestCase):
    def test_grants_only_attenuate(self):
        g = CapabilityGrant("r", frozenset({"a", "b"}))
        self.assertEqual(g.attenuate("c", {"a"}).actions, frozenset({"a"}))
        with self.assertRaises(ValueError):
            g.attenuate("c", {"a", "z"})

    def test_floats_rejected_in_signed_payload(self):
        with self.assertRaises(ValueError):
            digest({"x": 0.5})


if __name__ == "__main__":
    unittest.main(verbosity=2)
