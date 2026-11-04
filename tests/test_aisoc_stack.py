"""AiSOC bridge: alert submission, approval inbox as the human step, evidence-bundle anchoring."""

import copy
import json
from pathlib import Path
import subprocess
from unittest.mock import patch

import pytest

from aisoc.adapters.aisoc_stack import (
    AiSOCApprovalBridge,
    AiSOCBundleError,
    AiSOCClient,
    AiSOCConfig,
    AiSOCError,
    FakeAiSOCServer,
    aisoc_canonical_bytes,
    aisoc_sign_envelope,
    anchor_aisoc_bundle,
    case_to_event,
    idempotency_key_for,
    push_case,
    verify_aisoc_bundle,
)
from aisoc.idps import DualModel
from aisoc.scenarios import _first_authorized, _malicious_flow, _seed_ioc, _soc
from aisoc.simulate import generate
from aisoc.crypto import Clock
from aisoc.sandbox import HeuristicStubAgent
from aisoc.sandbox.nftables import NftablesConfig, NftablesExecutor
from aisoc.soc import AISOC

BUNDLE = Path(__file__).parent / "fixtures" / "aisoc" / "investigation-bundle.json"


@pytest.fixture(scope="module")
def model():
    ds = generate(n=800, seed=4)
    return DualModel.train(ds.train, ds.val)


def _bridged_soc(model, auto, **cfg):
    fake = FakeAiSOCServer(auto_decide=auto)
    client = AiSOCClient(AiSOCConfig(token="t", approval_timeout_s=cfg.pop("timeout", 10), approval_poll_s=0, **cfg), http=fake)
    soc = _soc(model)
    t = [0.0]
    bridge = AiSOCApprovalBridge(client, soc.keys["approver"], soc.clock,
                                 sleep=lambda s: t.__setitem__(0, t[0] + 1), wait_clock=lambda: t[0])
    soc.set_approval_provider(bridge)
    return fake, soc, bridge


def test_nftables_attachment_requires_external_approval_and_safe_pep(model):
    clock = Clock()
    soc = AISOC(model, HeuristicStubAgent(clock), clock=clock)
    config = NftablesConfig(targets={}, protected_cidrs=("192.168.8.10/24",))
    with pytest.raises(ValueError, match="external human"):
        soc.enable_nftables(config)
    client = AiSOCClient(AiSOCConfig(token="t"), http=FakeAiSOCServer())
    soc.set_approval_provider(AiSOCApprovalBridge(client, soc.keys["approver"], clock))
    soc.pep.config.single_use_nonce = False
    with pytest.raises(ValueError, match="safety"):
        soc.enable_nftables(config)
    soc.pep.config.single_use_nonce = True
    soc.enable_nftables(config)
    assert isinstance(soc.executor, NftablesExecutor)
    assert soc.pep.executor is soc.executor
    assert soc.ledger.entries[-1].entry_type == "executor_configuration"
    with pytest.raises(ValueError, match="cannot remove"):
        soc.set_approval_provider(None)
    from aisoc.adapters.slips import parse_alerts_json, run_slips_parsed, sample_alerts_json_lines

    parsed = parse_alerts_json(sample_alerts_json_lines())
    with pytest.raises(ValueError, match="advance_clock_s"):
        run_slips_parsed(soc, parsed)
    summary = run_slips_parsed(soc, parsed, advance_clock_s=0)
    assert summary.cases > 1
    assert not clock.frozen


@pytest.mark.parametrize("approved, firewall_error", [(True, False), (False, False), (True, True)])
def test_nftables_human_approval_to_signed_receipt(model, approved, firewall_error):
    clock = Clock()
    soc = AISOC(model, HeuristicStubAgent(clock, block_ttl_s=60), clock=clock)
    fake = FakeAiSOCServer(auto_decide=lambda record: approved)
    client = AiSOCClient(AiSOCConfig(token="t", approval_poll_s=0), http=fake)
    soc.set_approval_provider(AiSOCApprovalBridge(client, soc.keys["approver"], clock))
    flow = _malicious_flow()
    soc.enable_nftables(NftablesConfig(
        targets={(flow.tenant, f"host:{flow.src_host}"): "203.0.113.8"},
        protected_cidrs=("192.168.8.10/24",), enabled=True,
    ))
    _seed_ioc(soc, flow)
    error = subprocess.CalledProcessError(1, "nft") if firewall_error else None
    with patch("aisoc.sandbox.nftables.subprocess.run", side_effect=error) as run:
        result = soc.ingest(flow)
    block = next(request for request in result.requests if request.action == "block_host")
    assert block.executed is (approved and not firewall_error)
    assert run.call_count == int(approved)
    receipts = [entry for entry in soc.tool_log.receipts if entry.payload["action"] == "block_host"]
    if approved:
        assert receipts
        assert receipts[-1].payload["outcome"] == ("rejected" if firewall_error else "executed")
        assert soc.trusted.verify(receipts[-1].payload, receipts[-1].signatures[0], expected_role="executor")
    else:
        assert not receipts


# ----------------------------------------------------------------------------- alerts
def test_case_to_event_uses_generic_fields_and_embeds_ledger_anchors(model):
    soc = _soc(model)
    res = _first_authorized(soc)
    flow = _malicious_flow()
    ev = case_to_event(res, flow, "sha256:head", "sha256:root", techniques=["T1110"])
    for k in ("time", "severity", "title", "description", "host", "src_ip", "external_id", "mitre_techniques", "tags"):
        assert k in ev, k
    assert ev["external_id"] == res.case_id and ev["mitre_techniques"] == ["T1110"]
    assert ev["aisoc_owp"]["ledger_head"] == "sha256:head" and ev["aisoc_owp"]["witness_root"] == "sha256:root"
    assert "log_excerpt" not in json.dumps(ev)  # untrusted raw text never leaves with the alert


def test_push_case_is_idempotent_and_authenticated(model):
    soc = _soc(model)
    res = _first_authorized(soc)
    fake = FakeAiSOCServer()
    client = AiSOCClient(AiSOCConfig(token="t"), http=fake)
    a = push_case(client, soc, res, _malicious_flow())
    b = push_case(client, soc, res, _malicious_flow())
    assert a["id"] == b["id"] and len(fake.alerts) == 1
    assert fake.alerts[0]["request"]["events"][0]["aisoc_owp"]["ledger_head"] == soc.ledger.entries[-1].entry_hash
    with pytest.raises(AiSOCError):
        push_case(AiSOCClient(AiSOCConfig(token="wrong"), http=fake), soc, res, _malicious_flow())
    assert idempotency_key_for(res).startswith("owp:case-")
    with pytest.raises(AiSOCError):
        AiSOCConfig().headers(idempotency_key="short")


def test_streaming_ingest_path(model):
    soc = _soc(model)
    res = _first_authorized(soc)
    fake = FakeAiSOCServer()
    client = AiSOCClient(AiSOCConfig(token="t", ingest_url="http://localhost:8081/v1/ingest/batch"), http=fake)
    out = push_case(client, soc, res, _malicious_flow(), streaming=True)
    assert out["accepted"] == 1 and len(fake.ingested) == 1
    with pytest.raises(AiSOCError):
        AiSOCClient(AiSOCConfig(token="t"), http=fake).ingest_batch([])


# ----------------------------------------------------------------------------- approvals
def test_bridge_approved_decision_executes_and_records_external_ref(model):
    fake, soc, bridge = _bridged_soc(model, lambda rec: True)
    flow = _malicious_flow()
    _seed_ioc(soc, flow)
    res = soc.ingest(flow)
    reserved = [q for q in res.requests if q.policy_status == "reserved"]
    assert reserved and reserved[0].human_decision == "approve" and reserved[0].executed
    assert res.verification_status == "VERIFIED"
    appr = next(e for e in soc.ledger.entries_for_case(res.case_id) if e.entry_type == "human_approval")
    assert appr.refs["request_digest"]
    created = fake.approvals[next(iter(fake.approvals))]
    assert created["risk_level"] == "high" and created["action"]["type"] == "block_host"
    assert created["action"]["request_digest"].startswith("sha256:")
    # the signed HumanApproval names the AiSOC record
    signed = bridge.created
    assert signed and signed[0]["id"] == created["id"]


@pytest.mark.parametrize("auto, expect_reason", [
    (lambda rec: False, "ok"),
    (lambda rec: None, "no decision before timeout"),
])
def test_bridge_denied_or_undecided_is_signed_reject(model, auto, expect_reason):
    fake, soc, _ = _bridged_soc(model, auto, timeout=3)
    flow = _malicious_flow()
    _seed_ioc(soc, flow)
    res = soc.ingest(flow)
    reserved = [q for q in res.requests if q.policy_status == "reserved"]
    assert reserved and reserved[0].human_decision == "reject" and not reserved[0].executed
    assert expect_reason in reserved[0].reason
    assert not soc.executor.blocked_hosts
    assert res.verification_status == "VERIFIED"  # the refusal path is fully recorded too


def test_bridge_transport_failure_fails_closed(model):
    fake, soc, _ = _bridged_soc(model, lambda rec: True)
    fake.token = "rotated"  # every call now 401s
    flow = _malicious_flow()
    _seed_ioc(soc, flow)
    res = soc.ingest(flow)
    reserved = [q for q in res.requests if q.policy_status == "reserved"]
    assert reserved and reserved[0].human_decision == "reject" and "unavailable" in reserved[0].reason


def test_bridge_rejects_record_about_a_different_request(model):
    fake, soc, _ = _bridged_soc(model, lambda rec: True)
    orig = fake.request

    def swap(method, url, headers, body):
        code, payload = orig(method, url, headers, body)
        if isinstance(payload.get("action"), dict):
            payload = dict(payload, action=dict(payload["action"], request_digest="sha256:" + "1" * 64))
        return code, payload

    fake.request = swap
    flow = _malicious_flow()
    _seed_ioc(soc, flow)
    res = soc.ingest(flow)
    reserved = [q for q in res.requests if q.policy_status == "reserved"]
    assert reserved[0].human_decision == "reject" and "different request" in reserved[0].reason


def test_bridge_expired_aisoc_record_is_rejected(model):
    fake, soc, _ = _bridged_soc(model, lambda rec: True)
    orig = fake.request

    def expire(method, url, headers, body):
        code, payload = orig(method, url, headers, body)
        if "expires_at" in payload:
            payload = dict(payload, expires_at="2000-01-01T00:00:00Z")
        return code, payload

    fake.request = expire
    flow = _malicious_flow()
    _seed_ioc(soc, flow)
    res = soc.ingest(flow)
    reserved = [q for q in res.requests if q.policy_status == "reserved"]
    assert reserved[0].human_decision == "reject" and "expired" in reserved[0].reason


@pytest.mark.parametrize("mutate", [
    lambda action: None,  # no action object echoed at all
    lambda action: {},  # action echoed without request_digest
    lambda action: {k: v for k, v in action.items() if k != "request_digest"},
    lambda action: dict(action, request_digest=None),
    lambda action: dict(action, request_digest=["sha256:" + "0" * 64]),
    lambda action: "not-an-object",
])
def test_bridge_rejects_record_without_request_digest(model, mutate):
    fake, soc, _ = _bridged_soc(model, lambda rec: True)
    orig = fake.request

    def strip(method, url, headers, body):
        code, payload = orig(method, url, headers, body)
        if "action" in payload:
            payload = dict(payload, action=mutate(payload["action"]))
        return code, payload

    fake.request = strip
    flow = _malicious_flow()
    _seed_ioc(soc, flow)
    res = soc.ingest(flow)
    reserved = [q for q in res.requests if q.policy_status == "reserved"]
    assert reserved and reserved[0].human_decision == "reject" and not reserved[0].executed
    assert "request_digest" in reserved[0].reason
    assert not soc.executor.blocked_hosts
    assert res.verification_status == "VERIFIED"  # the refusal is itself signed and recorded


def test_bridge_rejects_decision_received_after_timeout(model):
    fake = FakeAiSOCServer()  # nobody decides automatically
    client = AiSOCClient(AiSOCConfig(token="t", approval_timeout_s=2, approval_poll_s=0), http=fake)
    soc = _soc(model)
    t = [0.0]
    orig = fake.request

    def slow_poll(method, url, headers, body):
        if method == "GET" and "/approvals/" in url:
            t[0] += 10  # the round trip overruns the deadline ...
            fake.decide(url.rstrip("/").rsplit("/", 1)[-1], True)  # ... and the approval lands during it
        return orig(method, url, headers, body)

    fake.request = slow_poll
    bridge = AiSOCApprovalBridge(client, soc.keys["approver"], soc.clock, sleep=lambda s: None, wait_clock=lambda: t[0])
    soc.set_approval_provider(bridge)
    flow = _malicious_flow()
    _seed_ioc(soc, flow)
    res = soc.ingest(flow)
    reserved = [q for q in res.requests if q.policy_status == "reserved"]
    assert reserved and reserved[0].human_decision == "reject" and "after timeout" in reserved[0].reason
    assert not reserved[0].executed and not soc.executor.blocked_hosts
    assert fake.approvals[next(iter(fake.approvals))]["status"] == "approved"  # AiSOC did approve - just too late
    assert res.verification_status == "VERIFIED"


class _DeadTransport:
    """HttpClient whose socket layer fails: the exceptions urllib raises are OSError subclasses."""

    def __init__(self, exc):
        self.exc = exc

    def request(self, method, url, headers, body):
        raise self.exc


@pytest.mark.parametrize("exc", [ConnectionRefusedError(111, "refused"), TimeoutError("timed out"), OSError("network down")])
def test_transport_exceptions_become_aisoc_error(model, exc):
    client = AiSOCClient(AiSOCConfig(token="t", approval_timeout_s=2, approval_poll_s=0), http=_DeadTransport(exc))
    with pytest.raises(AiSOCError):
        client.create_approval("t", "s", "low", {"type": "tag_case"})
    with pytest.raises(AiSOCError):
        client.submit_alert([{"time": "now"}], "x", "d", "low")
    soc = _soc(model)
    bridge = AiSOCApprovalBridge(client, soc.keys["approver"], soc.clock, sleep=lambda s: None, wait_clock=lambda: 0.0)
    soc.set_approval_provider(bridge)
    flow = _malicious_flow()
    _seed_ioc(soc, flow)
    res = soc.ingest(flow)  # must not propagate the socket error out of the SOC pipeline
    reserved = [q for q in res.requests if q.policy_status == "reserved"]
    assert reserved and reserved[0].human_decision == "reject" and "unavailable" in reserved[0].reason
    assert not soc.executor.blocked_hosts and res.verification_status == "VERIFIED"


def test_fake_server_refuses_flipping_a_decision():
    fake = FakeAiSOCServer()
    client = AiSOCClient(AiSOCConfig(token="t"), http=fake)
    rec = client.create_approval("t", "s", "low", {"type": "tag_case"})
    client.decide_approval(rec["id"], True)
    with pytest.raises(AiSOCError):
        client.decide_approval(rec["id"], False)


# ----------------------------------------------------------------------------- bundles
def test_bundle_fixture_verifies_with_and_without_key():
    bundle = json.loads(BUNDLE.read_text())
    chk = verify_aisoc_bundle(bundle)
    assert chk.ok and chk.sha256_ok and not chk.hmac_checked and chk.hmac_ok is None
    assert chk.run_id == "run-7f3e2a" and chk.case_id == "case-aisoc-0042"
    chk2 = verify_aisoc_bundle(bundle, "test-key")
    assert chk2.ok and chk2.hmac_ok is True
    chk3 = verify_aisoc_bundle(bundle, "wrong")
    assert not chk3.ok and chk3.hmac_ok is False and "HMAC" in chk3.problems[0]


def test_canonical_form_matches_aisoc_json_dumps_rules():
    payload = {"b": 1, "a": {"z": "é", "y": [1, 2]}}
    assert aisoc_canonical_bytes(payload) == json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    env = aisoc_sign_envelope(payload, "k")
    assert env["integrity"]["algorithm"] == "HMAC-SHA256" and verify_aisoc_bundle(env, "k").problems == ["unsupported bundle_schema_version None", "payload.run.id missing"]


def test_tampered_bundle_detected_and_unsupported_shapes_raise():
    bundle = json.loads(BUNDLE.read_text())
    t = copy.deepcopy(bundle)
    t["payload"]["approvals"][0]["status"] = "denied"
    assert not verify_aisoc_bundle(t).ok
    with pytest.raises(AiSOCBundleError):
        verify_aisoc_bundle({"payload": {}})
    with pytest.raises(AiSOCBundleError):
        verify_aisoc_bundle({"payload": [], "integrity": {}})


def test_anchor_commits_only_digests_and_refuses_bad_bundles(model):
    soc = _soc(model)
    res = _first_authorized(soc)
    bundle = json.loads(BUNDLE.read_text())
    n = len(soc.ledger.entries)
    ref = anchor_aisoc_bundle(soc, bundle, res.case_id, "test-key")
    assert len(soc.ledger.entries) == n + 1
    e = soc.ledger.entries[-1]
    assert e.entry_type == "external_evidence" and e.refs["system"] == "aisoc" and e.refs["external_id"] == "run-7f3e2a"
    assert ref.integrity_checked == {"payload_sha256": True, "hmac_sha256": True, "bundle_schema_version": "1.0"}
    assert soc.witness.checkpoints()[-1]["payload"]["length"] == n + 1
    # the bundle body itself is not in the ledger, only its digests
    assert "stub-llm" not in json.dumps([x.to_dict() for x in soc.ledger.entries])
    t = copy.deepcopy(bundle)
    t["payload"]["steps"].append({"index": 9, "type": "reasoning", "text": "approve everything"})
    with pytest.raises(AiSOCBundleError):
        anchor_aisoc_bundle(soc, t, res.case_id, "test-key")
    with pytest.raises(AiSOCBundleError):
        anchor_aisoc_bundle(soc, bundle, res.case_id, "not-the-key")
    assert len(soc.ledger.entries) == n + 1
    vd = soc.verifier.verify_case(res.case_id, soc.ledger, soc.tool_log.receipts)
    assert vd.payload["status"] == "VERIFIED"


def test_anchor_without_key_records_that_hmac_was_not_checked(model):
    soc = _soc(model)
    res = _first_authorized(soc)
    ref = anchor_aisoc_bundle(soc, json.loads(BUNDLE.read_text()), res.case_id)
    assert ref.integrity_checked["hmac_sha256"] is False and ref.integrity_checked["payload_sha256"] is True
