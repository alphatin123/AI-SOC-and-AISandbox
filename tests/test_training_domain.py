"""Architecture 1: the offline training domain.

數據採集與標註 → 數據校驗與清洗 → [已知攻擊模型 | 異常檢測模型] → 對抗與穩健性評估 → 模型登記+簽名 → 模型發布閘門

Every box has a test here, plus the CLI round trip that hands the signed release to the
inference domain (`slips-ingest --release-dir`) and re-verifies the ledger offline.
"""
import hashlib
import io
import json
from contextlib import redirect_stderr, redirect_stdout

import pytest

from aisoc.adapters.slips import ZeekConnIndex, parse_alerts_json
from aisoc.canonical import sha256_hex
from aisoc.crypto import Clock, Ed25519Signer, TrustedKeys
from aisoc.idps import BENIGN, FEATURE_SCHEMA_VERSION, MODEL_RELEASE_ROLE, FlowRecord, ModelReleaseError, verify_release
from aisoc.soc import AISOC
from aisoc.training import (
    DATASET_CURATOR_ROLE,
    DATASET_MANIFEST_SCHEMA,
    LABEL_RULE_VERSION,
    DatasetSnapshotError,
    TrainingDomainError,
    build_flow_records,
    build_snapshot,
    load_release_dir,
    load_snapshot,
    time_split,
    train_offline,
    validate_and_clean,
    write_snapshot,
    write_training_output,
)
from aisoc.training.dataset import UNLABELED_ANOMALY, trusted_keys_from_export
from aisoc.training.offline import STAGE_NAMES, TRAINING_REPORT_SCHEMA

from conftest import CAPTURE_T0, conn_row, slips_event, write_capture


def _signer():
    return Ed25519Signer(DATASET_CURATOR_ROLE)


def _snapshot(capture_dir, **kwargs):
    return build_snapshot(conn_log=capture_dir / "conn.log", alerts=capture_dir / "alerts.json", tenant="tenant-test",
                          signer=kwargs.pop("signer", None) or _signer(), clock=Clock(), **kwargs)


# ----------------------------------------------------------------------------- box 1: collection + labelling
def test_labels_follow_slips_rule_priority():
    T0 = CAPTURE_T0  # aligned to a 60 s bucket boundary
    rows = [
        # A: port scan, one of the two uids is referenced by Slips evidence -> whole window inherits the family (slips_uid)
        conn_row(T0 + 5, "A1", "10.0.0.23", 50001, "10.0.0.9", 80, "tcp", None, 0.0, 0, 0, "S0", 1, 0),
        conn_row(T0 + 6, "A2", "10.0.0.23", 50002, "10.0.0.9", 81, "tcp", None, 0.0, 0, 0, "REJ", 1, 1),
        # B: password guessing; Slips gives no uids, only (source, target, time) -> slips_host_time
        conn_row(T0 + 600, "B1", "10.0.0.88", 50003, "10.0.0.12", 22, "tcp", "ssh", 1.2, 1800, 2000, "SF", 12, 12),
        # B2: same hosts, 50 minutes after the evidence -> outside label_window_s -> silence
        conn_row(T0 + 3600, "B2", "10.0.0.88", 50004, "10.0.0.12", 22, "tcp", "ssh", 1.0, 1700, 2100, "SF", 11, 11),
        # B3: same source host and time bucket as B1, but a different target than the evidence names -> silence
        conn_row(T0 + 620, "B3", "10.0.0.88", 50005, "10.0.0.99", 443, "tcp", "ssl", 2.0, 900, 9000, "SF", 10, 12),
        # C: anomaly-only (ML) evidence by uid -> unlabeled_anomaly (quarantined, not a class, not baseline)
        conn_row(T0 + 1200, "C1", "10.0.0.31", 50006, "198.51.100.7", 8443, "tcp", None, 3.0, 900, 1200, "SF", 9, 9),
        # D: nothing from Slips except a weak indicator that carries no family -> benign (slips_silence)
        conn_row(T0 + 1800, "D1", "10.0.0.40", 50007, "93.184.216.34", 443, "tcp", "ssl", 4.0, 1200, 30000, "SF", 20, 30),
        # F: two uids in one window matched to two different families -> conflict, strongest (confidence x threat) wins
        conn_row(T0 + 2400, "F1", "10.0.0.50", 50008, "10.0.0.60", 23, "tcp", None, 0.0, 0, 0, "S0", 1, 0),
        conn_row(T0 + 2401, "F2", "10.0.0.50", 50009, "10.0.0.60", 22, "tcp", "ssh", 1.0, 1500, 1800, "SF", 10, 10),
        # G: a row Slips labelled but whose measurements are missing -> label kept, measurement stays None (cleaning drops it later)
        dict(conn_row(T0 + 3000, "G1", "10.0.0.70", 50010, "10.0.0.9", 445, "tcp", None, 0.0, 0, 0, "S0", 1, 0), orig_bytes=None),
    ]
    alerts = [
        slips_event("E1", "VERTICAL_PORT_SCAN", "flowalerts", "high", 0.9, "vertical port scan", "10.0.0.23", 0, ["A1"], "High", "10.0.0.9", 0, T0 + 5),
        slips_event("E2", "PASSWORD_GUESSING", "flowalerts", "medium", 0.8, "password guessing", "10.0.0.88", 10, [], "Medium", "10.0.0.12", 22, T0 + 700),
        slips_event("E3", "ANOMALOUS_FLOW", "flowmldetection", "low", 0.65, "anomalous flow", "10.0.0.31", 20, ["C1"], "Low", "198.51.100.7", 8443, T0 + 1200),
        slips_event("E4", "CONNECTION_WITHOUT_DNS", "flowalerts", "low", 0.8, "connection without DNS", "10.0.0.40", 30, ["D1"], "Low", "93.184.216.34", 443, T0 + 1800),
        slips_event("E5", "VERTICAL_PORT_SCAN", "flowalerts", "low", 0.5, "scan", "10.0.0.50", 40, ["F1"], "Low", "10.0.0.60", 0, T0 + 2400),
        slips_event("E6", "PASSWORD_GUESSING", "flowalerts", "high", 0.9, "guessing", "10.0.0.50", 40, ["F2"], "High", "10.0.0.60", 22, T0 + 2401),
        slips_event("E7", "VERTICAL_PORT_SCAN", "flowalerts", "high", 0.9, "scan", "10.0.0.70", 50, ["G1"], "High", "10.0.0.9", 0, T0 + 3000),
        # evidence that matches nothing in the capture must be counted as unmatched, not silently dropped
        slips_event("E8", "VERTICAL_PORT_SCAN", "flowalerts", "high", 0.9, "scan", "10.0.0.200", 60, ["ZZ"], "High", "10.0.0.9", 0, T0 + 90000),
    ]
    index = ZeekConnIndex.from_lines(json.dumps(r) for r in rows)
    parsed = parse_alerts_json(alerts)
    assert parsed.malformed == 0 and len(parsed.evidence) == 8
    records, stats = build_flow_records(index, parsed.evidence, parsed.incidents, tenant="t", window_s=60, label_window_s=300)
    by_host = {(r.src_host, r.dst_ip): r for r in records}
    assert len(records) == 8 and len(by_host) == 7  # B1 and B2 share hosts but sit in different time buckets
    assert (by_host[("10.0.0.23", "10.0.0.9")].label, by_host[("10.0.0.23", "10.0.0.9")].family) == ("port_scan", "port_scan")
    assert by_host[("10.0.0.23", "10.0.0.9")].conn_failures == 2 and by_host[("10.0.0.23", "10.0.0.9")].distinct_dst_ports == 2
    b_windows = [r for r in records if (r.src_host, r.dst_ip) == ("10.0.0.88", "10.0.0.12")]
    assert len(b_windows) == 2 and sorted(r.label for r in b_windows) == ["benign", "bruteforce"]
    assert by_host[("10.0.0.88", "10.0.0.99")].label == BENIGN
    assert by_host[("10.0.0.31", "198.51.100.7")].label == UNLABELED_ANOMALY and by_host[("10.0.0.31", "198.51.100.7")].family is None
    assert by_host[("10.0.0.40", "93.184.216.34")].label == BENIGN
    assert by_host[("10.0.0.50", "10.0.0.60")].label == "bruteforce"
    g = by_host[("10.0.0.70", "10.0.0.9")]
    assert g.label == "port_scan" and g.bytes_out is None and not g.has_required_fields()
    assert all(r.login_failures == 0.0 for r in records)
    assert all(r.flow_id.startswith("cap-") for r in records) and len({r.flow_id for r in records}) == len(records)
    s = stats.to_dict()
    assert s["label_sources"] == {"slips_uid": 3, "slips_host_time": 1, "slips_anomaly_only": 1, "slips_silence": 3}
    assert s["by_label"] == {"port_scan": 2, "bruteforce": 2, "unlabeled_anomaly": 1, "benign": 3}
    assert s["by_family"] == {"port_scan": 2, "bruteforce": 2}
    assert s["conflicts"] == 1 and s["windows_with_missing_measurements"] == 1
    # E4 is a weak indicator (no family, not an anomaly signal) so it is not part of the matched/unmatched accounting
    assert s["evidence_matched"] == 6 and s["evidence_unmatched"] == 1
    # the same (orig, resp) pair in a different bucket is a different window: same flow_id only for identical keys
    again, _ = build_flow_records(index, parsed.evidence, parsed.incidents, tenant="t", window_s=60, label_window_s=300)
    assert [r.flow_id for r in again] == [r.flow_id for r in records]
    with pytest.raises(ValueError):
        build_flow_records(index, parsed.evidence, parsed.incidents, tenant="t", window_s=0)


# ----------------------------------------------------------------------------- the signed dataset copy
def test_snapshot_round_trip_and_tamper_detection(capture_dir, tmp_path):
    snapshot = _snapshot(capture_dir, slips_blocking_claimed=True)
    p = snapshot.manifest.payload
    assert p["schema"] == DATASET_MANIFEST_SCHEMA == "owp-soc/dataset-manifest/0.1"
    assert p["dataset_id"] == "ds-" + p["flows_sha256"][:12] == snapshot.dataset_id
    assert p["source"]["kind"] == "zeek-conn-log" and p["source"]["capture_manifest"] is None
    assert p["source"]["conn_log_sha256"] == sha256_hex((capture_dir / "conn.log").read_bytes())
    assert p["source"]["alerts_sha256"] == sha256_hex((capture_dir / "alerts.json").read_bytes())
    assert p["labeling"]["rule_version"] == LABEL_RULE_VERSION and p["labeling"]["login_failures"].startswith("always 0")
    assert p["slips"]["blocking_claimed"] is True and p["slips"]["incidents"] == 1 and p["slips"]["malformed"] == 0
    assert p["slips"]["alerted_hosts"] == ["10.0.0.23"]
    assert p["counts"]["flows"] == len(snapshot.flows) > 300
    assert set(p["counts"]["by_label"]) == {"benign", "port_scan", "bruteforce", "unlabeled_anomaly"}
    assert "verified clean" in p["ground_truth"] and "unlabeled_anomaly" in p["ground_truth"]
    assert p["curator"]["role"] == DATASET_CURATOR_ROLE and p["feature_schema"] == FEATURE_SCHEMA_VERSION

    out = write_snapshot(snapshot, tmp_path / "snap")
    assert sorted(f.name for f in out.iterdir()) == ["curator-keys.json", "flows.jsonl", "manifest.json"]
    # co-located keys load, but the loader says so; explicit out-of-band keys are the real deployment path
    loaded = load_snapshot(out)
    assert loaded.trust_source == "co-located" and loaded.flows_sha256 == snapshot.flows_sha256
    assert [f.flow_id for f in loaded.flows] == [f.flow_id for f in snapshot.flows]
    assert all(a.label == b.label and a.bytes_in == b.bytes_in for a, b in zip(loaded.flows, snapshot.flows))
    explicit = trusted_keys_from_export(json.loads((out / "curator-keys.json").read_text()))
    assert load_snapshot(out, explicit).trust_source == "explicit"
    # a curator the training domain does not know -> refused even though the files are self-consistent
    with pytest.raises(DatasetSnapshotError, match="not trusted"):
        stranger = TrustedKeys()
        stranger.trust(_signer())
        load_snapshot(out, stranger)

    # tamper 1: relabel one attack flow as benign (baseline poisoning) -> hash mismatch
    poisoned = tmp_path / "poisoned"
    write_snapshot(snapshot, poisoned)
    lines = (poisoned / "flows.jsonl").read_text().splitlines()
    idx = next(i for i, line in enumerate(lines) if '"port_scan"' in line)
    lines[idx] = lines[idx].replace('"port_scan"', '"benign"')
    (poisoned / "flows.jsonl").write_text("\n".join(lines) + "\n")
    with pytest.raises(DatasetSnapshotError, match="flows_sha256"):
        load_snapshot(poisoned)
    # tamper 2: edit the signed manifest (e.g. claim Slips was blocking) -> signature no longer verifies
    edited = tmp_path / "edited"
    write_snapshot(snapshot, edited)
    manifest = json.loads((edited / "manifest.json").read_text())
    manifest["payload"]["slips"]["blocking_claimed"] = False
    (edited / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(DatasetSnapshotError, match="signature invalid"):
        load_snapshot(edited)
    # tamper 3: drop a flow line and fix nothing else -> hash mismatch (count check is behind it)
    truncated = tmp_path / "truncated"
    write_snapshot(snapshot, truncated)
    (truncated / "flows.jsonl").write_text("\n".join(lines[:-1]) + "\n")
    with pytest.raises(DatasetSnapshotError, match="flows_sha256"):
        load_snapshot(truncated)
    # malformed / missing pieces fail with the same exception type, never a traceback
    missing = tmp_path / "missing"
    missing.mkdir()
    with pytest.raises(DatasetSnapshotError, match="cannot read"):
        load_snapshot(missing)
    nokeys = tmp_path / "nokeys"
    write_snapshot(snapshot, nokeys)
    (nokeys / "curator-keys.json").unlink()
    with pytest.raises(DatasetSnapshotError, match="curator-keys.json"):
        load_snapshot(nokeys)
    # the wrong role may not sign a dataset
    with pytest.raises(DatasetSnapshotError, match="dataset_curator"):
        _snapshot(capture_dir, signer=Ed25519Signer(MODEL_RELEASE_ROLE))


def test_snapshot_pins_capture_manifest_hash(capture_dir, tmp_path):
    conn_bytes = (capture_dir / "conn.log").read_bytes()
    good = tmp_path / "capture-manifest.json"
    good.write_text(json.dumps({"schema": "owp-soc/capture-manifest/0.1", "source": {"kind": "pcap", "pcap_path": "/tmp/trace.pcap",
                                                                                  "pyshark": "0.6", "tshark": "4.2.2"},
                                "out_sha256": hashlib.sha256(conn_bytes).hexdigest(), "packets_used": 1234, "flows_written": 390,
                                "stop_reason": "source_exhausted", "content_policy": "header facts only"}))
    snap = _snapshot(capture_dir, capture_manifest=good)
    assert snap.manifest.payload["source"]["kind"] == "pyshark-capture"
    assert snap.manifest.payload["source"]["capture_manifest"]["source"]["pcap_path"] == "/tmp/trace.pcap"
    # the training report carries only a compact capture summary, not the whole manifest
    result = train_offline(snap, clock=Clock())
    capture = result.stages[0]["detail"]["capture"]
    assert capture["kind"] == "pcap" and capture["pcap_path"] == "/tmp/trace.pcap" and capture["packets_used"] == 1234
    assert result.stages[0]["detail"]["conn_rows"] == snap.manifest.payload["source"]["conn_rows"]
    bad = tmp_path / "bad-manifest.json"
    bad.write_text(json.dumps({"source": {"kind": "pcap"}, "out_sha256": "0" * 64}))
    with pytest.raises(DatasetSnapshotError, match="out_sha256"):
        _snapshot(capture_dir, capture_manifest=bad)
    notobj = tmp_path / "list.json"
    notobj.write_text("[]")
    with pytest.raises(DatasetSnapshotError, match="JSON object"):
        _snapshot(capture_dir, capture_manifest=notobj)


def test_write_snapshot_is_write_once(capture_dir, tmp_path):
    snapshot = _snapshot(capture_dir)
    target = tmp_path / "snap"
    write_snapshot(snapshot, target)
    before = {f.name: f.read_bytes() for f in target.iterdir()}
    with pytest.raises(DatasetSnapshotError, match="write-once"):
        write_snapshot(snapshot, target)
    with pytest.raises(DatasetSnapshotError, match="write-once"):
        write_snapshot(_snapshot(capture_dir), target)
    assert {f.name: f.read_bytes() for f in target.iterdir()} == before
    # an existing but empty directory is fine (e.g. a pre-created mount point)
    empty = tmp_path / "empty"
    empty.mkdir()
    write_snapshot(snapshot, empty)
    assert (empty / "manifest.json").exists()


# ----------------------------------------------------------------------------- box 2: validation + cleaning + split
def _flow(i, label=BENIGN, family=None, **over):
    base = dict(flow_id=f"f{i:04d}", tenant="t", src_host="10.0.0.1", dst_ip="10.0.0.2", dst_port=443,
                bytes_in=1000.0 + i, bytes_out=500.0, pkts_in=10.0, pkts_out=8.0, duration_s=1.5, mean_iat_ms=20.0,
                conn_failures=0.0, short_window_conns=2.0, distinct_dst_ports=1.0, login_failures=0.0,
                service_group="web", observed_at=f"2026-10-30T{(i // 60) % 24:02d}:{i % 60:02d}:00Z", label=label, family=family)
    base.update(over)
    return FlowRecord(**base)


def test_validate_and_clean_counts_every_drop():
    flows = [_flow(i) for i in range(40)]
    flows += [_flow(100 + i, "port_scan", "port_scan", conn_failures=20.0) for i in range(6)]
    flows += [_flow(200 + i, "bruteforce", "bruteforce") for i in range(3)]  # rare: below min_per_class
    flows += [_flow(300 + i, UNLABELED_ANOMALY) for i in range(2)]
    flows += [_flow(400, bytes_in=None), _flow(401, duration_s=float("nan")), _flow(402, pkts_out=-1.0)]
    flows += [_flow(5)]  # duplicate flow_id f0005
    kept, rep = validate_and_clean(flows, min_per_class=5, min_benign=30)
    r = rep.to_dict()
    assert r["input_flows"] == len(flows) == 55
    assert r["dropped_missing_measurements"] == 3 and r["dropped_duplicates"] == 1
    assert r["quarantined_anomaly_only"] == 2 and r["dropped_rare_families"] == {"bruteforce": 3}
    assert r["families_kept"] == {"port_scan": 6} and r["benign_kept"] == 40 and r["kept"] == 46 == len(kept)
    assert r["benign_baseline_sufficient"] is True
    assert r["input_flows"] == r["kept"] + r["dropped_missing_measurements"] + r["dropped_duplicates"] + r["quarantined_anomaly_only"] + sum(r["dropped_rare_families"].values())
    assert all(f.has_required_fields() and f.label != UNLABELED_ANOMALY and f.label != "bruteforce" for f in kept)
    assert any("unlabeled_anomaly" in n for n in r["notes"])
    # too little baseline is reported, not silently accepted
    kept2, rep2 = validate_and_clean([_flow(i) for i in range(10)], min_benign=30)
    assert len(kept2) == 10 and rep2.benign_baseline_sufficient is False
    assert any("benign baseline too small" in n for n in rep2.notes) and any("no attack family" in n for n in rep2.notes)


def test_time_split_is_ordered():
    import random

    flows = [_flow(i) for i in range(100)]
    random.Random(7).shuffle(flows)
    train, val, test = time_split(flows)
    assert (len(train), len(val), len(test)) == (60, 20, 20)
    assert train == sorted(train, key=lambda f: f.observed_at)
    assert max(f.observed_at for f in train) <= min(f.observed_at for f in val)
    assert max(f.observed_at for f in val) <= min(f.observed_at for f in test)
    assert {f.flow_id for f in train + val + test} == {f.flow_id for f in flows}
    a, b, c = time_split(flows, train_frac=0.5, val_frac=0.25)
    assert (len(a), len(b), len(c)) == (50, 25, 25)
    assert time_split([]) == ([], [], [])


# ----------------------------------------------------------------------------- boxes 3-6: train, evaluate, sign, gate
def test_train_offline_end_to_end_on_real_labels(capture_dir, tmp_path):
    snapshot = _snapshot(capture_dir)
    result = train_offline(snapshot, seed=1, clock=Clock())
    assert result.known_branch_source == "real-slips-labels"
    assert sorted(result.model.known.classes) == ["benign", "bruteforce", "port_scan"]
    assert result.model.model_version == f"dual_model/{snapshot.dataset_id}-seed1"
    assert [s["name"] for s in result.stages] == STAGE_NAMES and len(STAGE_NAMES) == 6
    assert [s["status"] for s in result.stages] == ["done"] * 5 + ["self-check-passed"]
    assert result.dataset_verification["status"] == "VERIFIED" and result.dataset_verification["trust_source"] == "in-memory"
    assert result.cleaning.dropped_missing_measurements == 1 and result.cleaning.quarantined_anomaly_only == 1
    assert result.split["train"] + result.split["val"] + result.split["test"] == result.cleaning.kept
    ev = result.evaluation
    assert set(ev["leave_one_family_out"]) == {"bruteforce", "port_scan"}
    for lofo in ev["leave_one_family_out"].values():
        assert lofo["held_out_test_flows"] > 0 and 0.0 <= lofo["recall_on_held_out_family"] <= 1.0
    assert set(ev["detection_time_split"]["recall_by_family"]) == {"bruteforce", "port_scan"}
    assert 0.0 <= ev["detection_time_split"]["benign_fpr_at_fixed_thresholds"] <= 0.2
    assert ev["false_positives_per_day"]["estimate_per_day"] is not None
    assert "perturbation_flip_rate" in ev["robustness"] and ev["known_branch_source"] == "real-slips-labels"
    # signing + gate: the release manifest points at the dataset by hash and carries the evaluation summary
    mp = result.manifest.payload
    assert mp["dataset_sha256"] == snapshot.flows_sha256 and mp["model_sha256"] == result.model_sha256
    assert mp["approved_by"] == "pending-human-gate" and mp["evaluation"]["known_branch_source"] == "real-slips-labels"
    assert mp["evaluation"]["dataset_id"] == snapshot.dataset_id
    gate = result.stages[5]["detail"]
    assert gate["human_approval"] == "pending" and len(gate["checks"]) == 5
    assert result.stages[4]["detail"]["signer_key_id"] in result.release_trust
    # written output is exactly what the inference domain and the dashboard read
    paths = write_training_output(result, tmp_path / "release")
    assert sorted(p.name for p in paths.values()) == sorted(["model.bin", "release-manifest.json", "release-trust.json",
                                                            "dataset-verification.json", "cleaning-report.json",
                                                            "training-report.json", "training-report.md"])
    assert sha256_hex(paths["model"].read_bytes()) == result.model_sha256
    report = json.loads(paths["report"].read_text())
    assert report["schema"] == TRAINING_REPORT_SCHEMA and report["release"] == json.loads(json.dumps(mp, default=str))
    assert "scaler" not in report["model"] and report["model"]["model_sha256"] == result.model_sha256
    assert "# Training report" in paths["report_md"].read_text()
    model_bytes, manifest, trust, trust_source = load_release_dir(tmp_path / "release")
    assert trust_source == "co-located"
    verified = verify_release(model_bytes, manifest, trust)
    assert verified.model.model_version == result.model.model_version
    # a human approval name is recorded as a claim, and the gate says so
    claimed = train_offline(snapshot, seed=1, clock=Clock(), approved_by="alice@soc")
    assert claimed.manifest.payload["approved_by"] == "alice@soc" and claimed.stages[5]["detail"]["human_approval"] == "claimed"
    # a changed model.bin fails the inference gate; a foreign trust file fails it too
    (tmp_path / "release" / "model.bin").write_bytes(model_bytes + b"\n")
    with pytest.raises(ModelReleaseError, match="hash"):
        verify_release(*load_release_dir(tmp_path / "release")[:3])
    foreign = TrustedKeys()
    foreign.trust(Ed25519Signer(MODEL_RELEASE_ROLE))
    (tmp_path / "foreign.json").write_text(json.dumps(foreign.export()))
    with pytest.raises(ModelReleaseError, match="not trusted"):
        verify_release(*load_release_dir(tmp_path / "release", tmp_path / "foreign.json")[:3])
    with pytest.raises(TrainingDomainError, match="cannot read"):
        load_release_dir(tmp_path / "nowhere")


def test_synthetic_known_fallback_is_explicit(tmp_path):
    quiet = write_capture(tmp_path / "quiet", with_attacks=False, benign_windows=120)
    snapshot = _snapshot(quiet)
    assert set(snapshot.manifest.payload["counts"]["by_label"]) == {"benign", "unlabeled_anomaly"}
    # default: refuse, and tell the operator exactly which flag would change that
    with pytest.raises(TrainingDomainError, match="--allow-synthetic-known"):
        train_offline(snapshot, clock=Clock())
    result = train_offline(snapshot, clock=Clock(), allow_synthetic_known=True)
    assert result.known_branch_source == "synthetic-fallback"
    assert result.model.model_version.endswith("-synthetic-known")
    assert result.manifest.payload["evaluation"]["known_branch_source"] == "synthetic-fallback"
    assert result.stages[2]["detail"]["known_branch_source"] == "synthetic-fallback"
    assert result.evaluation["known_branch_source"] == "synthetic-fallback"
    assert result.stages[2]["detail"]["families_in_train"] == {}
    # the anomaly branch still comes from the real benign baseline: thresholds exist per service group seen in the capture
    assert set(result.model.normality.tau_a) & {"web", "dns", "default"}
    # too little benign traffic is a hard stop, whatever the flags
    tiny = write_capture(tmp_path / "tiny", with_attacks=False, benign_windows=8)
    with pytest.raises(TrainingDomainError, match="benign baseline too small"):
        train_offline(_snapshot(tiny), clock=Clock(), allow_synthetic_known=True)


# ----------------------------------------------------------------------------- CLI: snapshot -> train -> ingest release -> verify
def _cli(argv):
    from aisoc.cli import main

    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = main(argv)
    return rc, out.getvalue(), err.getvalue()


def test_cli_snapshot_train_and_ingest_release(capture_dir, tmp_path):
    snap, train, run = tmp_path / "snap", tmp_path / "train", tmp_path / "run"
    rc, out, err = _cli(["dataset-snapshot", "--conn-log", str(capture_dir / "conn.log"), "--alerts", str(capture_dir / "alerts.json"),
                         "--out", str(snap), "--tenant", "tenant-cli", "--slips-blocking"])
    assert rc == 0, err
    printed = json.loads(out[: out.index("\nsigned dataset snapshot")])
    assert printed["flows"] > 300 and set(printed["by_label"]) >= {"benign", "port_scan", "bruteforce"}
    assert printed["label_sources"]["slips_uid"] > 0 and printed["label_sources"]["slips_host_time"] > 0
    # a second snapshot into the same directory is refused (write-once)
    rc, _, err = _cli(["dataset-snapshot", "--conn-log", str(capture_dir / "conn.log"), "--alerts", str(capture_dir / "alerts.json"), "--out", str(snap)])
    assert rc == 1 and "write-once" in err

    rc, out, err = _cli(["train-offline", str(snap), "--out", str(train), "--seed", "1"])
    assert rc == 0, err
    assert "WARNING: curator key taken from curator-keys.json" in err  # co-located trust is called out
    summary = json.loads(out[out.index("{"): out.index("\nrelease written")])
    assert summary["known_branch_source"] == "real-slips-labels"
    assert dict(summary["stages"]) == {**{n: "done" for n in STAGE_NAMES[:5]}, STAGE_NAMES[5]: "self-check-passed"}
    assert set(summary["lofo"]) == {"bruteforce", "port_scan"}
    # explicit out-of-band curator key: no warning
    rc, _, err = _cli(["train-offline", str(snap), "--out", str(tmp_path / "train2"), "--trust", str(snap / "curator-keys.json")])
    assert rc == 0 and "WARNING" not in err
    # a poisoned snapshot never reaches training
    poisoned = tmp_path / "poisoned"
    poisoned.mkdir()
    for name in ("manifest.json", "curator-keys.json"):
        (poisoned / name).write_bytes((snap / name).read_bytes())
    (poisoned / "flows.jsonl").write_text((snap / "flows.jsonl").read_text().replace('"port_scan"', '"benign"'))
    rc, _, err = _cli(["train-offline", str(poisoned), "--out", str(tmp_path / "train3")])
    assert rc == 1 and "dataset snapshot refused" in err and not (tmp_path / "train3").exists()

    # inference domain loads the offline release and scores the same capture with the internal normality model
    rc, out, err = _cli(["slips-ingest", str(capture_dir / "alerts.json"), "--conn-log", str(capture_dir / "conn.log"),
                         "--out", str(run), "--release-dir", str(train), "--internal-normality"])
    assert rc == 0, err
    assert "loaded offline-trained release dual_model/" in out and "known branch: real-slips-labels" in out
    assert "WARNING: trusting release-trust.json shipped next to the model" in err
    summary = json.loads((run / "slips-summary.json").read_text())
    assert summary["source"]["model_origin"] == f"offline release dir {train}"
    assert summary["model_release"]["dataset_sha256"] == json.loads((snap / "manifest.json").read_text())["payload"]["flows_sha256"]
    assert summary["model_release"]["approved_by"] == "pending-human-gate"
    assert summary["cases"] > 0 and summary["status_counts"].get("KNOWN_SUSPICIOUS", 0) > 0
    assert all(c["decision"]["model_version"].startswith("dual_model/ds-") for c in summary["case_results"])
    rc, out, _ = _cli(["verify", str(run)])
    assert rc == 0 and '"status": "VERIFIED"' in out
    # a release whose artefact was altered after signing is refused by the inference domain
    tampered = tmp_path / "tampered"
    tampered.mkdir()
    for f in train.iterdir():
        (tampered / f.name).write_bytes(f.read_bytes())
    (tampered / "model.bin").write_bytes((train / "model.bin").read_bytes() + b"x")
    rc, _, err = _cli(["slips-ingest", str(capture_dir / "alerts.json"), "--out", str(tmp_path / "run2"), "--release-dir", str(tampered)])
    assert rc == 1 and "release refused" in err
    # the synthetic-fallback flag is visible to the inference operator
    quiet = write_capture(tmp_path / "quiet", with_attacks=False, benign_windows=120)
    rc, _, _ = _cli(["dataset-snapshot", "--conn-log", str(quiet / "conn.log"), "--alerts", str(quiet / "alerts.json"), "--out", str(tmp_path / "qsnap")])
    assert rc == 0
    rc, _, err = _cli(["train-offline", str(tmp_path / "qsnap"), "--out", str(tmp_path / "qtrain")])
    assert rc == 1 and "--allow-synthetic-known" in err
    rc, out, _ = _cli(["train-offline", str(tmp_path / "qsnap"), "--out", str(tmp_path / "qtrain"), "--allow-synthetic-known"])
    assert rc == 0 and '"known_branch_source": "synthetic-fallback"' in out
    rc, out, _ = _cli(["slips-ingest", str(quiet / "alerts.json"), "--out", str(tmp_path / "qrun"), "--release-dir", str(tmp_path / "qtrain")])
    assert rc == 0 and "known branch: synthetic-fallback" in out
