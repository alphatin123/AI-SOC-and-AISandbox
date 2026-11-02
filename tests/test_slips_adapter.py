"""Slips (IDMEFv2 alerts.json + Zeek conn.log) -> external known/anomaly branches -> SOC."""

import json
import math
from pathlib import Path

import pytest

from aisoc.adapters.slips import (
    ANOMALY_TYPES,
    KNOWN_FAMILY_MAP,
    SlipsAdapter,
    SlipsEvidence,
    SlipsIncident,
    ZeekConnIndex,
    parse_alerts_json,
    parse_idmef_record,
    read_alerts_json,
    run_slips_alerts,
    sample_alerts_json_lines,
    threat_level_weight,
)
from aisoc.canonical import digest
from aisoc.idps import DualModel
from aisoc.scenarios import _soc
from aisoc.simulate import generate

FIXTURES = Path(__file__).parent / "fixtures" / "slips"


@pytest.fixture(scope="module")
def model():
    ds = generate(n=800, seed=3)
    return DualModel.train(ds.train, ds.val)


def test_parse_fixture_events_incidents_and_malformed_lines():
    parsed = read_alerts_json(FIXTURES / "alerts.json")
    assert len(parsed.evidence) == 7
    assert len(parsed.incidents) == 1
    assert parsed.malformed == 1
    assert parsed.slips_versions == {"1.1.24"}
    c2 = next(e for e in parsed.evidence if e.evidence_type == "COMMAND_AND_CONTROL_CHANNEL")
    assert c2.source_ip == "10.0.0.23" and c2.target_ip == "185.199.110.153" and c2.dst_port == 443
    assert c2.timewindow == 2 and c2.uids == ["CpZ1a4bKxJ0001", "CpZ1a4bKxJ0002"]
    assert c2.threat_level == pytest.approx(0.8) and c2.confidence == pytest.approx(0.9)
    assert c2.family == "c2" and c2.technique == "T1071"
    inc = parsed.incidents[0]
    assert isinstance(inc, SlipsIncident) and inc.source_ip == "10.0.0.23" and len(inc.correl_ids) == 3
    assert inc.accumulated_threat_level == pytest.approx(2.5)


def test_enum_string_forms_and_threat_levels_are_normalised():
    rec = json.loads(sample_alerts_json_lines()[0])
    note = json.loads(rec["Note"])
    note["evidence_type"] = "EvidenceType.COMMAND_AND_CONTROL_CHANNEL"
    note["threat_level"] = "ThreatLevel.CRITICAL"
    rec["Note"] = json.dumps(note)
    ev = parse_idmef_record(rec)
    assert isinstance(ev, SlipsEvidence)
    assert ev.evidence_type == "COMMAND_AND_CONTROL_CHANNEL" and ev.threat_level == 1.0
    assert threat_level_weight("medium") == 0.5 and threat_level_weight(0.7) == 0.7 and threat_level_weight("bogus") == 0.0


def test_unrecognised_records_are_rejected_not_guessed():
    assert parse_idmef_record({"Version": "1.0", "Status": "Event"}) is None
    assert parse_idmef_record({"Version": "2.D.V03", "Status": "Heartbeat"}) is None
    parsed = parse_alerts_json(['{"Version": "2.D.V03", "Status": "Event", "Note": "not json"}'])
    assert len(parsed.evidence) == 1 and parsed.evidence[0].evidence_type == ""


def test_known_family_map_and_anomaly_types_are_disjoint():
    assert not (set(KNOWN_FAMILY_MAP) & ANOMALY_TYPES)
    for fam, tech in KNOWN_FAMILY_MAP.values():
        assert fam and (tech is None or tech.startswith("T"))


def test_zeek_conn_index_json_and_tsv():
    idx = ZeekConnIndex.load(FIXTURES / "conn.log")
    agg = idx.aggregate(["CpZ1a4bKxJ0101", "CpZ1a4bKxJ0102", "CpZ1a4bKxJ0103"])
    assert agg["conn_failures"] == 3 and agg["short_window_conns"] == 3 and agg["distinct_dst_ports"] == 1
    assert idx.aggregate(["nope"]) is None
    tsv = "\n".join([
        "#separator \\x09",
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts\tconn_state",
        "1.0\tU1\t10.0.0.1\t1\t10.0.0.2\t22\ttcp\t2.0\t100\t200\t3\t4\tSF",
        "2.0\tU2\t10.0.0.1\t1\t10.0.0.2\t23\ttcp\t-\t-\t-\t1\t0\tS0",
    ])
    p = FIXTURES / "_tmp_conn.log"
    p.write_text(tsv)
    try:
        idx2 = ZeekConnIndex.load(p)
    finally:
        p.unlink()
    agg2 = idx2.aggregate(["U1", "U2"])
    # U2 (S0) never measured duration/bytes: those aggregates stay None instead of silently becoming 0
    assert agg2["bytes_out"] is None and agg2["bytes_in"] is None and agg2["duration_s"] is None
    assert agg2["pkts_in"] == 4 and agg2["pkts_out"] == 4
    assert agg2["conn_failures"] == 1 and agg2["distinct_dst_ports"] == 2 and agg2["short_window_conns"] == 2
    assert agg2["mean_iat_ms"] == pytest.approx(1000.0)
    only_u1 = idx2.aggregate(["U1"])
    assert only_u1["bytes_out"] == 100 and only_u1["bytes_in"] == 200 and only_u1["duration_s"] == 2.0
    assert only_u1["mean_iat_ms"] == pytest.approx(1000.0 * 2.0 / 6)


def _tsv_index(tmp_path, rows):
    header = [
        "#separator \\x09",
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts\tconn_state",
    ]
    p = tmp_path / "conn.log"
    p.write_text("\n".join(header + rows))
    return ZeekConnIndex.load(p)


def _event_with(line: str, **note_overrides):
    rec = json.loads(line)
    note = json.loads(rec["Note"])
    src = note_overrides.pop("source_ip", None)
    note.update(note_overrides)
    rec["Note"] = json.dumps(note)
    if src:
        rec["Source"][0]["IP"] = src
    return json.dumps(rec)


def test_note_that_decodes_to_a_non_object_is_treated_as_empty():
    rec = json.loads(sample_alerts_json_lines()[0])
    for raw in ("null", "[]", "42", '"text"', "[1, 2]"):
        ev = parse_idmef_record(dict(rec, Note=raw))
        assert isinstance(ev, SlipsEvidence), raw
        assert ev.evidence_type == "" and ev.uids == [] and ev.timewindow is None
        assert ev.source_ip == "10.0.0.23"  # structured IDMEF fields are still read
    inc = json.loads(sample_alerts_json_lines()[-1])
    parsed_inc = parse_idmef_record(dict(inc, Note="null"))
    assert isinstance(parsed_inc, SlipsIncident) and parsed_inc.accumulated_threat_level is None and parsed_inc.timewindow is None


def test_aggregate_preserves_missing_measurements(tmp_path):
    idx = _tsv_index(tmp_path, [
        "1.0\tA\t10.0.0.5\t40000\t203.0.113.9\t443\ttcp\t2.0\t100\t200\t3\t4\tSF",
        "2.0\tB\t10.0.0.5\t40001\t203.0.113.9\t443\ttcp\t-\t-\t-\t1\t0\tS0",
        "3.0\tC\t10.0.0.5\t40002\t203.0.113.9\t8443\ttcp\t1.0\t50\t-\t2\t2\tSF",
    ])
    agg = idx.aggregate(["A", "B", "C"], host="10.0.0.5")
    assert agg["bytes_out"] is None  # B has no orig_bytes
    assert agg["bytes_in"] is None  # B and C have no resp_bytes
    assert agg["duration_s"] is None  # B has no duration
    assert agg["pkts_out"] == 6 and agg["pkts_in"] == 6  # every row has packet counts
    assert agg["mean_iat_ms"] == pytest.approx(1000.0)  # every row has ts
    assert agg["conn_failures"] == 1 and agg["short_window_conns"] == 3 and agg["distinct_dst_ports"] == 2
    single = idx.aggregate(["B"])
    assert single["mean_iat_ms"] is None and single["pkts_out"] == 1 and single["duration_s"] is None
    # through the adapter the FlowRecord carries the gaps, so the internal normality model is never fed fabricated zeros
    line = _event_with(sample_alerts_json_lines()[0], uids=["A", "B", "C"], source_ip="10.0.0.5")
    (case,) = SlipsAdapter("t", idx).build_cases(parse_alerts_json([line]))
    assert case.flow.pkts_out == 6 and case.flow.bytes_out is None and case.flow.duration_s is None
    assert not case.flow.has_required_fields()


def test_aggregate_orients_rows_to_the_case_host(tmp_path):
    idx = _tsv_index(tmp_path, [
        # 10.0.0.5 initiated this one: orig_* already is the host's own direction
        "1.0\tOUT\t10.0.0.5\t40000\t203.0.113.9\t443\ttcp\t2.0\t100\t200\t3\t4\tSF",
        # 198.51.100.7 connected *to* 10.0.0.5:22 - the host is id.resp_h, so what it sent is resp_bytes
        "2.0\tIN\t198.51.100.7\t51000\t10.0.0.5\t22\ttcp\t5.0\t1000\t7000\t10\t20\tSF",
    ])
    as_host = idx.aggregate(["OUT", "IN"], host="10.0.0.5")
    assert as_host["bytes_out"] == 100 + 7000 and as_host["bytes_in"] == 200 + 1000
    assert as_host["pkts_out"] == 3 + 20 and as_host["pkts_in"] == 4 + 10
    assert as_host["distinct_dst_ports"] == 2  # peer ports: 443 and the inbound peer's 51000
    inbound_only = idx.aggregate(["IN"], host="10.0.0.5")
    assert inbound_only["bytes_out"] == 7000 and inbound_only["bytes_in"] == 1000
    zeek_view = idx.aggregate(["OUT", "IN"])  # no host given: Zeek originator view
    assert zeek_view["bytes_out"] == 1100 and zeek_view["bytes_in"] == 7200
    assert idx.aggregate(["IN"], host="10.9.9.9")["bytes_out"] == 1000  # host on neither end: originator view
    # build_flow passes the case host, so a case about the responder sees its own direction
    line = _event_with(sample_alerts_json_lines()[0], uids=["IN"], source_ip="10.0.0.5")
    (case,) = SlipsAdapter("t", idx).build_cases(parse_alerts_json([line]))
    assert case.flow.src_host == "10.0.0.5" and case.flow.bytes_out == 7000 and case.flow.bytes_in == 1000


def test_qualifying_evidence_is_not_suppressed_by_a_higher_confidence_weak_one():
    lines = sample_alerts_json_lines()
    c2 = lines[0]  # COMMAND_AND_CONTROL_CHANNEL, confidence 0.9, threat_level high (0.8)
    weak_ti = _event_with(lines[1], threat_level="low")  # confidence 1.0 but weight 0.2 < min_threat_weight
    (case,) = SlipsAdapter("t").build_cases(parse_alerts_json([c2, weak_ti]))
    assert case.known.label == "c2" and case.known.score == pytest.approx(0.9)
    assert not case.known.rejected and case.known.technique == "T1071"
    # when nothing qualifies the strongest candidate is still named, but the branch is rejected
    (strict,) = SlipsAdapter("t", tau_k=0.95).build_cases(parse_alerts_json([c2, weak_ti]))
    assert strict.known.rejected and strict.known.label == "threat_intel"


def test_adapter_groups_by_profile_and_timewindow_and_builds_branches():
    parsed = read_alerts_json(FIXTURES / "alerts.json")
    cases = SlipsAdapter("t", ZeekConnIndex.load(FIXTURES / "conn.log")).build_cases(parsed)
    by_flow = {c.flow.flow_id: c for c in cases}
    assert set(by_flow) == {"slips:10.0.0.23:tw2", "slips:10.0.0.42:tw3", "slips:10.0.0.77:tw1", "slips:10.0.0.88:tw4", "slips:10.0.0.90:tw5"}

    c2 = by_flow["slips:10.0.0.23:tw2"]
    assert len(c2.evidence) == 3 and len(c2.incidents) == 1
    assert c2.known.label == "threat_intel" and c2.known.score == 1.0 and not c2.known.rejected
    assert c2.known.technique == "T1071"  # falls back to the C2 evidence's technique
    assert c2.anomaly is None
    assert c2.flow.has_required_fields() and c2.flow.bytes_out > 1e8 and c2.flow.service_group == "web"
    assert "[COMMAND_AND_CONTROL_CHANNEL]" in c2.flow.log_excerpt
    assert c2.source_record["schema_version"].startswith("aisoc/slips-source-record/")
    assert digest(c2.source_record)  # canonicalisable

    ml = by_flow["slips:10.0.0.88:tw4"]
    assert ml.known.label == "unclassified" and ml.known.rejected
    assert ml.anomaly is not None and ml.anomaly.high and ml.anomaly.score == pytest.approx(0.65)
    assert ml.anomaly.source == "slips/flowmldetection"

    weak = by_flow["slips:10.0.0.90:tw5"]
    assert weak.known.rejected and weak.anomaly is None
    assert not weak.flow.has_required_fields() and weak.flow.bytes_in is None  # no conn.log row -> missing, not zero


def test_low_confidence_mapped_evidence_is_rejected_by_tau():
    parsed = read_alerts_json(FIXTURES / "alerts.json")
    strict = SlipsAdapter("t", tau_k=0.95).build_cases(parsed)
    ps = next(c for c in strict if c.flow.flow_id == "slips:10.0.0.42:tw3")
    assert ps.known.label == "port_scan" and ps.known.rejected


def test_run_through_soc_statuses_and_untrusted_description(model):
    soc = _soc(model)
    summ = run_slips_alerts(soc, FIXTURES / "alerts.json", conn_log=FIXTURES / "conn.log")
    assert summ.cases == 5 and summ.malformed == 1
    assert summ.status_counts == {"KNOWN_SUSPICIOUS": 3, "SUSPECTED_UNKNOWN": 1, "UNKNOWN": 1}
    assert summ.requires_human_review == 2
    by_flow = {r.flow_id: r for r in summ.results}
    scan = by_flow["slips:10.0.0.42:tw3"]
    assert scan.report["injection_flags_seen"], "injection text in Slips Description must be flagged"
    assert "+slips/" in scan.decision.model_version
    for r in summ.results:
        if r.investigated:
            assert r.verification_status == "VERIFIED"
    det = next(e for e in soc.ledger.entries_for_case(by_flow["slips:10.0.0.23:tw2"].case_id) if e.entry_type == "detection")
    assert det.refs["detector"].startswith("slips/") and det.refs["source_record_digest"].startswith("sha256:")
    weak = by_flow["slips:10.0.0.90:tw5"]
    assert weak.decision.status.value == "UNKNOWN" and not weak.investigated and weak.decision.requires_human_review


def test_internal_normality_only_used_when_opted_in_and_fields_present(model):
    soc = _soc(model)
    summ = run_slips_alerts(soc, FIXTURES / "alerts.json", conn_log=FIXTURES / "conn.log", use_internal_normality=True)
    by_flow = {r.flow_id: r for r in summ.results}
    assert by_flow["slips:10.0.0.23:tw2"].decision.anomaly_score is not None  # volumetrics present -> internal model scored it
    weak = by_flow["slips:10.0.0.90:tw5"]
    assert weak.decision.anomaly_score is None and weak.decision.status.value == "UNKNOWN"  # fields missing -> never "normal"


def test_export_cases_carries_flow_identity_and_slips_refs(model):
    soc = _soc(model)
    summ = run_slips_alerts(soc, FIXTURES / "alerts.json")
    rows = summ.export_cases()
    assert len(rows) == 5
    r = next(x for x in rows if x["flow_id"] == "slips:10.0.0.23:tw2")
    assert r["flow"]["src_host"] == "10.0.0.23" and r["slips"]["known"]["technique"] == "T1071"
    assert r["slips"]["incident_ids"] == ["i1-99999999"] and len(r["slips"]["evidence_ids"]) == 3
    assert not any(isinstance(v, float) and math.isnan(v) for v in r["flow"].values())
