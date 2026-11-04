"""Read-only dashboard data and HTTP boundaries."""

import json
import re
import threading
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from aisoc.dashboard import ReviewConflictError, _redact, create_server, save_review, snapshot, traffic_snapshot, verify_export
from aisoc.canonical import digest


def test_snapshot_masks_addresses_and_counts_actual_data(tmp_path):
    cases = [{"case_id": "case-1", "decision": {"status": "KNOWN_SUSPICIOUS", "requires_human_review": True},
              "investigated": True, "requests": [{"action": "block_host", "executed": True}],
              "report": {"narrative": "source 192.168.8.10/24"}}]
    (tmp_path / "cases.json").write_text(json.dumps(cases))
    data = snapshot(tmp_path)
    assert data["counts"]["cases"] == data["counts"]["blocks"] == data["counts"]["review"] == 1
    assert "192.168.8" not in json.dumps(data)
    assert data["source"] == "Synthetic export"
    assert data["counts"]["checkpoints"] == 0


def test_redaction_handles_ipv6():
    assert _redact("host:2001:db8::8") == "xxxx:xxxx::xxxx"
    assert _redact("192.168.8.0/24") == "x.x.x.x"


@pytest.mark.parametrize("statuses", [[], [
    "KNOWN_SUSPICIOUS", "SUSPECTED_UNKNOWN", "MODEL_CONFLICT",
    "INSUFFICIENT_EVIDENCE", "LOW_RISK_OBSERVE", "UNKNOWN",
]])
def test_snapshot_preserves_statuses_without_fabricating_cases(tmp_path, statuses):
    cases = [{"case_id": f"case-{index}", "decision": {"status": status}}
             for index, status in enumerate(statuses)]
    (tmp_path / "cases.json").write_text(json.dumps(cases))
    data = snapshot(tmp_path)
    assert data["counts"]["cases"] == len(statuses)
    assert [case["decision"]["status"] for case in data["cases"]] == statuses
    assert data["statuses"] == {status: 1 for status in statuses}


def test_snapshot_rejects_malformed_or_linked_exports(tmp_path):
    (tmp_path / "cases.json").write_text("{}")
    with pytest.raises(ValueError):
        snapshot(tmp_path)
    (tmp_path / "cases.json").unlink()
    (tmp_path / "cases.json").symlink_to(tmp_path / "other.json")
    (tmp_path / "other.json").write_text("[]")
    with pytest.raises(ValueError):
        snapshot(tmp_path)


def test_missing_export_does_not_claim_verified(tmp_path):
    with pytest.raises(ValueError, match="incomplete"):
        verify_export(tmp_path)


def test_model_conflict_review_persists_without_changing_evidence(tmp_path):
    case = {"case_id": "case-e49e9ce1d403", "decision": {"status": "MODEL_CONFLICT", "requires_human_review": True}}
    path = tmp_path / "cases.json"
    path.write_text(json.dumps([case]))
    original = path.read_bytes()
    saved = save_review(tmp_path, case["case_id"], "TRUE_POSITIVE", digest(case))
    assert saved["verdict"] == "TRUE_POSITIVE"
    assert save_review(tmp_path, case["case_id"], "TRUE_POSITIVE", digest(case))["review_id"] == saved["review_id"]
    save_review(tmp_path, case["case_id"], "FALSE_POSITIVE", digest(case))
    context = snapshot(tmp_path)["review_context"][case["case_id"]]
    assert context["latest"]["verdict"] == "FALSE_POSITIVE"
    assert [item["verdict"] for item in context["history"]] == ["FALSE_POSITIVE", "TRUE_POSITIVE"]
    assert path.read_bytes() == original
    case["decision"]["model_version"] = "changed-model"
    path.write_text(json.dumps([case]))
    assert snapshot(tmp_path)["review_context"][case["case_id"]]["latest"] is None


def test_review_database_symlinks_are_rejected(tmp_path):
    case = {"case_id": "case-1", "decision": {"status": "MODEL_CONFLICT"}}
    (tmp_path / "cases.json").write_text(json.dumps([case]))
    (tmp_path / ".dashboard-reviews.sqlite3").symlink_to(tmp_path / "other.sqlite3")
    with pytest.raises(ValueError, match="Unsafe"):
        save_review(tmp_path, "case-1", "TRUE_POSITIVE", digest(case))


def test_review_rejects_stale_unknown_or_ineligible_cases(tmp_path):
    case = {"case_id": "case-1", "decision": {"status": "MODEL_CONFLICT"}}
    path = tmp_path / "cases.json"
    path.write_text(json.dumps([case]))
    with pytest.raises(ReviewConflictError):
        save_review(tmp_path, "case-1", "TRUE_POSITIVE", "stale")
    with pytest.raises(KeyError):
        save_review(tmp_path, "missing", "TRUE_POSITIVE", digest(case))
    with pytest.raises(ValueError):
        save_review(tmp_path, "case-1", "approve_block", digest(case))
    case["decision"]["status"] = "LOW_RISK_OBSERVE"
    path.write_text(json.dumps([case]))
    with pytest.raises(ValueError):
        save_review(tmp_path, "case-1", "TRUE_POSITIVE", digest(case))


def test_review_http_requires_same_origin_token_and_current_case(tmp_path):
    case = {"case_id": "case-e49e9ce1d403", "decision": {"status": "MODEL_CONFLICT"}}
    (tmp_path / "cases.json").write_text(json.dumps([case]))
    server = create_server(tmp_path, 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with urlopen(base) as response:
            token = re.search(r'name="review-token" content="([^"]+)"', response.read().decode()).group(1)
        payload = {"case_id": case["case_id"], "case_digest": digest(case), "verdict": "TRUE_POSITIVE"}
        headers = {"Content-Type": "application/json", "Origin": base, "X-Review-Token": token}
        for changed in [{"X-Review-Token": "wrong"}, {"X-Review-Token": "\u00ff"},
                {"Origin": "http://evil.example"}, {"Host": "evil.example"}]:
            request = Request(base + "/api/review", data=json.dumps(payload).encode(), headers=dict(headers, **changed))
            with pytest.raises(HTTPError) as failure:
                urlopen(request)
            assert failure.value.code == 403
        with urlopen(Request(base + "/api/review", data=json.dumps(payload).encode(), headers=headers)) as response:
            saved = json.load(response)["review"]
        assert saved["verdict"] == "TRUE_POSITIVE"
        with urlopen(base + "/api/snapshot") as response:
            assert json.load(response)["review_context"][case["case_id"]]["latest"] == saved
        for changed, expected in [({"case_digest": "stale"}, 409), ({"verdict": "approve_block"}, 400),
                                  ({"case_id": "missing"}, 404)]:
            request = Request(base + "/api/review", data=json.dumps(dict(payload, **changed)).encode(), headers=headers)
            with pytest.raises(HTTPError) as failure:
                urlopen(request)
            assert failure.value.code == expected
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_traffic_unconfigured_missing_and_unsafe_sources(tmp_path):
    assert traffic_snapshot()["status"] == "NOT_CONFIGURED"
    path = tmp_path / "conn.log"
    assert traffic_snapshot(path)["status"] == "WAITING"
    path.symlink_to(tmp_path / "target.log")
    assert traffic_snapshot(path)["status"] == "ERROR"
    assert traffic_snapshot(tmp_path)["status"] == "ERROR"


def test_traffic_reads_appends_partial_lines_and_rotation(tmp_path):
    path = tmp_path / "conn.log"
    row = {"ts": time.time() - 2, "uid": "connection-1", "id.orig_h": "192.168.8.10",
           "id.resp_h": "2001:db8::8", "id.resp_p": 443, "proto": "tcp",
           "orig_bytes": 100, "resp_bytes": 200}
    path.write_text(json.dumps(row) + "\n" + '{"uid":')
    data = traffic_snapshot(path)
    assert data["status"] == "FRESH"
    assert data["counts"]["connections_60s"] == 1
    assert data["counts"]["bytes_60s"] == 300
    assert sum(data["buckets"]) == 1
    assert data["sources"]["connections"]["partial_line"]
    assert data["connections"][0]["source"] == "x.x.x.x"
    assert data["connections"][0]["destination"] == "xxxx:xxxx::xxxx"
    visible = traffic_snapshot(path, reveal_ips=True)
    assert visible["ip_visibility"] == "VISIBLE"
    assert visible["connections"][0]["source"] == "192.168.8.10"
    assert visible["connections"][0]["destination"] == "2001:db8::8"
    assert data["ip_visibility"] == "MASKED"
    path.write_text(json.dumps(dict(row, uid="connection-2")) + "\n")
    assert traffic_snapshot(path)["connections"][0]["uid"] == "connection-2"
    path.rename(tmp_path / "conn.old")
    path.write_text("")
    assert not traffic_snapshot(path)["connections"]


def test_traffic_handles_zeek_tsv_and_stale_sources(tmp_path):
    import os

    path = tmp_path / "conn.log"
    path.write_text("#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.resp_h\tproto\n"
                    + f"{time.time() - 120}\tconn-1\t192.168.8.10\t203.0.113.8\ttcp\n")
    os.utime(path, (time.time() - 120, time.time() - 120))
    data = traffic_snapshot(path)
    assert data["status"] == "STALE"
    assert data["counts"]["connections_60s"] == 0
    assert data["counts"]["bytes_60s"] is None
    assert data["connections"][0]["uid"] == "conn-1"


def test_traffic_parses_slips_alerts_without_exposing_free_text(tmp_path):
    from aisoc.adapters.slips import sample_alerts_json_lines

    path = tmp_path / "alerts.json"
    path.write_text("\n".join(sample_alerts_json_lines(" injected text")) + '\n[]\n{"unfinished":')
    data = traffic_snapshot(alerts=path)
    assert data["counts"]["buffer_alerts"] == 4
    assert data["counts"]["buffer_incidents"] == 1
    assert data["counts"]["malformed_alerts"] == 1
    assert "injected text" not in json.dumps(data)
    assert "10.0.0.23" not in json.dumps(data)


def test_traffic_keeps_zeek_headers_when_tail_is_bounded(tmp_path):
    path = tmp_path / "conn.log"
    path.write_text("#separator \\x09\n#fields\tts\tuid\tproto\n" + "#" * (2 * 1024 * 1024)
                    + f"\n{time.time() - 1}\ttail-connection\tudp\n")
    data = traffic_snapshot(path)
    assert data["sources"]["connections"]["truncated"]
    assert data["connections"][0]["uid"] == "tail-connection"
    assert data["protocols"] == {"udp": 1}


def test_traffic_http_observes_new_records(tmp_path):
    path = tmp_path / "conn.log"
    path.write_text("")
    server = create_server(tmp_path, 0, conn_log=path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/api/traffic"
    try:
        with urlopen(url) as response:
            assert json.load(response)["counts"]["connections_60s"] == 0
        with path.open("a") as stream:
            stream.write(json.dumps({"ts": time.time() - 1, "uid": "new-connection", "proto": "tcp"}) + "\n")
        with urlopen(url) as response:
            data = json.load(response)
        assert data["counts"]["connections_60s"] == 1
        assert data["connections"][0]["uid"] == "new-connection"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.parametrize("reveal_ips, expected", [(False, "x.x.x.x"), (True, "192.168.8.10")])
def test_traffic_http_ip_visibility_is_explicit(tmp_path, reveal_ips, expected):
    path = tmp_path / "conn.log"
    path.write_text(json.dumps({"ts": time.time() - 1, "uid": "visible-test", "id.orig_h": "192.168.8.10", "proto": "tcp"}) + "\n")
    server = create_server(tmp_path, 0, conn_log=path, reveal_ips=reveal_ips)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with urlopen(f"http://127.0.0.1:{server.server_port}/api/traffic") as response:
            data = json.load(response)
        assert data["ip_visibility"] == ("VISIBLE" if reveal_ips else "MASKED")
        assert data["connections"][0]["source"] == expected
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_http_read_only_and_no_arbitrary_paths(tmp_path):
    server = create_server(tmp_path, 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with urlopen(base) as response:
            html = response.read().decode()
            assert "AI-SOC & AISandbox" in html
            assert '<html lang="en">' in html
            assert "Security Overview" in html
            assert not re.search(r"[\u3400-\u9fff]", html)
            assert 'id="search"' in html
            assert 'id="detail"' in html
            assert 'data-view="idps"' in html
            assert 'data-tab="observed"' in html
            assert 'id="traffic-pause"' in html
            assert "Source Port" in html
            assert "Destination Port" in html
            assert "NOT_INGESTED" in html
            assert "openObservedDetail" in html
        with urlopen(base + "/lucide.js") as response:
            assert response.headers["Content-Type"].startswith("text/javascript")
            assert len(response.read()) > 1000
        with urlopen(base + "/api/snapshot") as response:
            assert json.load(response)["counts"]["cases"] == 0
            assert response.headers["Cache-Control"] == "no-store"
        with urlopen(base + "/api/traffic?path=/etc/passwd") as response:
            assert json.load(response)["status"] == "NOT_CONFIGURED"
        for request, status in [(base + "/../pyproject.toml", 404),
                                (Request(base + "/api/snapshot", data=b"{}"), 404),
                                (Request(base + "/api/snapshot", headers={"Host": "evil.example"}), 403)]:
            with pytest.raises(HTTPError) as failure:
                urlopen(request)
            assert failure.value.code == status
    finally:
        server.shutdown()
        server.server_close()
        thread.join()