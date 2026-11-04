"""Architecture 1, box 1 (data collection): pyshark packets -> Zeek-style conn.log rows.

These tests never need tshark: the flow assembler is fed PacketView objects directly, the
pyshark adapter is exercised with duck-typed fake packets, and the "unavailable" paths are
asserted to fail cleanly instead of crashing.
"""
import hashlib
import io
import json
import sys
from contextlib import redirect_stderr, redirect_stdout

import pytest

from aisoc.adapters.slips import ZeekConnIndex
from aisoc.capture import CaptureUnavailable, FakePacketSource, FlowAssembler, PacketView, PysharkSource, run_capture
from aisoc.capture.flows import CONN_LOG_FIELDS, TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN, conn_log_row_lines
from aisoc.capture.pyshark_source import packet_view_from_pyshark
from aisoc.capture.runner import CAPTURE_MANIFEST_SCHEMA

CLIENT, SERVER = "10.0.0.5", "93.184.216.34"


def tcp(ts, src, dst, sport, dport, flags, payload=0):
    return PacketView(ts, src, dst, sport, dport, "tcp", 54 + payload, payload, flags)


def handshake_and_close(t0=1000.0, sport=51000):
    """A complete client->server TCP exchange: 3-way handshake, data both ways, FIN both ways, trailing ACK."""
    c2s = lambda ts, flags, payload=0: tcp(ts, CLIENT, SERVER, sport, 443, flags, payload)  # noqa: E731
    s2c = lambda ts, flags, payload=0: tcp(ts, SERVER, CLIENT, 443, sport, flags, payload)  # noqa: E731
    return [
        c2s(t0, TCP_SYN),
        s2c(t0 + 0.01, TCP_SYN | TCP_ACK),
        c2s(t0 + 0.02, TCP_ACK),
        c2s(t0 + 0.03, TCP_PSH | TCP_ACK, 517),
        s2c(t0 + 0.05, TCP_ACK),
        s2c(t0 + 0.06, TCP_PSH | TCP_ACK, 4096),
        c2s(t0 + 0.50, TCP_FIN | TCP_ACK),
        s2c(t0 + 0.51, TCP_FIN | TCP_ACK),
        c2s(t0 + 0.52, TCP_ACK),  # the final ACK arrives after both FINs
    ]


def test_tcp_handshake_and_close_becomes_sf_row():
    assembler = FlowAssembler(idle_timeout_s=60, close_delay_s=5)
    emitted = []
    for pkt in handshake_and_close():
        emitted.extend(assembler.add(pkt))
    # nothing is emitted until the close delay has passed; the trailing ACK joins the closing flow
    assert emitted == [] and assembler.open_flows == 1
    # an unrelated packet 10 s later acts as the clock that flushes the closed connection
    emitted.extend(assembler.add(PacketView(1010.0, CLIENT, "10.0.0.53", 40000, 53, "udp", 70, 28)))
    assert len(emitted) == 1
    row = emitted[0]
    assert row["conn_state"] == "SF"
    assert (row["id.orig_h"], row["id.orig_p"], row["id.resp_h"], row["id.resp_p"]) == (CLIENT, 51000, SERVER, 443)
    assert row["proto"] == "tcp" and row["service"] == "ssl"
    assert row["orig_pkts"] == 5 and row["resp_pkts"] == 4  # trailing ACK counted in the same flow, no OTH flow
    assert row["orig_bytes"] == 517 and row["resp_bytes"] == 4096
    assert row["duration"] == pytest.approx(0.52)
    assert row["history"].startswith("ShA") and "D" in row["history"] and "d" in row["history"]
    assert "F" in row["history"] and "f" in row["history"]
    assert row["uid"].startswith("C") and len(row["uid"]) == 18
    assert list(row) == CONN_LOG_FIELDS
    # the same packets replayed give the same uid (deterministic, reproducible from a pcap)
    again = FlowAssembler()
    for pkt in handshake_and_close():
        again.add(pkt)
    assert again.flush_all()[0]["uid"] == row["uid"]
    # the remaining UDP flow is flushed at the end, and the assembler emitted exactly two flows in total
    rest = assembler.flush_all()
    assert len(rest) == 1 and rest[0]["proto"] == "udp" and rest[0]["service"] == "dns" and rest[0]["conn_state"] == "S0"
    assert assembler.flows_emitted == 2
    # rows are consumable by the existing Zeek index used by the Slips adapter
    index = ZeekConnIndex.from_lines(conn_log_row_lines([row]))
    agg = index.aggregate([row["uid"]], host=CLIENT)
    assert agg["bytes_out"] == 517 and agg["bytes_in"] == 4096 and agg["conn_failures"] == 0


@pytest.mark.parametrize("packets, expected", [
    # SYN with no answer at all
    ([tcp(1.0, CLIENT, SERVER, 50000, 81, TCP_SYN)], "S0"),
    # SYN answered by RST (closed port)
    ([tcp(1.0, CLIENT, SERVER, 50001, 82, TCP_SYN), tcp(1.01, SERVER, CLIENT, 82, 50001, TCP_RST | TCP_ACK)], "REJ"),
    # originator gives up with RST before any reply
    ([tcp(1.0, CLIENT, SERVER, 50002, 83, TCP_SYN), tcp(1.5, CLIENT, SERVER, 50002, 83, TCP_RST)], "RSTOS0"),
    # originator sends SYN then FIN, responder silent
    ([tcp(1.0, CLIENT, SERVER, 50003, 84, TCP_SYN), tcp(1.5, CLIENT, SERVER, 50003, 84, TCP_FIN | TCP_ACK)], "SH"),
    # full handshake, then the originator aborts
    ([tcp(1.0, CLIENT, SERVER, 50004, 80, TCP_SYN), tcp(1.01, SERVER, CLIENT, 80, 50004, TCP_SYN | TCP_ACK),
      tcp(1.02, CLIENT, SERVER, 50004, 80, TCP_ACK), tcp(1.1, CLIENT, SERVER, 50004, 80, TCP_RST | TCP_ACK)], "RSTO"),
    # full handshake, then the responder aborts
    ([tcp(1.0, CLIENT, SERVER, 50005, 80, TCP_SYN), tcp(1.01, SERVER, CLIENT, 80, 50005, TCP_SYN | TCP_ACK),
      tcp(1.02, CLIENT, SERVER, 50005, 80, TCP_ACK), tcp(1.1, SERVER, CLIENT, 80, 50005, TCP_RST | TCP_ACK)], "RSTR"),
    # established, nobody closed (idle)
    ([tcp(1.0, CLIENT, SERVER, 50006, 80, TCP_SYN), tcp(1.01, SERVER, CLIENT, 80, 50006, TCP_SYN | TCP_ACK),
      tcp(1.02, CLIENT, SERVER, 50006, 80, TCP_ACK)], "S1"),
    # established, only the originator sent FIN
    ([tcp(1.0, CLIENT, SERVER, 50007, 80, TCP_SYN), tcp(1.01, SERVER, CLIENT, 80, 50007, TCP_SYN | TCP_ACK),
      tcp(1.02, CLIENT, SERVER, 50007, 80, TCP_ACK), tcp(1.5, CLIENT, SERVER, 50007, 80, TCP_FIN | TCP_ACK)], "S2"),
    # established, only the responder sent FIN
    ([tcp(1.0, CLIENT, SERVER, 50008, 80, TCP_SYN), tcp(1.01, SERVER, CLIENT, 80, 50008, TCP_SYN | TCP_ACK),
      tcp(1.02, CLIENT, SERVER, 50008, 80, TCP_ACK), tcp(1.5, SERVER, CLIENT, 80, 50008, TCP_FIN | TCP_ACK)], "S3"),
    # capture started mid-connection: no SYN from the originator
    ([tcp(1.0, CLIENT, SERVER, 50009, 80, TCP_PSH | TCP_ACK, 100), tcp(1.1, SERVER, CLIENT, 80, 50009, TCP_ACK)], "OTH"),
    # UDP: both directions -> SF, one direction -> S0
    ([PacketView(1.0, CLIENT, "10.0.0.53", 40001, 53, "udp", 70, 28), PacketView(1.01, "10.0.0.53", CLIENT, 53, 40001, "udp", 150, 108)], "SF"),
    ([PacketView(1.0, CLIENT, "10.0.0.53", 40002, 53, "udp", 70, 28)], "S0"),
])
def test_conn_state_table(packets, expected):
    assembler = FlowAssembler()
    rows = []
    for pkt in packets:
        rows.extend(assembler.add(pkt))
    rows.extend(assembler.flush_all())
    assert len(rows) == 1, rows
    assert rows[0]["conn_state"] == expected
    # failed-connection states are exactly what the Slips adapter counts as conn_failures
    index = ZeekConnIndex.from_lines(conn_log_row_lines(rows))
    failures = index.aggregate([rows[0]["uid"]], host=CLIENT)["conn_failures"]
    assert failures == (1 if expected in {"S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR"} else 0)


def test_icmp_exchange_is_one_flow_and_idle_flows_expire():
    assembler = FlowAssembler(idle_timeout_s=10)
    # echo request (type 8) and reply (type 0) carry different "ports" but must be one flow
    assert assembler.add(PacketView(1.0, CLIENT, SERVER, 8, 0, "icmp", 98)) == []
    assert assembler.add(PacketView(1.02, SERVER, CLIENT, 0, 0, "icmp", 98)) == []
    assert assembler.open_flows == 1
    # 11 s of silence: the next packet of any flow expires it
    expired = assembler.add(PacketView(12.5, CLIENT, "10.0.0.53", 40000, 53, "udp", 70, 28))
    assert len(expired) == 1 and expired[0]["proto"] == "icmp" and expired[0]["conn_state"] == "SF"
    assert expired[0]["orig_pkts"] == 1 and expired[0]["resp_pkts"] == 1
    with pytest.raises(ValueError):
        FlowAssembler(idle_timeout_s=0)


class _Layer:
    def __init__(self, **fields):
        self.__dict__.update(fields)


class _FakePysharkPacket:
    """Duck-typed stand-in for pyshark.packet.packet.Packet (string-valued fields, like tshark emits)."""

    def __init__(self, ts, length, transport=None, ip=None, **layers):
        self.sniff_timestamp = ts
        self.length = length
        self.transport_layer = transport
        if ip is not None:
            self.ip = ip
        self.__dict__.update(layers)


def test_packet_view_from_pyshark_like_object():
    pkt = _FakePysharkPacket("1761815520.123456", "571", "TCP", _Layer(src="10.0.0.5", dst="93.184.216.34"),
                             tcp=_Layer(srcport="51000", dstport="443", flags="0x0018", len="517"))
    view = packet_view_from_pyshark(pkt)
    assert view == PacketView(1761815520.123456, "10.0.0.5", "93.184.216.34", 51000, 443, "tcp", 571, 517, TCP_PSH | TCP_ACK)
    assert view.has(TCP_PSH) and view.has(TCP_ACK) and not view.has(TCP_SYN)
    udp = _FakePysharkPacket("2.0", "70", "UDP", _Layer(src="10.0.0.5", dst="10.0.0.53"), udp=_Layer(srcport="40000", dstport="53", length="36"))
    assert packet_view_from_pyshark(udp) == PacketView(2.0, "10.0.0.5", "10.0.0.53", 40000, 53, "udp", 70, 28, 0)
    icmp = _FakePysharkPacket("3.0", "98", None, _Layer(src="10.0.0.5", dst="93.184.216.34"), icmp=_Layer(type="8", code="0"))
    assert packet_view_from_pyshark(icmp) == PacketView(3.0, "10.0.0.5", "93.184.216.34", 8, 0, "icmp", 98, 0, 0)
    # IPv6 is accepted through the ipv6 layer; unknown transports become "other"
    v6 = _FakePysharkPacket("4.0", "90", None, None, ipv6=_Layer(src="2001:db8::1", dst="2001:db8::2"))
    assert packet_view_from_pyshark(v6) == PacketView(4.0, "2001:db8::1", "2001:db8::2", 0, 0, "other", 90, 0, 0)
    # non-IP frames (ARP, LLDP ...) are skipped, as are packets with unusable timestamps
    assert packet_view_from_pyshark(_FakePysharkPacket("5.0", "60")) is None
    assert packet_view_from_pyshark(_FakePysharkPacket("not-a-time", "60", "TCP", _Layer(src="a", dst="b"))) is None
    # malformed flag strings degrade to "no flags" instead of raising
    odd = _FakePysharkPacket("6.0", "60", "TCP", _Layer(src="10.0.0.5", dst="10.0.0.6"), tcp=_Layer(srcport="1", dstport="2", flags="zz", len="0"))
    assert packet_view_from_pyshark(odd).tcp_flags == 0


def test_pyshark_source_reports_unavailable_cleanly(tmp_path, monkeypatch):
    # 1) pyshark itself missing -> CaptureUnavailable with the install hint, not ModuleNotFoundError
    import aisoc.capture.pyshark_source as mod

    def missing():
        raise CaptureUnavailable("pyshark is not installed; install the optional extra `pip install 'aisoc[capture]'`")

    monkeypatch.setattr(mod, "_import_pyshark", missing)
    with pytest.raises(CaptureUnavailable, match="aisoc\\[capture\\]"):
        PysharkSource.live("eth0")
    with pytest.raises(CaptureUnavailable):
        PysharkSource.pcap(tmp_path / "x.pcap")

    # 2) pyshark importable but tshark missing / capture refusing to start -> still CaptureUnavailable
    class _NoTshark(Exception):
        pass

    class _FakePyshark:
        @staticmethod
        def LiveCapture(**kwargs):
            raise _NoTshark("TShark not found")

        @staticmethod
        def FileCapture(**kwargs):
            raise _NoTshark("TShark not found")

    monkeypatch.setattr(mod, "_import_pyshark", lambda: _FakePyshark)
    monkeypatch.setattr(mod, "_versions", lambda: {"pyshark": "fake", "tshark": None})
    with pytest.raises(CaptureUnavailable, match="_NoTshark"):
        PysharkSource.live("eth0", bpf_filter="not port 6379")
    pcap = tmp_path / "trace.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    with pytest.raises(CaptureUnavailable, match="cannot open pcap"):
        PysharkSource.pcap(pcap)
    # a pcap path that does not exist is reported before pyshark is even asked
    with pytest.raises(CaptureUnavailable, match="pcap file not found"):
        PysharkSource.pcap(tmp_path / "missing.pcap")

    # 3) a capture that dies mid-stream surfaces as CaptureUnavailable from the iterator
    class _DyingCapture:
        closed = False

        def sniff_continuously(self):
            yield _FakePysharkPacket("1.0", "60", "TCP", _Layer(src="10.0.0.5", dst="10.0.0.6"), tcp=_Layer(srcport="1", dstport="2", flags="0x0002", len="0"))
            raise OSError("tshark exited")

        def close(self):
            self.closed = True

    dying = _DyingCapture()
    source = PysharkSource(dying, {"kind": "live", "interface": "eth0"})
    views = []
    with pytest.raises(CaptureUnavailable, match="tshark exited"):
        for view in source:
            views.append(view)
    assert len(views) == 1 and source.packets_seen == 1
    source.close()
    assert dying.closed and source.describe() == {"kind": "live", "interface": "eth0"}


def test_run_capture_writes_rows_and_manifest(tmp_path):
    packets = handshake_and_close(t0=100.0) + [
        PacketView(100.9, CLIENT, "10.0.0.53", 40000, 53, "udp", 70, 28),
        PacketView(100.91, "10.0.0.53", CLIENT, 53, 40000, "udp", 150, 108),
        tcp(101.0, "10.0.0.23", "10.0.0.9", 45000, 22, TCP_SYN),
        tcp(101.01, "10.0.0.9", "10.0.0.23", 22, 45000, TCP_RST | TCP_ACK),
    ]
    source = FakePacketSource(packets, {"kind": "fake", "note": "unit test"})
    out = tmp_path / "sensor" / "conn.log"
    progress_calls = []
    manifest = run_capture(source, out, idle_timeout_s=30, progress=progress_calls.append, progress_every=4)
    rows = [json.loads(line) for line in out.read_text().splitlines()]
    assert {r["conn_state"] for r in rows} == {"SF", "REJ"} and len(rows) == 3
    by_port = {r["id.resp_p"]: r for r in rows}
    assert by_port[443]["service"] == "ssl" and by_port[53]["proto"] == "udp" and by_port[22]["conn_state"] == "REJ"
    assert manifest["schema"] == CAPTURE_MANIFEST_SCHEMA == "owp-soc/capture-manifest/0.1"
    assert manifest["source"] == {"kind": "fake", "note": "unit test"}
    assert manifest["packets_used"] == len(packets) and manifest["flows_written"] == 3
    assert manifest["stop_reason"] == "source_exhausted" and manifest["errors"] == []
    assert manifest["first_packet_ts"] == 100.0 and manifest["last_packet_ts"] == 101.01
    assert manifest["out_sha256"] == hashlib.sha256(out.read_bytes()).hexdigest()
    assert "payload bytes" in manifest["content_policy"]
    assert source.closed and len(progress_calls) == len(packets) // 4
    written = json.loads((tmp_path / "sensor" / "capture-manifest.json").read_text())
    assert written == manifest
    # stop conditions are recorded truthfully
    manifest2 = run_capture(FakePacketSource(packets), tmp_path / "second.log", max_packets=3)
    assert manifest2["stop_reason"] == "max_packets" and manifest2["packets_used"] == 3
    # a source that raises still leaves a manifest and the flows seen so far behind
    class _Broken(FakePacketSource):
        def __iter__(self):
            yield packets[0]
            raise RuntimeError("permission denied")

    with pytest.raises(RuntimeError, match="permission denied"):
        run_capture(_Broken(packets), tmp_path / "third.log", manifest_path=tmp_path / "third-manifest.json")
    broken = json.loads((tmp_path / "third-manifest.json").read_text())
    assert broken["stop_reason"] == "error" and broken["errors"] == ["RuntimeError: permission denied"]
    assert broken["flows_written"] == 1  # the half-open SYN was flushed, not lost


def test_cli_capture_pcap_without_tshark_fails_cleanly(tmp_path, monkeypatch):
    from aisoc.cli import main

    def run(argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = main(argv)
        return rc, out.getvalue(), err.getvalue()

    rc, _, err = run(["capture", "--pcap", str(tmp_path / "nope.pcap"), "--out", str(tmp_path / "conn.log")])
    assert rc == 1 and "capture unavailable" in err and "pcap file not found" in err
    assert not (tmp_path / "conn.log").exists()
    # argument hygiene: exactly one source, and filters are tied to the right source kind
    rc, _, err = run(["capture", "--out", str(tmp_path / "conn.log")])
    assert rc == 2 and "exactly one of --interface or --pcap" in err
    rc, _, err = run(["capture", "--pcap", "x.pcap", "--bpf", "tcp", "--out", str(tmp_path / "conn.log")])
    assert rc == 2 and "--bpf applies to live capture only" in err
    rc, _, err = run(["capture", "--interface", "eth0", "--display-filter", "tcp", "--out", str(tmp_path / "conn.log")])
    assert rc == 2 and "--display-filter applies to pcap files only" in err
    # with pyshark present but no tshark, the error is still a one-line explanation (exit 1), never a traceback
    import aisoc.capture.pyshark_source as mod

    class _FakePyshark:
        @staticmethod
        def FileCapture(**kwargs):
            raise RuntimeError("TShark not found. Try adding its location to the configuration file.")

    monkeypatch.setattr(mod, "_import_pyshark", lambda: _FakePyshark)
    monkeypatch.setattr(mod, "_versions", lambda: {"pyshark": "fake", "tshark": None})
    pcap = tmp_path / "trace.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    rc, _, err = run(["capture", "--pcap", str(pcap), "--out", str(tmp_path / "conn.log")])
    assert rc == 1 and "TShark not found" in err and "Traceback" not in err
    assert "python" in sys.executable  # sanity: the CLI ran in-process
