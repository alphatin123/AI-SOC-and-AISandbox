"""Shared fixtures: a synthetic "capture" (Zeek-JSON conn.log + Slips IDMEFv2 alerts.json).

The generator mimics what `python -m aisoc capture` plus a Slips run leave behind, so the
training-domain and dashboard tests can exercise Architecture 1 end to end without tshark
or Slips installed.  Everything is deterministic for a given seed.
"""
import json
import random
from datetime import datetime, timezone
from pathlib import Path

import pytest

CAPTURE_T0 = 1761815520.0  # 2026-10-30T09:12:00Z


def _iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def conn_row(ts, uid, oh, op, rh, rp, proto, service, dur, ob, rb, state, opk, rpk):
    return {"ts": ts, "uid": uid, "id.orig_h": oh, "id.orig_p": op, "id.resp_h": rh, "id.resp_p": rp, "proto": proto,
            "service": service, "duration": dur, "orig_bytes": ob, "resp_bytes": rb, "conn_state": state,
            "missed_bytes": 0, "history": "ShADadFf", "orig_pkts": opk, "orig_ip_bytes": ob + 40 * opk,
            "resp_pkts": rpk, "resp_ip_bytes": rb + 40 * rpk}


def slips_event(eid, etype, module, threat_level, confidence, description, src, timewindow, uids, priority, target, dport, start):
    note = {"evidence_type": etype, "uids": uids, "accumulated_threat_level": 0, "threat_level": threat_level,
            "evidence_signal": "PAMP", "timewindow": timewindow, "source_module": module}
    record = {"Version": "2.D.V03", "ID": eid, "Status": "Event", "Priority": priority, "StartTime": _iso(start),
              "CreateTime": _iso(start + 60), "Confidence": confidence, "Description": description,
              "Analyzer": {"IP": "192.168.1.5", "Name": "Slips", "Model": "1.1.24", "Category": ["NIDS"],
                           "Data": ["Flow", "Network"], "Method": ["Heuristic"]},
              "Source": [{"IP": src, "Port": [], "Protocol": ["TCP"], "Note": json.dumps({"AS": {}, "rDNS": "", "SNI": ""})}],
              "Target": [{"IP": target, "Port": [dport]}], "Note": json.dumps(note)}
    return json.dumps(record)


def synthetic_capture(seed=3, benign_windows=200, scan_windows=20, brute_windows=20, hours=6.0, with_attacks=True):
    """Return (conn_log_lines, alert_lines).

    * benign web/DNS traffic from 10.0.0.10-39
    * vertical port scans from 10.0.0.23 labelled by Slips through flow uids
    * SSH password guessing from 10.0.0.88 labelled by Slips through (host, time) only
    * one anomaly-only (ML) evidence on a benign host -> unlabeled_anomaly
    * one conn row with a missing measurement -> dropped by cleaning
    * one Slips incident (Status: Incident) line
    """
    rng = random.Random(seed)
    rows, alerts = [], []
    counter = [0]

    def uid():
        counter[0] += 1
        return f"Ct{counter[0]:016d}"

    span = hours * 3600
    hosts = [f"10.0.0.{i}" for i in range(10, 40)]
    for _ in range(benign_windows):
        t = CAPTURE_T0 + rng.random() * span
        host = rng.choice(hosts)
        dst = rng.choice(["93.184.216.34", "142.250.72.14", "151.101.1.69"])
        for _ in range(rng.randint(1, 3)):
            ob, rb = rng.randint(300, 3000), rng.randint(2000, 60000)
            rows.append(conn_row(round(t + rng.random() * 20, 3), uid(), host, rng.randint(40000, 60000), dst, 443, "tcp", "ssl",
                                 round(rng.uniform(0.2, 8.0), 3), ob, rb, "SF", rng.randint(5, 40), rng.randint(5, 60)))
        if rng.random() < 0.5:
            rows.append(conn_row(round(t + 1, 3), uid(), host, rng.randint(40000, 60000), "10.0.0.53", 53, "udp", "dns",
                                 round(rng.uniform(0.01, 0.2), 3), rng.randint(40, 90), rng.randint(80, 300), "SF", 1, 1))
    if with_attacks:
        for k in range(scan_windows):
            t = CAPTURE_T0 + rng.random() * span
            uids = []
            for port in rng.sample(range(1, 1024), 25):
                u = uid()
                uids.append(u)
                rows.append(conn_row(round(t + rng.random() * 30, 3), u, "10.0.0.23", rng.randint(40000, 60000), "10.0.0.9", port,
                                     "tcp", None, 0.0, 0, 0, rng.choice(["S0", "REJ", "S0"]), 1, rng.choice([0, 1])))
            alerts.append(slips_event(f"ev-scan-{k:04d}", "VERTICAL_PORT_SCAN", "flowalerts", "high", 0.9,
                                      f"vertical port scan to 10.0.0.9 ({len(uids)} ports)", "10.0.0.23", k, uids[:5], "High", "10.0.0.9", 0, t))
        for k in range(brute_windows):
            t = CAPTURE_T0 + rng.random() * span
            for _ in range(rng.randint(15, 30)):
                rows.append(conn_row(round(t + rng.random() * 40, 3), uid(), "10.0.0.88", rng.randint(40000, 60000), "10.0.0.12", 22,
                                     "tcp", "ssh", round(rng.uniform(0.5, 2.5), 3), rng.randint(1500, 2600), rng.randint(1800, 3200),
                                     "SF", rng.randint(10, 20), rng.randint(10, 20)))
            alerts.append(slips_event(f"ev-brute-{k:04d}", "PASSWORD_GUESSING", "flowalerts", "medium", 0.8,
                                      "password guessing: 22 failed logins to 10.0.0.12:22", "10.0.0.88", 100 + k, [], "Medium",
                                      "10.0.0.12", 22, t + 20))
    t = CAPTURE_T0 + 100
    u = uid()
    rows.append(conn_row(t, u, "10.0.0.31", 50000, "198.51.100.7", 8443, "tcp", None, 3.0, 900, 1200, "SF", 9, 9))
    alerts.append(slips_event("ev-ml-0001", "ANOMALOUS_FLOW", "flowmldetection", "low", 0.65, "Anomalous flow detected by ML model",
                              "10.0.0.31", 999, [u], "Low", "198.51.100.7", 8443, t))
    bad = conn_row(CAPTURE_T0 + 200, uid(), "10.0.0.33", 50001, "93.184.216.34", 443, "tcp", "ssl", 1.0, 100, 100, "SF", 2, 2)
    bad["orig_bytes"] = None
    rows.append(bad)
    rows.sort(key=lambda r: r["ts"])
    incident = {"Version": "2.D.V03", "ID": "inc-0001", "Status": "Incident", "Priority": "High", "StartTime": _iso(CAPTURE_T0),
                "CreateTime": _iso(CAPTURE_T0 + 60),
                "Analyzer": {"IP": "192.168.1.5", "Name": "Slips", "Model": "1.1.24", "Category": ["NIDS"], "Data": ["Flow", "Network"],
                             "Method": ["Heuristic"]},
                "Source": [{"IP": "10.0.0.23" if with_attacks else "10.0.0.31"}], "CorrelID": ["ev-scan-0000" if with_attacks else "ev-ml-0001"],
                "Note": json.dumps({"accumulated_threat_level": 2.5, "accumulated_ratl": 2.5, "risk_level": "high", "timewindow": 0,
                                    "EndTime": _iso(CAPTURE_T0 + 3600)})}
    alerts.append(json.dumps(incident))
    return [json.dumps(r) for r in rows], alerts


def write_capture(directory: Path, **kwargs) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    conn, alerts = synthetic_capture(**kwargs)
    (directory / "conn.log").write_text("\n".join(conn) + "\n", encoding="utf-8")
    (directory / "alerts.json").write_text("\n".join(alerts) + "\n", encoding="utf-8")
    return directory


@pytest.fixture(scope="session")
def capture_dir(tmp_path_factory) -> Path:
    """conn.log + alerts.json for a capture that contains two Slips-labelled attack families."""
    return write_capture(tmp_path_factory.mktemp("capture"))


@pytest.fixture(scope="session")
def training_dir(tmp_path_factory, capture_dir) -> Path:
    """A complete `train-offline` output directory built from `capture_dir` (shared, read-only)."""
    from aisoc.crypto import Clock, Ed25519Signer
    from aisoc.training import DATASET_CURATOR_ROLE, build_snapshot, train_offline, write_snapshot, write_training_output

    root = tmp_path_factory.mktemp("training")
    snapshot = build_snapshot(conn_log=capture_dir / "conn.log", alerts=capture_dir / "alerts.json", tenant="tenant-test",
                              signer=Ed25519Signer(DATASET_CURATOR_ROLE), clock=Clock())
    write_snapshot(snapshot, root / "snapshot")
    result = train_offline(snapshot, seed=1, clock=Clock())
    write_training_output(result, root / "release")
    return root / "release"
