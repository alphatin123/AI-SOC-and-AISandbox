"""Loopback dashboard with read-only evidence and separate analyst classifications."""

from __future__ import annotations

import ipaddress
import json
import math
import os
import re
import secrets
import sqlite3
import stat
import subprocess
import sys
from collections import Counter
from contextlib import closing
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .adapters.slips import ZeekConnIndex, parse_alerts_json
from .canonical import digest


def _read_json(directory: Path, name: str, expected: type, default: Any) -> Any:
    path = directory / name
    if not path.exists():
        return default
    if path.is_symlink() or path.stat().st_size > 32 * 1024 * 1024:
        raise ValueError(f"{name}: unsafe file or export exceeds 32 MiB")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, expected):
        raise ValueError(f"{name}: expected {expected.__name__}")
    return value


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, str):
        candidate = value.removeprefix("host:")
        try:
            address = ipaddress.ip_interface(candidate)
            return "x.x.x.x" if address.version == 4 else "xxxx:xxxx::xxxx"
        except ValueError:
            return re.sub(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\w.])", "x.x.x.x", value)
    return value


def _case_export(directory: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    cases = _read_json(directory, "cases.json", list, [])
    summary = _read_json(directory, "slips-summary.json", dict, {})
    if isinstance(summary.get("case_results"), list):
        cases = summary["case_results"]
    if any(not isinstance(case, dict) or not isinstance(case.get("decision", {}), dict) for case in cases):
        raise ValueError("cases.json: malformed case")
    return cases, summary


def _review_path(directory: Path) -> Path:
    path = directory / ".dashboard-reviews.sqlite3"
    if path.is_symlink() or (path.exists() and (not path.is_file() or path.stat().st_size > 32 * 1024 * 1024)):
        raise ValueError("Unsafe review database")
    return path


def review_context(directory: Path, cases: list[dict[str, Any]]) -> dict[str, Any]:
    context = {case["case_id"]: {"case_digest": digest(case), "latest": None, "history": []}
               for case in cases if case.get("case_id") and case.get("decision", {}).get("status") == "MODEL_CONFLICT"}
    path = _review_path(directory)
    if not path.exists():
        return context
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as database:
        database.row_factory = sqlite3.Row
        for row in database.execute("SELECT * FROM reviews ORDER BY review_id DESC"):
            item = dict(row)
            current = context.get(item["case_id"])
            if current is not None and current["case_digest"] == item["case_digest"]:
                if current["latest"] is None:
                    current["latest"] = item
                if len(current["history"]) < 10:
                    current["history"].append(item)
    return context


class ReviewConflictError(ValueError):
    pass


def save_review(directory: Path, case_id: str, verdict: str, case_digest: str) -> dict[str, Any]:
    if not isinstance(case_id, str) or not isinstance(case_digest, str) or verdict not in ("TRUE_POSITIVE", "FALSE_POSITIVE"):
        raise ValueError("Review requires a case, case digest, and TRUE_POSITIVE or FALSE_POSITIVE verdict")
    cases, _ = _case_export(directory)
    case = next((item for item in cases if item.get("case_id") == case_id), None)
    if case is None:
        raise KeyError("Case not found")
    if case.get("decision", {}).get("status") != "MODEL_CONFLICT":
        raise ValueError("Classification is available only for MODEL_CONFLICT cases")
    if digest(case) != case_digest:
        raise ReviewConflictError("Case changed; refresh the case before reviewing")
    path = _review_path(directory)
    if not path.exists():
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            os.close(descriptor)
        except FileExistsError:
            _review_path(directory)
    with closing(sqlite3.connect(path)) as database, database:
        database.row_factory = sqlite3.Row
        database.execute("CREATE TABLE IF NOT EXISTS reviews (review_id INTEGER PRIMARY KEY, "
                         "case_id TEXT NOT NULL, case_digest TEXT NOT NULL, verdict TEXT NOT NULL "
                         "CHECK(verdict IN ('TRUE_POSITIVE', 'FALSE_POSITIVE')), reviewed_at TEXT NOT NULL, "
                         "reviewer TEXT NOT NULL)")
        database.execute("BEGIN IMMEDIATE")
        previous = database.execute("SELECT * FROM reviews WHERE case_id=? AND case_digest=? "
                                    "ORDER BY review_id DESC LIMIT 1", (case_id, case_digest)).fetchone()
        if previous is not None and previous["verdict"] == verdict:
            return dict(previous)
        cursor = database.execute("INSERT INTO reviews (case_id, case_digest, verdict, reviewed_at, reviewer) "
                                  "VALUES (?, ?, ?, ?, ?)",
                                  (case_id, case_digest, verdict, datetime.now(timezone.utc).isoformat(), "local-analyst"))
        row = database.execute("SELECT * FROM reviews WHERE review_id=?", (cursor.lastrowid,)).fetchone()
        return dict(row)


def snapshot(directory: Path) -> dict[str, Any]:
    cases, summary = _case_export(directory)
    ledger = _read_json(directory, "ledger.json", list, [])
    receipts = _read_json(directory, "tool-side-receipts.json", list, [])
    checkpoints = _read_json(directory, "witness-checkpoints.json", list, [])
    if any(not isinstance(case, dict) or not isinstance(case.get("decision", {}), dict) for case in cases):
        raise ValueError("cases.json: malformed case")
    statuses = Counter(case.get("decision", {}).get("status", "UNKNOWN") for case in cases)
    requests = [request for case in cases for request in case.get("requests", []) if isinstance(request, dict)]
    live = any(isinstance(entry, dict) and entry.get("entry_type") == "executor_configuration" for entry in ledger)
    return _redact({
        "run": directory.name,
        "source": "Slips export" if summary else "Synthetic export",
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "Recorded executor configuration" if live else "Simulation / exported evidence",
        "cases": cases,
        "review_context": review_context(directory, cases),
        "statuses": dict(statuses),
        "counts": {
            "cases": len(cases), "investigated": sum(bool(case.get("investigated")) for case in cases),
            "review": sum(bool(case.get("decision", {}).get("requires_human_review")) for case in cases),
            "executed": sum(bool(request.get("executed")) for request in requests),
            "blocks": sum(request.get("action") == "block_host" and bool(request.get("executed")) for request in requests),
            "entries": len(ledger), "receipts": len(receipts), "checkpoints": len(checkpoints),
        },
        "ledger": ledger[-80:][::-1],
        "receipts": receipts[-80:][::-1],
        "checkpoints": checkpoints[-30:][::-1],
    })


def verify_export(directory: Path) -> dict[str, Any]:
    result = subprocess.run(
        [sys.executable, "-m", "aisoc", "verify", str(directory)],
        capture_output=True, text=True, timeout=20,
    )
    if result.returncode not in (0, 1):
        raise ValueError("Verifier could not complete")
    try:
        report = json.loads(result.stdout)
    except ValueError as exc:
        raise ValueError("Verification unavailable: export is incomplete or malformed") from exc
    return _redact(report)


def _sensor_tail(path: Path | None, now: float) -> tuple[list[str], dict[str, Any]]:
    if path is None:
        return [], {"status": "NOT_CONFIGURED"}
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("sensor must be a regular file")
            header = stream.read(65536).split(b"\n")[:-1]
            offset = max(0, info.st_size - 2 * 1024 * 1024)
            stream.seek(offset)
            buffer = stream.read(2 * 1024 * 1024)
        partial = bool(buffer and not buffer.endswith(b"\n"))
        lines = buffer.split(b"\n")[:-1]
        if offset:
            lines = lines[1:]
        metadata = {
            "status": "FRESH" if now - info.st_mtime <= 30 else "STALE",
            "updated_at": datetime.fromtimestamp(info.st_mtime, timezone.utc).isoformat(),
            "age_s": round(max(0, now - info.st_mtime), 1),
            "truncated": bool(offset), "partial_line": partial,
        }
        headers = [line for line in header if line.startswith((b"#fields", b"#separator"))]
        return [line.decode("utf-8", errors="replace") for line in headers + lines], metadata
    except FileNotFoundError:
        return [], {"status": "WAITING", "error": "Sensor file has not been created"}
    except (OSError, ValueError):
        return [], {"status": "ERROR", "error": "Sensor file is unreadable or is not a regular file"}


def _sensor_number(value: Any) -> float | None:
    try:
        number = float(value)
        return number if math.isfinite(number) and number >= 0 else None
    except (TypeError, ValueError):
        return None


def traffic_snapshot(conn_log: Path | None = None, alerts: Path | None = None, *,
                    reveal_ips: bool = False) -> dict[str, Any]:
    now = datetime.now(timezone.utc).timestamp()
    connection_lines, connection_source = _sensor_tail(conn_log, now)
    alert_lines, alert_source = _sensor_tail(alerts, now)
    index = ZeekConnIndex.from_lines(connection_lines)
    connections = []
    for row in index.rows.values():
        timestamp = _sensor_number(row.get("ts"))
        if timestamp is None:
            continue
        orig_bytes, resp_bytes = _sensor_number(row.get("orig_bytes")), _sensor_number(row.get("resp_bytes"))
        connections.append({
            "uid": str(row["uid"]), "timestamp": timestamp,
            "source": row.get("id.orig_h"), "source_port": row.get("id.orig_p"),
            "destination": row.get("id.resp_h"), "destination_port": row.get("id.resp_p"),
            "protocol": row.get("proto"), "service": row.get("service"),
            "state": row.get("conn_state"),
            "bytes": orig_bytes + resp_bytes if orig_bytes is not None and resp_bytes is not None else None,
        })
    recent = [row for row in connections if now - 60 <= row["timestamp"] <= now]
    buckets = [0] * 12
    for row in recent:
        bucket = min(11, int((row["timestamp"] - (now - 60)) / 5))
        buckets[bucket] += 1
    evidence = []
    malformed = 0
    incidents = 0
    for line in alert_lines:
        if not line.strip() or line.startswith("#"):
            continue
        try:
            if not isinstance(json.loads(line), dict):
                raise ValueError("invalid alert")
            parsed = parse_alerts_json([line])
            malformed += parsed.malformed
            incidents += len(parsed.incidents)
            evidence.extend({
                "id": item.id, "timestamp": item.start_time, "type": item.evidence_type,
                "source": item.source_ip, "destination": item.target_ip,
                "confidence": item.confidence, "severity": item.threat_level,
            } for item in parsed.evidence)
        except (ValueError, TypeError, AttributeError, IndexError):
            malformed += 1
    statuses = [source["status"] for source in (connection_source, alert_source)]
    status = ("ERROR" if "ERROR" in statuses else "FRESH" if "FRESH" in statuses else
              "STALE" if "STALE" in statuses else "WAITING" if "WAITING" in statuses else "NOT_CONFIGURED")
    byte_counts = [row["bytes"] for row in recent if row["bytes"] is not None]
    result = {
        "status": status, "updated_at": datetime.fromtimestamp(now, timezone.utc).isoformat(),
        "ip_visibility": "VISIBLE" if reveal_ips else "MASKED",
        "sources": {"connections": connection_source, "alerts": alert_source},
        "counts": {"connections_60s": len(recent), "bytes_60s": sum(byte_counts) if byte_counts else None,
                   "buffer_connections": len(connections), "buffer_alerts": len(evidence),
                   "buffer_incidents": incidents, "malformed_alerts": malformed},
        "buckets": buckets, "protocols": dict(Counter(str(row["protocol"] or "unknown") for row in recent)),
        "connections": sorted(connections, key=lambda row: row["timestamp"], reverse=True)[:1000],
        "alerts": evidence[-100:][::-1],
    }
    return result if reveal_ips else _redact(result)


def create_server(directory: Path, port: int = 8765, *, conn_log: Path | None = None,
                  alerts: Path | None = None, reveal_ips: bool = False) -> ThreadingHTTPServer:
    directory = directory.resolve(strict=True)
    if not directory.is_dir():
        raise ValueError("Dashboard requires an exported run directory")
    review_token = secrets.token_urlsafe(32)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.headers.get("Host") not in (f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"):
                self.send_error(403)
                return
            route = urlsplit(self.path).path
            try:
                if route in ("/", "/index.html"):
                    html = Path(__file__).with_name("dashboard.html").read_text(encoding="utf-8")
                    payload = html.replace("</head>", f'<meta name="review-token" content="{review_token}"></head>').encode("utf-8")
                    content_type = "text/html; charset=utf-8"
                elif route == "/lucide.js":
                    payload = Path(__file__).with_name("lucide.js").read_bytes()
                    content_type = "text/javascript; charset=utf-8"
                elif route in ("/api/snapshot", "/api/verify", "/api/traffic"):
                    if route == "/api/traffic":
                        data = traffic_snapshot(conn_log, alerts, reveal_ips=reveal_ips)
                    else:
                        data = snapshot(directory) if route == "/api/snapshot" else verify_export(directory)
                    payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
                    content_type = "application/json; charset=utf-8"
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
            except (OSError, ValueError, TypeError, sqlite3.Error, subprocess.TimeoutExpired):
                self.send_response(503)
                payload = json.dumps({"error": "Export unavailable or incomplete. Check the selected run directory."}).encode()
                content_type = "application/json"
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self) -> None:
            host = self.headers.get("Host", "")
            allowed = (f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}")
            if host not in allowed:
                self._review_response(403, {"error": "Host not allowed"})
                return
            if self.path != "/api/review":
                self._review_response(404, {"error": "Route not found"})
                return
            presented_token = self.headers.get("X-Review-Token", "")
            if (self.headers.get("Origin") != f"http://{host}" or not presented_token.isascii()
                    or not secrets.compare_digest(presented_token, review_token)):
                self._review_response(403, {"error": "Same-origin review token required"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 4096 or self.headers.get_content_type() != "application/json":
                    raise ValueError("Review must be a JSON body up to 4096 bytes")
                self.connection.settimeout(5)
                body = json.loads(self.rfile.read(length))
                if not isinstance(body, dict) or set(body) != {"case_id", "verdict", "case_digest"}:
                    raise ValueError("Unexpected review fields")
                result = save_review(directory, body["case_id"], body["verdict"], body["case_digest"])
            except ReviewConflictError as exc:
                self._review_response(409, {"error": str(exc)})
            except KeyError:
                self._review_response(404, {"error": "Case not found"})
            except (ValueError, TypeError, UnicodeError) as exc:
                self._review_response(400, {"error": str(exc)})
            except (OSError, sqlite3.Error):
                self._review_response(503, {"error": "Review could not be saved"})
            else:
                self._review_response(200, {"review": result})

        def _review_response(self, status_code: int, data: dict[str, Any]) -> None:
            payload = json.dumps(_redact(data)).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: Any) -> None:
            pass

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def serve(directory: str, port: int = 8765, *, conn_log: str | None = None,
        alerts: str | None = None, reveal_ips: bool = False) -> int:
    server = create_server(Path(directory), port, conn_log=Path(conn_log) if conn_log else None,
                   alerts=Path(alerts) if alerts else None, reveal_ips=reveal_ips)
    print(f"AI-SOC dashboard: http://127.0.0.1:{server.server_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0