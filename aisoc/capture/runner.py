"""Drive a packet source through the FlowAssembler and record what was captured."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional

from ..owp.objects import schema
from .flows import FlowAssembler, PacketView, conn_log_row_lines

CAPTURE_MANIFEST_SCHEMA = schema("capture-manifest")


# ── 【老師註解】FakePacketSource ──────────────────────────────────
# 做什麼：測試／示範用的封包來源：給它一串 PacketView，它就像 PysharkSource 一樣可迭代、有 describe() 與計數器。
# 為什麼：抓包需要 root、網卡與 Wireshark；單元測試不能依賴這些。用假來源可以確定地重現「這 12 顆封包應該變成這 3 條連線」。
# 對應：準則 #13；測試 tests/test_capture.py::test_run_capture_writes_rows_and_manifest
class FakePacketSource:
    def __init__(self, packets: Iterable[PacketView], descriptor: Optional[Dict[str, Any]] = None) -> None:
        self._packets = list(packets)
        self._descriptor = descriptor or {"kind": "fake", "interface": None, "bpf_filter": None}
        self.packets_seen = 0
        self.packets_skipped = 0
        self.closed = False

    def describe(self) -> Dict[str, Any]:
        return dict(self._descriptor)

    def __iter__(self) -> Iterator[PacketView]:
        for p in self._packets:
            self.packets_seen += 1
            yield p

    def close(self) -> None:
        self.closed = True


@dataclass
class CaptureStats:
    packets: int = 0
    flows_written: int = 0
    started_at: str = ""
    finished_at: str = ""
    stop_reason: str = ""
    first_packet_ts: Optional[float] = None
    last_packet_ts: Optional[float] = None
    errors: List[str] = field(default_factory=list)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


# ── 【老師註解】run_capture ───────────────────────────────────────
# 做什麼：抓包主迴圈。封包 → FlowAssembler → 連線一結束就 append 一行 JSON 到 out_path（Zeek conn.log 格式）；
#         結束條件：封包數上限、秒數上限、來源讀完、或 Ctrl-C。收工時 flush 所有未結束連線，再寫 capture-manifest.json。
# 為什麼：
#   - 「邊抓邊寫」而不是收工才寫：儀表板的 IDPS 頁面可以 --conn-log 指向這個檔即時看；而且中途當機不會全部遺失。
#   - manifest 記下來源（網卡或 PCAP 雜湊）、過濾器、起訖時間、封包數、跳過的非 IP 封包數、連線數、輸出檔雜湊、工具版本：
#     這是資料集副本 manifest 的「上游證據」，沒有它就無法回答「這批資料是哪裡、什麼時候、用什麼抓的」。
#   - Ctrl-C 也要走正常收尾：中斷的抓包仍是合法資料，但 stop_reason 會誠實寫 "interrupted"。
# 怎麼看：duration_s 用的是牆上時鐘（time.monotonic），因為即時抓包時封包時間戳可能延遲；離線 PCAP 建議用 --packets 控制。
#         輸出檔若已存在會「續寫」(append)，所以 out_sha256 是整個檔案的雜湊——想要乾淨的一份就換個檔名。
# 拿掉會怎樣：沒有 manifest 的 conn.log 只是一堆行；資料集副本就簽不出可追溯的來源，稽核者也無法核對封包數是否被動過。
# 對應：準則 #7、#11、#13；測試 tests/test_capture.py::test_run_capture_writes_rows_and_manifest
def run_capture(
    source: Any,
    out_path: str | Path,
    *,
    max_packets: Optional[int] = None,
    duration_s: Optional[float] = None,
    idle_timeout_s: float = 60.0,
    manifest_path: Optional[str | Path] = None,
    progress: Optional[Callable[[CaptureStats], None]] = None,
    progress_every: int = 500,
) -> Dict[str, Any]:
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    manifest_file = Path(manifest_path) if manifest_path else out.with_name("capture-manifest.json")
    assembler = FlowAssembler(idle_timeout_s=idle_timeout_s)
    stats = CaptureStats(started_at=_now_iso())
    t0 = time.monotonic()
    stop = "source_exhausted"

    def write_rows(handle: Any, rows: List[Dict[str, Any]]) -> None:
        if not rows:
            return
        handle.write("\n".join(conn_log_row_lines(rows)) + "\n")
        handle.flush()
        stats.flows_written += len(rows)

    with out.open("a", encoding="utf-8") as handle:
        try:
            for pkt in source:
                stats.packets += 1
                stats.first_packet_ts = pkt.ts if stats.first_packet_ts is None else stats.first_packet_ts
                stats.last_packet_ts = pkt.ts
                write_rows(handle, assembler.add(pkt))
                if progress and stats.packets % progress_every == 0:
                    progress(stats)
                if max_packets is not None and stats.packets >= max_packets:
                    stop = "max_packets"
                    break
                if duration_s is not None and time.monotonic() - t0 >= duration_s:
                    stop = "duration"
                    break
        except KeyboardInterrupt:
            stop = "interrupted"
        except Exception as exc:  # capture errors must still leave a truthful manifest behind
            stop = "error"
            stats.errors.append(f"{type(exc).__name__}: {exc}")
        finally:
            write_rows(handle, assembler.flush_all())
            try:
                source.close()
            except Exception:
                pass
    stats.stop_reason = stop
    stats.finished_at = _now_iso()
    manifest = {
        "schema": CAPTURE_MANIFEST_SCHEMA,
        "source": source.describe(),
        "packets_seen": getattr(source, "packets_seen", stats.packets),
        "packets_used": stats.packets,
        "packets_skipped_non_ip": getattr(source, "packets_skipped", 0),
        "flows_written": stats.flows_written,
        "idle_timeout_s": idle_timeout_s,
        "format": "zeek-conn-json",
        "fields": "ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes conn_state missed_bytes history orig_pkts orig_ip_bytes resp_pkts resp_ip_bytes",
        "out_path": str(out),
        "out_sha256": hashlib.sha256(out.read_bytes()).hexdigest(),
        "content_policy": "header facts only; payload bytes are counted, never stored",
        **{k: v for k, v in asdict(stats).items() if k not in ("packets", "flows_written")},
    }
    manifest_file.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if stats.errors:
        raise RuntimeError(f"capture ended with errors (manifest written to {manifest_file}): {stats.errors[0]}")
    return manifest
