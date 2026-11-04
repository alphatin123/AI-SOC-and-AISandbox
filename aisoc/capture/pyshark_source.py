"""pyshark-backed packet sources (live interface or PCAP file).

pyshark drives ``tshark`` (Wireshark's CLI).  Both are optional dependencies of
this project; importing them happens lazily so that the rest of the training
domain, its tests and the dashboard work on machines without Wireshark.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, Iterator, Optional

from .flows import PacketView


class CaptureUnavailable(RuntimeError):
    """pyshark or tshark is not installed / usable on this machine."""


# ── 【老師註解】_import_pyshark ───────────────────────────────────
# 做什麼：在「真的要抓包」的那一刻才 import pyshark；沒裝就丟 CaptureUnavailable，並把安裝指令寫在錯誤訊息裡。
# 為什麼：pyshark 需要系統層的 tshark（Wireshark）。把 import 放在模組最上面，會讓沒有 Wireshark 的機器連
#         `python -m aisoc simulate` 都跑不起來——偵測管線不該因為一個「選配的感測器」而整個失效。
# 拿掉會怎樣：CI、儀表板、評測全都綁死在 Wireshark 上；而且錯誤會是看不懂的 ModuleNotFoundError。
# 對應：準則 #13；測試 tests/test_capture.py::test_pyshark_source_reports_unavailable_cleanly
def _import_pyshark() -> Any:
    try:
        import pyshark  # type: ignore
    except ImportError as exc:  # pragma: no cover - depends on the machine
        raise CaptureUnavailable(
            "pyshark is not installed; install the optional extra `pip install 'aisoc[capture]'` "
            "(and the system package tshark/wireshark-cli) to capture packets"
        ) from exc
    return pyshark


def _versions() -> Dict[str, Optional[str]]:
    out: Dict[str, Optional[str]] = {"pyshark": None, "tshark": None}
    try:
        from importlib import metadata

        out["pyshark"] = metadata.version("pyshark")
    except Exception:  # pragma: no cover - only when pyshark metadata is missing
        pass
    try:
        from pyshark.tshark import tshark as _tshark  # type: ignore

        out["tshark"] = str(_tshark.get_tshark_version())
    except Exception:
        pass
    return out


# ── 【老師註解】packet_view_from_pyshark ──────────────────────────
# 做什麼：pyshark 的 Packet（巨大、含酬載）→ PacketView（只留表頭事實）。非 IP 封包（ARP、純 L2）回 None，由呼叫端計數後跳過。
# 為什麼：這是「酬載在這裡被丟掉」的那一行。往後的流程只拿得到 IP、埠、長度、旗標與時間。
# 怎麼看：pyshark 把 TCP 旗標給成 "0x0018" 這種十六進位字串，所以用 int(x, 16)；欄位缺失時一律當 0，不猜值。
#         ICMP 用 type/code 填進 sport/dport（Zeek 也是這樣放）。
# 拿掉會怎樣：FlowAssembler 得直接讀 pyshark 物件，無法用假封包測試，也無法保證酬載沒被誰讀走。
# 對應：準則 #11；測試 tests/test_capture.py::test_packet_view_from_pyshark_like_object
def packet_view_from_pyshark(pkt: Any) -> Optional[PacketView]:
    ip = getattr(pkt, "ip", None) or getattr(pkt, "ipv6", None)
    if ip is None:
        return None
    try:
        ts = float(getattr(pkt, "sniff_timestamp", 0.0) or 0.0)
        length = int(getattr(pkt, "length", 0) or 0)
    except (TypeError, ValueError):
        return None
    src, dst = str(getattr(ip, "src", "")), str(getattr(ip, "dst", ""))
    if not src or not dst:
        return None
    transport = str(getattr(pkt, "transport_layer", "") or "").upper()
    if transport == "TCP" and getattr(pkt, "tcp", None) is not None:
        tcp = pkt.tcp
        flags_raw = str(getattr(tcp, "flags", "0") or "0")
        try:
            flags = int(flags_raw, 16) if flags_raw.lower().startswith("0x") else int(flags_raw)
        except ValueError:
            flags = 0
        return PacketView(ts, src, dst, _int(getattr(tcp, "srcport", 0)), _int(getattr(tcp, "dstport", 0)),
                          "tcp", length, _int(getattr(tcp, "len", 0)), flags)
    if transport == "UDP" and getattr(pkt, "udp", None) is not None:
        udp = pkt.udp
        # udp.length includes the 8-byte UDP header
        payload = max(_int(getattr(udp, "length", 0)) - 8, 0)
        return PacketView(ts, src, dst, _int(getattr(udp, "srcport", 0)), _int(getattr(udp, "dstport", 0)),
                          "udp", length, payload, 0)
    icmp = getattr(pkt, "icmp", None) or getattr(pkt, "icmpv6", None)
    if icmp is not None:
        return PacketView(ts, src, dst, _int(getattr(icmp, "type", 0)), _int(getattr(icmp, "code", 0)),
                          "icmp", length, 0, 0)
    return PacketView(ts, src, dst, 0, 0, "other", length, 0, 0)


def _int(value: Any) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


# ── 【老師註解】PysharkSource ─────────────────────────────────────
# 做什麼：可迭代的封包來源。live(interface, bpf) 開即時抓包；pcap(path) 讀檔。迭代時逐顆轉成 PacketView；非 IP 的記在 packets_skipped。
# 為什麼：runner 只認「可迭代、有 describe() 與兩個計數器」的物件，所以同一條流程可以餵真網卡、PCAP、或測試用的 FakePacketSource。
# 怎麼看：describe() 的內容會原封寫進 capture-manifest.json（介面名或 PCAP 的 SHA-256、BPF 過濾器、pyshark/tshark 版本），
#         之後資料集副本的 manifest 再引用它——這就是「資料從哪來」的第一環證據。
#         BPF 過濾器只做「少抓」，不做「改內容」；預設不過濾。建議在 Slips 同一台機器上抓同一張網卡，證據與標籤才對得上。
# 拿掉會怎樣：資料集 manifest 會寫不出來源；沒有來源的資料集無法被稽核者重現。
# 對應：準則 #7、#13；測試 tests/test_capture.py::test_pyshark_source_reports_unavailable_cleanly
class PysharkSource:
    def __init__(self, capture: Any, descriptor: Dict[str, Any]) -> None:
        self._capture = capture
        self._descriptor = descriptor
        self.packets_seen = 0
        self.packets_skipped = 0

    @classmethod
    def live(cls, interface: str, bpf_filter: Optional[str] = None, tshark_path: Optional[str] = None) -> "PysharkSource":
        pyshark = _import_pyshark()
        try:
            cap = pyshark.LiveCapture(interface=interface, bpf_filter=bpf_filter or None, tshark_path=tshark_path)
        except Exception as exc:  # TSharkNotFoundException and friends
            raise CaptureUnavailable(f"cannot start live capture on {interface!r}: {type(exc).__name__}: {exc}") from exc
        return cls(cap, {"kind": "live", "interface": interface, "bpf_filter": bpf_filter, **_versions()})

    @classmethod
    def pcap(cls, path: str | Path, display_filter: Optional[str] = None, tshark_path: Optional[str] = None) -> "PysharkSource":
        pyshark = _import_pyshark()
        p = Path(path)
        if not p.is_file():
            raise CaptureUnavailable(f"pcap file not found: {p}")
        sha = hashlib.sha256(p.read_bytes()).hexdigest()
        try:
            # FileCapture has no BPF option; offline files take a Wireshark *display* filter instead
            cap = pyshark.FileCapture(input_file=str(p), display_filter=display_filter or None, keep_packets=False, tshark_path=tshark_path)
        except Exception as exc:
            raise CaptureUnavailable(f"cannot open pcap {p}: {type(exc).__name__}: {exc}") from exc
        return cls(cap, {"kind": "pcap", "pcap_path": str(p), "pcap_sha256": sha, "display_filter": display_filter, **_versions()})

    def describe(self) -> Dict[str, Any]:
        return dict(self._descriptor)

    def __iter__(self) -> Iterator[PacketView]:
        try:
            iterator = self._capture.sniff_continuously() if hasattr(self._capture, "sniff_continuously") else iter(self._capture)
            for raw in iterator:
                self.packets_seen += 1
                view = packet_view_from_pyshark(raw)
                if view is None:
                    self.packets_skipped += 1
                    continue
                yield view
        except CaptureUnavailable:
            raise
        except Exception as exc:  # tshark died, permission denied, malformed file ...
            raise CaptureUnavailable(f"capture stopped: {type(exc).__name__}: {exc}") from exc

    def close(self) -> None:
        try:
            self._capture.close()
        except Exception:
            pass
