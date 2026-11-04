"""Packets -> bidirectional flows -> Zeek ``conn.log``-compatible rows.

Only header facts are kept (addresses, ports, protocol, sizes, TCP flags, time).
Payload bytes are counted, never stored: the training domain learns from traffic
*shape*, and nothing textual from the wire can reach the models or the agent.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10

# Zeek's conn.log column order; kept here so TSV consumers and docs have one source of truth.
CONN_LOG_FIELDS: List[str] = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration",
    "orig_bytes", "resp_bytes", "conn_state", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes",
    "resp_pkts", "resp_ip_bytes",
]

# Small, explicit port -> Zeek service name map. Anything else is "no service detected" (None),
# exactly like Zeek writes "-" when no protocol analyzer confirmed the service.
_SERVICE_BY_PORT: Dict[Tuple[str, int], str] = {
    ("tcp", 21): "ftp", ("tcp", 22): "ssh", ("tcp", 25): "smtp", ("tcp", 80): "http", ("tcp", 443): "ssl",
    ("tcp", 587): "smtp", ("tcp", 3389): "rdp", ("udp", 53): "dns", ("tcp", 53): "dns", ("udp", 123): "ntp",
    ("udp", 67): "dhcp", ("udp", 68): "dhcp",
}


# ── 【老師註解】PacketView ────────────────────────────────────────
# 做什麼：一個封包「只留表頭事實」的精簡視圖：時間、來源／目的 IP 與埠、協定、整個封包長度、酬載長度、TCP 旗標。
# 為什麼：訓練域只學「流量的形狀」，不碰內容。pyshark 解析出的物件很大、而且含酬載；在進入任何統計之前先縮成這個小型別，
#         之後的程式就物理上拿不到酬載——這是「日誌／流量內容一律不可信」在資料採集端的體現。
# 怎麼看：proto 只有 tcp / udp / icmp / other 四種；非 TCP 時 tcp_flags 永遠是 0；payload_len 是傳輸層酬載長度（Zeek 的 orig_bytes 就是數這個）。
# 拿掉會怎樣：若直接把 pyshark 的 Packet 物件往下傳，任何一個下游函式都可能不小心讀到酬載（含注入文字），而且無法用假資料測試。
# 對應：準則 #11；測試 tests/test_capture.py::test_tcp_handshake_and_close_becomes_sf_row
@dataclass(frozen=True)
class PacketView:
    ts: float
    src: str
    dst: str
    sport: int
    dport: int
    proto: str  # tcp | udp | icmp | other
    length: int  # whole frame length as captured
    payload_len: int = 0  # transport payload bytes (what Zeek counts in orig_bytes/resp_bytes)
    tcp_flags: int = 0

    def has(self, flag: int) -> bool:
        return self.proto == "tcp" and bool(self.tcp_flags & flag)


@dataclass
class _FlowState:
    orig_h: str
    orig_p: int
    resp_h: str
    resp_p: int
    proto: str
    ts_first: float
    ts_last: float
    orig_pkts: int = 0
    resp_pkts: int = 0
    orig_bytes: int = 0
    resp_bytes: int = 0
    orig_ip_bytes: int = 0
    resp_ip_bytes: int = 0
    history: str = ""
    orig_syn: bool = False
    resp_synack: bool = False
    orig_fin: bool = False
    resp_fin: bool = False
    orig_rst: bool = False
    resp_rst: bool = False
    seen_flags: set = field(default_factory=set)

    def _note(self, letter: str) -> None:
        # Zeek writes each history letter once per direction (uppercase = originator, lowercase = responder)
        if letter not in self.seen_flags:
            self.seen_flags.add(letter)
            self.history += letter


def _uid(orig_h: str, orig_p: int, resp_h: str, resp_p: int, proto: str, ts: float) -> str:
    raw = f"{orig_h}:{orig_p}-{resp_h}:{resp_p}/{proto}@{ts:.6f}".encode("utf-8")
    return "C" + hashlib.sha256(raw).hexdigest()[:17]


# ── 【老師註解】FlowAssembler ─────────────────────────────────────
# 做什麼：把一顆顆封包組回「雙向連線」(5-tuple)，並在連線結束（FIN/FIN、RST、閒置逾時、收工）時吐出一列 Zeek conn.log 格式的紀錄。
# 為什麼：論文的 FlowRecord 是「一個視窗一筆」，而 Slips 轉接器已經會讀 Zeek conn.log；只要這裡輸出的欄位與 Zeek 相同，
#         pyshark 抓到的流量就能原封不動走既有的 ZeekConnIndex → FlowRecord → dual_model 路徑，不必再寫第二套解析器。
# 怎麼看：
#   - 「發起者」(orig) = 第一個被看到的封包的來源；之後反向的封包都算回應者 (resp)。
#   - conn_state 是 Zeek 的近似（見 _conn_state 的對照表）；history 用 Zeek 的字母（S=SYN、h=SYN-ACK、A/a=ACK、D/d=資料、F/f=FIN、R/r=RST）。
#   - idle_timeout_s：超過這段時間沒有新封包的 UDP／半開 TCP 連線視為結束，才不會永遠掛在記憶體裡。
#   - 這裡「沒有」任何偵測邏輯；它只是量尺。偵測／攔截是 Slips 的事，判定是 dual_model 的事。
# 拿掉會怎樣：沒有流量組裝就沒有 bytes/pkts/duration 這些量化特徵；dual_model 看到的全是缺值 → 一律 UNKNOWN（安全，但什麼也學不到）。
# 對應：準則 #11、#12；測試 tests/test_capture.py::test_tcp_handshake_and_close_becomes_sf_row、::test_conn_state_table
class FlowAssembler:
    def __init__(self, idle_timeout_s: float = 60.0, close_delay_s: float = 5.0) -> None:
        if idle_timeout_s <= 0:
            raise ValueError("idle_timeout_s must be positive")
        self.idle_timeout_s = float(idle_timeout_s)
        # Zeek keeps a closed TCP connection around for a few seconds so the final ACKs are
        # absorbed instead of spawning a bogus one-packet "OTH" connection.
        self.close_delay_s = float(close_delay_s)
        self._flows: Dict[Tuple[str, int, str, int, str], _FlowState] = {}
        self._closing: Dict[Tuple[str, int, str, int, str], Tuple[_FlowState, float]] = {}
        self.flows_emitted = 0

    @property
    def open_flows(self) -> int:
        return len(self._flows) + len(self._closing)

    # ── 【老師註解】FlowAssembler.add ─────────────────────────────
    # 做什麼：餵進一個 PacketView，回傳「因為這個封包而結束」或「已閒置逾時」的連線列（通常是空列表）。
    # 怎麼看：步驟 1 先收割閒置連線（以這個封包的時間為「現在」，所以離線 PCAP 也能重現同樣結果）；
    #         步驟 2 找正向或反向的既有連線；步驟 3 更新計數與旗標；步驟 4 判斷是否已結束。
    # 拿掉閒置收割會怎樣：長時間抓包時 UDP／掃描產生的半開連線會無限累積，記憶體爆掉，而且這些連線永遠寫不進 conn.log。
    def add(self, pkt: PacketView) -> List[Dict[str, Any]]:
        closed: List[Dict[str, Any]] = self._expire_idle(pkt.ts)
        key_fwd = self._key(pkt.src, pkt.sport, pkt.dst, pkt.dport, pkt.proto)
        key_rev = self._key(pkt.dst, pkt.dport, pkt.src, pkt.sport, pkt.proto)
        # 剛結束不久的連線：尾端的 ACK 併入原連線，不另開新連線
        for k, from_orig in ((key_fwd, True), (key_rev, False)):
            if k in self._closing:
                closing_state, _ = self._closing[k]
                self._update(closing_state, pkt, from_orig)
                self._closing[k] = (closing_state, pkt.ts)
                return closed
        state = self._flows.get(key_fwd)
        from_orig = True
        if state is None and key_rev in self._flows:
            state = self._flows[key_rev]
            from_orig = False
        if state is None:
            # 第一次看到：這個封包的來源就是發起者（ICMP 的「埠」欄位保留 type/code，像 Zeek 一樣）
            state = _FlowState(pkt.src, int(pkt.sport), pkt.dst, int(pkt.dport), pkt.proto, pkt.ts, pkt.ts)
            self._flows[key_fwd] = state
            key = key_fwd
        else:
            key = key_fwd if from_orig else key_rev
        self._update(state, pkt, from_orig)
        if self._is_finished(state):
            # 進入「關閉等待」：close_delay_s 之後才正式寫出（見 _expire_idle）
            self._closing[key] = (state, pkt.ts)
            del self._flows[key]
        return closed

    # ── 【老師註解】FlowAssembler.flush_all ───────────────────────
    # 做什麼：收工時把所有還開著的連線全部寫出（例如抓包到時間了、PCAP 讀完了）。
    # 為什麼：還沒正式結束的連線也是真實流量；不寫出來就等於默默丟掉一部分資料，統計會偏向「短而完整」的連線。
    def flush_all(self) -> List[Dict[str, Any]]:
        states = list(self._flows.values()) + [s for s, _ in self._closing.values()]
        rows = [self._emit(s) for s in sorted(states, key=lambda s: s.ts_first)]
        self._flows.clear()
        self._closing.clear()
        return rows

    # ------------------------------------------------------------------ internals
    @staticmethod
    def _key(a: str, ap: int, b: str, bp: int, proto: str) -> Tuple[str, int, str, int, str]:
        # ICMP has no ports; type/code are kept in the row but must not split one exchange into two flows
        if proto == "icmp":
            return (a, 0, b, 0, proto)
        return (a, int(ap), b, int(bp), proto)

    def _expire_idle(self, now: float) -> List[Dict[str, Any]]:
        done: List[_FlowState] = []
        for k, (s, closed_at) in list(self._closing.items()):
            if now - closed_at > self.close_delay_s:
                done.append(self._closing.pop(k)[0])
        for k in [k for k, s in self._flows.items() if now - s.ts_last > self.idle_timeout_s]:
            done.append(self._flows.pop(k))
        return [self._emit(s) for s in sorted(done, key=lambda s: s.ts_first)]

    def _update(self, s: _FlowState, pkt: PacketView, from_orig: bool) -> None:
        s.ts_last = max(s.ts_last, pkt.ts)
        if from_orig:
            s.orig_pkts += 1
            s.orig_bytes += max(pkt.payload_len, 0)
            s.orig_ip_bytes += max(pkt.length, 0)
        else:
            s.resp_pkts += 1
            s.resp_bytes += max(pkt.payload_len, 0)
            s.resp_ip_bytes += max(pkt.length, 0)
        if pkt.proto != "tcp":
            s._note("D" if from_orig else "d")
            return
        # TCP flag bookkeeping (letters follow Zeek's history column)
        if pkt.has(TCP_SYN) and not pkt.has(TCP_ACK):
            if from_orig:
                s.orig_syn = True
            s._note("S" if from_orig else "s")
        elif pkt.has(TCP_SYN) and pkt.has(TCP_ACK):
            if not from_orig:
                s.resp_synack = True
            s._note("h" if not from_orig else "H")
        if pkt.has(TCP_FIN):
            if from_orig:
                s.orig_fin = True
            else:
                s.resp_fin = True
            s._note("F" if from_orig else "f")
        if pkt.has(TCP_RST):
            if from_orig:
                s.orig_rst = True
            else:
                s.resp_rst = True
            s._note("R" if from_orig else "r")
        if pkt.payload_len > 0:
            s._note("D" if from_orig else "d")
        elif pkt.has(TCP_ACK) and not pkt.has(TCP_SYN | TCP_FIN | TCP_RST):
            s._note("A" if from_orig else "a")

    @staticmethod
    def _is_finished(s: _FlowState) -> bool:
        if s.proto != "tcp":
            return False  # UDP/ICMP only end by idle timeout or flush
        return s.orig_rst or s.resp_rst or (s.orig_fin and s.resp_fin)

    # ── 【老師註解】FlowAssembler._conn_state ─────────────────────
    # 做什麼：把觀察到的旗標翻成 Zeek 的 conn_state 代碼。對照表（TCP）：
    #   沒看到發起者 SYN → OTH（抓包中途才開始看）；例外：只看到回應者 SYN-ACK+RST → RSTRH、SYN-ACK+FIN → SHR
    #   SYN、對方完全沒回 → S0            SYN、對方 RST → REJ
    #   SYN、自己又 RST（對方沒回）→ RSTOS0  SYN、自己又 FIN（對方沒回）→ SH
    #   握手完成後：雙方 FIN → SF；發起者 RST → RSTO；回應者 RST → RSTR；只有發起者 FIN → S2；只有回應者 FIN → S3；都沒有 → S1
    #   非 TCP：雙向都有封包 → SF；只有單向 → S0
    # 為什麼：Slips 轉接器用 _FAILED_CONN_STATES = {S0, REJ, RSTOS0, RSTRH, SH, SHR} 來數「失敗連線」——這是埠掃描最重要的特徵之一；
    #         代碼若對不上 Zeek 的定義，conn_failures 特徵就會失真。
    # 怎麼看：這是「近似」：Zeek 還看序號與重傳；這裡只看旗標。足夠餵給特徵，但不要拿它當封包鑑識證據。
    # 對應：準則 #11；測試 tests/test_capture.py::test_conn_state_table
    @staticmethod
    def _conn_state(s: _FlowState) -> str:
        if s.proto != "tcp":
            return "SF" if (s.orig_pkts and s.resp_pkts) else "S0"
        if not s.orig_syn:
            if s.resp_synack and s.resp_rst:
                return "RSTRH"
            if s.resp_synack and s.resp_fin:
                return "SHR"
            return "OTH"
        if not s.resp_synack:
            if s.resp_rst:
                return "REJ"
            if s.orig_rst:
                return "RSTOS0"
            if s.orig_fin:
                return "SH"
            if s.resp_pkts:
                return "OTH"
            return "S0"
        if s.orig_fin and s.resp_fin:
            return "SF"
        if s.orig_rst:
            return "RSTO"
        if s.resp_rst:
            return "RSTR"
        if s.orig_fin:
            return "S2"
        if s.resp_fin:
            return "S3"
        return "S1"

    # ── 【老師註解】FlowAssembler._emit ───────────────────────────
    # 做什麼：一條連線 → 一個 dict，鍵名與 Zeek conn.log 的 JSON 輸出完全相同（含 "id.orig_h" 這種帶點的鍵）。
    # 為什麼：ZeekConnIndex.from_lines 以 uid 建索引、aggregate() 讀 orig_bytes/resp_bytes/orig_pkts/resp_pkts/duration/ts/conn_state/id.resp_p；
    #         儀表板的 traffic_snapshot 讀 id.orig_h/id.resp_h/proto/service/conn_state。欄位對齊，所有下游零修改。
    # 怎麼看：uid 以 "C" 開頭、共 18 字元，模仿 Zeek；由 5-tuple + 首封包時間雜湊而來，所以同一份 PCAP 重跑會得到相同 uid（可重現）。
    #         service 是依埠號查表的「宣稱」，不是協定分析確認的結果；查不到就是 None（Zeek 寫 "-"）。
    def _emit(self, s: _FlowState) -> Dict[str, Any]:
        self.flows_emitted += 1
        return {
            "ts": round(s.ts_first, 6),
            "uid": _uid(s.orig_h, s.orig_p, s.resp_h, s.resp_p, s.proto, s.ts_first),
            "id.orig_h": s.orig_h,
            "id.orig_p": s.orig_p,
            "id.resp_h": s.resp_h,
            "id.resp_p": s.resp_p,
            "proto": s.proto,
            "service": _SERVICE_BY_PORT.get((s.proto, s.resp_p)),
            "duration": round(max(s.ts_last - s.ts_first, 0.0), 6),
            "orig_bytes": s.orig_bytes,
            "resp_bytes": s.resp_bytes,
            "conn_state": self._conn_state(s),
            "missed_bytes": 0,
            "history": s.history,
            "orig_pkts": s.orig_pkts,
            "orig_ip_bytes": s.orig_ip_bytes,
            "resp_pkts": s.resp_pkts,
            "resp_ip_bytes": s.resp_ip_bytes,
        }


def conn_log_row_lines(rows: Iterable[Dict[str, Any]]) -> List[str]:
    """Rows -> JSON lines exactly as Zeek's ``LogAscii::use_json=T`` would write them."""
    return [json.dumps(row, separators=(",", ":"), sort_keys=False) for row in rows]
