#!/usr/bin/env python3
"""Render the two architecture figures used in docs/DIAGRAMS.zh-TW.md.

  figure 1  architecture-1-workflow   system workflow: AI-SOC (detection) x
                                      AI-Sandbox (response) x OWP ledger
  figure 2  decision-tree             dual_model Table III decision tree
                                      (aisoc/idps/dual_model.py::_combine)

Pure standard library; writes SVG and, when ``rsvg-convert`` is installed
(``apt install librsvg2-bin``), a 2560px-wide PNG next to it.  Both canvases
are 1920x1080 so they drop straight into a 16:9 slide.

Usage:  python docs/diagrams/make_diagrams.py [--no-png]
"""

from __future__ import annotations

import html
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

OUT = Path(__file__).resolve().parent
W, H = 1920, 1080
FONT = "'WenQuanYi Zen Hei','Noto Sans CJK TC','Microsoft JhengHei','PingFang TC',sans-serif"
MONO = "'DejaVu Sans Mono',Consolas,'Courier New',monospace"
PNG_WIDTH = 2560

# palette (fill, stroke)
C_SOC = ("#EEF4FB", "#2F5FA7")
C_SBX = ("#FFF6E8", "#C77D16")
C_LEDGER = ("#ECEFF1", "#37474F")
C_ONLINE = ("#E0F2F1", "#00796B")
C_TRAIN = ("#E8EAF6", "#3F51B5")
C_IDPS = ("#E3F2FD", "#1565C0")
C_SANDBOX = ("#FFF8E1", "#F9A825")
C_CTRL = ("#FBE9E7", "#D84315")
C_EXEC = ("#F3E5F5", "#6A1B9A")
C_DECISION = ("#FFF59D", "#F9A825")
C_INPUT = ("#E3F2FD", "#1565C0")
C_BRANCH = ("#E8EAF6", "#3F51B5")
C_WHITE_AMBER = ("#FFFFFF", "#F9A825")
INK = "#1F2933"
MUTED = "#5B6770"

STATUS_COLORS = {
    "KNOWN_SUSPICIOUS": "#EF6C00",
    "SUSPECTED_UNKNOWN": "#C62828",
    "MODEL_CONFLICT": "#7B1FA2",
    "INSUFFICIENT_EVIDENCE": "#546E7A",
    "LOW_RISK_OBSERVE": "#2E7D32",
    "UNKNOWN": "#263238",
}


# ──────────────────────────────────────────────────────────── text metrics
# Per-glyph advance widths (em) measured on WenQuanYi Zen Hei; a 3 % margin is
# added in wrap() so other CJK fonts with slightly wider Latin glyphs still fit.
def _char_w(ch: str) -> float:
    o = ord(ch)
    if 0x2E80 <= o <= 0x9FFF or 0xAC00 <= o <= 0xD7AF or 0xF900 <= o <= 0xFAFF or 0xFF00 <= o <= 0xFFEF:
        return 1.0
    if ch in "①②③④⑤⑥⑦⑧⑨⑩⇒→⇔∧∨≥≤×✓✗¬・—":
        return 0.9
    if ch.isupper():
        return 0.6
    if ch.isdigit():
        return 0.6
    if ch in " ,.;:'·|/()":
        return 0.32
    return 0.48


def text_width(s: str, size: float, mono: bool = False) -> float:
    if mono:
        return len(s) * size * 0.602
    return sum(_char_w(c) for c in s) * size


def wrap(text: str, max_px: float, size: float) -> List[str]:
    """Greedy wrap; every CJK character is a break opportunity, Latin words are kept whole."""
    limit = max_px / 1.03
    lines: List[str] = []
    for para in text.split("\n"):
        cur, token = "", ""

        def push(piece: str) -> None:
            nonlocal cur
            if text_width(cur + piece, size) > limit and cur:
                lines.append(cur.rstrip())
                cur = piece.lstrip()
            else:
                cur += piece

        for ch in para:
            if _char_w(ch) >= 0.9 or ch == " ":
                if token:
                    push(token)
                    token = ""
                push(ch)
            else:
                token += ch
        if token:
            push(token)
        lines.append(cur.rstrip())
    return lines


# ──────────────────────────────────────────────────────────── svg writer
class SVG:
    def __init__(self, title: str) -> None:
        self.parts: List[str] = []
        self.title = title
        self.warnings: List[str] = []

    def add(self, s: str) -> None:
        self.parts.append(s)

    def rect(self, x, y, w, h, fill, stroke, rx=10, sw=2, dash: Optional[str] = None) -> None:
        d = f' stroke-dasharray="{dash}"' if dash else ""
        self.add(f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" rx="{rx}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"{d}/>')

    def text(self, x, y, s, size=15, fill=INK, weight="normal", anchor="start", font=FONT) -> None:
        self.add(f'<text x="{x:.1f}" y="{y:.1f}" font-family="{font}" font-size="{size}" font-weight="{weight}" fill="{fill}" text-anchor="{anchor}">{html.escape(s)}</text>')

    def label(self, x, y, s, size=14, fill=INK, anchor="middle", weight="normal") -> None:
        """Text on a white backing so it stays legible when it sits on a line."""
        tw = text_width(s, size) + 10
        bx = x - tw / 2 if anchor == "middle" else (x - 5 if anchor == "start" else x - tw + 5)
        self.add(f'<rect x="{bx:.1f}" y="{y - size + 1:.1f}" width="{tw:.1f}" height="{size + 6}" rx="4" fill="#FFFFFF" opacity="0.94"/>')
        self.text(x, y, s, size, fill, weight, anchor)

    def path(self, pts: Sequence[Tuple[float, float]], stroke=INK, sw=2.2, dashed=False, arrow=True, marker="arrow") -> None:
        d = " ".join(f"{'M' if i == 0 else 'L'}{px:.1f},{py:.1f}" for i, (px, py) in enumerate(pts))
        dash = ' stroke-dasharray="7,6"' if dashed else ""
        mk = f' marker-end="url(#{marker})"' if arrow else ""
        self.add(f'<path d="{d}" fill="none" stroke="{stroke}" stroke-width="{sw}"{dash}{mk} stroke-linejoin="round"/>')

    # A box sizes itself from its content: title (bold, stroke colour), wrapped
    # body, and an optional code path printed bottom-right in monospace.
    def box(self, x, y, w, title: str, body: str = "", colors=C_IDPS, ts=15, bs=14, code: Optional[str] = None,
            center=False, h: Optional[float] = None, dry=False) -> float:
        fill, stroke = colors
        pad = 12
        tls = wrap(title, w - 2 * pad, ts)
        bls = wrap(body, w - 2 * pad, bs) if body else []
        ty = y + ts + 7
        last_ty = ty + (len(tls) - 1) * ts * 1.3
        if bls:
            by = last_ty + ts * 0.55 + bs
            last_by = by + (len(bls) - 1) * bs * 1.42
            bottom = last_by + bs * 0.45
        else:
            bottom = last_ty + ts * 0.4
        need = bottom - y + 9 + (14 if code else 0)
        if h is None:
            h = need
        elif need > h + 1:
            self.warnings.append(f"overflow {need - h:.0f}px in box '{title[:18]}'")
        if dry:
            return h
        self.rect(x, y, w, h, fill, stroke)
        tx = x + w / 2 if center else x + pad
        anchor = "middle" if center else "start"
        for i, tl in enumerate(tls):
            self.text(tx, ty + i * ts * 1.3, tl, ts, stroke, "bold", anchor)
        for i, bl in enumerate(bls):
            self.text(tx, by + i * bs * 1.42, bl, bs, INK, "normal", anchor)
        if code:
            self.text(x + w - pad, y + h - 7, code, 11.5, MUTED, "normal", "end", MONO)
        return h

    def stack(self, x, y, w, items, gap=10, arrows=True) -> Tuple[List[Tuple[float, float]], float]:
        """Lay boxes out vertically. items: (title, body, colors, code) or ("pair", [item, item]).

        Returns ([(top, height), ...], bottom_y)."""
        tops: List[Tuple[float, float]] = []
        cur = y
        for idx, item in enumerate(items):
            if item[0] == "pair":
                a, b = item[1]
                half = (w - 12) / 2
                h = max(self.box(x, cur, half, a[0], a[1], a[2], code=a[3], dry=True),
                        self.box(x + half + 12, cur, half, b[0], b[1], b[2], code=b[3], dry=True))
                self.box(x, cur, half, a[0], a[1], a[2], code=a[3], h=h)
                self.box(x + half + 12, cur, half, b[0], b[1], b[2], code=b[3], h=h)
            else:
                t, b_, c, code = item
                h = self.box(x, cur, w, t, b_, c, code=code)
            if arrows and idx > 0:
                self.path([(x + w / 2, cur - gap), (x + w / 2, cur)])
            tops.append((cur, h))
            cur += h + gap
        return tops, cur - gap

    def panel(self, x, y, w, h, title: str, colors, ts=22, dash: Optional[str] = None, subtitle: str = "") -> None:
        fill, stroke = colors
        self.rect(x, y, w, h, fill, stroke, rx=16, sw=2.5, dash=dash)
        self.text(x + 18, y + ts + 8, title, ts, stroke, "bold")
        if subtitle:
            self.text(x + 18 + text_width(title, ts) * 1.04 + 14, y + ts + 8, subtitle, 14, MUTED)

    def save(self, name: str, png: bool) -> None:
        head = (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">'
            f"<title>{html.escape(self.title)}</title><defs>"
            f'<marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{INK}"/></marker>'
            f'<marker id="arrow-grey" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{C_LEDGER[1]}"/></marker>'
            f'</defs><rect width="{W}" height="{H}" fill="#FFFFFF"/>'
        )
        svg_path = OUT / f"{name}.svg"
        svg_path.write_text(head + "\n".join(self.parts) + "</svg>", encoding="utf-8")
        for wmsg in self.warnings:
            print(f"  warning: {name}: {wmsg}", file=sys.stderr)
        print(f"  wrote {svg_path.relative_to(OUT.parent.parent)}")
        if png:
            tool = shutil.which("rsvg-convert")
            if not tool:
                print("  rsvg-convert not found; PNG skipped (apt install librsvg2-bin)", file=sys.stderr)
                return
            png_path = OUT / f"{name}.png"
            subprocess.run([tool, "-w", str(PNG_WIDTH), str(svg_path), "-o", str(png_path)], check=True)
            print(f"  wrote {png_path.relative_to(OUT.parent.parent)}")


# ──────────────────────────────────────────────────────────── figure 1
def figure_workflow() -> SVG:
    s = SVG("圖 1 系統工作流程架構圖")
    s.text(W / 2, 38, "圖 1　系統工作流程架構圖：AI-SOC（偵測）× AI-Sandbox（處置）× OWP 帳本（問責）", 28, INK, "bold", "middle")
    s.text(W / 2, 64, "對應論文「架構一：dual_model 訓練與推理」與 Table III；方框右下為程式路徑。實線＝資料流／控制流，虛線＝寫入帳本。", 15, MUTED, "normal", "middle")

    PANEL_Y, PANEL_H = 84, 768
    PANEL_BOTTOM = PANEL_Y + PANEL_H
    probe = SVG("probe")  # measurement-only canvas, so panels can be sized before boxes are drawn

    # ═════════ part 1 · AI-SOC
    PLx, PLw = 28, 880
    s.panel(PLx, PANEL_Y, PLw, PANEL_H, "第一部分　AI-SOC：偵測（Detection）", C_SOC, subtitle="線上感測 → 離線訓練域 → 沙箱內 dual_model 推理")

    # online column
    ox, oy, ow = 44, 124, 300
    online_items = [
        ("pyshark 即時抓包", "從網卡或 PCAP 讀封包，彙整成連線紀錄 conn.log；每個 PCAP 的 SHA-256 記入抓包清單", C_ONLINE, "aisoc/capture/"),
        ("Slips IPS 偵測／攔截", "StratosphereLinuxIPS 產生 alerts.json，作為已知分支的標籤來源；可選 nftables 攔截；告警也可直接供應推理", C_ONLINE, "adapters/slips.py"),
    ]
    o_tops, o_bottom = probe.stack(ox + 14, oy + 44, ow - 28, online_items, gap=12, arrows=False)
    oh = o_bottom + 14 - oy
    s.panel(ox, oy, ow, oh, "線上：即時網路", C_ONLINE, 17, dash="6,5", subtitle="＝訓練資料來源")
    s.stack(ox + 14, oy + 44, ow - 28, online_items, gap=12, arrows=False)

    # offline training domain
    tx, ty, tw = 364, 124, 528
    train_items = [
        ("① 簽名資料集副本（dataset_curator 鑰匙）", "整份雜湊 flows_sha256 → 簽名 → 快照；載入時先驗簽再用", C_TRAIN, None),
        ("② 資料校驗與清洗", "時間序切分 train／val／test；測試集永不參與擬合或調門檻", C_TRAIN, None),
        ("pair", [
            ("③a 已知分支 f_k（監督）", "輸出類別＋校準信心 c_k；c_k < τ_k（0.7）⇒ 拒答 rejected，不硬塞舊類別", C_TRAIN, None),
            ("③b 異常分支 f_a（無監督）", "Isolation Forest（或 Autoencoder）只學正常基線；τ_a＝驗證集正常樣本 99.5 分位，依服務群組", C_TRAIN, None),
        ]),
        ("④ 留一家族評估（LOFO）＋ 每日誤報", "整個攻擊家族不參與訓練，量化「沒見過也能抓到」的能力；對抗／穩健性評估", C_TRAIN, None),
        ("⑤ 模型登記＋簽名發布清單（model_release 鑰匙）→ ⑥ 發布閘門", "清單釘住模型 SHA-256；閘門驗哈希、驗簽、人工批准；未批准＝不得進沙箱", C_TRAIN, None),
    ]
    t_tops, t_bottom = probe.stack(tx + 14, ty + 44, tw - 28, train_items, gap=10)
    th = t_bottom + 14 - ty
    s.panel(tx, ty, tw, th, "離線訓練域（與沙箱無直連）", C_TRAIN, 17, dash="6,5", subtitle="aisoc/training/")
    s.stack(tx + 14, ty + 44, tw - 28, train_items, gap=10)

    # online → ① dataset snapshot (both sources merge into one feed)
    jx = (ox + ow + tx) / 2
    snap_cy = t_tops[0][0] + t_tops[0][1] / 2
    for top, hh in o_tops:
        s.path([(ox + ow - 14, top + hh / 2), (jx, top + hh / 2)], arrow=False)
    s.path([(jx, o_tops[0][0] + o_tops[0][1] / 2), (jx, o_tops[-1][0] + o_tops[-1][1] / 2)], arrow=False)
    s.path([(jx, snap_cy), (tx + 14, snap_cy)])
    s.path([(jx, o_tops[0][0] + o_tops[0][1] / 2), (jx, snap_cy)], arrow=False)

    # inference box
    ix, iw = 44, 848
    iy = ty + th + 44
    ih = s.box(ix, iy, iw, "AI-IDPS：dual_model 沙箱內推理（管理域 A，最低權限）",
               "載入前只驗哈希與簽名（release.load_verified_model），不信任檔名與路徑；沙箱內只有唯讀模型、特徵窗口與唯一通道，沒有私鑰、訓練資料、標籤、其他網路\n"
               "已知分支 c_k ＋ 異常分支 s_a → Table III 六條規則（見圖 2）→ 六種案件狀態\n"
               "KNOWN_SUSPICIOUS／SUSPECTED_UNKNOWN／MODEL_CONFLICT ⇒ 派 Agent｜INSUFFICIENT_EVIDENCE／LOW_RISK_OBSERVE 不派｜缺資料或模型失敗 ⇒ UNKNOWN，絕不當成正常",
               C_IDPS, 18, 14.5, code="aisoc/idps/")
    if iy + ih > PANEL_BOTTOM - 10:
        s.warnings.append(f"inference box ends at {iy + ih:.0f} > panel bottom {PANEL_BOTTOM}")
    s.path([(tx + tw / 2, ty + th), (tx + tw / 2, iy)])
    s.label(tx + tw / 2 + 10, ty + th + 26, "模型位元組＋清單（只驗哈希與簽名）", 13, MUTED, "start")
    s.path([(ox + ow / 2, oy + oh), (ox + ow / 2, iy)])
    mid = (oy + oh + iy) / 2
    s.label(ox + ow / 2, mid - 6, "即時流量／Slips 告警", 13, MUTED)
    s.label(ox + ow / 2, mid + 14, "（外部已知分支 decide_external）", 12, MUTED)

    # ═════════ part 2 · AI-Sandbox
    PRx, PRw = 1012, 880
    s.panel(PRx, PANEL_Y, PRw, PANEL_H, "第二部分　AI-Sandbox：處置（Response）", C_SBX, subtitle="Agent 只會「請求」，沙箱外的控制面才能「授權與執行」")

    sx, sw_ = 1028, 396
    cx, cw = 1480, 396
    sub_y = 124
    sandbox_items = [
        ("凍結工作單 WorkOrder ＋ 最小能力授予 CapabilityGrant", "範圍只有 host:<來源主機>／case:<案件>；1 小時、最多 3 次；只有 KNOWN_SUSPICIOUS 才含 block_host，疑似零日／衝突只給可逆動作", C_SANDBOX, "soc.py::_freeze_task"),
        ("Agent（假設可被攻陷）", "只讀工具、無鑰匙、無網卡、無憑證；所有動作都是「請求」不是命令；外部輸入一律視為不可信", C_SANDBOX, "sandbox/agent.py · untrusted.py"),
        ("唯一出口：出口代理 Egress Proxy", "先記帳、後轉發；記不了就丟（fail-closed）；限流、會話控制；每則訊息綁 agent_id 與案件", C_SANDBOX, "sandbox/egress.py"),
        ("逃逸後也拿不到", "私鑰、訓練資料、標籤、其他網路、宿主檔案、寫模型、改配置 ⇒ 偽造不了責任鏈", C_WHITE_AMBER, None),
    ]
    control_items = [
        ("① 政策引擎 → allowed／reserved／denied", "越權、跨租戶、不在工作單或能力授予內 ⇒ denied；低影響可逆 ⇒ allowed；高影響或出站 ⇒ reserved（必須人簽）", C_CTRL, "sandbox/policy.py"),
        ("② 人類審批：簽名，綁定請求摘要", "看到完整 ApprovalView 才簽；簽名綁 request_digest，批了 A 不能拿去執行 B（防橡皮圖章）", C_CTRL, "sandbox/authorization.py"),
        ("③ 簽名服務 → 單次、短時效、綁範圍的授權", "私鑰在沙箱外（部署時放 HSM）；nonce 單次、expires_at 短；綁 action／resource／tenant／destination；絕不盲簽", C_CTRL, "sandbox/authorization.py"),
        ("④ PEP：八項檢查全過才執行 ⇒ 簽名收據", "簽名 → 綁定 → 時效 → 撤銷 → 高影響須帶人批摘要 → 冪等 → 單次 nonce → 受限執行；任一失敗也簽「rejected」收據", C_CTRL, "sandbox/pep.py"),
    ]
    # measure both columns first so the two sub-panels share one height
    _, sb = probe.stack(sx + 14, sub_y + 44, sw_ - 28, sandbox_items)
    _, cb = probe.stack(cx + 14, sub_y + 44, cw - 28, control_items)
    sub_h = max(sb, cb) + 14 - sub_y
    s.panel(sx, sub_y, sw_, sub_h, "沙箱（管理域 A）", C_SANDBOX, 17, dash="6,5", subtitle="最低權限、唯讀、只有 vsock")
    s.panel(cx, sub_y, cw, sub_h, "控制面（沙箱外）", C_CTRL, 17, dash="6,5", subtitle="四道閘門，每一道都上帳")
    s_tops, _ = s.stack(sx + 14, sub_y + 44, sw_ - 28, sandbox_items)
    c_tops, _ = s.stack(cx + 14, sub_y + 44, cw - 28, control_items)

    # hand-off: detection → sandbox
    hand_y = iy + 40
    gap_x = (PLx + PLw + PRx) / 2
    wo_cy = s_tops[0][0] + s_tops[0][1] / 2
    s.path([(ix + iw, hand_y), (gap_x, hand_y), (gap_x, wo_cy), (sx, wo_cy)], sw=2.6)
    s.label(gap_x, (hand_y + wo_cy) / 2 - 6, "需要調查的案件", 14, INK, weight="bold")
    s.label(gap_x, (hand_y + wo_cy) / 2 + 14, "派 Agent 調查", 12, MUTED)

    # egress → policy engine (orthogonal through the channel between the sub-panels)
    chan = (sx + sw_ + cx) / 2
    eg_cy = s_tops[2][0] + s_tops[2][1] / 2
    pol_cy = c_tops[0][0] + c_tops[0][1] / 2
    s.path([(sx + sw_ - 14, eg_cy), (chan, eg_cy), (chan, pol_cy), (cx + 14, pol_cy)])
    s.label(chan, (eg_cy + pol_cy) / 2 - 4, "報告／", 12.5, INK, weight="bold")
    s.label(chan, (eg_cy + pol_cy) / 2 + 14, "動作請求", 12.5, INK, weight="bold")

    # executor + tool-side log
    ey = sub_y + sub_h + 24
    exec_items_l = ("執行器 Executor", "封鎖主機（nftables）／標記／觀察名單；只在 PEP 八項檢查全過後才有副作用；撤銷清單可即時收回授權", C_EXEC, "sandbox/nftables.py")
    exec_items_r = ("工具側日誌 ToolSideLog（第二本帳）", "執行與拒絕都由 executor 鑰匙簽收據；驗證器拿它與帳本對賬，抓出「有做沒記」（bypass）", C_EXEC, "sandbox/pep.py")
    eh = max(s.box(sx, ey, sw_, *exec_items_l[:3], code=exec_items_l[3], dry=True),
             s.box(cx, ey, cw, *exec_items_r[:3], code=exec_items_r[3], dry=True))
    s.box(sx, ey, sw_, *exec_items_l[:3], code=exec_items_l[3], h=eh)
    s.box(cx, ey, cw, *exec_items_r[:3], code=exec_items_r[3], h=eh)
    pep_bottom = c_tops[-1][0] + c_tops[-1][1]
    s.path([(cx + cw / 2, pep_bottom), (cx + cw / 2, ey)])
    s.label(cx + cw / 2 + 50, ey - 9, "收據", 12, MUTED)
    s.path([(cx + 50, pep_bottom), (cx + 50, ey - 11), (sx + sw_ / 2, ey - 11), (sx + sw_ / 2, ey)])
    s.label(sx + sw_ / 2 + 70, ey - 15, "通過 ⇒ 執行", 12, MUTED)

    # scenario strip
    chip_y = ey + eh + 14
    s.rect(sx, chip_y, cw + cx - sx, 50, "#FFFFFF", C_SBX[1])
    s.text((sx + cx + cw) / 2, chip_y + 20, "逃逸攻擊鏈情境 19 條全部擋下（aisoc/scenarios.py；滲透測試報告 docs/PENTEST-REPORT.zh-TW.md）", 14, C_SBX[1], "bold", "middle")
    s.text((sx + cx + cw) / 2, chip_y + 40, "注入攻陷 Agent・跨租戶・重放・過期・撤銷・改參數・竄改／截斷帳本・繞過帳本執行・消融：移除 nonce／人批／外部見證", 12.5, MUTED, "normal", "middle")
    if chip_y + 50 > PANEL_BOTTOM - 8:
        s.warnings.append(f"scenario strip ends at {chip_y + 50:.0f} > panel bottom {PANEL_BOTTOM}")

    # ═════════ OWP ledger bar
    lx, ly, lw, lh = 28, 876, 1864, 180
    s.panel(lx, ly, lw, lh, "OWP 帳本（aisoc/owp/）— 問責（Accountability）：每一步都寫帳本，先記帳、後動作", C_LEDGER, 20)
    s.text(lx + 18, ly + 56, "帳本事件（依發生順序）：detection → work_order → capability_grant → agent_egress → investigation_report → action_request → policy_decision → human_approval → authorization → action_receipt → verification_decision → acceptance_decision", 12.5, MUTED, "normal", "start", MONO)
    cells = [
        ("只存指紋，不存原始流量", "偵測、工作單、授權、人批、收據皆以摘要入帳；原始證據放 WORM／加密庫，監管者不必接觸流量"),
        ("哈希鏈 ＋ Merkle 檢查點 ＋ 外部見證", "每個案件結束簽 Merkle 根；見證者錨定長度與根 ⇒ 事後竄改或截斷都被抓到"),
        ("獨立驗證器離線對賬（owp/verifier.py）", "逐筆驗鏈、驗簽名、對收據、找「未入帳的執行」→ VERIFIED／UNKNOWN／FAILED"),
        ("接受決定 ＋ 任何人可用公鑰驗證", "VERIFIED→ACCEPTED／UNKNOWN→DEFERRED／FAILED→REJECTED；trusted-keys.json 只含公鑰"),
    ]
    cwid = (lw - 36 - 3 * 14) / 4
    cell_h = max(s.box(0, 0, cwid, t, b, ("#FFFFFF", C_LEDGER[1]), 15, 14, dry=True) for t, b in cells)
    for i, (t, b) in enumerate(cells):
        s.box(lx + 18 + i * (cwid + 14), ly + 72, cwid, t, b, ("#FFFFFF", C_LEDGER[1]), 15, 14, h=cell_h)
    for ax, label, anchor in ((ix + 140, "detection／dedup_suppressed", "start"), (sx + 80, "work_order／capability_grant／agent_egress", "start"), (cx + cw - 60, "policy_decision／human_approval／authorization／action_receipt", "end")):
        s.path([(ax, PANEL_BOTTOM), (ax, ly)], stroke=C_LEDGER[1], dashed=True, marker="arrow-grey")
        s.label(ax + (8 if anchor == "start" else -8), PANEL_BOTTOM + 16, label, 11, MUTED, anchor)
    return s


# ──────────────────────────────────────────────────────────── figure 2
def figure_decision_tree() -> SVG:
    s = SVG("圖 2 模型核心決策系統決策樹")
    s.text(W / 2, 36, "圖 2　模型核心決策系統決策樹：dual_model Table III（aisoc/idps/dual_model.py::_combine）", 28, INK, "bold", "middle")
    s.text(W / 2, 62, "符號：c_k＝已知分支校準信心，rejected ⇔ c_k < τ_k（0.7）；s_a＝異常分數，high ⇔ s_a ≥ τ_a（τ_a＝驗證集正常樣本 99.5 分位，依服務群組）；0.9＝高信心正常門檻", 14, MUTED, "normal", "middle")
    s.text(W / 2, 84, "規則由上而下、先符合先成立：先問「已知分支有沒有把握」，再問「異常高不高」，最後才敢說「正常」——先排除危險，才能放行。", 14, MUTED, "normal", "middle")

    def node(cx, cy, w, h, title, sub="", colors=C_DECISION, ts=16, ss=13) -> None:
        fill, stroke = colors
        s.rect(cx - w / 2, cy - h / 2, w, h, fill, stroke, rx=12)
        if sub:
            s.text(cx, cy - 3, title, ts, INK, "bold", "middle")
            s.text(cx, cy + 16, sub, ss, MUTED, "normal", "middle", MONO)
        else:
            s.text(cx, cy + ts / 3, title, ts, INK, "bold", "middle")

    y_in, y_d0, y_br, y_d1, y_d2, y_d3, y_d4 = 124, 196, 290, 384, 470, 556, 642
    leaf_y, leaf_h = 704, 318
    leaf_w, gap = 296, 16
    xs = [30 + leaf_w / 2 + i * (leaf_w + gap) for i in range(6)]
    X_KS, X_MC, X_SU, X_IE, X_LR, X_UN = xs
    X_MID = W / 2

    node(X_MID, y_in, 420, 44, "一筆流量／事件 FlowRecord（或 Slips 告警）", colors=C_INPUT)
    s.path([(X_MID, y_in + 22), (X_MID, y_d0 - 30)])
    node(X_MID, y_d0, 440, 60, "資料齊全 ∧ 模型可用？", "has_required_fields() 且兩分支無例外")

    node(X_MID - 212, y_br, 400, 64, "已知分支 f_k：label、c_k、rejected", "KnownModel.predict → c_k < τ_k(0.7) ⇒ rejected", C_BRANCH, 15, 12)
    node(X_MID + 212, y_br, 400, 64, "異常分支 f_a：s_a、τ_a、high", "NormalityModel.score ≥ threshold_for(service_group)", C_BRANCH, 15, 12)
    s.path([(X_MID, y_d0 + 30), (X_MID, y_br - 46), (X_MID - 212, y_br - 46), (X_MID - 212, y_br - 32)])
    s.path([(X_MID, y_br - 46), (X_MID + 212, y_br - 46), (X_MID + 212, y_br - 32)])
    s.label(X_MID + 30, y_d0 + 46, "是", 14, INK, "start", weight="bold")
    s.path([(X_MID - 212, y_br + 32), (X_MID - 212, y_br + 46), (X_MID, y_br + 46), (X_MID, y_d1 - 30)])
    s.path([(X_MID + 212, y_br + 32), (X_MID + 212, y_br + 46), (X_MID, y_br + 46)], arrow=False)

    # D0 否 → UNKNOWN
    s.path([(X_MID + 220, y_d0), (X_UN, y_d0), (X_UN, leaf_y)])
    s.label(X_MID + 240, y_d0 - 8, "否（欄位缺漏／模型例外／外部偵測器無結論）", 14, INK, "start", weight="bold")

    node(X_MID, y_d1, 440, 60, "已知分支有信心指認攻擊類別？", "label ≠ benign ∧ ¬rejected")
    s.path([(X_MID - 220, y_d1), (X_KS, y_d1), (X_KS, leaf_y)])
    s.label(X_MID - 240, y_d1 - 8, "是 ⇒ 規則①", 14, STATUS_COLORS["KNOWN_SUSPICIOUS"], "end", weight="bold")
    s.path([(X_MID, y_d1 + 30), (X_MID, y_d2 - 30)])
    s.label(X_MID + 14, y_d1 + 52, "否（benign 或 拒答）", 14, INK, "start", weight="bold")

    node(X_MID, y_d2, 320, 60, "異常高？", "high ⇔ s_a ≥ τ_a")
    X_D3, X_D5 = X_MID - 310, X_MID + 310
    s.path([(X_MID, y_d2 + 30), (X_MID, y_d2 + 44), (X_D3, y_d2 + 44), (X_D3, y_d3 - 30)])
    s.path([(X_MID, y_d2 + 44), (X_D5, y_d2 + 44), (X_D5, y_d3 - 30)])
    s.label(X_D3 + 14, y_d3 - 38, "是（很怪）", 14, INK, "start", weight="bold")
    s.label(X_D5 + 14, y_d3 - 38, "否（不怪）", 14, INK, "start", weight="bold")

    node(X_D3, y_d3, 300, 60, "已知分支拒答？", "rejected（c_k < τ_k）")
    node(X_D5, y_d3, 300, 60, "已知分支拒答？", "rejected（c_k < τ_k）")
    # D3: 是 → SUSPECTED_UNKNOWN (rule 2) ; 否 → D4
    s.path([(X_D3, y_d3 + 30), (X_D3, y_d3 + 44), (X_SU, y_d3 + 44), (X_SU, leaf_y)])
    s.label(X_SU + 12, y_d3 + 76, "是 ⇒ 規則②（沒見過、又很怪）", 13, STATUS_COLORS["SUSPECTED_UNKNOWN"], "start", weight="bold")
    s.path([(X_D3, y_d3 + 44), (X_MC, y_d3 + 44), (X_MC, y_d4 - 30)])
    s.label(X_MC - 14, y_d4 - 38, "否（benign）", 13, INK, "end", weight="bold")
    node(X_MC, y_d4, 300, 60, "有信心的正常？", "c_k ≥ high_confidence_normal(0.9)")
    s.path([(X_MC, y_d4 + 30), (X_MC, leaf_y)])
    s.label(X_MC - 14, y_d4 + 52, "是 ⇒ 規則③", 13, STATUS_COLORS["MODEL_CONFLICT"], "end", weight="bold")
    s.path([(X_MC + 150, y_d4), (X_SU - 40, y_d4), (X_SU - 40, leaf_y)])
    s.label(X_MC + 160, y_d4 - 8, "否（弱正常）⇒ 規則④", 13, STATUS_COLORS["SUSPECTED_UNKNOWN"], "start", weight="bold")
    # D5: 是 → INSUFFICIENT_EVIDENCE ; 否 → LOW_RISK_OBSERVE
    s.path([(X_D5, y_d3 + 30), (X_D5, y_d3 + 44), (X_IE, y_d3 + 44), (X_IE, leaf_y)])
    s.path([(X_D5, y_d3 + 44), (X_LR, y_d3 + 44), (X_LR, leaf_y)])
    s.label(X_IE + 14, y_d3 + 90, "是 ⇒ 規則⑤", 13, STATUS_COLORS["INSUFFICIENT_EVIDENCE"], "start", weight="bold")
    s.label(X_LR + 14, y_d3 + 90, "否（正常）⇒ 規則⑥", 13, STATUS_COLORS["LOW_RISK_OBSERVE"], "start", weight="bold")

    leaves = [
        (X_KS, "KNOWN_SUSPICIOUS", "① 已知可疑",
         ["條件　已知分支有信心指認攻擊家族（如暴力破解、埠掃描）",
          "人審　不必先人審，先派人調查",
          "Agent　✓ 派沙箱 Agent 調查",
          "封鎖　可申請 block_host，但屬高影響 ⇒ reserved，仍要人簽名才執行",
          "其他　tag／watchlist（可逆）"]),
        (X_MC, "MODEL_CONFLICT", "③ 模型衝突",
         ["條件　已知分支很有信心說正常（c_k ≥ 0.9），異常分支卻說很怪——兩個模型打架",
          "人審　✓ 必須；不能直接放行，也不能硬判是攻擊，禁止自動關案",
          "Agent　✓ 派 Agent 調查",
          "封鎖　✗ 不給；只給可逆動作 tag／watchlist"]),
        (X_SU, "SUSPECTED_UNKNOWN", "②④ 疑似未知（疑似零日）",
         ["條件　② 拒答 ∧ 異常高：沒見過、又很怪；④ 弱正常（c_k < 0.9）∧ 異常高：比照零日",
          "人審　✓ 必須",
          "Agent　✓ 派 Agent 調查",
          "封鎖　✗ 不給；只給可逆動作 tag／watchlist",
          "說明　只說「疑似」：偵測的是行為異常，不是證明零日"]),
        (X_IE, "INSUFFICIENT_EVIDENCE", "⑤ 證據不足",
         ["條件　拒答 ∧ 異常低：不認識、但也不怪",
          "人審　抽樣複核（不強制每筆人審）",
          "Agent　✗ 不派",
          "動作　無；優先補資料、補特徵，而不是猜"]),
        (X_LR, "LOW_RISK_OBSERVE", "⑥ 低風險觀察",
         ["條件　已知分支說正常 ∧ 異常低 ∧ 資料齊全",
          "人審　✗",
          "Agent　✗ 不派",
          "動作　只做漂移監控，不開案",
          "規模　絕大多數流量：示範報告 600 筆中 541 筆"]),
        (X_UN, "UNKNOWN", "資料缺失／模型失敗",
         ["條件　欄位缺漏、模型拋例外，或外部偵測器（Slips）沒給結論且無異常訊號",
          "人審　✓ 必須",
          "Agent　✗ 不派",
          "原則　缺資料不能當成正常；系統壞掉要讓人知道，不是靜默放行"]),
    ]
    bs, lh = 14, 20
    for cx, status, zh, body in leaves:
        col = STATUS_COLORS[status]
        x0, y0 = cx - leaf_w / 2, leaf_y
        s.rect(x0, y0, leaf_w, leaf_h, "#FFFFFF", col, rx=12, sw=2.5)
        s.add(f'<path d="M{x0 + 12},{y0} h{leaf_w - 24} a12,12 0 0 1 12,12 v44 h-{leaf_w} v-44 a12,12 0 0 1 12,-12 z" fill="{col}"/>')
        s.text(cx, y0 + 24, status, 16 if len(status) < 20 else 14, "#FFFFFF", "bold", "middle", MONO)
        s.text(cx, y0 + 46, zh, 15, "#FFFFFF", "bold", "middle")
        yy = y0 + 82
        for line in body:
            key, _, rest = line.partition("　")
            wrapped = wrap(rest, leaf_w - 24 - 54, bs)
            s.text(x0 + 12, yy, key, bs, col, "bold")
            for i, wl in enumerate(wrapped):
                s.text(x0 + 66, yy + i * lh, wl, bs, INK)
            yy += max(1, len(wrapped)) * lh + 7
        if yy - 7 + 4 > y0 + leaf_h:
            s.warnings.append(f"leaf {status} overflow {yy - (y0 + leaf_h):.0f}px")

    s.text(30, 1046, "外部已知分支（Slips 供應，decide_external）：若沒有任何異常訊號，只有「有信心指認攻擊」才成立規則①（並記下「異常分支不可用」）；拒答或說正常 ⇒ 一律 UNKNOWN，絕不是 LOW_RISK_OBSERVE。", 12.5, MUTED)
    s.text(30, 1066, "兩個旗標 requires_human_review／requires_agent_investigation 與分數 c_k、s_a、τ_a 全部分開寫入帳本（detection 事件），事後可複核「為什麼是這個狀態」；封鎖與否由圖 1 的控制面決定，偵測端只給建議。", 12.5, MUTED)
    return s


def main(argv: Sequence[str]) -> int:
    png = "--no-png" not in argv
    OUT.mkdir(parents=True, exist_ok=True)
    print("rendering figures …")
    figure_workflow().save("architecture-1-workflow", png)
    figure_decision_tree().save("decision-tree", png)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
