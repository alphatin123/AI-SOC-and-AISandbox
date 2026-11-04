"""Dataset snapshot ("dataset 副本"): captured connections + Slips verdicts, signed and write-once.

Inputs
    conn.log   Zeek-shaped rows (from Slips' Zeek *or* ``aisoc capture``)
    alerts.json  Slips IDMEFv2 evidence/incidents for the same traffic
Output
    flows.jsonl        one FlowRecord per (originator, responder, time window)
    manifest.json      signed by the ``dataset_curator`` role; pins flows_sha256, sources, labelling rule
    curator-keys.json  public key export so the training domain can verify the signature

Labels come from Slips only.  "benign" therefore means *not flagged by Slips*,
not *verified clean*; the manifest says so in plain words.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ..adapters.slips import SlipsEvidence, SlipsIncident, SlipsParseResult, ZeekConnIndex, _service_group, read_alerts_json
from ..canonical import sha256_hex
from ..crypto import Clock, Ed25519Signer, TrustedKeys, parse_iso
from ..idps import BENIGN, FEATURE_SCHEMA_VERSION, FlowRecord
from ..owp.objects import Signed, schema

DATASET_MANIFEST_SCHEMA = schema("dataset-manifest")
DATASET_CURATOR_ROLE = "dataset_curator"
LABEL_RULE_VERSION = "slips-label-rule-1"
UNLABELED_ANOMALY = "unlabeled_anomaly"

GROUND_TRUTH_NOTE = (
    "Labels are derived from Slips evidence only. 'benign' means Slips raised no evidence for that host/window, "
    "not that the traffic was verified clean. 'unlabeled_anomaly' rows were flagged by Slips' learned/anomaly "
    "detectors without a named attack class and must not be used as a class or as baseline."
)


class DatasetSnapshotError(Exception):
    pass


@dataclass
class LabelStats:
    label_sources: Dict[str, int] = field(default_factory=dict)
    by_label: Dict[str, int] = field(default_factory=dict)
    by_family: Dict[str, int] = field(default_factory=dict)
    by_service_group: Dict[str, int] = field(default_factory=dict)
    conflicts: int = 0
    evidence_matched: int = 0
    evidence_unmatched: int = 0
    windows_with_missing_measurements: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DatasetSnapshot:
    flows: List[FlowRecord]
    manifest: Signed
    curator_keys: Dict[str, Dict[str, str]]
    trust_source: str = "in-memory"

    @property
    def flows_sha256(self) -> str:
        return str(self.manifest.payload["flows_sha256"])

    @property
    def dataset_id(self) -> str:
        return str(self.manifest.payload["dataset_id"])


def _ts(value: Any) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _iso_ts(value: str) -> Optional[float]:
    try:
        return parse_iso(value).timestamp()
    except (TypeError, ValueError):
        return None


def _window_iso(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


# ── 【老師註解】build_flow_records ────────────────────────────────
# 做什麼：conn.log 的每一列 → 依「(發起者, 回應者, 時間窗 window_s)」分組 → 每組用 ZeekConnIndex.aggregate 算成一筆 FlowRecord →
#         再用 Slips 的證據替它貼標籤。
# 為什麼：這是「數據採集與標註」那一格。Slips 是 IPS（偵測＋攔截），它的判斷成為訓練標籤；pyshark／Zeek 的 conn.log 提供量化特徵。
#         兩者是同一段流量的兩個視角，靠 uid 與 (主機, 時間) 對上。
# 怎麼看（標籤規則 slips-label-rule-1，優先序由強到弱）：
#   1) slips_uid       ：這組的任一 uid 出現在某條「有家族」的證據裡 → 該家族
#   2) slips_host_time ：來源 IP（與目的 IP，若證據有寫）相符，且時間差 ≤ label_window_s → 該家族
#   3) slips_anomaly_only：只對到 Slips 的異常型證據（ANOMALOUS_FLOW 之類，沒有家族名） → "unlabeled_anomaly"（隔離，不當類別也不當基線）
#   4) slips_silence   ：Slips 什麼都沒說 → "benign"（＝「沒被標記」，不是「驗證乾淨」）
#   同一組若對到多個不同家族 → 取「信心×威脅等級」最高者，並把 conflicts +1 寫進統計。
#   量化欄位缺值（aggregate 回 None）照實保留 None；清洗階段會把它們剔除並計數，不在這裡補 0。
# 拿掉會怎樣：沒有這一步，抓到的流量只是幾十萬行 JSON；dual_model 的已知分支沒有類別可學，異常分支沒有基線可學。
# 對應：準則 #11、#12、#13；測試 tests/test_training_domain.py::test_labels_follow_slips_rule_priority
def build_flow_records(
    index: ZeekConnIndex,
    evidence: Sequence[SlipsEvidence],
    incidents: Sequence[SlipsIncident],
    *,
    tenant: str,
    window_s: int = 60,
    label_window_s: int = 300,
) -> Tuple[List[FlowRecord], LabelStats]:
    if window_s <= 0 or label_window_s < 0:
        raise ValueError("window_s must be positive and label_window_s non-negative")
    stats = LabelStats()
    # 步驟 1：分組 (orig_h, resp_h, bucket)
    groups: Dict[Tuple[str, str, int], List[Dict[str, Any]]] = {}
    for row in index.rows.values():
        ts = _ts(row.get("ts"))
        orig_h, resp_h = row.get("id.orig_h"), row.get("id.resp_h")
        if ts is None or not orig_h or not resp_h:
            continue
        groups.setdefault((str(orig_h), str(resp_h), int(ts // window_s)), []).append(row)

    # 步驟 2：證據索引（uid → 證據；(來源, 目的) → 證據列表）
    by_uid: Dict[str, List[SlipsEvidence]] = {}
    by_host: Dict[str, List[Tuple[Optional[float], SlipsEvidence]]] = {}
    for ev in evidence:
        if ev.family is None and not ev.is_anomaly_signal:
            continue  # 弱指標不貼標籤
        for uid in ev.uids:
            by_uid.setdefault(str(uid), []).append(ev)
        by_host.setdefault(ev.source_ip, []).append((_iso_ts(ev.start_time), ev))
    matched_ids: set = set()

    def weight(ev: SlipsEvidence) -> float:
        return float(ev.confidence or 0.0) * float(ev.threat_level or 0.0)

    records: List[FlowRecord] = []
    for (orig_h, resp_h, bucket), rows in sorted(groups.items(), key=lambda kv: (kv[0][2], kv[0][0], kv[0][1])):
        uids = [str(r["uid"]) for r in rows]
        agg = index.aggregate(uids, host=orig_h) or {}
        if any(agg.get(k) is None for k in ("bytes_in", "bytes_out", "pkts_in", "pkts_out", "duration_s", "mean_iat_ms")):
            stats.windows_with_missing_measurements += 1
        ports = Counter(int(p) for p in (r.get("id.resp_p") for r in rows) if str(p).lstrip("-").isdigit())
        dst_port = ports.most_common(1)[0][0] if ports else 0
        window_start = bucket * window_s

        # 步驟 3：貼標籤
        family_hits: List[Tuple[str, SlipsEvidence]] = []
        anomaly_hit = False
        for uid in uids:
            for ev in by_uid.get(uid, ()):
                matched_ids.add(ev.id)
                if ev.family:
                    family_hits.append(("slips_uid", ev))
                else:
                    anomaly_hit = True
        if not family_hits:
            for ev_ts, ev in by_host.get(orig_h, ()):
                if ev.target_ip and ev.target_ip != resp_h:
                    continue
                if ev_ts is None:
                    continue
                # distance from the evidence time to the window [start, start + window_s]
                gap = max(window_start - ev_ts, ev_ts - (window_start + window_s), 0.0)
                if gap > label_window_s:
                    continue
                matched_ids.add(ev.id)
                if ev.family:
                    family_hits.append(("slips_host_time", ev))
                else:
                    anomaly_hit = True
        if family_hits:
            families = {ev.family for _, ev in family_hits}
            if len(families) > 1:
                stats.conflicts += 1
            source, best = max(family_hits, key=lambda h: (weight(h[1]), h[0] == "slips_uid"))
            label, family = str(best.family), str(best.family)
        elif anomaly_hit:
            source, label, family = "slips_anomaly_only", UNLABELED_ANOMALY, None
        else:
            source, label, family = "slips_silence", BENIGN, None

        rec = FlowRecord(
            flow_id="cap-" + hashlib.sha256(f"{tenant}|{orig_h}|{resp_h}|{bucket}|{window_s}".encode()).hexdigest()[:12],
            tenant=tenant, src_host=orig_h, dst_ip=resp_h, dst_port=dst_port,
            bytes_in=agg.get("bytes_in"), bytes_out=agg.get("bytes_out"),  # type: ignore[arg-type]
            pkts_in=agg.get("pkts_in"), pkts_out=agg.get("pkts_out"),  # type: ignore[arg-type]
            duration_s=agg.get("duration_s"), mean_iat_ms=agg.get("mean_iat_ms"),  # type: ignore[arg-type]
            conn_failures=float(agg.get("conn_failures") or 0.0),
            short_window_conns=float(agg.get("short_window_conns") or len(rows)),
            distinct_dst_ports=float(agg.get("distinct_dst_ports") or 0.0),
            login_failures=0.0,  # not derivable from conn.log; documented in the manifest
            service_group=_service_group(dst_port), observed_at=_window_iso(window_start),
            label=label, family=family, log_excerpt="",
        )
        records.append(rec)
        stats.label_sources[source] = stats.label_sources.get(source, 0) + 1
        stats.by_label[label] = stats.by_label.get(label, 0) + 1
        if family:
            stats.by_family[family] = stats.by_family.get(family, 0) + 1
        stats.by_service_group[rec.service_group] = stats.by_service_group.get(rec.service_group, 0) + 1

    labelled = [ev for ev in evidence if ev.family is not None or ev.is_anomaly_signal]
    stats.evidence_matched = sum(1 for ev in labelled if ev.id in matched_ids)
    stats.evidence_unmatched = len(labelled) - stats.evidence_matched
    return records, stats


def flows_to_bytes(flows: Sequence[FlowRecord]) -> bytes:
    """Canonical JSONL (sorted keys, no spaces, one record per line) -> what flows_sha256 is computed over."""
    return ("".join(json.dumps(asdict(f), sort_keys=True, separators=(",", ":")) + "\n" for f in flows)).encode("utf-8")


def flows_from_bytes(data: bytes) -> List[FlowRecord]:
    out: List[FlowRecord] = []
    for n, line in enumerate(data.decode("utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
            out.append(FlowRecord(**obj))
        except (ValueError, TypeError) as exc:
            raise DatasetSnapshotError(f"flows.jsonl line {n}: malformed FlowRecord ({type(exc).__name__})") from exc
    return out


# ── 【老師註解】build_snapshot ────────────────────────────────────
# 做什麼：讀 conn.log + alerts.json（+ 可選的 capture-manifest.json），產生 FlowRecord 清單與一張「資料集 manifest」，
#         由 dataset_curator 角色的鑰匙簽名。這就是交給離線訓練域的「dataset 副本」。
# 為什麼：訓練域與感測器之間是跨域交接（準則 #7、#9）。跨域的東西必須「內容雜湊 + 角色簽名」：
#         - flows_sha256 釘住 flows.jsonl 的每一個位元組；之後 release manifest 的 dataset_sha256 就引用它 → 模型 ↔ 資料集可以互相追溯。
#         - conn_log_sha256 / alerts_sha256 / capture_manifest 釘住上游來源 → 可以回頭核對「這份資料集真的來自那次抓包與那份 Slips 輸出」。
#         - labeling 區塊寫明規則版本與各標籤來源的數量 → 評估數字時知道「ground truth 有多可靠」。
#         - slips.blocking_claimed 只是「部署者宣稱 Slips 有開 -p 攔截」，這裡無法驗證，所以欄位名就叫 claimed（準則 #13）。
# 怎麼看：簽名者角色不對直接拒簽（一角色一鑰匙）；tenant 由部署者指定（Slips 沒有租戶概念）。
# 拿掉會怎樣：任何人改一行 flows.jsonl（例如把攻擊改標成 benign＝基線投毒）都不會被發現，訓練出的模型照樣被簽發。
# 對應：準則 #7、#9、#13；測試 tests/test_training_domain.py::test_snapshot_round_trip_and_tamper_detection
def build_snapshot(
    *,
    conn_log: str | Path,
    alerts: str | Path,
    tenant: str,
    signer: Ed25519Signer,
    clock: Optional[Clock] = None,
    capture_manifest: Optional[str | Path] = None,
    window_s: int = 60,
    label_window_s: int = 300,
    slips_blocking_claimed: bool = False,
    dataset_id: Optional[str] = None,
) -> DatasetSnapshot:
    if signer.role != DATASET_CURATOR_ROLE:
        raise DatasetSnapshotError(f"dataset manifests must be signed by the {DATASET_CURATOR_ROLE!r} role, not {signer.role!r}")
    clock = clock or Clock()
    conn_path, alerts_path = Path(conn_log), Path(alerts)
    conn_bytes, alerts_bytes = conn_path.read_bytes(), alerts_path.read_bytes()
    index = ZeekConnIndex.from_lines(conn_bytes.decode("utf-8", errors="replace").splitlines())
    parsed: SlipsParseResult = read_alerts_json(alerts_path)
    cap_manifest: Optional[Dict[str, Any]] = None
    if capture_manifest is not None:
        cap_manifest = json.loads(Path(capture_manifest).read_text(encoding="utf-8"))
        if not isinstance(cap_manifest, dict):
            raise DatasetSnapshotError("capture manifest must be a JSON object")
        if cap_manifest.get("out_sha256") and cap_manifest["out_sha256"] != sha256_hex(conn_bytes):
            raise DatasetSnapshotError("capture manifest out_sha256 does not match the conn.log being snapshotted")

    flows, stats = build_flow_records(index, parsed.evidence, parsed.incidents, tenant=tenant,
                                      window_s=window_s, label_window_s=label_window_s)
    flows_sha = sha256_hex(flows_to_bytes(flows))
    did = dataset_id or ("ds-" + flows_sha[:12])
    payload: Dict[str, Any] = {
        "schema": DATASET_MANIFEST_SCHEMA,
        "dataset_id": did,
        "created_at": clock.iso(),
        "tenant": tenant,
        "feature_schema": FEATURE_SCHEMA_VERSION,
        "source": {
            "kind": "pyshark-capture" if cap_manifest else "zeek-conn-log",
            "conn_log": conn_path.name,
            "conn_log_sha256": sha256_hex(conn_bytes),
            "conn_rows": len(index.rows),
            "alerts": alerts_path.name,
            "alerts_sha256": sha256_hex(alerts_bytes),
            "capture_manifest": cap_manifest,
        },
        "slips": {
            "versions": sorted(parsed.slips_versions),
            "evidence": len(parsed.evidence),
            "incidents": len(parsed.incidents),
            "malformed": parsed.malformed,
            "blocking_claimed": bool(slips_blocking_claimed),
            "alerted_hosts": sorted({inc.source_ip for inc in parsed.incidents}),
        },
        "labeling": {
            "rule_version": LABEL_RULE_VERSION,
            "window_s": window_s,
            "label_window_s": label_window_s,
            **stats.to_dict(),
            "login_failures": "always 0: not derivable from conn.log",
        },
        "counts": {"flows": len(flows), "by_label": stats.by_label, "by_family": stats.by_family,
                   "by_service_group": stats.by_service_group},
        "flows_sha256": flows_sha,
        "ground_truth": GROUND_TRUTH_NOTE,
        "curator": {"role": signer.role, "key_id": signer.key_id},
    }
    manifest = Signed(payload=payload, signatures=[signer.sign_payload(payload)])
    trust = TrustedKeys()
    trust.trust(signer)
    return DatasetSnapshot(flows=flows, manifest=manifest, curator_keys=trust.export())


# ── 【老師註解】write_snapshot ────────────────────────────────────
# 做什麼：把 snapshot 寫成三個檔：flows.jsonl、manifest.json、curator-keys.json。目錄若已存在且非空 → 拒絕（WORM：只寫一次）。
# 為什麼：資料集副本一旦簽了名就不該再被「原地覆寫」；要改就產生新的一份（新的 dataset_id）。這是論文「證據只增不改」在資料集上的版本。
# 拿掉會怎樣：同一個目錄被重複覆寫後，manifest 與 flows 可能來自不同次執行，雜湊對不上卻沒人知道哪一份才是真的。
# 對應：準則 #7；測試 tests/test_training_domain.py::test_write_snapshot_is_write_once
def write_snapshot(snapshot: DatasetSnapshot, out_dir: str | Path) -> Path:
    out = Path(out_dir)
    if out.exists() and any(out.iterdir()):
        raise DatasetSnapshotError(f"refusing to overwrite existing dataset snapshot directory {out} (write-once)")
    out.mkdir(parents=True, exist_ok=True)
    (out / "flows.jsonl").write_bytes(flows_to_bytes(snapshot.flows))
    (out / "manifest.json").write_text(json.dumps(snapshot.manifest.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "curator-keys.json").write_text(json.dumps(snapshot.curator_keys, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out


def trusted_keys_from_export(exported: Dict[str, Dict[str, str]]) -> TrustedKeys:
    trust = TrustedKeys()
    for kid, entry in exported.items():
        trust.trust_raw(kid, str(entry["role"]), bytes.fromhex(str(entry["public_raw_hex"])))
    return trust


# ── 【老師註解】load_snapshot ─────────────────────────────────────
# 做什麼：訓練域「收件」時的四道檢查：manifest schema → 簽名有效且簽名者被信任為 dataset_curator → flows.jsonl 的 SHA-256 等於 manifest 釘住的值
#         → 筆數與 manifest 一致。任何一道不過就丟 DatasetSnapshotError，不會「勉強訓練」。
# 為什麼：訓練域不信任檔案路徑，只信任「簽名 + 雜湊」。這是基線投毒的第一道防線——改了資料就對不上雜湊，換了 manifest 就對不上簽名。
# 怎麼看：trust=None 時會用「同目錄的 curator-keys.json」——這在示範時方便，但等於「信任和資料一起送來的鑰匙」，
#         所以 trust_source 會標成 "co-located"，CLI 會印出警告；正式部署應把 curator 公鑰透過另一條路徑（out-of-band）交給訓練域。
# 拿掉會怎樣：載入端只看檔名，攻擊者把投毒後的 flows.jsonl 放到對的路徑就能左右模型學到的「正常」。
# 對應：準則 #9、#10；測試 tests/test_training_domain.py::test_snapshot_round_trip_and_tamper_detection
def load_snapshot(directory: str | Path, trust: Optional[TrustedKeys] = None) -> DatasetSnapshot:
    d = Path(directory)
    try:
        manifest_obj = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
        flows_bytes = (d / "flows.jsonl").read_bytes()
    except (OSError, ValueError) as exc:
        raise DatasetSnapshotError(f"cannot read dataset snapshot in {d}: {type(exc).__name__}: {exc}") from exc
    if not isinstance(manifest_obj, dict) or not isinstance(manifest_obj.get("payload"), dict):
        raise DatasetSnapshotError("manifest.json is not a signed object")
    manifest = Signed(payload=manifest_obj["payload"], signatures=list(manifest_obj.get("signatures") or []))
    p = manifest.payload
    # 檢查 1：schema
    if p.get("schema") != DATASET_MANIFEST_SCHEMA:
        raise DatasetSnapshotError(f"unexpected dataset manifest schema {p.get('schema')!r}")
    trust_source = "explicit"
    if trust is None:
        try:
            exported = json.loads((d / "curator-keys.json").read_text(encoding="utf-8"))
            trust = trusted_keys_from_export(exported)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise DatasetSnapshotError("no trusted curator keys given and curator-keys.json is missing or malformed") from exc
        trust_source = "co-located"
    # 檢查 2：簽名 + 角色
    if not any(trust.verify(p, s, expected_role=DATASET_CURATOR_ROLE) for s in manifest.signatures):
        raise DatasetSnapshotError("dataset manifest signature invalid or signer not trusted as dataset_curator")
    # 檢查 3：flows 雜湊
    if sha256_hex(flows_bytes) != p.get("flows_sha256"):
        raise DatasetSnapshotError("flows.jsonl does not match the flows_sha256 pinned by the signed manifest")
    flows = flows_from_bytes(flows_bytes)
    # 檢查 4：筆數
    if int((p.get("counts") or {}).get("flows", -1)) != len(flows):
        raise DatasetSnapshotError("flow count differs from the signed manifest")
    if p.get("feature_schema") != FEATURE_SCHEMA_VERSION:
        raise DatasetSnapshotError("dataset was built for a different feature schema")
    return DatasetSnapshot(flows=flows, manifest=manifest, curator_keys=trust.export(), trust_source=trust_source)
