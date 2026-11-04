"""Offline training on a verified dataset snapshot -> signed model release.

Stages (Architecture 1):
    1 數據採集與標註   (done upstream: the signed snapshot)
    2 數據校驗與清洗   validate_and_clean + time_split
    3 已知攻擊模型 | 異常檢測模型   DualModel.train (or the explicit synthetic-known fallback)
    4 對抗與穩健性評估  held-out metrics, leave-one-family-out, false positives / day, perturbation flips
    5 模型登記 + 簽名   release_model (model_release role)
    6 模型發布閘門     verify_release self-check; human approval recorded as a claim only
"""

from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..canonical import sha256_hex
from ..crypto import Clock, Ed25519Signer, TrustedKeys, parse_iso
from ..idps import BENIGN, MODEL_RELEASE_ROLE, DualModel, FlowRecord, KnownModel, NormalityModel, featurize, release_model, verify_release
from ..idps.features import StandardScaler
from ..owp.objects import Signed
from ..simulate import ESCALATED, detection_metrics, generate
from .dataset import UNLABELED_ANOMALY, DatasetSnapshot

TRAINING_REPORT_SCHEMA = "owp-soc/training-report/0.1"
STAGE_NAMES = [
    "data_collection_and_labeling",
    "data_validation_and_cleaning",
    "known_attack_and_anomaly_models",
    "adversarial_and_robustness_evaluation",
    "model_registration_and_signing",
    "model_release_gate",
]


class TrainingDomainError(Exception):
    pass


@dataclass
class CleaningReport:
    input_flows: int = 0
    kept: int = 0
    dropped_missing_measurements: int = 0
    dropped_duplicates: int = 0
    quarantined_anomaly_only: int = 0
    dropped_rare_families: Dict[str, int] = field(default_factory=dict)
    benign_kept: int = 0
    families_kept: Dict[str, int] = field(default_factory=dict)
    min_per_class: int = 5
    min_benign: int = 30
    benign_baseline_sufficient: bool = False
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ── 【老師註解】validate_and_clean ────────────────────────────────
# 做什麼：「數據校驗與清洗」那一格。四條規則，每一條都「數出來」寫進 CleaningReport：
#   1) 六個量化欄位缺任一個（None/NaN/負數）→ 丟掉（dropped_missing_measurements）——缺值不能補 0 再拿去學「正常」。
#   2) flow_id 重複 → 只留第一筆（dropped_duplicates）。
#   3) 標籤是 unlabeled_anomaly（Slips 說怪但說不出是什麼）→ 隔離（quarantined_anomaly_only）：不能當基線（會把異常學成正常），
#      也不能當類別（沒有名字）。它們留在報告裡等人看。
#   4) 某個攻擊家族樣本數 < min_per_class → 丟掉並記名（dropped_rare_families）：幾筆樣本學不出一個類別，只會讓校準失真。
#   最後檢查 benign 是否 ≥ min_benign，否則 benign_baseline_sufficient=False，訓練會拒絕繼續。
# 為什麼：論文要求「資料校驗與清洗」是獨立一格，而且它的輸出要能被稽核——所以這裡回的是報告，不是 print。
# 拿掉會怎樣：壞感測器的缺值變成 0、Slips 的異常旗標混進基線、三筆樣本的「家族」硬學出一個類別——模型看起來有在動，其實學的是雜訊。
# 對應：準則 #11、#13；測試 tests/test_training_domain.py::test_validate_and_clean_counts_every_drop
def validate_and_clean(flows: Sequence[FlowRecord], *, min_per_class: int = 5, min_benign: int = 30) -> Tuple[List[FlowRecord], CleaningReport]:
    rep = CleaningReport(input_flows=len(flows), min_per_class=min_per_class, min_benign=min_benign)
    seen: set = set()
    stage: List[FlowRecord] = []
    for f in flows:
        if not f.has_required_fields():
            rep.dropped_missing_measurements += 1
            continue
        if f.flow_id in seen:
            rep.dropped_duplicates += 1
            continue
        seen.add(f.flow_id)
        if f.label == UNLABELED_ANOMALY:
            rep.quarantined_anomaly_only += 1
            continue
        stage.append(f)
    counts: Dict[str, int] = {}
    for f in stage:
        if f.label and f.label != BENIGN:
            counts[f.label] = counts.get(f.label, 0) + 1
    rare = {fam: n for fam, n in counts.items() if n < min_per_class}
    kept = [f for f in stage if not (f.label in rare)]
    rep.dropped_rare_families = rare
    rep.kept = len(kept)
    rep.benign_kept = sum(1 for f in kept if f.label == BENIGN)
    rep.families_kept = {fam: n for fam, n in counts.items() if fam not in rare}
    rep.benign_baseline_sufficient = rep.benign_kept >= min_benign
    if rep.quarantined_anomaly_only:
        rep.notes.append("unlabeled_anomaly rows are kept out of both branches; review them manually")
    if not rep.benign_baseline_sufficient:
        rep.notes.append(f"benign baseline too small ({rep.benign_kept} < {min_benign}); capture longer before training")
    if not rep.families_kept:
        rep.notes.append("no attack family with enough Slips-labelled samples; the known branch cannot be trained on this capture")
    return kept, rep


# ── 【老師註解】time_split ────────────────────────────────────────
# 做什麼：按 observed_at 排序後切 60/20/20（train/val/test）。
# 為什麼：流量是時間序列；隨機切分會讓「未來的資料」漏進訓練（例如同一次掃描的前半在 train、後半在 test），分數虛高。
#         與 simulate.generate 的切法一致，兩邊的數字才能用同一把尺看。
# 對應：準則 #13；測試 tests/test_training_domain.py::test_time_split_is_ordered
def time_split(flows: Sequence[FlowRecord], train_frac: float = 0.6, val_frac: float = 0.2) -> Tuple[List[FlowRecord], List[FlowRecord], List[FlowRecord]]:
    ordered = sorted(flows, key=lambda f: (f.observed_at, f.flow_id))
    n = len(ordered)
    a, b = int(n * train_frac), int(n * (train_frac + val_frac))
    return ordered[:a], ordered[a:b], ordered[b:]


@dataclass
class TrainingResult:
    model: DualModel
    manifest: Signed
    release_trust: Dict[str, Dict[str, str]]
    dataset_id: str
    dataset_sha256: str
    cleaning: CleaningReport
    split: Dict[str, int]
    known_branch_source: str
    evaluation: Dict[str, Any]
    stages: List[Dict[str, Any]]
    dataset_verification: Dict[str, Any]
    model_sha256: str

    def report(self) -> Dict[str, Any]:
        return {
            "schema": TRAINING_REPORT_SCHEMA,
            "dataset_id": self.dataset_id,
            "dataset_sha256": self.dataset_sha256,
            "dataset_verification": self.dataset_verification,
            "cleaning": self.cleaning.to_dict(),
            "split": self.split,
            "known_branch_source": self.known_branch_source,
            "model": {"model_version": self.model.model_version, "model_sha256": self.model_sha256,
                      **{k: v for k, v in self.model.describe().items() if k != "scaler"}},
            "evaluation": self.evaluation,
            "release": self.manifest.payload,
            "stages": self.stages,
        }


def _stage(name: str, status: str, **detail: Any) -> Dict[str, Any]:
    return {"name": name, "status": status, "detail": detail}


def _span_days(flows: Sequence[FlowRecord]) -> Optional[float]:
    stamps = []
    for f in flows:
        try:
            stamps.append(parse_iso(f.observed_at).timestamp())
        except (TypeError, ValueError):
            continue
    if len(stamps) < 2:
        return None
    return max((max(stamps) - min(stamps)) / 86400.0, 1.0 / 24.0)


def _perturb(f: FlowRecord, factor: float) -> FlowRecord:
    d = asdict(f)
    for k in ("bytes_in", "bytes_out", "pkts_in", "pkts_out", "duration_s", "mean_iat_ms"):
        d[k] = float(d[k]) * factor
    return FlowRecord(**d)


# ── 【老師註解】evaluate ──────────────────────────────────────────
# 做什麼：「對抗與穩健性評估」那一格，四組數字：
#   a) 留出測試集上的 recall（按家族）與 benign 誤報率（門檻已在 val 定死，這裡是「量」不是「調」）；
#   b) leave-one-family-out：把某個家族整個拿掉重新訓練，看異常分支抓不抓得到它——這是「疑似零日」能力的量化（需要 ≥2 個真實家族）；
#   c) 每日誤報數估計 = benign 測試流量被升級的筆數 ÷ 測試集涵蓋的天數（給分析師負載一個數量級）；
#   d) 擾動穩健性：把六個量化欄位同時放大／縮小 5%、10%，看判定狀態翻轉的比例；以及基線自我異常率（訓練 benign 被判異常的比例，應≈ 1−quantile）。
# 為什麼：論文把評估放在簽名之前——沒有數字的模型不該被簽發；而且這些數字會進 release manifest，推論端與稽核者都看得到。
# 怎麼看：「對抗」在這個參考實作裡只做了擾動測試，不是完整的 evasion／投毒攻擊；note 會明講（準則 #13）。
# 拿掉會怎樣：release manifest 的 evaluation 是空的，人類閘門沒有依據決定要不要放行。
# 對應：準則 #12、#13；測試 tests/test_training_domain.py::test_train_offline_end_to_end_on_real_labels
def evaluate(model: DualModel, train: Sequence[FlowRecord], val: Sequence[FlowRecord], test: Sequence[FlowRecord], *,
             tau_k: float, anomaly_quantile: float, families: Sequence[str], seed: int) -> Dict[str, Any]:
    metrics = detection_metrics(model, test) if test else {"test_size": 0, "benign_fpr_at_fixed_thresholds": None,
                                                           "recall_by_family": {}, "status_counts": {}}
    metrics["note"] = "real capture labelled by Slips; thresholds fixed on the validation split; not comparable to published IDS results"

    lofo: Dict[str, Any] = {}
    if len(families) >= 2:
        for fam in families:
            tr = [f for f in train if f.family != fam]
            va = [f for f in val if f.family != fam]
            held = [f for f in test if f.family == fam]
            if not held or not any(f.label != BENIGN for f in tr):
                lofo[fam] = {"recall_on_held_out_family": None, "held_out_test_flows": len(held), "note": "not enough data"}
                continue
            m = DualModel.train(tr, va, tau_k=tau_k, anomaly_quantile=anomaly_quantile, model_version=model.model_version + f"-lofo-{fam}")
            decisions = [m.decide(f) for f in held]
            lofo[fam] = {
                "recall_on_held_out_family": round(sum(d.status in ESCALATED for d in decisions) / len(decisions), 4),
                "held_out_test_flows": len(held),
                "status_counts_on_held_out": dict(sorted(((s, sum(1 for d in decisions if d.status.value == s)) for s in {d.status.value for d in decisions}))),
            }
    else:
        lofo = {"note": "leave-one-family-out needs at least two Slips-labelled attack families in this capture"}

    benign_test = [f for f in test if f.label == BENIGN]
    fp = sum(model.decide(f).status in ESCALATED for f in benign_test)
    span = _span_days(test)
    fp_per_day = {"benign_test_flows": len(benign_test), "false_positives": fp, "test_span_days": round(span, 4) if span else None,
                  "estimate_per_day": round(fp / span, 2) if span else None,
                  "note": "benign = not flagged by Slips; the estimate scales with capture duration, not with site size"}

    sample = list(test[:200]) if test else list(val[:200])
    flips: Dict[str, Optional[float]] = {}
    for pct in (0.05, 0.10):
        changed = 0
        for i, f in enumerate(sample):
            base = model.decide(f).status
            factor = 1.0 + pct if i % 2 == 0 else 1.0 - pct
            if model.decide(_perturb(f, factor)).status != base:
                changed += 1
        flips[f"{int(pct * 100)}pct"] = round(changed / len(sample), 4) if sample else None
    train_benign = [f for f in train if f.label == BENIGN]
    self_anom = sum(model.decide(f).anomaly_high is True for f in train_benign)
    robustness = {
        "perturbation_flip_rate": flips,
        "baseline_self_anomaly_rate": round(self_anom / len(train_benign), 4) if train_benign else None,
        "expected_self_anomaly_rate": round(1.0 - anomaly_quantile, 4),
        "note": "perturbation test only; this is not an adversarial evasion or poisoning evaluation",
    }
    return {"detection_time_split": metrics, "leave_one_family_out": lofo, "false_positives_per_day": fp_per_day,
            "robustness": robustness, "seed": seed}


def _compose_with_synthetic_known(train: Sequence[FlowRecord], val: Sequence[FlowRecord], *, seed: int, tau_k: float,
                                  anomaly_quantile: float, model_version: str) -> DualModel:
    """Real benign baseline for scaler + normality branch; synthetic data for the known branch (explicitly flagged)."""
    raw_train = [featurize(f) for f in train]
    scaler = StandardScaler().fit(raw_train)
    normal_train = [scaler.transform(featurize(f)) for f in train if f.label == BENIGN]
    normality = NormalityModel(quantile=anomaly_quantile).fit(normal_train)
    val_normal = [(scaler.transform(featurize(f)), f.service_group) for f in val if f.label == BENIGN]
    normality.set_thresholds([x for x, _ in val_normal], [g for _, g in val_normal])
    syn = generate(seed=seed)
    x_syn = [scaler.transform(featurize(f)) for f in syn.train]
    y_syn = [f.label or BENIGN for f in syn.train]
    known = KnownModel(tau_k=tau_k).fit(x_syn, y_syn)
    known.calibrate([scaler.transform(featurize(f)) for f in syn.val], [f.label or BENIGN for f in syn.val])
    return DualModel(scaler=scaler, known=known, normality=normality, model_version=model_version)


# ── 【老師註解】train_offline ─────────────────────────────────────
# 做什麼：離線訓練域的總流程：已驗證的 snapshot → 清洗 → 時間切分 → 訓練兩個分支 → 評估 → 用 model_release 鑰匙簽發 → 自我跑一次發布閘門。
#         回傳 TrainingResult（模型、manifest、信任清單、每一格的狀態）。
# 為什麼：這一個函式就是「架構一」的左半邊；每一格的結果都留在 stages 裡，儀表板的 Training Domain 頁面直接畫這六格。
# 怎麼看：
#   - 已知分支預設只用「真實 Slips 標籤」。真實家族不夠（< 1 個達 min_per_class）時會停下來報錯——
#     除非明確給 allow_synthetic_known=True，這時 scaler 與異常分支仍用真實 benign 基線，已知分支改用合成資料，
#     並在 model_version、known_branch_source、manifest.evaluation 三處都標成 synthetic-fallback（不能偷偷混用）。
#   - dataset_sha256 填的是 snapshot 的 flows_sha256 → release manifest 與 dataset manifest 以雜湊互相指向。
#   - approved_by 預設 "pending-human-gate"：簽名證明「訓練域產出了這個製品」，不證明「人類批准了它」；人類批准是另一件事（準則 #13）。
#   - 最後呼叫 verify_release 自我檢查：訓練域自己先用推論端的五道檢查跑一遍，確定交出去的東西過得了閘門。
# 拿掉會怎樣：訓練變成「跑個腳本存個檔」；沒有清洗報告、沒有評估、沒有簽名，推論端只能相信檔名。
# 對應：準則 #9、#10、#12、#13；測試 tests/test_training_domain.py::test_train_offline_end_to_end_on_real_labels、::test_synthetic_known_fallback_is_explicit
def train_offline(
    snapshot: DatasetSnapshot,
    *,
    seed: int = 1,
    tau_k: float = 0.7,
    anomaly_quantile: float = 0.995,
    allow_synthetic_known: bool = False,
    approved_by: str = "pending-human-gate",
    min_per_class: int = 5,
    min_benign: int = 30,
    clock: Optional[Clock] = None,
    release_signer: Optional[Ed25519Signer] = None,
    model_version: Optional[str] = None,
) -> TrainingResult:
    clock = clock or Clock()
    p = snapshot.manifest.payload
    stages: List[Dict[str, Any]] = []
    dataset_verification = {"dataset_id": snapshot.dataset_id, "flows_sha256": snapshot.flows_sha256,
                            "signature_role": "dataset_curator", "trust_source": snapshot.trust_source, "status": "VERIFIED"}
    source = p.get("source", {}) or {}
    cap = source.get("capture_manifest") or {}
    cap_src = cap.get("source") or {}
    # 儀表板只需要抓包的「來源 + 數量」摘要，不重複整份 capture manifest
    capture_summary = {
        "kind": cap_src.get("kind"), "interface": cap_src.get("interface"), "pcap_path": cap_src.get("pcap_path"),
        "bpf_filter": cap_src.get("bpf_filter"), "display_filter": cap_src.get("display_filter"),
        "pyshark": cap_src.get("pyshark"), "tshark": cap_src.get("tshark"),
        "packets_used": cap.get("packets_used"), "packets_skipped_non_ip": cap.get("packets_skipped_non_ip"),
        "flows_written": cap.get("flows_written"), "stop_reason": cap.get("stop_reason"),
        "started_at": cap.get("started_at"), "finished_at": cap.get("finished_at"),
        "content_policy": cap.get("content_policy"),
    } if cap else None
    stages.append(_stage(STAGE_NAMES[0], "done", source=source.get("kind"), flows=len(snapshot.flows),
                         conn_rows=source.get("conn_rows"), conn_log_sha256=source.get("conn_log_sha256"),
                         alerts_sha256=source.get("alerts_sha256"), capture=capture_summary,
                         labeling=p.get("labeling", {}).get("label_sources", {}), slips=p.get("slips", {}),
                         ground_truth=p.get("ground_truth")))

    # 第 2 格：校驗與清洗 + 時間切分
    clean, cleaning = validate_and_clean(snapshot.flows, min_per_class=min_per_class, min_benign=min_benign)
    train, val, test = time_split(clean)
    split = {"train": len(train), "val": len(val), "test": len(test)}
    stages.append(_stage(STAGE_NAMES[1], "done" if cleaning.benign_baseline_sufficient else "failed", **cleaning.to_dict(), split=split))
    if not cleaning.benign_baseline_sufficient:
        raise TrainingDomainError("; ".join(cleaning.notes) or "benign baseline too small")
    if not any(f.label == BENIGN for f in val):
        raise TrainingDomainError("validation split has no benign flows; anomaly thresholds cannot be set")

    # 第 3 格：兩個分支
    train_families = {}
    for f in train:
        if f.label and f.label != BENIGN:
            train_families[f.label] = train_families.get(f.label, 0) + 1
    usable = sorted(fam for fam, n in train_families.items() if n >= min_per_class)
    version = model_version or f"dual_model/{snapshot.dataset_id}-seed{seed}"
    if usable:
        known_source = "real-slips-labels"
        model = DualModel.train(train, val, tau_k=tau_k, anomaly_quantile=anomaly_quantile, model_version=version)
    elif allow_synthetic_known:
        known_source = "synthetic-fallback"
        version += "-synthetic-known"
        model = _compose_with_synthetic_known(train, val, seed=seed, tau_k=tau_k, anomaly_quantile=anomaly_quantile, model_version=version)
    else:
        stages.append(_stage(STAGE_NAMES[2], "failed", reason="no attack family with enough Slips labels in the training split",
                             families_in_train=train_families))
        raise TrainingDomainError(
            "the capture has no attack family with enough Slips labels to train the known branch "
            f"(need >= {min_per_class} per class in the training split; got {train_families or 'none'}). "
            "Capture longer, or pass --allow-synthetic-known to train the known branch on synthetic data (clearly flagged)."
        )
    stages.append(_stage(STAGE_NAMES[2], "done", known_branch_source=known_source, known_classes=model.known.classes,
                         anomaly_quantile=anomaly_quantile, tau_k=tau_k, thresholds=model.normality.tau_a,
                         families_in_train=train_families))

    # 第 4 格：評估
    evaluation = evaluate(model, train, val, test, tau_k=tau_k, anomaly_quantile=anomaly_quantile, families=usable, seed=seed)
    evaluation["known_branch_source"] = known_source
    stages.append(_stage(STAGE_NAMES[3], "done", **{k: evaluation[k] for k in ("detection_time_split", "leave_one_family_out",
                                                                               "false_positives_per_day", "robustness")}))

    # 第 5 格：簽名
    signer = release_signer or Ed25519Signer(MODEL_RELEASE_ROLE)
    manifest_eval = {
        "benign_fpr": evaluation["detection_time_split"].get("benign_fpr_at_fixed_thresholds"),
        "recall_by_family": evaluation["detection_time_split"].get("recall_by_family", {}),
        "lofo_recall": {fam: v.get("recall_on_held_out_family") for fam, v in evaluation["leave_one_family_out"].items() if isinstance(v, dict)},
        "false_positives_per_day": evaluation["false_positives_per_day"].get("estimate_per_day"),
        "known_branch_source": known_source,
        "dataset_id": snapshot.dataset_id,
    }
    manifest = release_model(model, snapshot.flows_sha256, signer, clock, approved_by=approved_by, evaluation=manifest_eval)
    trust = TrustedKeys()
    trust.trust(signer)
    model_sha = sha256_hex(model.to_bytes())
    stages.append(_stage(STAGE_NAMES[4], "done", model_version=model.model_version, model_sha256=model_sha,
                         dataset_sha256=snapshot.flows_sha256, signer_key_id=signer.key_id, released_at=manifest.payload["released_at"]))

    # 第 6 格：發布閘門自我檢查
    verify_release(model.to_bytes(), manifest, trust)
    human = "pending" if approved_by == "pending-human-gate" else "claimed"
    stages.append(_stage(STAGE_NAMES[5], "self-check-passed", checks=["manifest schema", "signature + role", "model sha256",
                                                                      "feature schema", "model_version"],
                         human_approval=human, approved_by=approved_by,
                         note="verify_release ran the same five checks the inference domain runs; human approval is a recorded claim, not a cryptographic proof"))
    return TrainingResult(model=model, manifest=manifest, release_trust=trust.export(), dataset_id=snapshot.dataset_id,
                          dataset_sha256=snapshot.flows_sha256, cleaning=cleaning, split=split, known_branch_source=known_source,
                          evaluation=evaluation, stages=stages, dataset_verification=dataset_verification, model_sha256=model_sha)


def _markdown(report: Dict[str, Any]) -> str:
    lines = [f"# Training report — {report['dataset_id']}", "",
             f"- dataset flows_sha256: `{report['dataset_sha256']}`",
             f"- model: `{report['model']['model_version']}` sha256 `{report['model']['model_sha256']}`",
             f"- known branch source: **{report['known_branch_source']}**",
             f"- approved_by: {report['release'].get('approved_by')}", "", "## Pipeline", ""]
    for s in report["stages"]:
        lines.append(f"- {s['name']}: **{s['status']}**")
    c = report["cleaning"]
    lines += ["", "## Cleaning", "", f"- input {c['input_flows']}, kept {c['kept']}, missing {c['dropped_missing_measurements']}, "
              f"duplicates {c['dropped_duplicates']}, quarantined anomaly-only {c['quarantined_anomaly_only']}, "
              f"rare families dropped {c['dropped_rare_families']}"]
    e = report["evaluation"]
    lines += ["", "## Evaluation", "", f"- benign FPR (test): {e['detection_time_split'].get('benign_fpr_at_fixed_thresholds')}",
              f"- recall by family: {e['detection_time_split'].get('recall_by_family')}",
              f"- leave-one-family-out: {e['leave_one_family_out']}",
              f"- false positives / day: {e['false_positives_per_day'].get('estimate_per_day')}",
              f"- robustness: {e['robustness']}", "",
              "_Labels come from Slips; 'benign' means not flagged. Numbers describe this capture only._", ""]
    return "\n".join(lines)


# ── 【老師註解】write_training_output ─────────────────────────────
# 做什麼：把訓練結果寫成推論端與儀表板要讀的檔案：model.bin（製品 bytes）、release-manifest.json（簽名清單）、
#         release-trust.json（model_release 公鑰）、dataset-verification.json、cleaning-report.json、training-report.json／.md。
# 為什麼：`slips-ingest --release-dir` 與 `dashboard --training-dir` 都只認這幾個檔名；model.bin 的 SHA-256 必須等於 manifest 的 model_sha256。
# 對應：準則 #10；測試 tests/test_training_domain.py::test_train_offline_end_to_end_on_real_labels
def write_training_output(result: TrainingResult, out_dir: str | Path) -> Dict[str, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    report = result.report()
    paths = {
        "model": out / "model.bin",
        "manifest": out / "release-manifest.json",
        "trust": out / "release-trust.json",
        "dataset_verification": out / "dataset-verification.json",
        "cleaning": out / "cleaning-report.json",
        "report": out / "training-report.json",
        "report_md": out / "training-report.md",
    }
    paths["model"].write_bytes(result.model.to_bytes())
    paths["manifest"].write_text(json.dumps(result.manifest.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    paths["trust"].write_text(json.dumps(result.release_trust, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    paths["dataset_verification"].write_text(json.dumps(result.dataset_verification, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    paths["cleaning"].write_text(json.dumps(result.cleaning.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    paths["report"].write_text(json.dumps(report, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    paths["report_md"].write_text(_markdown(report), encoding="utf-8")
    return paths


def load_release_dir(directory: str | Path, trust_path: Optional[str | Path] = None) -> Tuple[bytes, Signed, TrustedKeys, str]:
    """Read model.bin + release-manifest.json (+ trust) the way the inference domain should: bytes, manifest, keys."""
    d = Path(directory)
    try:
        model_bytes = (d / "model.bin").read_bytes()
        manifest_obj = json.loads((d / "release-manifest.json").read_text(encoding="utf-8"))
        trust_file = Path(trust_path) if trust_path else d / "release-trust.json"
        exported = json.loads(trust_file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise TrainingDomainError(f"cannot read release directory {d}: {type(exc).__name__}: {exc}") from exc
    if not isinstance(manifest_obj, dict) or not isinstance(manifest_obj.get("payload"), dict):
        raise TrainingDomainError("release-manifest.json is not a signed object")
    trust = TrustedKeys()
    try:
        for kid, entry in exported.items():
            trust.trust_raw(kid, str(entry["role"]), bytes.fromhex(str(entry["public_raw_hex"])))
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise TrainingDomainError("release trust file is malformed") from exc
    manifest = Signed(payload=manifest_obj["payload"], signatures=list(manifest_obj.get("signatures") or []))
    return model_bytes, manifest, trust, ("explicit" if trust_path else "co-located")
