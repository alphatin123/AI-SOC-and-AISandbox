"""dual_model: combine the known branch and the normality branch (paper Table III).

The original single "low confidence AND high anomaly" gate is kept, and two
branches are added: a *model conflict* branch (confident-normal yet highly
anomalous) and an *insufficient evidence* branch. Missing data is never
treated as normal.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence

from .features import FEATURE_NAMES, FEATURE_SCHEMA_VERSION, FlowRecord, StandardScaler, featurize
from .known_model import BENIGN, KnownModel
from .normality_model import NormalityModel


class CaseStatus(str, Enum):
    KNOWN_SUSPICIOUS = "KNOWN_SUSPICIOUS"        # known attack class, evidence consistent
    SUSPECTED_UNKNOWN = "SUSPECTED_UNKNOWN"      # low confidence / reject + high anomaly
    MODEL_CONFLICT = "MODEL_CONFLICT"            # confident normal + high anomaly
    LOW_RISK_OBSERVE = "LOW_RISK_OBSERVE"        # normal, enough data, low anomaly
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"  # low confidence + low anomaly
    UNKNOWN = "UNKNOWN"                          # missing data / model failure


@dataclass
class CaseDecision:
    flow_id: str
    tenant: str
    status: CaseStatus
    known_label: Optional[str]
    known_score: Optional[float]
    known_rejected: Optional[bool]
    anomaly_score: Optional[float]
    anomaly_threshold: Optional[float]
    anomaly_high: Optional[bool]
    requires_human_review: bool
    requires_agent_investigation: bool
    reasons: List[str] = field(default_factory=list)
    feature_schema: str = FEATURE_SCHEMA_VERSION
    model_version: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class DualModel:
    scaler: StandardScaler
    known: KnownModel
    normality: NormalityModel
    model_version: str = "dual_model/dev"
    high_confidence_normal: float = 0.9

    @classmethod
    def train(
        cls,
        train: Sequence[FlowRecord],
        val: Sequence[FlowRecord],
        tau_k: float = 0.7,
        anomaly_quantile: float = 0.995,
        model_version: str = "dual_model/dev",
    ) -> "DualModel":
        """Fit scaler, known branch and normality branch on train, tune on val.

        Labels are only consumed here. The test split must never be passed in.
        """
        raw_train = [featurize(f) for f in train]
        scaler = StandardScaler().fit(raw_train)
        x_train = [scaler.transform(r) for r in raw_train]
        y_train = [f.label or BENIGN for f in train]

        known = KnownModel(tau_k=tau_k).fit(x_train, y_train)
        x_val = [scaler.transform(featurize(f)) for f in val]
        y_val = [f.label or BENIGN for f in val]
        known.calibrate(x_val, y_val)

        normal_train = [x for x, y in zip(x_train, y_train) if y == BENIGN]
        normality = NormalityModel(quantile=anomaly_quantile).fit(normal_train)
        val_normal = [(x, f.service_group) for x, f, y in zip(x_val, val, y_val) if y == BENIGN]
        normality.set_thresholds([x for x, _ in val_normal], [g for _, g in val_normal])

        return cls(scaler=scaler, known=known, normality=normality, model_version=model_version)

    def decide(self, flow: FlowRecord) -> CaseDecision:
        base = dict(flow_id=flow.flow_id, tenant=flow.tenant, model_version=self.model_version)
        if not flow.has_required_fields():
            return CaseDecision(
                status=CaseStatus.UNKNOWN,
                known_label=None, known_score=None, known_rejected=None,
                anomaly_score=None, anomaly_threshold=None, anomaly_high=None,
                requires_human_review=True, requires_agent_investigation=False,
                reasons=["missing required telemetry; not treated as normal"],
                **base,
            )
        try:
            x = self.scaler.transform(featurize(flow))
            kp = self.known.predict(x)
            s_a = self.normality.score(x)
            tau_a = self.normality.threshold_for(flow.service_group)
        except Exception as exc:  # model failure must surface as UNKNOWN, not normal
            return CaseDecision(
                status=CaseStatus.UNKNOWN,
                known_label=None, known_score=None, known_rejected=None,
                anomaly_score=None, anomaly_threshold=None, anomaly_high=None,
                requires_human_review=True, requires_agent_investigation=False,
                reasons=[f"model failure: {type(exc).__name__}"],
                **base,
            )

        high = s_a >= tau_a
        common = dict(
            known_label=kp.label, known_score=round(kp.score, 6), known_rejected=kp.rejected,
            anomaly_score=round(s_a, 6), anomaly_threshold=round(tau_a, 6), anomaly_high=high,
        )

        if kp.label != BENIGN and not kp.rejected:
            return CaseDecision(
                status=CaseStatus.KNOWN_SUSPICIOUS,
                requires_human_review=False, requires_agent_investigation=True,
                reasons=[f"known class {kp.label} with calibrated score {kp.score:.3f}"],
                **common, **base,
            )
        if kp.rejected and high:
            return CaseDecision(
                status=CaseStatus.SUSPECTED_UNKNOWN,
                requires_human_review=True, requires_agent_investigation=True,
                reasons=["known branch rejected", f"anomaly {s_a:.3f} >= tau_a {tau_a:.3f}"],
                **common, **base,
            )
        if kp.label == BENIGN and kp.score >= self.high_confidence_normal and high:
            return CaseDecision(
                status=CaseStatus.MODEL_CONFLICT,
                requires_human_review=True, requires_agent_investigation=True,
                reasons=["confident normal but highly anomalous; must not auto-close"],
                **common, **base,
            )
        if kp.label == BENIGN and not kp.rejected and high:
            # benign but not highly confident, and anomalous: escalate like unknown
            return CaseDecision(
                status=CaseStatus.SUSPECTED_UNKNOWN,
                requires_human_review=True, requires_agent_investigation=True,
                reasons=["weakly-normal with high anomaly"],
                **common, **base,
            )
        if kp.rejected and not high:
            return CaseDecision(
                status=CaseStatus.INSUFFICIENT_EVIDENCE,
                requires_human_review=False, requires_agent_investigation=False,
                reasons=["low confidence, low anomaly; sample for review"],
                **common, **base,
            )
        return CaseDecision(
            status=CaseStatus.LOW_RISK_OBSERVE,
            requires_human_review=False, requires_agent_investigation=False,
            reasons=["normal with sufficient data; drift monitoring only"],
            **common, **base,
        )

    def describe(self) -> Dict[str, Any]:
        return {
            "model_version": self.model_version,
            "feature_schema": FEATURE_SCHEMA_VERSION,
            "features": FEATURE_NAMES,
            "scaler": self.scaler.to_dict(),
            "known_branch": self.known.to_dict(),
            "normality_branch": self.normality.to_dict(),
            "high_confidence_normal": self.high_confidence_normal,
        }
