"""dual_model: combine the known branch and the normality branch (paper Table III).

The original single "low confidence AND high anomaly" gate is kept, and two
branches are added: a *model conflict* branch (confident-normal yet highly
anomalous) and an *insufficient evidence* branch. Missing data is never
treated as normal.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

from .features import FEATURE_NAMES, FEATURE_SCHEMA_VERSION, FlowRecord, StandardScaler, featurize
from .known_model import BENIGN, KnownModel, KnownPrediction
from .normality_model import NormalityModel

MODEL_FILE_SCHEMA = "aisoc/dual_model_file/v1"


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

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CaseDecision":
        kw = dict(d)
        kw["status"] = CaseStatus(kw["status"])
        return cls(**kw)


@dataclass
class ExternalKnown:
    """Known-branch verdict produced outside this package (e.g. a Slips evidence line).

    ``label`` uses the same vocabulary as the internal known branch (``benign`` or
    an attack family); ``rejected`` means the producer could not place the event in
    any known class with sufficient confidence. ``source`` names the producing
    system/module so the decision stays attributable.
    """

    label: str
    score: float
    rejected: bool
    source: str
    technique: Optional[str] = None
    evidence_ids: List[str] = field(default_factory=list)


@dataclass
class ExternalAnomaly:
    """Normality-branch signal produced outside this package (e.g. Slips ML/anomaly modules)."""

    score: float
    high: bool
    source: str
    threshold: Optional[float] = None


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

        return self._combine(kp, s_a, tau_a, base, anomaly_source="internal")

    def decide_external(
        self,
        flow: FlowRecord,
        known: ExternalKnown,
        anomaly: Optional[ExternalAnomaly] = None,
        use_internal_normality: bool = False,
    ) -> CaseDecision:
        """Table III with the known branch supplied by an external detector.

        The normality branch is, in order of preference: this model's own
        normality model when ``use_internal_normality`` is set *and* the flow
        carries the volumetric fields (only meaningful if the model was trained
        on the same network); otherwise the external anomaly signal; otherwise
        *unknown*, which is never treated as normal.
        """
        base = dict(flow_id=flow.flow_id, tenant=flow.tenant, model_version=f"{self.model_version}+{known.source}")
        kp = KnownPrediction(label=known.label, score=known.score, scores={known.label: known.score}, rejected=known.rejected)
        if use_internal_normality and flow.has_required_fields():
            try:
                x = self.scaler.transform(featurize(flow))
                s_a = self.normality.score(x)
                tau_a = self.normality.threshold_for(flow.service_group)
            except Exception as exc:
                return self._unknown(base, f"normality model failure: {type(exc).__name__}")
            return self._combine(kp, s_a, tau_a, base, anomaly_source="internal")
        if anomaly is not None:
            tau = anomaly.threshold if anomaly.threshold is not None else (anomaly.score if anomaly.high else anomaly.score + 1.0)
            return self._combine(kp, anomaly.score, tau, base, anomaly_source=anomaly.source, high_override=anomaly.high)
        if kp.label != BENIGN and not kp.rejected:
            # A confident known-attack verdict stands on its own; the missing normality branch is recorded.
            return CaseDecision(
                status=CaseStatus.KNOWN_SUSPICIOUS,
                known_label=kp.label, known_score=round(kp.score, 6), known_rejected=False,
                anomaly_score=None, anomaly_threshold=None, anomaly_high=None,
                requires_human_review=False, requires_agent_investigation=True,
                reasons=[f"known class {kp.label} from {known.source} with score {kp.score:.3f}", "normality branch unavailable"],
                **base,
            )
        return self._unknown(base, "known branch rejected/benign and no normality signal; not treated as normal",
                             known_label=kp.label, known_score=round(kp.score, 6), known_rejected=kp.rejected)

    def _unknown(self, base: Dict[str, Any], reason: str, **known_fields: Any) -> CaseDecision:
        fields = dict(known_label=None, known_score=None, known_rejected=None)
        fields.update(known_fields)
        return CaseDecision(
            status=CaseStatus.UNKNOWN,
            anomaly_score=None, anomaly_threshold=None, anomaly_high=None,
            requires_human_review=True, requires_agent_investigation=False,
            reasons=[reason],
            **fields, **base,
        )

    def _combine(
        self,
        kp: KnownPrediction,
        s_a: float,
        tau_a: float,
        base: Dict[str, Any],
        anomaly_source: str,
        high_override: Optional[bool] = None,
    ) -> CaseDecision:
        high = (s_a >= tau_a) if high_override is None else high_override
        common = dict(
            known_label=kp.label, known_score=round(kp.score, 6), known_rejected=kp.rejected,
            anomaly_score=round(s_a, 6), anomaly_threshold=round(tau_a, 6), anomaly_high=high,
        )
        src = "" if anomaly_source == "internal" else f" ({anomaly_source})"

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
                reasons=["known branch rejected", f"anomaly {s_a:.3f} >= tau_a {tau_a:.3f}{src}"],
                **common, **base,
            )
        if kp.label == BENIGN and kp.score >= self.high_confidence_normal and high:
            return CaseDecision(
                status=CaseStatus.MODEL_CONFLICT,
                requires_human_review=True, requires_agent_investigation=True,
                reasons=["confident normal but highly anomalous; must not auto-close" + src],
                **common, **base,
            )
        if kp.label == BENIGN and not kp.rejected and high:
            # benign but not highly confident, and anomalous: escalate like unknown
            return CaseDecision(
                status=CaseStatus.SUSPECTED_UNKNOWN,
                requires_human_review=True, requires_agent_investigation=True,
                reasons=["weakly-normal with high anomaly" + src],
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

    # ------------------------------------------------------------------ persistence
    def to_params(self) -> Dict[str, Any]:
        return {
            "schema": MODEL_FILE_SCHEMA,
            "model_version": self.model_version,
            "feature_schema": FEATURE_SCHEMA_VERSION,
            "features": FEATURE_NAMES,
            "high_confidence_normal": self.high_confidence_normal,
            "scaler": self.scaler.to_dict(),
            "known": self.known.to_params(),
            "normality": self.normality.to_params(),
        }

    @classmethod
    def from_params(cls, p: Dict[str, Any]) -> "DualModel":
        if p.get("schema") != MODEL_FILE_SCHEMA:
            raise ValueError(f"unsupported model file schema {p.get('schema')!r}")
        if p.get("feature_schema") != FEATURE_SCHEMA_VERSION:
            raise ValueError("model was trained against a different feature schema")
        return cls(
            scaler=StandardScaler.from_dict(p["scaler"]),
            known=KnownModel.from_params(p["known"]),
            normality=NormalityModel.from_params(p["normality"]),
            model_version=str(p["model_version"]),
            high_confidence_normal=float(p["high_confidence_normal"]),
        )

    def to_bytes(self) -> bytes:
        """Canonical model artefact bytes; a release manifest pins their SHA-256."""
        return json.dumps(self.to_params(), sort_keys=True, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> "DualModel":
        return cls.from_params(json.loads(data.decode("utf-8")))

    def save(self, path: Union[str, Path]) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(self.to_bytes())
        return path

    @classmethod
    def load(cls, path: Union[str, Path]) -> "DualModel":
        return cls.from_bytes(Path(path).read_bytes())
