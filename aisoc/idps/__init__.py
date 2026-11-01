"""AI-IDPS: dual_model detection (known-pattern branch + normality branch)."""

from .dual_model import CaseDecision, CaseStatus, DualModel
from .features import FEATURE_NAMES, FEATURE_SCHEMA_VERSION, FlowRecord, featurize
from .known_model import BENIGN, KnownModel
from .normality_model import NormalityModel

__all__ = [
    "BENIGN",
    "CaseDecision",
    "CaseStatus",
    "DualModel",
    "FEATURE_NAMES",
    "FEATURE_SCHEMA_VERSION",
    "FlowRecord",
    "KnownModel",
    "NormalityModel",
    "featurize",
]
