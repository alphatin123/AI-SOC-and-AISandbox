"""Flow records and the versioned feature schema shared by both branches.

Both the known-pattern branch and the normality branch must see exactly the
same feature vector computed from information available at decision time.
The schema is versioned so a model artefact can be tied to the features it
was trained with.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

FEATURE_SCHEMA_VERSION = "aisoc/features/v1"

FEATURE_NAMES: List[str] = [
    "log_bytes_in",
    "log_bytes_out",
    "out_in_byte_ratio",
    "log_pkts_in",
    "log_pkts_out",
    "log_duration",
    "log_mean_iat_ms",
    "conn_failures",
    "log_short_window_conns",
    "distinct_dst_ports",
    "login_failures",
    "is_well_known_port",
]


@dataclass
class FlowRecord:
    flow_id: str
    tenant: str
    src_host: str
    dst_ip: str
    dst_port: int
    bytes_in: float
    bytes_out: float
    pkts_in: float
    pkts_out: float
    duration_s: float
    mean_iat_ms: float
    conn_failures: float
    short_window_conns: float
    distinct_dst_ports: float
    login_failures: float
    service_group: str = "default"
    observed_at: str = ""
    # Ground truth is kept only for offline evaluation and is never visible to inference.
    label: Optional[str] = None
    family: Optional[str] = None
    # Raw log text attached to the flow. Treated as *untrusted content* downstream.
    log_excerpt: str = ""

    def has_required_fields(self) -> bool:
        for name in ("bytes_in", "bytes_out", "pkts_in", "pkts_out", "duration_s", "mean_iat_ms"):
            v = getattr(self, name)
            if v is None or (isinstance(v, float) and math.isnan(v)) or v < 0:
                return False
        return True


def featurize(flow: FlowRecord) -> List[float]:
    def l(x: float) -> float:
        return math.log1p(max(x, 0.0))

    denom = flow.bytes_in + 1.0
    return [
        l(flow.bytes_in),
        l(flow.bytes_out),
        min(flow.bytes_out / denom, 1000.0),
        l(flow.pkts_in),
        l(flow.pkts_out),
        l(flow.duration_s),
        l(flow.mean_iat_ms),
        float(flow.conn_failures),
        l(flow.short_window_conns),
        float(flow.distinct_dst_ports),
        float(flow.login_failures),
        1.0 if flow.dst_port in (22, 53, 80, 443) else 0.0,
    ]


@dataclass
class StandardScaler:
    """Fit on training data only; applying it elsewhere is a leakage bug."""

    means: List[float] = field(default_factory=list)
    stds: List[float] = field(default_factory=list)

    def fit(self, rows: Sequence[Sequence[float]]) -> "StandardScaler":
        n = len(rows)
        d = len(rows[0])
        self.means = [sum(r[j] for r in rows) / n for j in range(d)]
        self.stds = []
        for j in range(d):
            var = sum((r[j] - self.means[j]) ** 2 for r in rows) / max(n - 1, 1)
            self.stds.append(math.sqrt(var) if var > 1e-12 else 1.0)
        return self

    def transform(self, row: Sequence[float]) -> List[float]:
        return [(x - m) / s for x, m, s in zip(row, self.means, self.stds)]

    def to_dict(self) -> Dict[str, List[float]]:
        return {"means": self.means, "stds": self.stds}

    @classmethod
    def from_dict(cls, d: Dict[str, List[float]]) -> "StandardScaler":
        return cls(means=[float(x) for x in d["means"]], stds=[float(x) for x in d["stds"]])
