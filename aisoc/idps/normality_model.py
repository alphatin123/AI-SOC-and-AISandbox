"""Normality branch f_a(x): Isolation Forest implemented in pure Python.

The model is fit on *vetted normal windows only*. The anomaly threshold tau_a
is taken from a quantile of validation-normal scores (per service group when
enough data exists). The 99.5 quantile is a development starting point, not a
deployment FPR guarantee.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence


def _c(n: int) -> float:
    if n <= 1:
        return 0.0
    h = math.log(n - 1) + 0.5772156649
    return 2.0 * h - 2.0 * (n - 1) / n


class _Node:
    __slots__ = ("feature", "split", "left", "right", "size")

    def __init__(self) -> None:
        self.feature: int = -1
        self.split: float = 0.0
        self.left: Optional["_Node"] = None
        self.right: Optional["_Node"] = None
        self.size: int = 0


def _build(rows: List[Sequence[float]], depth: int, max_depth: int, rng: random.Random) -> _Node:
    node = _Node()
    node.size = len(rows)
    if depth >= max_depth or len(rows) <= 1:
        return node
    d = len(rows[0])
    candidates = [j for j in range(d) if min(r[j] for r in rows) < max(r[j] for r in rows)]
    if not candidates:
        return node
    j = rng.choice(candidates)
    lo = min(r[j] for r in rows)
    hi = max(r[j] for r in rows)
    split = rng.uniform(lo, hi)
    node.feature = j
    node.split = split
    node.left = _build([r for r in rows if r[j] < split], depth + 1, max_depth, rng)
    node.right = _build([r for r in rows if r[j] >= split], depth + 1, max_depth, rng)
    return node


def _path_length(node: _Node, row: Sequence[float], depth: int = 0) -> float:
    if node.left is None or node.right is None:
        return depth + _c(node.size)
    if row[node.feature] < node.split:
        return _path_length(node.left, row, depth + 1)
    return _path_length(node.right, row, depth + 1)


@dataclass
class NormalityModel:
    n_trees: int = 60
    sample_size: int = 128
    seed: int = 11
    trees: List[_Node] = field(default_factory=list)
    tau_a: Dict[str, float] = field(default_factory=dict)  # per service group, "default" fallback
    quantile: float = 0.995
    _sample_n: int = 0

    def fit(self, x_normal: Sequence[Sequence[float]]) -> "NormalityModel":
        rng = random.Random(self.seed)
        rows = [list(r) for r in x_normal]
        n = min(self.sample_size, len(rows))
        self._sample_n = n
        max_depth = int(math.ceil(math.log2(max(n, 2))))
        self.trees = [_build(rng.sample(rows, n), 0, max_depth, rng) for _ in range(self.n_trees)]
        return self

    def score(self, row: Sequence[float]) -> float:
        if not self.trees:
            raise RuntimeError("normality model not fitted")
        e = sum(_path_length(t, row) for t in self.trees) / len(self.trees)
        return 2.0 ** (-e / max(_c(self._sample_n), 1e-9))

    def set_thresholds(
        self,
        x_val_normal: Sequence[Sequence[float]],
        groups: Optional[Sequence[str]] = None,
        min_group_size: int = 50,
    ) -> Dict[str, float]:
        scores = [self.score(r) for r in x_val_normal]
        self.tau_a = {"default": _quantile(scores, self.quantile)}
        if groups is not None:
            by_group: Dict[str, List[float]] = {}
            for s, g in zip(scores, groups):
                by_group.setdefault(g, []).append(s)
            for g, vals in by_group.items():
                if len(vals) >= min_group_size:
                    self.tau_a[g] = _quantile(vals, self.quantile)
        return self.tau_a

    def threshold_for(self, group: str) -> float:
        return self.tau_a.get(group, self.tau_a.get("default", 1.0))

    def is_anomalous(self, row: Sequence[float], group: str = "default") -> bool:
        return self.score(row) >= self.threshold_for(group)

    def to_dict(self) -> Dict[str, object]:
        return {
            "type": "isolation_forest",
            "n_trees": self.n_trees,
            "sample_size": self.sample_size,
            "quantile": self.quantile,
            "tau_a": self.tau_a,
        }

    def to_params(self) -> Dict[str, object]:
        """Complete, loadable parameter set including every tree."""
        d = self.to_dict()
        d.update({"seed": self.seed, "sample_n": self._sample_n, "trees": [_node_to_dict(t) for t in self.trees]})
        return d

    @classmethod
    def from_params(cls, p: Dict[str, object]) -> "NormalityModel":
        if p.get("type") != "isolation_forest":
            raise ValueError("unsupported normality-model type")
        m = cls(
            n_trees=int(p["n_trees"]),  # type: ignore[arg-type]
            sample_size=int(p["sample_size"]),  # type: ignore[arg-type]
            seed=int(p.get("seed", 11)),  # type: ignore[arg-type]
            quantile=float(p["quantile"]),  # type: ignore[arg-type]
            tau_a={k: float(v) for k, v in dict(p["tau_a"]).items()},  # type: ignore[arg-type]
        )
        m._sample_n = int(p["sample_n"])  # type: ignore[arg-type]
        m.trees = [_node_from_dict(t) for t in list(p["trees"])]  # type: ignore[arg-type]
        return m


def _node_to_dict(n: _Node) -> Dict[str, object]:
    d: Dict[str, object] = {"size": n.size}
    if n.left is not None and n.right is not None:
        d.update({"feature": n.feature, "split": n.split, "left": _node_to_dict(n.left), "right": _node_to_dict(n.right)})
    return d


def _node_from_dict(d: Dict[str, object]) -> _Node:
    n = _Node()
    n.size = int(d["size"])  # type: ignore[arg-type]
    if "left" in d:
        n.feature = int(d["feature"])  # type: ignore[arg-type]
        n.split = float(d["split"])  # type: ignore[arg-type]
        n.left = _node_from_dict(d["left"])  # type: ignore[arg-type]
        n.right = _node_from_dict(d["right"])  # type: ignore[arg-type]
    return n


def _quantile(values: Sequence[float], q: float) -> float:
    if not values:
        return 1.0
    s = sorted(values)
    pos = (len(s) - 1) * q
    lo = int(math.floor(pos))
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (pos - lo)
