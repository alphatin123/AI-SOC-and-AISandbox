"""Known-pattern branch f_k(x): one-vs-rest logistic regression (pure Python).

Outputs a class label and a per-class calibrated score. Temperature scaling is
fit on the validation split; the reject threshold tau_k is a hyper-parameter
chosen on validation data, never on the test split.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Tuple

BENIGN = "benign"


def _sigmoid(z: float) -> float:
    if z >= 0:
        ez = math.exp(-z)
        return 1.0 / (1.0 + ez)
    ez = math.exp(z)
    return ez / (1.0 + ez)


@dataclass
class KnownPrediction:
    label: str
    score: float  # calibrated probability of the predicted label
    scores: Dict[str, float]
    rejected: bool


@dataclass
class KnownModel:
    classes: List[str] = field(default_factory=list)
    weights: Dict[str, List[float]] = field(default_factory=dict)
    bias: Dict[str, float] = field(default_factory=dict)
    temperature: float = 1.0
    tau_k: float = 0.7
    lr: float = 0.1
    epochs: int = 60
    l2: float = 1e-3
    seed: int = 7

    def fit(self, x: Sequence[Sequence[float]], y: Sequence[str]) -> "KnownModel":
        rng = random.Random(self.seed)
        self.classes = sorted(set(y))
        d = len(x[0])
        idx = list(range(len(x)))
        for cls in self.classes:
            w = [0.0] * d
            b = 0.0
            target = [1.0 if label == cls else 0.0 for label in y]
            for _ in range(self.epochs):
                rng.shuffle(idx)
                for i in idx:
                    z = b + sum(wj * xj for wj, xj in zip(w, x[i]))
                    g = _sigmoid(z) - target[i]
                    for j in range(d):
                        w[j] -= self.lr * (g * x[i][j] + self.l2 * w[j])
                    b -= self.lr * g
            self.weights[cls] = w
            self.bias[cls] = b
        return self

    def _logits(self, row: Sequence[float]) -> Dict[str, float]:
        return {
            cls: self.bias[cls] + sum(wj * xj for wj, xj in zip(self.weights[cls], row))
            for cls in self.classes
        }

    def _probs(self, row: Sequence[float]) -> Dict[str, float]:
        logits = self._logits(row)
        m = max(logits.values())
        exps = {c: math.exp((v - m) / self.temperature) for c, v in logits.items()}
        s = sum(exps.values())
        return {c: v / s for c, v in exps.items()}

    def calibrate(self, x_val: Sequence[Sequence[float]], y_val: Sequence[str]) -> float:
        """Grid-search a softmax temperature minimising NLL on the validation split."""
        best_t, best_nll = 1.0, float("inf")
        for t in [0.5, 0.75, 1.0, 1.5, 2.0, 3.0, 4.0]:
            self.temperature = t
            nll = 0.0
            for row, label in zip(x_val, y_val):
                p = self._probs(row).get(label, 1e-9)
                nll -= math.log(max(p, 1e-9))
            if nll < best_nll:
                best_t, best_nll = t, nll
        self.temperature = best_t
        return best_t

    def predict(self, row: Sequence[float]) -> KnownPrediction:
        probs = self._probs(row)
        label, score = max(probs.items(), key=lambda kv: kv[1])
        return KnownPrediction(label=label, score=score, scores=probs, rejected=score < self.tau_k)

    def to_dict(self) -> Dict[str, object]:
        return {
            "type": "ovr_logistic_regression",
            "classes": self.classes,
            "temperature": self.temperature,
            "tau_k": self.tau_k,
            "epochs": self.epochs,
            "lr": self.lr,
            "l2": self.l2,
        }

    def to_params(self) -> Dict[str, object]:
        """Complete, loadable parameter set (what a release manifest must pin)."""
        d = self.to_dict()
        d.update({"weights": self.weights, "bias": self.bias, "seed": self.seed})
        return d

    @classmethod
    def from_params(cls, p: Dict[str, object]) -> "KnownModel":
        if p.get("type") != "ovr_logistic_regression":
            raise ValueError("unsupported known-model type")
        return cls(
            classes=list(p["classes"]),  # type: ignore[arg-type]
            weights={k: [float(v) for v in ws] for k, ws in dict(p["weights"]).items()},  # type: ignore[arg-type]
            bias={k: float(v) for k, v in dict(p["bias"]).items()},  # type: ignore[arg-type]
            temperature=float(p["temperature"]),  # type: ignore[arg-type]
            tau_k=float(p["tau_k"]),  # type: ignore[arg-type]
            lr=float(p["lr"]),  # type: ignore[arg-type]
            epochs=int(p["epochs"]),  # type: ignore[arg-type]
            l2=float(p["l2"]),  # type: ignore[arg-type]
            seed=int(p.get("seed", 7)),  # type: ignore[arg-type]
        )
