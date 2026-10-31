"""Dual-model detection with signed model release.

SignatureKnownModel / BaselineAnomalyModel are deterministic STAND-INS so the pipeline is
runnable without ML dependencies. Replace with the trained models; keep the interface
(predict -> KnownResult, score -> AnomalyResult) and the release/verify flow."""
import json
from dataclasses import dataclass

from .canon import digest, fmt, sha256_hex
from .crypto import sign_payload, verify_signed

ATTACK_TECHNIQUE = {"port_scan": "T1046", "dns_tunnel": "T1071.004"}   # examples only


class ModelVerificationError(Exception):
    pass


@dataclass(frozen=True)
class KnownResult:
    label: str
    confidence: float


@dataclass(frozen=True)
class AnomalyResult:
    score: float
    top_features: tuple


@dataclass(frozen=True)
class Thresholds:
    known_conf_max: float = 0.5
    anomaly_min: float = 0.9
    rule_version: str = "zd-rule-1"


class SignatureKnownModel:
    def __init__(self, params):
        self.signatures, self.scale = params["signatures"], params["scale"]

    def predict(self, feats) -> KnownResult:
        best = ("none", 0.0)
        for label, sig in self.signatures.items():
            dist = sum(abs(feats.get(k, 0) - v) / self.scale[k] for k, v in sig.items()) / len(sig)
            conf = max(0.0, 1.0 - dist)
            if conf > best[1]:
                best = (label, conf)
        return KnownResult(*best)


class BaselineAnomalyModel:
    def __init__(self, params):
        self.mean, self.std = params["mean"], params["std"]

    def score(self, feats) -> AnomalyResult:
        z = {k: abs(feats.get(k, 0) - m) / max(self.std[k], 1e-9) for k, m in self.mean.items()}
        score = min(1.0, (sum(z.values()) / len(z)) / 6.0)
        top = tuple(k for k, _ in sorted(z.items(), key=lambda kv: -kv[1])[:3])
        return AnomalyResult(score, top)


def decide(known: KnownResult, anomaly: AnomalyResult, th: Thresholds) -> bool:
    """Suspected zero-day = known model unsure AND anomaly model alarmed."""
    return known.confidence < th.known_conf_max and anomaly.score > th.anomaly_min


# ---- model release gate (training domain -> sandbox, one-way, signed) -------------
def release_model(params: dict, release_kp, name, version, dataset_sha256):
    blob = json.dumps(params, sort_keys=True).encode()
    manifest = sign_payload(release_kp, {
        "type": "model_manifest", "name": name, "version": version,
        "sha256": sha256_hex(blob), "dataset_sha256": dataset_sha256})
    return blob, manifest


def load_verified_model(blob: bytes, manifest: dict, keyring) -> dict:
    ok, code = verify_signed(manifest, keyring, expect_role="model_release")
    if not ok:
        raise ModelVerificationError(f"manifest rejected: {code}")
    if sha256_hex(blob) != manifest["sha256"]:
        raise ModelVerificationError("model bytes do not match signed hash")
    return json.loads(blob)


def standardized_output(case_id, window_ref, known, anomaly, suspected, th, manifests) -> dict:
    """The ONLY artefact the sandbox produces. Strings/ints only (signable)."""
    return {
        "schema": "aisoc.output/0.1", "case_id": case_id, "window_ref": window_ref,
        "known": {"label": known.label if known.confidence >= 0.3 else "UNKNOWN",
                  "confidence": fmt(known.confidence),
                  "attack_technique": ATTACK_TECHNIQUE.get(known.label)
                  if known.confidence >= 0.3 else None},
        "anomaly": {"score": fmt(anomaly.score), "top_features": list(anomaly.top_features)},
        "verdict": {"suspected_zero_day": suspected, "rule_version": th.rule_version},
        "models": {"known_sha256": manifests["known"]["sha256"],
                   "anomaly_sha256": manifests["anomaly"]["sha256"]},
    }
