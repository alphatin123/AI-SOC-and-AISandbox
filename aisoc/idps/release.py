"""Signed model release gate (training domain -> inference domain).

A model may only be loaded for inference if a *release manifest* signed by the
``model_release`` role pins the exact artefact bytes (SHA-256), the training
dataset digest and the feature schema. The inference side never trusts a model
file by its path or name. This is the "model registration + signature +
release gate" step of the paper's training-domain pipeline; the human approval
that precedes signing is organisational and is represented only by the
manifest's ``approved_by`` field.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from ..canonical import sha256_hex
from ..crypto import Clock, Ed25519Signer, TrustedKeys
from ..owp.objects import Signed, schema
from .dual_model import DualModel
from .features import FEATURE_SCHEMA_VERSION

MODEL_RELEASE_ROLE = "model_release"
MANIFEST_SCHEMA = schema("model-manifest")


class ModelReleaseError(Exception):
    pass


def release_model(
    model: DualModel,
    dataset_sha256: str,
    signer: Ed25519Signer,
    clock: Clock,
    approved_by: str = "unspecified",
    evaluation: Optional[Dict[str, Any]] = None,
) -> Signed:
    """Produce the signed manifest for ``model``. Call only from the training domain."""
    if signer.role != MODEL_RELEASE_ROLE:
        raise ModelReleaseError(f"release manifests must be signed by the {MODEL_RELEASE_ROLE!r} role, not {signer.role!r}")
    payload = {
        "schema_version": MANIFEST_SCHEMA,
        "model_version": model.model_version,
        "feature_schema": FEATURE_SCHEMA_VERSION,
        "model_sha256": sha256_hex(model.to_bytes()),
        "dataset_sha256": dataset_sha256,
        "released_at": clock.iso(),
        "approved_by": approved_by,
        "evaluation": evaluation or {},
    }
    return Signed(payload=payload, signatures=[signer.sign_payload(payload)])


def load_verified_model(model_bytes: bytes, manifest: Signed, trusted: TrustedKeys) -> DualModel:
    """Fail closed: no valid manifest, wrong role, hash or schema mismatch -> no model."""
    p = manifest.payload
    if p.get("schema_version") != MANIFEST_SCHEMA:
        raise ModelReleaseError("unexpected manifest schema")
    if not any(trusted.verify(p, s, expected_role=MODEL_RELEASE_ROLE) for s in manifest.signatures):
        raise ModelReleaseError("manifest signature invalid or signer not trusted for model release")
    actual = sha256_hex(model_bytes)
    if actual != p.get("model_sha256"):
        raise ModelReleaseError("model artefact hash does not match the signed manifest")
    if p.get("feature_schema") != FEATURE_SCHEMA_VERSION:
        raise ModelReleaseError("manifest feature schema does not match this inference build")
    model = DualModel.from_bytes(model_bytes)
    if model.model_version != p.get("model_version"):
        raise ModelReleaseError("model_version inside the artefact differs from the manifest")
    return model
