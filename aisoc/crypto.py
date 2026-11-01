"""Ed25519 signing helpers and a deterministic clock.

``Ed25519Signer`` keeps the private key inside the object and exposes no
export method. This models the *interface* of an HSM-backed signer; it is an
in-memory stand-in and must not be mistaken for hardware key protection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .canonical import canonical_bytes, sha256_hex


def utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class Clock:
    """Injectable clock so tests and simulations are deterministic."""

    def __init__(self, start: Optional[datetime] = None) -> None:
        self._now = start or datetime(2026, 11, 1, 0, 0, 0, tzinfo=timezone.utc)
        self.frozen = start is not None

    def now(self) -> datetime:
        if self.frozen:
            return self._now
        return datetime.now(timezone.utc)

    def advance(self, seconds: float) -> None:
        self.frozen = True
        self._now = self._now + timedelta(seconds=seconds)

    def iso(self) -> str:
        return utc_iso(self.now())


class Ed25519Signer:
    def __init__(self, role: str, private_key: Optional[ed25519.Ed25519PrivateKey] = None) -> None:
        self.role = role
        self._private_key = private_key or ed25519.Ed25519PrivateKey.generate()
        self.public_key = self._private_key.public_key()
        self.key_id = "ed25519:" + sha256_hex(self.public_bytes())[:32]

    def public_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )

    def public_pem(self) -> str:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    def sign_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        sig = self._private_key.sign(canonical_bytes(payload))
        return {"key_id": self.key_id, "role": self.role, "alg": "Ed25519", "sig": sig.hex()}


@dataclass
class TrustedKeys:
    """Registry of public keys and the roles they are trusted for."""

    _keys: Dict[str, ed25519.Ed25519PublicKey] = field(default_factory=dict)
    _roles: Dict[str, str] = field(default_factory=dict)

    def trust(self, signer: Ed25519Signer) -> None:
        self._keys[signer.key_id] = signer.public_key
        self._roles[signer.key_id] = signer.role

    def trust_raw(self, key_id: str, role: str, raw_public: bytes) -> None:
        self._keys[key_id] = ed25519.Ed25519PublicKey.from_public_bytes(raw_public)
        self._roles[key_id] = role

    def role_of(self, key_id: str) -> Optional[str]:
        return self._roles.get(key_id)

    def verify(self, payload: Dict[str, Any], signature: Dict[str, Any], expected_role: Optional[str] = None) -> bool:
        key = self._keys.get(signature.get("key_id", ""))
        if key is None:
            return False
        if expected_role is not None and self._roles.get(signature["key_id"]) != expected_role:
            return False
        try:
            key.verify(bytes.fromhex(signature["sig"]), canonical_bytes(payload))
        except (InvalidSignature, ValueError, KeyError):
            return False
        return True

    def export(self) -> Dict[str, Dict[str, str]]:
        return {
            kid: {
                "role": self._roles[kid],
                "public_raw_hex": key.public_bytes(
                    encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
                ).hex(),
            }
            for kid, key in self._keys.items()
        }
