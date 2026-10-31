"""Ed25519 signing in the flat layout described for the OpenWorkProof MCP verify tool:
a signed object carries signature_alg, signer_key_id, digest and signature next to
its payload fields. Confirm the exact schema against the OWP repo before interop.
"""
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives import serialization

from .canon import digest, sha256_hex

SIG_FIELDS = ("signature_alg", "signer_key_id", "digest", "signature")


class KeyPair:
    """In production the private half lives in an HSM/KMS and is non-exportable.
    This class only offers sign(); there is deliberately no export method."""

    def __init__(self):
        self.__sk = Ed25519PrivateKey.generate()
        raw = self.__sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.public_hex = raw.hex()
        self.key_id = sha256_hex(raw)[:16]

    def sign(self, data: bytes) -> str:
        return self.__sk.sign(data).hex()


def register(keyring: dict, kp: KeyPair, role: str) -> None:
    keyring[kp.key_id] = {"pub": kp.public_hex, "role": role}


def sign_payload(kp: KeyPair, payload: dict) -> dict:
    d = digest(payload)
    return {**payload, "signature_alg": "Ed25519", "signer_key_id": kp.key_id,
            "digest": d, "signature": kp.sign(d.encode())}


def verify_signed(signed, keyring, expect_role=None, revoked=frozenset()):
    """Returns (ok, code)."""
    if not isinstance(signed, dict) or any(f not in signed for f in SIG_FIELDS):
        return False, "MALFORMED"
    if signed["signature_alg"] != "Ed25519":
        return False, "BAD_ALG"
    entry = keyring.get(signed["signer_key_id"])
    if entry is None:
        return False, "UNKNOWN_SIGNER"
    if signed["signer_key_id"] in revoked:
        return False, "KEY_REVOKED"
    if expect_role and entry["role"] != expect_role:
        return False, "WRONG_ROLE"
    payload = {k: v for k, v in signed.items() if k not in SIG_FIELDS}
    try:
        d = digest(payload)
    except ValueError:
        return False, "MALFORMED"
    if d != signed["digest"]:
        return False, "DIGEST_MISMATCH"
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(entry["pub"])).verify(
            bytes.fromhex(signed["signature"]), d.encode())
    except (InvalidSignature, ValueError):
        return False, "BAD_SIGNATURE"
    return True, "OK"
