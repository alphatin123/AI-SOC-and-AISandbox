"""Canonical JSON and hashing helpers.

NOTE: this is deterministic JSON, not full RFC 8785 (JCS). Floats are rejected in
signed payloads on purpose (use str/int) so canonicalisation stays unambiguous.
For production use a real JCS implementation.
"""
import hashlib
import json


def _reject_floats(o):
    if isinstance(o, float):
        raise ValueError("floats are not allowed in signed payloads; use str or int")
    if isinstance(o, dict):
        for k, v in o.items():
            if not isinstance(k, str):
                raise ValueError("object keys must be strings")
            _reject_floats(v)
    elif isinstance(o, (list, tuple)):
        for v in o:
            _reject_floats(v)


def canonical(obj) -> bytes:
    _reject_floats(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(obj) -> str:
    return sha256_hex(canonical(obj))


def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def fmt(x: float) -> str:
    """Scores travel as fixed-precision strings inside signed objects."""
    return f"{x:.4f}"
