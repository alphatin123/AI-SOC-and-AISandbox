"""JSON canonicalization (RFC 8785 subset) and digest helpers.

Only the subset of JCS needed for the SOC protocol objects is implemented:
objects with string keys, strings, booleans, null, integers and finite
floats. NaN / Infinity are rejected because JCS cannot represent them.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any


class CanonicalizationError(ValueError):
    pass


def _check(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (bool, str, int)):
        return
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise CanonicalizationError(f"{path}: non-finite float not allowed")
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise CanonicalizationError(f"{path}: object keys must be strings")
            _check(v, f"{path}.{k}")
        return
    if isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            _check(v, f"{path}[{i}]")
        return
    raise CanonicalizationError(f"{path}: unsupported type {type(value).__name__}")


def _normalize(value: Any) -> Any:
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, dict):
        return {k: _normalize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize(v) for v in value]
    return value


def canonical_bytes(value: Any) -> bytes:
    """Return the JCS-style canonical UTF-8 encoding of ``value``."""
    _check(value)
    return json.dumps(
        _normalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(value: Any) -> str:
    """sha256 over the canonical encoding, prefixed so the algorithm is explicit."""
    return "sha256:" + sha256_hex(canonical_bytes(value))
