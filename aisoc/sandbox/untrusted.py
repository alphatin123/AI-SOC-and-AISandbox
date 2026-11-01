"""Data/control separation primitives.

Anything that comes from logs, URLs, attachments or tool outputs is wrapped in
``Untrusted`` so it cannot be confused with instructions. A heuristic injection
screen flags suspicious content for the analyst view; it is *not* a security
boundary. The actual boundary is that agent output can only select from an
enumerated action set and must pass external policy (see ``policy.py``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Generic, List, TypeVar

T = TypeVar("T")

_INJECTION_PATTERNS = [
    r"ignore (all |any )?(previous|prior|above) instructions",
    r"you are now",
    r"system prompt",
    r"as an? (ai|assistant|agent),? you must",
    r"\bexfil(trate)?\b",
    r"curl\s+-X\s+POST",
    r"base64\s+-d",
    r"disable (the )?audit",
    r"approve (this|the) (action|request)",
    r"(send|upload|post) .* to https?://",
    r"\bdrop table\b",
    r"new tenant",
]
_COMPILED = [re.compile(p, re.IGNORECASE) for p in _INJECTION_PATTERNS]


@dataclass(frozen=True)
class Untrusted(Generic[T]):
    source: str
    content: T
    flags: List[str] = field(default_factory=list)

    def __str__(self) -> str:  # pragma: no cover - guard against accidental string use
        raise TypeError("Untrusted content must be accessed via .content explicitly")


def screen_text(text: str) -> List[str]:
    return [p.pattern for p, _ in zip(_COMPILED, _INJECTION_PATTERNS) if p.search(text)]


def wrap(source: str, content: Any) -> Untrusted[Any]:
    flags: List[str] = []
    if isinstance(content, str):
        flags = screen_text(content)
    elif isinstance(content, dict):
        for v in content.values():
            if isinstance(v, str):
                flags.extend(screen_text(v))
    return Untrusted(source=source, content=content, flags=sorted(set(flags)))
