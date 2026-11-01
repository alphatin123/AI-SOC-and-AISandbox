"""Tamper-evident ledger: hash chain + Merkle checkpoints + external witness.

The ledger stores *digests and relational metadata only*. Sensitive raw content
is kept in a separate ``EncryptedEvidenceStore`` so that retention / deletion
policy can be applied to originals without breaking the commitment chain.

What this provides: detection of modification, truncation and forking relative
to a witnessed checkpoint. What it cannot provide: discovery of actions that
were never recorded. That gap is addressed by reconciliation against the
independent tool-side log (see ``verifier.py``).
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..canonical import canonical_bytes, digest, sha256_hex
from ..crypto import Clock, Ed25519Signer, TrustedKeys

GENESIS = "sha256:" + "0" * 64


@dataclass
class LedgerEntry:
    index: int
    entry_type: str
    case_id: str
    object_digest: str
    refs: Dict[str, str]
    recorded_at: str
    prev_hash: str
    entry_hash: str = ""

    def body(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "entry_type": self.entry_type,
            "case_id": self.case_id,
            "object_digest": self.object_digest,
            "refs": self.refs,
            "recorded_at": self.recorded_at,
            "prev_hash": self.prev_hash,
        }

    def compute_hash(self) -> str:
        return digest(self.body())

    def to_dict(self) -> Dict[str, Any]:
        d = self.body()
        d["entry_hash"] = self.entry_hash
        return d


def merkle_root(hashes: List[str]) -> str:
    if not hashes:
        return GENESIS
    layer = [h.split(":", 1)[1] for h in hashes]
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        layer = [sha256_hex(bytes.fromhex(layer[i]) + bytes.fromhex(layer[i + 1])) for i in range(0, len(layer), 2)]
    return "sha256:" + layer[0]


class ExternalWitness:
    """Append-only checkpoint store operated by a *different* administrator.

    Backed by a JSONL file when ``path`` is given, otherwise in memory. The
    separation of duties is organisational; this class only provides the
    append-only interface and the verification helper.
    """

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = path
        self._mem: List[Dict[str, Any]] = []
        if path is not None and path.exists():
            self._mem = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

    def publish(self, checkpoint: Dict[str, Any]) -> None:
        self._mem.append(checkpoint)
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(checkpoint, sort_keys=True) + "\n")

    def checkpoints(self) -> List[Dict[str, Any]]:
        return list(self._mem)


class HashChainLedger:
    def __init__(self, signer: Ed25519Signer, clock: Clock, witness: Optional[ExternalWitness] = None) -> None:
        self.signer = signer
        self.clock = clock
        self.witness = witness
        self.entries: List[LedgerEntry] = []
        self._lock = threading.Lock()

    def append(self, entry_type: str, case_id: str, obj: Dict[str, Any], refs: Optional[Dict[str, str]] = None) -> LedgerEntry:
        with self._lock:
            prev = self.entries[-1].entry_hash if self.entries else GENESIS
            entry = LedgerEntry(
                index=len(self.entries),
                entry_type=entry_type,
                case_id=case_id,
                object_digest=digest(obj),
                refs=refs or {},
                recorded_at=self.clock.iso(),
                prev_hash=prev,
            )
            entry.entry_hash = entry.compute_hash()
            self.entries.append(entry)
            return entry

    def checkpoint(self) -> Dict[str, Any]:
        with self._lock:
            payload = {
                "schema_version": "owp-soc/ledger-checkpoint/0.1",
                "length": len(self.entries),
                "head_hash": self.entries[-1].entry_hash if self.entries else GENESIS,
                "merkle_root": merkle_root([e.entry_hash for e in self.entries]),
                "issued_at": self.clock.iso(),
            }
            cp = {"payload": payload, "signatures": [self.signer.sign_payload(payload)]}
            if self.witness is not None:
                self.witness.publish(cp)
            return cp

    def verify_chain(self) -> List[str]:
        """Return a list of problems (empty if the local chain is self-consistent)."""
        problems: List[str] = []
        prev = GENESIS
        for i, e in enumerate(self.entries):
            if e.index != i:
                problems.append(f"index mismatch at {i}")
            if e.prev_hash != prev:
                problems.append(f"prev_hash mismatch at {i}")
            if e.compute_hash() != e.entry_hash:
                problems.append(f"entry_hash mismatch at {i}")
            prev = e.entry_hash
        return problems

    def verify_against_witness(self, trusted: TrustedKeys) -> List[str]:
        """Compare local state with witnessed checkpoints (tamper / truncation / fork)."""
        problems: List[str] = []
        if self.witness is None:
            return ["no external witness configured"]
        cps = self.witness.checkpoints()
        if not cps:
            return ["no witnessed checkpoint; integrity relative to external anchor is UNKNOWN"]
        for cp in cps:
            payload = cp["payload"]
            if not any(trusted.verify(payload, s, expected_role="ledger") for s in cp["signatures"]):
                problems.append("checkpoint signature invalid")
                continue
            n = payload["length"]
            if n > len(self.entries):
                problems.append(f"ledger truncated: witnessed length {n} > local {len(self.entries)}")
                continue
            prefix = self.entries[:n]
            if merkle_root([e.entry_hash for e in prefix]) != payload["merkle_root"]:
                problems.append(f"merkle root mismatch for witnessed prefix of length {n} (tamper or fork)")
            if prefix and prefix[-1].entry_hash != payload["head_hash"]:
                problems.append(f"head hash mismatch at witnessed length {n}")
        return problems

    def entries_for_case(self, case_id: str) -> List[LedgerEntry]:
        return [e for e in self.entries if e.case_id == case_id]

    def export(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps([e.to_dict() for e in self.entries], indent=2, sort_keys=True))


class EncryptedEvidenceStore:
    """Sensitive originals, encrypted at rest and addressable by content digest.

    Deleting an item removes the plaintext commitment target, but the ledger
    digest (and therefore the chain) stays verifiable.
    """

    def __init__(self, key: Optional[bytes] = None) -> None:
        self._key = key or AESGCM.generate_key(bit_length=256)
        self._aead = AESGCM(self._key)
        self._items: Dict[str, bytes] = {}
        self.access_log: List[Dict[str, str]] = []

    def put(self, obj: Dict[str, Any]) -> str:
        data = canonical_bytes(obj)
        d = "sha256:" + sha256_hex(data)
        nonce = os.urandom(12)
        self._items[d] = nonce + self._aead.encrypt(nonce, data, d.encode())
        return d

    def get(self, d: str, accessor: str, purpose: str) -> Optional[Dict[str, Any]]:
        self.access_log.append({"digest": d, "accessor": accessor, "purpose": purpose})
        blob = self._items.get(d)
        if blob is None:
            return None
        plain = self._aead.decrypt(blob[:12], blob[12:], d.encode())
        return json.loads(plain.decode("utf-8"))

    def delete(self, d: str) -> bool:
        return self._items.pop(d, None) is not None

    def __contains__(self, d: str) -> bool:
        return d in self._items
