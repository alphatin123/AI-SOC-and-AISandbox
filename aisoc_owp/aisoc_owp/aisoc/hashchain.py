"""Append-only hash chain (JSON lines). Used twice: the gateway audit log (domain B)
and the decision ledger. Write failures raise AuditWriteError so callers fail closed."""
import json
import os
from pathlib import Path

from .canon import digest
from .crypto import sign_payload

GENESIS = "0" * 64


class AuditWriteError(RuntimeError):
    pass


def verify_entries(entries) -> list:
    problems, prev = [], GENESIS
    for i, e in enumerate(entries):
        try:
            body = {k: e[k] for k in ("seq", "ts", "prev_hash", "payload")}
        except KeyError as ex:
            problems.append(f"entry {i}: missing field {ex}")
            continue
        if e["seq"] != i:
            problems.append(f"entry {i}: seq gap or reorder")
        if e["prev_hash"] != prev:
            problems.append(f"entry {i}: prev_hash mismatch (chain broken)")
        if digest(body) != e.get("entry_hash"):
            problems.append(f"entry {i}: entry_hash mismatch (content altered)")
        prev = e.get("entry_hash")
    return problems


def load_file(path) -> list:
    return [json.loads(l) for l in Path(path).read_text("utf-8").splitlines() if l.strip()]


class HashChain:
    def __init__(self, path, clock):
        self.path, self.clock = Path(path), clock
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.entries = load_file(self.path) if self.path.exists() else []
        if not self.path.exists():
            self.path.touch()
        bad = verify_entries(self.entries)
        if bad:
            raise ValueError("existing chain invalid: " + bad[0])

    @property
    def head(self) -> str:
        return self.entries[-1]["entry_hash"] if self.entries else GENESIS

    def append(self, payload: dict) -> dict:
        body = {"seq": len(self.entries), "ts": self.clock.now(),
                "prev_hash": self.head, "payload": payload}
        entry = {**body, "entry_hash": digest(body)}
        self._write_line(json.dumps(entry, sort_keys=True, ensure_ascii=False))
        self.entries.append(entry)
        return entry

    def _write_line(self, line: str):
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
                os.fsync(f.fileno())
        except OSError as e:
            raise AuditWriteError(str(e)) from e


def make_anchor(chain: HashChain, kp_log, name: str, clock) -> dict:
    """Signed checkpoint to be stored OUTSIDE the system (rollback detection)."""
    return sign_payload(kp_log, {"type": "chain_anchor", "chain": name,
                                 "seq": len(chain.entries) - 1, "head": chain.head,
                                 "anchored_at": clock.now()})


def check_anchor(entries, anchor) -> list:
    seq = anchor["seq"]
    if seq >= len(entries):
        return [f"anchor seq {seq} beyond chain length: chain was truncated/rolled back"]
    if entries[seq]["entry_hash"] != anchor["head"]:
        return [f"anchor head does not match entry {seq}: history was rewritten"]
    return []
