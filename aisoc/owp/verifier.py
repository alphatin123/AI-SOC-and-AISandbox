"""Independent verifier: chain integrity, witness anchoring and tool-side reconciliation.

The verifier never trusts the ledger alone. Each executed tool receipt must be
preceded by a recorded authorization that binds the same request digest, and
every ledger execution record must be matched by a tool-side receipt. A
receipt without authorization is a *bypass*; an authorization without any
receipt is reported but is not by itself a failure (an action may legitimately
not have been executed).
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

from ..canonical import digest
from ..crypto import Clock, Ed25519Signer, TrustedKeys
from .ledger import HashChainLedger
from .objects import Signed, VerificationDecision, new_id


class Verifier:
    def __init__(self, signer: Ed25519Signer, trusted: TrustedKeys, clock: Clock) -> None:
        self.signer = signer
        self.trusted = trusted
        self.clock = clock

    def verify_case(
        self,
        case_id: str,
        ledger: HashChainLedger,
        tool_receipts: Iterable[Signed],
    ) -> Signed:
        findings: List[str] = []
        unknown = False

        chain_problems = ledger.verify_chain()
        findings.extend(f"chain: {p}" for p in chain_problems)

        witness_problems = ledger.verify_against_witness(self.trusted)
        for p in witness_problems:
            findings.append(f"witness: {p}")
            if "UNKNOWN" in p or "no external witness" in p:
                unknown = True

        entries = ledger.entries_for_case(case_id)
        auth_by_request: Dict[str, int] = {}
        exec_entries: Dict[str, int] = {}
        for e in entries:
            if e.entry_type == "authorization":
                auth_by_request[e.refs.get("request_digest", "")] = e.index
            elif e.entry_type == "action_receipt":
                exec_entries[e.object_digest] = e.index

        receipts = [r for r in tool_receipts if r.payload.get("case_id") == case_id]
        for r in receipts:
            p = r.payload
            if not any(self.trusted.verify(p, s, expected_role="executor") for s in r.signatures):
                findings.append(f"receipt {p.get('receipt_id')}: executor signature invalid")
                continue
            if p.get("outcome") != "executed":
                continue
            rd = p.get("request_digest", "")
            d = digest(p)
            if d not in exec_entries:
                findings.append(f"receipt {p['receipt_id']}: executed on tool side but NOT recorded in ledger (bypass)")
                continue
            if rd not in auth_by_request:
                findings.append(f"receipt {p['receipt_id']}: executed without any recorded authorization (bypass)")
            elif auth_by_request[rd] > exec_entries[d]:
                findings.append(f"receipt {p['receipt_id']}: authorization recorded after execution")

        receipt_digests = {digest(r.payload) for r in receipts}
        for d, idx in exec_entries.items():
            if d not in receipt_digests:
                findings.append(f"ledger entry {idx}: execution recorded but no matching tool-side receipt")

        if findings and not (unknown and all(f.startswith("witness:") for f in findings)):
            status = "FAILED"
        elif unknown:
            status = "UNKNOWN"
        else:
            status = "VERIFIED"

        vd = VerificationDecision(
            verification_id=new_id("vd"),
            case_id=case_id,
            status=status,
            findings=findings,
            checked_entries=len(entries),
            verified_at=self.clock.iso(),
            verifier_identity=self.signer.key_id,
        )
        payload = vd.to_dict()
        return Signed(payload=payload, signatures=[self.signer.sign_payload(payload)])
