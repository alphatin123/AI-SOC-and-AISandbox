"""Offline verifier. Inputs: ledger entries, public keyring, optional evidence store and anchor.
No network, no access to the running system. Returns a list of findings (empty = consistent).

Like OpenWorkProof, this proves binding and consistency, not that the judgment was right,
and it cannot detect a coherently re-minted history without an external anchor."""
from .canon import digest
from .crypto import verify_signed
from .hashchain import check_anchor, verify_entries


def verify_bundle(ledger_entries, keyring, evidence_store=None, anchor=None, revoked_at=None) -> list:
    f = list(verify_entries(ledger_entries))
    if anchor:
        f += check_anchor(ledger_entries, anchor)
    decisions, nonces, intents = {}, set(), {}
    revoked_at = revoked_at or {}
    for e in ledger_entries:
        p, ts = e["payload"], e["ts"]
        if p.get("type") == "decision_signed":
            s = p["signed"]
            ok, code = verify_signed(s, keyring, "agent_sign")
            if not ok:
                f.append(f"seq {e['seq']}: decision signature invalid ({code})")
                continue
            if s["signer_key_id"] in revoked_at and s["issued_at"] >= revoked_at[s["signer_key_id"]]:
                f.append(f"seq {e['seq']}: decision issued after key revocation")
            decisions[s["digest"]] = s
            if evidence_store is not None:
                ev = evidence_store.get(s["evidence_sha256"])
                if ev is None or digest(ev) != s["evidence_sha256"]:
                    f.append(f"seq {e['seq']}: evidence missing or altered for decision")
        elif p.get("type") == "exec_intent":
            d = decisions.get(p["decision_digest"])
            if d is None:
                f.append(f"seq {e['seq']}: execution without a verified signed decision")
                continue
            intents[d["digest"]] = d
            if p["nonce"] != d["nonce"] or p["nonce"] in nonces:
                f.append(f"seq {e['seq']}: nonce mismatch or reuse (replay)")
            nonces.add(p["nonce"])
            if not (d["issued_at"] <= ts <= d["expires_at"]):
                f.append(f"seq {e['seq']}: executed outside validity window")
            if digest(d["args"]) != d["args_digest"]:
                f.append(f"seq {e['seq']}: args do not match signed digest")
            if d["resolution"] == "denied":
                f.append(f"seq {e['seq']}: executed a denied action")
            if d["resolution"] == "reserved":
                a = p.get("acceptance")
                ok, code = verify_signed(a, keyring, "acceptor") if a else (False, "MISSING")
                if not ok:
                    f.append(f"seq {e['seq']}: reserved action without valid acceptance ({code})")
                elif (a["verdict"] != "approve" or a["decision_digest"] != d["digest"]
                      or a["args_digest"] != d["args_digest"] or ts > a["expires_at"]):
                    f.append(f"seq {e['seq']}: acceptance does not bind this decision")
        elif p.get("type") == "exec_result":
            d = intents.get(p["decision_digest"])
            if d is None:
                f.append(f"seq {e['seq']}: result without intent")
            elif d["action"] == "egress_connect":
                o, a = p["outcome"], d["args"]
                if (o.get("dst_ip"), o.get("dst_port"), o.get("proto")) != (a["dst_ip"], a["dst_port"], a["proto"]):
                    f.append(f"seq {e['seq']}: egress opened to a destination not in the signed decision")
    return f
