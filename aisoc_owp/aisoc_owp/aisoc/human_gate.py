"""Human gate: what the analyst sees, and the Acceptor signature that binds to ONE decision."""
import ipaddress

from .crypto import sign_payload


def classify_ip(ip: str) -> str:
    a = ipaddress.ip_address(ip)
    return "private" if (a.is_private or a.is_loopback or a.is_link_local) else "public"


def describe(signed: dict) -> str:
    """Request card shown to the analyst. Egress requests surface the target IP."""
    a = signed["args"]
    lines = [f"action      : {signed['action']}",
             f"agent       : {signed['agent_id']}",
             f"expires_at  : {signed['expires_at']}",
             f"evidence    : {signed['evidence_sha256'][:16]}..."]
    if signed["action"] == "egress_connect":
        lines.append(f"DESTINATION : {a['dst_ip']}:{a['dst_port']}/{a['proto']} "
                     f"({classify_ip(a['dst_ip'])} network)")
    else:
        lines.append(f"args        : {a}")
    return "\n".join(lines)


class Acceptor:
    """Independent key, held by the analyst (hardware token in production)."""
    ROLE = "acceptor"

    def __init__(self, keypair, analyst_id, clock):
        self.kp, self.analyst_id, self.clock = keypair, analyst_id, clock

    def decide(self, signed_decision: dict, verdict: str, note: str = "") -> dict:
        assert verdict in ("approve", "reject")
        return sign_payload(self.kp, {
            "type": "acceptance", "analyst": self.analyst_id, "verdict": verdict,
            "decision_digest": signed_decision["digest"],
            "work_order_id": signed_decision["work_order_id"],
            "action": signed_decision["action"],
            "args_digest": signed_decision["args_digest"],
            "evidence_sha256": signed_decision["evidence_sha256"],
            "decided_at": self.clock.now(), "expires_at": signed_decision["expires_at"],
            "note": note})
