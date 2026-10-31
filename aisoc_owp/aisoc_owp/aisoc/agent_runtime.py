"""Code that runs INSIDE the sandbox. It is handed exactly one capability: a channel.
No keys, no sockets, no training data, no write access to models. Everything it wants
done outside the sandbox it must ask for through the channel."""
import secrets

from .canon import digest
from .detect import (BaselineAnomalyModel, SignatureKnownModel, Thresholds, decide,
                     standardized_output)
from .policy import EGRESS_CONNECT, QUARANTINE_HOST


class SandboxChannel:
    def __init__(self, send):
        self._send = send

    def send(self, msg: dict) -> dict:
        return self._send(msg)


class AgentRuntime:
    def __init__(self, work_order_id, known_params, anomaly_params, manifests, channel, thresholds=None):
        self.work_order_id = work_order_id
        self._known, self._anomaly = SignatureKnownModel(known_params), BaselineAnomalyModel(anomaly_params)
        self._manifests, self._channel = manifests, channel
        self._th = thresholds or Thresholds()

    def process_window(self, features: dict, window_ref: str, host: str, ttl_s: int = 300) -> dict:
        known, anomaly = self._known.predict(features), self._anomaly.score(features)
        suspected = decide(known, anomaly, self._th)
        case_id = "ZD-" + digest({"w": window_ref, "h": host})[:10]
        out = standardized_output(case_id, window_ref, known, anomaly, suspected, self._th, self._manifests)
        self._channel.send({"type": "verdict", "case_id": case_id, "output": out})
        if not suspected:
            return {"suspected": False, "output": out}
        resp = self._channel.send(self._request(QUARANTINE_HOST, {"host": host}, digest(out), ttl_s))
        return {"suspected": True, "output": out, "decision": resp, "evidence_sha256": digest(out)}

    def request_egress(self, ip, port, proto, evidence_sha256, ttl_s=120) -> dict:
        return self._channel.send(self._request(
            EGRESS_CONNECT, {"dst_ip": ip, "dst_port": port, "proto": proto}, evidence_sha256, ttl_s))

    def _request(self, action, args, evidence_sha256, ttl_s) -> dict:
        return {"type": "decision_request", "request_id": secrets.token_hex(8),
                "agent_id": "ignored-overridden-by-proxy", "work_order_id": self.work_order_id,
                "action": action, "args": args, "evidence_sha256": evidence_sha256, "ttl_s": ttl_s}
