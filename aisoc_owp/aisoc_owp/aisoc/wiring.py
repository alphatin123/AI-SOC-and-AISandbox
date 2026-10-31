"""Assembles the whole architecture in one process for demos and tests.
In production each box below is a separate process/VM/trust domain."""
from dataclasses import dataclass
from pathlib import Path

from .agent_runtime import AgentRuntime, SandboxChannel
from .canon import sha256_hex
from .clock import Clock
from .crypto import KeyPair, register
from .detect import load_verified_model, release_model
from .egress_proxy import ControlledEgressProxy
from .executor import Executor
from .hashchain import HashChain
from .human_gate import Acceptor
from .policy import (BLOCK_FLOW, EGRESS_CONNECT, QUARANTINE_HOST, READ_FEATURES, WRITE_VERDICT,
                     CapabilityGrant, HumanAgencyProfile, WorkOrder)
from .signer_service import AgentRegistry, AgentSignService

KNOWN = {"signatures": {"port_scan": {"syn_rate": 900, "dst_ports": 500, "bytes": 2000},
                        "dns_tunnel": {"syn_rate": 5, "dst_ports": 1, "bytes": 90000}},
         "scale": {"syn_rate": 100, "dst_ports": 20, "bytes": 20000}}
ANOMALY = {"mean": {"syn_rate": 20, "dst_ports": 4, "bytes": 5000},
           "std": {"syn_rate": 10, "dst_ports": 2, "bytes": 2000}}


@dataclass
class World:
    clock: Clock
    keyring: dict
    revoked: set
    audit: HashChain
    ledger: HashChain
    registry: AgentRegistry
    signer: AgentSignService
    proxy: ControlledEgressProxy
    executor: Executor
    acceptor: Acceptor
    runtime: AgentRuntime
    channel: SandboxChannel
    wo: WorkOrder
    kp_log: KeyPair

    def handle_pending(self, verdict="approve"):
        out = []
        while self.proxy.pending:
            s = self.proxy.pending.pop(0)
            acc = None if s["resolution"] == "allowed" else self.acceptor.decide(s, verdict)
            out.append((s, acc, self.executor.execute(s, acc)))
        return out


def build_world(base_dir, max_sign_per_minute=10, max_proxy_per_minute=30) -> World:
    base, clock = Path(base_dir), Clock(fixed=1_800_000_000)
    kp_sign, kp_acc, kp_rel, kp_log = KeyPair(), KeyPair(), KeyPair(), KeyPair()
    keyring: dict = {}
    for kp, role in ((kp_sign, "agent_sign"), (kp_acc, "acceptor"),
                     (kp_rel, "model_release"), (kp_log, "log_anchor")):
        register(keyring, kp, role)                     # public halves only
    revoked: set = set()

    root = CapabilityGrant("grant-root", frozenset(
        {READ_FEATURES, WRITE_VERDICT, QUARANTINE_HOST, BLOCK_FLOW, EGRESS_CONNECT}))
    grant = root.attenuate("grant-agent", {READ_FEATURES, WRITE_VERDICT, QUARANTINE_HOST, EGRESS_CONNECT})
    wo = WorkOrder("wo-001", "aisoc-zero-day-triage",
                   frozenset({READ_FEATURES, WRITE_VERDICT, QUARANTINE_HOST, EGRESS_CONNECT}), 600)
    profile = HumanAgencyProfile("hap-001", {
        READ_FEATURES: "delegated", WRITE_VERDICT: "delegated",
        QUARANTINE_HOST: "reserved", EGRESS_CONNECT: "reserved"})

    audit, ledger = HashChain(base / "audit.jsonl", clock), HashChain(base / "ledger.jsonl", clock)
    registry = AgentRegistry({"soc-agent-01"})
    signer = AgentSignService(kp_sign, registry, wo, grant, profile, ledger, clock, max_sign_per_minute)
    proxy = ControlledEgressProxy(audit, signer, "soc-agent-01", clock, max_per_minute=max_proxy_per_minute)

    handlers = {
        QUARANTINE_HOST: lambda a, ttl: {"quarantined": a["host"]},
        EGRESS_CONNECT: lambda a, ttl: {"rule": "pinhole", "dst_ip": a["dst_ip"],
                                        "dst_port": a["dst_port"], "proto": a["proto"], "ttl_s": ttl},
    }
    executor = Executor(keyring, revoked, wo, grant, profile, ledger, clock, handlers)

    # model release gate: training domain signs, sandbox only verifies and loads read-only
    ds = sha256_hex(b"training-dataset-v1")
    kb, km = release_model(KNOWN, kp_rel, "known", "1.0.0", ds)
    ab, am = release_model(ANOMALY, kp_rel, "anomaly", "1.0.0", ds)
    known_p, anomaly_p = load_verified_model(kb, km, keyring), load_verified_model(ab, am, keyring)

    channel = SandboxChannel(proxy.forward)
    runtime = AgentRuntime(wo.work_order_id, known_p, anomaly_p,
                           {"known": km, "anomaly": am}, channel)
    return World(clock, keyring, revoked, audit, ledger, registry, signer, proxy, executor,
                 Acceptor(kp_acc, "analyst-07", clock), runtime, channel, wo, kp_log)
