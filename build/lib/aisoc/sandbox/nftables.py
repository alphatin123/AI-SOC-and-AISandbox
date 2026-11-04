"""Opt-in Ubuntu host blocking through administrator-provisioned nftables sets."""

from __future__ import annotations

import ipaddress
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass
from types import MappingProxyType
from typing import Dict, Mapping, Tuple

from ..crypto import Clock, Ed25519Signer
from ..owp.objects import ActionRequest
from .agent import ACTION_ADD_WATCHLIST, ACTION_BLOCK_HOST, ACTION_TAG_CASE
from .pep import BoundedExecutor


@dataclass(frozen=True)
class NftablesConfig:
    targets: Mapping[Tuple[str, str], str]
    protected_cidrs: Tuple[str, ...]
    enabled: bool = False
    max_ttl_s: int = 900

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool:
            raise ValueError("enabled must be a boolean")
        if not self.protected_cidrs:
            raise ValueError("explicit management protection is required")
        if type(self.max_ttl_s) is not int or not 1 <= self.max_ttl_s <= 900:
            raise ValueError("max_ttl_s must be an integer between 1 and 900")
        protected = tuple(str(ipaddress.ip_network(cidr, strict=False)) for cidr in self.protected_cidrs)
        targets = {}
        for identity, address in self.targets.items():
            if not isinstance(identity, tuple) or len(identity) != 2 or not all(isinstance(part, str) and part for part in identity):
                raise ValueError("targets must be keyed by (tenant, resource)")
            targets[identity] = str(ipaddress.ip_address(address))
        object.__setattr__(self, "targets", MappingProxyType(targets))
        object.__setattr__(self, "protected_cidrs", protected)


class NftablesExecutor(BoundedExecutor):
    """Block only configured IPs; never resolve agent-supplied names or create rules."""

    def __init__(self, signer: Ed25519Signer, clock: Clock, config: NftablesConfig) -> None:
        super().__init__(signer, clock)
        self.config = config
        self._protected = tuple(ipaddress.ip_network(cidr) for cidr in config.protected_cidrs)
        self._block_lock = threading.Lock()
        self._attempts: deque[float] = deque()

    def run(self, request: ActionRequest, env: Dict, egress_default_deny: bool) -> Dict:
        if request.action in (ACTION_TAG_CASE, ACTION_ADD_WATCHLIST):
            return super().run(request, env, egress_default_deny)
        if request.action != ACTION_BLOCK_HOST:
            raise ValueError("nftables executor does not support this action")
        if not self.config.enabled:
            raise ValueError("live firewall blocking is disabled")
        if self.clock.frozen:
            raise ValueError("live blocking requires a real-time clock")
        if env.get("request_digest") != request.digest() or not env.get("approval_digest"):
            raise ValueError("blocking requires request-bound human approval")
        address = self.config.targets.get((request.tenant, request.resource))
        if address is None:
            raise ValueError("target is not in the administrator's tenant/resource map")
        target = ipaddress.ip_address(address)
        if target.is_loopback or target.is_link_local or target.is_multicast or target.is_unspecified:
            raise ValueError("special-use target is protected")
        if target == ipaddress.ip_address("255.255.255.255"):
            raise ValueError("broadcast target is protected")
        if isinstance(target, ipaddress.IPv6Address) and target.ipv4_mapped is not None:
            raise ValueError("IPv4-mapped IPv6 targets are not supported")
        if any(target in network for network in self._protected):
            raise ValueError("target belongs to a protected network")
        ttl_s = request.params.get("ttl_s")
        if type(ttl_s) is not int or not 1 <= ttl_s <= self.config.max_ttl_s:
            raise ValueError("blocking TTL exceeds the configured bound")
        set_name = "blocked_v4" if target.version == 4 else "blocked_v6"
        with self._block_lock:
            now = time.monotonic()
            while self._attempts and self._attempts[0] <= now - 60:
                self._attempts.popleft()
            if len(self._attempts) >= 10:
                raise ValueError("firewall block rate limit exceeded")
            self._attempts.append(now)
            subprocess.run(
                ["/usr/sbin/nft", "add", "element", "inet", "aisoc_guard", set_name,
                 "{", str(target), "timeout", f"{ttl_s}s", "}"],
                check=True, capture_output=True, text=True, timeout=5,
            )
        return {"blocked": request.resource, "ip": str(target), "ttl_s": ttl_s, "backend": "nftables"}