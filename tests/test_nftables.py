"""Firewall integration tests without privileges or host firewall changes."""

import subprocess
from unittest.mock import patch

import pytest

from aisoc.crypto import Clock, Ed25519Signer, TrustedKeys
from aisoc.owp import ActionRequest, Signed
from aisoc.sandbox import PolicyEnforcementPoint, ToolSideLog
from aisoc.sandbox.nftables import NftablesConfig, NftablesExecutor


@pytest.fixture
def firewall():
    clock = Clock()
    config = NftablesConfig(
        targets={("tenant-a", "host:attacker"): "203.0.113.8"},
        protected_cidrs=("192.168.8.10/24",), enabled=True,
    )
    executor = NftablesExecutor(Ed25519Signer("executor"), clock, config)
    request = ActionRequest(
        request_id="req-firewall", case_id="case-firewall", tenant="tenant-a",
        action="block_host", resource="host:attacker", destination=None,
        params={"ttl_s": 60}, evidence_ids=["evidence-1"],
        idempotency_key="firewall-1", requested_at=clock.iso(),
    )
    return executor, request


def envelope(request):
    return {"request_digest": request.digest(), "approval_digest": "approved"}


def test_block_uses_bounded_command_without_shell(firewall):
    executor, request = firewall
    with patch("aisoc.sandbox.nftables.subprocess.run") as run:
        result = executor.run(request, envelope(request), True)
    assert result == {"blocked": "host:attacker", "ip": "203.0.113.8", "ttl_s": 60, "backend": "nftables"}
    run.assert_called_once_with(
        ["/usr/sbin/nft", "add", "element", "inet", "aisoc_guard", "blocked_v4",
         "{", "203.0.113.8", "timeout", "60s", "}"],
        check=True, capture_output=True, text=True, timeout=5,
    )


@pytest.mark.parametrize("address", ["192.168.8.1", "192.168.8.10", "192.168.8.254", "127.0.0.1", "::1", "fe80::1", "224.0.0.1", "0.0.0.0", "255.255.255.255", "::ffff:192.168.8.10"])
def test_protected_addresses_never_reach_nft(firewall, address):
    executor, request = firewall
    executor = NftablesExecutor(executor.signer, executor.clock, NftablesConfig(
        targets={(request.tenant, request.resource): address},
        protected_cidrs=("192.168.8.10/24",), enabled=True,
    ))
    assert executor.config.protected_cidrs == ("192.168.8.0/24",)
    with patch("aisoc.sandbox.nftables.subprocess.run") as run, pytest.raises(ValueError):
        executor.run(request, envelope(request), True)
    run.assert_not_called()


@pytest.mark.parametrize("ttl", [0, -1, 901, True, "60", 1.5, None])
def test_invalid_ttl_never_reaches_nft(firewall, ttl):
    executor, request = firewall
    request.params["ttl_s"] = ttl
    with patch("aisoc.sandbox.nftables.subprocess.run") as run, pytest.raises(ValueError):
        executor.run(request, envelope(request), True)
    run.assert_not_called()


def test_ipv6_uses_separate_set(firewall):
    executor, request = firewall
    executor = NftablesExecutor(executor.signer, executor.clock, NftablesConfig(
        targets={(request.tenant, request.resource): "2001:db8::8"},
        protected_cidrs=("192.168.8.0/24",), enabled=True,
    ))
    with patch("aisoc.sandbox.nftables.subprocess.run") as run:
        executor.run(request, envelope(request), True)
    assert "blocked_v6" in run.call_args.args[0]
    assert "2001:db8::8" in run.call_args.args[0]


def test_disabled_and_missing_approval_and_wrong_tenant_fail_closed(firewall):
    executor, request = firewall
    disabled = NftablesExecutor(executor.signer, executor.clock, NftablesConfig(
        targets=executor.config.targets, protected_cidrs=executor.config.protected_cidrs,
    ))
    with patch("aisoc.sandbox.nftables.subprocess.run") as run:
        with pytest.raises(ValueError, match="disabled"):
            disabled.run(request, envelope(request), True)
        with pytest.raises(ValueError, match="approval"):
            executor.run(request, {}, True)
        request.tenant = "tenant-b"
        with pytest.raises(ValueError, match="map"):
            executor.run(request, envelope(request), True)
    run.assert_not_called()


def test_rate_limit(firewall):
    executor, request = firewall
    with patch("aisoc.sandbox.nftables.subprocess.run") as run, patch("aisoc.sandbox.nftables.time.monotonic", return_value=100):
        for attempt in range(10):
            executor.run(request, envelope(request), True)
        with pytest.raises(ValueError, match="rate limit"):
            executor.run(request, envelope(request), True)
    assert run.call_count == 10


def test_pep_rejects_unsigned_request_before_firewall(firewall):
    executor, request = firewall
    pep = PolicyEnforcementPoint(TrustedKeys(), executor, ToolSideLog(), executor.clock)
    with patch("aisoc.sandbox.nftables.subprocess.run") as run:
        result = pep.execute(request, Signed(payload=envelope(request), signatures=[]))
    assert not result.executed
    assert result.receipt.payload["outcome"] == "rejected"
    run.assert_not_called()


def test_firewall_failure_propagates(firewall):
    executor, request = firewall
    with patch("aisoc.sandbox.nftables.subprocess.run", side_effect=subprocess.CalledProcessError(1, "nft")):
        with pytest.raises(subprocess.CalledProcessError):
            executor.run(request, envelope(request), True)


def test_frozen_clock_never_reaches_firewall(firewall):
    executor, request = firewall
    executor.clock.advance(0)
    with patch("aisoc.sandbox.nftables.subprocess.run") as run, pytest.raises(ValueError, match="real-time"):
        executor.run(request, envelope(request), True)
    run.assert_not_called()


@pytest.mark.parametrize("enabled", ["false", 1, None])
def test_enabled_requires_boolean(enabled):
    with pytest.raises(ValueError, match="boolean"):
        NftablesConfig(targets={}, protected_cidrs=("192.168.8.0/24",), enabled=enabled)


@pytest.mark.parametrize("endpoint, token", [("http://soc.example.org", "test-token"), ("https://soc.example.org", "")])
def test_cli_refuses_insecure_or_unauthenticated_approval(tmp_path, monkeypatch, capsys, endpoint, token):
    import json
    from aisoc.cli import main

    config = tmp_path / "firewall.json"
    config.write_text(json.dumps({
        "enabled": True, "protected_cidrs": ["192.168.8.10/24"], "targets": [],
    }))
    monkeypatch.setenv("AISOC_TOKEN", token)
    with patch("aisoc.cli._train") as train, patch("aisoc.sandbox.nftables.subprocess.run") as run:
        result = main(["slips-ingest", "missing-alerts.json", "--nftables-config", str(config),
                       "--approval-base-url", endpoint])
    assert result == 1
    assert "configuration refused" in capsys.readouterr().err
    train.assert_not_called()
    run.assert_not_called()