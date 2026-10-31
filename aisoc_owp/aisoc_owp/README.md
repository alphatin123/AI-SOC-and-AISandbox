# aisoc_owp — AI SOC zero-day triage with sandboxed agent + OpenWorkProof-style signing

Reference implementation of the architecture diagram "最低權限版雙模型架構".
Assume-breach: the agent runs in the sandbox with no keys, no data, no network; everything
it wants done is a *signed, scoped, single-use, expiring* decision that an outside executor
re-verifies, and reserved actions (quarantine, egress) also need a human Acceptor signature.

    python -m aisoc                      # demo: normal flow + escaped-agent attack suite
    python -m unittest discover -s tests # 25 tests

Needs Python 3.12 and `cryptography`. Nothing else.

## Diagram box -> code

| Diagram | File |
|---|---|
| 入口網關 / 受控出口代理 (log-before-forward, fail-closed, rate limit) | `egress_proxy.py` |
| 只讀模型 + 模型發布閘門 (signed manifest, hash check) | `detect.py` (`release_model`, `load_verified_model`) |
| 特徵提取 / 已知攻擊推理 / 異常檢測推理 / 判定 / 標準化輸出 | `detect.py`, `agent_runtime.py` |
| 隔離沙箱內只有一個 channel | `agent_runtime.py` (`SandboxChannel`) |
| Agent Sign 簽名服務 (key outside sandbox) | `signer_service.py`, `crypto.py` |
| 策略執行點 (allowed / reserved / denied) | `policy.py`, `executor.py` |
| 人工批准 + 顯示目的 IP | `human_gate.py` |
| OWP 帳本 / 審計日誌 (hash chain, anchor) | `hashchain.py` |
| 離線驗證 | `verifier.py` |
| 與真實 OpenWorkProof 對接 | `owp_adapter.py` |
| 組裝 | `wiring.py` |

## OpenWorkProof role mapping

| OWP role | here |
|---|---|
| Maintainer | creates `WorkOrder` (`wiring.build_world`) |
| Manager | `CapabilityGrant.attenuate` (grants only shrink) |
| Developer | `AgentRuntime` (asks; cannot act) |
| Sidecar | proxy + executor record execution facts |
| Verifier | NOT implemented as an independent re-runner. `verifier.py` is an offline bundle checker |
| Acceptor | `human_gate.Acceptor` (separate key, bound to one decision digest) |

## Switching to the real OpenWorkProof

`owp_adapter.py` wraps `policy.derive_authorization_context` / `policy.authorize_tool_call`
and `verify_acceptance_bundle`, using the signatures shown in the project's article.
Plug it in with `Executor(..., owp_hook=make_owp_hook(OWPBackend(), your_context_builder))`.
Building real WorkOrder/grant/receipt objects: copy from the repo at tag v1.4.0
(`examples/human_agency_profile_v01.py`, `tests/evidence-bundles/verify_evidence_bundle.py`).
Bind commitments through signed fields (`commitment_fields`), never the `metadata` envelope.

## What is tested vs. not

Tested (25 tests): forged / spoofed / tampered decisions, reserved action without human,
acceptance bound to one decision, replay (also after restart), expiry, out-of-scope and
malformed requests, revoked agent/key, rate limit, fail-closed when audit or ledger cannot
be written, model tamper at release gate, offline detection of edited / deleted entries,
rollback via external anchor, egress destination mismatch, evidence substitution.

NOT tested / known gaps:
- `OWPBackend` was never run (package not installable where this was built).
- Models are deterministic stand-ins, not trained models.
- Everything runs in one process. The "agent has no keys" check is a convention, not an
  isolation boundary. Real isolation = microVM (Firecracker/Kata) or gVisor + vsock, with
  signer, executor, audit log and ledger in separate trust domains.
- `canon.py` is deterministic JSON, not RFC 8785. Private keys are in memory, not an HSM.
- A coherently rebuilt history passes internal checks; store anchors outside the system.
- Time comes from one clock; signatures prove attribution and integrity, not that the
  detection was right. A compromised agent can still request actions inside its grant.
