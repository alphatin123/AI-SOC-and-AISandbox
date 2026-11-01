# AI-SOC-and-AISandbox

Reference implementation of the architecture in
**《AI 安全與道德治理：結合 dual_model、Agent 影響限制與 OpenWorkProof 的可驗證 AI SOC 架構》**
(design paper, v2.0, 2026-11-01 — included in this repository as `.docx`).

Three subsystems, bound together by a tamper-evident evidence chain:

| Subsystem | Package | Role |
|---|---|---|
| **AI-IDPS / dual_model** | `aisoc/idps/` | known-pattern branch + normality branch, multi-path case decision (paper Table III) |
| **AI Agent sandbox** | `aisoc/sandbox/` | constrained read-only investigation agent, external policy (`allowed / reserved / denied`), human approval, signing service, Policy Enforcement Point |
| **OpenWorkProof-aligned evidence** | `aisoc/owp/` | `WorkOrder → CapabilityGrant → PolicyDecision → ActionReceipt → VerificationDecision → AcceptanceDecision`, hash-chained ledger, Merkle checkpoints, external witness, independent verifier |

The orchestrator is `aisoc/soc.py`. Design mapping and limitations are in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Quick start

```bash
pip install -r requirements.txt
python -m pytest -q                                   # 41 tests
python -m aisoc simulate --out demo-output/aisoc-run  # train, run SOC, scenarios, ablations
python -m aisoc verify demo-output/aisoc-run          # offline re-verification of the exported run
```

`simulate` writes `report.md` / `report.json` plus the exported `ledger.json`,
`witness-checkpoints.json`, `tool-side-receipts.json`, `trusted-keys.json`,
`cases.json` and `model-card.json`. `verify` recomputes the hash chain, checks
witnessed Merkle roots against the ledger signer's public key, validates every
executor-signed receipt and flags any execution that has no recorded
authorization.

## What the security scenarios demonstrate

All are run by `simulate` and by `tests/test_end_to_end.py`:

* an agent **fully controlled by prompt injection** proposes exfiltration,
  cross-tenant blocking, audit shutdown and policy change — zero are executed;
* replay of a valid single-use authorization, expired or revoked envelopes, and
  parameter changes after approval are rejected at the PEP;
* ledger modification / truncation after an external checkpoint is detected;
* an execution that **bypasses the ledger** is detected by reconciling the
  tool-side receipt log;
* ablations: removing the nonce re-enables replay; removing the PEP approval
  check still yields zero executions because the signer also refuses; removing
  the witness yields `UNKNOWN` / `DEFERRED`, never `ACCEPTED`.

## Honest scope

Following the paper's research-integrity statement:

* **All data is synthetic and all agents are deterministic stubs.** Detection
  figures in `report.json` describe this code on generated traffic. They are
  not results on CIC-IDS, UNSW-NB15 or any real network, and are not comparable
  to published IDS numbers.
* Keys live in memory (an HSM *interface*, not hardware); all five trust
  domains run in one process. The paper's guarantees require separately
  administered domains, which code alone cannot establish.
* The injection screen is heuristic and is **not** the security boundary; the
  boundary is that agent output is a structured request that must pass external
  policy, human reservation and the PEP.
* No zero-day immunity, no unconditional containment, no certification is
  claimed.

## Earlier material

`working-demo/`, `working-demo-signed/`, `surface-bundle-demo/` and the
`*-demo*.py` scripts are earlier Surface-Bundle / environment-fingerprint
experiments that expect an upstream `OpenWorkProof/` checkout (currently empty
here). They are kept for reference and are independent of `aisoc/`.

## License

See [LICENSE](LICENSE).