# Architecture: AI-IDPS + Agent Sandbox + OpenWorkProof

This document maps the paper *AI 安全與道德治理：結合 dual_model、Agent 影響限制與
OpenWorkProof 的可驗證 AI SOC 架構* to the code in `aisoc/`. Section numbers
refer to the paper.

## 1. Separation of responsibilities (§I, §VI-C, §IX-A)

```
 telemetry ──► dual_model (idps/) ──► CaseDecision
                                          │  requires_agent_investigation
                                          ▼
                       WorkOrder (frozen task + evidence digest)
                       CapabilityGrant (tenant / actions / resources / ttl / uses)
                                          │
                                          ▼
             ┌───────────── inner execution domain A (can be lost) ─────────────┐
             │  InvestigationAgent ── read-only tools ── Untrusted[...] results  │
             │  output: InvestigationReport + ActionRequest(s)   (no authority)  │
             └──────────────────────────────┬───────────────────────────────────┘
                                            ▼
             ┌───────────── external service domain C ──────────────────────────┐
             │ PolicyEngine  → allowed | reserved | denied   (C_eff intersection) │
             │ HumanApprover → HumanApproval bound to request/evidence/params     │
             │ AuthorizationSigner → Ed25519 envelope (only after policy check)   │
             │ PolicyEnforcementPoint → sig, binding, expiry, revocation,         │
             │   approval, atomic nonce, idempotency → BoundedExecutor            │
             │   → ActionReceipt signed by *executor* key                         │
             └──────────────────────────────┬───────────────────────────────────┘
                                            ▼
             ┌───────────── independent audit domain B ─────────────────────────┐
             │ HashChainLedger (digests only) → Merkle checkpoint → ExternalWitness│
             │ EncryptedEvidenceStore (originals, separately keyed, deletable)    │
             │ Verifier: chain + witness + tool-side reconciliation               │
             │ AcceptanceDecision by a human                                       │
             └────────────────────────────────────────────────────────────────────┘
```

Five keys exist (`ledger`, `authorizer`, `executor`, `verifier`, `approver`).
`TrustedKeys.verify(..., expected_role=...)` means a key trusted for one role
cannot sign for another. In this reference implementation all five live in one
process; the paper's assumptions (§IV-B) require them to be in separately
administered domains with no reachable path from A to the private keys.

## 2. dual_model (§V–§VI) — `aisoc/idps/`

| Paper element | Code |
|---|---|
| shared, versioned features; scaler fit on train only | `features.py` (`FEATURE_SCHEMA_VERSION`, `StandardScaler`) |
| known branch f_k with calibrated score and reject option | `known_model.py` (OvR logistic regression, temperature scaling on validation, `tau_k`) |
| normality branch f_a on vetted normal windows, per-service-group τ_a | `normality_model.py` (Isolation Forest, quantile threshold on validation-normal) |
| Table III multi-path decision incl. conflict and insufficient-evidence branches; missing data ⇒ UNKNOWN | `dual_model.py` (`CaseStatus`, `DualModel.decide`) |
| leave-one-family-out, time-ordered split | `simulate.py` (`generate(held_out_family=...)`) |

Scores `c_k`, `s_a` and `τ_a` are stored separately on every `CaseDecision`.
Labels are consumed only in `DualModel.train`; the agent's verdicts are never
fed back as labels.

## 3. Agent sandbox (§VII, §VI-C) — `aisoc/sandbox/`

* `untrusted.py` – every log/tool output is wrapped in `Untrusted`; a heuristic
  injection screen adds flags that are shown to humans. **The screen is not a
  boundary.** The boundary is that agent output is a structured
  `ActionRequest` whose action must be in the `WorkOrder` vocabulary.
* `tools.py` – tenant-scoped read-only tools with a per-case budget and an
  independent `ToolSideLog` (second record used for reconciliation).
* `agent.py` – `HeuristicStubAgent` (decides from fields, never from free text)
  and `InjectionFollowingStubAgent` (deliberately obeys injected text, used to
  test L1). Agents cannot: modify policy, write training labels, disable audit,
  export raw telemetry (`FORBIDDEN_FOR_AGENT`).
* `policy.py` – `C_eff = C_task ∩ C_grant ∩ C_human ∩ C_runtime`. High impact
  and all outbound connections are `reserved`. Egress must give exact
  `ip:port`, scope (public/private is re-derived, not trusted) and TTL.
* `authorization.py` – `ApprovalView` shows supporting *and* missing evidence,
  injection flags, impact and reversibility (§IX-B). `AuthorizationSigner`
  refuses denied decisions and reserved decisions without a valid, bound
  approval. Envelope fields follow §VIII-B.
* `pep.py` – check order: signature → binding (request/params/destination
  digests) → expiry → revocation → approval presence → idempotency → atomic
  nonce → bounded execution with egress default-deny → executor-signed
  receipt. `PEPConfig` flags exist only for ablations.

## 4. OpenWorkProof alignment (§VIII) — `aisoc/owp/`

Object chain: `WorkOrder → CapabilityGrant → PolicyDecision → HumanApproval →
AuthorizationEnvelope → ActionReceipt → VerificationDecision →
AcceptanceDecision`. Schema strings are `owp-soc/<name>/0.1` and are this
project's SOC-extension proposals, not the upstream OWP schema.

* `canonical.py` – RFC 8785 subset; what gets signed is always canonical bytes.
* `ledger.py` – hash chain storing digests and references only; Merkle
  checkpoints signed by the ledger key and published to an `ExternalWitness`
  (append-only JSONL). Detects modification, truncation and forks relative to a
  witnessed checkpoint. `EncryptedEvidenceStore` keeps originals under a
  separate key with an access log, so retention/deletion does not break the
  chain (§IX-C).
* `verifier.py` – chain + witness + reconciliation: an executed tool receipt
  without a prior recorded authorization is a **bypass**; a ledger execution
  without a receipt is an inconsistency. No witness ⇒ `UNKNOWN`, never
  `VERIFIED`.

## 5. Scenarios and ablations (§XI-A) — `aisoc/scenarios.py`

| Scenario | Control exercised |
|---|---|
| injection drives a compromised agent | task scope, forbidden actions, tenant check, egress precision |
| cross-tenant target | policy tenant binding |
| replay | idempotency (same key) and single-use nonce / binding (new key) |
| expired / revoked | PEP expiry and revocation list |
| parameter change after approval | params_digest / request_digest binding |
| ledger tamper & truncation | hash chain + witnessed Merkle root |
| bypass | tool-side reconciliation |
| ablations | removing nonce ⇒ replay succeeds; removing PEP approval check ⇒ signer still refuses; removing witness ⇒ `UNKNOWN`/`DEFERRED` |

## 6. What this implementation does **not** show

* No real traffic, no public dataset, no LLM. Detection numbers in
  `report.json` are properties of synthetic generators.
* Keys are in memory; "HSM" is an interface, not hardware.
* One process; domain separation is organisational and must be verified by
  checking admin identities and reachable paths (§IV-B).
* The injection screen is heuristic; the NonceStore is single-replica.
* Nothing here is a formal proof, a certification or a zero-day guarantee.
