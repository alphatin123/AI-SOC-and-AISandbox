# AI-SOC-and-AISandbox

Reference implementation of the architecture in
**《AI 安全與道德治理：結合 dual_model、Agent 影響限制與 OpenWorkProof 的可驗證 AI SOC 架構》**
(design paper, v2.0, 2026-11-01 — included in this repository as `.docx`).

Three subsystems, bound together by a tamper-evident evidence chain:

| Subsystem | Package | Role |
|---|---|---|
| **AI-IDPS / dual_model** | `aisoc/idps/` | known-pattern branch + normality branch, multi-path case decision (paper Table III); signed model release gate from the training domain |
| **AI Agent sandbox** | `aisoc/sandbox/` | constrained read-only investigation agent, controlled egress proxy (record-then-forward, fail-closed), external policy (`allowed / reserved / denied`), human approval, signing service, Policy Enforcement Point |
| **OpenWorkProof-aligned evidence** | `aisoc/owp/` | `WorkOrder → CapabilityGrant → PolicyDecision → ActionReceipt → VerificationDecision → AcceptanceDecision`, hash-chained ledger, Merkle checkpoints, external witness, independent verifier |
| **Adapters** | `aisoc/adapters/` | [Slips](https://github.com/stratosphereips/StratosphereLinuxIPS) as the AI-IDPS (IDMEFv2 `alerts.json` + Zeek `conn.log` → external detector branches), [AiSOC](https://github.com/beenuar/AiSOC) as the SOC platform (alerts, approval inbox as the human step, HMAC bundles anchored into the ledger) |
| **Offline training domain (Architecture 1)** | `aisoc/capture/`, `aisoc/training/` | pyshark real-time / pcap capture → Zeek-style `conn.log` + signed capture manifest; Slips verdicts become labels; signed, write-once **dataset snapshot** (`dataset_curator` key) → validation/cleaning → known + normality branches → leave-one-family-out evaluation → signed release manifest (`model_release` key) with human approval recorded as pending until a person signs off |

The orchestrator is `aisoc/soc.py`. Design mapping and limitations are in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md); running against Slips and
AiSOC is described in [`docs/INTEGRATION.md`](docs/INTEGRATION.md).

**新手請先讀** [`docs/GUIDE.zh-TW.md`](docs/GUIDE.zh-TW.md)（繁體中文老師版指南：
核心概念、十三條準則對照程式碼與測試、逐步重現與預期輸出、「動手破壞它」練習、
程式碼閱讀路線）。程式碼中每個重要函數上方都有 `【老師註解】` 區塊；
`grep -rn "老師註解" aisoc/` 可列出全部。

## Quick start

```bash
pip install -r requirements.txt
python -m pytest -q                                   # 192 tests
python -m aisoc simulate --out demo-output/aisoc-run  # train, run SOC, scenarios, ablations
python -m aisoc verify demo-output/aisoc-run          # offline re-verification of the exported run

# Slips output through the same pipeline (fixture; see docs/INTEGRATION.md for a real capture)
python -m aisoc slips-ingest tests/fixtures/slips/alerts.json \
    --conn-log tests/fixtures/slips/conn.log --out demo-output/slips-run
python -m aisoc verify demo-output/slips-run
python -m aisoc aisoc-push demo-output/slips-run --dry-run          # events that would go to AiSOC
python -m aisoc aisoc-bundle-verify tests/fixtures/aisoc/investigation-bundle.json --hmac-key test-key
```

### Architecture 1: offline training domain

Capture → Slips → signed dataset snapshot → offline training → signed release →
inference. Every hand-over is verified by hash + role-bound signature, never by
file name or path (details in [`docs/INTEGRATION.md`](docs/INTEGRATION.md) §1.5,
beginner walk-through in [`docs/GUIDE.zh-TW.md`](docs/GUIDE.zh-TW.md) §13):

```bash
pip install -e '.[capture]'                       # pyshark; live capture also needs tshark + CAP_NET_RAW
python -m aisoc capture --interface eth0 --duration 60 --out sensor-output/pyshark-conn.log
#   (or: python -m aisoc capture --pcap your.pcap --out sensor-output/pyshark-conn.log)
#   run Slips on the same traffic -> sensor-output/alerts/alerts.json (docs/INTEGRATION.md §1.1 / live sensor)
python -m aisoc dataset-snapshot --conn-log sensor-output/pyshark-conn.log \
    --alerts sensor-output/alerts/alerts.json --capture-manifest sensor-output/capture-manifest.json \
    --out demo-output/dataset-snapshot                          # signed, write-once dataset copy
python -m aisoc train-offline demo-output/dataset-snapshot --out demo-output/training-run
python -m aisoc slips-ingest sensor-output/alerts/alerts.json --conn-log sensor-output/pyshark-conn.log \
    --release-dir demo-output/training-run --internal-normality --out demo-output/slips-run-trained
python -m aisoc verify demo-output/slips-run-trained
python -m aisoc dashboard demo-output/slips-run-trained --training-dir demo-output/training-run
```

`train-offline` refuses a snapshot whose `flows.jsonl` no longer matches the
signed manifest; `slips-ingest --release-dir` refuses a `model.bin` whose hash
does not match the signed release manifest. Labels come only from Slips, so
`benign` means *not flagged by Slips*; the known branch is trained on real Slips
families and stops with an error (instead of silently using synthetic data)
when none has enough samples unless `--allow-synthetic-known` is given, in which
case the fallback is flagged in `model_version`, the manifest and the dashboard.
`approved_by` stays `pending-human-gate` until a person re-issues the release
with `--approved-by`.

## Optional Local Qwen Investigation Agent

The default `--agent stub` remains deterministic and requires no model server.
To test a locally hosted Qwen model, first install and start your own
OpenAI-compatible vLLM service. This repository does not download model weights
or install GPU runtimes. Choose a model that the installed vLLM version can
serve with chat-completions function calling; its exact model ID is deployment
specific, so use the service's configured served name rather than assuming a
particular Qwen checkpoint exists.

```bash
export AISOC_LLM_BASE_URL=http://127.0.0.1:8000/v1
export AISOC_LLM_MODEL=qwen-agent
export AISOC_LLM_API_KEY=local-vllm
python -m aisoc simulate --agent qwen --max-cases 1 --out /tmp/aisoc-qwen-run
python -m aisoc verify /tmp/aisoc-qwen-run
```

Use the same `--agent qwen` option with `slips-ingest` to investigate cases
created from Slips evidence. The client accepts loopback HTTP(S) endpoints only,
uses Python's standard library, makes no model download, and limits tool rounds
and calls. Only tenant-scoped read-only tools are exposed. The model's JSON
report is validated and its action proposals are reconstructed against the
frozen work order; existing policy, human approval, signer, PEP and ledger remain
in force. Qwen output is not calibrated detection evidence and does not replace
the IDPS verdict. If inference, tool calling, or JSON validation fails, the
agent returns `undetermined` and proposes no action; it does not silently fall
back to the stub. An installed model must support the OpenAI chat-completions
tool-call format or these safe-failure results will occur.

`--agent stub` remains the default for tests, scenarios and reproducible
reference runs. Select Qwen explicitly only for a local inference smoke test.

`simulate` writes `report.md` / `report.json` plus the exported `ledger.json`,
`witness-checkpoints.json`, `tool-side-receipts.json`, `trusted-keys.json`,
`cases.json` and `model-card.json`. `verify` recomputes the hash chain, checks
witnessed Merkle roots against the ledger signer's public key, validates every
executor-signed receipt, flags any execution that has no recorded
authorization and any agent request that did not pass through the audited
egress channel.

## Local Dashboard

Install the local package, then open an exported run in the English
dashboard. Exported evidence remains read-only:

```bash
python -m pip install -e .
python -m aisoc dashboard /absolute/path/to/exported-run --port 8765
```

Open http://127.0.0.1:8765. From the repository root, the default command
`python -m aisoc dashboard` reads `demo-output/aisoc-run`. Select a different
port if 8765 is already in use.

The dashboard provides searchable cases, review flags, case details, ledger and
receipt inspection, independent export verification, and redacted JSON downloads.
It refreshes exported data every 30 seconds. The optional Network IDPS view
polls configured sensor files every two seconds; it does not capture packets or
provide an approval service. IP addresses are masked, no private keys are served, and
the UI cannot approve requests or change firewall rules. Historical case
verification is distinct from the current integrity check of the export.

The layout follows Architecture 1 of the paper. The sidebar is split into an
**Offline Training Domain** group (Training Domain) and an **Inference Domain**
group (Network IDPS, Detection Cases, Human Review, Evidence Ledger, Action Records).
A six-step pipeline strip at the top of the Overview — Capture → Slips IPS →
Dataset snapshot → Training domain → Release gate → Inference → ledger — shows
per-stage counts and status, and a provenance line states whether the model
hash recorded in the export's ledger equals the hash in the attached
training-domain release. Without a training run attached the strip's first
stages are simply off and the model release is shown as a recorded claim; the
dashboard never fabricates provenance it cannot read.

The server binds only to loopback. Keep any Codespaces port forwarding private;
do not expose this unauthenticated analyst view publicly. The local icon bundle
is Lucide 0.468.0; typography uses Google Fonts with a local fallback.

### Training Domain View

Attach a `train-offline` output directory to see the offline pipeline:

```bash
python -m aisoc dashboard demo-output/slips-run-trained \
  --training-dir demo-output/training-run --port 8765
```

The view reads `training-report.json` (plus the presence of
`release-manifest.json` and `model.bin`) and renders the six Architecture-1
stages — data collection and labeling, validation and cleaning, known + anomaly
models, adversarial and robustness evaluation, model registration and signing,
release gate — with the dataset snapshot's verification status, label sources
(`slips_uid`, `slips_host_time`, `slips_anomaly_only`, `slips_silence`), cleaning
counts, model thresholds, leave-one-family-out recall, false positives per day,
and the release-gate self-checks with human approval shown as `pending` until
`approved_by` names a person. The case drawer additionally shows the
standardized dual_model output (`known` / `anomaly` / `verdict` / `models`)
for each ingested case. Without `--training-dir` the view reports
`NOT_CONFIGURED`; a directory without a report reports `WAITING`; symlinks and
unreadable reports report `ERROR`. Sensor hosts listed in the report are masked
unless `--show-ips` is given. `/api/training` is read-only and ignores any
directory supplied by the client.

### Model Conflict Review

Open a `MODEL_CONFLICT` case, then use **True Positive** or **False Positive**
under **Actions and Authorization → Human Review**. The selected verdict and
save time appear immediately and remain available after reloading the dashboard.
You can change a classification; the previous decision remains in the history.

Reviews are stored in `.dashboard-reviews.sqlite3` inside the selected run
directory, not in the original cases, signed ledger, or receipts. The directory
must be writable to save reviews. Decisions are bound to the exact case digest;
if a case changes, a stale submission is rejected and an old review is not
presented as its current classification. The detector status stays
`MODEL_CONFLICT`; classification does not approve any action, retrain a model,
or trigger firewall blocking.

The local endpoint checks Host, Origin, a per-server review token, case
eligibility, and a bounded JSON body. These are request protections, not analyst
authentication: reviews identify only a `local-analyst` session and are not
digitally signed human approvals. Keep the port private and use an authenticated
review service for multi-user or production attribution. Back up the review
database separately from exported evidence; it is excluded from Git.

### Network IDPS Monitoring

Run Slips/Zeek on a host that can observe the authorized network traffic, as
described in [the integration guide](docs/INTEGRATION.md). Point the dashboard
at the actively written files and select **Network IDPS**:

```bash
python -m aisoc dashboard /absolute/path/to/exported-run \
  --conn-log /absolute/path/to/slips-run/zeek_files/conn.log \
  --alerts /absolute/path/to/slips-run/alerts.json \
  --show-ips \
  --port 8765
```

Either sensor option can be omitted. Without either, the view reports
`NOT_CONFIGURED`; missing files report `WAITING`. `FRESH` means a configured file
was modified within 30 seconds, not that packet capture is confirmed healthy;
older files report `STALE`, and unreadable files report `ERROR`. Per-source
health is shown separately. Codespaces cannot observe your LAN merely by
running this dashboard: use a local monitoring host or securely deliver its logs.

The view provides recent connections and alerts, a 60-second activity chart,
protocol filtering, search, manual refresh, and pause/resume. IPs are masked by
default; `--show-ips` explicitly reveals sensor IPs to this loopback dashboard.
Keep port forwarding private. In Overview and Detection Cases, **Observed
Traffic** shows the newest up to 1,000 Zeek connection records from the bounded
log tail, with separate source/destination IP and port columns. Its Case
Verification field is `NOT_INGESTED`: raw Zeek flows are not signed SOC cases,
are not written into the ledger, and cannot trigger investigation, review, or
firewall actions. Ingest corresponding Slips alerts with `slips-ingest` to
create cases that the offline verifier can check. The Observed Traffic view is
not a durable archive of all captured traffic.

The monitor reopens each file on every poll to handle rotation, reads a bounded
2 MiB tail plus Zeek headers, and ignores incomplete final lines. Counts cover
that bounded buffer, not the complete capture; high traffic can exceed the
buffer. Zeek JSON-lines and standard TSV are supported.

The chart uses the connection timestamps reported by Zeek, not packet arrival
times; connections may be logged only after completion. Reported bytes are flow
totals for recent connection timestamps, not instantaneous link throughput.
Slips alerts are sensor claims, not independently verified SOC case verdicts.
This monitor does not create cases, approve actions, or trigger firewall blocks.

## What the security scenarios demonstrate

All are run by `simulate` and by `tests/test_end_to_end.py`:

* an agent **fully controlled by prompt injection** proposes exfiltration,
  cross-tenant blocking, audit shutdown and policy change — zero are executed;
* replay of a valid single-use authorization, expired or revoked envelopes, and
  parameter changes after approval are rejected at the PEP;
* ledger modification / truncation after an external checkpoint is detected;
* an execution that **bypasses the ledger** is detected by reconciling the
  tool-side receipt log;
* Slips `Description` text used as prompt injection is flagged and never acted
  on; anomaly-only / weak-indicator-only Slips windows end in mandatory human
  review instead of agent action;
* the AiSOC approval inbox stands in for the human step: approve, deny,
  undecided (timeout) and a mismatched record all yield a *signed* outcome,
  and a one-byte change in an AiSOC evidence bundle is caught by both the
  HMAC re-derivation and the ledger digest;
* the sandbox egress proxy fails closed when the audit domain is down, and a
  model that does not match its signed release manifest is never loaded;
* ablations: removing the nonce re-enables replay; removing the PEP approval
  check still yields zero executions because the signer also refuses; removing
  the witness yields `UNKNOWN` / `DEFERRED`, never `ACCEPTED`; making the
  egress proxy fail open lets requests out, but the verifier then reports
  `FAILED` because they have no egress record.

## Honest scope

Following the paper's research-integrity statement:

* **The bundled model is trained on synthetic data and all agents are
  deterministic stubs.** Detection figures in `report.json` describe this code
  on generated traffic. They are not results on CIC-IDS, UNSW-NB15 or any real
  network, and are not comparable to published IDS numbers. With Slips as the
  detector, detection quality is Slips'; this project adds the decision
  policy, sandbox and evidence chain, not a better classifier.
* Keys live in memory (an HSM *interface*, not hardware); all five trust
  domains run in one process. The paper's guarantees require separately
  administered domains, which code alone cannot establish.
* The injection screen is heuristic and is **not** the security boundary; the
  boundary is that agent output is a structured request that must pass the
  egress proxy, external policy, human reservation and the PEP.
* The AiSOC adapters are tested against a fake server built from the AiSOC
  OpenAPI description, not against a live deployment.
* In the offline training domain, **labels come only from Slips**: `benign`
  means *not flagged by Slips*, not human-verified clean traffic, so anything
  Slips misses becomes part of the normality baseline (a poisoning surface that
  is recorded, not detected). The pyshark `FlowAssembler` is a simplified
  Zeek-style connection state machine, not Zeek; `login_failures` is always 0
  because a connection log cannot see authentication results; `--slips-blocking`
  records an operator claim that is not verified. Curator and release public keys
  that ship next to the artefacts are accepted only with a printed warning —
  hand them over out-of-band (`--trust`, `--release-trust`) for real use.
* No zero-day immunity, no unconditional containment, no certification is
  claimed.

## Earlier material

`working-demo/`, `working-demo-signed/`, `surface-bundle-demo/` and the
`*-demo*.py` scripts are earlier Surface-Bundle / environment-fingerprint
experiments that expect an upstream `OpenWorkProof/` checkout (currently empty
here). They are kept for reference and are independent of `aisoc/`.

## License

See [LICENSE](LICENSE).