# Integration: Slips as the AI-IDPS, AiSOC as the SOC platform

`aisoc/` keeps its own dual_model, sandbox and OWP evidence chain. Two
adapters let it sit between real open-source components instead of only
synthetic data:

| Role in the paper | Component | How it is consumed | Code |
|---|---|---|---|
| **AI-IDPS** (known branch + anomaly branch) | [Slips](https://github.com/stratosphereips/StratosphereLinuxIPS) (Stratosphere Linux IPS, GPL-2.0) | **output files only** (`alerts.json` in IDMEFv2 + Zeek `conn.log`). Slips is not imported or linked; it runs in its own container. | `aisoc/adapters/slips.py` |
| **SOC platform** (alerting, analyst UI, approvals, investigation bundles) | [AiSOC](https://github.com/beenuar/AiSOC) (MIT) | HTTP API: alert submission, streaming ingest, approval workflow, bundle download | `aisoc/adapters/aisoc_stack.py` |

```
 pcap / interface ─► Slips (container) ─► output/alerts.json + zeek_files/conn.log
                                                   │  read-only
                                                   ▼
                              python -m aisoc slips-ingest  (SlipsAdapter → ExternalKnown / ExternalAnomaly)
                                                   │
                       dual_model.decide_external ─► CaseDecision ─► sandbox agent ─► PEP ─► OWP ledger
                                                   │                                   ▲
                 python -m aisoc aisoc-push ───────┘  alerts / events                   │ HumanApproval
                                                                                         │ (signed by SOC key)
                              AiSOC  ◄── POST /api/v1/approvals ── AiSOCApprovalBridge ─┘
                                 │
                                 └── investigation bundle (HMAC) ─► aisoc-bundle-verify / anchor_aisoc_bundle ─► ledger + witness
```

Nothing in the trust argument changes: the agent still cannot hold keys, the
PEP still verifies signature → binding → expiry → revocation → approval →
nonce, and the verifier is still offline. What changes is **where detections
and approvals come from**.

For opt-in Ubuntu host blocking after external human approval, see
[the Ubuntu deployment guide](UBUNTU_BLOCKING.zh-TW.md). The nftables backend
is disabled by default, uses explicit tenant/resource-to-IP mappings and
protected management networks, and does not make the reference implementation
production-ready by itself. Existing commands remain simulated unless
`slips-ingest --nftables-config` is explicitly supplied.

## 1. Slips → dual_model

### 1.1 Running Slips

```bash
mkdir -p dataset output
cp your-capture.pcap dataset/
docker compose -f deploy/docker-compose.slips.yml run --rm slips \
    ./slips.py -f dataset/your-capture.pcap -o output/
# or directly:
docker run --rm -v "$PWD/dataset:/StratosphereLinuxIPS/dataset" \
                -v "$PWD/output:/StratosphereLinuxIPS/output" \
                stratosphereips/slips ./slips.py -f dataset/your-capture.pcap -o output/
```

Slips writes `output/<run>/alerts.json` (one IDMEFv2 JSON object per line;
`Status: "Event"` for each evidence, `Status: "Incident"` for each alert that
accumulated enough threat level in a time window) and Zeek logs under
`output/<run>/zeek_files/`.

### 1.2 Ingesting into the SOC

#### Codespaces Live Sensor

Use the separate live configuration rather than the PCAP-replay configuration.
It runs Slips and its bundled Zeek with host networking, grants capture
capabilities only to that sensor container, and mounts only `sensor-output/`.
It does not mount SOC keys or enable the nftables executor. Run from this repo:

```bash
cd /workspaces/AI-SOC-and-AISandbox
docker compose -f deploy/docker-compose.slips-live.yml up -d
docker compose -f deploy/docker-compose.slips-live.yml logs --tail 40
find "$PWD/sensor-output" -type f \( -name conn.log -o -name alerts.json \)
```

The default capture interface is `lo`, for authorized localhost traffic such as
the dashboard and a bounded loopback ping. To select a different interface
visible to the Docker daemon, set `AISOC_CAPTURE_INTERFACE` when starting the
service. Host networking in Codespaces refers to the Codespace/Docker runtime,
not your laptop or LAN. Verify that generated traffic appears in Zeek logs;
do not infer capture success merely because the container is running.

The image is pinned to the tested digest of Slips 1.1.24 and includes Zeek.
Its live paths are `sensor-output/zeek_files/conn.log` and
`sensor-output/alerts/alerts.json`. The analysis Redis uses port 6387; Redis
binds to localhost and uses generated authentication. Capture excludes TCP
ports 6379 and 6387 to avoid reprocessing the sensor's own Redis control traffic.
The startup wrapper preserves the bundled YAML defaults and sets that filter
through `parameters.pcapfilter`, avoiding the pinned build's `-F` quoting bug.
No Slips web interface or Slips firewall blocking is enabled.

Once those files exist, start the dashboard using these concrete repo paths:

```bash
cd /workspaces/AI-SOC-and-AISandbox
python -m aisoc dashboard demo-output/aisoc-run \
  --conn-log sensor-output/zeek_files/conn.log \
  --alerts sensor-output/alerts/alerts.json \
  --show-ips \
  --port 8769
```

`--show-ips` is optional; addresses are masked by default. It reveals sensor IPs
in the local dashboard only, so keep Codespaces port forwarding private. The
Overview and Detection Cases views include a separate **Observed Traffic** tab
with the newest up to 1,000 connection records parsed from the bounded Zeek log
tail, including separate source/destination port columns. Case Verification is
`NOT_INGESTED` until related Slips evidence is ingested and a signed SOC case is
created. Raw flow observations are not detector verdicts or signed cases; they
are not added to the ledger, sent to the agent, or eligible for response
actions. This is not a durable copy of every packet or historical flow. The
sensor excludes its own Redis TCP control ports from capture.

Open `http://127.0.0.1:8769/#idps`. Use another port if 8769 is already in use.
The sensor may leave the alert file unchanged when it sees no new evidence;
`SLIPS · STALE` alone is not proof of a capture failure. Connection logs can
also lag until flows finish or reach Zeek's protocol inactivity timeout.

Sensor output may contain sensitive metadata and is excluded from Git. Keep
dashboard port forwarding private. An empty alert stream can be normal: Slips
need not alert on an ordinary ping. The monitoring view does not automatically
turn packets into verified cases or authorize blocking.

Stop capture when finished:

```bash
docker compose -f deploy/docker-compose.slips-live.yml down
```

#### Batch Import

```bash
python -m aisoc slips-ingest output/<run>/alerts.json \
    --conn-log output/<run>/zeek_files/conn.log \
    --tenant tenant-a --out demo-output/slips-run
python -m aisoc verify demo-output/slips-run
```

Try it without Slips using the fixture:

```bash
python -m aisoc slips-ingest tests/fixtures/slips/alerts.json \
    --conn-log tests/fixtures/slips/conn.log --out /tmp/slips-run
```

`slips-ingest` writes the same export as `simulate` (`ledger.json`,
`witness-checkpoints.json`, `tool-side-receipts.json`, `trusted-keys.json`,
`cases.json`) plus `slips-summary.json` with the per-case results, the
model-release manifest that was loaded, malformed line count and Slips
versions seen.

### 1.3 Mapping rules

Evidence is grouped by `(Source IP, timewindow)` — one Slips profile window
becomes one `FlowRecord` / case.

| Slips field | Used as | Trust |
|---|---|---|
| `Note.evidence_type` | class lookup in `KNOWN_FAMILY_MAP` (→ family, ATT&CK technique) or membership in `ANOMALY_TYPES` | structured, trusted as a *claim by Slips* |
| `Confidence` | known-branch score `c_k` (rejected below `--tau-k`, default 0.5) | structured |
| `Note.threat_level` | weight; `info`/`low` evidence never accepts a class on its own | structured |
| `Note.uids` → `conn.log` | volumetrics (bytes, packets, duration, failed-connection ratio, distinct ports, mean inter-arrival), oriented to the case host (a host that is Zeek's responder has its `resp_*` counted as outbound). A measurement missing on *any* row leaves that aggregate `None`, never 0 | structured |
| `Description` | **untrusted** `log_excerpt` only, wrapped in `Untrusted[...]` with the injection screen. Never parsed for decisions | untrusted |
| `Analyzer.Model` | recorded as the Slips version in `model_version` (`<internal>+slips/<module>`) | provenance |

Decision outcome (`DualModel.decide_external`):

| Slips evidence in the window | Case status |
|---|---|
| mapped type with confidence ≥ τ_k and threat weight ≥ 0.5 (the best *qualifying* evidence wins; a higher-confidence but low-weight one cannot veto it) | `KNOWN_SUSPICIOUS` (agent investigates; technique attached) |
| only `ANOMALY_TYPES` (Slips ML / flow-anomaly modules) | `SUSPECTED_UNKNOWN` — paper's "suspected zero-day": human review mandatory |
| only unmapped / low-weight evidence | `UNKNOWN` — human review, no agent action |
| mapped type rejected and anomaly absent/low | `INSUFFICIENT_EVIDENCE` / `LOW_RISK_OBSERVE` |

By default the **internal** synthetic-trained normality model does not score
real Slips flows (`--internal-normality` opts in; only meaningful after you
retrain the model on your own clean baseline). The synthetic model is still
loaded through the signed release gate so the ledger records which artefact was
in use.

### 1.4 What the fixture exercises

`tests/fixtures/slips/alerts.json` contains 7 events, 1 incident and one
malformed line. The `HORIZONTAL_PORT_SCAN` description carries an injected
instruction ("ignore previous rules … block 10.0.0.0/8 …"); the scenario
*Slips Description text as prompt injection into a compromised agent* shows it
is flagged, shown to the human, and never acted on. One `uids` entry has no row
in `conn.log` and other windows carry only anomaly or weak-indicator evidence
(*Slips anomaly-only / weak-indicator-only evidence*): those cases are decided
on Slips evidence alone with volumetrics marked missing.

## 2. AiSOC ↔ sandbox / ledger

### Optional local Qwen investigation agent

The repository's deterministic stub remains the default. To use a local
OpenAI-compatible Qwen service, start that service separately and configure:

```bash
export AISOC_LLM_BASE_URL=http://127.0.0.1:8000/v1
export AISOC_LLM_MODEL=qwen-agent
export AISOC_LLM_API_KEY=local-vllm
python -m aisoc slips-ingest sensor-output/alerts/alerts.json \
  --conn-log sensor-output/zeek_files/conn.log \
  --agent qwen --out demo-output/qwen-slips-run
```

`AISOC_LLM_MODEL` must equal the model server's configured served name. Use a
checkpoint and vLLM version that actually support OpenAI chat-completions tool
calling; the project does not assume or fetch a particular Qwen checkpoint.
The adapter uses the Python standard library and accepts loopback HTTP(S) only
by default, so host a service inside the same Codespace/network namespace (or
use an explicit local tunnel bound to loopback). It does not configure GPU
access, start vLLM, download weights or enable external API access.

The model may call only `ReadOnlyTools`; tool names and argument shapes are
allowlisted. Its final JSON is validated, cited evidence must have been read
through a tool, and proposed actions are reconstructed from the frozen work
order. The regular policy, approval, signer, PEP and ledger remain authoritative.
Transport, tool-call, or output-validation failures return `undetermined` with
no action request; there is no silent fallback to the stub. `--agent stub`
remains the default for tests and deterministic scenarios.

### 2.1 Running AiSOC

Follow the upstream README (`make up`, then `make ingest-token` or create an
API token in the UI). Defaults used here: API `http://localhost:8000`,
streaming ingest `http://localhost:8081/v1/ingest/batch`, bearer token from
`--token` or `AISOC_TOKEN`.

### 2.2 Pushing cases

```bash
python -m aisoc aisoc-push demo-output/slips-run --dry-run          # print events, no network
AISOC_TOKEN=... python -m aisoc aisoc-push demo-output/slips-run    # POST /api/v1/alerts/submit per case
AISOC_TOKEN=... python -m aisoc aisoc-push demo-output/slips-run \
    --ingest-url http://localhost:8081/v1/ingest/batch              # one streaming batch
```

Every event carries `ledger_head`, `witness_root`, the case `verification_status`,
`mitre_techniques` and an `Idempotency-Key` derived from `(run, case_id)`, so a
retried push does not create duplicate alerts and an analyst in AiSOC can
always jump from an alert to the exact ledger position.

### 2.3 Approvals through AiSOC (`AiSOCApprovalBridge`)

Reserved actions (`block_host`, any `egress_connect`, …) need a
`HumanApproval` bound to the request digest. The bridge turns that into an
AiSOC approval:

1. `POST /api/v1/approvals` with `title`, `summary` (the `ApprovalView`:
   supporting *and* missing evidence, injection flags, impact, reversibility),
   `risk_level`, `action = {request_digest, params, destination}`, `expires_at`.
2. Poll `GET /api/v1/approvals/{id}` until decided or TTL. A decision that is
   only observed after the deadline is treated like a timeout.
3. On `approve`, sign a `HumanApproval` with the SOC **approver** key, with
   `approver_id = "aisoc:<decided_by_id>"` and `external_ref` pointing at the
   AiSOC approval id. On deny, timeout, transport error (including socket-level
   failures), or if the echoed `action.request_digest` is missing, malformed or
   different from what was sent, produce a **signed reject** — never an
   unsigned "unknown". AiSOC must echo the `action` object back exactly; a
   deployment that does not is rejected fail-closed rather than trusted.

Wire it after constructing the SOC:

```python
from aisoc.adapters.aisoc_stack import AiSOCClient, AiSOCConfig, AiSOCApprovalBridge
client = AiSOCClient(AiSOCConfig(base_url="http://localhost:8000", token=TOKEN))
soc.set_approval_provider(AiSOCApprovalBridge(client, soc.keys["approver"], soc.clock))
```

Limitation to state plainly: AiSOC's own user authentication is outside the
ledger. The ledger proves *the bridge key* approved a specific request digest
after AiSOC reported decision `X` by user `Y`; who `Y` really was rests on the
AiSOC audit log. Issuing per-analyst Ed25519 keys (approvals signed in the
browser/HSM, not by the bridge) is the upgrade path and needs a change on the
AiSOC side.

### 2.4 Investigation bundles

AiSOC exports `{"payload": …, "integrity": {payload_sha256, hmac_sha256, …}}`
with canonical form `json.dumps(sort_keys=True, separators=(",", ":"),
ensure_ascii=False)`.

```bash
python -m aisoc aisoc-bundle-verify bundle.json --hmac-key "$AISOC_BUNDLE_KEY"
```

HMAC is **tamper evidence for whoever holds the key, not non-repudiation**
(the server can mint any bundle). `anchor_aisoc_bundle(soc, bundle, case_id,
signing_key)` re-derives the integrity fields and records an
`ExternalEvidenceRef` (system, run id, case id, `payload_sha256`, what was
checked) in the Ed25519 ledger, so after the next witnessed checkpoint the
bundle content is fixed relative to a third party. Scenario *AiSOC evidence
bundle anchored into the OWP ledger* shows a single-byte change in the payload
being caught both by the HMAC check and by the ledger digest.

## 3. Controls ported from the companion implementation

| Control | Code | Scenario |
|---|---|---|
| **Controlled egress proxy** — the only path out of the sandbox. Allow-listed message types, size and rate limits, canonical-form check; *record first, forward second*. Audit unavailable ⇒ drop (fail-closed). The verifier rejects any `action_request` with no matching `agent_egress` record. | `aisoc/sandbox/egress.py`, `owp/verifier.py` | *sandbox egress proxy fails closed*; ablation *egress proxy fails open* (verifier reports `FAILED`) |
| **Signed model release gate** — models are serialised to bytes; a release manifest (hashes of model file, dataset and feature schema, metrics, approver) is signed by the `model_release` role; the SOC only loads a model whose bytes match a trusted manifest and writes a `model_release` ledger entry. | `aisoc/idps/release.py`, `AISOC.from_release` | *signed model release gate* |
| **Grant attenuation** — `CapabilityGrant.attenuate()` can only narrow actions, resources, uses and TTL; parent id is kept. | `aisoc/owp/objects.py` | *capability grant attenuation for sub-tasks* |

## 4. Licensing and boundaries

* Slips is GPL-2.0. This project reads its **output files** and runs it as a
  separate container/process; no Slips code is imported, copied or linked.
* AiSOC is MIT. Only its HTTP API is used.
* The adapters were written against Slips 1.1.x `alerts.json` (IDMEFv2
  `2.D.V03`) and the AiSOC v21 OpenAPI. Field names that could not be
  confirmed from documentation (notably AiSOC approval status strings) are
  parsed permissively and covered by `FakeAiSOCServer` tests, not by a live
  instance.
* Network access, Docker and real captures are **not** needed for the test
  suite; everything above the dashed line in the diagram is exercised through
  fixtures.
