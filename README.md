# GYMSIEGE

GYMSIEGE runs two public security-agent benchmarks as a **Daytona fleet evaluation**:

- **[CyberGym-E2E](https://github.com/sunblaze-ucb/cybergym-e2e)** — find-vulnerability → PoC → patch, scored by the real ARVO sanitizer oracle.
- **[ExploitGym](https://github.com/sunblaze-ucb/exploitgym)** — exploit-development evaluation, run through the upstream evaluator with its firewall, local LLM proxy, controller, hardened targets, and budget accounting.

It measures both **agent capability** (pass@k, oracle stages, research navigation success, tokens/cost) and **infrastructure behavior** (provisioning latency, a concurrency failure curve, CPU/memory/disk telemetry, recordings, cleanup reliability).

Every trial runs inside a real, disposable Daytona sandbox — nothing here is simulated. `results.json` stays a not-yet-run schema template until an actual trial has completed against the live Daytona and provider APIs.

## Contents

- [How it fits together](#how-it-fits-together)
- [Files](#files)
- [Requirements](#requirements)
- [Local setup and credentials](#local-setup-and-credentials)
- [CyberGym-E2E protocol](#cybergym-e2e-protocol)
- [ExploitGym protocol](#exploitgym-protocol)
- [Dashboard and cleanup](#dashboard-and-cleanup)
- [Metrics and interpretation](#metrics-and-interpretation)
- [Guardrails](#guardrails)
- [Verification](#verification)
- [Reproduction helper](#reproduction-helper)

## How it fits together

```
snapshot_build.py / exploitgym_snapshot_build.py
        │  bake a reusable Daytona snapshot (toolchain + data + images)
        ▼
orchestrator.py  ──asyncio.Semaphore(MAX_PARALLEL)──►  sandbox_runner.py
   run / sweep /                                          one (task, mode, trial):
   provision-bench /                                       create → secrets → recording
   exploitgym-run /                                        → solver_agent.py → metrics
   reap                                                     → artifacts → TTL → delete
        │
        ▼
results.json + results/*.json/*.ndjson + recordings/*.mp4
        │
        ▼
dashboard.py  (local uvicorn, or --publish to a live Daytona preview link)
```

`solver_agent.py` is the unit of "what the agent actually does" inside each sandbox, split into two halves:

- **ResearchAgent** — Computer Use: opens the vuln report in a real browser, reads it via the accessibility tree (screenshot fallback), writes a research note. A capability signal only; it does not feed back into the sanitizer oracle.
- **BuildAgent** — headless work over `process.exec`: runs the upstream benchmark's own find-vuln → PoC → patch loop, then performs one additional network-isolated re-detonation as the authoritative result.

## Files

| File | Purpose |
|---|---|
| `common.py` | Shared config, env parsing, constants (`CONCURRENCY_LADDER`, snapshot names, secret name defaults), and JSON I/O helpers used by every entrypoint below. |
| `snapshot_build.py` | Bakes `gymsiege-toolchain`: installs the sanitizer toolchain, clones CyberGym-E2E, pre-pulls the Docker build images for the pinned task set, snapshots the sandbox, and seeds a provisioning baseline sample. |
| `exploitgym_snapshot_build.py` | Bakes `gymsiege-exploitgym` for the official userspace smoke tasks (harness, static agent runtimes, firewall/proxy deps). |
| `solver_agent.py` | Defines `Solver`: separates Computer Use research work from headless CyberGym build/oracle work. |
| `sandbox_runner.py` | Runs one CyberGym trial end-to-end — provisioning, secrets, recording, solver call, metrics capture, artifact download, TTL arm, and guaranteed deletion. |
| `orchestrator.py` | CLI entrypoint: `run`, `sweep`, `provision-bench`, `exploitgym-run`, `reap` — owns the concurrency semaphore and fans trials out across the fleet. |
| `exploitgym_adapter.py` | Runs upstream ExploitGym inside a sandbox with mandatory firewall/proxy/hardened settings; delegates task construction and scoring to ExploitGym itself. |
| `dashboard.py` | FastAPI app combining the CyberGym/ExploitGym leaderboards, concurrency curve, provisioning latency histogram, per-sandbox telemetry, and recording links. Runs locally or publishes to a live Daytona preview link. |
| `configure_secrets.py` | Copies a local provider API key into a named Daytona organization Secret, once, without ever printing or committing the value. |
| `tasks.pinned.txt` | 20 pinned CyberGym tasks used by the main protocol. |
| `exploitgym_tasks.pinned.txt` | Ten userspace tasks from ExploitGym's official 20-task sample. |
| `.env.defaults` | Non-secret, committed Daytona Secret *names* (never values). |
| `tests/` | Unit tests for task parsing, pass@k/oracle aggregation, ExploitGym score parsing, and the non-disableable hardened command profile. |
| `demo.sh` | End-to-end reproduction script: bake → smoke run → concurrency probe → dashboard publish. |

Generated/ignored at runtime (not committed): `.venv/`, `data/`, `artifacts/`, `recordings/*.mp4`, `results/*.json`, `results.json` (template only is tracked).

## Requirements

- Python 3.11+ (tested against 3.11.9)
- A [Daytona](https://www.daytona.io/) account and API key
- An LLM provider key for whichever solver backend you run (OpenAI, Anthropic, or a LiteLLM/Bedrock deployment)
- Real API quota on both Daytona and the chosen LLM provider — every command in this README talks to live services and consumes it

## Local setup and credentials

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

Developer-local values belong in the git-ignored `.env.local`:

```dotenv
DAYTONA_API_KEY=...
OPENAI_API_KEY=...
# Optional, for CyberGym's native Anthropic backend:
ANTHROPIC_API_KEY=...
```

Non-secret vault *names* are committed in `.env.defaults`. Copy local provider values into Daytona's organization vault once:

```bash
.venv/bin/python configure_secrets.py openai
# Optional:
.venv/bin/python configure_secrets.py anthropic
```

Existing secrets are reused; pass `--replace` only when deliberately rotating a value. Sandboxes receive mappings such as `OPENAI_API_KEY -> gymsiege-openai` through `update_secrets` — plaintext values are never placed in sandbox-create parameters or logs.

CyberGym upstream doesn't currently accept a direct OpenAI provider the way ExploitGym does. For CyberGym, use its Anthropic backend or a LiteLLM deployment:

```dotenv
LITELLM_BASE_URL=https://your-litellm.example
GYMSIEGE_LITELLM_SECRET_NAME=gymsiege-litellm
```

## CyberGym-E2E protocol

```bash
# One-time toolchain/data/image snapshot.
.venv/bin/python snapshot_build.py

# Small real-oracle smoke run.
.venv/bin/python orchestrator.py run \
  --limit 2 --k 1 --modes patch-only --max-parallel 2

# Publication run: 20 tasks x k=3 x both modes.
.venv/bin/python orchestrator.py run \
  --k 3 --modes e2e patch-only --max-parallel 8

# Infrastructure experiments.
.venv/bin/python orchestrator.py provision-bench --samples 10
.venv/bin/python orchestrator.py sweep --levels 1 2 4 8 16 32
```

The upstream agent first performs its normal network-attached LLM loop. After it freezes `poc.bin` and `fix.patch`, GYMSIEGE calls `update_network_settings(network_block_all=True)` and independently re-runs the real vulnerable/fixed sanitizer stages. Only a nonzero vulnerable exit plus a zero fixed exit, under this isolated confirmation, can become `status=success`.

## ExploitGym protocol

The default is deliberately bounded to the ten official userspace sample tasks. It uses `exp.hardened`, upstream `--use-firewall`, the local LLM proxy (which blocks provider-side external retrieval), model allowlisting, a per-task budget, and `keep_container=false`. Generated exploit payloads remain inside the Daytona sandbox; only `result.json`, `task.log`, usage, and telemetry are downloaded.

```bash
# One-time public harness/runtime/image snapshot.
.venv/bin/python exploitgym_snapshot_build.py

# One-task validation with the existing OpenAI vault secret.
.venv/bin/python orchestrator.py exploitgym-run \
  --limit 1 --k 1 --max-parallel 1 \
  --agent codex --model gpt-5.3-codex --budget-usd 5

# Ten-task pass@3 run.
.venv/bin/python orchestrator.py exploitgym-run \
  --k 3 --max-parallel 2 \
  --agent codex --model gpt-5.3-codex --budget-usd 5
```

Kernel and V8 tasks are excluded by default because they change hardware/KVM and image requirements — a custom compatible snapshot plus `--allow-non-userspace` is required to opt in, and the hardened flags remain enforced regardless.

ExploitGym's agent interaction must retain LLM connectivity, so its containment signal is the upstream internal Docker firewall rather than a false claim of Daytona-wide block-all during the agent step. GYMSIEGE blocks Daytona egress immediately after the evaluator returns and records both facts separately per trial.

## Dashboard and cleanup

```bash
# Local dashboard.
.venv/bin/python dashboard.py

# Snapshot results into a named, TTL-protected Daytona dashboard sandbox.
.venv/bin/python dashboard.py --publish

# Inspect or reap leaked siege-* sandboxes.
.venv/bin/python orchestrator.py reap --dry-run
.venv/bin/python orchestrator.py reap
```

The dashboard combines the CyberGym and ExploitGym leaderboards, the concurrency failure curve, provisioning p50/p95, per-sandbox CPU/memory time-series, results, and CyberGym recordings. Publication uploads a point-in-time snapshot; re-run `--publish --sandbox-id ID` to refresh an existing dashboard sandbox in place.

## Metrics and interpretation

- **CyberGym**: stage1–4, isolated vulnerable/fixed exit codes, pass@1/pass@k by `e2e` and `patch-only`, research navigation success, tokens/cost.
- **ExploitGym**: upstream score/checks, pass@1/pass@k, hardened/firewall/proxy assertions, tokens/cost.
- **Infrastructure**: warm-pool vs. snapshot vs. fork p50/p95, concurrency completion/capability/timeout/OOM curves, per-trial metrics series, TTL/delete outcomes.
- `oracle_unavailable` is excluded from CyberGym capability denominators but remains in infrastructure statistics.
- An ExploitGym flag score is distinct from the optional causal target-vulnerability scorer — don't label it "target vulnerability used" without running upstream `agent_scorer`.

## Guardrails

- All target builds and executions occur inside Daytona sandboxes and nested benchmark containers.
- CyberGym's final PoC confirmation runs with Daytona network block-all.
- ExploitGym always uses its internal no-route firewall and local retrieval-blocking LLM proxy — no direct-key mode is exposed.
- Every trial arms TTL immediately and calls blocking deletion in `finally`; `reap` catches crash leftovers.
- Provider keys stay in `.env.local` and Daytona organization Secrets. `.env.local`, benchmark data, recordings, and artifacts are git-ignored.
- ExploitGym exploit payloads are intentionally never exported to the host.

## Verification

```bash
.venv/bin/python -m unittest discover -s tests -v
python3 -m py_compile *.py
bash -n demo.sh
```

The local suite verifies task parsing, pass@k/oracle aggregation, ExploitGym score parsing, and the non-disableable firewall/proxy/hardened command profile.

## Reproduction helper

`demo.sh` performs a CyberGym smoke run, a tiny concurrency probe, and dashboard publication end-to-end from a clean checkout. It talks to the real Daytona API and burns real quota — it is not a dry run. Set `RUN_EXPLOITGYM=1` to additionally bake and run one hardened ExploitGym userspace task:

```bash
./demo.sh
RUN_EXPLOITGYM=1 ./demo.sh
```
