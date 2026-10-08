# HANDOFF — CyberGym pinned Modal run: Codex agent makes zero model calls

**Status: OPEN.** Infra is healthy; the agent/solver phase fails on every task.

## TL;DR

The full 22-task `cybergym-pinned-modal.yml` run (`37668408810`, 2026-10-07) went
**green at the job level** but **every one of the 22 tasks came back
`status=error`**. Each task: Modal snapshot restored fine, Docker came up, then the
`evaluation` stage lasted only **~2 s**, the Codex agent made **zero model calls**
(`solver_usage=None`, `$0`), produced **no patch**, and errored. The green jobs are
an artifact of the per-task `|| true` in the shard loop (now guarded — see below).

## What is CONFIRMED working (do not re-debug)

- Dispatch + sharding + `max_tasks` cap.
- Tracked manifest resolve + Modal snapshot restore: `snapshot_restore` ~0.07 s,
  `Modal sandbox … ready (provisioning=snapshot)`, `docker_start` ~17 s, all
  `complete`. The image `im-01M376G3D7WYH73HT614RRXE5C` still exists.
- Gateway reachable from a laptop shell with a freshly minted key (HTTP 200).

## The failure, precisely

Per-task result JSON (e.g. `curl/arvo_66012`):
- `status=error`, `last_stage=cleanup`, `stage1..4=None`, `agent_success=None`.
- `stage_timings.evaluation.duration_s ≈ 2.1`, `research_mode=skipped`.
- `solver_usage=None`, `solver_cost_usd=None`, `patch_local_path=None`.

In `solver_agent.py`, `status = summary.get("status", "error" if not ok_exec else
"unknown")` (`:558`) and the stages come from the last attempt. All `None` ⇒
**`summary.json` had no attempts** ⇒ `scripts/run_agent.py --agent codex` aborted
before completing a single attempt, writing no usage and no patch.

## PRIME SUSPECT — the LiteLLM gateway path is broken

Reported 2026-10-08: **LiteLLM on localhost is down**, and hitting the reserved
ngrok domain `exchange-pug-shortly.ngrok-free.dev` shows a **client/edge IP in
Norway, not the UK** gateway host. So the ngrok domain is **not terminating at the
live local gateway** — agent model calls from inside the Modal sandbox reach
nothing usable and fail fast, which matches the 2 s / `$0` / no-patch signature
exactly. A one-off `HTTP 200` from a laptop shell is **not** sufficient evidence
the path is healthy from Modal; verify end-to-end before blaming the agent.

**Resolve first:**
1. Bring the local LiteLLM gateway back up on `:4000`.
2. Re-establish the ngrok tunnel so the reserved domain terminates at THIS host;
   confirm the tunnel's agent region and that the domain is not claimed elsewhere
   (the Norway edge IP suggests a stale/foreign tunnel or a dead agent falling
   back to an ngrok edge).
3. Prove it end-to-end, not just reachable: a request with the minted key should
   hit the local gateway's logs (watch LiteLLM stdout) and return a model list
   that matches the local config — tie a request id through.

## SECOND — the agent's own log is not captured (fixed here; needed to see more)

`modal_sandbox_runner.py` downloads `run_agent.log` + trajectory logs to
`ARTIFACTS_DIR` = `artifacts/<task>/<mode>/trial-N/` (`:439`, `:448`), but the
workflow only uploaded/synced `results/modal_trials/` — so the agent's actual
stderr was discarded with the sandbox. The workflow now **also uploads
`artifacts/`** (and the no-success guard fails a shard that wins nothing), so the
next run's `run_agent.log` will show Codex's real error. Read it before guessing
further.

## SECONDARY SUSPECTS (rule out once the gateway is verified)

- **CyberGym Squid firewall allowlist.** CyberGym runs the agent behind a Squid
  domain-allowlist proxy; its default list is only
  `api.anthropic.com`/`api.openai.com`/`generativelanguage.googleapis.com`. Calls
  to the ngrok host were historically rejected `403`, surfacing in Codex as a
  generic "stream disconnected" (documented in `solver_agent.py:416-426`). The
  code already passes `--domain <LITELLM_BASE_URL host>` to
  `python -m firewall start` (`:433-435`). Verify that allowlisted host is
  *exactly* the host the agent actually dials (and that `LITELLM_BASE_URL` inside
  the Modal sandbox — from the `gymsiege-litellm` secret's `OPENAI_API_BASE` —
  matches the one the runner allowlists).
- **Model id / provider rejection.** `--litellm-model-id` / `--model-provider`
  passed to `run_agent.py` (`:460-461`). A rejected id fails fast with no spend
  (cf. the CVE-Bench `[claude-code:unrecognized_model] gpt-5.6-luna` note). Confirm
  the model id is served by the *local* gateway's config.
- **Key valid from inside Modal.** The run reads the key from the
  `gymsiege-litellm` Modal secret, not the shell. Confirm that secret's
  `OPENAI_API_KEY` authenticates against the *live* gateway (a shell 200 only
  proves the shell key).

## Reproduce (cheap)

```bash
# after the gateway is verified live end-to-end:
gh workflow run cybergym-pinned-modal.yml --ref main \
  -f litellm_base_url=https://exchange-pug-shortly.ngrok-free.dev \
  -f shards=1 -f max_tasks=1
RID=$(gh run list --workflow=cybergym-pinned-modal.yml --event=workflow_dispatch \
        --limit 1 --json databaseId -q '.[0].databaseId')
gh run watch "$RID" --exit-status
gh run download "$RID"          # now includes artifacts/<task>/.../run_agent.log
# read run_agent.log for Codex's real error (403 / auth / model id / connect)
```

## Resolution plan (ordered)

1. **Fix the gateway path** (localhost up + ngrok terminating at this host, region
   sane) and prove it end-to-end from a request that lands in the local logs.
2. **Re-run one task** (`shards=1 max_tasks=1`) and read `run_agent.log` from the
   now-uploaded `artifacts/` — stop guessing, read the error.
3. If it's a `403`/allowlist: reconcile the firewall `--domain` host with the
   agent's actual endpoint host.
4. If it's auth: refresh the `gymsiege-litellm` Modal secret's key against the
   live gateway.
5. If it's model id: align `--litellm-model-id` with the live gateway's config.
6. Only after a single task reaches `status=success` with non-`$0` spend, scale
   back to the full 22 (`shards=8`, no `max_tasks`).

## Key code references

- `solver_agent.py:388-466` — firewall start (`--domain` allowlist) + `run_agent.py`
  invocation; `:550-558` — status/usage parsing (empty summary ⇒ `error`).
- `solver_agent.py:416-426` — the documented Squid-403 → "stream disconnected"
  failure mode.
- `modal_sandbox_runner.py:420-454` — artifact download (`run_agent.log`,
  trajectory) into `artifacts/` (not previously uploaded by CI).
- `.github/workflows/cybergym-pinned-modal.yml` — shard loop, no-success guard,
  artifact upload.
