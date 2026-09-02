# Codebase overview

Entry-point doc for how GYMSIEGE's Daytona adapter fits together, starting from
the client object every entrypoint opens first. For issue-specific deep dives
(the ARVO sanitizer oracle, the 60-minute safety TTL, the nested-container
egress bug) see [`daytona-notes.md`](daytona-notes.md); this doc is the
narrower "what talks to what" map.

## `AsyncDaytona` — the fleet-level client

`AsyncDaytona` is the async client for the Daytona SDK used throughout the
GYMSIEGE codebase as the entry point for all sandbox *lifecycle* operations —
anything that creates, finds, or enumerates sandboxes/snapshots rather than
acting on one you already hold. Specifically it's used to:

- **Create sandboxes** — `daytona.create()` for a warm-pool-eligible "cold"
  sandbox, or `daytona.create(CreateSandboxFromSnapshotParams(...))` to spin
  one up from the pre-baked `gymsiege-toolchain` snapshot. The snapshot form
  is called directly in `snapshot_build.py` (baking the toolchain and taking
  a restore-latency sample) and in `sandbox_runner.py:_create_sandbox`
  (every real CyberGym trial); the cold form is the `provisioning == "cold"`
  arm in that same function, plus the baseline sample in
  `orchestrator.py`'s `provision-bench` command. `orchestrator.py run`
  reaches `daytona.create()` too, but indirectly — through
  `sandbox_runner.run_trial` for ordinary trials, and directly for the
  `--provisioning fork` warm-parent sandbox it creates once up front before
  fanning out `.fork()` calls against it. `sweep` never calls `create()`
  itself either; it drives the same `run_trial` path at increasing
  concurrency levels.
- **List sandboxes** — `daytona.list()` (an async generator, not something
  you `await` into a list — see the note in `orchestrator.py`) in the `reap`
  command, to find and delete stray `siege-*` sandboxes left behind by a
  crashed run.
- **Fetch a sandbox by id** — `daytona.get(...)` in `dashboard.py`'s
  `publish()` function, to reuse an existing dashboard sandbox instead of
  recreating one on every redeploy.
- **Manage the snapshot catalog** — `daytona.snapshot.list()` (returns a
  `PaginatedSnapshots` object with an `.items` list, not a bare list) shows
  up in two places: `demo.sh`'s inline Python snippet, to check whether
  `gymsiege-toolchain` already exists before rebaking it, and
  `exploitgym_snapshot_build.py`, doing the same existence check for the
  `gymsiege-exploitgym` snapshot before that bake runs.

It's always opened as an async context manager
(`async with AsyncDaytona() as daytona:`), which reads
`DAYTONA_API_KEY`/`DAYTONA_API_URL`/`DAYTONA_TARGET` from the environment
(loaded from `.env`/`.env.local` via `common.py`'s `load_dotenv` calls, so
those vars don't need to be exported by hand) and handles client teardown on
exit — `configure_secrets.py`, `dashboard.py`, `orchestrator.py`,
`snapshot_build.py`, and `exploitgym_snapshot_build.py` all follow this same
`async with` pattern rather than manually opening/closing the client.

## `AsyncSandbox` — the per-sandbox handle

Every individual sandbox object `AsyncDaytona` returns (`AsyncSandbox`) then
exposes the *per-sandbox* operations — `process.exec`, `computer_use.*`,
`get_metrics`/`get_metrics_latest`, `update_network_settings`, `set_ttl`,
`delete`, `fork`, `create_snapshot`, `download_url`, `update_secrets` — that
the rest of the pipeline (`sandbox_runner.py`, `solver_agent.py`) uses to
actually run each CyberGym-E2E or ExploitGym trial once the sandbox exists.
`AsyncDaytona` hands one out; everything after that is a method call on that
one object until `sandbox.delete()` ends its life.

## The isolated PoC re-detonation (`solver_agent.py`)

One `AsyncSandbox` method combination worth calling out on its own:
`update_network_settings(network_block_all=True/False)`, used in
`BuildAgent._reconfirm_isolated` (`solver_agent.py`).

CyberGym's own `scripts/run_agent.py` needs network access for the whole
find-vuln → PoC → patch loop, since the solver's own LLM calls go out over
the network throughout — so the sandbox can't be network-cut for that entire
phase. Instead, once `run_agent.py` has finished and frozen its artifacts
(`poc.bin` / `fix.patch`, located from the newest `summary.json` under
`agent_output/<task>/`), `BuildAgent.run` calls `_reconfirm_isolated`, which:

1. Calls `sandbox.update_network_settings(network_block_all=True)` — the
   network is now cut at the Daytona sandbox level.
2. Runs a small generated Python script inside the sandbox
   (`_isolated_oracle_script`) that reuses CyberGym's own container helpers
   (`start_container`, `setup_workspace`, `copy_to_container`, `exec_run`,
   `cleanup_container` from its `scripts/utils.py`) to spin up **two fresh,
   nested per-arm containers** — one for the vulnerable build, one with
   `fix.patch` applied — copies the frozen `poc.bin` into each, and runs
   `run_poc.sh` directly to capture its raw exit code (`run_poc_exit_code`),
   alongside CyberGym's own `validate.py` stage result, for each arm.
   Because the outer sandbox's network is already blocked at this point, a
   missing base image fails closed here instead of silently pulling one
   mid-detonation.
3. Parses the two raw exit codes out of a `GYMSIEGE_ORACLE_JSON:` marker line
   in the script's stdout as `vul_exit_code` (unpatched build) and
   `fix_exit_code` (patched build) — these are what `results.json` reports,
   distinct from `run_agent.py`'s own network-attached internal stage1/stage2
   validation.
4. Re-opens the network (`network_block_all=False`) in a `finally` block
   regardless of outcome, so the subsequent artifact `download_url` calls,
   recording upload, and cleanup exec still work.

`BuildResult.network_isolated_detonation` is only `True` when both exit codes
came back non-`None`; a failure anywhere in that sequence is captured as
`detonation_error` on the result instead of silently dropping the trial.

## Telemetry capture and the OOM proxy

1. Every trial, win or lose, ends by calling `sandbox.get_metrics_latest()`
   and `sandbox.get_metrics(start=None, end=None)` inside `sandbox_runner.py`
   (lines 201–204), storing the results on the `TrialResult` as
   `metrics_latest` (one point-in-time sample) and `metrics_series` (the full
   time-series across the trial's lifetime — `cpu_used_pct`, `mem_used`,
   `mem_total`, `disk_used`, etc., straight from the real `SandboxMetrics`
   the SDK returns). This is a single end-of-trial snapshot taken right after
   the build/PoC/patch phase (including the isolated re-detonation above)
   finishes and `status` is classified, not periodic polling during the
   trial — `get_metrics()` with no bounds just pulls back whatever history
   Daytona's backend already accumulated for that sandbox.
2. Back in the sweep, once a probe batch at a given concurrency level
   finishes, `orchestrator.py:_trial_hit_oom_threshold` (line 555) walks
   every sample in that trial's `metrics_series` plus its final
   `metrics_latest`, and flags the trial as OOM-adjacent if any single sample
   shows `mem_used >= 0.95 * mem_total`.
3. `n_oom` (line 513) is just the count of trials at that concurrency level
   for which that flag came back true, and `oom_rate = n_oom / n` goes into
   `results/concurrency_sweep.json`.

So "OOM" here really means "this sandbox's real memory telemetry crossed 95%
utilization at some point during the trial," not a captured OOM-killer
event, exit code, or kernel log line — Daytona's SDK doesn't expose one.
It's a proxy: high enough that memory pressure plausibly contributed to
whatever else went wrong at that concurrency level (a failed build, a killed
process, a timeout), but it's correlational, not a confirmed cause. The 95%
threshold is hardcoded (not configurable via CLI/env) — worth knowing if you
want to tune sensitivity.

**Caveat — trials that never reach the capture point.** Because step 1 only
runs after the build phase completes, a trial that times out
(`asyncio.wait_for` in `sweep`'s `bounded()`) or crashes before reaching that
line in `sandbox_runner.py` never gets a `metrics_latest`/`metrics_series` at
all — both fields stay `None` on its `TrialResult`. That makes such a trial
invisible to `_trial_hit_oom_threshold`, so it's counted only in
`n_timeout`/`n_error`, never in `n_oom` — even if the underlying cause was
memory pressure severe enough to hang the sandbox. The two rates are
mutually exclusive by construction, not because timeouts and OOM don't
overlap in reality. The same gap makes those trials invisible to the
dashboard's per-sandbox telemetry charts, which only render trials with a
non-empty `metrics_series`.
