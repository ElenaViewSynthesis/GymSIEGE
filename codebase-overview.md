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

## Hugging Face dataset transfer hosts

The CyberGym dataset payload is fetched during the bake
(`snapshot_build.py`'s `BOOTSTRAP_SH`), authenticated by the
`gymsiege-huggingface` Daytona Secret. That Secret is scoped to nine exact
FQDNs, defined once in `configure_secrets.py` as `HUGGINGFACE_SECRET_HOSTS`
and mirrored in [`HUGGINGFACE_HOSTS.md`](HUGGINGFACE_HOSTS.md):

| # | Host | Role |
|---|---|---|
| 1 | `huggingface.co` | Hub API — auth, gated-repo resolution, metadata |
| 2 | `cas-server.xethub.hf.co` | Xet content-addressed store, US |
| 3 | `cas-server.xethub-eu.hf.co` | Xet content-addressed store, EU |
| 4 | `transfer.xethub.hf.co` | Xet transfer endpoint, US |
| 5 | `transfer.xethub-eu.hf.co` | Xet transfer endpoint, EU |
| 6 | `us.aws.cdn.hf.co` | CDN payload delivery, AWS US — **the observed redirect target** |
| 7 | `us.gcp.cdn.hf.co` | CDN payload delivery, GCP US |
| 8 | `cdn-lfs-us-1.hf.co` | Legacy LFS CDN, US |
| 9 | `cdn-lfs-eu-1.hf.co` | Legacy LFS CDN, EU |

Two things this list is *not*. It is not a network allowlist — a Daytona
Secret's `hosts` field is a value-substitution trust boundary governing where
Daytona may send that secret. And it is not permanent: it tracks Hugging Face's
current download-behind-a-firewall guidance, so re-review it whenever
`huggingface_hub` is upgraded. `tests/test_core.py` asserts the list is
duplicate-free and still contains the key members.

**This list is not what blocks the bake.** An A/B probe
(`hf_header_probe.py`) transferred payload bytes from `us.aws.cdn.hf.co`
*inside a sandbox* (ranged `GET` → `206`), retiring the egress theory. The
sandbox's responses match local on every header the client needs except
`Content-Length`, which is absent — and `huggingface_hub` refuses to download a
file whose size it cannot determine. Details in
[`DAYTONA_HUGGINGFACE_EGRESS_ISSUE.md`](DAYTONA_HUGGINGFACE_EGRESS_ISSUE.md).
Note also that this dataset is Xet-backed, so `huggingface_hub`'s real payload
path is Xet rather than the CDN redirect (`file_download.py:1777`); Xet is
Hugging Face's *current* backend and Git LFS the legacy one, not the reverse.

## Telemetry capture and the OOM proxy

Telemetry is captured at **two** points in a trial's life, and the second one
exists specifically so a trial that dies early still leaves evidence behind.

1. **Normal path** — a trial that reaches the end of its build/PoC/patch
   phase (including the isolated re-detonation above) calls
   `sandbox.get_metrics_latest()` and `sandbox.get_metrics(start=None,
   end=None)` at `sandbox_runner.py:210-216`, right after `status` is
   classified. The results land on the `TrialResult` as `metrics_latest`
   (one point-in-time sample) and `metrics_series` (the time-series across
   the sandbox's lifetime — `cpu_used_pct`, `mem_used`, `mem_total`,
   `disk_used`, etc., straight from the real `SandboxMetrics` the SDK
   returns). Neither call is periodic polling: `get_metrics()` with no
   bounds just pulls back whatever history Daytona's backend already
   accumulated for that sandbox.
2. **Cancellation/timeout path** — `run_trial`'s `finally` block calls
   `_capture_telemetry_bounded` (`sandbox_runner.py:260`, defined at line
   299) *before* the sandbox is deleted. It re-runs the same two SDK calls
   under a 30-second `asyncio.wait_for` and swallows every exception. So a
   trial cancelled mid-build by the sweep's outer deadline still gets
   telemetry, provided the control plane is responsive enough to answer.
   This capture is best-effort by design — an unresponsive control plane
   logs a warning and leaves the fields `None` rather than blocking cleanup.
3. **Retaining the partial result** — the sweep's own wrapper,
   `orchestrator.py:_run_sweep_trial_with_timeout`, pre-allocates the
   `TrialResult` and passes it into `run_trial` as the `result=` argument,
   so the object the `finally` block mutates is the same one the wrapper
   returns on timeout. Previously the timeout arm returned `None` and threw
   the telemetry away even when it had been fetched.
4. **Classification** — once a probe batch at a given concurrency level
   finishes, `orchestrator.py:_trial_hit_oom_threshold` (line 598) walks
   every sample in that trial's `metrics_series` plus its final
   `metrics_latest`, flagging the trial as OOM-adjacent if any single sample
   shows `mem_used >= 0.95 * mem_total`. `n_oom` (line 550) counts those,
   and `oom_rate = n_oom / n` goes into `results/concurrency_sweep.json`.

So "OOM" here really means "this sandbox's real memory telemetry crossed 95%
utilization at some point during the trial," not a captured OOM-killer
event, exit code, or kernel log line — Daytona's SDK doesn't expose one.
It's a proxy: high enough that memory pressure plausibly contributed to
whatever else went wrong at that concurrency level (a failed build, a killed
process, a timeout), but it's correlational, not a confirmed cause. The 95%
threshold is hardcoded (not configurable via CLI/env) — worth knowing if you
want to tune sensitivity.

**Timeout and OOM now overlap on purpose.** Because a timed-out trial can
carry telemetry, it can be counted in `n_timeout` *and* `n_oom`
simultaneously. That is intended: the two describe different things (how the
trial ended, versus what its memory was doing), and forcing them to be
disjoint is what previously hid memory pressure behind timeouts. The overlap
is reported explicitly as `n_timeout_oom` / `timeout_oom_rate`
(`orchestrator.py:551-566`), so `timeout_rate + oom_rate` should not be read
as a sum of distinct failures. A timeout whose telemetry fetch also failed
stays unclassified — it is *not* assumed to be non-OOM.

**Caveat — ExploitGym has not been fixed.** The above applies to CyberGym's
`run_trial` only. `exploitgym_adapter.py` still captures telemetry once, very
late (lines 524-527), after evaluation, the network block, and `result.json`
scoring — so its error, cancellation, and outer-deadline paths all discard
telemetry exactly the way `sweep` used to. Nothing surfaces this yet, because
`exploitgym-run` is a flat semaphore fan-out with no concurrency ladder and
`_write_exploitgym_results` computes no OOM statistic at all. It becomes a
real data-loss bug the moment anyone adds either. Tracked as Priority 8 in
[`TODO.md`](TODO.md).

Both paths still leave a gap for the dashboard: trials whose telemetry fetch
failed outright render nothing in the per-sandbox charts, which only draw
trials with a non-empty `metrics_series`.
