# Codex handoff — optional: tolerate a transient client↔sandbox connection reset in the evaluation poll

**Owner:** Codex · **Priority:** low (optional resilience) · **Type:** resilience improvement (code)
**Opened:** 2026-09-21 · **Scope:** `exploitgym_adapter.py` evaluation poll (and the
CyberGym poll path if it shares the pattern)

## Reproducibility / whether this is worth doing

**Not reproducible on demand, and not confirmed to be a harness defect.** The
reset appeared once, on `arvo_66311` `--k 5` trial 5 over a poor wifi link; an
immediate rerun on a better connection went **5/5 with no reset**. So this looks
like a transient *client-side network* fault, not a deterministic bug. The
harness already fails safe today: it catches the reset, reaps the session,
destroys the sandbox, and records an honest `error` — and a re-run recovers the
data point. This handoff is therefore a **defensive nice-to-have** for flaky
networks and long unattended `--k` runs, **not** an urgent fix. Skip it unless
resets start recurring; if implemented, the unit-test path below is the real
acceptance (the live repro is environmental and can't be forced).

## The bug (fix it, don't just document it)

`arvo_66311` `--k 5` trial 5 (2026-09-21) died at ~2.4 min into evaluation with:

    ExploitGym trial failed: Failed to execute command: [Errno 104] Connection reset by peer
    -> ERROR - harness/platform failure, not an agent result

The captured diagnostics prove the **sandbox and agent were healthy** at the
time: `artifacts/exploitgym/user_cybergym_arvo_66311/trial-5/gymsiege-evaluation-processes.log`
shows the `run_agent.py` process tree (pid 1109 → 2122 → 2125) alive and the
Codex agent mid-run; `result.json` simply hadn't been written yet. It was the
**client's connection to the sandbox that dropped**, not the work. The other
4/5 trials completed cleanly. On a clean-wifi rerun the same task went 5/5, which
confirms this is a transient network/connection fault, not a task or agent
problem — but a single dropped poll read should not cost a whole trial.

## Root cause (read the code, confirmed)

Evaluation is launched detached and then polled for a complete `result.json`
(`_run_evaluation` → `_wait_for_complete_result`, `exploitgym_adapter.py` ~260–420).
The poll loop repeatedly calls `_read_json(sandbox, result_json_path)` /
`_read_remote_text(...)`, each of which issues a `sandbox.process.exec("cat …")`.
If **one** of those poll reads raises a transient connection error
(`[Errno 104] Connection reset by peer` — an aiohttp/OSError-class or a Daytona
connection wrapper that is **not** a clean `Daytona*Timeout*Error`), it
propagates out of `_wait_for_complete_result`, up through `_run_evaluation`, to
`run_exploitgym_trial`'s generic `except Exception` (~line 1025).

There, `_is_agent_no_return` (`exploitgym_adapter.py:167`) only matches
`DaytonaConnectionTimeoutError` / `DaytonaProcessExecutionTimeoutError` /
`ExploitGymAgentNoReturnError`, so a raw connection **reset** is neither an
agent-no-return nor recoverable — it falls straight to `status=error`,
harness/platform failure, and the trial is lost. The `result.json` poll design
already makes completion observable across reconnections; the loop just doesn't
survive a single dropped connection.

## What to build

The evaluation is detached in the sandbox and its completion is observable via
`result.json` + the status file, so a dropped **poll** connection should be
**retried against the same sandbox**, not fatal.

1. **Make the poll loop tolerate transient connection faults.** In
   `_wait_for_complete_result` (and inside `_read_json`/`_read_remote_text`, or
   wrapping their calls), catch the transient connection-error class —
   `ConnectionError`/`OSError` with `errno == 104` (ECONNRESET), connection
   aborted/broken-pipe, and any Daytona connection-error wrapper whose message
   carries these — and **retry that individual read** with short bounded
   backoff, staying within the existing overall `backstop_s`
   (`timeout_s + EXPLOITGYM_AGENT_FLUSH_GRACE_S`). Do not treat a single failed
   poll read as end-of-trial.
2. **Confirm liveness before continuing to retry.** If reconnection repeatedly
   fails, probe whether the sandbox is still reachable/alive at all (a cheap
   call). A sandbox that is genuinely gone is a real failure; a sandbox that is
   alive but momentarily unreachable is a retry.
3. **Bounded, honest fallback.** If the connection cannot be re-established
   within the backstop (or the sandbox is confirmed gone), keep it a failure —
   but give it a distinct `failure_reason` (e.g. `platform_connection_reset`),
   separate from `agent_did_not_return_within_budget`, so a transient-network
   loss is not conflated with an exec-timeout wall. Recovered resets should just
   log and continue (no status change).
4. **The launch exec, too.** If the initial detached `_launch_evaluation` exec
   can hit the same reset before the process is started, guard it with a bounded
   retry — but only if it can be made safe against double-launching the eval
   (idempotency check on the status/pid file). If that safety can't be
   guaranteed cheaply, leave launch as-is and note why.
5. **Keep the reap.** `_reap_evaluation_process_tree` must still run in the
   `finally` in every path, including the give-up path.

## Guardrails

- Bounded retries only — never an unbounded reconnect loop; the overall
  `backstop_s` remains the hard ceiling.
- Never double-launch or double-count a trial; a resumed poll must attach to the
  same in-flight evaluation, not start a second one.
- Don't relabel a genuine agent-no-return, a real sandbox-gone, or a
  `completed - no exploitation` — this only rescues *transient* connection
  faults against a still-live sandbox.
- Don't weaken the hardened/firewall flags, the exec backstop, or the
  result-detection/reap logic from the earlier fixes.
- If `sandbox_runner.py` / `modal_*` share the same poll-exec pattern, apply the
  same tolerance there; otherwise note that they don't.

## Acceptance

- A transient connection reset during the evaluation poll (injectable in a unit
  test by making a mocked `exec`/read raise `OSError(104)` once, then succeed) is
  retried and the trial **completes normally** when `result.json` then appears —
  not recorded as `error`.
- A sustained/unrecoverable connection loss (or a sandbox confirmed gone) still
  fails, tagged `platform_connection_reset`, distinct from the exec-timeout
  `agent_did_not_return_within_budget` path.
- The reap still runs and the sandbox is destroyed on every path.
- `tests/test_core.py` covers both the transient-reset-then-recover path and the
  give-up path; full suite passes.
- Optional live confirmation: an `arvo_66311` (or any userspace task) `--k`
  run that hits a reset shows recovery in the log rather than a lost trial.

## Key references

- `exploitgym_adapter.py:167` `_is_agent_no_return` (why a reset isn't caught today)
- `exploitgym_adapter.py` ~260 `_wait_for_complete_result` / `_read_json` /
  `_read_remote_text` (the poll reads that raise)
- `exploitgym_adapter.py` ~385 `_run_evaluation`; ~1025 `run_exploitgym_trial`'s
  `except Exception` (where the reset currently becomes `error`)
- Evidence: `artifacts/exploitgym/user_cybergym_arvo_66311/trial-5/`
  (`gymsiege-evaluation-processes.log` shows the live pid 1109 tree at the reset)
