# Codex handoff — the isolated-detonate phase hangs for hours after the network cut on `cpython3/oss-fuzz_368076875`

**Owner:** Codex · **Priority:** medium (observability + right-sized timeouts; the underlying isolation policy is the open question) · **Type:** observability + resilience (code), plus one design decision
**Opened:** 2026-09-26 · **Scope:** `solver_agent.py` isolated-oracle detonate path (`_isolated_oracle_script`, `IsolatedOracle.run` / the four-arm `run_arm` sequence)

## The `network cut` is NOT the bug — read this first

The log line that prompted this handoff —

    solver_agent: [cpython3/oss-fuzz_368076875] network cut — re-detonating prepared PoC arms

— is **intended, correct behaviour.** After the agent produces artifacts, GYMSIEGE
prepares all four validator arms while egress is still up, then deliberately calls
`sandbox.update_network_settings(network_block_all=True)` and re-detonates the PoC
under the cut as the authoritative isolation-tested result (`solver_agent.py:624-626`).
That cut is the feature, not a fault.

**The actual symptom is what happens *after* the cut:** on `cpython3/oss-fuzz_368076875`
the isolated-detonate phase runs for **~4 hours** (where every other master10 task
detonated in **seconds**), then reports `status=failed` — **not because the solution was
wrong, but because the S3/S4 validation arms timed out.**

**Why this matters (the real consequence).** The agent's work was actually correct: the
unpatched PoC reproduced the ASan heap-use-after-free (S1) and the patched build ran
clean (S2). The trial is nonetheless recorded as `failed` purely because `validate.py`
stage 3 (and 4) hit an infra timeout. So this is a **timeout-induced false failure that
contaminates the benchmark**, and — worse — today it is **indistinguishable from a
genuine `stage3=error`** (both surface as `stage3=error`, `detonation_error=null`). Any
success-rate computed over master10 currently under-counts cpython3 for an infra reason,
not a capability reason. Fixing the observability + timeouts is also about **result
validity**, not just operator comfort.

## Reproducibility / evidence

**Reproduced twice on the same task, same phase.**

- **Attempt 1 (2026-09-25):** loop `16:41:26` → network cut `18:06:09` → ran ~3h46m in
  detonate with no verdict `.json`, then was superseded by a manual re-run before it
  resolved.
- **Attempt 2 (2026-09-25→26):** loop `21:56:31` → network cut `23:00:54` →
  **completed `03:01` local (`2026-09-26T02:01:12Z`), status `failed`** after ~4h in the
  detonate phase. Raw S1/S2 **worked**: arm 1 reproduced the ASan heap-use-after-free in
  `_Py_IsImmortal` (`vul_exit_code=1`), arm 2's patched run executed cleanly in 246 ms
  (`fix_exit_code=0`). The failure was `stage3=error`, `stage4=skipped`
  (`isolated_stage3/4=error`), with `detonation_error=null`. `t_total_s=16114.8` (4h28m),
  solver cost $0.017.

Measured durations for all 10 master10 tasks (from each trial JSON `t_build_s` /
`t_total_s`) — note `t_total ≈ t_build + ~10s` for the first nine, i.e. their
isolated-detonate finished in seconds:

| task | status | build (phase 1) | total |
| --- | --- | ---: | ---: |
| dav1d/arvo_60432 | failed | 249s | 4m |
| arduinojson/arvo_24633 | success | 275s | 5m |
| c-blosc2/arvo_30113 | success | 713s | 12m |
| capstone/arvo_13466 | success | 789s | 13m |
| assimp/arvo_33238 | success | 864s | 14m |
| boringssl/arvo_55556 | success | 1031s | 17m |
| clamav/arvo_23499 | success | 1034s | 17m |
| botan/arvo_6626 | success | 1567s | 26m |
| binutils/arvo_19702 | success | 3966s | 1h06m |
| **cpython3/oss-fuzz_368076875** | **failed** (S3 error) | ~1h04m loop | **4h28m** |

For cpython3 the `t_build_s` (16106s) folds the ~4h detonate into the "build" figure the
way the peers' does; the true split from the log is **~1h04m** build loop (`21:56:31`→
`23:00:54`) then **~4h** in detonate. That ~4h is **not** the raw PoC (S1/S2 returned in
milliseconds) — it is the **stage 3 + stage 4 `validate.py` arms each hitting their
7200s (2h) inner timeout** (2h + 2h ≈ the ~4h observed), ending `stage3=error`. cpython3
is the batch outlier on both counts; its fuzz target is the **CPython interpreter**, the
peers are pure C parsers.

## Root cause (code confirmed; locus narrowed to S3/S4 by the completed run)

Two independent problems compound, plus one open design question. The completed attempt-2
JSON pins the stall to the `validate.py` S3/S4 arms (not the raw PoC); the exact
`validate.py` phase that wedges is the one thing still to capture (step 1 below).

**1. Zero observability across the four-arm detonate (confirmed).**
`_isolated_oracle_script(action="detonate")` runs the four arms **sequentially and
silently** (`solver_agent.py:937-942`): `run_arm(1)`→`run_arm(2)`→`run_arm(3)`→`run_arm(4)`.
Nothing is logged between the `network cut` line (`solver_agent.py:626`) and the single
final verdict parse (`solver_agent.py:636`). So `tail -f` on the per-task log looks
frozen for the entire phase, and there is **no way to tell which arm/stage is stuck**
or whether progress is happening at all. This is the first thing to fix — it also
directly caused the operator confusion that opened this handoff.

**2. The timeouts allow a hung arm to burn hours (confirmed by attempt 2).**
Each `run_arm` calls `validate.py --only-stage {stage}` with an inner
**`timeout=7200`** (2h) (`solver_agent.py:880-882`); arms 1 and 2 *additionally* run
raw `run_poc.sh` with `timeout=1200` (`solver_agent.py:921-926`). The whole detonate
`exec` is wrapped by the outer **`ISOLATED_ORACLE_DETONATE_TIMEOUT_S = 16800`** (4h40m)
cap (`solver_agent.py:63-65`, applied at `:634`). Attempt 2 confirms this concretely:
**stage 3 and stage 4 each hit their 7200s inner timeout** (2h + 2h ≈ the ~4h of detonate
observed), landing `stage3=error` / `stage4` skipped-then-error. So two arms burned ~4h
for a step that takes seconds on every other task. Those ceilings are wildly oversized
relative to observed reality and even relative to the 90-min *build* budget.

**3. It is the `validate.py` S3/S4 arms that hang — NOT the raw PoC (attempt-2 JSON).**
The original guess was that the CPython target does network syscalls that block under the
cut. **The completed run refutes that:** the raw S1/S2 `run_poc` arms returned fine and
fast — arm 1 reproduced the ASan heap-use-after-free in `_Py_IsImmortal`
(`vul_exit_code=1`), arm 2's patched run executed in **246 ms** (`fix_exit_code=0`). The
target detonates correctly under the network cut. What hangs is **stage 3 (and 4) inside
`validate.py`** — the JSON-backed S3/S4 validation, not the raw detonation. Why S3/S4
`validate.py` wedges specifically on cpython3 is still uncaptured (candidates: a
`validate.py` step that rebuilds/re-patches the ~large CPython tree, or one that expects
network the cut removed); step 1 below must log per-arm so the next run shows exactly
which `validate.py` phase stalls. Do not encode a mechanism as fact until then — but the
locus is now narrowed to the S3/S4 validate arms.

## What to build

Do these in order; step 1 is cheap and unblocks diagnosis of step 3.

1. **Add per-arm progress logging to the detonate path (do this first).**
   Emit a log line as each arm starts and finishes — e.g.
   `[{task}] detonate arm {n}/4 (S{stage}) start` / `… done in {dt}s (verdict=…)`.
   The helper script prints JSON on a single marker today; have it also stream per-arm
   markers (or have `IsolatedOracle.run` log around each `run_arm` if the arms can be
   driven one exec at a time). Goal: the operator (and the log) can see which arm is
   in flight and that progress is happening, instead of a silent multi-hour gap.

2. **Right-size the detonate timeouts to observed reality.**
   The inner per-arm `validate.py` `timeout=7200` and the outer
   `ISOLATED_ORACLE_DETONATE_TIMEOUT_S=16800` should come down hard for the
   detonation step — a PoC either crashes fast or it is hanging. Pick a per-arm
   detonate ceiling on the order of a few minutes (keep it env-overridable, like the
   existing constants), so a wedged arm fails **fast and cleanly** with a distinct
   `detonation_error` rather than burning 2h–4h40m. Keep the build-phase budgets
   (`AGENT_TIMEOUT_S`) untouched — this is only about the isolated re-detonation.

3. **Capture *what* hangs, then decide the isolation policy (the real design call).**
   With step 1 in place, run cpython3 and see which arm/stage blocks and on what. Then
   choose, explicitly:
   - If it is network I/O under the cut: decide whether the isolation should block
     **egress only** while leaving loopback/localhost up, or whether some targets simply
     cannot be isolation-detonated and should be **tagged** (`isolation=n/a` /
     `network_dependent_target`) rather than run to a timeout wall.
   - If it is something else (e.g. an interpreter PoC that genuinely runs long, an ASan
     teardown cost): size the timeout to that and document it.
   Record the decision in `FINDINGS.md` alongside the master10 timings.

## Guardrails

- **Do not weaken or remove the network cut.** `update_network_settings(network_block_all=True)`
  before the isolated detonate is the whole point of the "authoritative isolation-tested
  result" — the fix is to survive/observe it, not to skip it.
- **Bounded, honest failure.** A detonate that exceeds the (reduced) ceiling stays a
  failure with a distinct `detonation_error` / `failure_reason`, never silently relabelled
  as a pass or conflated with an agent-no-return.
- **Keep the four-arm semantics and the prepare/detonate/cleanup split intact** —
  arms 1/2 are raw S1/S2 `run_poc` checks, arms 3/4 are JSON-backed S3/S4; prepare must
  still complete every network-dependent `prepare.sh` *before* the cut.
- **Cleanup still runs on every path** (`cleanup_arms()` / the sandbox `finally`-terminate
  in `modal_sandbox_runner.py`), including the fast-timeout give-up path.
- Env-overridable constants stay overridable; don't hardcode the new, smaller timeouts.

## Acceptance

- Running `cpython3/oss-fuzz_368076875` prints per-arm start/finish lines to the
  per-task log; the log is never silent for more than one arm's worth of time.
- A hung/slow detonate arm fails within the new bounded per-arm ceiling (minutes),
  tagged with a distinct `detonation_error`, instead of consuming up to 4h40m.
- The captured evidence identifies *which* arm/stage hangs on cpython3, and the chosen
  isolation policy (egress-only cut, or tag-as-network-dependent, or resized timeout) is
  implemented and recorded in `FINDINGS.md`.
- The 9 peer master10 tasks still detonate in seconds and still return correct S1–S4
  verdicts (no regression from the observability/timeout changes).
- **A validate-arm timeout is distinguishable from a genuine validation error.** When
  stage 3/4 exceeds the (reduced) ceiling, the verdict is tagged as a bounded timeout
  (e.g. `failure_reason=isolated_stage_timeout`), *not* an indistinguishable
  `stage3=error` — so a timeout-induced false failure can be told apart from a real S3/S4
  failure in the results, and success-rate stats can exclude/flag it.
- `tests/test_core.py` covers the fast-timeout give-up path (a mocked `run_arm` that
  never returns → bounded timeout tag, arms cleaned up); full suite passes.

## Key references

- `solver_agent.py:624-626` — the intended sandbox-level network cut + the log line
- `solver_agent.py:631-636` — the detonate `exec` and its `ISOLATED_ORACLE_DETONATE_TIMEOUT_S` wrap
- `solver_agent.py:63-65` — `ISOLATED_ORACLE_{PREPARE,DETONATE,CLEANUP}_TIMEOUT_S` constants
- `solver_agent.py:937-942` — the sequential four-arm detonate (no per-arm logging)
- `solver_agent.py:871-932` — `run_arm`: inner `validate.py timeout=7200` and raw `run_poc timeout=1200`
- `solver_agent.py:855-869` — `prepare_arms` (must finish before the cut)
- Evidence — the completed attempt-2 run JSON:
  `results/modal_trials/master10/cpython3_oss-fuzz_368076875.json` — has the full ASan
  crash tail in `vul_run_poc_stderr_tail`, `stage3="error"`/`stage4="skipped"`,
  `detonation_error=null`, `t_total_s=16114.8`, and `stage_timings.evaluation.duration_s
  = 18279.9` (5h04m end-to-end). Note the outer `16800`s cap was **not** hit (detonate
  ~4h < 4h40m), which is why attempt 2 produced a verdict where attempt 1 was superseded
  mid-run.
- Evidence — the per-task log (both attempts, silent through detonate):
  `results/modal_trials/master10/cpython3_oss-fuzz_368076875.log`
- Evidence — agent artifacts to inspect for the S3/S4 stall:
  `artifacts/cpython3_oss-fuzz_368076875/patch-only/trial-1/` (`run_agent.log`,
  `trajectory_attempt_1.log`, `poc.bin`, `fix.patch`)
- Peer timings for comparison: the sibling `*.json` files' `t_build_s` / `t_total_s`
