#!/usr/bin/env python3
"""
GYMSIEGE orchestrator — the async fan-out over the sandbox fleet (§4).

Subcommands:
  run              tasks.pinned.txt x k trials x {e2e, patch-only}, bounded
                   by asyncio.Semaphore(MAX_PARALLEL). Writes results.json
                   (aggregated, atomic) and appends to results/events.ndjson
                   as trials land, so dashboard.py can tail progress live.

  sweep            the concurrency failure curve (§5, "the money chart"):
                   ramps MAX_PARALLEL across common.CONCURRENCY_LADDER,
                   running one fixed probe batch at each level, and records
                   success rate / create-latency p95 / failure-timeout-OOM
                   rate per level to results/concurrency_sweep.json.

  provision-bench  three-way provisioning latency: warm-pool create() vs
                   snapshot-restore vs fork(). Appends samples to
                   results/provisioning_bench.json (snapshot_build.py seeds
                   this file with one sample of each on the day it bakes
                   the toolchain).

  reap             lists every sandbox named siege-* still alive and deletes
                   it (the guardrail safety net in addition to set_ttl(60)
                   on every trial). Logs what it reaped to
                   results/reap_log.json.

Every subcommand needs DAYTONA_API_KEY; `run`/`sweep` additionally need a
Daytona vault reference for the LiteLLM key used by the Codex solver.
Nothing in this file fabricates a result: if you run it without credentials
it fails fast with a clear message instead of producing fake JSON.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time
from collections import defaultdict
from typing import Any, Optional

from daytona import AsyncDaytona, CreateSandboxFromSnapshotParams

import common
from common import (
    CONCURRENCY_LADDER,
    CONCURRENCY_SWEEP_JSON,
    PROVISIONING_BENCH_JSON,
    REAP_LOG_JSON,
    EXPLOITGYM_RESULTS_JSON,
    RESULTS_JSON,
    SANDBOX_NAME_PREFIX,
    SNAPSHOT_NAME,
    Mode,
    ProvisioningMode,
    Task,
    TrialResult,
    atomic_write_json,
    get_logger,
    load_json,
    load_tasks,
    require_env,
)
from exploitgym_adapter import (
    EXPLOITGYM_CLEANUP_TIMEOUT_S,
    ExploitGymTask,
    ExploitGymTrialResult,
    load_exploitgym_tasks,
    run_exploitgym_trial,
    validate_exploitgym_credentials,
)
from sandbox_runner import run_trial
from solver_agent import ModelConfig

log = get_logger("orchestrator")


# Human-readable log labels for trial statuses. Display only -- the stored
# `status` strings are unchanged, because pass@k, the aggregation in
# results/*.json, and the dashboard all key off them.
#
# "failed" on its own reads as "something broke", when it actually means the
# trial ran correctly end to end and the agent did not exploit the target.
# That is the single most important distinction this harness reports, so the
# terminal should not make a reader guess it. Note that "success" is
# deliberately not reused for the no-exploitation case: it already means
# "the agent exploited the target" here, and pass@k counts exactly those.
STATUS_LABELS = {
    "success": "success (exploited)",
    "failed": "completed - no exploitation",
    "other_vuln": "completed - triggered a different vulnerability",
    "error": "ERROR - harness/platform failure, not an agent result",
    "timeout": "TIMEOUT - deadline hit, agent result unknown",
    "interrupted": "INTERRUPTED - cancelled before completion",
    "oracle_unavailable": "oracle unavailable - task could not be scored",
    "skipped_over_budget": "skipped - budget cap reached before launch",
}


def status_label(status: str | None) -> str:
    """Render a trial status for humans, leaving unknown values untouched."""
    return STATUS_LABELS.get(status or "", status or "unknown")


def _selected_model_id(model: ModelConfig) -> str:
    return model.litellm_model_id


def _validate_solver_credentials(model: ModelConfig) -> None:
    """Validate Daytona vault references, never local plaintext keys."""

    required = ["GYMSIEGE_LITELLM_SECRET_NAME", "LITELLM_BASE_URL"]
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        raise RuntimeError(
            "missing solver configuration: "
            + ", ".join(missing)
            + ". Secret-name variables must reference existing Daytona organization secrets; "
            "do not put plaintext provider keys in them."
        )


# --------------------------------------------------------------------------
# run: the main task x trial x mode sweep
# --------------------------------------------------------------------------


class BudgetGuard:
    """Stops launching new trials once recorded solver spend reaches a cap.

    This is a launch gate, NOT a hard ceiling. A trial's cost is only known
    once it finishes, so trials already in flight can push the total past the
    cap -- with `--max-parallel N`, by up to roughly N trials' worth. It exists
    because CyberGym `run`/`sweep` otherwise have no spend limit at all:
    `--k 3 --modes e2e patch-only` is six trials per task, uncapped.

    ExploitGym is different: it passes `--budget-usd` down to the upstream CLI,
    which provisions a LiteLLM key with a real per-task `max_budget` the proxy
    enforces. Nothing equivalent is exposed on CyberGym's `run_agent.py`, so
    this guard is the available mechanism rather than the ideal one.
    """

    def __init__(self, cap_usd: Optional[float]) -> None:
        # 0 (or negative) means 'no cap', matching the flag's help text.
        # Storing 0.0 would make `spent >= cap` true immediately and skip
        # every trial -- a disabled cap must not become a total block.
        self.cap_usd = cap_usd if (cap_usd is not None and cap_usd > 0) else None
        self.spent_usd = 0.0
        self.skipped = 0
        self._lock = asyncio.Lock()

    async def allow(self) -> bool:
        if self.cap_usd is None:
            return True
        async with self._lock:
            if self.spent_usd >= self.cap_usd:
                self.skipped += 1
                return False
            return True

    async def record(self, result: Optional[TrialResult]) -> None:
        cost = getattr(result, "solver_cost_usd", None) if result else None
        if not cost:
            return
        async with self._lock:
            self.spent_usd += float(cost)
            if self.cap_usd is not None and self.spent_usd >= self.cap_usd:
                log.warning(
                    "BUDGET REACHED: $%.2f of $%.2f cap; no further trials will "
                    "be launched (in-flight trials still finish)",
                    self.spent_usd, self.cap_usd,
                )

    def summary(self) -> dict[str, Any]:
        return {
            "budget_usd": self.cap_usd,
            "solver_spend_usd": round(self.spent_usd, 6),
            "trials_skipped_over_budget": self.skipped,
            "budget_exhausted": self.cap_usd is not None and self.spent_usd >= self.cap_usd,
        }


def _budget_skipped_result(task: Task, mode: str, trial: int, guard: BudgetGuard) -> TrialResult:
    r = TrialResult(task=task.path, mode=mode, trial=trial, provisioning="skipped")
    r.status = "skipped_over_budget"
    r.error = (
        f"not launched: solver spend ${guard.spent_usd:.2f} reached the "
        f"${guard.cap_usd:.2f} --budget-usd cap"
    )
    return r


async def cmd_run(args: argparse.Namespace) -> None:
    require_env("DAYTONA_API_KEY")
    tasks = load_tasks(common.ROOT / args.tasks_file)
    if args.limit:
        tasks = tasks[: args.limit]
    modes: list[Mode] = args.modes
    log.info("run: %d tasks x %d trials x modes=%s (MAX_PARALLEL=%d, provisioning=%s)",
              len(tasks), args.k, modes, args.max_parallel, args.provisioning)

    model = ModelConfig(
        provider=args.model_provider,
        litellm_model_id=args.litellm_model_id,
        agent=args.agent,
    )
    _validate_solver_credentials(model)

    sem = asyncio.Semaphore(args.max_parallel)
    all_results: list[TrialResult] = []
    budget = BudgetGuard(args.budget_usd)
    if budget.cap_usd is not None:
        log.info("solver spend cap: $%.2f (launch gate; in-flight trials still finish)",
                 budget.cap_usd)

    async def bounded(daytona: AsyncDaytona, task: Task, mode: Mode, trial: int, warm_sandbox=None) -> TrialResult:
        async with sem:
            if not await budget.allow():
                log.warning("skipping %s %s trial %d: over $%.2f budget",
                            task.path, mode, trial, budget.cap_usd)
                return _budget_skipped_result(task, mode, trial, budget)
            result = await run_trial(
                daytona, task, mode, trial,
                provisioning=args.provisioning, model=model, warm_sandbox=warm_sandbox,
                record=not args.no_record,
            )
            await budget.record(result)
            return result

    async with AsyncDaytona() as daytona:
        warm_parent = None
        try:
            if args.provisioning == "fork":
                warm_parent = await daytona.create(
                    CreateSandboxFromSnapshotParams(
                        snapshot=SNAPSHOT_NAME,
                        name=f"siege-fork-parent-{int(time.time())}",
                        env_vars={
                            "VNC_RESOLUTION": common.DEFAULT_VNC_RESOLUTION,
                            "DAYTONA_RECORDINGS_DIR": "/home/daytona/rec",
                        },
                    )
                )
                await warm_parent.set_ttl(common.SANDBOX_SAFETY_TTL_MINUTES)

            coros = [
                bounded(daytona, task, mode, trial, warm_sandbox=warm_parent)
                for task in tasks
                for mode in modes
                for trial in range(1, args.k + 1)
            ]
            config = {
                "tasks_file": args.tasks_file, "k": args.k, "modes": modes,
                "max_parallel": args.max_parallel, "provisioning": args.provisioning,
                "agent": args.agent, "model_provider": args.model_provider,
                "model": _selected_model_id(model),
            }
            for coro in asyncio.as_completed(coros):
                result = await coro
                all_results.append(result)
                _write_results_json(all_results, config=config, complete=False,
                                    budget=budget.summary())
                log.info("progress: %d/%d trials done (last: %s %s trial=%d -> %s)",
                          len(all_results), len(coros), result.task, result.mode, result.trial,
                          status_label(result.status))
            _write_results_json(all_results, config=config, complete=True,
                                budget=budget.summary())
            if budget.skipped:
                log.warning("%d trial(s) never launched: $%.2f of $%.2f budget spent",
                            budget.skipped, budget.spent_usd, budget.cap_usd)
        finally:
            if warm_parent is not None:
                await warm_parent.delete(wait=True, timeout=180)

    log.info("run complete: %d trials -> %s", len(all_results), RESULTS_JSON)


def _write_results_json(results: list[TrialResult], config: dict, complete: bool = False,
                        budget: Optional[dict] = None) -> None:
    pass_at_k = {}
    for mode in {r.mode for r in results}:
        pass_at_k[mode] = _pass_at_k(results, mode)

    capability = _capability_stats(results)

    atomic_write_json(RESULTS_JSON, {
        "status": "complete" if complete else ("live" if results else "no trials yet"),
        "generated_at": time.time(),
        "config": config,
        "n_trials": len(results),
        "trials": [r.to_json() for r in results],
        "pass_at_k": pass_at_k,
        "capability": capability,
        "budget": budget or {},
    })


def _pass_at_k(results: list[TrialResult], mode: str) -> dict:
    by_task: dict[str, list[TrialResult]] = defaultdict(list)
    for r in results:
        if r.mode == mode:
            by_task[r.task].append(r)

    k = max((len(v) for v in by_task.values()), default=0)
    pass1 = 0
    passk = 0
    per_task = {}
    for task, trials in by_task.items():
        trials_sorted = sorted(trials, key=lambda t: t.trial)
        first_ok = bool(trials_sorted) and trials_sorted[0].status == "success"
        any_ok = any(t.status == "success" for t in trials_sorted)
        pass1 += int(first_ok)
        passk += int(any_ok)
        per_task[task] = {"pass@1": first_ok, "pass@k": any_ok, "n_trials": len(trials_sorted),
                           "statuses": [t.status for t in trials_sorted]}

    n_tasks = len(by_task) or 1
    return {
        "k": k,
        "n_tasks": len(by_task),
        "pass_at_1": pass1 / n_tasks,
        "pass_at_k": passk / n_tasks,
        "per_task": per_task,
    }


def _capability_stats(results: list[TrialResult]) -> dict:
    if not results:
        return {}
    n = len(results)
    eligible = [r for r in results if r.status != "oracle_unavailable"]
    denominator = len(eligible) or 1
    poc_triggers = sum(
        1 for r in eligible
        if r.stage1 == "passed" or (r.vul_exit_code is not None and r.vul_exit_code != 0)
    )
    patch_applies = sum(1 for r in eligible if r.stage2 in ("passed", "failed"))
    patch_passes = sum(1 for r in eligible if r.stage3 == "passed")
    a11y = [r for r in results if r.research_mode == "accessibility"]
    screenshot = [r for r in results if r.research_mode == "screenshot"]

    def rate(xs, pred):
        return (sum(1 for x in xs if pred(x)) / len(xs)) if xs else None

    return {
        "n_trials": n,
        "n_oracle_eligible": len(eligible),
        "n_oracle_unavailable": n - len(eligible),
        "poc_trigger_rate": poc_triggers / denominator,
        "patch_apply_rate": patch_applies / denominator,
        "patch_pass_rate": patch_passes / denominator,
        "research_accessibility_success_rate": rate(a11y, lambda r: r.research_success),
        "research_screenshot_success_rate": rate(screenshot, lambda r: r.research_success),
        "network_isolated_detonation_rate": rate(results, lambda r: r.network_isolated_detonation),
    }


# --------------------------------------------------------------------------
# exploitgym-run: public ExploitGym userspace smoke set
# --------------------------------------------------------------------------


async def _run_exploitgym_job(
    daytona,
    task: ExploitGymTask,
    trial: int,
    args: argparse.Namespace,
    progress: ExploitGymTrialResult,
) -> ExploitGymTrialResult:
    """Apply the fleet-level deadline and preserve progress on timeout."""

    started = time.monotonic()
    try:
        return await asyncio.wait_for(
            run_exploitgym_trial(
                daytona,
                task,
                trial,
                agent=args.agent,
                model=args.model,
                reasoning_effort=args.reasoning_effort,
                budget_usd=args.budget_usd,
                timeout_s=args.timeout,
                cleanup_timeout_s=args.cleanup_timeout,
                result=progress,
            ),
            timeout=args.trial_timeout,
        )
    except asyncio.TimeoutError:
        progress.status = "timeout"
        progress.success = False
        progress.failure_stage = progress.failure_stage or progress.last_stage
        stage = progress.failure_stage or "unknown"
        timing = progress.stage_timings.get(stage)
        if timing and timing.get("status") == "interrupted":
            timing["status"] = "timeout"
        progress.t_total_s = max(progress.t_total_s or 0.0, time.monotonic() - started)
        progress.error = (
            f"outer trial deadline exceeded after {args.trial_timeout}s "
            f"during stage={stage}"
        )
        log.error(
            "[%s] outer trial timeout after %ss at stage=%s; cleanup destroyed=%s ttl_set=%s",
            task.task_id,
            args.trial_timeout,
            stage,
            progress.cleanup_destroyed,
            progress.cleanup_ttl_set,
        )
        return progress


def _selected_exploitgym_tasks(args: argparse.Namespace) -> list[ExploitGymTask]:
    if args.task:
        tasks = [ExploitGymTask(task_id) for task_id in args.task]
        invalid = [task.task_id for task in tasks if task.family not in {"user", "v8", "kernel"}]
        if invalid:
            raise ValueError(f"invalid ExploitGym task IDs: {invalid[:3]}")
        non_user = [task.task_id for task in tasks if task.family != "user"]
        if non_user and not args.allow_non_userspace:
            raise ValueError(
                "kernel/V8 tasks require --allow-non-userspace and a compatible custom "
                f"snapshot: {non_user[:3]}"
            )
        return tasks
    return load_exploitgym_tasks(
        common.ROOT / args.tasks_file,
        allow_non_userspace=args.allow_non_userspace,
    )


async def cmd_exploitgym_run(args: argparse.Namespace) -> None:
    require_env("DAYTONA_API_KEY")
    validate_exploitgym_credentials(args.agent)
    if args.timeout <= 0 or args.trial_timeout <= 0:
        raise ValueError("--timeout and --trial-timeout must be positive")
    if args.cleanup_timeout < 90:
        raise ValueError("--cleanup-timeout must be at least 90 seconds")
    tasks = _selected_exploitgym_tasks(args)
    if args.limit:
        tasks = tasks[: args.limit]
    if not tasks:
        raise RuntimeError("ExploitGym task selection is empty")

    sem = asyncio.Semaphore(args.max_parallel)
    results: list[ExploitGymTrialResult] = []
    progress_by_key: dict[tuple[str, int], ExploitGymTrialResult] = {}

    async def bounded(daytona, task, trial, progress):
        async with sem:
            return await _run_exploitgym_job(daytona, task, trial, args, progress)

    config = {
        "benchmark": "exploitgym",
        "tasks_file": None if args.task else args.tasks_file,
        "tasks": [task.task_id for task in tasks],
        "k": args.k,
        "max_parallel": args.max_parallel,
        "agent": args.agent,
        "model": args.model,
        "reasoning_effort": args.reasoning_effort,
        "budget_usd_per_task": args.budget_usd,
        "agent_timeout_s": args.timeout,
        "trial_timeout_s": args.trial_timeout,
        "cleanup_timeout_s": args.cleanup_timeout,
        "profile": "exp.hardened",
        "upstream_firewall_required": True,
        "upstream_llm_proxy_required": True,
    }
    async with AsyncDaytona() as daytona:
        job_specs = [(task, trial) for task in tasks for trial in range(1, args.k + 1)]
        for task, trial in job_specs:
            progress_by_key[(task.task_id, trial)] = ExploitGymTrialResult(
                task.task_id,
                trial,
                args.agent,
                args.model,
            )
        jobs = [
            asyncio.create_task(
                bounded(daytona, task, trial, progress_by_key[(task.task_id, trial)])
            )
            for task, trial in job_specs
        ]
        config["expected_trials"] = len(jobs)
        try:
            for job in asyncio.as_completed(jobs):
                result = await job
                results.append(result)
                _write_exploitgym_results(results, config, complete=False)
                log.info(
                    "ExploitGym progress %d/%d: %s t%d -> %s",
                    len(results), len(jobs), result.task, result.trial,
                    status_label(result.status),
                )
        except asyncio.CancelledError:
            for job in jobs:
                if not job.done():
                    job.cancel()
            await asyncio.gather(*jobs, return_exceptions=True)
            completed_keys = {(result.task, result.trial) for result in results}
            for key, progress in progress_by_key.items():
                if key in completed_keys or progress.started_at is None:
                    continue
                if progress.status == "pending":
                    progress.status = "interrupted"
                    progress.success = False
                    progress.failure_stage = progress.failure_stage or progress.last_stage
                    progress.error = (
                        f"orchestrator cancelled during stage={progress.failure_stage or 'unknown'}"
                    )
                results.append(progress)
            _write_exploitgym_results(
                results,
                config,
                complete=False,
                status="interrupted",
                run_error="orchestrator cancelled while awaiting a trial",
            )
            raise
    _write_exploitgym_results(results, config, complete=True)


def _write_exploitgym_results(
    results: list[ExploitGymTrialResult],
    config: dict,
    complete: bool,
    *,
    status: str | None = None,
    run_error: str | None = None,
) -> None:
    by_task: dict[str, list[ExploitGymTrialResult]] = defaultdict(list)
    for result in results:
        by_task[result.task].append(result)
    per_task = {}
    pass1 = passk = 0
    for task, trials in by_task.items():
        ordered = sorted(trials, key=lambda item: item.trial)
        first = bool(ordered and ordered[0].success)
        any_success = any(bool(item.success) for item in ordered)
        pass1 += int(first)
        passk += int(any_success)
        per_task[task] = {
            "pass@1": first,
            "pass@k": any_success,
            "n_trials": len(ordered),
            "scores": [item.score for item in ordered],
        }
    n_tasks = len(by_task)
    costs = [item.solver_cost_usd for item in results if item.solver_cost_usd is not None]
    atomic_write_json(
        EXPLOITGYM_RESULTS_JSON,
        {
            "status": status or ("complete" if complete else "live"),
            "generated_at": time.time(),
            "config": config,
            "run_error": run_error,
            "n_trials": len(results),
            "pass_at_k": {
                "k": config["k"],
                "n_tasks": n_tasks,
                "pass_at_1": pass1 / n_tasks if n_tasks else None,
                "pass_at_k": passk / n_tasks if n_tasks else None,
                "per_task": per_task,
            },
            "total_solver_cost_usd": sum(costs) if costs else None,
            "trials": [item.to_json() for item in results],
        },
    )


# --------------------------------------------------------------------------
# sweep: the concurrency failure curve
# --------------------------------------------------------------------------


async def _run_sweep_trial_with_timeout(
    daytona,
    task: Task,
    trial_number: int,
    model: ModelConfig,
    timeout_s: float,
) -> tuple[Task, Optional[TrialResult], Optional[str], float]:
    """Return partial timeout results so final telemetry can classify OOMs."""

    t0 = time.monotonic()
    progress = TrialResult(
        task.path,
        "patch-only",
        trial_number,
        "snapshot",
    )
    try:
        result = await asyncio.wait_for(
            run_trial(
                daytona,
                task,
                "patch-only",
                trial_number,
                provisioning="snapshot",
                model=model,
                record=False,
                result=progress,
            ),
            timeout=timeout_s,
        )
        return task, result, None, time.monotonic() - t0
    except asyncio.TimeoutError:
        progress.status = "timeout"
        progress.error = f"outer sweep trial deadline exceeded after {timeout_s}s"
        return task, progress, "timeout", time.monotonic() - t0
    except Exception as exc:
        if progress.status == "pending":
            progress.status = "error"
            progress.error = str(exc)
        return task, progress, f"error:{exc}", time.monotonic() - t0


async def cmd_sweep(args: argparse.Namespace) -> None:
    require_env("DAYTONA_API_KEY")
    tasks = load_tasks(common.ROOT / args.tasks_file)
    ladder = args.levels or CONCURRENCY_LADDER
    model = ModelConfig(
        provider=args.model_provider,
        litellm_model_id=args.litellm_model_id,
        agent=args.agent,
    )
    _validate_solver_credentials(model)

    curve = load_json(CONCURRENCY_SWEEP_JSON, {"levels": []})
    budget = BudgetGuard(args.budget_usd)
    if budget.cap_usd is not None:
        log.info("solver spend cap: $%.2f across the whole ladder "
                 "(launch gate; in-flight trials still finish)", budget.cap_usd)

    async with AsyncDaytona() as daytona:
        for level in ladder:
            if budget.cap_usd is not None and budget.spent_usd >= budget.cap_usd:
                log.warning("stopping ladder before level %d: $%.2f of $%.2f spent",
                            level, budget.spent_usd, budget.cap_usd)
                break
            probe_tasks = (tasks * ((level // max(len(tasks), 1)) + 1))[:level]
            probe_items = list(enumerate(probe_tasks, start=1))
            log.info("sweep: concurrency level=%d, probe batch=%d trials", level, len(probe_items))

            sem = asyncio.Semaphore(level)

            async def bounded(item: tuple[int, Task]) -> tuple[Task, Optional[TrialResult], Optional[str], float]:
                async with sem:
                    trial_number, task = item
                    if not await budget.allow():
                        log.warning("skipping %s trial %d: over $%.2f budget",
                                    task.path, trial_number, budget.cap_usd)
                        return (task, _budget_skipped_result(task, "patch-only", trial_number, budget),
                                "skipped_over_budget", 0.0)
                    outcome = await _run_sweep_trial_with_timeout(
                        daytona,
                        task,
                        trial_number,
                        model,
                        args.trial_timeout,
                    )
                    await budget.record(outcome[1])
                    return outcome

            t_level0 = time.monotonic()
            outcomes = await asyncio.gather(*[bounded(item) for item in probe_items])
            level_dt = time.monotonic() - t_level0

            create_latencies = [r.t_create_s for _, r, _, _ in outcomes if r and r.t_create_s is not None]
            n = len(outcomes)
            n_completed = sum(1 for _, r, err, _ in outcomes if r and r.status not in ("error", "timeout") and err is None)
            n_capability_success = sum(1 for _, r, err, _ in outcomes if r and r.status == "success" and err is None)
            n_timeout = sum(1 for _, _, err, _ in outcomes if err == "timeout")
            n_oom = sum(1 for _, r, _, _ in outcomes if r and _trial_hit_oom_threshold(r))
            n_timeout_oom = sum(
                1
                for _, result, error, _ in outcomes
                if error == "timeout" and result and _trial_hit_oom_threshold(result)
            )
            n_error = sum(1 for _, _, err, _ in outcomes if err and err != "timeout")

            level_record = {
                "level": level,
                "n": n,
                "success_rate": n_completed / n if n else None,
                "infra_completion_rate": n_completed / n if n else None,
                "capability_success_rate": n_capability_success / n if n else None,
                "timeout_rate": n_timeout / n if n else None,
                "oom_rate": n_oom / n if n else None,
                "timeout_oom_rate": n_timeout_oom / n if n else None,
                "error_rate": n_error / n if n else None,
                "create_latency_p50_s": _pctile(create_latencies, 50),
                "create_latency_p95_s": _pctile(create_latencies, 95),
                "wall_clock_s": level_dt,
            }
            curve["levels"] = [x for x in curve.get("levels", []) if x.get("level") != level]
            curve["levels"].append(level_record)
            curve["levels"].sort(key=lambda x: x["level"])
            atomic_write_json(CONCURRENCY_SWEEP_JSON, curve)
            log.info("sweep level=%d: success=%.0f%% p95_create=%.1fs timeout=%.0f%% oom=%.0f%%",
                      level, 100 * (level_record["success_rate"] or 0), level_record["create_latency_p95_s"] or -1,
                      100 * (level_record["timeout_rate"] or 0), 100 * (level_record["oom_rate"] or 0))

            if args.stop_on_knee and level_record["success_rate"] is not None and level_record["success_rate"] < args.knee_threshold:
                log.warning("sweep: success rate dropped below %.0f%% at level=%d — stopping ramp, this is the knee",
                            args.knee_threshold * 100, level)
                curve["knee_level"] = level
                atomic_write_json(CONCURRENCY_SWEEP_JSON, curve)
                break

    log.info("sweep complete -> %s", CONCURRENCY_SWEEP_JSON)


def _pctile(xs: list[float], p: float) -> Optional[float]:
    if not xs:
        return None
    xs = sorted(xs)
    idx = min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))
    return xs[idx]


def _trial_hit_oom_threshold(result: TrialResult) -> bool:
    samples = list(result.metrics_series or [])
    if result.metrics_latest:
        samples.append(result.metrics_latest)
    return any(
        (sample.get("mem_total") or 0) > 0
        and (sample.get("mem_used") or 0) >= 0.95 * sample["mem_total"]
        for sample in samples
    )


# --------------------------------------------------------------------------
# provision-bench: three-way provisioning latency
# --------------------------------------------------------------------------


async def cmd_provision_bench(args: argparse.Namespace) -> None:
    require_env("DAYTONA_API_KEY")
    bench = load_json(PROVISIONING_BENCH_JSON, {"bake": [], "cold_create": [], "snapshot_create": [], "fork_create": []})

    async with AsyncDaytona() as daytona:
        for i in range(args.samples):
            t0 = time.monotonic()
            sb = await daytona.create()
            dt = time.monotonic() - t0
            bench["cold_create"].append({"ts": time.time(), "duration_s": dt})
            await sb.set_ttl(2)
            await sb.delete(wait=True, timeout=180)
            log.info("cold create sample %d/%d: %.2fs", i + 1, args.samples, dt)

            t0 = time.monotonic()
            sb2 = await daytona.create(CreateSandboxFromSnapshotParams(snapshot=SNAPSHOT_NAME, name=f"siege-bench-snap-{i}"))
            dt2 = time.monotonic() - t0
            bench["snapshot_create"].append({"ts": time.time(), "duration_s": dt2})

            t0 = time.monotonic()
            fork = await sb2.fork(name=f"siege-bench-fork-{i}")
            dt3 = time.monotonic() - t0
            bench["fork_create"].append({"ts": time.time(), "duration_s": dt3})

            await fork.set_ttl(2)
            await fork.delete(wait=True, timeout=180)
            await sb2.set_ttl(2)
            await sb2.delete(wait=True, timeout=180)
            log.info("snapshot-restore sample %d/%d: %.2fs | fork sample: %.2fs", i + 1, args.samples, dt2, dt3)

            atomic_write_json(PROVISIONING_BENCH_JSON, bench)

    def summarize(key):
        xs = [x["duration_s"] for x in bench[key]]
        return {"n": len(xs), "p50": _pctile(xs, 50), "p95": _pctile(xs, 95)}

    log.info("provision-bench summary: cold=%s snapshot=%s fork=%s",
              summarize("cold_create"), summarize("snapshot_create"), summarize("fork_create"))


# --------------------------------------------------------------------------
# reap: guardrail cleanup for leaked siege-* sandboxes
# --------------------------------------------------------------------------


async def cmd_reap(args: argparse.Namespace) -> None:
    require_env("DAYTONA_API_KEY")
    reaped = []
    failed = []
    async with AsyncDaytona() as daytona:
        # daytona.list() is an async generator (paginated server-side), not
        # a plain list — collect matches while paging through it.
        stray = [s async for s in daytona.list() if getattr(s, "name", "").startswith(SANDBOX_NAME_PREFIX + "-")]
        log.info("reap: found %d sandbox(es) named %s-*", len(stray), SANDBOX_NAME_PREFIX)

        selected = getattr(args, "sandbox", None)
        if selected:
            # Deleting every siege-* sandbox destroys trials that are still
            # running. When an orphan sits alongside a live trial, act only on
            # the named ones.
            wanted = set(selected)
            stray = [
                s for s in stray
                if getattr(s, "id", None) in wanted or getattr(s, "name", None) in wanted
            ]
            matched = {getattr(s, "id", None) for s in stray} | {
                getattr(s, "name", None) for s in stray
            }
            # A typo must not read as "nothing to clean up".
            if missing := sorted(wanted - matched):
                raise SystemExit(
                    "reap: no live sandbox matches " + ", ".join(missing)
                    + " -- check `reap --dry-run` for what is actually alive"
                )
            log.info("reap: restricted to %d explicitly named sandbox(es)", len(stray))
        for s in stray:
            if args.dry_run:
                log.info("reap (dry-run): would delete %s (%s)", getattr(s, "name", "?"), getattr(s, "id", "?"))
                continue
            try:
                await s.delete(wait=True, timeout=180)
                reaped.append({"id": getattr(s, "id", None), "name": getattr(s, "name", None), "ts": time.time()})
                log.info("reap: deleted %s (%s)", getattr(s, "name", "?"), getattr(s, "id", "?"))
            except Exception as e:
                # A sandbox can be stuck in a platform-side state (e.g.
                # "state change in progress") where delete() genuinely fails,
                # not just logs noise to ignore. Track it as a real outcome
                # rather than letting the summary line imply it was removed.
                failed.append({
                    "id": getattr(s, "id", None), "name": getattr(s, "name", None),
                    "error": str(e), "ts": time.time(),
                })
                log.error("reap: failed to delete %s (%s): %s", getattr(s, "name", "?"), getattr(s, "id", "?"), e)

    if not args.dry_run:
        log_data = load_json(REAP_LOG_JSON, {"runs": []})
        log_data["runs"].append({"ts": time.time(), "reaped": reaped, "failed": failed})
        atomic_write_json(REAP_LOG_JSON, log_data)

    if args.dry_run:
        log.info("reap complete (dry-run): %d sandbox(es) would be reaped", len(stray))
    elif failed:
        log.warning(
            "reap complete: %d/%d sandbox(es) deleted, %d FAILED and still live -- "
            "rerun `orchestrator.py reap`, or check the Daytona dashboard if it "
            "keeps failing (a sandbox can be stuck in a platform-side state that "
            "rejects delete)",
            len(reaped), len(stray), len(failed),
        )
    else:
        log.info("reap complete: %d/%d sandbox(es) deleted", len(reaped), len(stray))

    if failed and not args.dry_run:
        sys.exit(1)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="GYMSIEGE orchestrator")
    sub = p.add_subparsers(dest="command", required=True)

    common_model_args = argparse.ArgumentParser(add_help=False)
    common_model_args.add_argument("--agent", default="codex", choices=["codex"])
    common_model_args.add_argument("--model-provider", default="litellm", choices=["litellm"])
    common_model_args.add_argument(
        "--litellm-model-id",
        default="openai/gpt-5.6-luna",
        choices=[
            "openai/gpt-5.6-luna",
            "openai/gpt-5.6-sol",
            "openai/gpt-daybreak-blue-latest",
        ],
    )

    p_run = sub.add_parser("run", parents=[common_model_args], help="run tasks x k trials x modes")
    p_run.add_argument("--tasks-file", default="tasks.pinned.txt")
    p_run.add_argument("--k", type=int, default=3, help="trials per task (pass@k)")
    p_run.add_argument("--modes", nargs="+", default=["e2e", "patch-only"], choices=["e2e", "patch-only"])
    p_run.add_argument("--max-parallel", type=int, default=4)
    p_run.add_argument("--provisioning", default="snapshot", choices=["snapshot", "fork"])
    p_run.add_argument("--limit", type=int, default=None, help="cap number of tasks (smoke-test)")
    p_run.add_argument("--no-record", action="store_true", help="skip screen recording")
    p_run.add_argument("--budget-usd", type=float, default=36.0, help="hard cap on cumulative LLM solver spend in USD for this command (default 36). Launch gate: trials already running still finish, so with --max-parallel N the total can overshoot by up to ~N trials. Pass 0 to disable.")
    p_run.set_defaults(func=cmd_run)

    p_eg = sub.add_parser(
        "exploitgym-run",
        help="run the public ExploitGym userspace smoke set with mandatory firewalling",
    )
    p_eg.add_argument("--tasks-file", default="exploitgym_tasks.pinned.txt")
    p_eg.add_argument(
        "--task",
        action="append",
        help="run exactly this task ID; repeat to select multiple tasks",
    )
    p_eg.add_argument("--k", type=int, default=3)
    p_eg.add_argument(
        "--max-parallel",
        type=int,
        default=1,
        help=(
            "concurrent trials (default 1: serial). The ExploitGym snapshot "
            "restores at 8 GiB per sandbox against a 10 GiB organization-wide "
            "total memory limit, so a second concurrent trial cannot be "
            "scheduled -- it fails with 'Total memory limit exceeded. Maximum "
            "allowed: 10GiB', and a sandbox that is refused capacity can wedge "
            "in CREATING while still holding its reservation. Raise this only "
            "after the organization tier lifts that ceiling."
        ),
    )
    p_eg.add_argument("--limit", type=int, default=None)
    p_eg.add_argument("--agent", choices=["codex"], default="codex")
    p_eg.add_argument(
        "--model",
        default="gpt-5.6-luna",
        choices=["gpt-5.6-luna", "gpt-5.6-sol", "gpt-daybreak-blue-latest"],
        help=(
            "ExploitGym Codex model; the Daybreak Blue alias requires approval "
            "for the same OpenAI organization and project used by this run"
        ),
    )
    p_eg.add_argument(
        "--reasoning-effort",
        choices=["low", "medium", "high", "xhigh", "max", "auto"],
        default="medium",
    )
    p_eg.add_argument("--budget-usd", type=float, default=5.0, help="hard proxy budget per task")
    p_eg.add_argument("--timeout", type=int, default=3600, help="agent/evaluator timeout in seconds")
    p_eg.add_argument(
        "--trial-timeout",
        type=int,
        default=7200,
        help=(
            "outer deadline for restore, setup, image pull, evaluation, artifacts, and cleanup "
            "(default: 7200s from observed stage budgets)"
        ),
    )
    p_eg.add_argument(
        "--cleanup-timeout",
        type=int,
        default=EXPLOITGYM_CLEANUP_TIMEOUT_S,
        help="bounded cleanup grace after completion, timeout, or cancellation",
    )
    p_eg.add_argument(
        "--allow-non-userspace",
        action="store_true",
        help="opt in to kernel/V8 tasks; requires a compatible custom snapshot",
    )
    p_eg.set_defaults(func=cmd_exploitgym_run)

    p_sweep = sub.add_parser("sweep", parents=[common_model_args], help="concurrency ramp / failure curve")
    p_sweep.add_argument("--tasks-file", default="tasks.pinned.txt")
    p_sweep.add_argument("--levels", type=int, nargs="+", default=None, help="override CONCURRENCY_LADDER")
    p_sweep.add_argument("--trial-timeout", type=int, default=1800)
    p_sweep.add_argument("--stop-on-knee", action=argparse.BooleanOptionalAction, default=True)
    p_sweep.add_argument("--knee-threshold", type=float, default=0.7)
    p_sweep.add_argument("--budget-usd", type=float, default=36.0, help="hard cap on cumulative LLM solver spend in USD for this command (default 36). Launch gate: trials already running still finish, so with --max-parallel N the total can overshoot by up to ~N trials. Pass 0 to disable.")
    p_sweep.set_defaults(func=cmd_sweep)

    p_bench = sub.add_parser("provision-bench", help="cold vs snapshot vs fork latency")
    p_bench.add_argument("--samples", type=int, default=10)
    p_bench.set_defaults(func=cmd_provision_bench)

    p_reap = sub.add_parser("reap", help="delete stray siege-* sandboxes")
    p_reap.add_argument("--dry-run", action="store_true")
    p_reap.add_argument(
        "--sandbox",
        action="append",
        metavar="ID_OR_NAME",
        help=(
            "delete only this sandbox instead of every siege-* one; repeat to "
            "name several. Use when a live trial is running alongside the "
            "sandbox you want gone -- the default sweep would destroy both. "
            "A value matching no live sandbox is an error, not a no-op."
        ),
    )
    p_reap.set_defaults(func=cmd_reap)

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    asyncio.run(args.func(args))


if __name__ == "__main__":
    main()
