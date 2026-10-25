#!/usr/bin/env python3
"""Aggregate a repeated-trial cohort into the paper's §3.7 and §3.8 numbers.

Input: one frozen schema-v2 manifest per trial (``--manifest`` repeated), each
with its own batch directory of published results. Nothing here starts a run;
the script only reads published results and writes derived tables.

What it computes, following neurips_main.tex §3.7–§3.8 and Appendix E:

* pass@k per task, Chen et al. (2021) unbiased estimator
  ``1 - C(n_i - c_i, k) / C(n_i, k)``, where a success is ``status == "success"``
  (``other_vuln`` and ``oracle_mismatch`` are non-successes, as in Table 2).
  Cohort pass@k is the mean over tasks; its 95% interval is a percentile
  bootstrap that resamples *tasks* (default 20,000 draws, seed 0), the same
  cluster logic the paper uses for CVE-Bench. Per-task rates ``c_i/n_i`` carry
  the Jeffreys interval (Beta(c+1/2, n-c+1/2), edges pinned at 0 and 1).
* The §3.7 table: tasks grouped by their trial-1 outcome; for each group the
  number of tasks with any success in trials 2..n, the pooled later-trial
  success rate (Wilson), and pass@1 / pass@k over the group's tasks.
* §3.8 best-of-N: for each selector that cannot see the ground truth, pick one
  of the first N attempts per task and grade the pick with the oracle verdict
  already recorded. Selectors: random; the agent's own report
  (``agent_success``); the online chain (stages 1-3 passed); the online chain
  re-checked under isolation (``isolated_stage3`` passed). Ties and the random
  pick use a fixed seed. Reported with N, the rate, a task bootstrap interval,
  the oracle-mismatch rate among picked attempts, and the summed spend.

Outputs (``--out-dir``): ``trials.csv`` (one row per task x trial),
``passk_by_task.csv``, ``passk_summary.json``, ``first_trial_groups.csv``,
``best_of_n.csv``, ``table_rows.tex`` (rows in the §3.7 table's own format) and
``provenance.json`` (manifest and result hashes, seed, draws, missing cells).

Strict by default: every frozen cell must be published and every publication
record must match, via ``materialize_cybergym_cohort._schema_v2_entries``.
``--allow-partial`` instead reads whatever is published (still validating each
payload against its manifest) and reports the missing cells, for progress
checks while trials are still running.

Usage (repository root, WSL):
    PYDANTIC_DISABLE_PLUGINS=1 .venv/bin/python aggregate_repeats_passk.py \
        --manifest reference/cybergym-e2e-repeats-v1.t1.json \
        --manifest reference/cybergym-e2e-repeats-v1.t2.json ... \
        --out-dir results/paper/cybergym-e2e-repeats-v1 --k 1 2 --n 2

The cohort runs two trials per task, so the defaults are pass@1..2 and
best-of-2; a k or N above a task's trial count is reported as undefined.
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import sys
from collections import defaultdict
from dataclasses import dataclass
from math import comb
from pathlib import Path
from typing import Any, Callable, Iterable

import materialize_cybergym_cohort as materialize
import run_modal_repeats as repeats
from cybergym_capability_curve_rate import _z_for, wilson

ROOT = Path(__file__).resolve().parent
SUCCESS = "success"
MISMATCH = "oracle_mismatch"
LABELS = {
    "success": "\\lblSuccess{}",
    "failed": "\\lblFailed{}",
    "other_vuln": "\\lblOtherVuln{}",
    "oracle_mismatch": "\\lblMismatch{}",
    "no_patch": "\\lblNoPatch{}",
    "no_poc": "\\lblNoPoc{}",
}
ROW_ORDER = ["failed", "other_vuln", "oracle_mismatch", "no_poc", "no_patch", "success"]


# --------------------------------------------------------------------------
# estimators (pure functions; unit-tested)
# --------------------------------------------------------------------------
def pass_at_k(n: int, c: int, k: int) -> float:
    """Unbiased pass@k for n trials with c successes (Chen et al. 2021)."""
    if k < 1 or k > n:
        raise ValueError(f"k must satisfy 1 <= k <= n (k={k}, n={n})")
    if c < 0 or c > n:
        raise ValueError(f"c must satisfy 0 <= c <= n (c={c}, n={n})")
    if n - c < k:
        return 1.0
    return 1.0 - comb(n - c, k) / comb(n, k)


def jeffreys(c: int, n: int, confidence: float = 0.95) -> tuple[float, float]:
    """Equal-tailed Jeffreys interval; edges pinned at 0 and 1 (Appendix E)."""
    if n == 0:
        return 0.0, 1.0
    try:
        from scipy.stats import beta  # type: ignore
    except ImportError:  # the paper's renderer falls back to Wilson and says so
        _, lo, hi = wilson(c, n, _z_for(confidence))
        print("warning: SciPy unavailable, per-task intervals are Wilson not Jeffreys",
              file=sys.stderr)
        return lo, hi
    tail = (1.0 - confidence) / 2.0
    lo = 0.0 if c == 0 else float(beta.ppf(tail, c + 0.5, n - c + 0.5))
    hi = 1.0 if c == n else float(beta.ppf(1.0 - tail, c + 0.5, n - c + 0.5))
    return lo, hi


def task_bootstrap(values: list[float], draws: int, seed: int,
                   confidence: float = 0.95) -> tuple[float, float]:
    """Percentile bootstrap of the mean, resampling tasks with replacement."""
    if not values:
        return 0.0, 0.0
    rng = random.Random(seed)
    m = len(values)
    means = sorted(
        sum(values[rng.randrange(m)] for _ in range(m)) / m for _ in range(draws)
    )
    tail = (1.0 - confidence) / 2.0
    lo_i = max(0, min(len(means) - 1, int(round(tail * (len(means) - 1)))))
    hi_i = max(0, min(len(means) - 1, int(round((1.0 - tail) * (len(means) - 1)))))
    return means[lo_i], means[hi_i]


# --------------------------------------------------------------------------
# data model
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Trial:
    task: str
    trial: int
    status: str
    agent_success: bool
    gt_success: bool
    online_chain: bool      # stage1, stage2, stage3 all passed (S1-S3 online)
    isolated_chain: bool    # online chain and isolated_stage3 passed
    cost_usd: float
    sha256: str
    source: str


def _passed(payload: dict[str, Any], key: str) -> bool:
    return payload.get(key) == "passed"


def trial_from_payload(payload: dict[str, Any], sha256: str, source: str) -> Trial:
    online = all(_passed(payload, f"stage{i}") for i in (1, 2, 3))
    return Trial(
        task=str(payload["task"]),
        trial=int(payload["trial"]),
        status=str(payload["status"]),
        agent_success=bool(payload.get("agent_success")),
        gt_success=bool(payload.get("gt_success")),
        online_chain=online,
        isolated_chain=online and _passed(payload, "isolated_stage3"),
        cost_usd=float(payload.get("solver_cost_usd") or 0.0),
        sha256=sha256,
        source=source,
    )


# --------------------------------------------------------------------------
# loading
# --------------------------------------------------------------------------
def load_trials(
    manifest_paths: list[Path], root: Path, allow_partial: bool,
) -> tuple[list[Trial], list[dict[str, Any]], list[tuple[str, int]], list[dict[str, Any]]]:
    """Return (trials, manifests_provenance, missing_cells, exclusions)."""
    trials: list[Trial] = []
    provenance: list[dict[str, Any]] = []
    missing: list[tuple[str, int]] = []
    exclusions: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    cohort_ids: set[str] = set()
    conditions: set[tuple[str, str, str]] = set()
    for path in manifest_paths:
        manifest = repeats.load_manifest(path)
        cohort_hash = repeats.manifest_sha256(path)
        cohort_ids.add(manifest["cohort_id"])
        conditions.add((manifest["litellm_model_id"], manifest["snapshot_image_id"],
                        manifest["mode"]))
        batch_dir = root / manifest["output_root"] / manifest["batch_id"]
        entries: list[dict[str, Any]]
        if allow_partial:
            entries = []
            for task, trial in repeats.planned_cells(manifest):
                source = repeats.final_path(batch_dir, task, trial)
                if not source.is_file():
                    missing.append((task, trial))
                    continue
                payload = json.loads(source.read_text(encoding="utf-8"))
                repeats._validate_result_payload(payload, manifest, task, trial, cohort_hash)
                entries.append({"task": task, "trial": trial, "source": source,
                                "sha256": repeats.sha256_path(source), "payload": payload})
            ledger = batch_dir / "_meta" / "excluded_trials.jsonl"
            if ledger.is_file():
                exclusions.extend(materialize._load_exclusions(ledger, root))
        else:
            entries, batch_exclusions = materialize._schema_v2_entries(path, manifest, root)
            exclusions.extend(batch_exclusions)
        for entry in entries:
            key = (entry["task"], entry["trial"])
            if key in seen:
                raise repeats.ManifestError(f"cell {key} published by more than one manifest")
            seen.add(key)
            trials.append(trial_from_payload(
                entry["payload"], entry["sha256"], str(Path(entry["source"]).relative_to(root)),
            ))
        provenance.append({
            "manifest": str(path.relative_to(root)) if path.is_relative_to(root) else str(path),
            "manifest_sha256": cohort_hash,
            "batch_id": manifest["batch_id"],
            "trial_numbers": list(manifest["trial_numbers"]),
            "snapshot_image_id": manifest["snapshot_image_id"],
            "litellm_model_id": manifest["litellm_model_id"],
            "cells_published": len(entries),
        })
    if len(cohort_ids) != 1:
        raise repeats.ManifestError(f"manifests span several cohorts: {sorted(cohort_ids)}")
    if len(conditions) != 1:
        raise repeats.ManifestError(
            "manifests do not share one frozen condition (model, image, mode): "
            f"{sorted(conditions)}"
        )
    return trials, provenance, missing, exclusions


# --------------------------------------------------------------------------
# analysis
# --------------------------------------------------------------------------
def by_task(trials: Iterable[Trial]) -> dict[str, list[Trial]]:
    grouped: dict[str, list[Trial]] = defaultdict(list)
    for t in trials:
        grouped[t.task].append(t)
    return {task: sorted(ts, key=lambda t: t.trial) for task, ts in sorted(grouped.items())}


def passk_by_task(tasks: dict[str, list[Trial]], ks: list[int]) -> list[dict[str, Any]]:
    rows = []
    for task, ts in tasks.items():
        n = len(ts)
        c = sum(t.status == SUCCESS for t in ts)
        lo, hi = jeffreys(c, n)
        row: dict[str, Any] = {"task": task, "n": n, "c": c, "rate": c / n if n else 0.0,
                               "jeffreys_lo": lo, "jeffreys_hi": hi,
                               "outcomes": " ".join(t.status for t in ts)}
        for k in ks:
            row[f"pass@{k}"] = pass_at_k(n, c, k) if k <= n else None
        rows.append(row)
    return rows


def cohort_passk(task_rows: list[dict[str, Any]], ks: list[int], draws: int, seed: int,
                 ) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for k in ks:
        vals = [r[f"pass@{k}"] for r in task_rows if r[f"pass@{k}"] is not None]
        mean = sum(vals) / len(vals) if vals else 0.0
        lo, hi = task_bootstrap(vals, draws, seed)
        out[f"pass@{k}"] = {"mean": mean, "lo": lo, "hi": hi, "tasks": len(vals),
                            "skipped_tasks_with_n_below_k": len(task_rows) - len(vals)}
    return out


def first_trial_groups(tasks: dict[str, list[Trial]], ks: list[int], draws: int, seed: int,
                       z: float) -> list[dict[str, Any]]:
    """§3.7 rows: tasks grouped by trial-1 outcome; later columns use trials 2..n."""
    groups: dict[str, list[list[Trial]]] = defaultdict(list)
    for ts in tasks.values():
        first = next((t for t in ts if t.trial == 1), None)
        if first is None:
            continue
        groups[first.status].append(ts)
    rows = []
    for outcome in sorted(groups, key=lambda o: ROW_ORDER.index(o) if o in ROW_ORDER else 99):
        members = groups[outcome]
        later = [[t for t in ts if t.trial >= 2] for ts in members]
        any_later = sum(any(t.status == SUCCESS for t in ls) for ls in later)
        later_succ = sum(sum(t.status == SUCCESS for t in ls) for ls in later)
        later_n = sum(len(ls) for ls in later)
        _, w_lo, w_hi = wilson(later_succ, later_n, z) if later_n else (0.0, 0.0, 0.0)
        row: dict[str, Any] = {
            "first_trial_outcome": outcome, "tasks": len(members),
            "any_later_success": any_later, "later_successes": later_succ,
            "later_trials": later_n,
            "later_rate": later_succ / later_n if later_n else None,
            "later_rate_lo": w_lo if later_n else None,
            "later_rate_hi": w_hi if later_n else None,
        }
        for k in ks:
            vals = [pass_at_k(len(ts), sum(t.status == SUCCESS for t in ts), k)
                    for ts in members if len(ts) >= k]
            mean = sum(vals) / len(vals) if vals else None
            lo, hi = task_bootstrap(vals, draws, seed) if vals else (None, None)
            row[f"pass@{k}"] = mean
            row[f"pass@{k}_lo"] = lo
            row[f"pass@{k}_hi"] = hi
        rows.append(row)
    return rows


Selector = Callable[[list[Trial], random.Random], Trial]


def _pick(preferred: Callable[[Trial], bool]) -> Selector:
    def select(attempts: list[Trial], rng: random.Random) -> Trial:
        pool = [t for t in attempts if preferred(t)] or list(attempts)
        return pool[rng.randrange(len(pool))]
    return select


SELECTORS: dict[str, Selector] = {
    "random": lambda attempts, rng: attempts[rng.randrange(len(attempts))],
    "agent_report": _pick(lambda t: t.agent_success),
    "online_chain_s1_s3": _pick(lambda t: t.online_chain),
    "isolated_chain": _pick(lambda t: t.isolated_chain),
    "oracle_upper_bound": _pick(lambda t: t.status == SUCCESS),
}


def best_of_n(tasks: dict[str, list[Trial]], n: int, draws: int, seed: int,
              ) -> list[dict[str, Any]]:
    """§3.8: pick one of the first N attempts per task without the ground truth."""
    rows = []
    eligible = {task: ts[:n] for task, ts in tasks.items() if len(ts) >= n}
    for name, select in SELECTORS.items():
        rng = random.Random(f"{seed}:{name}:{n}")
        picks = [select(ts, rng) for ts in eligible.values()]
        hits = [1.0 if p.status == SUCCESS else 0.0 for p in picks]
        rate = sum(hits) / len(hits) if hits else 0.0
        lo, hi = task_bootstrap(hits, draws, seed)
        mismatch = sum(p.status == MISMATCH for p in picks)
        spend = sum(t.cost_usd for ts in eligible.values() for t in ts)
        rows.append({
            "selector": name, "N": n, "tasks": len(eligible),
            "selected_success": int(sum(hits)), "rate": rate, "lo": lo, "hi": hi,
            "selected_oracle_mismatch": mismatch,
            "mismatch_rate_among_selected": mismatch / len(picks) if picks else 0.0,
            "spend_usd": round(spend, 4),
        })
    return rows


# --------------------------------------------------------------------------
# output
# --------------------------------------------------------------------------
def _pct(x: float | None) -> str:
    return "---" if x is None else f"{100 * x:.1f}"


def table_rows_tex(mode_label: str, groups: list[dict[str, Any]], summary: dict[str, Any],
                   ks: list[int], total_tasks: int) -> str:
    """Rows in the exact column order of the §3.7 table: one pass@k column per k."""
    ks = sorted(ks)
    lines = []
    for i, g in enumerate(groups):
        zebra = "\\rowcolor{tabZebra}\n" if i % 2 else ""
        label = LABELS.get(g["first_trial_outcome"], g["first_trial_outcome"])
        later = ("---" if g["later_rate"] is None
                 else f"{g['later_successes']}/{g['later_trials']} ({_pct(g['later_rate'])}\\%)")
        passes = "".join(
            " & ---" if g[f"pass@{k}"] is None else f" & {_pct(g[f'pass@{k}'])}\\%" for k in ks
        )
        lines.append(
            f"{zebra}{mode_label} & {label} & {g['tasks']} & {g['any_later_success']} & {later}"
            f"{passes} \\\\"
        )
    # A pass@k with no eligible task (k above every task's trial count) is undefined, not zero.
    totals = "".join(
        " & ---" if not s.get("tasks")
        else f" & {_pct(s['mean'])}\\% [{_pct(s['lo'])}, {_pct(s['hi'])}]"
        for s in (summary[f"pass@{k}"] for k in ks)
    )
    lines.append(
        f"\\multicolumn{{5}}{{@{{}}l}}{{\\textbf{{All {total_tasks} valid tasks, {mode_label}}}}}"
        f"{totals} \\\\"
    )
    return "\n".join(lines) + "\n"


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


TRIALS_PER_TASK = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--manifest", type=Path, action="append", required=True,
                        help="frozen schema-v2 manifest; repeat once per trial batch")
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--k", type=int, nargs="+",
                        default=list(range(1, TRIALS_PER_TASK + 1)))
    parser.add_argument("--n", type=int, default=TRIALS_PER_TASK, help="N for best-of-N")
    parser.add_argument("--draws", type=int, default=20_000)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--confidence", type=float, default=0.95)
    parser.add_argument("--mode-label", default="End-to-end")
    parser.add_argument("--allow-partial", action="store_true",
                        help="read published cells only; report missing ones (progress check)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    manifests = [p if p.is_absolute() else ROOT / p for p in args.manifest]
    try:
        trials, provenance, missing, exclusions = load_trials(manifests, ROOT, args.allow_partial)
    except (repeats.ManifestError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not trials:
        print("error: no published trials found", file=sys.stderr)
        return 2

    ks = sorted(set(args.k))
    z = _z_for(args.confidence)
    tasks = by_task(trials)
    task_rows = passk_by_task(tasks, ks)
    summary = cohort_passk(task_rows, ks, args.draws, args.seed)
    groups = first_trial_groups(tasks, ks, args.draws, args.seed, z)
    bon = best_of_n(tasks, args.n, args.draws, args.seed)

    out = args.out_dir if args.out_dir.is_absolute() else ROOT / args.out_dir
    out.mkdir(parents=True, exist_ok=True)
    write_csv(out / "trials.csv", [t.__dict__ for t in trials])
    write_csv(out / "passk_by_task.csv", task_rows)
    write_csv(out / "first_trial_groups.csv", groups)
    write_csv(out / "best_of_n.csv", bon)
    (out / "passk_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (out / "table_rows.tex").write_text(
        table_rows_tex(args.mode_label, groups, summary, ks, len(tasks)), encoding="utf-8")
    (out / "provenance.json").write_text(json.dumps({
        "manifests": provenance,
        "trials_loaded": len(trials), "tasks": len(tasks),
        "trials_per_task": sorted({len(ts) for ts in tasks.values()}),
        "missing_cells": [list(c) for c in missing],
        "excluded_attempts": exclusions,
        "k": ks, "best_of_n": args.n, "bootstrap_draws": args.draws, "seed": args.seed,
        "confidence": args.confidence, "allow_partial": args.allow_partial,
        "success_definition": "status == 'success' (other_vuln, oracle_mismatch are non-successes)",
    }, indent=2, default=str) + "\n", encoding="utf-8")

    print(f"tasks: {len(tasks)}  trials: {len(trials)}  trials per task: "
          f"{sorted({len(ts) for ts in tasks.values()})}  missing cells: {len(missing)}")
    for k in ks:
        s = summary[f"pass@{k}"]
        print(f"pass@{k}: {100 * s['mean']:.1f}%  [{100 * s['lo']:.1f}, {100 * s['hi']:.1f}]"
              f"  over {s['tasks']} tasks")
    for g in groups:
        print(f"  first-trial {g['first_trial_outcome']:15s} tasks={g['tasks']:2d} "
              f"any-later-success={g['any_later_success']} later={g['later_successes']}/{g['later_trials']}")
    for b in bon:
        print(f"best-of-{b['N']} {b['selector']:20s} {100 * b['rate']:.1f}% "
              f"[{100 * b['lo']:.1f}, {100 * b['hi']:.1f}] mismatch-among-selected="
              f"{b['selected_oracle_mismatch']} spend=${b['spend_usd']:.2f}")
    if missing:
        print(f"partial: {len(missing)} cell(s) not yet published; numbers above are provisional")
    print(f"wrote {out.relative_to(ROOT) if out.is_relative_to(ROOT) else out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
