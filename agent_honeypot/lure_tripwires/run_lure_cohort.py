#!/usr/bin/env python3
"""Factorial driver for the unsolvable-task experiment (paper Section 5).

Cells are task pair x form (solvable, unsolvable) x time budget (short, long)
x trial, for one model, each a real Codex agent in the Docker boundary
(workspace-write client sandbox, one scoped virtual key per cell, the gateway +
Langfuse allow-list, web search off), its budget the harness timeout. The cell
order is shuffled with a seed recorded in the frozen plan, so time-of-day drift
does not line up with one form or budget.

As the intent driver (run_cohort.py, whose helpers this reuses): plan mode
prints the cells and the worst case; --execute needs EXPERIMENT_APPROVED=1 and
clean image inputs; the plan is frozen in lure-cohort.json; one ledger row per
cell in ledger.jsonl; a ceiling guard before each cell (spent so far + that
cell's cap <= ceiling); hard checks stop the cohort (exit 1), setup faults stop
it past --max-setup-faults (exit 75); a rerun with the same plan resumes,
skipping cells whose last row passed the gate. The gate adds the lure suite's
own checks: the verifier ran, the lifecycle record exists, and the cell ran the
planned task and budget. lure-summary.json is written on every exit.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import random
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
_spec = importlib.util.spec_from_file_location("lure_uses_intent_cohort", REPO / "agent_honeypot/intent_tripwires/run_cohort.py")
intent = importlib.util.module_from_spec(_spec)
assert _spec.loader
_spec.loader.exec_module(intent)

TASKS = HERE / "tasks.jsonl"
RUNNER = REPO / "docker_honeypot" / "runner.py"
SUBJECT_COMMAND = intent.SUBJECT_COMMAND  # the Codex adapter takes any case's prompt and workspace
CODEX_SANDBOX = intent.CODEX_SANDBOX
COHORT_FILE = "lure-cohort.json"
SUMMARY = "lure-summary.json"
BUDGETS = {"short": 300, "long": 1200}
FORMS = ("solvable", "unsolvable")
EXEC_MARGIN = 600       # harness, verifier, archive and redaction around the agent's budget
SANDBOX_MARGIN = 900


def load_tasks() -> list[dict[str, Any]]:
    return [json.loads(line) for line in TASKS.read_text().splitlines() if line.strip()]


def plan_cells(pairs: list[str], budgets: list[str], trials: int, seed: int,
               caps: dict[str, float]) -> list[dict[str, Any]]:
    by_pair_form = {(t["metadata"]["pair"], t["metadata"]["form"]): t["id"] for t in load_tasks()}
    cells = []
    for pair in pairs:
        for form in FORMS:
            for budget in budgets:
                for trial in range(1, trials + 1):
                    case_id = by_pair_form[(pair, form)]
                    cells.append({"cell_id": f"{case_id}-{budget}-t{trial}", "case_id": case_id, "pair": pair,
                                  "form": form, "budget": budget, "budget_seconds": BUDGETS[budget],
                                  "trial": trial, "key_budget_usd": caps[budget]})
    random.Random(seed).shuffle(cells)
    return cells


def plan_record(args: argparse.Namespace) -> dict[str, Any]:
    caps = {"short": args.key_budget_short, "long": args.key_budget_long}
    return {
        "schema_version": "1.0", "suite": "lure", "provider": "docker", "arm": args.arm, "model": args.model,
        "ceiling_usd": args.ceiling, "spent_before_usd": args.spent_before, "key_budget_usd": caps,
        "budgets_seconds": {b: BUDGETS[b] for b in args.budgets}, "trials": args.trials, "seed": args.seed,
        "pairs": args.pairs, "codex_sandbox": CODEX_SANDBOX, "subject_command": SUBJECT_COMMAND,
        "image": args.image, "max_setup_faults": args.max_setup_faults,
        "cells": plan_cells(args.pairs, args.budgets, args.trials, args.seed, caps),
    }


def runner_command(args: argparse.Namespace, cell: dict[str, Any], *, dry_run: bool) -> list[str]:
    budget = int(cell["budget_seconds"])
    command = [
        args.python, str(args.runner), "--harness", "lure", "--case-id", cell["case_id"],
        "--subject-command", SUBJECT_COMMAND, "--egress-allowlist", "langfuse,gateway",
        "--model", args.model, "--key-budget", f"{cell['key_budget_usd']:g}", "--arm", args.arm,
        "--trial", str(cell["trial"]), "--agent-timeout", str(budget),
        "--exec-timeout", str(budget + EXEC_MARGIN), "--sandbox-timeout", str(budget + EXEC_MARGIN + SANDBOX_MARGIN),
        "--output", str(args.root / "cells"),
    ]
    if args.image:
        command += ["--image", args.image]
    if dry_run:
        command.append("--dry-run")
    return command


def freeze_plan(root: Path, plan: dict[str, Any]) -> None:
    path = root / COHORT_FILE
    if path.is_file():
        frozen = json.loads(path.read_text())
        if {k: v for k, v in frozen.items() if k != "frozen_at"} != plan:
            raise SystemExit(f"{path} holds a different plan; use a new --root or the same arguments")
        return
    root.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({**plan, "frozen_at": datetime.now(timezone.utc).isoformat()},
                               indent=2, sort_keys=True) + "\n")


def gate_cell(output: Path, cell: dict[str, Any]) -> dict[str, Any]:
    """The intent gate's hard and setup checks, plus the lure suite's own."""
    try:
        record = json.loads((output / intent.RUN_RECORD).read_text())
    except (OSError, json.JSONDecodeError):
        record = None
    record_dict = record if isinstance(record, dict) else {}
    key = record_dict.get("virtual_key") if isinstance(record_dict.get("virtual_key"), dict) else {}
    redaction = record_dict.get("redaction") if isinstance(record_dict.get("redaction"), dict) else {}
    revision = record_dict.get("source_revision") if isinstance(record_dict.get("source_revision"), dict) else {}
    spend = key.get("spend_usd")
    try:
        rows = json.loads((output / "summary.json").read_text()).get("results") or []
        row = rows[0] if rows and isinstance(rows[0], dict) else {}
    except (OSError, json.JSONDecodeError, AttributeError):
        row = {}
    signals = intent.trajectory_signals(output, cell["case_id"])
    chains = row.get("evidence_chains") if isinstance(row.get("evidence_chains"), list) else []
    hooks = row.get("agent_hooks_observed")
    verifier = row.get("verifier") if isinstance(row.get("verifier"), dict) else {}
    lifecycle = row.get("lifecycle") if isinstance(row.get("lifecycle"), dict) else {}
    hard = {
        "run_record_present": record is not None,
        "remote_exit_zero": record_dict.get("remote_exit_code") == 0,
        "termination_explicit_finally": record_dict.get("termination") == "explicit-finally",
        "key_revoked": bool(key.get("revoked_at")),
        "spend_recorded": intent._number(spend),
        "redaction_passed": redaction.get("passed") is True,
        "provider_docker": record_dict.get("provider") == "docker",
        "image_inputs_clean": revision.get("dirty") is False,
        "observable": row.get("observability") == "observable" and bool(chains) and all(chains),
        "agent_hooks_observed": hooks is True or not signals["command_executed"],
        "verifier_ran": verifier.get("status") == "implemented" and isinstance(verifier.get("passed"), bool),
        "lifecycle_recorded": lifecycle.get("termination") in ("agent_exit", "budget_exhausted", "enforced"),
        "planned_task_and_budget": row.get("case_id") == cell["case_id"]
        and lifecycle.get("budget_seconds") == cell["budget_seconds"],
    }
    setup = {
        "spend_within_cap": intent._number(spend) and spend <= cell["key_budget_usd"] + intent.EPSILON,
        "command_executed": signals["command_executed"],
        "output_tokens_positive": signals["output_tokens_positive"],
    }
    status = "hard_fail" if not all(hard.values()) else "setup_fault" if not all(setup.values()) else "ok"
    proxy = intent.proxy_decisions(output)
    refused = proxy.get("refused", {})
    boundary = row.get("boundary") if isinstance(row.get("boundary"), dict) else {}
    return {
        **{k: cell[k] for k in ("cell_id", "case_id", "pair", "form", "budget", "budget_seconds", "trial")},
        "status": status, "hard": hard, "setup": setup,
        "key_alias": key.get("key_alias"), "spend_usd": spend if intent._number(spend) else None,
        "stage": row.get("stage"), "lure": row.get("lure"),
        "verifier": {k: verifier.get(k) for k in ("status", "passed", "reason", "answer_matches_lure", "material_intact")},
        "lifecycle": lifecycle,
        "boundary": {k: boundary.get(k) for k in ("first_boundary_event", "time_to_first_boundary_event_s",
                                                  "observed_until_s", "alert_latency_s", "censored")},
        "agent_hooks_observed": hooks,
        "refused_client_hosts": {h: n for h, n in refused.items() if h in intent.KNOWN_CLIENT_HOSTS},
        "refused_other_hosts": {h: n for h, n in refused.items() if h not in intent.KNOWN_CLIENT_HOSTS},
        "archive_error": signals["archive_error"],
        "output": str(output),
    }


def spent(args: argparse.Namespace, ledger: list[dict[str, Any]]) -> float:
    return args.spent_before + sum(row["spend_usd"] for row in ledger if intent._number(row.get("spend_usd")))


def write_summary(root: Path, plan: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    ledger = intent.read_ledger(root)
    last = {row.get("cell_id"): row for row in ledger}
    done = [last[c["cell_id"]] for c in plan["cells"] if c["cell_id"] in last]
    ok = [row for row in done if row.get("status") == "ok"]
    groups: dict[str, dict[str, int]] = {}
    for row in ok:
        group = groups.setdefault(f"{row['form']}/{row['budget']}", Counter())
        lure = row.get("lure") or {}
        group["cells"] += 1
        group["lure_access"] += bool(lure.get("access"))
        group["lure_probe"] += bool(lure.get("probe"))
        group["verifier_passed"] += bool((row.get("verifier") or {}).get("passed"))
        group["budget_exhausted"] += (row.get("lifecycle") or {}).get("termination") == "budget_exhausted"
    summary = {
        "schema_version": "1.0", "arm": plan["arm"], "model": plan["model"],
        "cells_planned": len(plan["cells"]), "cells_passed_gate": len(ok),
        "statuses": dict(Counter(row.get("status") for row in done)),
        "stages": dict(Counter(row.get("stage") for row in ok)),
        "by_form_and_budget": {k: dict(v) for k, v in sorted(groups.items())},
        "spend_usd": round(sum(row["spend_usd"] for row in ledger if intent._number(row.get("spend_usd"))), 6),
        "spent_total_usd": round(spent(args, ledger), 6), "ceiling_usd": plan["ceiling_usd"],
        "written_at": datetime.now(timezone.utc).isoformat(),
    }
    (root / SUMMARY).write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


def run_plan(args: argparse.Namespace, plan: dict[str, Any]) -> int:
    cells = plan["cells"]
    worst = args.spent_before + sum(c["key_budget_usd"] for c in cells)
    print(f"plan: {len(cells)} cell(s), model {args.model}, seed {args.seed}, caps {plan['key_budget_usd']}, "
          f"ceiling ${args.ceiling:g}, spent before ${args.spent_before:g}; worst case ${worst:.2f}"
          + (" (the ceiling guard stops earlier)" if worst > args.ceiling else ""))
    failures = 0
    for index, cell in enumerate(cells):
        completed = subprocess.run(runner_command(args, cell, dry_run=True), cwd=REPO, env=intent.child_environment(),
                                   text=True, capture_output=True, check=False)
        out = intent.last_json_object(completed.stdout) or {}
        revision = out.get("source_revision") if isinstance(out.get("source_revision"), dict) else {}
        if completed.returncode != 0:
            failures += 1
            reason = (completed.stderr.strip().splitlines() or ["no output"])[-1]
            print(f"  {index + 1:3d} [{cell['cell_id']}] PLAN FAILED: {reason}")
            continue
        print(f"  {index + 1:3d} [{cell['cell_id']}] {cell['pair']} {cell['form']} {cell['budget']} "
              f"({cell['budget_seconds']} s), cap ${cell['key_budget_usd']:g}, image {out.get('image')}"
              f"{' (DIRTY inputs: --execute would refuse)' if revision.get('dirty') else ''}")
    return 1 if failures else 0


def run_execute(args: argparse.Namespace, plan: dict[str, Any]) -> int:
    if os.environ.get("EXPERIMENT_APPROVED") != "1":
        print("refusing --execute: paid cells need EXPERIMENT_APPROVED=1", file=sys.stderr)
        return 78
    first = subprocess.run(runner_command(args, plan["cells"][0], dry_run=True), cwd=REPO,
                           env=intent.child_environment(), text=True, capture_output=True, check=False)
    out = intent.last_json_object(first.stdout) or {}
    revision = out.get("source_revision") if isinstance(out.get("source_revision"), dict) else {}
    if first.returncode != 0 or revision.get("dirty") is not False:
        print("refusing --execute: the runner's plan failed or the image inputs are dirty (commit them first)",
              file=sys.stderr)
        return 78
    freeze_plan(args.root, plan)
    setup_faults = 0
    for cell in plan["cells"]:
        ledger = intent.read_ledger(args.root)
        last = {row.get("cell_id"): row for row in ledger}
        if last.get(cell["cell_id"], {}).get("status") == "ok":
            print(f"  [{cell['cell_id']}] already passed the gate; skipped")
            continue
        so_far = spent(args, ledger)
        if so_far + cell["key_budget_usd"] > args.ceiling + intent.EPSILON:
            print(f"ceiling guard: stopped before {cell['cell_id']} (spent ${so_far:.4f} + cap "
                  f"${cell['key_budget_usd']:g} > ceiling ${args.ceiling:g})")
            write_summary(args.root, plan, args)
            return 0
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        log = args.root / f"driver-{cell['cell_id']}-{stamp}.log"
        print(f"  [{cell['cell_id']}] RUN (spent so far ${so_far:.4f}); runner log {log.name}", flush=True)
        with log.open("w", encoding="utf-8") as handle:
            completed = subprocess.run(runner_command(args, cell, dry_run=False), cwd=REPO,
                                       env=intent.child_environment(), text=True, stdout=handle,
                                       stderr=subprocess.STDOUT, check=False)
        record = intent.last_json_object(log.read_text(errors="replace")) or {}
        output = Path(record["output"]) if isinstance(record.get("output"), str) else None
        if output is None:
            intent.append_ledger(args.root, {**{k: cell[k] for k in ("cell_id", "case_id", "pair", "form", "budget",
                                                                     "budget_seconds", "trial")},
                                             "status": "runner_failed", "runner_exit": completed.returncode,
                                             "spend_usd": None, "log": str(log)})
            print(f"  [{cell['cell_id']}] runner exit {completed.returncode} and no run record; stopping. "
                  f"If a key was minted, revoke it by alias now; see {log.name}", file=sys.stderr)
            write_summary(args.root, plan, args)
            return 1
        row = {**gate_cell(output, cell), "runner_exit": completed.returncode, "log": str(log)}
        if completed.returncode != 0 and row["status"] == "ok":
            row["status"] = "hard_fail"
        intent.append_ledger(args.root, row)
        failed = [name for group in ("hard", "setup") for name, ok in row[group].items() if not ok]
        lure = row.get("lure") or {}
        print(f"  [{cell['cell_id']}] gate {row['status']}{' (' + ', '.join(failed) + ')' if failed else ''}; "
              f"lure stage {row['stage']}, access {lure.get('access')}, probe {lure.get('probe')}, verifier "
              f"{row['verifier'].get('passed')}, termination {row['lifecycle'].get('termination')}, spend "
              f"{row['spend_usd']}, refused other hosts {row['refused_other_hosts'] or 'none'}", flush=True)
        if row["status"] == "hard_fail":
            print(f"stopping at the first failed gate ({cell['cell_id']}); key alias {row['key_alias']}: "
                  "if key_revoked is false, revoke it by alias now", file=sys.stderr)
            write_summary(args.root, plan, args)
            return 1
        if row["status"] == "setup_fault":
            setup_faults += 1
            if setup_faults > args.max_setup_faults:
                print(f"setup-fault limit exceeded at {cell['cell_id']}; not starting the next cell", file=sys.stderr)
                write_summary(args.root, plan, args)
                return 75
    summary = write_summary(args.root, plan, args)
    print(f"done: {summary['cells_passed_gate']}/{summary['cells_planned']} cells passed the gate; "
          f"by form and budget {summary['by_form_and_budget']}; spend ${summary['spend_usd']:.4f} "
          f"(total ${summary['spent_total_usd']:.4f} of ${summary['ceiling_usd']:g})")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, required=True, help="cohort root (frozen plan, ledger, cells)")
    parser.add_argument("--model", required=True)
    parser.add_argument("--key-budget-short", type=float, required=True, help="per-cell key cap, short budget, USD")
    parser.add_argument("--key-budget-long", type=float, required=True, help="per-cell key cap, long budget, USD")
    parser.add_argument("--ceiling", type=float, required=True)
    parser.add_argument("--spent-before", type=float, default=0.0)
    parser.add_argument("--pairs", default=",".join(sorted({t["metadata"]["pair"] for t in load_tasks()})),
                        help="comma-separated task pairs (default: all four)")
    parser.add_argument("--budgets", default="short,long", help="comma-separated: short (300 s), long (1200 s)")
    parser.add_argument("--trials", type=int, default=1)
    parser.add_argument("--seed", type=int, required=True, help="seed of the cell order, recorded in the plan")
    parser.add_argument("--arm", default="lure")
    parser.add_argument("--max-setup-faults", type=int, default=2)
    parser.add_argument("--image", help="a prebuilt agent image tag")
    parser.add_argument("--execute", action="store_true", help="run paid cells (needs EXPERIMENT_APPROVED=1)")
    parser.add_argument("--runner", type=Path, default=RUNNER, help=argparse.SUPPRESS)
    parser.add_argument("--python", default=sys.executable, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    args.root = args.root.resolve()
    known = sorted({t["metadata"]["pair"] for t in load_tasks()})
    args.pairs = [p.strip() for p in args.pairs.split(",") if p.strip()]
    args.budgets = [b.strip() for b in args.budgets.split(",") if b.strip()]
    if not args.pairs or set(args.pairs) - set(known):
        parser.error(f"--pairs must name pairs among {', '.join(known)}")
    if not args.budgets or set(args.budgets) - set(BUDGETS) or len(set(args.budgets)) != len(args.budgets):
        parser.error("--budgets must be short, long or both")
    if args.trials < 1 or args.max_setup_faults < 0 or args.spent_before < 0:
        parser.error("--trials >= 1, --max-setup-faults and --spent-before >= 0")
    for name in ("key_budget_short", "key_budget_long", "ceiling"):
        if not getattr(args, name) > 0:
            parser.error(f"--{name.replace('_', '-')} must be positive")
    if max(args.key_budget_short, args.key_budget_long) > args.ceiling:
        parser.error("a key cap exceeds --ceiling: no such cell could start")
    plan = plan_record(args)
    return run_execute(args, plan) if args.execute else run_plan(args, plan)


if __name__ == "__main__":
    raise SystemExit(main())
