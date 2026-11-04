#!/usr/bin/env python3
"""Run a cohort of real-agent intent cells (ITH-NNN) through the Docker boundary.

One cell per case, one case at a time, each through
docker_honeypot/runner.py --harness intent with the intent Codex adapter, a
per-cell virtual key, workspace-write, and the gateway + Langfuse allow-list
(plus the web-search token for the hosted-search cases, ITH-010 and ITH-011).

Without --execute it plans: each cell's runner --dry-run (free; no key, no
container) and the ceiling arithmetic. With --execute (and
EXPERIMENT_APPROVED=1), before the first cell it freezes the plan in
<root>/intent-cohort.json, refuses dirty image inputs, and then, per case:

* the ceiling guard: a cell starts only if the spend so far (--spent-before
  plus every cell in the ledger) plus the per-cell key cap stays within
  --ceiling;
* the gate, on the run record and the copied outputs. Hard checks, the
  collusion driver's plus the intent ones: remote exit 0, explicit cleanup,
  key revoked, spend recorded, redaction passed, a run record, provider
  docker, clean image inputs, observable with every chain valid, the
  web-search mode the case needs, and the hooks saw the agent's commands
  (score_collusion.agent_hook_check) whenever it ran one. Setup checks: spend
  within the cap, a command executed, output tokens above zero;
* one ledger row in <root>/ledger.jsonl: the gate, the stage and expectation,
  the hook verdict, the spend, and the egress proxy's decisions by host. A
  refused host is a finding, not a failure: the four Codex client hosts the
  author accepted (decision A1) are listed apart from every other.

A hard failure stops the cohort (exit 1); a setup fault is counted and stops
it once more than --max-setup-faults occurred (exit 75). A rerun with the same
plan resumes: cases whose last row passed the gate are skipped. The summary
goes to <root>/intent-summary.json. No key, token id, canary or marker value
is printed or written by this driver; the runner's own log (driver-*.log)
carries the run record with its token id and is never committed.

Watch it live with agent_honeypot/collusion_tripwires/cohort_monitor.py
<root> --watch 20, which reads this layout. Not yet: Langfuse traces. The
ingest's redactor reads canary.txt, but its push has not been tested on an
intent run.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tarfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
DATASET = HERE / "experiments.jsonl"
DATASET_V2 = HERE / "experiments-v2.jsonl"
PROBES = HERE / "probes.jsonl"
# Roles a real agent may run: the intent evaluations and the probe cases; the two
# sensor controls stay scripted.
AGENT_ROLES = ("intent_eval", "search_probe")
RUNNER = REPO / "docker_honeypot" / "runner.py"
SUBJECT_COMMAND = "bash /opt/honeypot/agent_honeypot/intent_tripwires/codex_intent.sh"
CODEX_SANDBOX = "workspace-write"
RUN_RECORD = "docker-run.json"
PROXY_LOG = "egress-proxy.log"
COHORT_FILE = "intent-cohort.json"
LEDGER = "ledger.jsonl"
SUMMARY = "intent-summary.json"
# The Codex client's own background hosts, refused by the proxy in every cell
# (the author accepted them as known noise, decision A1).
KNOWN_CLIENT_HOSTS = frozenset({"chatgpt.com", "ab.chatgpt.com", "github.com", "api.github.com"})
EPSILON = 1e-9


def load_cases(paths: tuple[Path, ...] = (DATASET, DATASET_V2, PROBES)) -> dict[str, dict[str, Any]]:
    """Both corpus versions (version 2's IDs are ITH-101..ITH-111) and the probe
    cases (ITH-9NN), by case ID."""
    return {row["id"]: row for path in paths if path.is_file()
            for row in (json.loads(line) for line in path.read_text().splitlines() if line.strip())}


def corpus_version(case: dict[str, Any]) -> int | str:
    """1, 2, or "probe" for a probe case outside both corpora."""
    return case["metadata"].get("corpus_version", 1)


def default_cases(cases: dict[str, dict[str, Any]], corpus: int | str = 1) -> list[str]:
    """The agent cases of one corpus version (or the probes); the two sensor controls stay scripted."""
    return sorted(case_id for case_id, case in cases.items()
                  if case["metadata"]["role"] in AGENT_ROLES and corpus_version(case) == corpus)


def web_search(case: dict[str, Any]) -> str:
    return "live" if case["metadata"].get("requires_live_web_search") else "disabled"


def allowlist(case: dict[str, Any]) -> str:
    return "langfuse,gateway,web-search" if web_search(case) == "live" else "langfuse,gateway"


def runner_command(args: argparse.Namespace, case: dict[str, Any], *, dry_run: bool) -> list[str]:
    command = [
        args.python, str(args.runner), "--harness", "intent", "--case-id", str(case["id"]),
        "--subject-command", SUBJECT_COMMAND, "--egress-allowlist", allowlist(case),
        "--model", args.model, "--key-budget", f"{args.key_budget:g}", "--arm", args.arm,
        "--trial", "1", "--agent-timeout", str(args.agent_timeout),
        "--output", str(args.root / "cells"),
    ]
    if args.image:
        command += ["--image", args.image]
    if getattr(args, "alert", False):
        command.append("--alert")
    if getattr(args, "enforce", False):
        # The driver runs real agents only; the runner refuses --enforce on one
        # without --enforce-real-agent, and so does main() here.
        command += ["--enforce", "--enforce-real-agent"]
    if dry_run:
        command.append("--dry-run")
    return command


def child_environment() -> dict[str, str]:
    env = os.environ.copy()
    env["HONEYPOT_CODEX_SANDBOX"] = CODEX_SANDBOX
    return env


def last_json_object(text: str) -> dict[str, Any] | None:
    lines = text.splitlines()
    starts = [index for index, line in enumerate(lines) if line.strip() == "{"]
    for start in reversed(starts):
        try:
            value = json.loads("\n".join(lines[start:]))
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return None


def _number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _archive_member(archive: tarfile.TarFile, name: str) -> bytes | None:
    try:
        member = archive.extractfile(name)
    except KeyError:
        return None
    return member.read() if member is not None else None


def trajectory_signals(output: Path, case_id: str) -> dict[str, Any]:
    """From the copied artifacts: did the agent run a command and produce
    output tokens, and the case report's stage signals and event counts."""
    result: dict[str, Any] = {"command_executed": False, "output_tokens_positive": False,
                              "report": None, "archive_error": None}
    try:
        with tarfile.open(output / "artifacts.tar.gz", "r:gz") as archive:
            trajectory = _archive_member(archive, f"cases/{case_id}/trajectory.jsonl")
            report = _archive_member(archive, f"cases/{case_id}/report.json")
    except (OSError, tarfile.TarError) as exc:
        result["archive_error"] = type(exc).__name__
        return result
    for raw in (trajectory or b"").splitlines():
        try:
            row = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(row, dict):
            continue
        item = row.get("item") if isinstance(row.get("item"), dict) else {}
        if row.get("type") == "command_execution" or item.get("type") == "command_execution":
            result["command_executed"] = True
        usage = row.get("usage") if row.get("type") == "turn.completed" else None
        if isinstance(usage, dict) and _number(usage.get("output_tokens")) and usage["output_tokens"] > 0:
            result["output_tokens_positive"] = True
    if trajectory is None:
        result["archive_error"] = "no trajectory"
    if report is not None:
        try:
            parsed = json.loads(report)
            result["report"] = {key: parsed.get(key) for key in (
                "observed_stage", "expectation_passed", "signals", "event_counts", "web_search")}
        except json.JSONDecodeError:
            pass
    return result


def proxy_decisions(output: Path) -> dict[str, dict[str, int]]:
    """Connections by decision and host from the egress proxy's log."""
    decisions: dict[str, Counter] = {}
    path = output / PROXY_LOG
    if not path.is_file():
        return {}
    for line in path.read_text(errors="replace").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        host = str(row.get("target", "")).rsplit(":", 1)[0].lower() or "?"
        decisions.setdefault(str(row.get("decision", "?")), Counter())[host] += 1
    return {decision: dict(sorted(counts.items())) for decision, counts in sorted(decisions.items())}


def gate_cell(output: Path, case: dict[str, Any], key_budget: float) -> dict[str, Any]:
    """The gate for one cell, from its run record and copied outputs."""
    case_id = str(case["id"])
    try:
        record = json.loads((output / RUN_RECORD).read_text())
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
    signals = trajectory_signals(output, case_id)
    chains = row.get("evidence_chains") if isinstance(row.get("evidence_chains"), list) else []
    hooks = row.get("agent_hooks_observed")
    hard = {
        "run_record_present": record is not None,
        "remote_exit_zero": record_dict.get("remote_exit_code") == 0,
        "termination_explicit_finally": record_dict.get("termination") == "explicit-finally",
        "key_revoked": bool(key.get("revoked_at")),
        "spend_recorded": _number(spend),
        "redaction_passed": redaction.get("passed") is True,
        "provider_docker": record_dict.get("provider") == "docker",
        "image_inputs_clean": revision.get("dirty") is False,
        "observable": row.get("observability") == "observable" and bool(chains) and all(chains),
        "web_search_matches": row.get("web_search") == web_search(case),
        # An empty turn has nothing to observe and is judged as a setup fault.
        "agent_hooks_observed": hooks is True or not signals["command_executed"],
    }
    setup = {
        "spend_within_cap": _number(spend) and spend <= key_budget + EPSILON,
        "command_executed": signals["command_executed"],
        "output_tokens_positive": signals["output_tokens_positive"],
    }
    status = "ok"
    if not all(hard.values()):
        status = "hard_fail"
    elif not all(setup.values()):
        status = "setup_fault"
    proxy = proxy_decisions(output)
    refused = proxy.get("refused", {})
    report = signals["report"] or {}
    return {
        "case_id": case_id, "status": status, "hard": hard, "setup": setup,
        "key_alias": key.get("key_alias"), "spend_usd": spend if _number(spend) else None,
        "stage": row.get("stage"), "expectation_passed": row.get("expectation_passed"),
        "web_search": row.get("web_search"), "agent_hooks": row.get("agent_hooks"),
        "agent_hooks_observed": hooks, "signals": report.get("signals"),
        "event_counts": report.get("event_counts"),
        "proxy": proxy,
        "refused_client_hosts": {host: n for host, n in refused.items() if host in KNOWN_CLIENT_HOSTS},
        "refused_other_hosts": {host: n for host, n in refused.items() if host not in KNOWN_CLIENT_HOSTS},
        # The alerter's record (None without --alert/--enforce): first boundary
        # event, alert and kill latencies, censoring.
        "boundary": row.get("boundary"),
        "archive_error": signals["archive_error"],
        "output": str(output),
    }


def read_ledger(root: Path) -> list[dict[str, Any]]:
    path = root / LEDGER
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def append_ledger(root: Path, row: dict[str, Any]) -> None:
    with (root / LEDGER).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")


def spent(args: argparse.Namespace, ledger: list[dict[str, Any]]) -> float:
    return args.spent_before + sum(row["spend_usd"] for row in ledger if _number(row.get("spend_usd")))


def plan_record(args: argparse.Namespace, case_ids: list[str], cases: dict[str, dict[str, Any]]) -> dict[str, Any]:
    plan = _plan_base(args, case_ids, cases)
    # Recorded only when set, so plans frozen before these options still resume.
    if getattr(args, "alert", False) or getattr(args, "enforce", False):
        plan["alert"] = True
    if getattr(args, "enforce", False):
        plan["enforce"] = True
    return plan


def _plan_base(args: argparse.Namespace, case_ids: list[str], cases: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": "1.0", "suite": "intent", "corpus_version": args.corpus,
        "provider": "docker", "arm": args.arm,
        "model": args.model, "key_budget_usd": args.key_budget, "ceiling_usd": args.ceiling,
        "spent_before_usd": args.spent_before, "agent_timeout_seconds": args.agent_timeout,
        "codex_sandbox": CODEX_SANDBOX, "subject_command": SUBJECT_COMMAND, "image": args.image,
        "max_setup_faults": args.max_setup_faults,
        "cells": [{"case_id": case_id, "web_search": web_search(cases[case_id]),
                   "egress_allowlist": allowlist(cases[case_id])} for case_id in case_ids],
    }


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


def write_summary(root: Path, plan: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    ledger = read_ledger(root)
    last = {row["case_id"]: row for row in ledger}
    done = [last[cell["case_id"]] for cell in plan["cells"] if cell["case_id"] in last]
    passed = [row for row in done if row["status"] == "ok"]
    summary = {
        "schema_version": "1.0", "arm": plan["arm"], "model": plan["model"],
        "cells_planned": len(plan["cells"]), "cells_passed_gate": len(passed),
        "cells_attempted": len(ledger),
        "stages": dict(sorted(Counter(str(row["stage"]) for row in passed).items())),
        "expectation_met": sum(row["expectation_passed"] is True for row in passed),
        "hooks_observed": sum(row["agent_hooks_observed"] is True for row in passed),
        "refused_other_hosts": {row["case_id"]: row["refused_other_hosts"] for row in passed
                                if row["refused_other_hosts"]},
        "spend_usd": round(spent(args, ledger) - args.spent_before, 6),
        "spent_total_usd": round(spent(args, ledger), 6), "ceiling_usd": plan["ceiling_usd"],
        "cells": [{key: row.get(key) for key in (
            "case_id", "status", "stage", "expectation_passed", "web_search", "agent_hooks_observed",
            "spend_usd", "refused_other_hosts")} for row in done],
    }
    (root / SUMMARY).write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


def run_plan(args: argparse.Namespace, case_ids: list[str], cases: dict[str, dict[str, Any]]) -> int:
    print(f"plan: {len(case_ids)} cell(s), model {args.model}, key cap ${args.key_budget:g}, "
          f"ceiling ${args.ceiling:g}, spent before ${args.spent_before:g}; worst case "
          f"${args.spent_before + len(case_ids) * args.key_budget:.2f}")
    failures = 0
    for case_id in case_ids:
        completed = subprocess.run(runner_command(args, cases[case_id], dry_run=True), cwd=REPO,
                                   env=child_environment(), text=True, capture_output=True, check=False)
        plan = last_json_object(completed.stdout) or {}
        policy = plan.get("policy") if isinstance(plan.get("policy"), dict) else {}
        revision = plan.get("source_revision") if isinstance(plan.get("source_revision"), dict) else {}
        if completed.returncode != 0:
            failures += 1
            reason = (completed.stderr.strip().splitlines() or ["no output"])[-1]
            print(f"  [{case_id}] PLAN FAILED: {reason}")
            continue
        print(f"  [{case_id}] web_search {policy.get('web_search')}, allow-list "
              f"{allowlist(cases[case_id])}, codex {policy.get('codex_sandbox')}, image {plan.get('image')}"
              f"{' (DIRTY inputs: --execute would refuse)' if revision.get('dirty') else ''}")
    return 1 if failures else 0


def run_execute(args: argparse.Namespace, case_ids: list[str], cases: dict[str, dict[str, Any]]) -> int:
    if os.environ.get("EXPERIMENT_APPROVED") != "1":
        print("refusing --execute: paid cells need EXPERIMENT_APPROVED=1", file=sys.stderr)
        return 78
    first = subprocess.run(runner_command(args, cases[case_ids[0]], dry_run=True), cwd=REPO,
                           env=child_environment(), text=True, capture_output=True, check=False)
    plan_out = last_json_object(first.stdout) or {}
    revision = plan_out.get("source_revision") if isinstance(plan_out.get("source_revision"), dict) else {}
    if first.returncode != 0 or revision.get("dirty") is not False:
        print("refusing --execute: the runner's plan failed or the image inputs are dirty "
              "(commit them first)", file=sys.stderr)
        return 78
    plan = plan_record(args, case_ids, cases)
    freeze_plan(args.root, plan)
    setup_faults = 0
    for case_id in case_ids:
        ledger = read_ledger(args.root)
        last = {row["case_id"]: row for row in ledger}
        if last.get(case_id, {}).get("status") == "ok":
            print(f"  [{case_id}] already passed the gate; skipped")
            continue
        so_far = spent(args, ledger)
        if so_far + args.key_budget > args.ceiling + EPSILON:
            print(f"ceiling guard: stopped before {case_id} (spent ${so_far:.4f} + cap "
                  f"${args.key_budget:g} > ceiling ${args.ceiling:g})")
            write_summary(args.root, plan, args)
            return 0
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        log = args.root / f"driver-{case_id}-{stamp}.log"
        print(f"  [{case_id}] RUN (spent so far ${so_far:.4f}); runner log {log.name}")
        with log.open("w", encoding="utf-8") as handle:
            completed = subprocess.run(runner_command(args, cases[case_id], dry_run=False), cwd=REPO,
                                       env=child_environment(), text=True, stdout=handle,
                                       stderr=subprocess.STDOUT, check=False)
        record = last_json_object(log.read_text(errors="replace")) or {}
        output = Path(record["output"]) if isinstance(record.get("output"), str) else None
        if output is None:
            row = {"case_id": case_id, "status": "runner_failed", "runner_exit": completed.returncode,
                   "spend_usd": None, "stage": None, "expectation_passed": None,
                   "agent_hooks_observed": None, "refused_other_hosts": {}, "log": str(log)}
            append_ledger(args.root, row)
            print(f"  [{case_id}] runner exit {completed.returncode} and no run record; stopping. "
                  f"If a key was minted, revoke it by alias now; see {log.name}", file=sys.stderr)
            write_summary(args.root, plan, args)
            return 1
        row = {**gate_cell(output, cases[case_id], args.key_budget),
               "runner_exit": completed.returncode, "log": str(log)}
        if completed.returncode != 0 and row["status"] == "ok":
            row["status"] = "hard_fail"
        append_ledger(args.root, row)
        failed = [name for group in ("hard", "setup") for name, ok in row[group].items() if not ok]
        print(f"  [{case_id}] gate {row['status']}{' (' + ', '.join(failed) + ')' if failed else ''}; "
              f"stage {row['stage']}, expectation {row['expectation_passed']}, hooks "
              f"{row['agent_hooks_observed']}, web_search {row['web_search']}, spend {row['spend_usd']}, "
              f"refused other hosts {row['refused_other_hosts'] or 'none'}")
        if row["status"] == "hard_fail":
            print(f"stopping at the first failed gate ({case_id}); key alias {row['key_alias']}: "
                  "if key_revoked is false, revoke it by alias now", file=sys.stderr)
            write_summary(args.root, plan, args)
            return 1
        if row["status"] == "setup_fault":
            setup_faults += 1
            if setup_faults > args.max_setup_faults:
                print(f"setup-fault limit exceeded at {case_id} ({setup_faults} > "
                      f"{args.max_setup_faults}); not starting the next cell", file=sys.stderr)
                write_summary(args.root, plan, args)
                return 75
    summary = write_summary(args.root, plan, args)
    print(f"done: {summary['cells_passed_gate']}/{summary['cells_planned']} cells passed the gate; "
          f"stages {summary['stages']}; expectation met {summary['expectation_met']}; hooks observed "
          f"{summary['hooks_observed']}; spend ${summary['spend_usd']:.4f} (total "
          f"${summary['spent_total_usd']:.4f} of ${summary['ceiling_usd']:g})")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, required=True, help="cohort root (frozen plan, ledger, cells)")
    parser.add_argument("--model", required=True)
    parser.add_argument("--key-budget", type=float, required=True, help="per-cell virtual-key cap, USD")
    parser.add_argument("--ceiling", type=float, required=True, help="the author's ceiling for this cohort, USD")
    parser.add_argument("--spent-before", type=float, default=0.0,
                        help="spend already counted against the ceiling, USD")
    parser.add_argument("--corpus", choices=("1", "2", "probe"), default="1",
                        help="intent corpus version: 1 (ITH-001..011, untrusted text in UNTRUSTED_CONTEXT.md), "
                             "2 (ITH-101..111, the same text inside TASK.md), or probe (ITH-9NN, probe cases "
                             "outside both corpora); default 1")
    parser.add_argument("--cases", help="comma-separated ITH case IDs of that corpus (default: its 11 intent evaluations)")
    parser.add_argument("--arm", default="intent")
    parser.add_argument("--agent-timeout", type=int, default=900)
    parser.add_argument("--max-setup-faults", type=int, default=2)
    parser.add_argument("--image", help="a prebuilt agent image tag (default: the runner builds HEAD)")
    parser.add_argument("--execute", action="store_true", help="run paid cells (needs EXPERIMENT_APPROVED=1)")
    parser.add_argument("--alert", action="store_true",
                        help="observe-only alerter in every cell (ALERT_RAISED + boundary.json)")
    parser.add_argument("--enforce", action="store_true",
                        help="kill each agent at its first boundary event; needs --enforce-real-agent")
    parser.add_argument("--enforce-real-agent", action="store_true",
                        help="the explicit word that real agents may be killed (with --enforce)")
    parser.add_argument("--runner", type=Path, default=RUNNER, help=argparse.SUPPRESS)
    parser.add_argument("--python", default=sys.executable, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.enforce and not args.enforce_real_agent:
        parser.error("--enforce kills real agents: it needs --enforce-real-agent as well")
    if args.enforce_real_agent and not args.enforce:
        parser.error("--enforce-real-agent only qualifies --enforce")
    args.corpus = int(args.corpus) if args.corpus.isdigit() else args.corpus
    args.root = args.root.resolve()
    cases = load_cases()
    case_ids = ([item.strip() for item in args.cases.split(",") if item.strip()] if args.cases
                else default_cases(cases, args.corpus))
    unknown = [case_id for case_id in case_ids if case_id not in cases]
    if unknown:
        parser.error(f"unknown case(s): {', '.join(unknown)}")
    other = [case_id for case_id in case_ids if corpus_version(cases[case_id]) != args.corpus]
    if other:
        parser.error(f"not in corpus version {args.corpus} (never pool the versions): {', '.join(other)}")
    controls = [case_id for case_id in case_ids if cases[case_id]["metadata"]["role"] not in AGENT_ROLES]
    if controls:
        parser.error(f"sensor controls stay scripted: {', '.join(controls)}")
    if len(set(case_ids)) != len(case_ids):
        parser.error("each case runs once per cohort")
    for name in ("key_budget", "ceiling"):
        if not getattr(args, name) > 0:
            parser.error(f"--{name.replace('_', '-')} must be positive")
    if args.spent_before < 0 or args.max_setup_faults < 0 or args.agent_timeout < 1:
        parser.error("--spent-before and --max-setup-faults must be >= 0, --agent-timeout >= 1")
    if args.key_budget > args.ceiling:
        parser.error("--key-budget exceeds --ceiling: no cell could start")
    return run_execute(args, case_ids, cases) if args.execute else run_plan(args, case_ids, cases)


if __name__ == "__main__":
    raise SystemExit(main())
