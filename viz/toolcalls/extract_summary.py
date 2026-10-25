#!/usr/bin/env python3
"""Per-task tool-call summary for the interactive chart (one row per task).

Reads each published cell's Codex trajectory log and counts the agent's tool
calls (completed ``command_execution`` and ``file_change`` items), alongside the
reasoning/message counts and the published outcome, cost and wall-clock. Emits
the flat JSON the chart embeds as ``DATA`` (see ``build.py``).

Run it from a checkout that has the gitignored ``artifacts/`` and ``results/``
directories (the paid-run outputs); override the repo root with GYMSIEGE_ROOT.

    python3 viz/toolcalls/extract_summary.py viz/toolcalls/datasets/summary.json
"""
import glob
import json
import os
import sys
from pathlib import Path

ROOT = Path(os.environ.get("GYMSIEGE_ROOT") or Path(__file__).resolve().parents[2])

# cohort -> (artifact search roots in priority order, published-results batch, trial)
COHORTS = {
    "repeats-t2": ([ROOT / "artifacts", ROOT / "artifacts/_repeats-v1-backup-2026-10-22"],
                   "cybergym-e2e-repeats-v1-t2", 2),
    "ext25-t1":   ([ROOT / "artifacts/_ext25-v1", ROOT / "artifacts"],
                   "cybergym-e2e-ext25-v1-t1", 1),
    "ext25-t2":   ([ROOT / "artifacts/_ext25-v1", ROOT / "artifacts"],
                   "cybergym-e2e-ext25-v1-t2", 2),
}


def count_log(path):
    tool = reasoning = message = 0
    for line in open(path, encoding="utf-8", errors="replace"):
        try:
            e = json.loads(line)
        except Exception:
            continue
        if e.get("type") != "item.completed":
            continue
        t = (e.get("item") or {}).get("type")
        if t in ("command_execution", "file_change"):
            tool += 1
        elif t == "reasoning":
            reasoning += 1
        elif t == "agent_message":
            message += 1
    return tool, reasoning, message


def find_traj(dirs, safe, trial):
    for base in dirs:
        logs = sorted(glob.glob(str(base / safe / "e2e" / f"trial-{trial}" / "trajectory_attempt_*.log")))
        if logs:
            return logs
    return []


def main(out_path):
    out = []
    for cohort, (dirs, batch, trial) in COHORTS.items():
        pub_dir = ROOT / "results/modal_trials_e2e" / batch / "published-results"
        for pf in sorted(glob.glob(str(pub_dir / "*.json"))):
            d = json.load(open(pf, encoding="utf-8"))
            task = d["task"]
            tool = reasoning = message = 0
            for lg in find_traj(dirs, task.replace("/", "_"), trial):
                tc, rc, mc = count_log(lg)
                tool += tc
                reasoning += rc
                message += mc
            out.append({
                "c": cohort, "t": task, "p": task.split("/")[0], "s": d["status"],
                "tc": tool, "rs": reasoning,
                "cost": round(d.get("solver_cost_usd") or 0, 4),
                "min": round((d.get("t_total_s") or 0) / 60, 1),
                "ag": bool(d.get("agent_success")), "gt": bool(d.get("gt_success")),
            })
    out.sort(key=lambda r: (r["c"], -r["tc"]))
    Path(out_path).write_text(json.dumps(out, separators=(",", ":")), encoding="utf-8")
    for c in COHORTS:
        rows = [r for r in out if r["c"] == c]
        print(f"{c}: {len(rows)} tasks, {sum(r['tc'] for r in rows)} tool calls")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "viz/toolcalls/datasets/summary.json")
