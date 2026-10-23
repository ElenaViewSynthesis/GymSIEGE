#!/usr/bin/env python3
"""Per-task tool-call detail for the interactive chart's expand panels.

For every published cell, lists each command the agent ran with a category and
its shell exit status, plus per-category counts. Emits JSON keyed by
``cohort|task`` that the chart embeds as ``DETAIL`` (see ``build.py``).

Categories are keyword heuristics applied to the command (after stripping the
``/bin/bash -lc "..."`` wrapper), in priority order so a pipeline that both
reads and searches is tagged by its most significant action.

Run from a checkout with the gitignored ``artifacts/`` and ``results/`` dirs;
override the repo root with GYMSIEGE_ROOT.

    python3 viz/toolcalls/extract_detail.py viz/toolcalls/datasets/detail.json
"""
import glob
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(os.environ.get("GYMSIEGE_ROOT") or Path(__file__).resolve().parents[2])

COHORTS = {
    "repeats-t2": ([ROOT / "artifacts", ROOT / "artifacts/_repeats-v1-backup-2026-10-22"],
                   "cybergym-e2e-repeats-v1-t2", 2),
    "ext25-t1":   ([ROOT / "artifacts/_ext25-v1", ROOT / "artifacts"],
                   "cybergym-e2e-ext25-v1-t1", 1),
}

CATS = [
    ("edit",   re.compile(r"\bapply_patch\b|\bpatch \b|\bpatch<|\bsed -i\b|\btee \b| > /src/|>>?\s*\S+\.(c|cc|cpp|h|py|sh|patch)\b|git apply")),
    ("build",  re.compile(r"\bmake\b|\bcmake\b|\bninja\b|\./configure|\bgcc\b|\bg\+\+|\bclang\b|\bcc \b|compile|build\.sh|autogen|\bcargo \b|go build|meson\b")),
    ("run",    re.compile(r"/out/|run_poc|\./fuzz|detonate|poc\.bin|\brun\.sh\b|LLVMFuzzer")),
    ("test",   re.compile(r"\bctest\b|make (test|check)|\.phpt\b|run-tests|\bpytest\b|\bcheck\.sh")),
    ("search", re.compile(r"\brg \b|\brg$|\bgrep\b|\bfind \b|rg --files|\blocate\b|\bls \b|\bls$")),
    ("read",   re.compile(r"\bsed -n|\bcat \b|\bhead\b|\btail\b|\bnl \b|\bless\b|\bwc \b|\bfile \b|\bstrings\b|readelf|objdump|\bnm \b|\bxxd\b|\bod \b")),
]


def unwrap(cmd):
    m = re.match(r'^/bin/bash -l?c\s+"(.*)"$', cmd, re.S) or re.match(r"^/bin/bash -l?c\s+'(.*)'$", cmd, re.S)
    inner = m.group(1) if m else cmd
    inner = inner.replace("\\n", " ").replace('\\"', '"').replace("\\\\", "\\")
    return re.sub(r"\s+", " ", inner).strip()


def categorize(inner):
    for name, rx in CATS:
        if rx.search(inner):
            return name
    return "shell"


def find_traj(dirs, safe, trial):
    for base in dirs:
        logs = sorted(glob.glob(str(base / safe / "e2e" / f"trial-{trial}" / "trajectory_attempt_*.log")))
        if logs:
            return logs
    return []


def main(out_path):
    out = {}
    for cohort, (dirs, batch, trial) in COHORTS.items():
        pub = sorted(glob.glob(str(ROOT / "results/modal_trials_e2e" / batch / "published-results" / "*.json")))
        for pf in pub:
            task = json.load(open(pf))["task"]
            calls, types = [], {}
            for lg in find_traj(dirs, task.replace("/", "_"), trial):
                for line in open(lg, encoding="utf-8", errors="replace"):
                    try:
                        e = json.loads(line)
                    except Exception:
                        continue
                    it = e.get("item") or {}
                    if e.get("type") != "item.completed":
                        continue
                    if it.get("type") == "command_execution":
                        inner = unwrap(it.get("command") or "")
                        calls.append([categorize(inner), 1 if it.get("exit_code") == 0 else 0, inner[:180]])
                    elif it.get("type") == "file_change":
                        ch = it.get("changes") or it.get("path") or "file edit"
                        calls.append(["edit", 1, ("edit: " + str(ch))[:180]])
            for c in calls:
                types[c[0]] = types.get(c[0], 0) + 1
            out[f"{cohort}|{task}"] = {"types": types, "calls": calls}
    Path(out_path).write_text(json.dumps(out, separators=(",", ":")), encoding="utf-8")
    print(f"{len(out)} tasks, {sum(len(v['calls']) for v in out.values())} commands")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "viz/toolcalls/datasets/detail.json")
