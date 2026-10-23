"""Table 2 (tab:passk) values from an aggregate_repeats_passk.py --k 1 2 --n 2 output dir.

pass@1 and pass@2 are taken over the tasks with both trials, so the two are
comparable; ffmpeg/oss-fuzz_385167047 (one valid trial) is left out of both.
Usage: table2_values.py OUT_DIR
"""
import csv, json, sys
from pathlib import Path
sys.path.insert(0, ".")
import aggregate_repeats_passk as agg

out = Path(sys.argv[1])
rows = list(csv.DictReader(open(out / "passk_by_task.csv")))
both = [r for r in rows if int(r["n"]) == 2]           # tasks with both trials
T = len(both)
pct = lambda x: f"{100 * x:.1f}"
def est(key):
    vals = [float(r[key]) for r in both]
    lo, hi = agg.task_bootstrap(vals, 20_000, 0)
    return sum(vals) / T, lo, hi

p1, p2 = est("pass@1"), est("pass@2")
disc = sum(int(r["c"]) == 1 for r in both)
print(f"tasks with two trials: {T} (of {len(rows)} loaded)")
print(f"pass@1 = {pct(p1[0])}% [{pct(p1[1])}, {pct(p1[2])}]")
print(f"pass@2 = {pct(p2[0])}% [{pct(p2[1])}, {pct(p2[2])}]")
print(f"discordant (c_i = 1): {disc} of {T};  identity check "
      f"pass@2-pass@1 = {p2[0] - p1[0]:.4f} vs disc/(2T) = {disc / (2 * T):.4f}")
print("discordant tasks:", ", ".join(r["task"] for r in both if int(r["c"]) == 1) or "none")

print("\n% ---- Table 2 end-to-end rows (paste over the --- cells) ----")
labels = {"success": r"\lblSuccess{}", "other_vuln": r"\lblOtherVuln{}", "failed": r"\lblFailed{}"}
order = ["success", "other_vuln", "failed"]
groups = sorted(csv.DictReader(open(out / "first_trial_groups.csv")),
                key=lambda g: order.index(g["first_trial_outcome"]) if g["first_trial_outcome"] in order else 9)
for g in groups:
    v1, v2 = ("---" if g[k] == "" else pct(float(g[k])) + r"\%" for k in ("pass@1", "pass@2"))
    print(f"End-to-end & {labels.get(g['first_trial_outcome'], g['first_trial_outcome'])} "
          f"& {g['tasks']} & {v1} & {v2} \\\\")
print(rf"\multicolumn{{3}}{{@{{}}l}}{{\textbf{{All {T} tasks with two valid trials, end-to-end}}}}"
      rf" & {pct(p1[0])}\% [{pct(p1[1])}, {pct(p1[2])}] & {pct(p2[0])}\% [{pct(p2[1])}, {pct(p2[2])}] \\")
print("\n% ---- caption sentence ----")
print(rf"End-to-end, pass@1 is {pct(p1[0])}\% [{pct(p1[1])}, {pct(p1[2])}] and pass@2 is "
      rf"{pct(p2[0])}\% [{pct(p2[1])}, {pct(p2[2])}], with {disc} of {T} tasks discordant")
missing = json.load(open(out / "provenance.json")).get("missing_cells", [])
print(f"\n{'PROVISIONAL: ' + str(len(missing)) + ' cells unpublished' if missing else 'all cells published'}")
