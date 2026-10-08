#!/usr/bin/env bash
# Watch a single sharded cybergym-pinned-modal.yml run to completion and print a
# per-shard + per-task roll-up. READ-ONLY: never dispatches, cancels, or writes
# to GitHub.
#
# Why this is separate from watch_exploitbench_sweep.sh: an ExploitBench sweep is
# MANY serial dispatch RUNS (one env each); a CyberGym run is ONE run with a
# matrix of shard JOBS. This tracks one run id's jobs, then rolls up per-task
# results by downloading the run's artifacts (no AWS creds needed) and filtering
# to this run by `started_at` (shard artifacts can also contain pre-existing
# canonical result JSONs from earlier runs).
#
# Usage:
#   ./monitoring/watch_cybergym_run.sh [RUN_ID]        # default: newest dispatch run
#   EB_POLL=45 ./monitoring/watch_cybergym_run.sh 37668408810
#   EB_ONCE=1  ./monitoring/watch_cybergym_run.sh      # one snapshot + roll-up, no loop
set -uo pipefail

WF="cybergym-pinned-modal.yml"
POLL="${EB_POLL:-45}"
ONCE="${EB_ONCE:-0}"
RID="${1:-${EB_RUN_ID:-}}"

command -v gh >/dev/null || { echo "gh CLI not found on PATH." >&2; exit 1; }
if [ -z "$RID" ]; then
  RID="$(gh run list --workflow="$WF" --event=workflow_dispatch --limit 1 \
          --json databaseId -q '.[0].databaseId' 2>/dev/null)"
fi
[ -n "$RID" ] || { echo "No run id (pass one, or dispatch a run first)." >&2; exit 1; }
CREATED="$(gh run view "$RID" --json createdAt -q .createdAt 2>/dev/null)"
echo "Watching $WF run $RID (created $CREATED)  poll=${POLL}s  (Ctrl-C to stop)"

# One status line; exits 0 when the run is completed, else 2.
poll_once() {
  gh run view "$RID" --json status,conclusion,jobs 2>/dev/null | python3 - <<'PY'
import sys, json, datetime
from collections import Counter
try:
    d = json.load(sys.stdin)
except Exception:
    print("  (gh returned no data; will retry)"); sys.exit(2)
runj = [j for j in d.get("jobs", []) if j.get("name","").startswith("run")]
st = Counter(j["status"] for j in runj)
done = sum(1 for j in runj if j["status"] == "completed")
inflight = sum(st.get(k,0) for k in ("in_progress","queued","waiting","pending","requested"))
cc = Counter((j.get("conclusion") or "-") for j in runj)
ts = datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S")
print(f"[{ts}] run={d['status']}  shards done {done}/{len(runj)}  running/queued {inflight}"
      f"  | success {cc.get('success',0)} fail {sum(v for k,v in cc.items() if k not in ('success','-'))}")
sys.exit(0 if d.get("status") == "completed" else 2)
PY
}

while : ; do
  if poll_once; then break; fi
  [ "$ONCE" = "1" ] && break
  sleep "$POLL"
done

echo
echo "=== Per-shard job status (run $RID) ==="
gh run view "$RID" --json jobs \
  -q '.jobs[] | select(.name|startswith("run")) | "\(.name)\t\(.conclusion // .status)"'

echo
echo "=== Per-task roll-up ==="
tmp="$(mktemp -d)"
if gh run download "$RID" -D "$tmp" >/dev/null 2>&1; then
  python3 - "$tmp" "${CREATED:-}" <<'PY'
import sys, glob, json, os
from collections import Counter
root, created = sys.argv[1], (sys.argv[2] or "")[:16]   # trim to minute, ISO compares lexically
best = {}
for f in glob.glob(os.path.join(root, "**", "*.json"), recursive=True):
    try:
        d = json.load(open(f))
    except Exception:
        continue
    if "status" not in d or "task" not in d:
        continue
    sa = d.get("started_at", "")
    if created and sa and sa < created:          # skip pre-existing canonical results
        continue
    t = d["task"]
    if t not in best or sa > best[t].get("started_at", ""):
        best[t] = d
if not best:
    print("  (no per-task result JSONs matched this run; check artifacts)")
else:
    tally = Counter()
    print(f"  {'TASK':<34} {'STATUS':<16} NOTE")
    for t in sorted(best):
        d = best[t]; s = d.get("status", "?"); tally[s] += 1
        note = d.get("failure_reason") or d.get("last_stage") or ""
        ec = ""
        if d.get("vul_exit_code") is not None or d.get("fix_exit_code") is not None:
            ec = f"vul={d.get('vul_exit_code')} fix={d.get('fix_exit_code')}"
        print(f"  {t:<34} {str(s):<16} {str(note)[:30]} {ec}")
    print(f"\n  tasks: {len(best)}   status tally: {dict(tally)}")
    # Point at the agent logs when nothing succeeded (the common agent-phase failure).
    if tally.get("success", 0) == 0:
        logs = glob.glob(os.path.join(root, "**", "run_agent.log"), recursive=True)
        print(f"\n  0 successes. run_agent.log artifacts to inspect: {len(logs)}")
        for p in logs[:3]:
            print(f"    {p}")
PY
else
  echo "  (gh run download failed; the run may still be in progress or have no artifacts)"
fi
rm -rf "$tmp"
echo
echo "Run $RID roll-up complete."
