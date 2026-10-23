#!/usr/bin/env bash
# Freeze the single-trial schema-v2 manifests for the end-to-end extension cohort
# (cybergym-e2e-ext25-v1), one per trial 1..2, pinned to a dedicated
# 25-task snapshot (results/modal_snapshot.ext25.json) and HEAD. Same manifest shape as freeze_e2e_repeats.sh; the task list
# and its selection criteria come from reference/cybergym_e2e_ext25_cohort.v1.json.
# Read-only except for writing reference/*.json.
#
#   - Two trials per task, matching the two-trial repeats cohort.
#   - The manifests must stay UNCOMMITTED (committing advances HEAD and breaks
#     their own source-revision check); re-freeze after any commit.
#   - Smoke task is curl/arvo_66012, already known to install and grade on this
#     image (it is in the repeats cohort).
#
#   bash freeze_e2e_ext25.sh        # trials 1 and 2
#   bash freeze_e2e_ext25.sh 2      # only trial 2, e.g. to re-freeze an unrun trial
set -euo pipefail

cd "$(dirname "$0")"

python3 - "$@" <<'PY'
import json, hashlib, subprocess, pathlib, sys
TRIALS = [int(a) for a in sys.argv[1:]] or [1, 2]
assert all(k in (1, 2) for k in TRIALS), "the extension cohort has two trials"
SNAP = "results/modal_snapshot.ext25.json"   # baked from txt/tasks.ext25.txt; the tracked 22-task snapshot lacks 23 of these tasks
COHORT_FILE = "reference/cybergym_e2e_ext25_cohort.v1.json"
commit = subprocess.run(["git","rev-parse","HEAD"],capture_output=True,text=True,check=True).stdout.strip()
diff   = subprocess.run(["git","diff","--binary","HEAD","--","."],capture_output=True,check=True).stdout
assert pathlib.Path(SNAP).is_file(), f"bake the extension snapshot first: {SNAP}"
snap_b = pathlib.Path(SNAP).read_bytes(); snap = json.loads(snap_b)
assert set(snap["tasks"]) >= set(json.load(open("reference/cybergym_e2e_ext25_cohort.v1.json"))["ordered_tasks"]), "snapshot lacks cohort tasks"
cohort_b = pathlib.Path(COHORT_FILE).read_bytes(); cohort = json.loads(cohort_b)
tasks  = cohort["ordered_tasks"]
assert len(tasks) == 25 and len(set(tasks)) == 25, len(tasks)
master = {l.strip() for l in open("reference/cybergym_tasks.master.txt") if l.strip()}
assert not (set(tasks) - master), sorted(set(tasks) - master)
MODEL, COHORT, SMOKE, PER_CELL = "gpt-5.6-luna", cohort["cohort_id"], "curl/arvo_66012", 0.13
assert SMOKE in tasks
for K in TRIALS:
    m = {
      "schema_version":2, "cohort_id":COHORT, "benchmark":"cybergym-e2e", "mode":"e2e",
      "provider":"modal", "provisioning":"snapshot", "model_provider":"litellm",
      "litellm_model_id":MODEL, "agent":"codex",
      "source_revision":{"commit":commit, "dirty":bool(diff),
                         "diff_sha256":hashlib.sha256(diff).hexdigest(),
                         "diff_scope":"git diff --binary HEAD -- ."},
      "snapshot_manifest":SNAP, "snapshot_manifest_sha256":hashlib.sha256(snap_b).hexdigest(),
      "snapshot_image_id":snap["snapshot_image_id"],
      "ordered_tasks":tasks, "trial_numbers":[K],
      "batch_id":f"{COHORT}-t{K}", "smoke_task":SMOKE,
      "retry_policy":{"max_attempts":3,"retry_sleep_s":20,
                      "retryable_statuses":["error","oracle_unavailable"]},
      "output_root":"results/modal_trials_e2e", "paper_output_root":f"results/paper/{COHORT}",
      "exclusion_rules":{"terminal_statuses":["success","failed","no_patch","no_poc","other_vuln","oracle_mismatch"],
          "retry_missing_result":True,"retry_malformed_result":True,
          "unknown_status_action":"exclude-and-stop-cell",
          "note":"Terminal model outcomes remain in the capability denominator; only preserved infrastructure-invalid attempts are excluded."},
      "cost_estimate":{"currency":"USD","planned_cells":len(tasks),"estimated_cost_per_cell":PER_CELL,
          "estimated_total":round(len(tasks)*PER_CELL,2),
          "basis":"Per-cell estimate carried from cybergym-e2e-paper-v1 (measured curl pilot $0.124).",
          "note":"Planning estimate only, not a provider-side hard cap."},
      "selection":{"cohort_file":COHORT_FILE,
                   "cohort_file_sha256":hashlib.sha256(cohort_b).hexdigest(),
                   "criteria":cohort["selection_criteria"]}}
    out = pathlib.Path(f"reference/{COHORT}.t{K}.json")
    if out.exists() and out.read_text() != json.dumps(m,indent=1)+"\n":
        raise SystemExit(f"refusing to overwrite differing manifest: {out} (delete it first to re-freeze)")
    out.write_text(json.dumps(m,indent=1)+"\n")
    print("wrote", out, "| commit", commit[:12], "| image", snap["snapshot_image_id"], "| trial", K)
PY
