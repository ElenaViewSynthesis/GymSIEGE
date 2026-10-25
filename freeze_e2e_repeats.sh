#!/usr/bin/env bash
# Freeze the 2 single-trial schema-v2 manifests for the end-to-end repeated-trial
# cohort (cybergym-e2e-repeats-v1), one per trial 1..2, pinned to the current
# recipe-v3 snapshot and HEAD. Read-only except for writing reference/*.json.
# The cohort runs two trials per task; trials above 2 are refused.
#
#   - One trial per manifest/batch: the harness smoke gate requires exactly one
#     trial_number, and each batch dir pins its cohort-manifest sha.
#   - Pins the current snapshot (cybergym/snapshots/modal_snapshot.json) and the
#     current HEAD commit; the manifests must stay UNCOMMITTED (committing would
#     advance HEAD and break their own source-revision check).
#
# Run from anywhere; it cd's to the repo. After freezing: --phase plan (free),
# then --phase smoke/full (paid) per trial.
#
#   bash freeze_e2e_repeats.sh            # trials 1..2
#   bash freeze_e2e_repeats.sh 2          # only this trial, e.g. to re-freeze
#                                         # unrun trials after a commit moved HEAD
#                                         # without touching a running trial's manifest
set -euo pipefail

cd "$(dirname "$0")"

python3 - "$@" <<'PY'
import json, hashlib, subprocess, pathlib, sys
MAX_TRIALS = 2
TRIALS = [int(a) for a in sys.argv[1:]] or list(range(1, MAX_TRIALS + 1))
bad = [k for k in TRIALS if not 1 <= k <= MAX_TRIALS]
if bad:
    raise SystemExit(f"trial(s) {bad} outside 1..{MAX_TRIALS}: the cohort runs {MAX_TRIALS} trials per task")
SNAP = "cybergym/snapshots/modal_snapshot.json"
commit = subprocess.run(["git","rev-parse","HEAD"],capture_output=True,text=True,check=True).stdout.strip()
diff   = subprocess.run(["git","diff","--binary","HEAD","--","."],capture_output=True,check=True).stdout
snap_b = pathlib.Path(SNAP).read_bytes(); snap = json.loads(snap_b)
tasks  = json.load(open("reference/cybergym_e2e_paper_cohort.v1.json"))["ordered_tasks"]
assert len(tasks) == 22, len(tasks)
MODEL, COHORT, SMOKE, PER_CELL = "gpt-5.6-luna", "cybergym-e2e-repeats-v1", "arrow/arvo_41221", 0.13
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
          "note":"Planning estimate only, not a provider-side hard cap."}}
    out = pathlib.Path(f"reference/{COHORT}.t{K}.json")
    if out.exists() and out.read_text() != json.dumps(m,indent=1)+"\n":
        raise SystemExit(f"refusing to overwrite differing manifest: {out} (delete it first to re-freeze)")
    out.write_text(json.dumps(m,indent=1)+"\n")
    print("wrote", out, "| commit", commit[:12], "| image", snap["snapshot_image_id"], "| trial", K)
PY
