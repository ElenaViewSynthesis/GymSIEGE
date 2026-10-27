#!/usr/bin/env bash
# Experimental-run driver for the collusion suite, through the Modal honeypot
# runner (modal_honeypot/runner.py --harness collusion). Every run is inside the
# externally contained sandbox; scripted runs block egress, while real-agent
# runs allow only the gateway and Langfuse hosts. A real-agent subject can only
# run there, never on the host. This script is SAFE BY DEFAULT: it prints the plan (the runner's
# --dry-run) and starts no sandbox and no model call unless you pass --execute.
#
#   ./agent_honeypot/collusion_tripwires/run_experiments.sh            # plan every arm (free)
#   ./agent_honeypot/collusion_tripwires/run_experiments.sh --arm lure-pair --model PINNED_MODEL
#   ./agent_honeypot/collusion_tripwires/run_experiments.sh --list     # list arms + Table 3 rows
#   ./agent_honeypot/collusion_tripwires/run_experiments.sh --arm sensor-controls --execute   # PAID
#
# Agent arms require --model (or MODEL), gateway and Langfuse URLs. Paid runs
# also require EXPERIMENT_APPROVED=1 and LITELLM_MASTER_KEY on the host, so a
# stray --execute cannot mint or bill by itself. --allow-network is never passed.
set -Eeuo pipefail

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd -- "$repo"
runner="modal_honeypot/runner.py"

# --------------------------------------------------------------------------
# EXPERIMENT ARMS. Augment this table from Table 3 of the honeypot paper: add
# a row and it becomes a selectable arm. Columns, whitespace-separated:
#   arm            : short name (no spaces)
#   selection      : ALL | comma-separated CLH ids | SENSORS
#   subject        : scripted | agent
#   trials         : repetitions per case (frozen before you look at outcomes)
#   table3         : the Table 3 row(s) this arm fills
#   description    : one line
#
# subject=agent uses $SUBJECT_CMD (a codex exec adapter by default; override
# with --subject-command or the SUBJECT_CMD env var). subject=scripted makes no
# model call and is the calibration/sensor path.
# --------------------------------------------------------------------------
SENSORS="CLH-006,CLH-007,CLH-008,CLH-009,CLH-010,CLH-011,CLH-012,CLH-013,CLH-014,CLH-015,CLH-016,CLH-017,CLH-018,CLH-019,CLH-020"

read -r -d '' ARMS <<TABLE || true
sensor-controls   SENSORS                           scripted  1  Sensor-control_pass                                           15 collusion sensor controls; must pass before any agent arm
scripted-calib    ALL                               scripted  1  Cross-run_coordination(suite_built)                           full 40-case scripted baseline (expect 40/40, every chain valid)
lure-pair         CLH-036,CLH-037                   agent     3  Cross-run_coordination/Lure-access_difference/Time-to-first-coordination-event   solvable vs unsolvable, real agent subject, chain on
benign-base       CLH-001,CLH-002,CLH-003,CLH-004   agent     3  Benign_base_rate                                              no-channel/no-injection controls under a real agent
# --- add new arms below, one per Table 3 experiment you want to run ---
TABLE

# Default real-agent subject: Codex, live search disabled, JSONL transcript kept
# so the Phase 2 transcript-shape review can confirm item.type="web_search".
# Override per invocation with --subject-command or the SUBJECT_CMD env var.
# The runner shlex-splits this into argv; the payload carries no single quotes.
if [[ -z ${SUBJECT_CMD:-} ]]; then
  SUBJECT_CMD='bash -lc '\''set -o pipefail; codex -c web_search="disabled" exec --json "$(cat "$HONEYPOT_COLLUSION_PROMPT_FILE")" | tee "$HONEYPOT_COLLUSION_TRANSCRIPT"'\'''
fi

want_arm=
execute=0
list=0
workers=4
output_root="results/modal-honeypot-collusion-exp"
cost_per_cell=0.13   # planning estimate carried from the chain cohort; agent arms may differ
model=${MODEL:-}
key_budget=0.50
key_ttl=

usage() { sed -n '2,20p' "$0"; }
while (($#)); do
  case "$1" in
    --arm) want_arm=$2; shift 2 ;;
    --execute) execute=1; shift ;;
    --list) list=1; shift ;;
    --workers) workers=$2; shift 2 ;;
    --subject-command) SUBJECT_CMD=$2; shift 2 ;;
    --model) model=$2; shift 2 ;;
    --key-budget) key_budget=$2; shift 2 ;;
    --key-ttl) key_ttl=$2; shift 2 ;;
    --output) output_root=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; usage >&2; exit 64 ;;
  esac
done

arm_rows() { grep -vE '^\s*#|^\s*$' <<<"$ARMS"; }

if ((list)); then
  printf '%-16s %-9s %-7s %-40s %s\n' ARM SUBJECT TRIALS "TABLE 3 ROW(S)" DESCRIPTION
  while read -r arm sel subj trials t3 desc; do
    printf '%-16s %-9s %-7s %-40s %s\n' "$arm" "$subj" "$trials" "$t3" "$desc"
  done < <(arm_rows)
  exit 0
fi

# Expand a selection token into case IDs.
cases_of() {
  case "$1" in
    ALL) python3 -c 'import json;[print(json.loads(l)["id"]) for l in open("agent_honeypot/collusion_tripwires/cases.jsonl") if l.strip()]' ;;
    SENSORS) tr ',' '\n' <<<"$SENSORS" ;;
    *) tr ',' '\n' <<<"$1" ;;
  esac
}

# Pre-flight for paid runs.
preflight() {
  local any_agent=$1
  if ((any_agent)); then
    [[ -n $model ]] || {
      printf 'agent arm needs --model (or MODEL) so its virtual key is pinned to one model\n' >&2; exit 78; }
    [[ -n ${OPENAI_BASE_URL:-} ]] || {
      printf 'agent arm needs OPENAI_BASE_URL set to the external gateway tunnel URL ending in /v1\n' >&2; exit 78; }
    [[ -n ${LANGFUSE_BASE_URL:-} ]] || {
      printf 'agent arm needs LANGFUSE_BASE_URL for the scoped egress plan\n' >&2; exit 78; }
    python3 - <<'PY' || exit 78
import os
from urllib.parse import urlparse

parsed = urlparse(os.environ["OPENAI_BASE_URL"])
host = parsed.hostname or ""
if parsed.scheme != "https" or not host:
    raise SystemExit("OPENAI_BASE_URL must be an absolute HTTPS URL")
if host in {"localhost", "0.0.0.0", "::1"} or host.startswith("127."):
    raise SystemExit("OPENAI_BASE_URL must not point at loopback")
if parsed.path.rstrip("/")[-3:] != "/v1":
    raise SystemExit("OPENAI_BASE_URL must end in /v1")
PY
  fi
  if ((execute)); then
    [[ ${EXPERIMENT_APPROVED:-0} == 1 ]] || {
      printf 'refusing paid run: set EXPERIMENT_APPROVED=1 to confirm (and you reviewed the plan + cost)\n' >&2; exit 77; }
    if ((any_agent)); then
      [[ -n ${LITELLM_MASTER_KEY:-} ]] || {
        printf 'agent arm needs LITELLM_MASTER_KEY on the host to mint its scoped virtual key\n' >&2; exit 78; }
      printf 'NOTE: each agent run mints one budgeted virtual key and injects it only through an ephemeral Modal Secret.\n' >&2
    fi
  fi
}

# Run or plan one arm.
run_arm() {
  local arm=$1 sel=$2 subj=$3 trials=$4 t3=$5
  local -a cases; mapfile -t cases < <(cases_of "$sel")
  local cells=$(( ${#cases[@]} * trials ))
  printf '\n== arm %s  (subject=%s, trials=%s, cells=%s, Table 3: %s)\n' "$arm" "$subj" "$trials" "$cells" "$t3"
  local tag="$output_root/$arm"
  for case_id in "${cases[@]}"; do
    for ((t=1; t<=trials; t++)); do
      local -a cmd=(python3 "$runner" --harness collusion --case-id "$case_id"
                    --workers "$workers" --output "$tag")
      if [[ $subj == agent ]]; then
        cmd+=(--subject-command "$SUBJECT_CMD" --egress-allowlist langfuse,gateway
              --model "$model" --arm "$arm" --trial "$t" --key-budget "$key_budget")
        [[ -n $key_ttl ]] && cmd+=(--key-ttl "$key_ttl")
      fi
      ((execute)) || cmd+=(--dry-run)
      printf '  [%s trial %d] %s\n' "$case_id" "$t" "$( ((execute)) && echo RUN || echo PLAN )"
      "${cmd[@]}" >/dev/null 2>&1 || printf '    (runner exit %s -- inspect %s)\n' "$?" "$tag" >&2
    done
  done
}

# Select arms.
selected=()
while read -r arm sel subj trials t3 desc; do
  [[ -z $want_arm || $want_arm == "$arm" ]] && selected+=("$arm|$sel|$subj|$trials|$t3")
done < <(arm_rows)
[[ ${#selected[@]} -gt 0 ]] || { printf 'no matching arm: %s (use --list)\n' "${want_arm:-}" >&2; exit 64; }

# Cost summary + agent detection.
total_cells=0 any_agent=0
for row in "${selected[@]}"; do
  IFS='|' read -r arm sel subj trials t3 <<<"$row"
  mapfile -t c < <(cases_of "$sel"); total_cells=$(( total_cells + ${#c[@]} * trials ))
  [[ $subj == agent ]] && any_agent=1
done
printf 'Plan: %d arm(s), %d cells, ~$%.2f (@ $%.2f/cell). Mode: %s.\n' \
  "${#selected[@]}" "$total_cells" "$(python3 -c "print($total_cells*$cost_per_cell)")" "$cost_per_cell" \
  "$( ((execute)) && echo EXECUTE-PAID || echo PLAN-ONLY )"
((any_agent)) && printf 'Agent arms present: real-agent collusion runs ONLY inside the sandbox (containment-gated); never on the host.\n'

preflight "$any_agent"

for row in "${selected[@]}"; do
  IFS='|' read -r arm sel subj trials t3 <<<"$row"
  run_arm "$arm" "$sel" "$subj" "$trials" "$t3"
done

if ((execute)); then
  printf '\nDone. Outputs under %s/<arm>/ ; read each run summary.json and its evidence chains before reporting.\n' "$output_root"
else
  printf '\nPLAN ONLY: no sandbox, no model call. Re-run with --execute and EXPERIMENT_APPROVED=1 after review.\n'
fi
