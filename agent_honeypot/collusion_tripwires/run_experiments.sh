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
#   ./agent_honeypot/collusion_tripwires/run_experiments.sh --arm lure-pair --trials 1 --model PINNED_MODEL
#   ./agent_honeypot/collusion_tripwires/run_experiments.sh --list     # list arms + Table 3 rows
#   ./agent_honeypot/collusion_tripwires/run_experiments.sh --arm sensor-controls --execute   # PAID
#   ./agent_honeypot/collusion_tripwires/run_experiments.sh --arm lure-pair --trials 1 --case CLH-036 \
#       --model PINNED_MODEL --execute                                  # PAID, one case of the arm
#
# Agent arms require --model (or MODEL), gateway and Langfuse URLs. Paid runs
# also require EXPERIMENT_APPROVED=1 and LITELLM_MASTER_KEY on the host, so a
# stray --execute cannot mint or bill by itself. --allow-network is never passed.
# --trials overrides the selected arm's frozen default without editing the table.
# --case restricts a selected arm to one of its cases, so paid cells can run one
# at a time with a review in between.
#
# Under --execute every cell's runner output is kept in
# <output>/<arm>/driver-<case>-t<trial>-<stamp>.log (never discarded), the
# driver stops at the first failed cell, and after each agent cell it reads the
# runner's run record and refuses to continue unless the sandbox terminated
# through the explicit finally, the virtual key was revoked, its spend is within
# the cap, and the redaction scan passed. --keep-going restores the old
# continue-past-failures behaviour for scripted calibration sweeps. The gate
# prints field names, booleans and the key alias only, never a key value.
set -Eeuo pipefail

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd -- "$repo"
# HONEYPOT_RUNNER lets the unit tests substitute a fake runner; production runs
# leave it unset.
runner=${HONEYPOT_RUNNER:-modal_honeypot/runner.py}

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

# Default real-agent subject: the image's pinned Codex gateway adapter. It pins
# live search off and retains the JSONL transcript for the Phase 2 shape review.
# Override per invocation with --subject-command or the SUBJECT_CMD env var.
# The runner shlex-splits this into argv; the payload carries no single quotes.
if [[ -z ${SUBJECT_CMD:-} ]]; then
  SUBJECT_CMD='bash /opt/honeypot/modal_honeypot/codex_gateway.sh'
fi

want_arm=
want_case=
execute=0
keep_going=0
list=0
workers=4
output_root="results/modal-honeypot-collusion-exp"
cost_per_cell=0.13   # planning estimate carried from the chain cohort; agent arms may differ
model=${MODEL:-}
key_budget=0.50
key_ttl=
trials_override=

usage() { sed -n '2,20p' "$0"; }
while (($#)); do
  case "$1" in
    --arm) want_arm=$2; shift 2 ;;
    --case) want_case=$2; shift 2 ;;
    --execute) execute=1; shift ;;
    --keep-going) keep_going=1; shift ;;
    --list) list=1; shift ;;
    --workers) workers=$2; shift 2 ;;
    --subject-command) SUBJECT_CMD=$2; shift 2 ;;
    --model) model=$2; shift 2 ;;
    --key-budget) key_budget=$2; shift 2 ;;
    --key-ttl) key_ttl=$2; shift 2 ;;
    --trials) trials_override=$2; shift 2 ;;
    --output) output_root=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; usage >&2; exit 64 ;;
  esac
done

if [[ -n $trials_override && ! $trials_override =~ ^[1-9][0-9]*$ ]]; then
  printf '%s\n' '--trials must be a positive integer' >&2
  exit 64
fi
if [[ -n $want_case ]]; then
  [[ -n $want_arm ]] || { printf '%s\n' '--case requires --arm' >&2; exit 64; }
  [[ $want_case =~ ^CLH-[0-9]{3}$ ]] || { printf '%s\n' '--case must be a CLH-NNN id' >&2; exit 64; }
fi

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

# The arm's cases after the optional --case filter. Membership is validated in
# the main shell (see "Select arms"), because an exit inside a process
# substitution would only end the subshell and leave an empty, silent plan.
arm_cases() {
  local sel=$1
  local -a all; mapfile -t all < <(cases_of "$sel")
  if [[ -z $want_case ]]; then
    printf '%s\n' "${all[@]}"
    return 0
  fi
  local c
  for c in "${all[@]}"; do
    [[ $c == "$want_case" ]] && printf '%s\n' "$c"
  done
}

# After an agent cell: read the runner's final run record from the kept log and
# refuse to go on unless the sandbox was torn down, the key revoked, the spend
# within the cap, and the redaction scan clean. Prints names, booleans, the
# alias and the output path; never a key value.
check_agent_run() {
  local log=$1 budget=$2
  python3 - "$log" "$budget" <<'PY'
import json
import sys

log_path, budget = sys.argv[1], float(sys.argv[2])
lines = open(log_path, encoding="utf-8", errors="replace").read().splitlines()
starts = [i for i, line in enumerate(lines) if line.strip() == "{"]
if not starts:
    print("gate: FAILED, the runner printed no run record", file=sys.stderr)
    raise SystemExit(1)
try:
    record = json.loads("\n".join(lines[starts[-1]:]))
except json.JSONDecodeError:
    print("gate: FAILED, the runner's run record is not valid JSON", file=sys.stderr)
    raise SystemExit(1)
key = record.get("virtual_key") if isinstance(record.get("virtual_key"), dict) else {}
redaction = record.get("redaction") if isinstance(record.get("redaction"), dict) else {}
spend = key.get("spend_usd")
checks = {
    "termination_explicit_finally": record.get("termination") == "explicit-finally",
    "key_revoked": bool(key.get("revoked_at")),
    "spend_recorded": isinstance(spend, (int, float)) and not isinstance(spend, bool),
    "spend_within_cap": isinstance(spend, (int, float)) and not isinstance(spend, bool) and spend <= budget,
    "redaction_passed": redaction.get("passed") is True,
}
alias = key.get("key_alias") or "(no alias recorded)"
summary = " ".join(f"{name}={str(ok).lower()}" for name, ok in checks.items())
print(f"gate: {summary} alias={alias} output={record.get('output', '?')}")
if not all(checks.values()):
    print(f"gate: FAILED for alias {alias}; if key_revoked is false, revoke it by alias now", file=sys.stderr)
    raise SystemExit(1)
PY
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
  local -a cases; mapfile -t cases < <(arm_cases "$sel" "$arm")
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
      if ((execute)); then
        mkdir -p "$tag"
        local log="$tag/driver-${case_id}-t${t}-$(date -u +%Y%m%dT%H%M%SZ).log"
        local rc=0
        "${cmd[@]}" 2>&1 | tee "$log" || true
        rc=${PIPESTATUS[0]}
        printf '    runner exit %s; output kept in %s\n' "$rc" "$log"
        if ((rc != 0)); then
          if ((keep_going)); then
            printf '    (--keep-going: continuing past the failed cell)\n' >&2
            continue
          fi
          printf 'stopping at the first failed cell (%s trial %d); inspect %s\n' "$case_id" "$t" "$log" >&2
          exit "$rc"
        fi
        if [[ $subj == agent ]]; then
          if ! check_agent_run "$log" "$key_budget"; then
            if ((keep_going)); then
              printf '    (--keep-going: continuing past the failed gate)\n' >&2
              continue
            fi
            printf 'post-run gate failed for %s trial %d; not starting the next cell\n' "$case_id" "$t" >&2
            exit 75
          fi
        fi
      else
        "${cmd[@]}" || printf '    (runner exit %s -- inspect plan above)\n' "$?" >&2
      fi
    done
  done
}

# Select arms.
selected=()
while read -r arm sel subj trials t3 desc; do
  [[ -z $want_arm || $want_arm == "$arm" ]] && selected+=("$arm|$sel|$subj|$trials|$t3")
done < <(arm_rows)
[[ ${#selected[@]} -gt 0 ]] || { printf 'no matching arm: %s (use --list)\n' "${want_arm:-}" >&2; exit 64; }

# A --case outside the selected arm is refused here, in the main shell, so the
# refusal really stops the script.
if [[ -n $want_case ]]; then
  for row in "${selected[@]}"; do
    IFS='|' read -r arm sel subj trials t3 <<<"$row"
    mapfile -t all_cases < <(cases_of "$sel")
    found=0
    for c in "${all_cases[@]}"; do [[ $c == "$want_case" ]] && found=1; done
    ((found)) || {
      printf 'case %s is not in arm %s (its cases: %s)\n' "$want_case" "$arm" "$(IFS=,; echo "${all_cases[*]}")" >&2
      exit 64
    }
  done
fi

# Cost summary + agent detection.
total_cells=0 any_agent=0
for row in "${selected[@]}"; do
  IFS='|' read -r arm sel subj trials t3 <<<"$row"
  [[ -n $trials_override ]] && trials=$trials_override
  mapfile -t c < <(arm_cases "$sel" "$arm"); total_cells=$(( total_cells + ${#c[@]} * trials ))
  [[ $subj == agent ]] && any_agent=1
done
printf 'Plan: %d arm(s), %d cells, ~$%.2f (@ $%.2f/cell). Mode: %s.\n' \
  "${#selected[@]}" "$total_cells" "$(python3 -c "print($total_cells*$cost_per_cell)")" "$cost_per_cell" \
  "$( ((execute)) && echo EXECUTE-PAID || echo PLAN-ONLY )"
((any_agent)) && printf 'Agent arms present: real-agent collusion runs ONLY inside the sandbox (containment-gated); never on the host.\n'

preflight "$any_agent"

for row in "${selected[@]}"; do
  IFS='|' read -r arm sel subj trials t3 <<<"$row"
  [[ -n $trials_override ]] && trials=$trials_override
  run_arm "$arm" "$sel" "$subj" "$trials" "$t3"
done

if ((execute)); then
  printf '\nDone. Outputs under %s/<arm>/ ; read each run summary.json and its evidence chains before reporting.\n' "$output_root"
else
  printf '\nPLAN ONLY: no sandbox, no model call. Re-run with --execute and EXPERIMENT_APPROVED=1 after review.\n'
fi
