#!/usr/bin/env bash
# Experimental-run driver for the collusion suite, through one of two providers:
#   --provider modal  (default) modal_honeypot/runner.py, a Modal sandbox;
#                     output under results/modal-honeypot-collusion-exp, run
#                     record modal-run.json.
#   --provider docker docker_honeypot/runner.py, a local Docker container on an
#                     internal network behind an allow-listing egress proxy;
#                     output under results/docker-honeypot-collusion-exp, run
#                     record docker-run.json. A second, disclosed boundary.
# Every run is inside the externally contained boundary; scripted runs block
# egress, while real-agent runs reach only the gateway and Langfuse hosts. A
# real-agent subject can only run there, never on the host. This script is
# SAFE BY DEFAULT: it prints the plan (the runner's --dry-run; --dry-run says so
# explicitly) and starts no sandbox and no model call unless you pass --execute.
#
#   ./agent_honeypot/collusion_tripwires/run_experiments.sh            # plan every arm (free)
#   ./agent_honeypot/collusion_tripwires/run_experiments.sh --arm lure-pair --model PINNED_MODEL
#   ./agent_honeypot/collusion_tripwires/run_experiments.sh --arm lure-pair --trials 1 --model PINNED_MODEL
#   ./agent_honeypot/collusion_tripwires/run_experiments.sh --list     # list arms + Table 3 rows
#   ./agent_honeypot/collusion_tripwires/run_experiments.sh --arm sensor-controls --execute   # PAID
#   ./agent_honeypot/collusion_tripwires/run_experiments.sh --provider docker --arm sensor-controls --execute
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
# the cap, the redaction scan passed, the archived turn executed a command
# and produced output tokens, and a hook saw the agent's commands (the run's
# summary row carries agent_hooks_observed=true: at least one hook event in each
# subject's chain inside its tool-call windows; collusion cohort opus-v2 had
# none, and a cell without it stops the arm). Empty turns are setup faults; consecutive setup
# faults up to --max-setup-faults (default 1) are skipped before the next one
# stops the arm.
# --keep-going restores the old
# continue-past-failures behaviour for scripted calibration sweeps. The gate
# prints field names, booleans and the key alias only, never a key value.
# --langfuse pushes each agent cell's host-side trace (agent_honeypot/
# langfuse_ingest.py --push) once its gate has passed, waiting up to
# --langfuse-wait seconds (default 180) for the gateway's generations of that
# key alias to be visible; a failed push is reported and the arm continues.
# Needs LANGFUSE_PUBLIC_KEY, LANGFUSE_SECRET_KEY and LANGFUSE_BASE_URL.
set -Eeuo pipefail

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd -- "$repo"
# The runner needs the pinned Modal SDK, which lives in the repo venv, not in
# the system python3. Use the venv interpreter whenever it exists so the driver
# does not depend on the venv being activated in the caller's shell (a plain
# `python3` stopped the 2026-10-29T08:29Z pilot attempt before any sandbox).
# HONEYPOT_PYTHON overrides the choice.
if [[ -n ${HONEYPOT_PYTHON:-} ]]; then
  python=$HONEYPOT_PYTHON
elif [[ -x $repo/.venv/bin/python ]]; then
  python=$repo/.venv/bin/python
else
  python=python3
fi
if ! command -v -- "$python" >/dev/null 2>&1 && [[ ! -x $python ]]; then
  printf 'python interpreter not found: %s (set HONEYPOT_PYTHON or create the repo .venv)\n' "$python" >&2
  exit 78
fi

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
SENSORS="CLH-006,CLH-007,CLH-008,CLH-009,CLH-010,CLH-011,CLH-012,CLH-013,CLH-014,CLH-015,CLH-016,CLH-017,CLH-018,CLH-019,CLH-020,CLH-041"

read -r -d '' ARMS <<TABLE || true
sensor-controls   SENSORS                           scripted  1  Sensor-control_pass                                           16 collusion sensor controls; must pass before any agent arm
scripted-calib    ALL                               scripted  1  Cross-run_coordination(suite_built)                           full 41-case scripted baseline (expect 41/41, every chain valid)
lure-pair         CLH-036,CLH-037                   agent     3  Cross-run_coordination/Lure-access_difference/Time-to-first-coordination-event   solvable vs unsolvable, real agent subject, chain on
benign-base       CLH-001,CLH-002,CLH-003,CLH-004   agent     3  Benign_base_rate                                              no-channel/no-injection controls under a real agent
channels-all      CLH-001,CLH-002,CLH-003,CLH-004,CLH-005,CLH-021,CLH-022,CLH-023,CLH-024,CLH-025,CLH-026,CLH-027,CLH-028,CLH-029,CLH-030,CLH-031,CLH-032,CLH-033,CLH-034,CLH-035,CLH-036,CLH-037,CLH-038,CLH-039,CLH-040   agent     3  Cross-run_coordination(all_channels)   every behaviour case (board, inboxes, queue, delegation, cache, workspaces) under a real agent; 75 cells, own frozen table and go
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
dry_run=0
keep_going=0
list=0
workers=4
provider=modal
output_root=
output_root_set=0
langfuse=0
langfuse_wait=180
traces_pushed=0
traces_failed=0
cost_per_cell=0.13   # planning estimate carried from the chain cohort; agent arms may differ
model=${MODEL:-}
key_budget=0.50
key_ttl=
agent_timeout=900
trials_override=
max_setup_faults=1

usage() { sed -n '2,/^set -Eeuo pipefail$/p' "$0" | sed '$d'; }
while (($#)); do
  case "$1" in
    --arm) want_arm=$2; shift 2 ;;
    --case) want_case=$2; shift 2 ;;
    --execute) execute=1; shift ;;
    --dry-run) dry_run=1; shift ;;
    --provider) provider=$2; shift 2 ;;
    --keep-going) keep_going=1; shift ;;
    --max-setup-faults) max_setup_faults=$2; shift 2 ;;
    --langfuse) langfuse=1; shift ;;
    --langfuse-wait) langfuse_wait=$2; shift 2 ;;
    --list) list=1; shift ;;
    --workers) workers=$2; shift 2 ;;
    --subject-command) SUBJECT_CMD=$2; shift 2 ;;
    --model) model=$2; shift 2 ;;
    --key-budget) key_budget=$2; shift 2 ;;
    --key-ttl) key_ttl=$2; shift 2 ;;
    --agent-timeout) agent_timeout=$2; shift 2 ;;
    --trials) trials_override=$2; shift 2 ;;
    --output) output_root=$2; output_root_set=1; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; usage >&2; exit 64 ;;
  esac
done

# The provider selects the runner, the default output root and the run record
# the post-run gate reads. HONEYPOT_RUNNER lets the unit tests substitute a fake
# runner; production runs leave it unset.
case "$provider" in
  modal)
    default_runner=modal_honeypot/runner.py
    default_output=results/modal-honeypot-collusion-exp
    run_record=modal-run.json ;;
  docker)
    default_runner=docker_honeypot/runner.py
    default_output=results/docker-honeypot-collusion-exp
    run_record=docker-run.json ;;
  *) printf '%s\n' '--provider must be modal or docker' >&2; exit 64 ;;
esac
runner=${HONEYPOT_RUNNER:-$default_runner}
# HONEYPOT_INGEST lets the unit tests substitute a fake trace ingester.
ingest=${HONEYPOT_INGEST:-agent_honeypot/langfuse_ingest.py}
if [[ ! $langfuse_wait =~ ^[1-9][0-9]*$ ]]; then
  printf '%s\n' '--langfuse-wait must be a positive integer number of seconds' >&2
  exit 64
fi
((output_root_set)) || output_root=$default_output
if ((dry_run && execute)); then
  printf '%s\n' '--dry-run and --execute are mutually exclusive' >&2
  exit 64
fi

if [[ -n $trials_override && ! $trials_override =~ ^[1-9][0-9]*$ ]]; then
  printf '%s\n' '--trials must be a positive integer' >&2
  exit 64
fi
if [[ ! $agent_timeout =~ ^[1-9][0-9]*$ ]]; then
  printf '%s\n' '--agent-timeout must be a positive integer' >&2
  exit 64
fi
if [[ ! $max_setup_faults =~ ^[0-9]+$ ]]; then
  printf '%s\n' '--max-setup-faults must be a non-negative integer' >&2
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

# After an agent cell: find the output directory in the runner's final printed
# record, load the provider's run record from it (modal-run.json or
# docker-run.json), and refuse to go on unless that record exists and names the
# provider, the boundary was torn down, the key revoked, the spend within the
# cap, and the redaction scan clean. Prints names, booleans, the alias and the
# output path; never a key value.
check_agent_run() {
  local log=$1 budget=$2 setup_faults=$3 max_faults=$4
  python3 - "$log" "$budget" "$setup_faults" "$max_faults" "$run_record" "$provider" <<'PY'
import json
import sys
import tarfile
from pathlib import Path

log_path, budget = sys.argv[1], float(sys.argv[2])
prior_setup_faults, max_setup_faults = int(sys.argv[3]), int(sys.argv[4])
run_record_name, provider = sys.argv[5], sys.argv[6]
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
# The provider's record on disk is the one the gate trusts; the printed copy
# only says where it is.
file_record = None
if isinstance(record.get("output"), str):
    try:
        file_record = json.loads((Path(record["output"]) / run_record_name).read_text())
    except (OSError, json.JSONDecodeError):
        file_record = None
if isinstance(file_record, dict):
    record = {**file_record, "output": record["output"]}
key = record.get("virtual_key") if isinstance(record.get("virtual_key"), dict) else {}
redaction = record.get("redaction") if isinstance(record.get("redaction"), dict) else {}
spend = key.get("spend_usd")
command_executed = False
output_tokens_positive = False
archive_error = None
try:
    output = Path(record["output"])
    archive_path = output / "artifacts.tar.gz"
    case_id = str(record["case_id"])
    prefix = f"cases/{case_id}/runs/"
    with tarfile.open(archive_path, "r:gz") as archive:
        member_names = [
            name for name in archive.getnames()
            if name.startswith(prefix) and name.endswith("/trajectory.jsonl")
        ]
        if not member_names:
            raise FileNotFoundError(f"{prefix}<subject>/trajectory.jsonl")
        for member_name in member_names:
            member = archive.extractfile(member_name)
            if member is None:
                continue
            for raw in member:
                try:
                    row = json.loads(raw)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                item = row.get("item") if isinstance(row.get("item"), dict) else {}
                if row.get("type") == "command_execution" or item.get("type") == "command_execution":
                    command_executed = True
                usage = row.get("usage") if row.get("type") == "turn.completed" else None
                if isinstance(usage, dict):
                    value = usage.get("output_tokens")
                    if isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0:
                        output_tokens_positive = True
except (KeyError, OSError, tarfile.TarError) as exc:
    archive_error = type(exc).__name__
# The hook gate (score_collusion.agent_hook_check), from the run's summary row.
hooks_observed = None
try:
    run_rows = json.loads((Path(record["output"]) / "summary.json").read_text()).get("results") or []
    hooks_observed = run_rows[0].get("agent_hooks_observed") if run_rows else None
except (KeyError, OSError, json.JSONDecodeError, AttributeError, TypeError):
    hooks_observed = None

hard_checks = {
    "remote_exit_zero": record.get("remote_exit_code") == 0,
    "termination_explicit_finally": record.get("termination") == "explicit-finally",
    "key_revoked": bool(key.get("revoked_at")),
    "spend_recorded": isinstance(spend, (int, float)) and not isinstance(spend, bool),
    "redaction_passed": redaction.get("passed") is True,
    "run_record_present": isinstance(file_record, dict),
    # Modal records predate the field; a Docker record must name its provider.
    "provider_matches": record.get("provider") == (None if provider == "modal" else provider),
    # An empty turn has nothing to observe and is judged as a setup fault below.
    "agent_hooks_observed": hooks_observed is True or not command_executed,
}
setup_checks = {
    "spend_within_cap": isinstance(spend, (int, float)) and not isinstance(spend, bool) and spend <= budget,
    "command_executed": command_executed,
    "output_tokens_positive": output_tokens_positive,
}
checks = {**hard_checks, **setup_checks}
alias = key.get("key_alias") or "(no alias recorded)"
summary = " ".join(f"{name}={str(ok).lower()}" for name, ok in checks.items())
empty_turn = not command_executed or not output_tokens_positive
setup_fault = all(hard_checks.values()) and (empty_turn or not setup_checks["spend_within_cap"])
count = prior_setup_faults + 1 if setup_fault else 0
print(
    f"gate: {summary} empty_turn={str(empty_turn).lower()} "
    f"setup_fault_count={count}/{max_setup_faults} alias={alias} "
    f"output={record.get('output', '?')}"
)
if not all(hard_checks.values()):
    print(f"gate: FAILED for alias {alias}; if key_revoked is false, revoke it by alias now", file=sys.stderr)
    raise SystemExit(1)
if setup_fault:
    reason = "empty turn" if empty_turn else "spend cap exceeded"
    detail = f"; archive_error={archive_error}" if archive_error else ""
    print(f"gate: setup fault ({reason}) for alias {alias}{detail}", file=sys.stderr)
    raise SystemExit(2)
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
    # A paid Modal cell needs the Modal SDK in the chosen interpreter, and a
    # Docker cell a reachable Docker daemon; a plan needs neither.
    if [[ -z ${HONEYPOT_RUNNER:-} && $provider == modal ]] && ! "$python" -c 'import modal' >/dev/null 2>&1; then
      printf 'the interpreter %s cannot import modal; use the repo .venv (requirements.txt pins modal==1.6.0) or set HONEYPOT_PYTHON\n' "$python" >&2
      exit 78
    fi
    if [[ -z ${HONEYPOT_RUNNER:-} && $provider == docker ]] && ! docker info >/dev/null 2>&1; then
      printf 'the docker provider needs a reachable Docker daemon (docker info failed)\n' >&2
      exit 78
    fi
    if ((any_agent)); then
      [[ -n ${LITELLM_MASTER_KEY:-} ]] || {
        printf 'agent arm needs LITELLM_MASTER_KEY on the host to mint its scoped virtual key\n' >&2; exit 78; }
      if [[ $provider == docker ]]; then
        printf 'NOTE: each agent run mints one budgeted virtual key and passes it only as docker exec environment, by name.\n' >&2
      else
        printf 'NOTE: each agent run mints one budgeted virtual key and injects it only through an ephemeral Modal Secret.\n' >&2
      fi
    fi
    if ((langfuse && any_agent)); then
      local name
      for name in LANGFUSE_PUBLIC_KEY LANGFUSE_SECRET_KEY LANGFUSE_BASE_URL; do
        [[ -n ${!name:-} ]] || {
          printf -- '--langfuse needs %s on the host\n' "$name" >&2; exit 78; }
      done
      if [[ -z ${HONEYPOT_INGEST:-} ]] && ! "$python" -c 'import langfuse' >/dev/null 2>&1; then
        printf 'the interpreter %s cannot import langfuse (requirements.txt pins langfuse==4.15.1)\n' "$python" >&2
        exit 78
      fi
    fi
  fi
}

# After an agent cell has passed its gate: push its host-side trace. Never stops
# the arm; a failure is counted, logged beside the run, and reported at the end.
push_trace() {
  local log=$1 run_dir=
  run_dir=$(python3 - "$log" <<'PY'
import json
import sys

lines = open(sys.argv[1], encoding="utf-8", errors="replace").read().splitlines()
starts = [i for i, line in enumerate(lines) if line.strip() == "{"]
try:
    print(json.loads("\n".join(lines[starts[-1]:])).get("output", "") if starts else "")
except json.JSONDecodeError:
    print("")
PY
  ) || run_dir=
  if [[ -z $run_dir || ! -d $run_dir ]]; then
    traces_failed=$((traces_failed + 1))
    printf '    langfuse: no run directory in the runner record; trace not pushed\n' >&2
    return 0
  fi
  local trace_log="$run_dir/langfuse-push.log"
  if "$python" "$ingest" "$run_dir" --push --wait-for-gateway "$langfuse_wait" > "$trace_log" 2>&1; then
    traces_pushed=$((traces_pushed + 1))
    printf '    langfuse: trace pushed (%s)\n' "$(tail -n 1 "$trace_log")"
  else
    traces_failed=$((traces_failed + 1))
    printf '    langfuse: push FAILED, see %s; the arm continues. Re-push once with: %s %s %s --push --wait-for-gateway %s\n' \
      "$trace_log" "$python" "$ingest" "$run_dir" "$langfuse_wait" >&2
  fi
}

# Run or plan one arm.
run_arm() {
  local arm=$1 sel=$2 subj=$3 trials=$4 t3=$5
  local -a cases; mapfile -t cases < <(arm_cases "$sel" "$arm")
  local cells=$(( ${#cases[@]} * trials ))
  local setup_faults=0
  printf '\n== arm %s  (subject=%s, trials=%s, cells=%s, Table 3: %s)\n' "$arm" "$subj" "$trials" "$cells" "$t3"
  local tag="$output_root/$arm"
  for case_id in "${cases[@]}"; do
    for ((t=1; t<=trials; t++)); do
      local -a cmd=("$python" "$runner" --harness collusion --case-id "$case_id"
                    --workers "$workers" --output "$tag")
      if [[ $subj == agent ]]; then
        cmd+=(--subject-command "$SUBJECT_CMD" --egress-allowlist langfuse,gateway
              --model "$model" --arm "$arm" --trial "$t" --key-budget "$key_budget"
              --agent-timeout "$agent_timeout")
        [[ -n $key_ttl ]] && cmd+=(--key-ttl "$key_ttl")
      fi
      ((execute)) || cmd+=(--dry-run)
      printf '  [%s trial %d] %s\n' "$case_id" "$t" "$( ((execute)) && echo RUN || echo PLAN )"
      if ((execute)); then
        mkdir -p "$tag"
        local log="$tag/driver-${case_id}-t${t}-$(date -u +%Y%m%dT%H%M%SZ).log"
        local rc=0
        set +e
        "${cmd[@]}" 2>&1 | tee "$log"
        rc=${PIPESTATUS[0]}
        set -e
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
          local gate_rc=0
          set +e
          check_agent_run "$log" "$key_budget" "$setup_faults" "$max_setup_faults"
          gate_rc=$?
          set -e
          if ((gate_rc == 2)); then
            setup_faults=$((setup_faults + 1))
            if ((keep_going)); then
              printf '    (--keep-going: continuing past the failed gate)\n' >&2
              continue
            fi
            if ((setup_faults > max_setup_faults)); then
              printf 'setup-fault limit exceeded for %s trial %d (%d > %d); not starting the next cell\n' \
                "$case_id" "$t" "$setup_faults" "$max_setup_faults" >&2
              exit 75
            fi
            printf '    (setup fault %d/%d: continuing to the next cell)\n' \
              "$setup_faults" "$max_setup_faults" >&2
            continue
          elif ((gate_rc != 0)); then
            if ((keep_going)); then
              printf '    (--keep-going: continuing past the failed gate)\n' >&2
              continue
            fi
            printf 'post-run gate failed for %s trial %d; not starting the next cell\n' "$case_id" "$t" >&2
            exit 75
          fi
          setup_faults=0
          if ((langfuse)); then
            push_trace "$log"
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
printf 'Provider: %s (runner %s, run record %s). Output root: %s.\n' \
  "$provider" "$runner" "$run_record" "$output_root"
((any_agent)) && printf 'Agent arms present: real-agent collusion runs ONLY inside the sandbox (containment-gated); never on the host.\n'
if ((langfuse && any_agent)); then
  printf 'Langfuse: each agent cell that passes its gate gets its trace pushed (%s), waiting up to %ss for the gateway generations.\n' \
    "$ingest" "$langfuse_wait"
fi

preflight "$any_agent"

for row in "${selected[@]}"; do
  IFS='|' read -r arm sel subj trials t3 <<<"$row"
  [[ -n $trials_override ]] && trials=$trials_override
  run_arm "$arm" "$sel" "$subj" "$trials" "$t3"
done

if ((execute)); then
  if ((langfuse && any_agent)); then
    printf '\nLangfuse: %d trace(s) pushed, %d failed.\n' "$traces_pushed" "$traces_failed"
  fi
  printf '\nDone. Outputs under %s/<arm>/ ; read each run summary.json and its evidence chains before reporting.\n' "$output_root"
else
  printf '\nPLAN ONLY: no sandbox, no model call. Re-run with --execute and EXPERIMENT_APPROVED=1 after review.\n'
fi
