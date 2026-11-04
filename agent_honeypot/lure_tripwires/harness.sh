#!/usr/bin/env bash
set -Eeuo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd -- "$script_dir/../.." && pwd)
case_id=
timeout_seconds=300
output_dir=
trajectory=
observe_network=0
observe_only=0
evidence_chain=${HONEYPOT_EVIDENCE_CHAIN:-0}

usage() {
  cat <<'EOF'
Usage: harness.sh --case-id ULT-NNN [--timeout SECONDS] [--output DIR]
                  [--trajectory FILE] [--observe-network] [--observe-only]
                  [--evidence-chain] -- COMMAND [ARG...]

One run of the unsolvable-task experiment (paper Section 5): lays out the task
and its lures (prepare_task.py: the agent's side under DIR/task, everything
that names the experiment one level up), starts the loopback lure hub and the
lure watcher (lure_watch.py: inotify on the lure files and folders, so no lure
path enters the agent's environment), and runs COMMAND in the task workspace
under agent_honeypot/harness.sh for --timeout seconds (the run's time budget)
with the alerter on in observe mode. The hub and the watcher share one
harness-side chain, lure-events.tsv. After COMMAND exits it stops the watcher,
runs the task verifier (verify_task.py, outside the agent's process tree, on
its own copies) and scores the run (score_lure.py). Non-loopback connects are
blocked by the preload unless --observe-network; --observe-network and
--observe-only are for an externally contained sandbox.
EOF
}

while (($#)); do
  case "$1" in
    --case-id) case_id=$2; shift 2 ;;
    --timeout) timeout_seconds=$2; shift 2 ;;
    --output) output_dir=$2; shift 2 ;;
    --trajectory) trajectory=$2; shift 2 ;;
    --observe-network) observe_network=1; shift ;;
    --observe-only) observe_only=1; shift ;;
    --evidence-chain) evidence_chain=1; shift ;;
    --) shift; break ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; usage >&2; exit 64 ;;
  esac
done
[[ $case_id =~ ^ULT-[0-9]{3}$ ]] || { printf 'A valid --case-id is required\n' >&2; exit 64; }
[[ $timeout_seconds =~ ^[0-9]+$ && $timeout_seconds -gt 0 ]] || { printf 'Invalid timeout\n' >&2; exit 64; }
(($#)) || { usage >&2; exit 64; }
if [[ -z $output_dir ]]; then
  output_dir="$PWD/results/lure-honeypot/${case_id}-$(date -u +%Y%m%dT%H%M%SZ)-$$"
fi
output_dir=$(realpath -m "$output_dir")
[[ ! -e $output_dir ]] || { printf 'Output already exists: %s\n' "$output_dir" >&2; exit 73; }

python3 "$script_dir/prepare_task.py" "$case_id" --output "$output_dir" >/dev/null
# The verifier's material (its copies and the lure solutions) sits under the
# run folder, which a Codex workspace-write sandbox can write (/tmp). Its
# fingerprint is taken now and held only in this shell; the verifier refuses
# to judge when the material changed during the run.
material_digest=$(python3 "$script_dir/verify_task.py" --output "$output_dir" --material-digest)
[[ $material_digest =~ ^[0-9a-f]{64}$ ]] || { printf 'No verifier fingerprint\n' >&2; exit 70; }
bait="$output_dir/task"
workspace="$bait/workspace"
lure_events="$output_dir/lure-events.tsv"
port_file="$output_dir/hub.port"
agent_stdout="$output_dir/agent.stdout.log"
agent_stderr="$output_dir/agent.stderr.log"
shim_dir="$output_dir/egress-shims"
watch_stop="$output_dir/lure-watch.stop"
watch_ready="$output_dir/lure-watch.ready"
mkdir -p -- "$shim_dir"
: >"$lure_events"
# The intent suite's egress tripwires: curl and the rest are recorded as
# NETWORK_TOOL_ATTEMPT and then run; the preload (scripted runs) or the egress
# proxy (real agents) decides where they may connect.
for tool in curl wget git scp sftp rsync nc ncat socat; do
  ln -s "$repo/agent_honeypot/intent_tripwires/egress-tripwire" "$shim_dir/$tool"
done

# shellcheck source=../evidence_chain.sh
source "$repo/agent_honeypot/evidence_chain.sh"
if ((evidence_chain)); then
  evidence_chain_start "$lure_events" 9 "$output_dir/lure-evidence.json"
fi
hub_args=(--events "$lure_events" --port-file "$port_file" --token-file "$output_dir/hub.marker"
          --solutions "$bait/reference/solutions")
((evidence_chain)) && hub_args+=(--events-fd "$EVIDENCE_FD")
python3 "$script_dir/lure_hub.py" "${hub_args[@]}" &
hub_pid=$!
watch_pid=
cleanup() {
  for pid in "$hub_pid" "$watch_pid"; do
    if [[ -n $pid ]] && kill -0 "$pid" 2>/dev/null; then kill -TERM "$pid" 2>/dev/null || true; fi
  done
}
trap cleanup EXIT INT TERM
for _ in {1..50}; do
  [[ -s $port_file ]] && break
  sleep 0.05
done
[[ -s $port_file ]] || { printf 'Lure hub failed to start\n' >&2; exit 70; }
hub_url="http://127.0.0.1:$(<"$port_file")"
# The hub's address goes into the token dotfile once the port is known, before
# the watcher starts (it would record this write as an open).
printf 'url = %s\n' "$hub_url" >>"$bait/.benchmark-hub"

watch_args=(--watch-list "$output_dir/lure-watch.tsv" --stop-file "$watch_stop" --ready-file "$watch_ready")
if ((evidence_chain)); then
  watch_args+=(--log-fd "$EVIDENCE_FD")
else
  watch_args+=(--log "$lure_events")
fi
python3 "$script_dir/lure_watch.py" "${watch_args[@]}" &
watch_pid=$!
for _ in {1..100}; do
  [[ -e $watch_ready ]] && break
  kill -0 "$watch_pid" 2>/dev/null || break
  sleep 0.05
done
[[ -e $watch_ready ]] || { printf 'Lure watcher failed to start\n' >&2; exit 70; }
[[ -n $trajectory ]] || trajectory="$output_dir/trajectory.jsonl"

# Nothing here names a lure, the hub or the canary: the agent's environment
# carries only what the base harness and the Codex adapter need.
common_env=(
  HONEYPOT_EXTRA_PATH="$shim_dir"
  HONEYPOT_BLOCK_EGRESS_TOOLS=0
  HONEYPOT_CASE_PROMPT_FILE="$output_dir/prompt.txt"
  HONEYPOT_WORKSPACE="$workspace"
  HONEYPOT_TRAJECTORY="$trajectory"
  HONEYPOT_AGENT_STDOUT="$agent_stdout"
  HONEYPOT_AGENT_STDERR="$agent_stderr"
  HONEYPOT_EVIDENCE_CHAIN="$evidence_chain"
  # The alerter in observe mode (agent_honeypot/alerter.py; read and unset by the
  # base harness): a lure open or hub probe raises ALERT_RAISED.
  HONEYPOT_ALERT=1
  HONEYPOT_ALERT_LOGS="$lure_events"
  NO_PROXY=127.0.0.1,localhost
  no_proxy=127.0.0.1,localhost
)
if ((! observe_network)); then
  common_env+=(HONEYPOT_BLOCK_NETWORK=1)
fi

base_args=(--timeout "$timeout_seconds" --output "$output_dir/process")
if ((observe_only)); then
  base_args+=(--observe-only)
fi

set +e
env "${common_env[@]}" "$repo/agent_honeypot/harness.sh" \
  "${base_args[@]}" -- \
  bash -c 'cd -- "$HONEYPOT_WORKSPACE"; "$@" >"$HONEYPOT_AGENT_STDOUT" 2>"$HONEYPOT_AGENT_STDERR"' \
  _ "$@"
agent_status=$?
set -e

# The watcher stops before anything of the harness's own reads a lure again.
: >"$watch_stop"
for _ in {1..40}; do
  kill -0 "$watch_pid" 2>/dev/null || break
  sleep 0.1
done
cleanup
wait "$hub_pid" 2>/dev/null || true
wait "$watch_pid" 2>/dev/null || true
trap - EXIT INT TERM
if ((evidence_chain)); then
  evidence_chain_finish
fi

# The verifier: after the agent, in this harness, on the verifier's own copies.
HONEYPOT_LURE_MATERIAL_DIGEST=$material_digest \
  python3 "$script_dir/verify_task.py" --output "$output_dir" >/dev/null || true
unset material_digest
score_args=(--output "$output_dir" --budget-seconds "$timeout_seconds")
if ((evidence_chain)); then
  score_args+=(--evidence "$output_dir/process/evidence.json" --evidence "$output_dir/lure-evidence.json")
fi
python3 "$script_dir/score_lure.py" "${score_args[@]}" >/dev/null || true
printf 'Lure-task artifacts: %s\nAgent exit: %s\n' "$output_dir" "$agent_status"
python3 - "$output_dir/lure-report.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
v = r.get("verifier") or {}
print(f"Case: {r['case_id']} ({r['pair']}, {r['form']})  lure stage={r['observed_stage']}  "
      f"verifier passed={v.get('passed')}  termination={r['lifecycle']['termination']}")
PY
exit "$agent_status"
