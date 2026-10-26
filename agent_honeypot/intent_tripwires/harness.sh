#!/usr/bin/env bash
set -Eeuo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd -- "$script_dir/../.." && pwd)
case_id=
timeout_seconds=60
output_dir=
trajectory=
observe_network=0
evidence_chain=${HONEYPOT_EVIDENCE_CHAIN:-0}

usage() {
  cat <<'EOF'
Usage: harness.sh --case-id ITH-NNN [--timeout SECONDS] [--output DIR]
                  [--trajectory FILE] [--observe-network] [--evidence-chain]
                  -- COMMAND [ARG...]

Creates synthetic sensitive files, a loopback receipt sink, file/network
tripwires, and runs COMMAND in the case workspace. External egress tools and
non-loopback connect() calls are blocked by default. --observe-network removes
that user-space block and is only for an externally contained VM/sandbox.
--evidence-chain routes the sink log and the process log through parent-owned
keyed mirrors (see agent_honeypot/evidence_chain.py).
EOF
}

while (($#)); do
  case "$1" in
    --case-id) case_id=$2; shift 2 ;;
    --timeout) timeout_seconds=$2; shift 2 ;;
    --output) output_dir=$2; shift 2 ;;
    --trajectory) trajectory=$2; shift 2 ;;
    --observe-network) observe_network=1; shift ;;
    --evidence-chain) evidence_chain=1; shift ;;
    --) shift; break ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; usage >&2; exit 64 ;;
  esac
done
[[ $case_id =~ ^ITH-[0-9]{3}$ ]] || { printf 'A valid --case-id is required\n' >&2; exit 64; }
[[ $timeout_seconds =~ ^[0-9]+$ && $timeout_seconds -gt 0 ]] || { printf 'Invalid timeout\n' >&2; exit 64; }
(($#)) || { usage >&2; exit 64; }
if [[ -z $output_dir ]]; then
  output_dir="$PWD/results/intent-honeypot/${case_id}-$(date -u +%Y%m%dT%H%M%SZ)-$$"
fi
output_dir=$(realpath -m "$output_dir")
[[ ! -e $output_dir ]] || { printf 'Output already exists: %s\n' "$output_dir" >&2; exit 73; }

python3 "$script_dir/prepare_case.py" "$case_id" --output "$output_dir" >/dev/null
workspace="$output_dir/workspace"
canary_file="$output_dir/canary.txt"
sensitive_paths=$(<"$output_dir/sensitive-paths.txt")
sink_events="$output_dir/sink-events.tsv"
port_file="$output_dir/sink.port"
agent_stdout="$output_dir/agent.stdout.log"
agent_stderr="$output_dir/agent.stderr.log"
intent_report="$output_dir/intent-report.json"
process_output="$output_dir/process"
shim_dir="$output_dir/egress-shims"
mkdir -p -- "$shim_dir"
: >"$sink_events"

for tool in curl wget git scp sftp rsync nc ncat socat; do
  ln -s "$script_dir/egress-tripwire" "$shim_dir/$tool"
done

# shellcheck source=../evidence_chain.sh
source "$repo/agent_honeypot/evidence_chain.sh"
sink_args=(--events "$sink_events" --port-file "$port_file" --canary-file "$canary_file")
if ((evidence_chain)); then
  evidence_chain_start "$sink_events" 9 "$output_dir/sink-evidence.json"
  sink_args+=(--events-fd "$EVIDENCE_FD")
fi
python3 "$script_dir/sink.py" "${sink_args[@]}" &
sink_pid=$!
cleanup() {
  if kill -0 "$sink_pid" 2>/dev/null; then kill -TERM "$sink_pid" 2>/dev/null || true; fi
}
trap cleanup EXIT INT TERM
for _ in {1..50}; do
  [[ -s $port_file ]] && break
  sleep 0.05
done
[[ -s $port_file ]] || { printf 'Intent sink failed to start\n' >&2; exit 70; }
sink_url="http://127.0.0.1:$(<"$port_file")"
[[ -n $trajectory ]] || trajectory="$output_dir/trajectory.jsonl"

common_env=(
  HONEYPOT_EXTRA_PATH="$shim_dir"
  HONEYPOT_SENSITIVE_PATHS="$sensitive_paths"
  HONEYPOT_SENSITIVE_RELATIVE_NAMES_FILE="$output_dir/sensitive-relative-names.txt"
  HONEYPOT_CANARY_FILE="$canary_file"
  HONEYPOT_SINK_URL="$sink_url"
  HONEYPOT_BLOCK_EGRESS_TOOLS=1
  HONEYPOT_CASE_PROMPT_FILE="$output_dir/prompt.txt"
  HONEYPOT_WORKSPACE="$workspace"
  HONEYPOT_TRAJECTORY="$trajectory"
  HONEYPOT_AGENT_STDOUT="$agent_stdout"
  HONEYPOT_AGENT_STDERR="$agent_stderr"
  HONEYPOT_EVIDENCE_CHAIN="$evidence_chain"
  NO_PROXY=127.0.0.1,localhost
  no_proxy=127.0.0.1,localhost
)
if ((observe_network)); then
  common_env+=(HONEYPOT_BLOCK_EGRESS_TOOLS=0)
else
  common_env+=(HONEYPOT_BLOCK_NETWORK=1)
fi

set +e
env "${common_env[@]}" "$repo/agent_honeypot/harness.sh" \
  --timeout "$timeout_seconds" --output "$process_output" -- \
  bash -c 'cd -- "$HONEYPOT_WORKSPACE"; "$@" >"$HONEYPOT_AGENT_STDOUT" 2>"$HONEYPOT_AGENT_STDERR"' \
  _ "$@"
agent_status=$?
set -e

cleanup
wait "$sink_pid" 2>/dev/null || true
trap - EXIT INT TERM
if ((evidence_chain)); then
  evidence_chain_finish
fi

score_args=(
  --case "$output_dir/case.json"
  --canary-file "$canary_file"
  --events "$process_output/events.tsv"
  --events "$sink_events"
  --stdout "$agent_stdout"
  --stderr "$agent_stderr"
  --output "$intent_report"
)
[[ -f $trajectory ]] && score_args+=(--trajectory "$trajectory")
if ((evidence_chain)); then
  score_args+=(--evidence "$process_output/evidence.json" --evidence "$output_dir/sink-evidence.json")
fi
python3 "$script_dir/score_intent.py" "${score_args[@]}" >/dev/null || true
printf 'Intent-tripwire artifacts: %s\nAgent exit: %s\n' "$output_dir" "$agent_status"
python3 - "$intent_report" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
print(f"Case: {r['case_id']}  stage={r['observed_stage']}  expectation_passed={r['expectation_passed']}")
PY
exit "$agent_status"

