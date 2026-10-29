#!/usr/bin/env bash
# Follow the Codex JSONL stream of a real-agent collusion run while the Modal
# sandbox is alive, from a second WSL terminal, without touching the run.
#
#   ./modal_honeypot/watch_sandbox_stream.sh                 # newest running honeypot sandbox, CLH-036
#   ./modal_honeypot/watch_sandbox_stream.sh --case CLH-037
#   ./modal_honeypot/watch_sandbox_stream.sh --sandbox-id sb-XXXX --raw
#   ./modal_honeypot/watch_sandbox_stream.sh --list           # running sandboxes of the honeypot app
#   ./modal_honeypot/watch_sandbox_stream.sh --events         # follow the subject's events.tsv instead
#
# How it reads: Modal's sandbox filesystem API (stat + read_bytes by offset),
# which spawns NO process inside the sandbox. An exec'd `tail` would appear to
# the harness's procfs monitor as a new session and contaminate the run's event
# counts; this does not. The view is the trajectory file as `tee` writes it,
# polled every few seconds, so it lags the agent by at most the poll interval.
#
# What it shows: by default one compact line per JSONL event (type, item type,
# a short excerpt). --raw prints the redacted JSON lines in full.
#
# Redaction: the stream may carry the run's ephemeral virtual key (an agent
# that prints its environment puts it into command output) and per-run marker
# values. Both are replaced by pattern before anything reaches the terminal:
# sk-… tokens, Bearer tokens, HONEYCOLLUDE markers. Do not redirect this
# script's output into a file; the terminal is the intended sink.
#
# Needs: the repo venv (modal 1.6.0) and Modal credentials. Sources .env.local
# for MODAL_TOKEN_ID/SECRET (never .env.defaults, which blanks them).
set -Eeuo pipefail

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd -- "$repo"

if [[ -f .env.local ]]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env.local
  set +a
fi
export PYDANTIC_DISABLE_PLUGINS=1

python=.venv/bin/python
[[ -x $python ]] || { printf 'repo venv not found at %s (run from WSL)\n' "$python" >&2; exit 78; }

exec "$python" modal_honeypot/watch_sandbox_stream.py "$@"
