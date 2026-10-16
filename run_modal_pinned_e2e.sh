#!/usr/bin/env bash
# Plan or execute the frozen CyberGym E2E paper cohort. The Python runner owns
# the smoke-first gate, manifest-hash pin, append-only attempts, exclusion
# ledger, and published-results separation. With no arguments this is read-only.
set -euo pipefail

cd "$(dirname "$0")"

if [[ ! -f .venv/bin/activate || ! -x .venv/bin/python ]]; then
  echo "missing repository virtual environment: .venv" >&2
  exit 2
fi
python_bin="$PWD/.venv/bin/python"
manifest="reference/cybergym_e2e_paper_cohort.v1.json"

exec "$python_bin" run_modal_repeats.py --manifest "$manifest" "$@"
