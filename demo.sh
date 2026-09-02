#!/usr/bin/env bash
# GYMSIEGE demo entrypoint — reproduces a real (small) run from a clean
# checkout. Requires DAYTONA_API_KEY plus a Daytona organization-secret
# reference for the selected solver; see README.md#credentials. This talks to the real Daytona
# API and burns real quota — it is not a dry run.
set -euo pipefail

cd "$(dirname "$0")"

PYTHON_BIN="${PYTHON_BIN:-python3}"
if [[ ! -x .venv/bin/python ]]; then
  "$PYTHON_BIN" -m venv .venv
fi
.venv/bin/python -m pip install -q -r requirements.txt

.venv/bin/python - <<'PY'
import os
import common  # loads .env.local without printing it
missing = [
    name
    for name in ("DAYTONA_API_KEY", "LITELLM_BASE_URL", "GYMSIEGE_LITELLM_SECRET_NAME")
    if not os.environ.get(name)
]
if missing:
    raise SystemExit("Missing configuration: " + ", ".join(missing))
PY

echo "=== 1/4: bake gymsiege-toolchain (skip if it already exists) ==="
if .venv/bin/python - <<'PY'; then
import asyncio, os, sys
from daytona import AsyncDaytona
from common import SNAPSHOT_NAME

async def exists():
    async with AsyncDaytona() as d:
        page = await asyncio.wait_for(d.snapshot.list(), timeout=180)
        return any(
            getattr(s, "name", None) == SNAPSHOT_NAME
            and str(getattr(s, "state", "")).rsplit(".", 1)[-1].upper() == "ACTIVE"
            for s in page.items
        )

sys.exit(0 if asyncio.run(exists()) else 1)
PY
  echo "gymsiege-toolchain is ACTIVE, skipping bake."
else
  .venv/bin/python snapshot_build.py
fi

echo "=== 2/4: two-task smoke run (curl/arvo_66012, k=1, patch-only) ==="
.venv/bin/python orchestrator.py run --tasks-file tasks.pinned.txt --limit 2 --k 1 --modes patch-only --max-parallel 2

echo "=== 3/4: tiny concurrency probe (levels 1,2) ==="
.venv/bin/python orchestrator.py sweep --levels 1 2

echo "=== 4/4: publish the dashboard ==="
.venv/bin/python dashboard.py --publish

if [[ "${RUN_EXPLOITGYM:-0}" == "1" ]]; then
  echo "=== optional: ExploitGym hardened userspace smoke task ==="
  .venv/bin/python exploitgym_snapshot_build.py
  .venv/bin/python orchestrator.py exploitgym-run --limit 1 --k 1 --max-parallel 1
fi

echo
echo "Demo run complete. See results.json and results/ for raw output,"
echo "recordings/ for the .mp4 trace, and the printed URL above for the live dashboard."
echo
echo "For the full protocol (20-task main set x k=3, both modes, full"
echo "concurrency ladder), run:"
echo "  python3 orchestrator.py run --k 3 --modes e2e patch-only --max-parallel 8"
echo "  python3 orchestrator.py sweep"
