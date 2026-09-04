#!/usr/bin/env bash
# GYMSIEGE force-reap — escalating removal for a sandbox that ordinary
# cleanup cannot delete. Run this from a WSL terminal, not native Windows.
#
# Why this exists: `orchestrator.py reap` calls delete() and stops there. A
# sandbox wedged in a transitional state (CREATING) refuses delete with
# "Sandbox state change in progress", and the Daytona dashboard refuses it
# too -- while the sandbox still holds its full memory reservation against
# the organization-wide 10 GiB total. Since the ExploitGym snapshot restores
# at 8 GiB per sandbox, one wedged sandbox blocks every subsequent run with
# "Total memory limit exceeded", so removing it is not cosmetic.
#
# The ladder, stopping as soon as the sandbox is gone:
#   1. SDK  stop(force=True)   -- SIGKILL rather than SIGTERM
#   2. SDK  delete(wait=True)
#   3. REST POST   /sandbox/{id}/stop?force=true   -- bypasses SDK state checks
#   4. REST DELETE /sandbox/{id}
#
# This deletes real cloud resources and cannot be undone. It refuses to run
# without an explicit target unless you pass --all.
#
# Usage:
#   ./force_reap.sh <sandbox-id-or-name>   # one specific sandbox
#   ./force_reap.sh --all                  # every siege-* sandbox
#   ./force_reap.sh --list                 # show siege-* sandboxes, change nothing
#
# Exit codes: 0 = every target gone, 1 = at least one survived, 2 = usage error.
set -euo pipefail

cd "$(dirname "$0")"

# Pick an interpreter that can actually import the SDK. .venv/bin/python is
# the intended one, but that venv symlinks to /usr/bin/python3 and so only
# resolves inside WSL -- from a native Windows shell it is a dead symlink.
# Probing beats assuming: a wrong pick fails later as an opaque traceback.
PY_BIN=""
for candidate in "${PYTHON_BIN:-}" .venv/bin/python python3 python; do
  [[ -n "$candidate" ]] || continue
  if "$candidate" -c 'import daytona' >/dev/null 2>&1; then
    PY_BIN="$candidate"
    break
  fi
done
if [[ -z "$PY_BIN" ]]; then
  # The script already cd's to its own directory, so the hint does not need
  # an absolute path -- and must not hardcode one, since that would be wrong
  # for every checkout but the machine it was written on.
  cat >&2 <<'EOF'
error: no Python interpreter here can import the daytona SDK.
Run this from a WSL terminal (the venv symlinks to /usr/bin/python3, so it
resolves there but not from a native Windows shell):
  ./force_reap.sh --list
If the venv is missing, rebuild it from the repo root:
  python3 -m venv .venv && .venv/bin/python -m pip install -r requirements.txt
EOF
  exit 2
fi
[[ "$PY_BIN" == ".venv/bin/python" ]] || echo "note: using $PY_BIN (not .venv/bin/python)" >&2

usage() {
  echo "usage: $0 <sandbox-id-or-name> | --all | --list" >&2
  exit 2
}

[[ $# -eq 1 ]] || usage
TARGET="$1"

case "$TARGET" in
  -h|--help) usage ;;
  --list)
    exec "$PY_BIN" orchestrator.py reap --dry-run
    ;;
esac

# `common` loads .env.local without echoing any value.
"$PY_BIN" - "$TARGET" <<'PY'
import asyncio
import sys

import common  # noqa: F401  -- loads .env.local into the environment
from common import SANDBOX_NAME_PREFIX
from daytona import AsyncDaytona

target = sys.argv[1]


async def state_of(daytona, ref):
    """Return the sandbox's state, or None once it no longer exists."""
    try:
        sandbox = await daytona.get(ref, request_timeout=60)
    except Exception:
        return None
    return str(getattr(sandbox, "state", "unknown"))


async def escalate(daytona, sandbox) -> bool:
    """Run the ladder against one sandbox. True once it is gone."""
    ref = getattr(sandbox, "id", None) or getattr(sandbox, "name", None)
    name = getattr(sandbox, "name", "?")
    print(f"\n=== {name} ({ref}) state={getattr(sandbox, 'state', '?')} ===")

    steps = (
        ("stop(force=True)", lambda: sandbox.stop(timeout=120, force=True)),
        ("delete(wait=True)", lambda: sandbox.delete(timeout=180, wait=True)),
    )
    for label, call in steps:
        try:
            await call()
            print(f"  {label}: OK")
        except Exception as exc:
            # Keep going: a refused stop does not mean delete will be refused.
            print(f"  {label}: FAILED -> {str(exc).splitlines()[0]}")
        if await state_of(daytona, ref) is None:
            print(f"  gone after {label}")
            return True

    print("  SDK path exhausted; falling back to the REST API")
    return False


async def main() -> int:
    survivors = []
    async with AsyncDaytona() as daytona:
        if target == "--all":
            prefix = f"{SANDBOX_NAME_PREFIX}-"
            targets = [
                s async for s in daytona.list()
                if str(getattr(s, "name", "")).startswith(prefix)
            ]
            if not targets:
                print(f"no {prefix}* sandboxes found; nothing to do")
                return 0
            print(f"targeting {len(targets)} {prefix}* sandbox(es)")
        else:
            try:
                targets = [await daytona.get(target, request_timeout=60)]
            except Exception as exc:
                print(f"{target}: not found ({exc})")
                return 0  # already gone is the desired end state

        for sandbox in targets:
            if not await escalate(daytona, sandbox):
                ref = getattr(sandbox, "id", None) or getattr(sandbox, "name", None)
                survivors.append(str(ref))

    # Hand any survivor to the REST fallback in the shell below.
    with open("/tmp/gymsiege-force-reap-survivors", "w", encoding="utf-8") as handle:
        handle.write("\n".join(survivors))
    return 1 if survivors else 0


raise SystemExit(asyncio.run(main()))
PY
sdk_status=$?

if [[ $sdk_status -eq 0 ]]; then
  echo
  echo "all targets removed via the SDK"
  exit 0
fi

SURVIVORS_FILE=/tmp/gymsiege-force-reap-survivors
[[ -s "$SURVIVORS_FILE" ]] || { echo "nothing left to escalate"; exit 0; }

# REST fallback. `set -a` exports every .env.local value without printing it.
set -a
# shellcheck disable=SC1091
. ./.env.local
set +a
: "${DAYTONA_API_KEY:?DAYTONA_API_KEY is not set in .env.local}"
API_URL="${DAYTONA_API_URL:-https://app.daytona.io/api}"

rc=0
while read -r SB; do
  [[ -n "$SB" ]] || continue
  echo
  echo "=== REST fallback for $SB ==="
  curl -sS -X POST "$API_URL/sandbox/$SB/stop?force=true" \
    -H "Authorization: Bearer $DAYTONA_API_KEY" \
    -w '\n  stop   -> HTTP %{http_code}\n' || true
  curl -sS -X DELETE "$API_URL/sandbox/$SB" \
    -H "Authorization: Bearer $DAYTONA_API_KEY" \
    -w '\n  delete -> HTTP %{http_code}\n' || true

  if "$PY_BIN" - "$SB" <<'PY'; then
import asyncio, sys
import common  # noqa: F401
from daytona import AsyncDaytona

async def main():
    async with AsyncDaytona() as d:
        try:
            sb = await d.get(sys.argv[1], request_timeout=60)
        except Exception:
            return 0          # gone
        print(f"  still present, state={getattr(sb, 'state', '?')}")
        return 1

raise SystemExit(asyncio.run(main()))
PY
    echo "  gone"
  else
    rc=1
  fi
done < "$SURVIVORS_FILE"
rm -f "$SURVIVORS_FILE"

if [[ $rc -ne 0 ]]; then
  cat >&2 <<'EOF'

Still not removed. That is a stuck platform-side operation, not a bad command:
a sandbox in CREATING has never finished provisioning, so there is no running
process to kill and no completed resource to delete. What remains is the
server-side expiry timer passed as ttl_minutes at creation (60 minutes), which
releases the memory reservation on its own.

Worth quoting in a support ticket -- a resource that can be neither used nor
deleted while it consumes the organization's entire memory quota is the
sharpest form of daytonaio/daytona#5156.
EOF
fi
exit $rc
