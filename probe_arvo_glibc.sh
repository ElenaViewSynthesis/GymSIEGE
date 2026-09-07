#!/bin/bash
# Probe a target's OWN glibc/OS info directly, without going through
# node_compatibility_probe's pass/fail-only check (exploitgym_adapter.py's
# node_compatibility_probe only tells you whether the baked Node runtime's
# specific version requirements are satisfied; it never reports what the
# target's glibc actually IS). Run with --network none, matching this
# project's isolation posture for any offline compatibility check.
#
# Meant to be uploaded and exec'd inside a gymsiege-exploitgym sandbox by
# probe_arvo_glibc.py, one call per target image.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: probe_arvo_glibc.sh -i IMAGE [-t TASK_ID] [-o json|text] [-v]
  -i IMAGE    target Docker image to probe (required)
  -t TASK_ID  ExploitGym task id this image belongs to (label only)
  -o FORMAT   json (default) or text
  -v          verbose progress on stderr
EOF
  exit 2
}

image=""
task_id=""
output="json"
verbose=0

while getopts "i:t:o:vh" opt; do
  case "$opt" in
    i) image="$OPTARG" ;;
    t) task_id="$OPTARG" ;;
    o) output="$OPTARG" ;;
    v) verbose=1 ;;
    h) usage ;;
    *) usage ;;
  esac
done

[ -n "$image" ] || usage

[ "$verbose" = "1" ] && printf 'probing %s (task=%s)\n' "$image" "$task_id" >&2

if raw="$(docker run --rm --network none --entrypoint /bin/sh "$image" -c '
  strings /lib/x86_64-linux-gnu/libc.so.6 2>/dev/null | grep -oE "GLIBC_[0-9]+\.[0-9]+" | sort -Vu
  echo "---"
  cat /etc/os-release 2>/dev/null
' 2>&1)"; then
  ok=1
else
  ok=0
fi

# Serialize with python3 (already in the sandbox toolchain) rather than
# hand-rolled shell string escaping -- the os-release fields can contain
# quotes/spaces that would break naive JSON building.
printf '%s' "$raw" | python3 -c '
import json, sys

image, task_id, output, ok = sys.argv[1:5]
raw = sys.stdin.read()

if ok == "0":
    record = {"task_id": task_id, "image": image, "ok": False, "error": raw.strip()[-2000:]}
else:
    glibc_part, _, os_part = raw.partition("---\n")
    versions = [v for v in glibc_part.strip().splitlines() if v]
    os_release = dict(
        line.split("=", 1) for line in os_part.strip().splitlines() if "=" in line
    )
    record = {
        "task_id": task_id,
        "image": image,
        "ok": True,
        "glibc_versions": versions,
        "highest_glibc": versions[-1] if versions else None,
        "os_pretty_name": os_release.get("PRETTY_NAME", "").strip().strip("\""),
    }

if output == "json":
    print(json.dumps(record))
else:
    rec_ok = record["ok"]
    print("task=" + task_id + " image=" + image + " ok=" + str(rec_ok))
    if rec_ok:
        highest = record["highest_glibc"]
        os_name = record["os_pretty_name"]
        versions = ",".join(record["glibc_versions"])
        print("  highest_glibc=" + str(highest) + " os=" + os_name)
        print("  all_versions=" + versions)
    else:
        print("  error=" + record["error"])
' "$image" "$task_id" "$output" "$ok"
