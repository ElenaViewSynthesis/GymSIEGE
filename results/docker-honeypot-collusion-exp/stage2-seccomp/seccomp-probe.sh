#!/usr/bin/env bash
# Stage 2 seccomp record: Landlock ABI and the three Codex-sandbox runs inside
# the boundary container under docker_honeypot/seccomp-bwrap.json, plus an
# strace of which added calls bubblewrap uses. No key, no network, no model.
# Writes /tmp/stage2-seccomp/seccomp.log (verbatim) and seccomp.json.
set -uo pipefail
REPO=/mnt/c/Users/proxi/Documents/codex-7/daytona-sandbox
PROFILE=$REPO/docker_honeypot/seccomp-bwrap.json
IMG=${IMG:?set IMG to the agent image tag}
OUT=/tmp/stage2-seccomp
NAME=seccomp-probe-boundary
ADDED=clone,clone3,unshare,setns,mount,umount2,pivot_root,mount_setattr,open_tree,move_mount,fsopen,fsconfig,fsmount,fspick,sethostname
mkdir -p "$OUT"
LOG=$OUT/seccomp.log
: > "$LOG"
declare -A EXIT
log() { printf '%s\n' "$*" | tee -a "$LOG"; }

# The runner's sandbox flags plus the profile, with --network none (the sandbox
# question does not involve the network).
docker rm --force "$NAME" >/dev/null 2>&1
docker run --detach --rm --name "$NAME" --cpus 2 --memory 4g --pids-limit 512 \
  --read-only=false --cap-drop ALL --cap-add SETGID --cap-add SETUID \
  --security-opt no-new-privileges --security-opt "seccomp=$PROFILE" \
  --workdir /workspace --network none "$IMG" sleep infinity >/dev/null

as_agent() { docker exec --workdir /tmp/probe-dir "$NAME" /usr/sbin/runuser -u honeypot -- "$@"; }

log "== recorded $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "image: $IMG $(docker image inspect --format '{{.Id}}' "$IMG")"
log "profile: docker_honeypot/seccomp-bwrap.json sha256 $(sha256sum "$PROFILE" | cut -d' ' -f1)"
log "flags: $(docker inspect --format 'CapDrop={{.HostConfig.CapDrop}} CapAdd={{.HostConfig.CapAdd}} Privileged={{.HostConfig.Privileged}} Mounts={{len .Mounts}} Network={{.HostConfig.NetworkMode}}' "$NAME")"
log "security_opt: $(docker inspect --format '{{range .HostConfig.SecurityOpt}}{{if eq (printf "%.7s" .) "seccomp"}}seccomp=<profile contents>{{else}}{{.}}{{end}} {{end}}' "$NAME")"
log "kernel: $(docker exec "$NAME" uname -r)  codex: $(docker exec "$NAME" codex --version 2>&1 | grep -v 'stale arg0')"
docker exec "$NAME" /usr/sbin/runuser -u honeypot -- mkdir -p /tmp/probe-dir

log ""
log "== Landlock ABI: landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION), as honeypot"
ABI=$(as_agent python3 -c '
import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
abi = libc.syscall(444, None, 0, 1)
print(abi if abi >= 0 else "error " + os.strerror(ctypes.get_errno()))
')
log "  abi=$ABI"

probe() {  # key, command...
  local key=$1; shift
  log "\$ codex sandbox -c sandbox_mode=\"workspace-write\" -- $*   [cwd /tmp/probe-dir, $key]"
  as_agent codex sandbox -c 'sandbox_mode="workspace-write"' -- "$@" > "$OUT/.out" 2>&1
  EXIT[$key]=$?
  grep -v 'stale arg0 temp dirs' "$OUT/.out" | sed 's/^/  | /' | tee -a "$LOG"
  log "  exit=${EXIT[$key]}"
}

log ""
log "== Codex's own sandbox (bubblewrap) under the narrow profile"
probe true /bin/true
probe in_dir_write sh -c 'echo probe > /tmp/probe-dir/inside.txt && cat /tmp/probe-dir/inside.txt'
probe out_dir_write sh -c 'echo probe > /home/honeypot/outside.txt'
log "  files after: $(as_agent sh -c 'ls /tmp/probe-dir/inside.txt /home/honeypot/outside.txt 2>&1' | tr '\n' ' ')"

log ""
log "== Which added calls bubblewrap makes (strace -f, the added set plus clone3; /bin/true run)"
as_agent strace -f -qq -e "trace=$ADDED" -o /tmp/probe-dir/strace.txt \
  codex sandbox -c 'sandbox_mode="workspace-write"' -- /bin/true > "$OUT/.out" 2>&1
STRACE_EXIT=$?
log "  strace run exit=$STRACE_EXIT"
docker exec "$NAME" cat /tmp/probe-dir/strace.txt > "$OUT/strace.txt" 2>/dev/null
python3 - "$OUT/strace.txt" <<'PY' | tee -a "$LOG"
import re, sys
from collections import Counter
calls, refused = Counter(), Counter()
for line in open(sys.argv[1], errors="replace"):
    m = re.match(r"\s*\d+\s+([a-z0-9_]+)\(", line)
    if not m:
        continue
    calls[m.group(1)] += 1
    if re.search(r"= -1 (EPERM|EACCES|ENOSYS)", line):
        refused[(m.group(1), re.search(r"= -1 (\w+)", line).group(1))] += 1
print("  calls made:", ", ".join(f"{k} x{v}" for k, v in sorted(calls.items())) or "none")
print("  refused:", ", ".join(f"{k}={e} x{v}" for (k, e), v in sorted(refused.items())) or "none")
PY
docker rm --force "$NAME" >/dev/null 2>&1
log "  container removed: $(docker container inspect "$NAME" >/dev/null 2>&1 && echo no || echo yes)"
rm -f "$OUT/.out"

python3 - "$OUT/seccomp.json" "$IMG" "$ABI" "$(sha256sum "$PROFILE" | cut -d' ' -f1)" \
  "${EXIT[true]}" "${EXIT[in_dir_write]}" "${EXIT[out_dir_write]}" "$OUT/strace.txt" <<'PY'
import json, re, sys
from collections import Counter
path, image, abi, sha, t, i, o, strace = sys.argv[1:]
codes = {"true": int(t), "in_dir_write": int(i), "out_dir_write": int(o)}
calls = Counter(m.group(1) for line in open(strace, errors="replace")
                if (m := re.match(r"\s*\d+\s+([a-z0-9_]+)\(", line)))
record = {
    "probe": "stage2-seccomp", "image": image,
    "seccomp_profile": {"path": "docker_honeypot/seccomp-bwrap.json", "sha256": sha},
    "landlock_abi": int(abi) if abi.lstrip("-").isdigit() else abi,
    "helper_invocation": "codex sandbox -c sandbox_mode=\"workspace-write\"",
    "exit_codes": codes,
    "expected": {"true": 0, "in_dir_write": 0, "out_dir_write": "nonzero, permission or read-only error"},
    "boundary_sandbox_works": codes["true"] == 0 and codes["in_dir_write"] == 0 and codes["out_dir_write"] != 0,
    "added_calls_observed": dict(sorted(calls.items())),
}
json.dump(record, open(path, "w"), indent=2, sort_keys=True)
print(json.dumps(record, indent=2, sort_keys=True))
PY
