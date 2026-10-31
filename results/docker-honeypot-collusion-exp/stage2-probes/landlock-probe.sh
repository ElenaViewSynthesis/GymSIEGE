#!/usr/bin/env bash
# Stage 2 step 2, recorded: Landlock ABI inside the boundary container and the
# three runs under Codex's own sandbox. No key, no network, no model call.
# Writes /tmp/stage2-probes/landlock.log (verbatim) and landlock.json.
set -uo pipefail
IMG=${IMG:-rogue-agent-honeypot:5bbd1c1-dirty}
OUT=/tmp/stage2-probes
mkdir -p "$OUT"
LOG=$OUT/landlock.log
: > "$LOG"
declare -A EXIT

log() { printf '%s\n' "$*" | tee -a "$LOG"; }

# Exactly the runner's sandbox flags (docker_honeypot/runner.py sandbox_run_argv),
# with --network none: the sandbox question does not involve the network.
BOUNDARY_FLAGS=(--cpus 2 --memory 4g --pids-limit 512 --read-only=false
  --cap-drop ALL --cap-add SETGID --cap-add SETUID
  --security-opt no-new-privileges --workdir /workspace --network none)

start() {  # name, extra flags...
  local name=$1; shift
  docker rm --force "$name" >/dev/null 2>&1
  docker run --detach --rm --name "$name" "${BOUNDARY_FLAGS[@]}" "$@" "$IMG" sleep infinity >/dev/null
}

probe() {  # key, container, codex args..., -- command...
  local key=$1 name=$2; shift 2
  log "\$ codex sandbox -c sandbox_mode=\"workspace-write\" $*   [$key]"
  docker exec --workdir /workspace "$name" /usr/sbin/runuser -u honeypot -- \
    codex sandbox -c 'sandbox_mode="workspace-write"' "$@" > "$OUT/.out" 2>&1
  EXIT[$key]=$?
  grep -v 'stale arg0 temp dirs' "$OUT/.out" | sed 's/^/  | /' | tee -a "$LOG"
  log "  exit=${EXIT[$key]}"
}

three() {  # prefix, container, codex args...
  local prefix=$1 name=$2; shift 2
  probe "$prefix.true" "$name" "$@" -- /bin/true
  probe "$prefix.in_dir_write" "$name" "$@" -- sh -c 'echo probe > /workspace/probe-in.txt'
  probe "$prefix.out_dir_write" "$name" "$@" -- sh -c 'echo probe > /home/honeypot/probe-out.txt'
  log "  files after: $(docker exec "$name" /usr/sbin/runuser -u honeypot -- sh -c 'ls /workspace/probe-in.txt /home/honeypot/probe-out.txt 2>&1' | tr '\n' ' ')"
  docker exec "$name" /usr/sbin/runuser -u honeypot -- rm -f /workspace/probe-in.txt /home/honeypot/probe-out.txt
}

log "== recorded $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "image: $IMG $(docker image inspect --format '{{.Id}}' "$IMG")"
log "docker: $(docker version --format 'client {{.Client.Version}} server {{.Server.Version}}')"
start ll-probe-boundary
log "flags: $(docker inspect --format 'CapDrop={{.HostConfig.CapDrop}} CapAdd={{.HostConfig.CapAdd}} SecurityOpt={{.HostConfig.SecurityOpt}} Privileged={{.HostConfig.Privileged}} Mounts={{len .Mounts}} Network={{.HostConfig.NetworkMode}}' ll-probe-boundary)"
log "kernel: $(docker exec ll-probe-boundary uname -r)"
log "codex: $(docker exec ll-probe-boundary codex --version 2>&1 | grep -v 'stale arg0')"
log "max_user_namespaces: $(docker exec ll-probe-boundary cat /proc/sys/user/max_user_namespaces)"

log ""
log "== Landlock ABI: landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION), as honeypot"
ABI=$(docker exec ll-probe-boundary /usr/sbin/runuser -u honeypot -- python3 -c '
import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
abi = libc.syscall(444, None, 0, 1)
print(abi if abi >= 0 else "error " + os.strerror(ctypes.get_errno()))
')
log "  abi=$ABI"

log ""
log "== Helper: find / -name 'codex-linux-sandbox*' -type f"
HELPERS=$(docker exec ll-probe-boundary sh -c "find / -xdev -name 'codex-linux-sandbox*' -type f 2>/dev/null")
log "  found: ${HELPERS:-none (the sandbox is built into the codex binary; run as 'codex sandbox')}"
log "  codex sandbox --help (first line): $(docker exec ll-probe-boundary /usr/sbin/runuser -u honeypot -- codex sandbox --help 2>&1 | grep -v 'stale arg0' | head -1)"

log ""
log "== A. The boundary as built (Docker default seccomp)"
three default ll-probe-boundary
log ""
log "== B. Same container, Codex's deprecated legacy Landlock path"
three legacy ll-probe-boundary --enable use_legacy_landlock
docker rm --force ll-probe-boundary >/dev/null 2>&1

log ""
log "== C. Diagnostic only, NOT the boundary: same flags plus --security-opt seccomp=unconfined"
start ll-probe-unconfined --security-opt seccomp=unconfined
three unconfined ll-probe-unconfined
docker rm --force ll-probe-unconfined >/dev/null 2>&1
rm -f "$OUT/.out"

python3 - "$OUT/landlock.json" "$IMG" "$ABI" \
  "${EXIT[default.true]}" "${EXIT[default.in_dir_write]}" "${EXIT[default.out_dir_write]}" \
  "${EXIT[legacy.true]}" "${EXIT[legacy.in_dir_write]}" "${EXIT[legacy.out_dir_write]}" \
  "${EXIT[unconfined.true]}" "${EXIT[unconfined.in_dir_write]}" "${EXIT[unconfined.out_dir_write]}" <<'PY'
import json, sys
path, image, abi, *codes = sys.argv[1:]
codes = [int(c) for c in codes]
runs = lambda c: {"true": c[0], "in_dir_write": c[1], "out_dir_write": c[2]}
expected = {"true": 0, "in_dir_write": 0, "out_dir_write": "nonzero"}
default = runs(codes[0:3])
record = {
    "probe": "stage2-step2-landlock", "image": image,
    "landlock_abi": int(abi) if abi.lstrip("-").isdigit() else abi,
    "helper_file": None, "helper_invocation": "codex sandbox -c sandbox_mode=\"workspace-write\"",
    "exit_codes": {
        "default_seccomp_boundary": default,
        "legacy_landlock_feature": runs(codes[3:6]),
        "seccomp_unconfined_diagnostic": runs(codes[6:9]),
    },
    "expected": expected,
    "boundary_sandbox_works": default["true"] == 0 and default["in_dir_write"] == 0
                              and default["out_dir_write"] != 0,
}
json.dump(record, open(path, "w"), indent=2, sort_keys=True)
print(json.dumps(record, indent=2, sort_keys=True))
PY
