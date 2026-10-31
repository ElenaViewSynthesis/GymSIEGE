#!/usr/bin/env python3
"""Build docker_honeypot/seccomp-bwrap.json from Docker's default profile.

The Docker boundary's sandbox container runs Codex 0.164.0 with its own
workspace-write sandbox, which is bubblewrap: it needs an unprivileged user
namespace and the mount calls that populate it. Docker's default seccomp
profile allows those only to containers holding CAP_SYS_ADMIN, which this
container never has. This script keeps the default profile's rules verbatim
and appends one documented rule per call bubblewrap needs, nothing else.

Source: docker_honeypot/seccomp-default.json is a byte-for-byte copy of
github.com/moby/profiles seccomp/v0.2.3 seccomp/default.json, the module that
Docker Engine 29.5.2 (moby commit 568f755) pins in its go.mod.

Run from the repository root:  python3 docker_honeypot/build_seccomp_profile.py
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT = HERE / "seccomp-default.json"
OUTPUT = HERE / "seccomp-bwrap.json"
SOURCE = {
    "module": "github.com/moby/profiles/seccomp",
    "version": "v0.2.3",
    "url": "https://raw.githubusercontent.com/moby/profiles/seccomp/v0.2.3/seccomp/default.json",
    "pinned_by": "moby/moby go.mod at 568f755ebeb1ac9c6a8febbda6cd371ea0a9630b (Docker Engine 29.5.2)",
    "vendored_copy": "docker_honeypot/seccomp-default.json",
}

# The six namespace flags bubblewrap may create. CLONE_NEWCGROUP (0x02000000)
# and CLONE_NEWTIME (0x00000080) stay refused.
CLONE_NEWNS = 0x00020000
CLONE_NEWUTS = 0x04000000
CLONE_NEWIPC = 0x08000000
CLONE_NEWUSER = 0x10000000
CLONE_NEWPID = 0x20000000
CLONE_NEWNET = 0x40000000
CLONE_NEWCGROUP = 0x02000000
CLONE_NEWTIME = 0x00000080
ALLOWED_NAMESPACES = (
    CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWNET
)
# Docker's default refuses clone() whenever any of these bits is set.
DEFAULT_CLONE_MASK = 0x7E020000
assert DEFAULT_CLONE_MASK == ALLOWED_NAMESPACES | CLONE_NEWCGROUP

# One rule per call, in the order bubblewrap reaches them while building the
# sandbox. Each comment names the bubblewrap step the call serves.
ADDED_RULES: list[dict[str, object]] = [
    {
        "names": ["clone"],
        "action": "SCMP_ACT_ALLOW",
        "args": [{"index": 0, "value": CLONE_NEWCGROUP, "op": "SCMP_CMP_MASKED_EQ"}],
        "excludes": {"arches": ["s390", "s390x"]},
        "comment": "bwrap: the raw clone() that starts the sandbox child in new user, mount, "
                   "pid, ipc, uts and net namespaces; any flag mix of those six passes, "
                   "CLONE_NEWCGROUP is still refused",
    },
    {
        "names": ["unshare"],
        "action": "SCMP_ACT_ALLOW",
        "args": [{"index": 0, "value": CLONE_NEWCGROUP | CLONE_NEWTIME, "op": "SCMP_CMP_MASKED_EQ"}],
        "comment": "bwrap: namespaces entered after the clone, such as the second user "
                   "namespace that drops the outer uid mapping; cgroup and time namespaces "
                   "are still refused",
    },
    {
        "names": ["setns"],
        "action": "SCMP_ACT_ALLOW",
        "comment": "bwrap: joining a namespace it already holds a file descriptor for "
                   "(--userns, --pidns, and re-entering the outer user namespace)",
    },
    {
        "names": ["mount"],
        "action": "SCMP_ACT_ALLOW",
        "comment": "bwrap: making / private (MS_SLAVE|MS_REC), the tmpfs new root, the "
                   "--ro-bind / --bind / --dev / --proc / --tmpfs mounts, and the read-only "
                   "remounts of everything outside the writable roots",
    },
    {
        "names": ["pivot_root"],
        "action": "SCMP_ACT_ALLOW",
        "comment": "bwrap: switching the sandbox into the new root it assembled",
    },
    {
        "names": ["umount2"],
        "action": "SCMP_ACT_ALLOW",
        "comment": "bwrap: detaching the old root after pivot_root (MNT_DETACH)",
    },
    {
        "names": ["mount_setattr"],
        "action": "SCMP_ACT_ALLOW",
        "comment": "bwrap / new mount API: recursive attribute changes (read-only, nosuid, "
                   "nodev) on a bound tree in one call",
    },
    {
        "names": ["open_tree"],
        "action": "SCMP_ACT_ALLOW",
        "comment": "bwrap / new mount API: detached copy of a tree, the new-API form of a "
                   "bind mount",
    },
    {
        "names": ["move_mount"],
        "action": "SCMP_ACT_ALLOW",
        "comment": "bwrap / new mount API: attaching a tree from open_tree or fsmount at its "
                   "place in the new root",
    },
    {
        "names": ["fsopen"],
        "action": "SCMP_ACT_ALLOW",
        "comment": "bwrap / new mount API: creating a filesystem context (proc, tmpfs, mqueue)",
    },
    {
        "names": ["fsconfig"],
        "action": "SCMP_ACT_ALLOW",
        "comment": "bwrap / new mount API: setting options on that context before it is created",
    },
    {
        "names": ["fsmount"],
        "action": "SCMP_ACT_ALLOW",
        "comment": "bwrap / new mount API: turning the configured context into a mount",
    },
    {
        "names": ["fspick"],
        "action": "SCMP_ACT_ALLOW",
        "comment": "bwrap / new mount API: reconfiguring an existing mount, the new-API form "
                   "of a remount",
    },
    {
        "names": ["sethostname"],
        "action": "SCMP_ACT_ALLOW",
        "comment": "bwrap: setting the hostname inside its new UTS namespace (--hostname)",
    },
]

# Requested and deliberately left at Docker's default: clone3 takes its flags in
# a struct that seccomp cannot inspect, so allowing it would admit every
# namespace type including cgroup and time; the default rule answers it with
# ENOSYS, glibc then falls back to clone(), and bubblewrap calls clone() itself.
LEFT_AT_DEFAULT = {"clone3": "ENOSYS for containers without CAP_SYS_ADMIN (default rule)"}


def build() -> dict[str, object]:
    raw = DEFAULT.read_bytes()
    default = json.loads(raw)
    profile = dict(default)
    profile["syscalls"] = [*default["syscalls"], *ADDED_RULES]
    # Docker reads defaultAction, defaultErrnoRet, archMap and syscalls; this key is
    # ignored by the daemon and is the profile's provenance.
    profile["x-gymsiege-provenance"] = {
        **SOURCE,
        "default_sha256": hashlib.sha256(raw).hexdigest(),
        "default_rules_kept_verbatim": len(default["syscalls"]),
        "added_rules": len(ADDED_RULES),
        "left_at_default": LEFT_AT_DEFAULT,
        "built_by": "docker_honeypot/build_seccomp_profile.py",
    }
    return profile


def main() -> int:
    profile = build()
    OUTPUT.write_text(json.dumps(profile, indent=2) + "\n")
    print(f"wrote {OUTPUT.name}: sha256 {hashlib.sha256(OUTPUT.read_bytes()).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
