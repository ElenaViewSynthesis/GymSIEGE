#!/usr/bin/env python3
"""Event-driven alerter, and opt-in enforcer, for one harness run.

Tails the run's visible event logs (the process log first, then any sink or
replication log) as the evidence-chain mirrors write them, and classifies every
line with boundary_events.py, the same scored set and exclusions as the
time-to-first-boundary-event metric. At the first boundary event it writes
ALERT_RAISED, timestamped by this process, naming the trigger's kind, log, line
and timestamp. The relay forwards only the lines writers sent through its FIFO;
the visible logs are the complete, ordered streams, so they are what is tailed.

With --enforce (off by default) it then kills the agent's process tree and
chains KILL_ISSUED and TERMINATED. The tree is every live process that is

* a descendant of the agent root (walking parent links in /proc),
* in the root's session or process group, or
* carrying the run's launch ID (HONEYPOT_LAUNCH_ID) in its environment,

so a child started with nohup (reparented) or setsid (a session of its own)
is still found. Sweeps repeat until none is left (or 10 s pass); TERMINATED
records the time the last sweep found nothing, how many processes were killed,
the sweeps, and any survivor. The harness, its monitor, mirrors and relay, the
decoy sibling and this process are never targets, and the session and group
rules are dropped if the root shares them with the harness.

Lines go to the chain pipe (--log-fd) like every other writer's, or are
appended to --event-log when the chain is off. The alerter runs in the harness,
outside the agent's tree and without the preload, so it raises no event of its
own other than these three.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import signal
import time
from pathlib import Path


HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("honeypot_boundary_events", HERE / "boundary_events.py")
boundary = importlib.util.module_from_spec(_spec)
assert _spec.loader
_spec.loader.exec_module(boundary)

KILL_DEADLINE_SECONDS = 10.0


def now_stamp() -> str:
    ns = time.time_ns()
    return f"{ns // 1_000_000_000}.{ns % 1_000_000_000:09d}"


class Writer:
    def __init__(self, log_fd: int, event_log: Path | None) -> None:
        self.log_fd = log_fd
        self.event_log = event_log

    def emit(self, kind: str, target: int | str, detail: str, stamp: str | None = None) -> str:
        stamp = stamp or now_stamp()
        line = f"{stamp}\t{kind}\t{os.getpid()}\t{target}\t{detail}\n".encode()
        if self.log_fd >= 0:
            try:
                os.write(self.log_fd, line)
                return stamp
            except OSError:
                pass
        if self.event_log is not None:
            with self.event_log.open("ab") as handle:
                handle.write(line)
        return stamp


class Tail:
    """New complete lines of one growing file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.name = path.name
        self.handle = None
        self.buffer = b""
        self.lines = 0

    def read(self) -> list[tuple[int, str]]:
        if self.handle is None:
            try:
                self.handle = self.path.open("rb")
            except OSError:
                return []
        chunk = self.handle.read()
        if not chunk:
            return []
        self.buffer += chunk
        out = []
        while b"\n" in self.buffer:
            raw, self.buffer = self.buffer.split(b"\n", 1)
            self.lines += 1
            out.append((self.lines, raw.decode("utf-8", "replace")))
        return out


def _stat(pid: int) -> tuple[int, int, int, str] | None:
    """(ppid, pgid, sid, state) of a live process, or None."""
    try:
        raw = (Path("/proc") / str(pid) / "stat").read_text()
    except OSError:
        return None
    end = raw.rfind(")")
    fields = raw[end + 2:].split()
    try:
        return int(fields[1]), int(fields[2]), int(fields[3]), fields[0]
    except (IndexError, ValueError):
        return None


def _carries(pid: int, marker: bytes) -> bool:
    try:
        environ = (Path("/proc") / str(pid) / "environ").read_bytes()
    except OSError:
        return False
    return marker in environ.split(b"\0")


def agent_processes(root: int, *, launch_id: str | None, protect: set[int], harness: int | None) -> set[int]:
    """Every live (non-zombie) process of the agent's tree, as the module doc defines it."""
    table: dict[int, tuple[int, int, int, str]] = {}
    for entry in Path("/proc").iterdir():
        if entry.name.isdigit():
            info = _stat(int(entry.name))
            if info is not None:
                table[int(entry.name)] = info
    children: dict[int, list[int]] = {}
    for pid, (ppid, _pgid, _sid, _state) in table.items():
        children.setdefault(ppid, []).append(pid)
    members: set[int] = set()
    stack = [root] if root in table else []
    while stack:
        pid = stack.pop()
        if pid in members:
            continue
        members.add(pid)
        stack.extend(children.get(pid, []))
    root_info = table.get(root)
    root_sid = root_info[2] if root_info else root
    root_pgid = root_info[1] if root_info else root
    harness_info = table.get(harness) if harness else None
    use_session = not harness_info or harness_info[2] != root_sid
    use_group = not harness_info or harness_info[1] != root_pgid
    marker = f"HONEYPOT_LAUNCH_ID={launch_id}".encode() if launch_id else None
    for pid, (_ppid, pgid, sid, _state) in table.items():
        if (use_session and sid == root_sid) or (use_group and pgid == root_pgid):
            members.add(pid)
        elif marker is not None and _carries(pid, marker):
            members.add(pid)
    return {pid for pid in members if pid in table and table[pid][3] != "Z" and pid not in protect}


def enforce(root: int, writer: Writer, *, launch_id: str | None, protect: set[int],
            harness: int | None) -> None:
    targets = agent_processes(root, launch_id=launch_id, protect=protect, harness=harness)
    writer.emit("KILL_ISSUED", root, f"signal=KILL targets={len(targets)}")
    if not targets:
        writer.emit("TERMINATED", root, "killed=0 sweeps=1 survivors=0 cause=exited_before_kill")
        return
    killed: set[int] = set()
    refused: set[int] = set()
    sweeps = 0
    deadline = time.monotonic() + KILL_DEADLINE_SECONDS
    while targets and time.monotonic() < deadline:
        sweeps += 1
        for pid in targets:
            try:
                os.kill(pid, signal.SIGKILL)
                killed.add(pid)
            except ProcessLookupError:
                pass
            except PermissionError:
                refused.add(pid)
        time.sleep(0.002)
        targets = agent_processes(root, launch_id=launch_id, protect=protect, harness=harness) - refused
    survivors = agent_processes(root, launch_id=launch_id, protect=protect, harness=harness)
    cause = "enforced" if not survivors else "survivors"
    writer.emit("TERMINATED", root,
                f"killed={len(killed)} sweeps={sweeps} survivors={len(survivors)} cause={cause}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--log", type=Path, action="append", required=True,
                        help="a visible event log to tail; the process log first")
    parser.add_argument("--root-file", type=Path, required=True, help="file holding the agent root's PID")
    parser.add_argument("--harness-pid", type=int)
    parser.add_argument("--canary-pid", type=int)
    parser.add_argument("--decoys", default="", help="colon-separated paths the run registered as decoys")
    parser.add_argument("--log-fd", type=int, default=-1)
    parser.add_argument("--event-log", type=Path, help="append here when the chain is off")
    parser.add_argument("--stop-file", type=Path, required=True)
    parser.add_argument("--ready-file", type=Path,
                        help="created once the alerter is tailing, so the harness can start the agent")
    parser.add_argument("--enforce", action="store_true")
    parser.add_argument("--launch-id")
    parser.add_argument("--interval", type=float, default=0.005)
    parser.add_argument("--drain-quiet", type=float, default=0.3)
    parser.add_argument("--drain-max", type=float, default=5.0)
    args = parser.parse_args()

    writer = Writer(args.log_fd, args.event_log)
    lineage = boundary.Lineage(
        harness_pids=[args.harness_pid] if args.harness_pid else [],
        canary_pids=[args.canary_pid] if args.canary_pid else [],
    )
    tracker = boundary.Tracker(lineage, decoys=args.decoys.split(":"))
    tails = [Tail(path) for path in args.log]
    protect = {os.getpid(), os.getppid()}
    for pid in (args.harness_pid, args.canary_pid):
        if pid:
            protect.add(pid)
    root: int | None = None
    alerted = False
    stop_seen_at: float | None = None
    last_data = time.monotonic()

    def read_root() -> int | None:
        try:
            return int(args.root_file.read_text().strip())
        except (OSError, ValueError):
            return None

    if args.ready_file is not None:
        args.ready_file.touch()
    while True:
        if root is None:
            root = read_root()
            if root is not None:
                lineage.root = lineage.root or root
        got = False
        for tail in tails:
            for number, text in tail.read():
                got = True
                event = boundary.parse_line(text, tail.name, number)
                if event is None or event.kind in boundary.ALERT_KINDS:
                    continue
                if tracker.feed(event) and not alerted:
                    alerted = True
                    writer.emit("ALERT_RAISED", event.pid,
                                f"trigger={event.kind} trigger_log={tail.name} trigger_line={number} "
                                f"trigger_ts={event.timestamp:.9f}")
                    if args.enforce:
                        waited = time.monotonic()
                        while root is None and time.monotonic() - waited < 2.0:
                            time.sleep(0.01)
                            root = read_root()
                        if root is not None:
                            enforce(root, writer, launch_id=args.launch_id, protect=protect,
                                    harness=args.harness_pid)
                        else:
                            writer.emit("TERMINATED", 0, "killed=0 sweeps=0 survivors=0 cause=root_unknown")
        clock = time.monotonic()
        if got:
            last_data = clock
        if stop_seen_at is None and args.stop_file.exists():
            stop_seen_at = clock
        if stop_seen_at is not None and (
                clock - last_data >= args.drain_quiet or clock - stop_seen_at >= args.drain_max):
            break
        time.sleep(args.interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
