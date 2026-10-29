#!/usr/bin/env python3
"""Follow a file inside a running Modal honeypot sandbox by polling its filesystem API.

Used by watch_sandbox_stream.sh. Reads with stat + read_bytes (no process is
started inside the sandbox), prints new lines as they appear, redacts secrets and
markers by pattern, and stops when the sandbox exits.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time

DEFAULT_APP = "rogue-agent-honeypots"
OUTPUT_ROOT = "/tmp/honeypot-output"

REDACTIONS = [
    (re.compile(r"sk-[A-Za-z0-9_-]{8,}"), "[REDACTED-KEY]"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{8,}"), "Bearer [REDACTED-TOKEN]"),
    (re.compile(r"HONEYCOLLUDE(?:_CONTENT)?_[A-Za-z0-9_-]+"), "[REDACTED-MARKER]"),
    (re.compile(r"HONEYTRIPWIRE_[A-Za-z0-9_-]+"), "[REDACTED-MARKER]"),
]


def redact(text: str) -> str:
    for pattern, replacement in REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


def excerpt(value: object, limit: int = 160) -> str:
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def compact(line: str) -> str:
    """One line per Codex JSONL event: type, item type, and a short excerpt."""
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        return f"?? {excerpt(line)}"
    kind = str(event.get("type", "?"))
    item = event.get("item") if isinstance(event.get("item"), dict) else {}
    item_type = str(item.get("type", "")) if item else ""
    detail: object = ""
    for key in ("command", "text", "aggregated_output", "message", "query", "error"):
        if item and item.get(key):
            detail = item[key]
            break
    if not detail:
        for key in ("message", "error", "text"):
            if event.get(key):
                detail = event[key]
                break
    head = f"{kind:<16} {item_type:<20}".rstrip()
    return f"{head} {excerpt(detail)}" if detail else head


def pick_sandbox(modal, app_name: str, sandbox_id: str | None):
    if sandbox_id:
        return modal.Sandbox.from_id(sandbox_id)
    app = modal.App.lookup(app_name)
    running = [sb for sb in modal.Sandbox.list(app_id=app.app_id) if sb.poll() is None]
    if not running:
        raise SystemExit(f"no running sandbox in app {app_name!r}; start the run first, or pass --sandbox-id")
    if len(running) > 1:
        ids = ", ".join(sb.object_id for sb in running)
        print(f"note: {len(running)} running sandboxes ({ids}); following the first. Use --sandbox-id to choose.",
              file=sys.stderr)
    return running[0]


def list_sandboxes(modal, app_name: str) -> int:
    app = modal.App.lookup(app_name)
    rows = list(modal.Sandbox.list(app_id=app.app_id))
    if not rows:
        print(f"no sandboxes listed for app {app_name!r}")
        return 0
    for sb in rows:
        state = "running" if sb.poll() is None else f"exited({sb.poll()})"
        print(f"{sb.object_id}  {state}")
    return 0


def follow(sb, path: str, *, interval: float, raw: bool, tail_only: bool) -> int:
    fs = sb.filesystem
    offset = 0
    announced = False
    carry = b""
    while True:
        exited = sb.poll()
        try:
            info = fs.stat(path)
            exists = True
        except Exception:
            exists = False
        if exists:
            if not announced:
                print(f"-- following {path} in {sb.object_id}", file=sys.stderr)
                announced = True
                if tail_only:
                    offset = int(getattr(info, "size", 0) or 0)
            size = int(getattr(info, "size", 0) or 0)
            if size > offset:
                data = fs.read_bytes(path)[offset:size]
                offset = size
                buffer = carry + data
                lines = buffer.split(b"\n")
                carry = lines.pop()  # incomplete trailing line, if any
                for chunk in lines:
                    text = redact(chunk.decode("utf-8", errors="replace"))
                    print(text if raw else compact(text), flush=True)
        if exited is not None:
            if carry:
                text = redact(carry.decode("utf-8", errors="replace"))
                print(text if raw else compact(text), flush=True)
            print(f"-- sandbox {sb.object_id} exited with {exited}; {offset} bytes read", file=sys.stderr)
            return 0
        time.sleep(interval)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--app-name", default=DEFAULT_APP)
    parser.add_argument("--sandbox-id", help="follow this sandbox instead of the newest running one")
    parser.add_argument("--case", default="CLH-036", help="case whose subject stream to follow")
    parser.add_argument("--path", help="explicit remote path; overrides --case/--events")
    parser.add_argument("--events", action="store_true",
                        help="follow the subject harness's events.tsv instead of the Codex JSONL")
    parser.add_argument("--interval", type=float, default=3.0, help="poll interval in seconds (min 1)")
    parser.add_argument("--raw", action="store_true", help="print redacted JSON lines in full")
    parser.add_argument("--tail", action="store_true", help="start at the current end of the file")
    parser.add_argument("--list", action="store_true", help="list the app's sandboxes and exit")
    args = parser.parse_args()
    if args.interval < 1:
        parser.error("--interval must be at least 1 second (each poll is a control-plane call)")

    try:
        import modal
    except ModuleNotFoundError:
        raise SystemExit("the modal SDK is not importable; run through watch_sandbox_stream.sh with the repo venv")

    if args.list:
        return list_sandboxes(modal, args.app_name)

    if args.path:
        path = args.path
    elif args.events:
        path = f"{OUTPUT_ROOT}/cases/{args.case}/runs/subject/harness/events.tsv"
    else:
        path = f"{OUTPUT_ROOT}/cases/{args.case}/runs/subject/trajectory.jsonl"

    sb = pick_sandbox(modal, args.app_name, args.sandbox_id)
    try:
        return follow(sb, path, interval=args.interval, raw=args.raw, tail_only=args.tail)
    except KeyboardInterrupt:
        print("-- stopped by user; the run continues unaffected", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
