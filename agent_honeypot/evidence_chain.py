#!/usr/bin/env python3
"""Parent-owned, keyed evidence chain for a harness event log.

Every writer of an event log (the preload, the PATH shims, the procfs monitor,
the sinks, the harness itself) sends raw lines down an inherited pipe instead
of appending to a file. The mirror runs in the harness, never in the agent's
process tree. It appends each line verbatim to the visible log, which the
scorers read as before, and a chained record to a private file: sequence
number, previous chain hash, SHA-256 chain hash, and an HMAC under a 32-byte
key minted per run. The key never leaves the mirror process: when the run
ends, the mirror itself recomputes the chain, compares the visible log with it
line by line, copies the chain beside the visible log, and writes the
verdict to an evidence file. The agent holds the write end of the pipe, like
every other writer, but never the read end, so it cannot drain events, and it
never holds the key, so it cannot forge or repair a chain.

An edited, truncated, or padded visible log is reported as a mismatch; an
edited chain breaks the hash linkage. Both make the run unobservable. The
``verify`` subcommand re-runs the structural check on a copied chain later
(hash linkage and the visible comparison, reported with ``hmac_checked``
false; the HMAC needs the key, which was never stored).
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import select
import shutil
import signal
import sys
import tempfile
from pathlib import Path
from typing import Any


ZERO_HASH = "0" * 64
_finish_requested = False


def chained_record(sequence: int, raw: str, previous: str, key: bytes) -> tuple[str, str]:
    material = f"{sequence}\t{previous}\t{raw}".encode()
    signature = hmac.new(key, material, hashlib.sha256).hexdigest()
    chain_hash = hashlib.sha256(material + b"\t" + signature.encode()).hexdigest()
    return f"{sequence}\t{previous}\t{chain_hash}\t{signature}\t{raw}\n", chain_hash


def _clean(line: bytes) -> str:
    return line.decode("utf-8", "replace").replace("\r", " ")


def _request_finish(*_: object) -> None:
    global _finish_requested
    _finish_requested = True


def mirror(read_fd: int, visible: Path, private: Path, key: bytes) -> int:
    """Copy raw lines from read_fd to the visible log and chained records to private."""
    previous = ZERO_HASH
    count = 0
    buffer = b""
    with visible.open("ab") as visible_out, private.open("xb") as mirror_out:
        def record(line: bytes) -> None:
            nonlocal previous, count
            count += 1
            raw = _clean(line)
            chained, previous = chained_record(count, raw, previous, key)
            visible_out.write(raw.encode() + b"\n")
            visible_out.flush()
            os.fsync(visible_out.fileno())
            mirror_out.write(chained.encode())
            mirror_out.flush()
            os.fsync(mirror_out.fileno())

        while True:
            ready, _, _ = select.select([read_fd], [], [], 0.2)
            if ready:
                chunk = os.read(read_fd, 65536)
                if not chunk:
                    break
                buffer += chunk
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    record(line)
            elif _finish_requested:
                break
        if buffer:
            record(buffer)
    return count


def verify(mirror_path: Path, visible_path: Path, key: bytes | None) -> dict[str, Any]:
    errors: list[str] = []
    raws: list[str] = []
    if not mirror_path.is_file():
        errors.append("mirror file missing")
    else:
        previous = ZERO_HASH
        for expected, line in enumerate(mirror_path.read_bytes().split(b"\n"), 1):
            if not line:  # trailing newline, or a run that logged nothing
                continue
            parts = _clean(line).split("\t", 4)
            if len(parts) != 5:
                errors.append(f"line {expected}: expected 5 fields")
                continue
            sequence_s, recorded_previous, chain_hash, signature, raw = parts
            try:
                sequence = int(sequence_s)
            except ValueError:
                errors.append(f"line {expected}: invalid sequence")
                continue
            if sequence != expected:
                errors.append(f"line {expected}: sequence {sequence}")
            if recorded_previous != previous:
                errors.append(f"line {expected}: previous hash mismatch")
            material = f"{sequence}\t{recorded_previous}\t{raw}".encode()
            if key is not None:
                expected_signature = hmac.new(key, material, hashlib.sha256).hexdigest()
                if not hmac.compare_digest(signature, expected_signature):
                    errors.append(f"line {expected}: HMAC mismatch")
            # The chain hash covers the material and the recorded signature, so an
            # edited record is caught even without the key; only the signature's
            # authenticity needs it.
            if chain_hash != hashlib.sha256(material + b"\t" + signature.encode()).hexdigest():
                errors.append(f"line {expected}: chain hash mismatch")
            previous = chain_hash
            raws.append(raw)
    visible: list[str] = []
    if visible_path.is_file():
        visible = [_clean(line) for line in visible_path.read_bytes().split(b"\n")]
        if visible and visible[-1] == "":
            visible.pop()
    else:
        errors.append("visible log missing")
    common = min(len(raws), len(visible))
    modified = sum(1 for index in range(common) if raws[index] != visible[index])
    chain_valid = not errors
    matches = raws == visible
    return {
        "schema_version": "1.0",
        "valid": chain_valid and matches,
        "chain_valid": chain_valid,
        "hmac_checked": key is not None,
        "mirror_matches_visible": matches,
        "mirror_events": len(raws),
        "visible_lines": len(visible),
        "visible_extra": max(0, len(visible) - len(raws)),
        "visible_missing": max(0, len(raws) - len(visible)),
        "visible_modified": modified,
        "errors": errors,
    }


def _cmd_mirror(args: argparse.Namespace) -> int:
    signal.signal(signal.SIGUSR1, _request_finish)
    key = secrets.token_bytes(32)
    private_dir = Path(tempfile.mkdtemp(prefix="evidence-chain-"))
    private = private_dir / "events.mirror.tsv"
    try:
        mirror(args.read_fd, args.visible, private, key)
        report = verify(private, args.visible, key)
        shutil.copyfile(private, args.mirror)
    finally:
        shutil.rmtree(private_dir, ignore_errors=True)
    report["mirror_path"] = str(args.mirror)
    report["mirror_sha256"] = hashlib.sha256(args.mirror.read_bytes()).hexdigest()
    args.evidence.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return 0 if report["valid"] else 2


def _cmd_verify(args: argparse.Namespace) -> int:
    key: bytes | None = None
    text = sys.stdin.read().strip()
    if text:
        try:
            key = bytes.fromhex(json.loads(text)["key_hex"] if text.startswith("{") else text)
        except (ValueError, KeyError, json.JSONDecodeError):
            key = None
    report = verify(args.mirror, args.visible, key)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered)
    print(rendered, end="")
    return 0 if report["valid"] else 2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    mirror_parser = commands.add_parser("mirror", help="read raw lines from a pipe, write the visible log and the chain")
    mirror_parser.add_argument("--read-fd", type=int, default=0)
    mirror_parser.add_argument("--visible", type=Path, required=True)
    mirror_parser.add_argument("--mirror", type=Path, required=True, help="where the chain is copied when the run ends")
    mirror_parser.add_argument("--evidence", type=Path, required=True, help="verification verdict, written when the run ends")
    mirror_parser.set_defaults(func=_cmd_mirror)
    verify_parser = commands.add_parser("verify", help="re-check a copied chain against the visible log (hex key on stdin if known)")
    verify_parser.add_argument("--mirror", type=Path, required=True)
    verify_parser.add_argument("--visible", type=Path, required=True)
    verify_parser.add_argument("--output", type=Path)
    verify_parser.set_defaults(func=_cmd_verify)
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
