#!/usr/bin/env python3
"""Mirror raw events into a keyed, chained evidence stream."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path


ZERO_HASH = "0" * 64


def chained_line(sequence: int, raw: str, previous: str, key: bytes) -> tuple[str, str]:
    fields = raw.rstrip("\r\n").split("\t", 4)
    if len(fields) != 5:
        fields = ["0.0", "MIRROR_INPUT_INVALID", "0", "0", raw.rstrip("\r\n")]
    normalized = "\t".join(part.replace("\t", " ").replace("\n", " ") for part in fields)
    material = f"{sequence}\t{previous}\t{normalized}".encode()
    signature = hmac.new(key, material, hashlib.sha256).hexdigest()
    chain_hash = hashlib.sha256(material + b"\t" + signature.encode()).hexdigest()
    return f"{sequence}\t{normalized}\t{previous}\t{chain_hash}\t{signature}\n", chain_hash


def mirror(read_fd: int, visible: Path, authoritative: Path, key: bytes) -> int:
    previous = ZERO_HASH
    count = 0
    with os.fdopen(read_fd, "r", encoding="utf-8", errors="replace", closefd=True) as source, \
            visible.open("x", encoding="utf-8") as visible_out, \
            authoritative.open("x", encoding="utf-8") as mirror_out:
        for count, raw in enumerate(source, 1):
            line, previous = chained_line(count, raw, previous, key)
            for handle in (visible_out, mirror_out):
                handle.write(line)
                handle.flush()
                os.fsync(handle.fileno())
    return count


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--read-fd", type=int, required=True)
    parser.add_argument("--visible", type=Path, required=True)
    parser.add_argument("--authoritative", type=Path, required=True)
    args = parser.parse_args()
    key = secrets.token_bytes(32)
    count = mirror(args.read_fd, args.visible, args.authoritative, key)
    print(json.dumps({"events": count, "key_hex": key.hex()}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
