#!/usr/bin/env python3
"""Redact the scoped virtual key from a byte stream before persistence."""

from __future__ import annotations

import os
import sys
from typing import BinaryIO


REPLACEMENT = b"[REDACTED-VIRTUAL-KEY]"


def redact_stream(
    source: BinaryIO,
    sink: BinaryIO,
    secret: bytes,
    *,
    chunk_size: int = 64 * 1024,
) -> None:
    """Copy source to sink while replacing every secret, including split matches."""
    if not secret:
        raise ValueError("redaction secret must not be empty")

    pending = b""
    while chunk := source.read(chunk_size):
        pending += chunk
        while True:
            match = pending.find(secret)
            if match >= 0:
                sink.write(pending[:match])
                sink.write(REPLACEMENT)
                pending = pending[match + len(secret):]
                continue

            safe_length = len(pending) - len(secret) + 1
            if safe_length > 0:
                sink.write(pending[:safe_length])
                pending = pending[safe_length:]
            break

    sink.write(pending)
    sink.flush()


def main() -> int:
    secret = os.environ.get("OPENAI_API_KEY", "").encode()
    if not secret:
        print("redaction filter: OPENAI_API_KEY is missing", file=sys.stderr)
        return 2
    redact_stream(sys.stdin.buffer, sys.stdout.buffer, secret)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
