#!/usr/bin/env python3
"""Detect provider credentials in copied Modal run artifacts."""

from __future__ import annotations

import re
import tarfile
from collections.abc import Iterable
from pathlib import Path
from typing import BinaryIO


# Split the conventional prefix so repository diffs never contain a key-shaped literal.
LITELLM_KEY_PATTERN = re.compile(rb"(?<![A-Za-z0-9])s" + rb"k-[A-Za-z0-9_-]{8,}")


def _contains_secret(stream: BinaryIO, exact: bytes) -> bool:
    overlap = max(len(exact), 128)
    tail = b""
    while chunk := stream.read(1024 * 1024):
        data = tail + chunk
        if exact in data or LITELLM_KEY_PATTERN.search(data):
            return True
        tail = data[-overlap:]
    return False


def _file_contains_secret(path: Path, exact: bytes) -> bool:
    try:
        if tarfile.is_tarfile(path):
            with tarfile.open(path, "r:*") as archive:
                for member in archive.getmembers():
                    if not member.isfile():
                        continue
                    stream = archive.extractfile(member)
                    if stream is not None and _contains_secret(stream, exact):
                        return True
            return False
        with path.open("rb") as stream:
            return _contains_secret(stream, exact)
    except (OSError, tarfile.TarError):
        # An unreadable artifact cannot establish absence of a credential.
        return True


def scan_for_secret(paths: Iterable[Path], secret: str) -> list[Path]:
    """Return files containing the exact secret or any LiteLLM-shaped key."""
    if not secret:
        raise ValueError("secret must not be empty")
    exact = secret.encode()
    candidates: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            candidates.extend(
                child for child in sorted(path.rglob("*"))
                if child.is_file() and not child.is_symlink()
            )
        elif path.is_file() and not path.is_symlink():
            candidates.append(path)
    findings: list[Path] = []
    seen: set[Path] = set()
    for path in candidates:
        canonical = path.resolve()
        if canonical in seen:
            continue
        seen.add(canonical)
        if _file_contains_secret(path, exact):
            findings.append(path)
    return findings
