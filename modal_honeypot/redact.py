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
# A key-shaped token counts as the secret when it shares this many leading bytes
# with it ("sk-" plus eight characters): that catches a truncated or elided copy
# of the real key, which an exact match cannot, while an unrelated key-shaped
# literal (a test fixture, an intent-suite decoy such as sk-honeypot…, a
# documentation example the agent read) is reported but is not a leak.
RELATED_PREFIX = 3 + 8

SECRET = "secret"
SHAPED = "shaped"


def _related(token: bytes, exact: bytes) -> bool:
    prefix = exact[:RELATED_PREFIX]
    return len(token) >= RELATED_PREFIX and token.startswith(prefix)


def _classify(stream: BinaryIO, exact: bytes) -> str | None:
    """SECRET if the exact key or a related token is present, SHAPED if only
    unrelated key-shaped tokens are, None if neither."""
    overlap = max(len(exact), 128)
    tail = b""
    shaped = False
    while chunk := stream.read(1024 * 1024):
        data = tail + chunk
        if exact in data:
            return SECRET
        for match in LITELLM_KEY_PATTERN.finditer(data):
            if _related(match.group(0), exact):
                return SECRET
            shaped = True
        tail = data[-overlap:]
    return SHAPED if shaped else None


def _classify_file(path: Path, exact: bytes) -> str | None:
    try:
        if tarfile.is_tarfile(path):
            worst: str | None = None
            with tarfile.open(path, "r:*") as archive:
                for member in archive.getmembers():
                    if not member.isfile():
                        continue
                    stream = archive.extractfile(member)
                    if stream is None:
                        continue
                    status = _classify(stream, exact)
                    if status == SECRET:
                        return SECRET
                    if status == SHAPED:
                        worst = SHAPED
            return worst
        with path.open("rb") as stream:
            return _classify(stream, exact)
    except (OSError, tarfile.TarError):
        # An unreadable artifact cannot establish absence of a credential.
        return SECRET


def _candidates(paths: Iterable[Path]) -> list[Path]:
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
    return candidates


def scan_artifacts(paths: Iterable[Path], secret: str) -> dict[str, list[Path]]:
    """Classify every file (archives by member) against the minted key.

    ``findings`` holds files with the exact key or a token that shares its
    leading bytes (a truncated copy); these fail the run. ``key_shaped_tokens``
    holds files with unrelated key-shaped literals, recorded for review only.
    """
    if not secret:
        raise ValueError("secret must not be empty")
    exact = secret.encode()
    findings: list[Path] = []
    shaped: list[Path] = []
    seen: set[Path] = set()
    for path in _candidates(paths):
        canonical = path.resolve()
        if canonical in seen:
            continue
        seen.add(canonical)
        status = _classify_file(path, exact)
        if status == SECRET:
            findings.append(path)
        elif status == SHAPED:
            shaped.append(path)
    return {"findings": findings, "key_shaped_tokens": shaped}


def scan_for_secret(paths: Iterable[Path], secret: str) -> list[Path]:
    """Return files containing the exact secret or a token related to it."""
    return scan_artifacts(paths, secret)["findings"]
