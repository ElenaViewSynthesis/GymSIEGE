#!/usr/bin/env python3
"""Build a deterministic CyberGym task-to-sanitizer index.

Only ``crash.log`` files are downloaded from the gated dataset. The raw logs
stay below ``results/cybergym_index/`` (gitignored); the two derived reference
files are safe to commit.
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Iterable
from urllib.request import urlopen


UPSTREAM_REV = "b46456c46838b2b090d7e6ded5bfdf1ff583dba7"
DATASET_REV = "3aee406e4e915e32527fea16de7f002630fa8c76"
DATASET_ID = "sunblaze-ucb/cybergym-e2e"
TASKS_URL = (
    "https://raw.githubusercontent.com/sunblaze-ucb/cybergym-e2e/"
    f"{UPSTREAM_REV}/scripts/tasks.txt"
)
EXPECTED_TASKS = 920

_SUMMARY_PATTERNS = (
    ("LSan", re.compile(r"LeakSanitizer:\s*(.+)", re.IGNORECASE)),
    ("MSan", re.compile(r"MemorySanitizer:\s*(.+)", re.IGNORECASE)),
    ("UBSan", re.compile(r"UndefinedBehaviorSanitizer:\s*(.+)", re.IGNORECASE)),
    ("ASan", re.compile(r"AddressSanitizer:\s*(.+)", re.IGNORECASE)),
)
_LEAK_FALLBACK = re.compile(
    r"(?:detected memory leaks|(?:Direct|Indirect)[ -]leak(?: of)? .+)", re.IGNORECASE
)
_DECLARED_SANITIZER = re.compile(
    r"(?:^|\s)(?:export\s+)?SANITIZER\s*=\s*['\"]?([^\s'\"]+)", re.IGNORECASE
)
_OSS_FUZZ_CRASH_TYPE = re.compile(
    r"(?:OSS-Fuzz\s+)?crash[-_ ]type\s*[:=]\s*(.+)", re.IGNORECASE
)


@dataclass(frozen=True)
class CrashMetadata:
    sanitizer: str
    crash_type: str
    evidence_line: str
    declared_sanitizer: str | None = None
    oss_fuzz_crash_type: str | None = None


def parse_crash_log(text: str | None) -> CrashMetadata:
    """Extract the fired sanitizer and its verbatim summary from a crash log."""
    if not text or not text.strip():
        return CrashMetadata("unknown", "unknown", "")

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    declared = None
    oss_fuzz_type = None
    for line in lines:
        if declared is None and (match := _DECLARED_SANITIZER.search(line)):
            declared = match.group(1).rstrip(";,)")
        if oss_fuzz_type is None and (match := _OSS_FUZZ_CRASH_TYPE.search(line)):
            oss_fuzz_type = match.group(1).strip()

    # LeakSanitizer is part of ASan and can coexist with AddressSanitizer text,
    # so leak evidence deliberately has precedence over every other detector.
    for line in lines:
        if (match := _SUMMARY_PATTERNS[0][1].search(line)):
            return CrashMetadata("LSan", match.group(1).strip(), line, declared, oss_fuzz_type)
        if _LEAK_FALLBACK.search(line):
            return CrashMetadata("LSan", line, line, declared, oss_fuzz_type)

    for sanitizer, pattern in _SUMMARY_PATTERNS[1:]:
        matches = [(line, match) for line in lines if (match := pattern.search(line))]
        if matches:
            # Prefer the sanitizer's concise SUMMARY over its earlier ERROR
            # line, which commonly embeds volatile addresses and registers.
            line, match = next(
                ((line, match) for line, match in matches if line.startswith("SUMMARY:")),
                matches[0],
            )
            return CrashMetadata(
                sanitizer, match.group(1).strip(), line, declared, oss_fuzz_type
            )

    return CrashMetadata(
        "unknown", oss_fuzz_type or "unknown", "", declared, oss_fuzz_type
    )


def parse_task_lines(text: str) -> list[str]:
    tasks = [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]
    malformed = [task for task in tasks if task.count("/") != 1]
    if malformed:
        raise ValueError(f"malformed task IDs: {malformed[:3]}")
    if len(tasks) != len(set(tasks)):
        raise ValueError("master task list contains duplicate task IDs")
    return tasks


def build_records(tasks: Iterable[str], raw_dir: Path) -> tuple[list[dict[str, str]], list[tuple[str, str]]]:
    records: list[dict[str, str]] = []
    leaks: list[tuple[str, str]] = []
    for task in sorted(tasks):
        project, task_id = task.split("/", 1)
        log_path = raw_dir / "projects" / project / task_id / "crash.log"
        metadata = parse_crash_log(
            log_path.read_text(encoding="utf-8", errors="replace") if log_path.is_file() else None
        )
        records.append(
            {
                "task": task,
                "project": project,
                "sanitizer": metadata.sanitizer,
                "crash_type": metadata.crash_type,
                "source_rev": UPSTREAM_REV,
            }
        )
        if metadata.sanitizer == "LSan":
            leaks.append((task, metadata.evidence_line))
    return records, leaks


def _download_inputs(raw_dir: Path) -> str:
    try:
        from huggingface_hub import snapshot_download
    except ImportError as exc:  # pragma: no cover - exercised by CLI users
        raise SystemExit("Install requirements.txt before downloading the dataset") from exc

    with urlopen(TASKS_URL) as response:  # noqa: S310 - immutable trusted URL
        tasks_text = response.read().decode("utf-8")
    snapshot_download(
        DATASET_ID,
        repo_type="dataset",
        revision=DATASET_REV,
        allow_patterns=["projects/*/*/crash.log"],
        local_dir=raw_dir,
    )
    return tasks_text


def _write_outputs(tasks_text: str, raw_dir: Path, reference_dir: Path) -> tuple[list[dict[str, str]], list[tuple[str, str]]]:
    tasks = parse_task_lines(tasks_text)
    if len(tasks) != EXPECTED_TASKS:
        raise ValueError(f"expected {EXPECTED_TASKS} tasks, found {len(tasks)}")

    reference_dir.mkdir(parents=True, exist_ok=True)
    master = reference_dir / "cybergym_tasks.master.txt"
    master.write_text(
        f"# source_rev: {UPSTREAM_REV}\n" + tasks_text.rstrip("\n") + "\n",
        encoding="utf-8",
    )
    records, leaks = build_records(tasks, raw_dir)
    index = reference_dir / "cybergym_task_index.jsonl"
    index.write_text(
        "".join(json.dumps(record, separators=(",", ":")) + "\n" for record in records),
        encoding="utf-8",
    )
    return records, leaks


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-dir", type=Path, default=Path("results/cybergym_index"))
    parser.add_argument("--reference-dir", type=Path, default=Path("reference"))
    parser.add_argument(
        "--offline",
        action="store_true",
        help="reuse already-downloaded crash logs and the generated master list",
    )
    args = parser.parse_args()

    if args.offline:
        master = args.reference_dir / "cybergym_tasks.master.txt"
        tasks_text = "\n".join(
            line for line in master.read_text(encoding="utf-8").splitlines() if not line.startswith("#")
        )
    else:
        tasks_text = _download_inputs(args.raw_dir)
    records, leaks = _write_outputs(tasks_text, args.raw_dir, args.reference_dir)

    counts = Counter(record["sanitizer"] for record in records)
    print(f"source revision: {UPSTREAM_REV}")
    print(f"dataset revision: {DATASET_REV}")
    print(f"tasks: {len(records)}; counts: {dict(sorted(counts.items()))}")
    print(f"LeakSanitizer candidates: {len(leaks)}")
    for task, line in leaks:
        print(f"{task}: {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
