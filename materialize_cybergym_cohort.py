#!/usr/bin/env python3
"""Materialize a clean, manifest-declared CyberGym analysis directory."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

import run_modal_repeats as repeats


ROOT = Path(__file__).resolve().parent


def _write_if_absent_or_identical(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() == content:
            return
        raise FileExistsError(f"refusing to overwrite different cohort artifact: {path}")
    with path.open("xb") as handle:
        handle.write(content)


def materialize(
    manifest_path: Path, input_dir: Path, *, root: Path = ROOT
) -> list[dict[str, Any]]:
    manifest = repeats.load_manifest(manifest_path)
    repeats.validate_frozen_inputs(manifest, root)
    entries = [
        {**entry, "trial": manifest["baseline_trial"]}
        for entry in manifest["baseline_results"]
    ] + list(manifest["completed_repeats"])

    rows: list[dict[str, Any]] = []
    for entry in entries:
        source = root / entry["result"]
        payload = json.loads(source.read_text(encoding="utf-8"))
        rows.append(payload)
        destination = input_dir / (
            f"{entry['task'].replace('/', '_')}__trial-{entry['trial']}.json"
        )
        _write_if_absent_or_identical(destination, source.read_bytes())

    rows.sort(key=lambda row: (str(row.get("task")), int(row.get("trial") or 0)))
    out_dir = input_dir.parent
    _write_if_absent_or_identical(
        out_dir / "cohort.json",
        (json.dumps(rows, indent=2, default=str) + "\n").encode(),
    )
    columns = [
        "task", "trial", "status", "started_at", "finished_at",
        "stage1", "stage2", "stage3", "stage4",
        "isolated_stage3", "isolated_stage4", "solver_cost_usd",
    ]
    from io import StringIO
    buffer = StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    _write_if_absent_or_identical(
        out_dir / "cohort.csv", buffer.getvalue().encode()
    )
    _write_if_absent_or_identical(
        out_dir / "cohort-manifest.json", manifest_path.read_bytes()
    )
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest", type=Path, default=repeats.DEFAULT_MANIFEST,
    )
    parser.add_argument("--input-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        rows = materialize(
            args.manifest.expanduser().resolve(),
            args.input_dir.expanduser().resolve(),
        )
    except (repeats.ManifestError, OSError, ValueError) as exc:
        print(f"error: {exc}")
        return 1
    print(
        f"materialized {len(rows)} trials across "
        f"{len({row['task'] for row in rows})} tasks in {args.input_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
