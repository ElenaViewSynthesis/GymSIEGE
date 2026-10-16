#!/usr/bin/env python3
"""Materialize a clean, manifest-declared CyberGym analysis directory."""
from __future__ import annotations

import argparse
import csv
import hashlib
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


def _load_exclusions(path: Path, root: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise repeats.ManifestError(f"missing frozen exclusion ledger: {path}")
    rows: list[dict[str, Any]] = []
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        try:
            row = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise repeats.ManifestError(
                f"malformed exclusion ledger row {path}:{line_number}: {exc}"
            ) from exc
        artifact = root / row.get("artifact", "")
        if not artifact.is_file():
            raise repeats.ManifestError(f"excluded attempt artifact is missing: {artifact}")
        if repeats.sha256_path(artifact) != row.get("sha256"):
            raise repeats.ManifestError(f"excluded attempt artifact hash mismatch: {artifact}")
        rows.append(row)
    return rows


def _schema_v2_entries(
    manifest_path: Path, manifest: dict[str, Any], root: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    cohort_hash = repeats.manifest_sha256(manifest_path)
    batch_dir = root / manifest["output_root"] / manifest["batch_id"]
    metadata = json.loads((batch_dir / "_meta" / "batch.json").read_text(encoding="utf-8"))
    if metadata.get("cohort_manifest_sha256") != cohort_hash:
        raise repeats.ManifestError("batch metadata manifest hash mismatch")
    exclusions = _load_exclusions(batch_dir / "_meta" / "excluded_trials.jsonl", root)

    expected = repeats.planned_cells(manifest)
    published_dir = batch_dir / "published-results"
    actual_names = {path.name for path in published_dir.glob("*.json")}
    expected_names = {
        repeats.final_path(batch_dir, task, trial).name for task, trial in expected
    }
    if actual_names != expected_names:
        missing = sorted(expected_names - actual_names)
        extra = sorted(actual_names - expected_names)
        raise repeats.ManifestError(
            f"published result set does not match frozen cells; missing={missing}, extra={extra}"
        )

    entries: list[dict[str, Any]] = []
    for task, trial in expected:
        source = repeats.final_path(batch_dir, task, trial)
        publication_path = batch_dir / "_meta" / "publications" / (
            f"{task.replace('/', '_')}__trial-{trial}.json"
        )
        publication = json.loads(publication_path.read_text(encoding="utf-8"))
        source_hash = repeats.sha256_path(source)
        if publication.get("task") != task or publication.get("trial") != trial:
            raise repeats.ManifestError(f"publication identity mismatch: {publication_path}")
        if publication.get("published_result_sha256") != source_hash:
            raise repeats.ManifestError(f"publication result hash mismatch: {source}")
        if publication.get("cohort_manifest_sha256") != cohort_hash:
            raise repeats.ManifestError(f"publication manifest hash mismatch: {publication_path}")
        payload = json.loads(source.read_text(encoding="utf-8"))
        repeats._validate_result_payload(payload, manifest, task, trial, cohort_hash)
        entries.append({
            "task": task,
            "trial": trial,
            "source": source,
            "sha256": source_hash,
            "payload": payload,
        })
    return entries, exclusions


def materialize(
    manifest_path: Path, input_dir: Path, *, root: Path = ROOT
) -> list[dict[str, Any]]:
    manifest = repeats.load_manifest(manifest_path)
    repeats.validate_frozen_inputs(manifest, root)
    if manifest["schema_version"] == 2:
        expected_input = root / manifest["paper_output_root"] / "inputs"
        if input_dir != expected_input:
            raise repeats.ManifestError(
                f"schema-v2 input directory must be the frozen path {expected_input}"
            )
        if input_dir.parent.exists():
            raise FileExistsError(
                f"refusing to rematerialize immutable paper directory: {input_dir.parent}"
            )
        v2_entries, exclusions = _schema_v2_entries(manifest_path, manifest, root)
        entries = [
            {
                "task": entry["task"], "trial": entry["trial"],
                "result": str(entry["source"].relative_to(root)),
                "sha256": entry["sha256"],
            }
            for entry in v2_entries
        ]
    else:
        exclusions = list(manifest.get("excluded_trials", []))
        entries = [
            {**entry, "trial": manifest["baseline_trial"]}
            for entry in manifest["baseline_results"]
        ] + list(manifest["completed_repeats"])

    rows: list[dict[str, Any]] = []
    for entry in entries:
        source = root / entry["result"]
        payload = json.loads(source.read_text(encoding="utf-8"))
        actual_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        if actual_hash != entry["sha256"]:
            raise repeats.ManifestError(f"source-result hash mismatch: {source}")
        if manifest["schema_version"] == 2:
            repeats._validate_result_payload(
                payload, manifest, entry["task"], entry["trial"],
                repeats.manifest_sha256(manifest_path),
            )
        elif payload.get("task") != entry["task"] or payload.get("trial") != entry["trial"]:
            raise repeats.ManifestError(f"source result identity mismatch: {source}")
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
        "task", "trial", "status", "benchmark", "mode", "provider",
        "provisioning", "agent", "model_provider", "litellm_model_id",
        "snapshot_manifest", "snapshot_manifest_sha256", "snapshot_image_id",
        "cohort_id", "cohort_manifest_sha256", "batch_id",
        "started_at", "finished_at",
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
    source_results = [
        {
            "task": entry["task"], "trial": entry["trial"],
            "path": entry["result"], "sha256": entry["sha256"],
        }
        for entry in entries
    ]
    provenance = {
        "cohort_id": manifest["cohort_id"],
        "cohort_manifest_sha256": repeats.manifest_sha256(manifest_path),
        "input_count": len(rows),
        "distinct_task_count": len({row["task"] for row in rows}),
        "excluded_attempt_count": len(exclusions),
        "excluded_attempts": exclusions,
        "source_results": source_results,
        "funnel_command": (
            f"python3 cybergym_stage_funnel.py --results-dir {input_dir.relative_to(root)} "
            f"--by task --out {Path(manifest.get('paper_output_root', str(out_dir.relative_to(root)))) / 'cybergym_stage_funnel_by_task.png'}"
        ),
    }
    if manifest["schema_version"] == 2:
        ledger = (
            root / manifest["output_root"] / manifest["batch_id"]
            / "_meta" / "excluded_trials.jsonl"
        )
        provenance["excluded_trials_ledger"] = str(ledger.relative_to(root))
        provenance["excluded_trials_ledger_sha256"] = repeats.sha256_path(ledger)
    _write_if_absent_or_identical(
        out_dir / "cohort-provenance.json",
        (json.dumps(provenance, indent=2) + "\n").encode(),
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
