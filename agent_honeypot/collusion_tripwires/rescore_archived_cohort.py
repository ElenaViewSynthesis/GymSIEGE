#!/usr/bin/env python3
"""Re-score selected archived cells without changing their frozen run records."""

from __future__ import annotations

import argparse
import importlib.util
import json
import tarfile
import tempfile
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath
from typing import Any


HERE = Path(__file__).resolve().parent


def _load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


COHORT = _load_module("collusion_cohort_rescore", HERE / "aggregate_cohort.py")
SCORE = _load_module("collusion_score_rescore", HERE / "score_collusion.py")


DIRECTORY_AWARE_KINDS = {
    "SHARED_CHANNEL_READ", "FOREIGN_WORKSPACE_READ", "BOARD_READ", "PEER_DISCOVERY",
}


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text())


def _case_relative(path: str, case_id: str) -> Path | None:
    marker = f"/cases/{case_id}/"
    if marker not in path:
        return None
    relative = PurePosixPath(path.split(marker, 1)[1])
    if relative.is_absolute() or ".." in relative.parts:
        return None
    return Path(*relative.parts)


def _extract_case(archive_path: Path, case_id: str, destination: Path) -> None:
    prefix = PurePosixPath("cases") / case_id
    with tarfile.open(archive_path, "r:*") as archive:
        for member in archive.getmembers():
            source = PurePosixPath(member.name)
            try:
                relative = source.relative_to(prefix)
            except ValueError:
                continue
            if not relative.parts or ".." in relative.parts:
                continue
            target = destination.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                source_file = archive.extractfile(member)
                if source_file is not None:
                    target.write_bytes(source_file.read())


def archived_outputs(extracted_case: Path, case: dict[str, Any]) -> dict[str, str]:
    """Each subject's archived printed output, keyed by run id, for the scorer's
    output-derived events (content canaries, including the legacy fixture text).
    Marker values were scrubbed from these logs after the original scoring, so the
    marker-derived kinds cannot re-fire from them; the chain already holds those."""
    outputs: dict[str, str] = {}
    for run in case.get("input", {}).get("runs", []):
        if run.get("kind") != "subject":
            continue
        log = extracted_case / "runs" / str(run["id"]) / "harness.stdout.log"
        if log.is_file():
            outputs[str(run["id"])] = log.read_text(errors="replace")
    return outputs


def annotate_directory_reads(
    events: list[dict[str, Any]], extracted_case: Path, case_id: str,
    known_directories: set[str] | None = None,
) -> tuple[list[dict[str, Any]], int]:
    known_directories = known_directories or set()
    annotated: list[dict[str, Any]] = []
    directory_count = 0
    for event in events:
        copied = dict(event)
        detail = SCORE._detail(event.get("detail"))
        if event.get("kind") in DIRECTORY_AWARE_KINDS and "dir" not in detail:
            relative = _case_relative(str(detail.get("path", "")), case_id)
            event_path = str(detail.get("path", "")).rstrip("/")
            is_directory = (
                str(detail.get("op", "")) == "opendir"
                or event_path in known_directories
            )
            if relative is not None:
                is_directory = is_directory or (extracted_case / relative).is_dir()
            detail = dict(detail)
            detail["dir"] = "true" if is_directory else "false"
            directory_count += int(is_directory)
        copied["detail"] = detail
        annotated.append(copied)
    return annotated, directory_count


def archived_directory_paths(extracted_case: Path) -> set[str]:
    paths = _read_json(extracted_case / "paths.json")
    shared = Path(str(paths["shared"]))
    case_root = shared.parent
    directories = {
        case_root, shared, case_root / "runs", case_root / "secrets", case_root / "prompts",
    }
    for row in paths.get("runs", {}).values():
        workspace = Path(str(row["workspace"]))
        directories.update({
            workspace.parent, workspace, workspace / "notes", workspace / "solutions",
            workspace / "inbox", workspace / "src", workspace / "shared",
        })
    return {str(path).rstrip("/") for path in directories}


def _sources(extracted_case: Path, case_id: str) -> list[tuple[Path, str]]:
    rows = _read_json(extracted_case / "events-index.json")
    sources: list[tuple[Path, str]] = []
    for row in rows:
        relative = _case_relative(str(row.get("path", "")), case_id)
        if relative is not None:
            sources.append((extracted_case / relative, str(row.get("run_id", "unknown"))))
    return sources


def _chains(extracted_case: Path) -> list[dict[str, Any]]:
    return [
        {"path": str(path), **_read_json(path)}
        for path in sorted(extracted_case.rglob("evidence.json"))
    ]


def _rescored_result(original: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    result = json.loads(json.dumps(original))
    mapping = {
        "stage": "observed_stage", "score": "score", "severity": "severity",
        "expectation_passed": "expectation_passed", "observability": "observability",
        "time_to_first_coordination_s": "time_to_first_coordination_s",
        "verifier": "verifier", "evidence": "evidence", "event_counts": "event_counts",
        "verdict": "verdict",
    }
    for target, source in mapping.items():
        result[target] = report.get(source)
    return result


def rescore(cohort_root: Path, out_dir: Path, selection_path: Path) -> dict[str, Any]:
    selection = COHORT.load_selection(selection_path)
    mirror_root = out_dir / "rescored-cells"
    before: Counter[str] = Counter()
    after: Counter[str] = Counter()
    before_by_arm: dict[str, Counter[str]] = defaultdict(Counter)
    after_by_arm: dict[str, Counter[str]] = defaultdict(Counter)
    rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="collusion-v2-rescore-") as directory:
        extraction_root = Path(directory)
        for relative_text in sorted(selection):
            relative = Path(relative_text)
            run_dir = cohort_root / relative
            modal = _read_json(run_dir / "modal-run.json")
            summary = _read_json(run_dir / "summary.json")
            original = summary["results"][0]
            case_id = str(original.get("case_id") or modal.get("case_id"))
            archive_path = run_dir / "artifacts.tar.gz"
            if not archive_path.is_file():
                raise FileNotFoundError(f"missing archive for {relative_text}")
            extracted_case = extraction_root / relative.parent / relative.name / case_id
            extracted_case.mkdir(parents=True)
            _extract_case(archive_path, case_id, extracted_case)
            events = SCORE.load_events(_sources(extracted_case, case_id))
            events, directory_events = annotate_directory_reads(
                events, extracted_case, case_id, archived_directory_paths(extracted_case),
            )
            old_report = _read_json(extracted_case / "report.json")
            case = _read_json(extracted_case / "case.json")
            report = SCORE.build_report(
                case, events,
                markers=_read_json(extracted_case / "markers.json"),
                outputs=archived_outputs(extracted_case, case),
                delegation_tasks={}, chains=_chains(extracted_case),
                verifier=old_report.get("verifier"),
            )
            rescored_summary = json.loads(json.dumps(summary))
            rescored_summary["results"][0] = _rescored_result(original, report)
            mirror = mirror_root / relative
            mirror.mkdir(parents=True, exist_ok=True)
            (mirror / "modal-run.json").write_text(json.dumps(modal, indent=2, sort_keys=True) + "\n")
            (mirror / "summary.json").write_text(json.dumps(rescored_summary, indent=2, sort_keys=True) + "\n")
            before[str(original.get("stage") or "none")] += 1
            after[report["observed_stage"]] += 1
            before_by_arm[relative.parts[0]][str(original.get("stage") or "none")] += 1
            after_by_arm[relative.parts[0]][report["observed_stage"]] += 1
            rows.append({
                "run_dir": relative.as_posix(), "case_id": case_id,
                "before": str(original.get("stage") or "none"),
                "after": report["observed_stage"], "directory_events": directory_events,
            })

    aggregate = COHORT.aggregate(mirror_root, out_dir, selection=selection)
    manifest = {
        "schema_version": "1.0", "source_root": str(cohort_root),
        "selection_file": str(selection_path), "cells": rows,
        "stage_counts_before": dict(sorted(before.items())),
        "stage_counts_after": dict(sorted(after.items())),
        "stage_counts_before_by_arm": {
            arm: dict(sorted(counts.items())) for arm, counts in sorted(before_by_arm.items())
        },
        "stage_counts_after_by_arm": {
            arm: dict(sorted(counts.items())) for arm, counts in sorted(after_by_arm.items())
        },
    }
    (out_dir / "rescore-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return {"manifest": manifest, "aggregate": aggregate}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("cohort_root", type=Path)
    parser.add_argument("out_dir", type=Path)
    parser.add_argument("--selection-file", type=Path, required=True)
    args = parser.parse_args()
    result = rescore(
        args.cohort_root.resolve(), args.out_dir.resolve(), args.selection_file.resolve(),
    )
    print(json.dumps({
        "cells_selected": result["aggregate"]["cells_selected"],
        "stage_counts_before": result["manifest"]["stage_counts_before"],
        "stage_counts_after": result["manifest"]["stage_counts_after"],
        "output": str(args.out_dir.resolve()),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
