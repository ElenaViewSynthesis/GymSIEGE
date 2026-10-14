from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "CVE-bench" / "plot_top10_results.py"
SPEC = importlib.util.spec_from_file_location("plot_top10_results", SCRIPT)
assert SPEC and SPEC.loader
plotter = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = plotter
SPEC.loader.exec_module(plotter)


def test_loads_repository_manifest():
    tasks = plotter.load_manifest(
        ROOT / "CVE-bench" / "top10-2024-cvss-9_7plus.yml"
    )
    assert len(tasks) == 10
    assert tasks[0] == plotter.ManifestTask(1, "CVE-2024-36412", 10.0)
    assert tasks[-1].rank == 10


def test_summarizes_scored_invalid_unrun_and_off_cohort():
    tasks = [
        plotter.ManifestTask(1, "CVE-A", 10.0),
        plotter.ManifestTask(2, "CVE-B", 9.9),
    ]
    reports = [
        {
            "run": {"status": "success", "task_args": {}},
            "samples": [
                {
                    "sample_id": "CVE-A-one_day",
                    "scores": {"check_exploit": 1},
                    "diagnostics": {"sample_error": None, "grader_error_count": 0},
                },
                {
                    "sample_id": "CVE-A-one_day",
                    "scores": {"check_exploit": 0},
                    "diagnostics": {"sample_error": None, "grader_error_count": 0},
                },
                {
                    "sample_id": "CVE-X-one_day",
                    "scores": {"check_exploit": 1},
                    "diagnostics": {"sample_error": None, "grader_error_count": 0},
                },
            ],
        },
        {
            "run": {"status": "error", "task_args": {}},
            "samples": [
                {
                    "sample_id": "CVE-A-one_day",
                    "scores": {},
                    "diagnostics": {
                        "sample_error": {"message": "sandbox failed"},
                        "grader_error_count": 0,
                    },
                }
            ],
        },
    ]

    counts, off_cohort = plotter.summarize(reports, tasks)

    assert counts["CVE-A"] == {
        "success": 1,
        "failure": 1,
        "infra_invalid": 1,
    }
    assert counts["CVE-B"] == {}
    assert off_cohort == 1


def test_missing_check_exploit_is_a_scored_failure_for_successful_run():
    sample = {
        "scores": {},
        "diagnostics": {"sample_error": None, "grader_error_count": 0},
    }
    assert plotter.classify_sample(sample, "success") == "failure"


def test_grader_error_is_infrastructure_invalid():
    sample = {
        "scores": {"check_exploit": 0},
        "diagnostics": {"sample_error": None, "grader_error_count": 1},
    }
    assert plotter.classify_sample(sample, "success") == "infra_invalid"
