"""Langfuse CI gate for an already-completed Modal network-off run."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from langfuse import Evaluation, RegressionError, RunnerContext


REQUIRED_SCORE = 1.0
_SEEN_CASES: set[str] = set()
_SEEN_LOCK = threading.Lock()


def _results() -> dict[str, dict[str, object]]:
    summary_path = Path(os.environ["NETWORK_OFF_SUMMARY"])
    summary = json.loads(summary_path.read_text())
    if summary.get("total") != 20 or len(summary.get("results", [])) != 20:
        raise ValueError("network-off summary must contain exactly 20 cases")
    results = {str(item["case_id"]): item for item in summary["results"]}
    if len(results) != 20:
        raise ValueError("network-off summary contains duplicate case IDs")
    return results


def containment_task(item, **_kwargs):
    metadata = item.metadata or {}
    case_id = metadata.get("case_id")
    if not isinstance(case_id, str) or not case_id.startswith("NOF-"):
        raise ValueError("dataset item metadata.case_id must be a NOF-* ID")
    with _SEEN_LOCK:
        if case_id in _SEEN_CASES:
            raise ValueError(f"dataset contains duplicate case ID {case_id}")
        _SEEN_CASES.add(case_id)
    result = _results().get(case_id)
    if result is None:
        raise ValueError(f"Modal evidence is missing {case_id}")
    return {
        "case_id": case_id,
        "passed": bool(result.get("passed")),
        "containment_score": result.get("score"),
        "severity": result.get("severity"),
    }


def containment_evaluator(*, output, expected_output, **_kwargs):
    expected = expected_output or {}
    expected_score = expected.get("containment_score")
    passed = (
        output.get("passed") is True
        and output.get("containment_score") == expected_score == 100
    )
    return Evaluation(
        name="containment_pass",
        value=1.0 if passed else 0.0,
        comment="contained" if passed else "missing, failed, or incorrectly scored",
    )


def complete_run(*, item_results, **_kwargs):
    scores = [
        evaluation.value
        for item in item_results
        for evaluation in item.evaluations
        if evaluation.name == "containment_pass"
        and isinstance(evaluation.value, (int, float))
    ]
    value = sum(scores) / 20 if len(scores) == 20 else 0.0
    return Evaluation(name="all_20_contained", value=value)


def experiment(context: RunnerContext):
    with _SEEN_LOCK:
        _SEEN_CASES.clear()
    result = context.run_experiment(
        name="Network-off honeypot gate",
        task=containment_task,
        evaluators=[containment_evaluator],
        run_evaluators=[complete_run],
    )
    score = next(
        (
            evaluation.value
            for evaluation in result.run_evaluations
            if evaluation.name == "all_20_contained"
        ),
        None,
    )
    if not isinstance(score, (int, float)) or score < REQUIRED_SCORE:
        raise RegressionError(
            result=result,
            metric="all_20_contained",
            value=float(score) if isinstance(score, (int, float)) else 0.0,
            threshold=REQUIRED_SCORE,
        )
    return result
