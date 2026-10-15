#!/usr/bin/env python3
"""Project a CVE-bench Inspect ``.eval`` log into ``modal_trials``-shaped trial
JSONs, one per sample (per epoch = per trial), so the existing
``cybergym_task_forest.py`` can plot a per-CVE forest via ``--results-dir``.

This is a *thin projection*, not a new ``.eval`` parser: the robust, tested
reader lives in ``CVE-bench/extract_eval_actions.py`` (``extract_eval``) and is
reused here unchanged. Keeping the ``.eval``/zstd decoding in one place is the
point -- do not duplicate it. Because ``.eval`` members may be Zstandard-coded
(ZIP method 93), run this under the CVE-bench venv for real logs::

    /home/proxi/.venvs/cvebench/bin/python eval_to_trials.py run.eval \
        --out-dir results/cve-bench-trials

Then plot::

    python3 cybergym_task_forest.py \
        --results-dir results/cve-bench-trials \
        --interval jeffreys \
        --title "CVE-bench per-task exploit success  (jeffreys 95% CI)" \
        --out results/cve-bench-trials/cvebench_task_forest.png

A single-epoch run is one Bernoulli draw per CVE -- every point sits at 0% or
100% with a full-width interval. That is the honest picture. Run the eval with
``--epochs N`` to get replicate samples -> replicate trials -> tighter CIs and a
real pass@k denominator; this adapter already keys replicates by (task, epoch).

The stage-funnel does NOT apply to CVE-bench (no S1-S4 oracle; a single
``check_exploit`` grader), so no stage fields are emitted.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Reuse the existing .eval reader rather than re-parsing. ``CVE-bench`` has a
# hyphen, so it is not importable as a package; load it by path, exactly as
# tests/test_cve_eval_actions.py does.
# ---------------------------------------------------------------------------
_EXTRACTOR_PATH = Path(__file__).resolve().parent / "CVE-bench" / "extract_eval_actions.py"


def _load_extractor():
    spec = importlib.util.spec_from_file_location("extract_eval_actions", _EXTRACTOR_PATH)
    if not spec or not spec.loader:  # pragma: no cover - import plumbing
        raise ImportError(f"cannot load extractor from {_EXTRACTOR_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_VARIANT_SUFFIX = re.compile(r"[-_](one_day|zero_day)$")
_FILENAME_UNSAFE = re.compile(r"[^0-9A-Za-z._-]+")

# Robust, defensive mapping of the raw ``check_exploit`` scorer value to a
# status. ``extract_eval`` normalizes scores via ``_score_value`` (returns the
# scalar, not the ``{"value": ...}`` wrapper), but we still code the mapping to
# tolerate the common string/bool/int shapes rather than ``== 1``.
_SUCCESS_TOKENS = {"c", "correct", "true", "success", "pass", "passed", "1"}


def task_from_sample_id(sample_id: Any) -> Optional[str]:
    """Strip Inspect's one/zero-day suffix from a CVE sample id.

    Both ``CVE-2024-36412_one_day`` and the hyphenated form found in real
    archived logs, ``CVE-2024-36412-one_day``, map to ``CVE-2024-36412``.

    Must come from the sample id (or ``run.task_args.challenges``), NOT
    ``run.task`` -- that is the Inspect task name ``"cvebench"``, identical for
    every CVE, and keying a forest on it collapses the whole suite into one row.
    """
    if not sample_id:
        return None
    return _VARIANT_SUFFIX.sub("", str(sample_id))


def status_from_check(value: Any) -> str:
    """Map a raw ``check_exploit`` value to ``"success"``/``"failed"``.

    Truthy/scored -> success; not scored -> failed. Treats ``1, True, "C",
    "CORRECT"`` as success and ``0, False, "I", "INCORRECT", None`` as fail.
    """
    if value is None:
        return "failed"
    if isinstance(value, bool):
        return "success" if value else "failed"
    if isinstance(value, (int, float)):
        return "success" if value else "failed"
    return "success" if str(value).strip().lower() in _SUCCESS_TOKENS else "failed"


def _invalid_reason(sample: dict[str, Any], run_status: Any) -> Optional[str]:
    """Why a sample is infrastructure-invalid, or None when it is valid.

    A broken-fixture / crashed-grader zero is not a model miss and must not be
    recorded as ``"failed"``. Gate on: the overall eval succeeded, the sample
    itself did not error, and the grader did not error. This is the general,
    benchmark-agnostic safeguard (it also covers file-based graders, which do
    not self-certify the way a db-backed grader's structured result does).
    """
    if run_status != "success":
        return f"run_status={run_status}"
    diagnostics = sample.get("diagnostics") or {}
    if diagnostics.get("sample_error") is not None:
        return "sample_error"
    if (diagnostics.get("grader_error_count") or 0) != 0:
        return "grader_error"
    return None


def _is_infra_valid(sample: dict[str, Any], run_status: Any) -> bool:
    """Only infra-valid samples belong in the pass@1 denominator."""
    return _invalid_reason(sample, run_status) is None


def _advance_iso(timestamp: str, seconds: int) -> str:
    """Return ``timestamp`` shifted forward by ``seconds``, preserving a ``Z``.

    Falls back to a deterministic suffix if the string is not ISO-8601, so
    disambiguation never silently drops an epoch.
    """
    has_z = timestamp.endswith("Z")
    core = timestamp[:-1] if has_z else timestamp
    try:
        shifted = datetime.fromisoformat(core) + timedelta(seconds=seconds)
    except ValueError:
        return f"{timestamp}+{seconds}s"
    out = shifted.isoformat()
    return out + "Z" if has_z else out


def _unique_started_at(
    task: str,
    started_at: str,
    completed_at: Optional[str],
    epoch: Any,
    used: set[tuple[str, str]],
    warnings: list[str],
) -> str:
    """Guarantee (task, started_at) uniqueness across emitted trials.

    ``load_trials`` dedups on exactly this pair and silently drops the later
    duplicate -- a dropped epoch would undercount n and bias the forest. Inspect
    normally stamps each epoch with a distinct ``started_at``; defend against a
    collision by falling back to ``completed_at``, then by advancing the
    timestamp by ``epoch`` seconds, warning either way.
    """
    if (task, started_at) not in used:
        return started_at

    if completed_at and (task, str(completed_at)) not in used:
        warnings.append(
            f"{task} epoch {epoch}: started_at {started_at!r} collides; "
            f"using completed_at {completed_at!r} to disambiguate"
        )
        return str(completed_at)

    step = epoch if isinstance(epoch, int) and epoch > 0 else 1
    candidate = _advance_iso(started_at, step)
    while (task, candidate) in used:
        candidate = _advance_iso(candidate, 1)
    warnings.append(
        f"{task} epoch {epoch}: started_at {started_at!r} collides; "
        f"advanced to {candidate!r} to disambiguate"
    )
    return candidate


def _sanitize(value: str) -> str:
    return _FILENAME_UNSAFE.sub("_", value).strip("_") or "x"


def eval_to_trials(
    report: dict[str, Any],
    *,
    benchmark: str,
    used: set[tuple[str, str]],
    warnings: list[str],
    include_invalid: bool = False,
) -> tuple[list[dict[str, Any]], int]:
    """Project one ``extract_eval`` report to trial dicts + an excluded count.

    With ``include_invalid``, an infrastructure-invalid sample is still counted
    in ``excluded`` but is also emitted as a ``status: "error"`` record (with an
    ``invalid_reason``), which the forest keeps out of the per-task denominator
    and shows in its ``--show-validity`` panel instead of dropping silently.
    """
    run = report.get("run") or {}
    run_status = run.get("status")
    task_args = run.get("task_args") if isinstance(run.get("task_args"), dict) else {}
    challenges = task_args.get("challenges")

    trials: list[dict[str, Any]] = []
    excluded = 0
    for sample in report.get("samples") or []:
        task = task_from_sample_id(sample.get("sample_id"))
        started_at = sample.get("started_at")
        if not task or not started_at:
            excluded += 1
            continue
        invalid_reason = _invalid_reason(sample, run_status)
        if invalid_reason is not None:
            excluded += 1
            if not include_invalid:
                continue

        # Cross-check the stripped id against a single-challenge task_arg.
        if isinstance(challenges, str) and challenges and challenges != task:
            warnings.append(
                f"{task}: sample-derived task != run.task_args.challenges "
                f"{challenges!r}; keeping sample-derived id"
            )

        scores = sample.get("scores") or {}
        check_value = scores.get("check_exploit") if isinstance(scores, dict) else None
        status = "error" if invalid_reason else status_from_check(check_value)

        started_at = _unique_started_at(
            task,
            str(started_at),
            sample.get("completed_at"),
            sample.get("epoch"),
            used,
            warnings,
        )
        used.add((task, started_at))

        trial = {
            "task": task,
            "started_at": started_at,
            "status": status,
            # Provenance the forest ignores but that keeps a trial auditable.
            "benchmark": benchmark,
            "epoch": sample.get("epoch"),
            "source_eval": report.get("source"),
            "check_exploit_value": check_value,
        }
        if invalid_reason:
            trial["invalid_reason"] = invalid_reason
        trials.append(trial)
    return trials, excluded


def _write_trials(trials: list[dict[str, Any]], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for trial in trials:
        name = (
            f"{_sanitize(trial['task'])}"
            f"__e{trial.get('epoch')}"
            f"__{_sanitize(trial['started_at'])}.json"
        )
        path = out_dir / name
        content = json.dumps(trial, indent=2, default=str) + "\n"
        if path.exists():
            if path.read_text(encoding="utf-8") == content:
                continue
            raise FileExistsError(f"refusing to overwrite existing trial: {path}")
        with path.open("x", encoding="utf-8") as handle:
            handle.write(content)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("inputs", nargs="+",
                        help=".eval file(s), or directories containing them")
    parser.add_argument("--out-dir", type=Path, default=Path("results/cve-bench-trials"),
                        help="directory for the emitted trial JSONs "
                             "(default results/cve-bench-trials)")
    parser.add_argument("--benchmark", default="cve-bench",
                        help="provenance tag written to each trial (default cve-bench)")
    parser.add_argument("--include-invalid", action="store_true",
                        help="also emit infrastructure-invalid samples as status "
                             "'error' records (with invalid_reason) so the forest's "
                             "--show-validity panel can count them; they never "
                             "enter the success denominator")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = _parser().parse_args(argv)
    extractor = _load_extractor()

    paths = extractor._expand_inputs(args.inputs)
    if not paths:
        print("error: no .eval files found", file=sys.stderr)
        return 2
    missing = [str(p) for p in paths if not p.is_file()]
    if missing:
        print(f"error: file not found: {', '.join(missing)}", file=sys.stderr)
        return 2

    used: set[tuple[str, str]] = set()
    warnings: list[str] = []
    all_trials: list[dict[str, Any]] = []
    total_excluded = 0
    try:
        for path in paths:
            report = extractor.extract_eval(path)
            trials, excluded = eval_to_trials(
                report, benchmark=args.benchmark, used=used, warnings=warnings,
                include_invalid=args.include_invalid,
            )
            all_trials.extend(trials)
            total_excluded += excluded
    except (extractor.EvalReadError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    try:
        _write_trials(all_trials, args.out_dir)
    except (OSError, UnicodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)
    cves = len({t["task"] for t in all_trials})
    invalid_note = (" (written as status 'error')" if args.include_invalid
                    else "")
    print(f"wrote {len(all_trials)} trials ({cves} CVEs) to {args.out_dir}, "
          f"excluded {total_excluded} invalid{invalid_note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
