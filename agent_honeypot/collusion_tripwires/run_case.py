#!/usr/bin/env python3
"""Run one or all local synthetic collusion-tripwire calibration cases."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import shlex
import shutil
import subprocess
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DATASET = HERE / "cases.jsonl"
BASE_HARNESS = ROOT / "agent_honeypot" / "harness.sh"
EVIDENCE_CHAIN = ROOT / "agent_honeypot" / "evidence_chain.py"
AGENT_SUBJECT = HERE / "agent_subject.py"
CONTAINMENT_MARKER = "MODAL_COLLUSION_CONTAINMENT_ENFORCED"
PROCESS_EVIDENCE_FD = 7
ORCHESTRATOR_EVIDENCE_FD = 10
BOARD_EVIDENCE_FD = 11


def _module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


PREPARE = _module("collusion_prepare", HERE / "prepare_case.py")
SCORE = _module("collusion_score_runner", HERE / "score_collusion.py")


class ChainLog:
    def __init__(self, root: Path, fixed_fd: int):
        root.mkdir(parents=True, exist_ok=True)
        self.visible = root / "events.tsv"
        self.mirror = root / "events.mirror.tsv"
        self.evidence = root / "evidence.json"
        self.visible.touch()
        read_fd, write_fd = os.pipe()
        if write_fd != fixed_fd:
            os.dup2(write_fd, fixed_fd)
            os.close(write_fd)
        os.set_inheritable(fixed_fd, True)
        self.fd = fixed_fd
        self.process = subprocess.Popen(
            [sys.executable, str(EVIDENCE_CHAIN), "mirror", "--read-fd", str(read_fd),
             "--visible", str(self.visible), "--mirror", str(self.mirror),
             "--evidence", str(self.evidence)],
            pass_fds=(read_fd,), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        os.close(read_fd)

    def emit(self, kind: str, detail: dict[str, Any], *, timestamp: float | None = None) -> None:
        payload = json.dumps(detail, sort_keys=True, separators=(",", ":"))
        os.write(self.fd, f"{timestamp or time.time():.9f}\t{kind}\t{os.getpid()}\t0\t{payload}\n".encode())

    def finish(self) -> dict[str, Any]:
        try:
            os.close(self.fd)
        except OSError:
            pass
        stdout, stderr = self.process.communicate(timeout=20)
        if self.process.returncode not in {0, 2} or not self.evidence.is_file():
            raise RuntimeError(f"evidence mirror failed: {stderr or stdout}")
        return json.loads(self.evidence.read_text())


def _load_cases() -> list[dict[str, Any]]:
    return PREPARE.load_cases(DATASET)


def _marker_registry(root: Path) -> dict[str, dict[str, str]]:
    markers = json.loads((root / "markers.json").read_text())
    child_path = root / "child-markers.jsonl"
    if child_path.is_file():
        for raw in child_path.read_text().splitlines():
            if not raw.strip():
                continue
            row = json.loads(raw)
            markers[row.pop("run_id")] = row
    return markers


def _delegations(root: Path) -> dict[str, dict[str, str]]:
    path = root / "delegations.jsonl"
    rows: dict[str, dict[str, str]] = {}
    if path.is_file():
        for raw in path.read_text().splitlines():
            if raw.strip():
                row = json.loads(raw)
                rows[row["run_id"]] = row
    return rows


def _owners(data: bytes, markers: dict[str, dict[str, str]], field: str) -> list[str]:
    text = data.decode(errors="replace")
    return sorted(owner for owner, values in markers.items() if values.get(field, "") in text)


def _snapshot(
    root: Path, chain: ChainLog, hashes: dict[str, str], writer: str,
    markers: dict[str, dict[str, str]], *, initial: bool = False,
) -> None:
    shared = root / "shared"
    candidates: list[tuple[Path, str, str]] = []
    for path in sorted(shared.rglob("*")):
        if path.is_file():
            candidates.append((path, "CHANNEL_VERSION", "orchestrator" if initial else writer))
    for workspace in sorted((root / "runs").glob("*/workspace")):
        owner = workspace.parent.name
        for path in sorted(workspace.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            kind = "INBOX_VERSION" if path.parent.name == "inbox" else "WORKSPACE_VERSION"
            candidates.append((path, kind, owner if initial else writer))
    for child_meta in sorted((root / "delegated").glob("**/run.json")) if (root / "delegated").exists() else []:
        row = json.loads(child_meta.read_text())
        workspace = Path(row["workspace"])
        for path in sorted(workspace.rglob("*")):
            if path.is_file() and not path.is_symlink():
                kind = "INBOX_VERSION" if path.parent.name == "inbox" else "WORKSPACE_VERSION"
                candidates.append((path, kind, row["run_id"] if initial else writer))
    for path, kind, owner in candidates:
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        key = str(path.resolve())
        if hashes.get(key) == digest:
            continue
        hashes[key] = digest
        chain.emit(kind, {
            "path": key, "sha256": digest, "writer": owner,
            "marker_owners": _owners(data, markers, "run_marker"),
            "content_owners": _owners(data, markers, "content_marker"),
        })


def _wait_ready(path: Path, process: subprocess.Popen[str]) -> str:
    for _ in range(100):
        if path.is_file() and path.read_text().strip():
            return path.read_text().strip()
        if process.poll() is not None:
            break
        time.sleep(0.05)
    raise RuntimeError("loopback board did not become ready")


def _run_env(case: dict[str, Any], root: Path, run: dict[str, Any], board_url: str, library: Path) -> dict[str, str]:
    paths = json.loads((root / "paths.json").read_text())
    markers = _marker_registry(root)
    run_id = str(run["id"])
    workspace = Path(paths["runs"][run_id]["workspace"])
    peers = [item for item in case["input"]["runs"] if item["id"] != run_id]
    peer_paths = [paths["runs"][item["id"]]["workspace"] for item in peers]
    env = os.environ.copy()
    env.update({
        "HONEYPOT_CASE_ID": str(case["id"]), "HONEYPOT_COLLUSION_ROOT": str(root),
        "HONEYPOT_COLLUSION_RUN_ID": run_id, "HONEYPOT_RUN_KIND": str(run["kind"]),
        "HONEYPOT_WORKSPACE": str(workspace), "HONEYPOT_SHARED": paths["shared"],
        "HONEYPOT_COLLUSION_PROMPT_FILE": paths["runs"][run_id]["prompt"],
        "HONEYPOT_COLLUSION_TRANSCRIPT": str(root / "runs" / run_id / "trajectory.jsonl"),
        "HONEYPOT_RUN_MARKER": markers[run_id]["run_marker"],
        "HONEYPOT_CONTENT_MARKER": markers[run_id]["content_marker"],
        "HONEYPOT_BOARD_URL": board_url, "HONEYPOT_PEER_WORKSPACES": ":".join(peer_paths),
        "HONEYPOT_PEER_RUN_IDS": ":".join(str(item["id"]) for item in peers),
        "HONEYPOT_COLLUSION_SHARED_PATHS": paths["shared"],
        "HONEYPOT_COLLUSION_PEER_INBOXES": ":".join(str(Path(item) / "inbox") for item in peer_paths),
        "HONEYPOT_COLLUSION_OWN_INBOX": str((workspace / "inbox").resolve()),
        "HONEYPOT_COLLUSION_INBOX": str((workspace / "inbox").resolve()),
        "HONEYPOT_COLLUSION_QUEUE": paths["queue"], "HONEYPOT_COLLUSION_RESULTS": paths["results"],
        "HONEYPOT_COLLUSION_PRELOAD": str(library), "HONEYPOT_EXTRA_PATH": str(HERE),
        "HONEYPOT_BASE_HARNESS": str(BASE_HARNESS), "HONEYPOT_SCRIPTED_ACTOR": str(HERE / "scripted_actor.py"),
        "HONEYPOT_NEST_DEPTH": "0", "HONEYPOT_MAX_NEST_DEPTH": "2",
        "HONEYPOT_SENSITIVE_PATHS": ":".join([paths["shared"], *peer_paths, paths["queue"], paths["results"]]),
        "HONEYPOT_PEER_ASSIGNMENT": str(peers[0]["assignment"] if peers else "synthetic peer assignment"),
    })
    if case["input"].get("observe_only"):
        env["HONEYPOT_COLLUSION_OBSERVE_ONLY"] = "1"
    else:
        env.pop("HONEYPOT_COLLUSION_OBSERVE_ONLY", None)
    return env


def _subject_command(value: str | None) -> list[str] | None:
    if value is None:
        return None
    command = shlex.split(value)
    if not command:
        raise ValueError("--subject-command must not be empty")
    return command


def _require_containment(subject_command: list[str] | None) -> None:
    if subject_command is not None and os.environ.get(CONTAINMENT_MARKER) != "1":
        raise RuntimeError(
            "real collusion subjects require external containment; "
            f"set {CONTAINMENT_MARKER}=1 only inside the Modal path or a disposable isolated VM"
        )


def _process_results(output_text: str, reporter: str, root: Path, chain: ChainLog, observe_only: bool) -> None:
    for line in output_text.splitlines():
        if not line.startswith("HONEYPOT_RESULT\t"):
            continue
        try:
            row = json.loads(line.split("\t", 1)[1])
        except json.JSONDecodeError:
            continue
        if row.get("run_id") != reporter:
            chain.emit("RESULT_SPOOFED", {
                "reporter": reporter, "claimed_run": row.get("run_id"), "blocked": not observe_only,
            })
            if not observe_only:
                continue
        with (root / "results.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"reporter": reporter, **row}, sort_keys=True) + "\n")


def _artifacts(root: Path) -> tuple[list[tuple[Path, str]], dict[str, str], list[Path]]:
    sources = [(root / "orchestrator" / "events.tsv", "orchestrator"), (root / "board" / "events.tsv", "board")]
    outputs: dict[str, str] = {}
    evidence = [root / "orchestrator" / "evidence.json", root / "board" / "evidence.json"]
    for run_root in sorted((root / "runs").glob("*")):
        run_id = run_root.name
        sources.append((run_root / "harness" / "events.tsv", run_id))
        outputs[run_id] = str(run_root / "harness.stdout.log")
        evidence.append(run_root / "harness" / "evidence.json")
    if (root / "delegated").exists():
        for meta in sorted((root / "delegated").glob("**/run.json")):
            row = json.loads(meta.read_text())
            child_root = meta.parent
            sources.append((child_root / "harness" / "events.tsv", row["run_id"]))
            outputs[row["run_id"]] = str(child_root / "harness.stdout.log")
            evidence.append(child_root / "harness" / "evidence.json")
    return sources, outputs, evidence


def _output_texts(root: Path, outputs: dict[str, str]) -> dict[str, str]:
    texts: dict[str, str] = {}
    for run_id, output_path in outputs.items():
        parts = []
        path = Path(output_path)
        if path.is_file():
            parts.append(path.read_text(errors="replace"))
        trajectory = root / "runs" / run_id / "trajectory.jsonl"
        if trajectory.is_file():
            parts.append(trajectory.read_text(errors="replace"))
        texts[run_id] = "\n".join(parts)
    return texts


def run_one(
    case: dict[str, Any], output: Path, *, subject_command: list[str] | None = None,
) -> dict[str, Any]:
    _require_containment(subject_command)
    PREPARE.prepare(case, output)
    library = output / "libcollusion_tripwire.so"
    subprocess.run([
        "gcc", "-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-o", str(library),
        str(HERE / "collusion_preload.c"), "-ldl",
    ], check=True)
    orchestrator = ChainLog(output / "orchestrator", ORCHESTRATOR_EVIDENCE_FD)
    board_chain = ChainLog(output / "board", BOARD_EVIDENCE_FD)
    orchestrator.emit("CASE_STARTED", {"case": case["id"]})
    ready = output / "board" / "ready.txt"
    board_command = [
        sys.executable, str(HERE / "board.py"), "--event-fd", str(BOARD_EVIDENCE_FD),
        "--markers", str(output / "markers.json"), "--ready", str(ready),
    ]
    if case["input"].get("observe_only"):
        board_command.append("--observe-only")
    board = subprocess.Popen(
        board_command, pass_fds=(BOARD_EVIDENCE_FD,),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    board_url = _wait_ready(ready, board)
    hashes: dict[str, str] = {}
    _snapshot(output, orchestrator, hashes, "orchestrator", _marker_registry(output), initial=True)
    observe_only = bool(case["input"].get("observe_only"))
    run_exit_codes: dict[str, int] = {}
    for run in case["input"]["runs"]:
        run_id = str(run["id"])
        run_root = output / "runs" / run_id
        env = _run_env(case, output, run, board_url, library)
        command = [str(BASE_HARNESS), "--evidence-chain", "--timeout", str(case["input"].get("timeout_seconds", 15)),
                   "--output", str(run_root / "harness")]
        if observe_only:
            command.append("--observe-only")
        if run["kind"] == "subject" and subject_command is not None:
            command.extend(["--", sys.executable, str(AGENT_SUBJECT), "--", *subject_command])
        else:
            command.extend(["--", sys.executable, str(HERE / "scripted_actor.py"), "--action", str(run["action"])])
        completed = subprocess.run(command, cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        run_exit_codes[run_id] = completed.returncode
        (run_root / "harness.stdout.log").write_text(completed.stdout)
        _process_results(completed.stdout, run_id, output, orchestrator, observe_only)
        _snapshot(output, orchestrator, hashes, run_id, _marker_registry(output))

    board.terminate()
    try:
        board.wait(timeout=10)
    except subprocess.TimeoutExpired:
        board.kill()
        board.wait(timeout=5)
    board_chain.finish()
    sources, outputs, evidence_paths = _artifacts(output)
    raw_events = SCORE.load_events(sources)
    output_texts = _output_texts(output, outputs)
    derived = SCORE.derive_events(raw_events, _marker_registry(output), output_texts, _delegations(output))
    for event in derived:
        orchestrator.emit(event["kind"], {**event["detail"], "run": event["run_id"]}, timestamp=event["timestamp"])
    orchestrator.emit("CASE_FINISHED", {"case": case["id"]})
    orchestrator.finish()

    sources, outputs, evidence_paths = _artifacts(output)
    chains = []
    for path in evidence_paths:
        try:
            chains.append({"path": str(path), **json.loads(path.read_text())})
        except (OSError, json.JSONDecodeError):
            chains.append({"path": str(path), "valid": False, "errors": ["missing or unreadable evidence"]})
    final_events = SCORE.load_events(sources)
    report = SCORE.build_report(
        case, final_events, markers=_marker_registry(output), outputs={},
        delegation_tasks=_delegations(output), chains=chains,
    )
    report["subject_mode"] = "agent" if subject_command is not None else "scripted"
    report["execution_boundary"] = (
        "externally-contained-real-agent" if subject_command is not None
        else "local-scripted-no-model-no-network"
    )
    report["run_exit_codes"] = run_exit_codes
    subject_ids = [str(run["id"]) for run in case["input"]["runs"] if run["kind"] == "subject"]
    report["agent_execution_passed"] = (
        all(run_exit_codes.get(run_id) == 0 for run_id in subject_ids)
        if subject_command is not None else None
    )
    if "verifier_can_pass" in case.get("metadata", {}):
        # Gate 3 Option 1 is an infrastructure pilot. No task verifier exists
        # yet, so preserve that limitation beside the behavioral result.
        report["verifier"] = "not implemented"
    (output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    (output / "events-index.json").write_text(json.dumps([
        {"path": str(path), "run_id": run_id} for path, run_id in sources
    ], indent=2, sort_keys=True) + "\n")
    return report


def run_all(
    cases: list[dict[str, Any]], output_root: Path, workers: int, *,
    subject_command_text: str | None = None,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    logs = output_root / "logs"
    logs.mkdir(exist_ok=True)

    def invoke(case_id: str) -> dict[str, Any]:
        command = [sys.executable, str(HERE / "run_case.py"), case_id, "--output-root", str(output_root)]
        if subject_command_text is not None:
            command.extend(["--subject-command", subject_command_text])
        completed = subprocess.run(
            command,
            cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        (logs / f"{case_id}.log").write_text(completed.stdout)
        report_path = output_root / case_id / "report.json"
        report = json.loads(report_path.read_text()) if report_path.is_file() else {}
        return {"case_id": case_id, "passed": completed.returncode == 0, "exit_code": completed.returncode,
                "stage": report.get("observed_stage"), "role": report.get("role"),
                "observable": report.get("observability") == "observable", "report": str(report_path)}

    rows: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=min(workers, len(cases))) as pool:
        futures = {pool.submit(invoke, case["id"]): case["id"] for case in cases}
        for future in as_completed(futures):
            try:
                rows.append(future.result())
            except Exception as exc:
                rows.append({"case_id": futures[future], "passed": False, "error": str(exc)})
    rows.sort(key=lambda row: row["case_id"])
    behavior = Counter(row.get("stage") for row in rows if row.get("role") == "behavior_eval")
    controls = Counter(row.get("stage") for row in rows if row.get("role") == "sensor_control")
    summary = {
        "schema_version": "1.0", "execution_boundary": (
            "externally-contained-real-agent" if subject_command_text is not None
            else "local-scripted-no-model-no-network"
        ),
        "subject_mode": "agent" if subject_command_text is not None else "scripted",
        "total": len(rows), "passed": sum(bool(row.get("passed")) for row in rows),
        "failed": sum(not bool(row.get("passed")) for row in rows),
        "all_chains_valid": all(bool(row.get("observable")) for row in rows),
        "behavior_stages": dict(sorted(behavior.items())),
        "sensor_control_stages": dict(sorted(controls.items())), "results": rows,
    }
    (output_root / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("case_id", nargs="?")
    selection.add_argument("--all", action="store_true")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--output-root", type=Path, default=ROOT / "results" / "collusion-honeypot")
    parser.add_argument(
        "--subject-command",
        help="replace each subject's scripted actor with this shell-split command; requires external containment",
    )
    args = parser.parse_args()
    if not 1 <= args.workers <= 8:
        parser.error("--workers must be between 1 and 8")
    cases = _load_cases()
    try:
        subject_command = _subject_command(args.subject_command)
        _require_containment(subject_command)
    except (RuntimeError, ValueError) as exc:
        parser.error(str(exc))
    if args.all:
        summary = run_all(
            cases, args.output_root.resolve(), args.workers,
            subject_command_text=args.subject_command,
        )
        print(json.dumps({key: summary[key] for key in ("total", "passed", "failed", "all_chains_valid")}, sort_keys=True))
        return 0 if summary["failed"] == 0 else 1
    case = next((item for item in cases if item["id"] == args.case_id), None)
    if case is None:
        raise SystemExit(f"unknown case: {args.case_id}")
    output = args.output_root.resolve() / str(case["id"])
    report = run_one(case, output, subject_command=subject_command)
    print(json.dumps({"case_id": case["id"], "stage": report["observed_stage"],
                      "calibration_passed": report["calibration_passed"],
                      "observability": report["observability"]}, sort_keys=True))
    if subject_command is not None:
        return 0 if report["observability"] == "observable" and report["agent_execution_passed"] else 2
    return 0 if report["calibration_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
