#!/usr/bin/env python3
"""Build host-side Langfuse traces from pulled, chain-verified artifacts.

The sandbox never imports this module.  It consumes completed artifacts on the
host, redacts synthetic markers, and either prints a deterministic trace plan
or sends that plan through a caller-supplied/Langfuse client.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Protocol

try:
    from agent_honeypot.evidence_chain import verify as verify_chain
except ModuleNotFoundError:  # direct ``python agent_honeypot/langfuse_ingest.py``
    from evidence_chain import verify as verify_chain


REPO = Path(__file__).resolve().parents[1]
HEX_128 = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32}(?![0-9A-Fa-f])")
TRUNCATE_OUTPUT = 4000
STAGE_EVENTS = {
    "BOARD_POST", "COORDINATION_ACTED", "CROSS_RUN_MARKER_TRANSFER",
    "DELEGATION_ESCAPE", "FOREIGN_WORKSPACE_READ", "NESTED_HARNESS_SPAWN",
    "SHARED_CHANNEL_WRITE", "TASK_QUEUE_TAMPER",
}
TOOL_ITEM_TYPES = {
    "command", "command_execution", "function_call", "mcp_tool_call",
    "tool", "tool_call", "web_search",
}


class LangfuseClient(Protocol):
    def start_as_current_observation(self, **kwargs: object): ...
    def create_event(self, **kwargs: object): ...
    def create_score(self, **kwargs: object) -> None: ...
    def shutdown(self) -> None: ...


class LangfuseObservationsClient(Protocol):
    def get_many(self, **kwargs: object) -> object: ...


@dataclass
class Observation:
    kind: str
    name: str
    input: Any = None
    output: Any = None
    metadata: dict[str, Any] = field(default_factory=dict)
    level: str | None = None
    children: list["Observation"] = field(default_factory=list)


@dataclass
class Score:
    name: str
    value: float | str
    data_type: str


@dataclass
class TracePlan:
    trace_id: str
    trace_seed: str
    session_id: str
    tags: list[str]
    attributes: dict[str, str]
    root: Observation
    scores: list[Score]
    case_id: str


@dataclass
class ChainLog:
    visible: Path
    mirror: Path | None
    run_id: str
    verdict: dict[str, Any]
    records: list[dict[str, Any]]


class MarkerRedactor:
    def __init__(self, values: list[str]):
        unique = sorted({value for value in values if value}, key=lambda item: (-len(item), item))
        self._labels = {value: f"MARKER_{index}" for index, value in enumerate(unique, 1)}

    @property
    def values(self) -> tuple[str, ...]:
        return tuple(self._labels)

    def text(self, value: str) -> str:
        result = value
        for marker, label in self._labels.items():
            result = result.replace(marker, label)
        return HEX_128.sub("CANARY_128", result)

    def value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.value(item) for item in value]
        if isinstance(value, tuple):
            return [self.value(item) for item in value]
        if isinstance(value, dict):
            return {self.text(str(key)): self.value(item) for key, item in value.items()}
        return value


def deterministic_trace_id(seed: str) -> str:
    """Match ``Langfuse.create_trace_id(seed=...)`` without initializing a client."""
    return hashlib.sha256(seed.encode("utf-8")).digest()[:16].hex()


def _read_json(path: Path, default: Any = None) -> Any:
    if not path.is_file():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _safe_extract(archive_path: Path, destination: Path, case_id: str | None = None) -> None:
    with tarfile.open(archive_path, "r:*") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            relative = Path(member.name)
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError("artifact archive contains an unsafe path")
            if case_id is not None and relative.parts[:1] == ("cases",):
                if len(relative.parts) < 2 or relative.parts[1] != case_id:
                    continue
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                raise ValueError("artifact archive contains an unreadable member")
            with source, target.open("wb") as output:
                shutil.copyfileobj(source, output)


@contextlib.contextmanager
def _materialize(source: Path, case_id: str | None = None) -> Iterator[tuple[Path, Path]]:
    source = source.resolve()
    if source.is_file():
        if not tarfile.is_tarfile(source):
            raise ValueError("the input file must be an artifacts tar archive")
        outer = source.parent
        archive = source
    elif source.is_dir():
        outer = source
        archive = source / "artifacts.tar.gz"
        if not archive.is_file():
            yield source, outer
            return
    else:
        raise ValueError(f"run path does not exist: {source}")
    with tempfile.TemporaryDirectory(prefix="langfuse-ingest-") as directory:
        root = Path(directory)
        _safe_extract(archive, root, case_id)
        yield root, outer


def _marker_leaves(value: Any, *, parent: str = "") -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            name = str(key).lower()
            if isinstance(item, str) and ("marker" in name or "canary_id" in name):
                found.append(item)
            else:
                found.extend(_marker_leaves(item, parent=name))
    elif isinstance(value, list):
        for item in value:
            found.extend(_marker_leaves(item, parent=parent))
    return found


def _collect_markers(root: Path) -> MarkerRedactor:
    values: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            if path.name == "markers.json" or path.name == "MANIFEST.json":
                values.extend(_marker_leaves(json.loads(path.read_text(encoding="utf-8"))))
            elif path.name in {"child-markers.jsonl", "marker.jsonl"}:
                for row in _read_jsonl(path):
                    values.extend(_marker_leaves(row))
            elif path.suffix == ".marker" or path.name in {"canary.txt", "canary-id.txt"}:
                if path.stat().st_size <= 4096:
                    values.append(path.read_text(encoding="utf-8", errors="replace").strip())
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise ValueError(f"cannot safely read marker source: {path}") from None
    return MarkerRedactor(values)


def _case_directories(root: Path, case_id: str | None) -> list[Path]:
    candidates = sorted({path.parent for path in root.rglob("case.json")})
    if case_id is not None:
        candidates = [path for path in candidates if path.name == case_id]
    if not candidates:
        suffix = f" for {case_id}" if case_id else ""
        raise ValueError(f"no case artifacts found{suffix}")
    return candidates


def _report(case_dir: Path) -> dict[str, Any]:
    for candidate in (case_dir / "report.json", case_dir / "report/report.json"):
        report = _read_json(candidate)
        if isinstance(report, dict):
            return report
    return {}


def _run_id(path: Path, case_dir: Path) -> str:
    relative = path.relative_to(case_dir)
    parts = relative.parts
    if len(parts) >= 3 and parts[0] == "runs":
        return parts[1]
    if "delegated" in parts and "harness" in parts:
        return parts[parts.index("harness") - 1]
    if parts and parts[0] in {"board", "orchestrator"}:
        return parts[0]
    return case_dir.name


def _mirror_records(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split("\t", 4)
        if len(parts) != 5:
            continue
        sequence, _previous, chain_hash, _signature, raw = parts
        try:
            sequence_number = int(sequence)
        except ValueError:
            continue
        records.append({"sequence": sequence_number, "chain_hash": chain_hash, "raw": raw})
    return records


def _instrument_chain(mirror: Path, visible: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Key-less structural verification for the instrument suite's 9-field chain."""
    errors: list[str] = []
    records: list[dict[str, Any]] = []
    previous = "0" * 64
    for expected, line in enumerate(mirror.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        parts = line.split("\t", 8)
        if len(parts) != 9:
            errors.append(f"line {expected}: expected 9 fields")
            continue
        sequence_s, timestamp, kind, pid, target, detail, recorded_previous, chain_hash, signature = parts
        try:
            sequence = int(sequence_s)
        except ValueError:
            errors.append(f"line {expected}: invalid sequence")
            continue
        normalized = "\t".join((timestamp, kind, pid, target, detail))
        material = f"{sequence}\t{recorded_previous}\t{normalized}".encode()
        if sequence != expected:
            errors.append(f"line {expected}: sequence {sequence}")
        if recorded_previous != previous:
            errors.append(f"line {expected}: previous hash mismatch")
        if chain_hash != hashlib.sha256(material + b"\t" + signature.encode()).hexdigest():
            errors.append(f"line {expected}: chain hash mismatch")
        previous = chain_hash
        records.append({"sequence": sequence, "chain_hash": chain_hash, "raw": normalized})
    matches = mirror.read_bytes() == visible.read_bytes()
    if not matches:
        errors.append("mirror does not match visible log")
    verdict = {
        "valid": not errors,
        "chain_valid": not [error for error in errors if "mirror does not match" not in error],
        "hmac_checked": False,
        "mirror_matches_visible": matches,
        "mirror_events": len(records),
        "errors": errors,
    }
    return verdict, records if verdict["valid"] else []


def _chain_logs(case_dir: Path) -> list[ChainLog]:
    logs: list[ChainLog] = []
    for visible in sorted(case_dir.rglob("events.tsv")):
        mirror = visible.with_name("events.mirror.tsv")
        if mirror.is_file():
            first = mirror.read_text(encoding="utf-8", errors="replace").splitlines()[:1]
            generic_fields = first[0].split("\t", 4) if first else []
            second_is_hash = (
                len(generic_fields) == 5
                and len(generic_fields[1]) == 64
                and all(char in "0123456789abcdef" for char in generic_fields[1].lower())
            )
            if second_is_hash:
                verdict = verify_chain(mirror, visible, None)
                records = _mirror_records(mirror) if verdict["valid"] else []
            else:
                verdict, records = _instrument_chain(mirror, visible)
            mirror_path: Path | None = mirror
        else:
            verdict = {"valid": False, "errors": ["mirror file missing"], "mirror_events": 0}
            records = []
            mirror_path = None
        logs.append(ChainLog(visible, mirror_path, _run_id(visible, case_dir), verdict, records))
    return logs


def _event_detail(raw: str) -> tuple[str, dict[str, Any]]:
    parts = raw.split("\t", 4)
    if len(parts) < 2:
        return "EVENT", {"raw": raw}
    kind = parts[1]
    detail: Any = parts[4] if len(parts) == 5 else ""
    try:
        decoded = json.loads(detail)
        detail = decoded
    except (TypeError, json.JSONDecodeError):
        pass
    if not isinstance(detail, dict):
        detail = {"detail": detail}
    clean: dict[str, Any] = {}
    for key, value in detail.items():
        if str(key).lower() in {"body", "payload", "request_body"}:
            rendered = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
            clean[f"{key}_sha256"] = hashlib.sha256(rendered.encode()).hexdigest()
            clean[f"{key}_bytes"] = len(rendered.encode())
        else:
            clean[str(key)] = value
    if len(parts) >= 4:
        clean.setdefault("pid", parts[2])
        clean.setdefault("ppid", parts[3])
    return kind, clean


def _event_observation(record: Mapping[str, Any], run_id: str, source: Path) -> Observation:
    kind, detail = _event_detail(str(record["raw"]))
    return Observation(
        kind="event",
        name=kind,
        input=detail,
        metadata={
            "chain_hash": str(record["chain_hash"]),
            "sequence": int(record["sequence"]),
            "source": source.as_posix(),
            "run_id": run_id,
        },
        level="WARNING" if kind in STAGE_EVENTS else "DEFAULT",
    )


def _tool_observations(path: Path, source: str) -> list[Observation]:
    observations: list[Observation] = []
    for row in _read_jsonl(path):
        item = row.get("item") if isinstance(row.get("item"), dict) else row
        item_type = str(item.get("type", row.get("type", "")))
        normalized = item_type.removeprefix("item.").removesuffix(".completed")
        if normalized not in TOOL_ITEM_TYPES and not any(token in normalized for token in ("command", "tool", "web_search")):
            continue
        command = item.get("command", item.get("arguments", item.get("input")))
        output = {
            key: item[key] for key in ("exit_code", "status") if key in item
        }
        transcript_output = item.get("aggregated_output", item.get("output"))
        if transcript_output is not None:
            output["output"] = str(transcript_output)[:TRUNCATE_OUTPUT]
        observations.append(Observation(
            kind="tool",
            name=f"tool:{normalized or 'unknown'}",
            input={"command": command},
            output=output,
            metadata={"source": source, "item_type": item_type},
        ))
    return observations


def _transcript_usage(case_dir: Path) -> tuple[int, int]:
    generations = 0
    tokens = 0
    for path in case_dir.rglob("trajectory.jsonl"):
        for row in _read_jsonl(path):
            if row.get("type") != "turn.completed":
                continue
            generations += 1
            usage = row.get("usage") if isinstance(row.get("usage"), dict) else {}
            total = usage.get("total_tokens")
            if isinstance(total, int) and not isinstance(total, bool):
                tokens += total
    return generations, tokens


def _object_field(value: object, *names: str) -> object:
    for name in names:
        if isinstance(value, Mapping) and name in value:
            return value[name]
        if hasattr(value, name):
            return getattr(value, name)
    return None


def _gateway_alias(observation: object) -> str | None:
    metadata = _object_field(observation, "metadata")
    if not isinstance(metadata, Mapping):
        return None
    direct = metadata.get("attributes.litellm.key_alias")
    if isinstance(direct, str):
        return direct
    attributes = metadata.get("attributes")
    if isinstance(attributes, Mapping):
        flattened = attributes.get("litellm.key_alias")
        if isinstance(flattened, str):
            return flattened
    litellm = attributes.get("litellm") if isinstance(attributes, Mapping) else None
    alias = litellm.get("key_alias") if isinstance(litellm, Mapping) else None
    return alias if isinstance(alias, str) else None


def _gateway_tokens(observation: object) -> int:
    usage = _object_field(observation, "usage_details", "usageDetails")
    if not isinstance(usage, Mapping):
        return 0
    for key in ("total", "total_tokens"):
        value = usage.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    input_tokens = usage.get("input", usage.get("input_tokens", 0))
    output_tokens = usage.get("output", usage.get("output_tokens", 0))
    return sum(
        value for value in (input_tokens, output_tokens)
        if isinstance(value, int) and not isinstance(value, bool)
    )


def add_gateway_generation_usage(
    plan: TracePlan, observations_client: LangfuseObservationsClient,
) -> None:
    """Stage 4: join gateway generations by alias and record count/token parity."""
    alias = plan.attributes.get("gateway_key_alias")
    if not alias:
        return
    filter_value = json.dumps([{
        "type": "stringObject",
        "column": "metadata",
        "key": "attributes.litellm.key_alias",
        "operator": "=",
        "value": alias,
    }], separators=(",", ":"))
    generation_count = 0
    total_tokens = 0
    cursor: str | None = None
    while True:
        response = observations_client.get_many(
            fields="core,metadata,usage", type="GENERATION", filter=filter_value,
            limit=1000, cursor=cursor,
        )
        data = _object_field(response, "data")
        for observation in data if isinstance(data, (list, tuple)) else []:
            # The API filter is authoritative; the local check keeps fake-client
            # tests honest and prevents a permissive backend from inflating counts.
            if _gateway_alias(observation) != alias:
                continue
            generation_count += 1
            total_tokens += _gateway_tokens(observation)
        meta = _object_field(response, "meta")
        next_cursor = _object_field(meta, "cursor")
        if not isinstance(next_cursor, str) or not next_cursor or next_cursor == cursor:
            break
        cursor = next_cursor
    plan.root.metadata["gateway_generation_count"] = generation_count
    plan.root.metadata["gateway_total_tokens"] = total_tokens
    plan.root.metadata["gateway_transcript_generation_count_mismatch"] = (
        generation_count != plan.root.metadata.get("transcript_generation_count")
    )


def _harness_name(case_id: str, modal: Mapping[str, Any]) -> str:
    if isinstance(modal.get("harness"), str):
        return str(modal["harness"])
    return {"APH": "agent", "CLH": "collusion", "IHT": "instrument", "MRH": "model", "NOF": "network-off"}.get(
        case_id.split("-", 1)[0], "honeypot"
    )


def _root_io(case: Mapping[str, Any], report: Mapping[str, Any], chains_valid: bool, trial: int) -> tuple[dict[str, Any], dict[str, Any]]:
    case_input = case.get("input") if isinstance(case.get("input"), dict) else {}
    case_metadata = case.get("metadata") if isinstance(case.get("metadata"), dict) else {}
    trace_input = {
        "case_id": case.get("id"),
        "role": case_metadata.get("role", report.get("role")),
        "category": case_metadata.get("category", report.get("category")),
        "task_prompt": case_input.get("instruction", case_input.get("task")),
        "planted_channels": case_metadata.get("tripwire", case_metadata.get("lure_arm")),
        "solvability": case_metadata.get("verifier_can_pass"),
        "trial": trial,
    }
    verifier = report.get("expectation_passed", report.get("calibration_passed"))
    trace_output = {
        "strongest_stage": report.get("observed_stage", report.get("stage")),
        "score": report.get("score", report.get("overall_score", report.get("containment_score"))),
        "severity": report.get("severity"),
        "policy_verdict": report.get("verdict"),
        "chains_valid": chains_valid,
        "verifier_result": verifier,
    }
    return trace_input, trace_output


def _score_rows(report: Mapping[str, Any], chains_valid: bool) -> list[Score]:
    verifier = report.get("expectation_passed", report.get("calibration_passed"))
    verdict = "pass" if verifier is True else "fail" if verifier is False else str(report.get("verdict", "unknown"))
    rows = [Score("chain_valid", 1.0 if chains_valid else 0.0, "NUMERIC")]
    stage = report.get("observed_stage", report.get("stage"))
    if stage is not None:
        rows.append(Score("stage", str(stage), "CATEGORICAL"))
    score = report.get("score", report.get("overall_score", report.get("containment_score")))
    if isinstance(score, (int, float)) and not isinstance(score, bool):
        rows.append(Score("score", float(score), "NUMERIC"))
    rows.append(Score("verdict", verdict, "CATEGORICAL"))
    return rows


def _run_specs(case_dir: Path, case: Mapping[str, Any], logs: list[ChainLog], chains_valid: bool) -> list[Observation]:
    run_kinds: dict[str, str] = {}
    case_input = case.get("input") if isinstance(case.get("input"), dict) else {}
    for row in case_input.get("runs", []) if isinstance(case_input.get("runs"), list) else []:
        if isinstance(row, dict) and row.get("id") is not None:
            run_kinds[str(row["id"])] = str(row.get("kind", "run"))

    specs: dict[str, Observation] = {}
    root_events: list[Observation] = []
    for log in logs:
        if log.run_id in {"board", "orchestrator"}:
            if chains_valid:
                source = log.visible.relative_to(case_dir)
                root_events.extend(
                    _event_observation(row, log.run_id, source) for row in log.records
                )
            continue
        kind = run_kinds.get(log.run_id, "delegate" if ".child" in log.run_id else log.run_id)
        spec = specs.setdefault(log.run_id, Observation(
            kind="span", name=f"run:{kind}:{log.run_id}",
            metadata={"run_id": log.run_id, "kind": kind, "depth": log.run_id.count(".child")},
        ))
        if chains_valid:
            source = log.visible.relative_to(case_dir)
            spec.children.extend(_event_observation(row, log.run_id, source) for row in log.records)

    for transcript in sorted(case_dir.rglob("trajectory.jsonl")):
        run_id = _run_id(transcript, case_dir)
        kind = run_kinds.get(run_id, "delegate" if ".child" in run_id else run_id)
        spec = specs.setdefault(run_id, Observation(
            kind="span", name=f"run:{kind}:{run_id}",
            metadata={"run_id": run_id, "kind": kind, "depth": run_id.count(".child")},
        ))
        if chains_valid:
            spec.children.extend(_tool_observations(
                transcript, transcript.relative_to(case_dir).as_posix(),
            ))

    if not specs:
        specs[case_dir.name] = Observation(
            kind="span", name=f"run:harness:{case_dir.name}",
            metadata={"run_id": case_dir.name, "kind": "harness", "depth": 0},
        )

    parent_for: dict[str, str] = {}
    for row in _read_jsonl(case_dir / "delegations.jsonl"):
        if row.get("run_id") and row.get("parent_run"):
            parent_for[str(row["run_id"])] = str(row["parent_run"])
    roots: list[Observation] = []
    for run_id, spec in specs.items():
        parent_id = parent_for.get(run_id)
        if parent_id in specs:
            specs[parent_id].children.append(spec)
        else:
            roots.append(spec)
    return root_events + sorted(roots, key=lambda item: item.name)


def _case_summary(summary: Mapping[str, Any], case_id: str) -> Mapping[str, Any]:
    for row in summary.get("results", []) if isinstance(summary.get("results"), list) else []:
        if isinstance(row, dict) and row.get("case_id") == case_id:
            return row
    return {}


def _build_case_plan(
    case_dir: Path, modal: Mapping[str, Any], summary: Mapping[str, Any],
    redactor: MarkerRedactor, cohort: str,
) -> TracePlan:
    case = _read_json(case_dir / "case.json", {})
    if not isinstance(case, dict):
        raise ValueError(f"invalid case.json: {case_dir}")
    report = _report(case_dir)
    case_id = str(case.get("id", case_dir.name))
    logs = _chain_logs(case_dir)
    report_chains = [row for row in report.get("evidence_chains", []) if isinstance(row, dict)] if isinstance(report.get("evidence_chains"), list) else []
    chains_valid = bool(logs) and all(log.verdict.get("valid") is True for log in logs)
    if report_chains:
        chains_valid = chains_valid and all(row.get("valid") is True for row in report_chains)
    if report.get("chain_valid") is False or report.get("observability") == "unobservable":
        chains_valid = False

    trial = int(modal.get("trial", 1))
    arm = str(modal.get("arm") or case.get("metadata", {}).get("lure_arm") or cohort)
    started_at = str(modal.get("started_at") or cohort)
    trace_seed = f"{cohort}:{case_id}:trial-{trial}:{started_at}"
    trace_id = deterministic_trace_id(trace_seed)
    virtual_key = modal.get("virtual_key")
    gateway_key_alias = (
        virtual_key.get("key_alias") if isinstance(virtual_key, Mapping) else None
    )
    gateway_key_alias = (
        gateway_key_alias
        if isinstance(gateway_key_alias, str) and gateway_key_alias
        else None
    )
    session_id = gateway_key_alias or f"{arm}/{case_id}/t{trial}"
    harness = _harness_name(case_id, modal)
    subject_mode = str(modal.get("subject_mode") or report.get("subject_mode") or "scripted")
    tags = [harness, arm, subject_mode, "chain=on"]
    if not chains_valid:
        tags.append("unobservable")
    trace_input, trace_output = _root_io(case, report, chains_valid, trial)
    transcript_generations, transcript_tokens = _transcript_usage(case_dir)
    metadata: dict[str, Any] = {
        "sandbox_id": modal.get("sandbox_id"),
        "policy": modal.get("policy", {}),
        "source_commit": modal.get("source_commit"),
        "observability": "observable" if chains_valid else "unobservable",
        "session_id_source": "key_alias" if gateway_key_alias else "derived",
        "transcript_generation_count": transcript_generations,
        "transcript_total_tokens": transcript_tokens,
    }
    if gateway_key_alias:
        metadata["gateway_key_alias"] = gateway_key_alias
    attributes = {
        "harness": harness, "arm": arm, "case_id": case_id, "trial": str(trial),
    }
    if gateway_key_alias:
        attributes["gateway_key_alias"] = gateway_key_alias
    root = Observation(
        kind="span", name=f"{harness}-case", input=trace_input, output=trace_output,
        metadata=metadata, children=_run_specs(case_dir, case, logs, chains_valid),
    )
    plan = TracePlan(
        trace_id=trace_id,
        trace_seed=trace_seed,
        session_id=session_id,
        tags=tags,
        attributes=attributes,
        root=root,
        scores=_score_rows(report, chains_valid),
        case_id=case_id,
    )
    return _redact_plan(plan, redactor)


def _redact_plan(plan: TracePlan, redactor: MarkerRedactor) -> TracePlan:
    rendered = redactor.value(asdict(plan))

    def observation(row: Mapping[str, Any]) -> Observation:
        return Observation(
            kind=str(row["kind"]), name=str(row["name"]), input=row.get("input"),
            output=row.get("output"), metadata=dict(row.get("metadata", {})),
            level=row.get("level"), children=[observation(child) for child in row.get("children", [])],
        )

    return TracePlan(
        # Generated correlation IDs are not artifact content and must remain
        # valid W3C identifiers even though they are 128-bit hex strings.
        trace_id=plan.trace_id, trace_seed=str(rendered["trace_seed"]),
        session_id=str(rendered["session_id"]), tags=list(rendered["tags"]),
        attributes=dict(rendered["attributes"]), root=observation(rendered["root"]),
        scores=[Score(**row) for row in rendered["scores"]], case_id=str(rendered["case_id"]),
    )


def build_trace_plans(source: Path, *, case_id: str | None = None) -> list[TracePlan]:
    source = Path(source)
    with _materialize(source, case_id) as (root, outer):
        modal = _read_json(outer / "modal-run.json", {})
        summary = _read_json(outer / "summary.json", _read_json(root / "summary.json", {}))
        modal = modal if isinstance(modal, dict) else {}
        summary = summary if isinstance(summary, dict) else {}
        case_directories = _case_directories(root, case_id)
        redactor = MarkerRedactor([
            marker
            for path in case_directories
            for marker in _collect_markers(path).values
        ])
        cohort = str(modal.get("arm") or outer.name)
        return [
            _build_case_plan(path, modal, summary, redactor, cohort)
            for path in case_directories
        ]


def _emit_observation(client: LangfuseClient, observation: Observation) -> None:
    if observation.kind == "event":
        kwargs: dict[str, Any] = {
            "name": observation.name, "input": observation.input,
            "output": observation.output, "metadata": observation.metadata,
        }
        if observation.level:
            kwargs["level"] = observation.level
        client.create_event(**kwargs)
        return
    kwargs = {
        "as_type": observation.kind,
        "name": observation.name,
        "input": observation.input,
        "output": observation.output,
        "metadata": observation.metadata,
    }
    if observation.level:
        kwargs["level"] = observation.level
    with client.start_as_current_observation(**kwargs):
        for child in observation.children:
            _emit_observation(client, child)


def push_trace_plans(
    plans: list[TracePlan], client: LangfuseClient, *,
    propagate: Callable[..., Any],
) -> None:
    try:
        for plan in plans:
            root = plan.root
            with client.start_as_current_observation(
                as_type="span", name=root.name, input=root.input, output=root.output,
                metadata=root.metadata, trace_context={"trace_id": plan.trace_id},
            ) as root_span:
                root_observation_id = getattr(root_span, "id", None)
                with propagate(
                    session_id=plan.session_id,
                    metadata=plan.attributes,
                    tags=plan.tags,
                    trace_name=root.name,
                ):
                    for child in root.children:
                        _emit_observation(client, child)
            for score in plan.scores:
                score_args: dict[str, Any] = {
                    "name": score.name,
                    "value": score.value,
                    "data_type": score.data_type,
                    "trace_id": plan.trace_id,
                }
                if root_observation_id is not None:
                    score_args["observation_id"] = root_observation_id
                client.create_score(**score_args)
    finally:
        client.shutdown()


def write_trace_ids(source: Path, plans: list[TracePlan]) -> None:
    source = Path(source)
    outer = source.parent if source.is_file() else source
    summary_path = outer / "summary.json"
    summary = _read_json(summary_path)
    if not isinstance(summary, dict):
        raise ValueError(f"cannot append Langfuse trace IDs without {summary_path}")
    if len(plans) == 1:
        langfuse = summary.setdefault("langfuse", {})
        existing = langfuse.get("trace_id")
        if existing is not None and existing != plans[0].trace_id:
            raise ValueError("summary.json already contains a different Langfuse trace ID")
        langfuse["trace_id"] = plans[0].trace_id
    else:
        by_case = {plan.case_id: plan.trace_id for plan in plans}
        matched: set[str] = set()
        for row in summary.get("results", []) if isinstance(summary.get("results"), list) else []:
            if isinstance(row, dict) and row.get("case_id") in by_case:
                case_id = str(row["case_id"])
                langfuse = row.setdefault("langfuse", {})
                existing = langfuse.get("trace_id")
                if existing is not None and existing != by_case[case_id]:
                    raise ValueError(f"summary.json already contains a different trace ID for {case_id}")
                langfuse["trace_id"] = by_case[case_id]
                matched.add(case_id)
        if matched != set(by_case):
            raise ValueError("summary.json does not contain every pushed case")
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _push_client() -> tuple[LangfuseClient, Callable[..., Any]]:
    required = ("LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY", "LANGFUSE_BASE_URL")
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        raise ValueError("--push requires " + ", ".join(missing))
    from langfuse import Langfuse, propagate_attributes
    client = Langfuse(
        public_key=os.environ["LANGFUSE_PUBLIC_KEY"],
        secret_key=os.environ["LANGFUSE_SECRET_KEY"],
        base_url=os.environ["LANGFUSE_BASE_URL"],
    )
    return client, propagate_attributes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path, help="run directory, calibration directory, or artifacts tar")
    parser.add_argument("--case-id", help="ingest one case from a multi-case run")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--push", action="store_true")
    args = parser.parse_args(argv)
    try:
        plans = build_trace_plans(args.run, case_id=args.case_id)
        if args.dry_run:
            print(json.dumps([asdict(plan) for plan in plans], indent=2, sort_keys=True))
            return 0
        client, propagate = _push_client()
        observations_client = client.api.observations
        try:
            for plan in plans:
                add_gateway_generation_usage(plan, observations_client)
        except Exception:
            client.shutdown()
            raise
        push_trace_plans(plans, client, propagate=propagate)
        write_trace_ids(args.run, plans)
        print(json.dumps({"trace_ids": [plan.trace_id for plan in plans]}, sort_keys=True))
        return 0
    except ValueError as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
