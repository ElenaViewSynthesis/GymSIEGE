"""Best-effort Langfuse tracing for completed benchmark trials.

The benchmark result remains the source of truth.  Nothing in this module may
raise into a trial: if Langfuse is unavailable, the run proceeds untraced.
"""

from __future__ import annotations

import contextvars
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from common import get_logger

log = get_logger("observability")

_client: Any = None
_initialised = False
_warning_emitted = False
_init_lock = threading.Lock()
_active_trace: contextvars.ContextVar[Optional["TrialTrace"]] = contextvars.ContextVar(
    "gymsiege_trial_trace", default=None
)


def new_run_id() -> str:
    """Return the caller-provided batch id, or a fresh id for one CLI run."""

    return os.environ.get("GYMSIEGE_RUN_ID") or f"gymsiege-{uuid.uuid4()}"


def _warn_once(message: str, *args: Any) -> None:
    global _warning_emitted
    if not _warning_emitted:
        _warning_emitted = True
        log.warning(message, *args)


def initialize_tracing(client: Any = None) -> Any:
    """Authenticate Langfuse once per process and return its singleton client.

    Passing ``client`` exists for focused tests; production always uses
    Langfuse's configured ``get_client()`` singleton.
    """

    global _client, _initialised
    with _init_lock:
        if _initialised:
            return _client
        _initialised = True
        if not (
            os.environ.get("LANGFUSE_PUBLIC_KEY")
            and os.environ.get("LANGFUSE_SECRET_KEY")
        ) and client is None:
            _warn_once("Langfuse tracing disabled: credentials are not configured")
            return None
        try:
            if client is None:
                from langfuse import get_client

                client = get_client()
            if not client.auth_check():
                _warn_once("Langfuse tracing disabled: authentication failed")
                return None
            _client = client
            return _client
        except Exception as exc:  # tracing must never affect benchmark work
            _warn_once("Langfuse tracing disabled: %s", exc)
            return None


def _reset_tracing_for_tests() -> None:
    global _client, _initialised, _warning_emitted
    _client = None
    _initialised = False
    _warning_emitted = False


def _as_datetime(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def _error_summary(value: Any) -> Optional[str]:
    """Keep useful failure context without exporting secrets or signed URLs."""

    if not value:
        return None
    first_line = str(value).splitlines()[0][:500]
    first_line = re.sub(r"https?://\S+", "<redacted-url>", first_line)
    first_line = re.sub(
        r"(?i)\b(api[_-]?key|token|secret|authorization)\b\s*[:=]\s*\S+",
        r"\1=<redacted>",
        first_line,
    )
    first_line = re.sub(r"\bsk-[A-Za-z0-9_-]+", "<redacted-key>", first_line)
    return first_line


def _metadata(result: Any, model: str, provider: str) -> dict[str, Any]:
    return {
        "task_id": getattr(result, "task", None),
        "trial": getattr(result, "trial", None),
        "mode": getattr(result, "mode", None),
        "model": model,
        "provider": provider,
        "sandbox_name": getattr(result, "sandbox_name", None),
        "benchmark": getattr(result, "benchmark", None),
    }


def _root_output(result: Any) -> dict[str, Any]:
    status = getattr(result, "status", None)
    score = getattr(result, "score", None)
    if score is None and status is not None:
        score = 1.0 if status == "success" else 0.0
    output: dict[str, Any] = {
        "status": status,
        "score": score,
        "solver_cost_usd": getattr(result, "solver_cost_usd", None),
    }
    if getattr(result, "benchmark", "") == "exploitgym":
        output.update(
            checks=getattr(result, "checks", None),
            success=getattr(result, "success", None),
            evaluation_completed_from_result=getattr(
                result, "evaluation_completed_from_result", None
            ),
        )
    else:
        output.update(
            stage1=getattr(result, "stage1", None),
            stage2=getattr(result, "stage2", None),
            stage3=getattr(result, "stage3", None),
            stage4=getattr(result, "stage4", None),
            isolated_stage3=getattr(result, "isolated_stage3", None),
            isolated_stage4=getattr(result, "isolated_stage4", None),
            vul_exit_code=getattr(result, "vul_exit_code", None),
            fix_exit_code=getattr(result, "fix_exit_code", None),
            network_isolated_detonation=getattr(
                result, "network_isolated_detonation", False
            ),
            cleanup_destroyed=getattr(result, "cleanup_destroyed", False),
        )
    return output


class TrialTrace:
    """One active root observation, kept open for the complete trial."""

    def __init__(
        self,
        result: Any,
        *,
        model: str,
        provider: str,
        session_id: str,
    ) -> None:
        self.result = result
        self.model = model
        self.provider = provider
        self.session_id = session_id
        self.client: Any = None
        self.root: Any = None
        self._attribute_cm: Any = None
        self._root_cm: Any = None
        self._token: Any = None
        self._stages: dict[str, Any] = {}
        self.closed = False

    def open(self) -> "TrialTrace":
        self.client = initialize_tracing()
        if self.client is None:
            return self
        try:
            from langfuse import propagate_attributes

            benchmark = getattr(self.result, "benchmark", "benchmark")
            root_name = (
                "exploitgym-trial" if benchmark == "exploitgym" else "cybergym-trial"
            )
            static_tags = [
                str(benchmark),
                str(getattr(self.result, "mode", "unknown")),
                str(self.model),
                str(self.provider),
            ]
            self._attribute_cm = propagate_attributes(
                session_id=self.session_id,
                tags=static_tags,
                trace_name=root_name,
                environment=os.environ.get("LANGFUSE_TRACING_ENVIRONMENT", "development"),
            )
            self._attribute_cm.__enter__()
            self._root_cm = self.client.start_as_current_observation(
                as_type="agent",
                name=root_name,
                input={
                    "task_id": getattr(self.result, "task", None),
                    "mode": getattr(self.result, "mode", None),
                    "trial": getattr(self.result, "trial", None),
                },
                metadata=_metadata(self.result, self.model, self.provider),
            )
            self.root = self._root_cm.__enter__()
            self._token = _active_trace.set(self)
        except Exception as exc:
            _warn_once("Langfuse tracing disabled after setup failure: %s", exc)
            self._exit_contexts()
            self.client = None
            self.root = None
        return self

    def _exit_contexts(self) -> None:
        if self._token is not None:
            try:
                _active_trace.reset(self._token)
            except Exception:
                pass
            self._token = None
        if self._root_cm is not None:
            try:
                self._root_cm.__exit__(None, None, None)
            except Exception:
                pass
            self._root_cm = None
        if self._attribute_cm is not None:
            try:
                self._attribute_cm.__exit__(None, None, None)
            except Exception:
                pass
            self._attribute_cm = None

    def start_stage(self, result: Any, stage: str) -> None:
        if self.root is None:
            return
        try:
            self._stages[stage] = self.root.start_observation(
                as_type="span",
                name=stage,
                input={"stage": stage},
                metadata={"stage": stage, "status": "running"},
            )
        except Exception as exc:
            _warn_once("Langfuse stage tracing failed; continuing untraced: %s", exc)

    def finish_stage(self, result: Any, stage: str, status: str) -> None:
        observation = self._stages.pop(stage, None)
        if observation is None:
            return
        timing = getattr(result, "stage_timings", {}).get(stage, {})
        failed = status not in {"ok", "complete", "passed", "skipped"}
        failure_stage = getattr(result, "failure_stage", None)
        if failure_stage == stage:
            failed = True
        try:
            update: dict[str, Any] = {
                "output": {
                    "status": "ok" if status == "complete" else status,
                    "duration_s": timing.get("duration_s"),
                },
                "metadata": {
                    "stage": stage,
                    "status": "ok" if status == "complete" else status,
                    "started_at": timing.get("started_at"),
                    "finished_at": timing.get("finished_at"),
                    "duration_s": timing.get("duration_s"),
                },
            }
            if failed:
                update.update(
                    level="ERROR",
                    status_message=(
                        getattr(result, "failure_reason", None)
                        or _error_summary(getattr(result, "error", None))
                        or f"stage ended with status={status}"
                    ),
                )
                update["metadata"].update(
                    failure_stage=failure_stage,
                    failure_reason=getattr(result, "failure_reason", None),
                    error=_error_summary(getattr(result, "error", None)),
                )
            observation.update(**update)
            finished = _as_datetime(timing.get("finished_at"))
            observation.end(
                end_time=int(finished.timestamp() * 1_000_000_000) if finished else None
            )
        except Exception as exc:
            _warn_once("Langfuse stage finalization failed; continuing: %s", exc)

    def close(self, result: Any) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            for stage in list(self._stages):
                self.finish_stage(result, stage, "interrupted")
            if self.root is not None:
                status = str(getattr(result, "status", "unknown"))
                cost = getattr(result, "solver_cost_usd", None)
                update: dict[str, Any] = {
                    "output": _root_output(result),
                    "metadata": {
                        **_metadata(result, self.model, self.provider),
                        "solver_cost_usd": cost,
                    },
                }
                if status in {"error", "timeout", "interrupted", "oracle_unavailable"}:
                    update.update(
                        level="ERROR",
                        status_message=_error_summary(getattr(result, "error", None)) or status,
                    )
                self.root.update(**update)

                # Tags are immutable at creation.  The terminal status only
                # exists now, so put it on a final child; Langfuse aggregates
                # all observation tags onto the trace.
                from langfuse import propagate_attributes

                with propagate_attributes(tags=[status]):
                    outcome = self.root.start_observation(
                        name="record-trial-outcome",
                        as_type="span",
                        input={"status": status},
                        output=_root_output(result),
                    )
                    outcome.end()

                # Langfuse accepts cost details on GENERATION observations,
                # not on the AGENT root.  Layer 1 cannot see the individual
                # in-sandbox model calls, so this explicitly named summary is
                # the honest aggregate supplied by the benchmark result.
                if isinstance(cost, (int, float)):
                    solver_summary = self.root.start_observation(
                        name="record-solver-cost",
                        as_type="generation",
                        model=self.model,
                        input={"task_id": getattr(result, "task", None)},
                        output={"status": status},
                        metadata={"aggregate": True},
                        cost_details={
                            "total": float(cost),
                            "solver_cost_usd": float(cost),
                        },
                    )
                    solver_summary.end()

                exploited = bool(
                    getattr(result, "success", None)
                    if getattr(result, "benchmark", "") == "exploitgym"
                    else status == "success"
                )
                self.root.score(name="exploited", value=1.0 if exploited else 0.0)
        except Exception as exc:
            _warn_once("Langfuse trial finalization failed; benchmark result preserved: %s", exc)
        finally:
            self._exit_contexts()
            if self.client is not None:
                try:
                    self.client.flush()
                except Exception as exc:
                    _warn_once("Langfuse flush failed; benchmark result preserved: %s", exc)


def begin_trial_trace(
    result: Any,
    *,
    model: str,
    provider: str,
    session_id: Optional[str] = None,
) -> TrialTrace:
    return TrialTrace(
        result,
        model=model,
        provider=provider,
        session_id=session_id or new_run_id(),
    ).open()


def stage_start(result: Any, stage: str) -> None:
    now = datetime.now(timezone.utc)
    result.last_stage = stage
    result.stage_timings[stage] = {
        "started_at": now.isoformat(),
        "finished_at": None,
        "duration_s": None,
        "status": "running",
    }
    trace = _active_trace.get()
    if trace is not None:
        trace.start_stage(result, stage)


def stage_finish(result: Any, stage: str, status: str = "complete") -> None:
    now = datetime.now(timezone.utc)
    timing = result.stage_timings.setdefault(stage, {"started_at": now.isoformat()})
    started = _as_datetime(timing.get("started_at"))
    timing.update(
        finished_at=now.isoformat(),
        duration_s=max(0.0, (now - started).total_seconds()) if started else None,
        status=status,
    )
    trace = _active_trace.get()
    if trace is not None:
        trace.finish_stage(result, stage, status)


def stage_abort_current(result: Any, status: str) -> None:
    stage = getattr(result, "last_stage", None)
    if stage and result.stage_timings.get(stage, {}).get("status") == "running":
        stage_finish(result, stage, status)
