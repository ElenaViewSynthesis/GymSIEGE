"""
Shared config, constants, and small helpers used by every GYMSIEGE entrypoint
(snapshot_build.py, orchestrator.py, sandbox_runner.py, solver_agent.py,
dashboard.py). Not one of the five named deliverables on its own — it exists
so those five files don't each reimplement the same env parsing and JSON
plumbing.

Everything here is real, runnable code. Nothing in this module fabricates
results: it only defines shapes and I/O helpers.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Literal, Optional

# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent

RESULTS_DIR = ROOT / "results"
RECORDINGS_DIR = ROOT / "recordings"
ARTIFACTS_DIR = ROOT / "artifacts"
DATA_DIR = ROOT / "data"

# Every entrypoint imports common, so loading local configuration here is
# enough to expose it through os.environ without any caller reading or logging
# secret values. An already-injected environment always wins.
try:
    from dotenv import load_dotenv

    load_dotenv(ROOT / ".env.defaults", override=False)
    load_dotenv(ROOT / ".env", override=False)
    load_dotenv(ROOT / ".env.local", override=False)
except ImportError:  # pragma: no cover - python-dotenv is in requirements.txt
    pass

RESULTS_JSON = RESULTS_DIR / "exploitgym-runs" / "results.json"
EVENTS_NDJSON = RESULTS_DIR / "events.ndjson"
CONCURRENCY_SWEEP_JSON = RESULTS_DIR / "concurrency_sweep.json"
PROVISIONING_BENCH_JSON = RESULTS_DIR / "provisioning_bench.json"
TELEMETRY_DIR = RESULTS_DIR / "telemetry"
REAP_LOG_JSON = RESULTS_DIR / "reap_log.json"
EXPLOITGYM_RESULTS_JSON = RESULTS_DIR / "exploitgym_results.json"

for _d in (RESULTS_DIR, RECORDINGS_DIR, ARTIFACTS_DIR, DATA_DIR, TELEMETRY_DIR, RESULTS_JSON.parent):
    _d.mkdir(parents=True, exist_ok=True)

# --------------------------------------------------------------------------
# Constants (§2/§4 of the spec)
# --------------------------------------------------------------------------

SNAPSHOT_NAME = os.environ.get("GYMSIEGE_SNAPSHOT", "gymsiege-toolchain")
SANDBOX_NAME_PREFIX = "siege"  # every sandbox we create is named siege-*
CYBERGYM_REPO_URL = "https://github.com/sunblaze-ucb/cybergym-e2e.git"
CYBERGYM_REMOTE_DIR = "/home/daytona/cybergym-e2e"  # path *inside* the sandbox
HF_DATASET = "sunblaze-ucb/cybergym-e2e"
EXPLOITGYM_REPO_URL = "https://github.com/sunblaze-ucb/exploitgym.git"
EXPLOITGYM_REMOTE_DIR = "/home/daytona/exploitgym"
EXPLOITGYM_SNAPSHOT_NAME = os.environ.get(
    "GYMSIEGE_EXPLOITGYM_SNAPSHOT", "gymsiege-exploitgym"
)

DEFAULT_VNC_RESOLUTION = os.environ.get("VNC_RESOLUTION", "1280x800")
AGENT_TIMEOUT_S = int(os.environ.get("GYMSIEGE_AGENT_TIMEOUT", "5400"))  # matches run_agent.py DEFAULT_TIMEOUT
SANDBOX_SAFETY_TTL_MINUTES = int(os.environ.get("GYMSIEGE_TTL_MIN", "60"))

Mode = Literal["e2e", "patch-only"]
ProvisioningMode = Literal["snapshot", "cold", "fork"]

CONCURRENCY_LADDER = [1, 2, 4, 8, 16, 32]

# --------------------------------------------------------------------------
# Env / client config
# --------------------------------------------------------------------------


def require_env(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        raise RuntimeError(
            f"{name} is not set. GYMSIEGE talks to the real Daytona API and "
            f"needs live credentials — see README.md#credentials."
        )
    return val


def have_daytona_credentials() -> bool:
    return bool(os.environ.get("DAYTONA_API_KEY"))


def sandbox_secret_refs(required_env_names: tuple[str, ...] | None = None) -> dict[str, str]:
    """Return Daytona vault mounts as ``ENV_NAME -> organization secret name``.

    Daytona's ``update_secrets`` does *not* accept plaintext secret values.
    The indirection is intentional: local API keys never cross the SDK as
    request payloads, and the sandbox receives only pre-created organization
    secrets.
    """

    mapping = {
        "OPENAI_API_KEY": os.environ.get("GYMSIEGE_OPENAI_SECRET_NAME"),
        "LITELLM_MASTER_KEY": os.environ.get("GYMSIEGE_LITELLM_SECRET_NAME"),
        "HF_TOKEN": os.environ.get("GYMSIEGE_HF_SECRET_NAME"),
    }
    if required_env_names is not None:
        mapping = {name: mapping.get(name) for name in required_env_names}
    return {env_name: secret_name for env_name, secret_name in mapping.items() if secret_name}


# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s", "%H:%M:%S")
        )
        logger.addHandler(handler)
        logger.setLevel(os.environ.get("GYMSIEGE_LOG_LEVEL", "INFO"))
    return logger


# --------------------------------------------------------------------------
# Task model
# --------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Task:
    """One CyberGym-E2E task, e.g. project='curl', task_id='arvo_66012'."""

    project: str
    task_id: str
    note: str = ""

    @property
    def path(self) -> str:
        """The `project/task_id` form run_agent.py expects, e.g. curl/arvo_66012."""
        return f"{self.project}/{self.task_id}"

    @property
    def safe_name(self) -> str:
        return self.path.replace("/", "_")

    @classmethod
    def parse(cls, line: str) -> Optional["Task"]:
        line = line.strip()
        if not line or line.startswith("#"):
            return None
        path, _, note = line.partition("#")
        path = path.strip()
        note = note.strip()
        if "/" not in path:
            raise ValueError(f"bad task line (expected project/task_id): {line!r}")
        project, task_id = path.split("/", 1)
        return cls(project=project.strip(), task_id=task_id.strip(), note=note)


def load_tasks(path: Path) -> list[Task]:
    tasks: list[Task] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        t = Task.parse(raw_line)
        if t is not None:
            tasks.append(t)
    return tasks


# --------------------------------------------------------------------------
# Trial result model (what sandbox_runner.py produces, orchestrator.py collects,
# dashboard.py renders)
# --------------------------------------------------------------------------


@dataclasses.dataclass
class TrialResult:
    task: str  # project/task_id
    mode: Mode
    trial: int
    provisioning: ProvisioningMode
    benchmark: str = "cybergym-e2e"
    sandbox_id: Optional[str] = None
    sandbox_name: Optional[str] = None

    status: str = "pending"  # pending|running|success|other_vuln|failed|error|oracle_unavailable|timeout
    stage1: Optional[str] = None  # agent PoC crashes w/o patch
    stage2: Optional[str] = None  # agent PoC OK with patch
    stage3: Optional[str] = None  # functionality tests pass with patch
    stage4: Optional[str] = None  # ground-truth PoC OK with patch
    agent_success: Optional[bool] = None
    gt_success: Optional[bool] = None

    vul_exit_code: Optional[int] = None  # sanitizer exit code on the unpatched build (post-detonation reconfirm)
    fix_exit_code: Optional[int] = None  # sanitizer exit code on the patched build (post-detonation reconfirm)
    network_isolated_detonation: bool = False

    research_mode: Optional[str] = None  # "accessibility" | "screenshot" | "skipped"
    research_success: Optional[bool] = None

    t_create_s: Optional[float] = None
    t_research_s: Optional[float] = None
    t_build_s: Optional[float] = None
    t_total_s: Optional[float] = None

    recording_path: Optional[str] = None
    poc_url: Optional[str] = None
    patch_url: Optional[str] = None
    log_url: Optional[str] = None
    poc_local_path: Optional[str] = None
    patch_local_path: Optional[str] = None
    log_local_path: Optional[str] = None

    metrics_latest: Optional[dict[str, Any]] = None
    metrics_series: Optional[list[dict[str, Any]]] = None
    solver_usage: Optional[dict[str, Any]] = None
    solver_cost_usd: Optional[float] = None
    vision_usage: Optional[dict[str, Any]] = None

    cleanup_ttl_set: bool = False
    cleanup_delete_accepted: bool = False
    cleanup_destroyed: bool = False
    detonation_error: Optional[str] = None

    error: Optional[str] = None
    started_at: Optional[str] = None
    finished_at: Optional[str] = None

    def to_json(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


def append_event(event: dict[str, Any]) -> None:
    """Append one JSON line to results/events.ndjson for the live dashboard to tail."""
    event = {"ts": time.time(), **event}
    with EVENTS_NDJSON.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, default=str) + "\n")


def read_events(limit: int = 500) -> list[dict[str, Any]]:
    if not EVENTS_NDJSON.exists():
        return []
    lines = EVENTS_NDJSON.read_text(encoding="utf-8").splitlines()
    out = []
    for line in lines[-limit:]:
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def atomic_write_json(path: Path, data: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    tmp.replace(path)


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default
