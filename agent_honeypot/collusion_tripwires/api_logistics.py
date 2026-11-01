"""API-call logistics of the real-agent collusion cohorts (the paper's appendix tables), from each cell's own
files plus the gateway's Langfuse records (read-only). Writes a JSON table and
prints per-cohort and per-case aggregates. No secrets: spends, counts, tokens.

Usage (WSL, repo root, .env.local exported):
  .venv/bin/python -I agent_honeypot/collusion_tripwires/api_logistics.py OUT.json

Cohorts:
  v1, v2, v3          the cells of results/modal-honeypot-collusion-exp/figures-v1v2v3/figures.json
  opus-modal          the Modal cells on claude-opus-5-5 (the refused first Opus cohort)
  opus-docker-pilots  results/docker-honeypot-collusion-exp/lure-pair/ (pilots 1 and 2)
  opus-v2             results/docker-honeypot-collusion-exp/opus-v2-20261101T072234Z/
  plus any further results/docker-honeypot-collusion-exp/<name>-<stamp>/ cohort root
"""
import json
import os
import sys
import tarfile
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, os.getcwd())
from agent_honeypot import langfuse_ingest as ingest  # noqa: E402

REPO = Path(os.getcwd())
MODAL = REPO / "results/modal-honeypot-collusion-exp"
DOCKER = REPO / "results/docker-honeypot-collusion-exp"


def transcript_usage(run_dir: Path) -> dict[str, int]:
    usage = {"turns": 0, "input_tokens": 0, "cached_input_tokens": 0, "output_tokens": 0, "commands": 0}
    archive_path = run_dir / "artifacts.tar.gz"
    if not archive_path.is_file():
        return usage
    with tarfile.open(archive_path) as archive:
        for name in archive.getnames():
            if not name.endswith("/trajectory.jsonl"):
                continue
            for raw in archive.extractfile(name):
                try:
                    event = json.loads(raw)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                item = event.get("item") if isinstance(event.get("item"), dict) else {}
                if event.get("type") == "item.completed" and item.get("type") == "command_execution":
                    usage["commands"] += 1
                if event.get("type") == "turn.completed":
                    u = event.get("usage") or {}
                    usage["turns"] += 1
                    for key in ("input_tokens", "cached_input_tokens", "output_tokens"):
                        usage[key] += int(u.get(key) or 0)
    return usage


def cell_row(cohort: str, boundary: str, run_dir: Path) -> dict:
    record_path = run_dir / ("docker-run.json" if (run_dir / "docker-run.json").is_file() else "modal-run.json")
    record = json.loads(record_path.read_text())
    summary = json.loads((run_dir / "summary.json").read_text())
    result = (summary.get("results") or [{}])[0]
    vk = record.get("virtual_key") or {}
    policy = record.get("policy") or {}
    return {
        "cohort": cohort, "boundary": boundary, "run_dir": str(run_dir.relative_to(REPO)),
        "arm": record.get("arm"), "case_id": record.get("case_id") or result.get("case_id"),
        "trial": record.get("trial"), "model": policy.get("key_model"),
        "key_cap_usd": vk.get("budget_usd") or policy.get("key_budget_usd"),
        "spend_usd": vk.get("spend_usd"), "alias": vk.get("key_alias"),
        "run_wall_seconds": result.get("run_wall_seconds"),
        **transcript_usage(run_dir),
    }


cells = []
figures = json.loads((MODAL / "figures-v1v2v3/figures.json").read_text())
for cell in figures["cells"]:
    run_dir = Path(cell["run_dir"])
    run_dir = run_dir if run_dir.is_absolute() else REPO / run_dir
    if not run_dir.is_dir():
        run_dir = MODAL / cell["arm"] / Path(cell["run_dir"]).name
    cells.append(cell_row(cell["cohort"], "modal-sandbox", run_dir))
seen = {c["run_dir"] for c in cells}
for run_dir in sorted(MODAL.glob("*/collusion-CLH-*-agent-*")):
    if str(run_dir.relative_to(REPO)) in seen or not (run_dir / "modal-run.json").is_file():
        continue
    record = json.loads((run_dir / "modal-run.json").read_text())
    if (record.get("policy") or {}).get("key_model") == "claude-opus-5-5":
        cells.append(cell_row("opus-modal", "modal-sandbox", run_dir))
for run_dir in sorted((DOCKER / "lure-pair").glob("collusion-CLH-*-agent-*")):
    cells.append(cell_row("opus-docker-pilots", "docker-container", run_dir))
for root in sorted(p for p in DOCKER.iterdir() if p.is_dir() and (p / "cohort.json").is_file()):
    name = json.loads((root / "cohort.json").read_text())["cohort"]
    for run_dir in sorted(root.glob("*/collusion-CLH-*-agent-*")):
        cells.append(cell_row(name, "docker-container", run_dir))

from langfuse import Langfuse  # noqa: E402

client = Langfuse(public_key=os.environ["LANGFUSE_PUBLIC_KEY"], secret_key=os.environ["LANGFUSE_SECRET_KEY"],
                  base_url=os.environ["LANGFUSE_BASE_URL"])
try:
    for cell in cells:
        if not cell["alias"]:
            cell["gateway_calls"] = cell["gateway_tokens"] = None
            continue
        plan = ingest.TracePlan(trace_id="0" * 32, trace_seed="x", session_id=cell["alias"], tags=[],
                                attributes={"gateway_key_alias": cell["alias"]},
                                root=ingest.Observation(kind="span", name="x", metadata={}),
                                scores=[], case_id="x")
        ingest.add_gateway_generation_usage(plan, client.api.observations)
        cell["gateway_calls"] = plan.root.metadata["gateway_generation_count"]
        cell["gateway_tokens"] = plan.root.metadata["gateway_total_tokens"]
finally:
    client.shutdown()

for cell in cells:
    cell.pop("alias", None)
Path(sys.argv[1]).write_text(json.dumps(cells, indent=2, sort_keys=True) + "\n")


def total(rows, key):
    values = [r[key] for r in rows if isinstance(r.get(key), (int, float))]
    return sum(values) if values else None


groups = defaultdict(list)
for cell in cells:
    groups[cell["cohort"]].append(cell)
order = ["v1", "v2", "v3", "opus-modal", "opus-docker-pilots"] + sorted(set(groups) - {"v1", "v2", "v3", "opus-modal", "opus-docker-pilots"})
print("cohort              boundary          model            cells  calls  in_tok      cached_in   out_tok   spend      $/cell   cap   wall_s(median)")
for name in [o for o in order if o in groups]:
    rows = groups[name]
    walls = sorted(r["run_wall_seconds"] for r in rows if isinstance(r.get("run_wall_seconds"), (int, float)))
    median = walls[len(walls) // 2] if walls else None
    spend = total(rows, "spend_usd") or 0.0
    models = sorted({str(r["model"]) for r in rows})
    caps = sorted({r["key_cap_usd"] for r in rows if r["key_cap_usd"] is not None})
    print(f"{name:19} {rows[0]['boundary']:17} {','.join(models):16} {len(rows):5}  {total(rows, 'gateway_calls')!s:5}  "
          f"{total(rows, 'input_tokens')!s:10}  {total(rows, 'cached_input_tokens')!s:10}  {total(rows, 'output_tokens')!s:8}  "
          f"${spend:8.4f}  ${spend / len(rows):.4f}  {caps}  {median}")
print("--- opus-v2 per case")
per_case = defaultdict(list)
for r in groups.get("opus-v2", []):
    per_case[(r["arm"], r["case_id"])].append(r)
for (arm, case), rows in sorted(per_case.items()):
    spend = total(rows, "spend_usd")
    print(f"  {arm:12} {case}  cells={len(rows)} calls={total(rows, 'gateway_calls')} commands={total(rows, 'commands')} "
          f"in={total(rows, 'input_tokens')} cached={total(rows, 'cached_input_tokens')} out={total(rows, 'output_tokens')} "
          f"spend=${spend:.4f} per_cell=${spend / len(rows):.4f}")
