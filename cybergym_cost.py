#!/usr/bin/env python3
"""Backfill ``solver_cost_usd`` for CyberGym Modal trial result JSONs.

Upstream ``scripts/run_agent.py`` authenticates its ``/key/info`` usage lookup
with the per-trial CHILD key, which lacks key-info permission, so that call
raises and ``summary.json`` never gets a ``litellm_api_key_usage`` block --
leaving ``solver_cost_usd`` null even on a successful, real-spend trial. This
script fills it deterministically from the Codex trajectory's cumulative
``turn.completed`` usage event and the operator-maintained per-token rate map
(``exploitbench/model_prices.json``, which already holds gpt-5.6-luna /
gpt-5.6-sol). No rate is ever invented: a model with no rate entry is left as-is,
and a result that already carries a cost is never overwritten.

Usage:
  python cybergym_cost.py --results-dir results/modal_trials \\
      --artifacts-dir artifacts [--model gpt-5.6-luna] [--prices PATH]
"""
from __future__ import annotations

import argparse
import glob
import json
import sys
from pathlib import Path
from typing import Any, Optional

DEFAULT_PRICES = Path(__file__).resolve().parent / "exploitbench" / "model_prices.json"
DEFAULT_MODEL = "gpt-5.6-luna"  # solver_agent.ModelConfig's default litellm_model_id


def load_prices(path: str | Path) -> dict[str, dict[str, float]]:
    """Read the per-token rate map. Missing/corrupt file -> empty (not fatal)."""
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return {k: v for k, v in raw.items() if not k.startswith("_") and isinstance(v, dict)}


def rates_for(prices: dict[str, dict[str, float]], model: str) -> Optional[dict[str, float]]:
    """Match the full model name or its last path segment (openai/x -> x)."""
    for key in (model, model.split("/")[-1]):
        if key in prices:
            return prices[key]
    return None


def parse_trajectory_usage(path: str | Path) -> Optional[dict[str, Any]]:
    """Return the last ``turn.completed`` ``usage`` object in a Codex JSONL log."""
    usage: Optional[dict[str, Any]] = None
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if '"turn.completed"' not in line or '"usage"' not in line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if obj.get("type") == "turn.completed" and isinstance(obj.get("usage"), dict):
                    usage = obj["usage"]  # cumulative; the final one wins
    except OSError:
        return None
    return usage


def compute_cost(usage: dict[str, Any], rates: dict[str, float]) -> float:
    """Price Codex token usage. ``input_tokens`` is the TOTAL; the cached subset
    is billed at ``cache_read`` and the remainder at ``input``."""
    total_in = int(usage.get("input_tokens") or 0)
    cached = int(usage.get("cached_input_tokens") or 0)
    out = int(usage.get("output_tokens") or 0)
    uncached = max(total_in - cached, 0)
    input_rate = float(rates.get("input", 0.0))
    cache_read = float(rates.get("cache_read", input_rate))
    output_rate = float(rates.get("output", 0.0))
    return uncached * input_rate + cached * cache_read + out * output_rate


def find_trajectory(artifacts_dir: str | Path, result: dict[str, Any]) -> Optional[str]:
    """Locate the trial's Codex trajectory: prefer the recorded local path, fall
    back to the deterministic ``<safe>/<mode>/trial-N/trajectory_attempt_*.log``."""
    for p in result.get("trajectory_local_paths") or []:
        if p and Path(p).is_file():
            return p
    safe = str(result.get("task", "")).replace("/", "_")
    mode = result.get("mode") or "patch-only"
    trial = result.get("trial")
    trial_glob = f"trial-{trial}" if trial is not None else "trial-*"
    patt = str(Path(artifacts_dir) / safe / mode / trial_glob / "trajectory_attempt_*.log")
    matches = sorted(glob.glob(patt))
    return matches[-1] if matches else None


def backfill_file(
    result_path: str | Path,
    artifacts_dir: str | Path,
    prices: dict[str, dict[str, float]],
    model: str,
) -> str:
    """Fill one result JSON's cost in place. Returns a short status string."""
    try:
        result = json.loads(Path(result_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "unreadable"
    if result.get("solver_cost_usd") is not None:
        return "already-costed"
    traj = find_trajectory(artifacts_dir, result)
    if not traj:
        return "no-trajectory"
    usage = parse_trajectory_usage(traj)
    if not usage:
        return "no-usage"
    rates = rates_for(prices, model)
    if not rates:
        return f"no-rate:{model}"
    cost = compute_cost(usage, rates)
    result["solver_cost_usd"] = round(cost, 6)
    if result.get("solver_usage") is None:
        result["solver_usage"] = {
            "source": "trajectory.turn.completed",
            "model": model,
            **{k: usage.get(k) for k in ("input_tokens", "cached_input_tokens", "output_tokens")},
        }
    Path(result_path).write_text(json.dumps(result, indent=2), encoding="utf-8")
    return f"filled:${cost:.4f}"


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Backfill solver_cost_usd for CyberGym trial JSONs.")
    ap.add_argument("--results-dir", default="results/modal_trials")
    ap.add_argument("--artifacts-dir", default="artifacts")
    ap.add_argument("--model", default=DEFAULT_MODEL, help="model whose rates price the tokens")
    ap.add_argument("--prices", default=str(DEFAULT_PRICES))
    args = ap.parse_args(argv)

    prices = load_prices(args.prices)
    for rp in sorted(glob.glob(str(Path(args.results_dir) / "*.json"))):
        print(f"{Path(rp).name}: {backfill_file(rp, args.artifacts_dir, prices, args.model)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
