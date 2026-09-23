#!/usr/bin/env python3
"""Materialize and validate the measured 920-task Modal shard plan."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


DEFAULT_PLAN = Path("reference/cybergym_modal_capacity.json")
DEFAULT_OUTPUT = Path("txt/modal_master_shards")


def plan_shards(images: list[dict], shard_count: int) -> list[dict]:
    """Keep tasks sharing an image together and balance projected bytes."""
    if shard_count < 1:
        raise ValueError("shard_count must be positive")
    shards = [{"projected_bytes": 0, "images": [], "tasks": []} for _ in range(shard_count)]
    ordered = sorted(images, key=lambda row: (-row["projected_bytes"], row["image"]))
    for image in ordered:
        shard = min(
            enumerate(shards),
            key=lambda pair: (pair[1]["projected_bytes"], pair[0]),
        )[1]
        shard["projected_bytes"] += image["projected_bytes"]
        shard["images"].append(image["image"])
        shard["tasks"].extend(image["tasks"])
    for shard in shards:
        shard["images"].sort()
        shard["tasks"].sort()
    return shards


def validate_plan(plan: dict, master_tasks: list[str], shards: list[dict]) -> None:
    planned = [task for shard in shards for task in shard["tasks"]]
    if len(planned) != len(set(planned)):
        raise ValueError("shard plan contains duplicate tasks")
    if set(planned) != set(master_tasks):
        missing = sorted(set(master_tasks) - set(planned))
        extra = sorted(set(planned) - set(master_tasks))
        raise ValueError(f"shard coverage mismatch: missing={missing[:3]}, extra={extra[:3]}")
    cap = plan["modal_disk_cap_bytes"]
    target = plan["shard_target_bytes"]
    oversized = [row["projected_bytes"] for row in shards if row["projected_bytes"] > target]
    if oversized:
        raise ValueError(
            f"{len(oversized)} shard(s) exceed the {target}-byte planning target "
            f"for the {cap}-byte Modal disk cap"
        )


def write_shards(plan_path: Path, output_dir: Path) -> list[dict]:
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    master_path = Path(plan["master_tasks_file"])
    master_tasks = [
        line.split("#", 1)[0].strip()
        for line in master_path.read_text(encoding="utf-8").splitlines()
        if line.split("#", 1)[0].strip()
    ]
    shards = plan_shards(plan["images"], plan["recommended_shards"])
    validate_plan(plan, master_tasks, shards)
    output_dir.mkdir(parents=True, exist_ok=True)
    for number, shard in enumerate(shards, 1):
        path = output_dir / f"shard-{number:02d}.txt"
        header = (
            f"# CyberGym master shard {number:02d}/{len(shards)}\n"
            f"# source_rev: {plan['source_rev']}\n"
            f"# dataset_rev: {plan['dataset_rev']}\n"
            f"# projected_bytes: {shard['projected_bytes']}\n"
            f"# images: {len(shard['images'])}; tasks: {len(shard['tasks'])}\n"
        )
        path.write_text(header + "\n".join(shard["tasks"]) + "\n", encoding="utf-8")
    return shards


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    shards = write_shards(args.plan, args.output_dir)
    for number, shard in enumerate(shards, 1):
        print(
            f"{number:02d}: {len(shard['tasks'])} tasks, {len(shard['images'])} images, "
            f"{shard['projected_bytes'] / 1e9:.3f} GB projected"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
