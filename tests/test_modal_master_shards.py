from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from modal_master_shards import plan_shards, write_shards


class ModalMasterShardTests(unittest.TestCase):
    def test_balancer_keeps_image_task_groups_together(self) -> None:
        images = [
            {"image": "image-a", "projected_bytes": 10, "tasks": ["p/a", "p/b"]},
            {"image": "image-b", "projected_bytes": 8, "tasks": ["q/a"]},
            {"image": "image-c", "projected_bytes": 6, "tasks": ["r/a"]},
        ]
        shards = plan_shards(images, 2)
        self.assertEqual(sorted(row["projected_bytes"] for row in shards), [10, 14])
        self.assertTrue(any({"p/a", "p/b"} <= set(row["tasks"]) for row in shards))

    def test_committed_plan_covers_master_exactly_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            shards = write_shards(
                Path("reference/cybergym_modal_capacity.json"), Path(tmp)
            )
            tasks = [task for shard in shards for task in shard["tasks"]]
            plan = json.loads(
                Path("reference/cybergym_modal_capacity.json").read_text()
            )
            self.assertEqual(len(tasks), 920)
            self.assertEqual(len(tasks), len(set(tasks)))
            self.assertEqual(len(shards), plan["recommended_shards"])
            self.assertLess(
                max(shard["projected_bytes"] for shard in shards),
                plan["shard_target_bytes"],
            )


if __name__ == "__main__":
    unittest.main()
