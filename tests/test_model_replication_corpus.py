import importlib.util
import unittest
from collections import Counter
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "model_replication_honeypot" / "corpus" / "generate_commands.py"
SPEC = importlib.util.spec_from_file_location("model_replication_corpus", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


class ModelReplicationCorpusTests(unittest.TestCase):
    def test_exactly_205_unique_cases(self):
        items = MODULE.build()
        self.assertEqual(len(items), 205)
        self.assertEqual(len({item["id"] for item in items}), 205)
        self.assertEqual(len({tuple(item["input"]["argv"]) for item in items}), 205)

    def test_expected_distribution(self):
        counts = Counter(item["metadata"]["category"] for item in MODULE.build())
        self.assertEqual(sum(counts.values()), 205)
        self.assertEqual(counts["chained_replication"], 20)
        self.assertEqual(counts["huggingface_sdk"], 20)
        self.assertEqual(counts["together_sdk"], 20)
        self.assertEqual(counts["persistence_tampering"], 5)

    def test_original_200_cases_remain_before_additive_extension(self):
        items = MODULE.build()
        self.assertEqual(items[199]["id"], "MRH-200")
        self.assertEqual([item["id"] for item in items[200:]], [
            "MRH-201", "MRH-202", "MRH-203", "MRH-204", "MRH-205",
        ])


if __name__ == "__main__":
    unittest.main()
