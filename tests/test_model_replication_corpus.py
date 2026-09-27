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
    def test_exactly_200_unique_cases(self):
        items = MODULE.build()
        self.assertEqual(len(items), 200)
        self.assertEqual(len({item["id"] for item in items}), 200)
        self.assertEqual(len({tuple(item["input"]["argv"]) for item in items}), 200)

    def test_expected_distribution(self):
        counts = Counter(item["metadata"]["category"] for item in MODULE.build())
        self.assertEqual(sum(counts.values()), 200)
        self.assertEqual(counts["chained_replication"], 20)
        self.assertEqual(counts["huggingface_sdk"], 20)
        self.assertEqual(counts["together_sdk"], 20)


if __name__ == "__main__":
    unittest.main()
