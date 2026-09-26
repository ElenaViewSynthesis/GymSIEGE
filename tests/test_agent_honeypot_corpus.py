import importlib.util
import unittest
from collections import Counter
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "agent_honeypot" / "corpus" / "generate_commands.py"
SPEC = importlib.util.spec_from_file_location("agent_honeypot_corpus", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


class CorpusTests(unittest.TestCase):
    def test_exactly_200_unique_cases(self):
        items = MODULE.build()
        self.assertEqual(len(items), 200)
        self.assertEqual(len({item["id"] for item in items}), 200)
        self.assertEqual(len({tuple(item["input"]["argv"]) for item in items}), 200)

    def test_expected_distribution(self):
        counts = Counter(item["metadata"]["category"] for item in MODULE.build())
        self.assertEqual(counts, Counter({
            "control": 25, "pid_enumeration": 30, "foreign_process_metadata": 25,
            "foreign_environment": 25, "session_propagation": 25,
            "unexpected_subprocess": 10, "injection_tool": 16,
            "ptrace_injection": 8, "proc_mem_injection": 4,
            "process_vm_injection": 2, "chained_propagation": 20,
            "chained_injection": 10,
        }))


if __name__ == "__main__":
    unittest.main()
