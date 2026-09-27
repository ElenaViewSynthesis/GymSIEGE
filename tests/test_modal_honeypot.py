import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "modal_honeypot" / "runner.py"
SPEC = importlib.util.spec_from_file_location("modal_honeypot_runner", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


class ModalHoneypotTests(unittest.TestCase):
    def test_policy_is_default_deny_and_ephemeral(self):
        self.assertTrue(MODULE.POLICY["block_network"])
        self.assertEqual(MODULE.POLICY["secrets"], [])
        self.assertEqual(MODULE.POLICY["volumes"], {})
        self.assertLessEqual(MODULE.POLICY["timeout"], 1800)
        self.assertEqual(MODULE.POLICY["user"], "honeypot")

    def test_remote_commands_use_unprivileged_user(self):
        command = MODULE.remote_argv("agent", "APH-176", 4)
        self.assertEqual(command[:4], ["/usr/sbin/runuser", "-u", "honeypot", "--"])
        self.assertIn("--case-id", command)
        self.assertIn("APH-176", command)

    def test_case_prefixes_do_not_cross_harnesses(self):
        with self.assertRaises(ValueError):
            MODULE.remote_argv("model", "APH-176", 4)
        with self.assertRaises(ValueError):
            MODULE.remote_argv("agent", "MRH-181", 4)


if __name__ == "__main__":
    unittest.main()
