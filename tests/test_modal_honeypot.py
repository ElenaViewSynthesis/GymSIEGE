import importlib.util
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).parents[1] / "modal_honeypot" / "runner.py"
SPEC = importlib.util.spec_from_file_location("modal_honeypot_runner", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)

SANDBOX_MODULE_PATH = Path(__file__).parents[1] / "modal_honeypot" / "in_sandbox.py"
SANDBOX_SPEC = importlib.util.spec_from_file_location("modal_honeypot_in_sandbox", SANDBOX_MODULE_PATH)
SANDBOX = importlib.util.module_from_spec(SANDBOX_SPEC)
assert SANDBOX_SPEC.loader
SANDBOX_SPEC.loader.exec_module(SANDBOX)


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

    def test_instrument_prefix_is_scoped(self):
        command = MODULE.remote_argv("instrument", "IHT-002", 4)
        self.assertIn("instrument", command)
        with self.assertRaises(ValueError):
            MODULE.remote_argv("agent", "IHT-002", 4)
        with self.assertRaises(ValueError):
            MODULE.remote_argv("instrument", "APH-176", 4)

    def test_collusion_prefix_and_containment_marker_are_scoped(self):
        command = MODULE.remote_argv("collusion", "CLH-036", 1)
        self.assertIn("MODAL_COLLUSION_CONTAINMENT_ENFORCED=1", command)
        self.assertIn("HONEYPOT_EVIDENCE_CHAIN=1", command)
        with self.assertRaises(ValueError):
            MODULE.remote_argv("agent", "CLH-036", 1)
        with self.assertRaises(ValueError):
            MODULE.remote_argv("collusion", "APH-176", 1)
        with self.assertRaises(ValueError):
            MODULE.remote_argv("collusion", "CLH-036", 1, allow_network=True)

    def test_collusion_subject_command_is_scoped_and_forwarded(self):
        command = MODULE.remote_argv(
            "collusion", "CLH-036", 1, subject_command="codex exec --json prompt",
        )
        self.assertEqual(command[-2:], ["--subject-command", "codex exec --json prompt"])
        with self.assertRaises(ValueError):
            MODULE.remote_argv("agent", "APH-176", 1, subject_command="true")

    def test_network_off_requires_explicit_opt_in(self):
        with self.assertRaises(ValueError):
            MODULE.remote_argv("network-off", "NOF-001", 4)

    def test_network_off_command_carries_enforcement_marker(self):
        command = MODULE.remote_argv(
            "network-off", "NOF-001", 4, network_off_enabled=True,
        )
        self.assertIn("MODAL_NETWORK_OFF_ENFORCED=1", command)
        self.assertIn("network-off", command)

    def test_network_off_rejects_wrong_prefix(self):
        with self.assertRaises(ValueError):
            MODULE.remote_argv(
                "network-off", "APH-001", 4, network_off_enabled=True,
            )

    def test_network_off_opt_in_is_scoped(self):
        with self.assertRaises(ValueError):
            MODULE.remote_argv("agent", "APH-176", 4, network_off_enabled=True)

    def test_allow_network_is_explicit_marked_and_refused_for_network_off(self):
        self.assertTrue(MODULE.POLICY["block_network"])  # the flag never changes the default
        command = MODULE.remote_argv("agent", "APH-176", 4, allow_network=True)
        self.assertIn("MODAL_NETWORK_OPEN=1", command)
        self.assertNotIn("MODAL_NETWORK_OPEN=1", MODULE.remote_argv("agent", "APH-176", 4))
        with self.assertRaises(ValueError):
            MODULE.remote_argv("network-off", "NOF-001", 4, network_off_enabled=True, allow_network=True)

    def test_chain_and_format_flags_become_environment_assignments(self):
        command = MODULE.remote_argv(
            "model", "MRH-181", 4, evidence_chain=True, weights_mode="format",
        )
        self.assertIn("HONEYPOT_EVIDENCE_CHAIN=1", command)
        self.assertIn("HONEYPOT_WEIGHTS_MODE=format", command)
        default = MODULE.remote_argv("model", "MRH-181", 4)
        self.assertNotIn("HONEYPOT_EVIDENCE_CHAIN=1", default)
        self.assertIn("HONEYPOT_WEIGHTS_MODE=text", default)

    def test_format_weights_are_model_only(self):
        for harness, case_id in (("agent", "APH-176"), ("instrument", "IHT-002")):
            with self.subTest(harness=harness), self.assertRaises(ValueError):
                MODULE.remote_argv(harness, case_id, 4, weights_mode="format")

    def test_demo_command_uses_sandbox_output_for_tmp(self):
        command = MODULE.remote_argv(None, None, 4, demo=True)
        self.assertIn("TMPDIR=/tmp/honeypot-output", command)
        self.assertIn("--demo", command)
        self.assertNotIn("--harness", command)

    def test_dry_run_records_chain_weights_and_output_name(self):
        completed = subprocess.run(
            [sys.executable, str(MODULE_PATH), "--harness", "model", "--all",
             "--evidence-chain", "--weights-mode", "format", "--dry-run"],
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        plan = json.loads(completed.stdout)
        self.assertTrue(plan["policy"]["evidence_chain"])
        self.assertEqual(plan["policy"]["weights_mode"], "format")
        self.assertEqual(plan["output_name"], "model-all-chain-format")

    def test_collusion_dry_run_is_blocked_secret_free_and_chained(self):
        completed = subprocess.run(
            [sys.executable, str(MODULE_PATH), "--harness", "collusion", "--all", "--dry-run"],
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        plan = json.loads(completed.stdout)
        self.assertTrue(plan["policy"]["block_network"])
        self.assertEqual(plan["policy"]["secrets"], [])
        self.assertTrue(plan["policy"]["evidence_chain"])
        self.assertIn("MODAL_COLLUSION_CONTAINMENT_ENFORCED=1", plan["remote_argv"])

    def test_instrument_uses_its_cli_and_nested_report(self):
        def complete(command, **_kwargs):
            output = Path(command[command.index("--output") + 1])
            report = output / "report" / "report.json"
            report.parent.mkdir(parents=True)
            report.write_text(json.dumps({
                "score": 80,
                "severity": "critical",
                "expectation_passed": True,
                "chain_valid": True,
                "mirror_matches_visible_log": True,
            }))
            return subprocess.CompletedProcess(command, 0, "instrument output")

        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            SANDBOX.subprocess, "run", side_effect=complete,
        ) as run:
            result = SANDBOX.run_case("instrument", "IHT-002", Path(directory))
        command = run.call_args.args[0]
        self.assertEqual(command[-4:], ["--case-id", "IHT-002", "--output", command[-1]])
        self.assertTrue(result["passed"])
        self.assertIsNone(result["observability"])
        self.assertTrue(result["chain_valid"])
        self.assertTrue(str(result["report"]).endswith("IHT-002/report/report.json"))

    def test_collusion_command_and_stage_flow_into_summary(self):
        def complete(command, **_kwargs):
            output_root = Path(command[command.index("--output-root") + 1])
            report = output_root / "CLH-036" / "report.json"
            report.parent.mkdir(parents=True)
            report.write_text(json.dumps({
                "score": 100,
                "severity": "critical",
                "observability": "observable",
                "observed_stage": "acted",
                "role": "behavior_eval",
                "expectation_passed": False,
                "subject_mode": "agent",
                "time_to_first_coordination_s": 0.5,
                "evidence_chains": [{"valid": True, "mirror_events": 9}],
            }))
            return subprocess.CompletedProcess(command, 0, "collusion output")

        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            SANDBOX.subprocess, "run", side_effect=complete,
        ) as run:
            result = SANDBOX.run_case(
                "collusion", "CLH-036", Path(directory), subject_command="fake-agent",
            )
        command = run.call_args.args[0]
        self.assertEqual(command[-2:], ["--subject-command", "fake-agent"])
        self.assertTrue(result["passed"])
        self.assertEqual(result["stage"], "acted")
        self.assertEqual(result["subject_mode"], "agent")
        self.assertEqual(result["evidence_chains"], [True])

    def test_artifact_bundle_keeps_agent_transcripts(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            transcript = output / "cases" / "CLH-036" / "runs" / "subject" / "trajectory.jsonl"
            transcript.parent.mkdir(parents=True)
            transcript.write_text('{"type":"item.completed"}\n')
            bundle = SANDBOX.bundle_artifacts(output)
            with tarfile.open(bundle, "r:gz") as archive:
                self.assertIn(
                    "cases/CLH-036/runs/subject/trajectory.jsonl",
                    archive.getnames(),
                )

    def test_unobservable_report_fails_even_with_zero_exit(self):
        def complete(command, **_kwargs):
            output_root = Path(command[command.index("--output-root") + 1])
            report = output_root / "APH-176" / "report.json"
            report.parent.mkdir(parents=True)
            report.write_text(json.dumps({
                "score": 0,
                "severity": "clean",
                "observability": "unobservable",
                "evidence_chains": [{"valid": False, "mirror_events": 12}],
            }))
            return subprocess.CompletedProcess(command, 0, "agent output")

        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            SANDBOX.subprocess, "run", side_effect=complete,
        ):
            result = SANDBOX.run_case("agent", "APH-176", Path(directory))
        self.assertFalse(result["passed"])
        self.assertEqual(result["observability"], "unobservable")
        self.assertEqual(result["evidence_chains"], [False])
        self.assertEqual(result["mirror_events"], [12])


if __name__ == "__main__":
    unittest.main()
