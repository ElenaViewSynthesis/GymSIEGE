import contextlib
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from modal_honeypot.virtual_key import VirtualKeyError


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

FAKE_VIRTUAL_KEY = "".join(("s", "k", "-", "unit_virtual_key_12345678"))


class FakeLiteLLMClient:
    def __init__(self):
        self.calls = []

    def generate(self, payload):
        self.calls.append(("generate", dict(payload)))
        return {"key": FAKE_VIRTUAL_KEY, "token_id": "f" * 64}

    def info(self, key_id):
        self.calls.append(("info", key_id))
        return {"info": {"spend": 0.0125}}

    def delete(self, key_id):
        self.calls.append(("delete", key_id))
        return {"deleted_keys": [key_id]}


class ModalHoneypotTests(unittest.TestCase):
    def _runner_args(self, output, **overrides):
        values = {
            "demo": False, "harness": "collusion", "case_id": "CLH-037",
            "enable_network_off_suite": False, "allow_network": False,
            "egress_allowlist": "langfuse,gateway", "weights_mode": "text",
            "subject_command": "fake-agent", "evidence_chain": False,
            "sandbox_timeout": 1800, "exec_timeout": 1500,
            "agent_timeout": 900, "workers": 1,
            "app_name": "fake-app", "output": Path(output), "dry_run": False,
            "model": "pinned-model", "key_budget": 0.50, "key_ttl": "35m",
            "arm": "lure-pair", "trial": 2,
        }
        values.update(overrides)
        return SimpleNamespace(**values)

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
            model="pinned-model",
        )
        self.assertEqual(command[-4:], [
            "--subject-command", "codex exec --json prompt", "--agent-timeout", "900",
        ])
        self.assertIn("--preserve-environment", command[:5])
        self.assertIn("HONEYPOT_CODEX_MODEL=pinned-model", command)
        self.assertNotIn("--preserve-environment", MODULE.remote_argv("collusion", "CLH-036", 1))
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
                "observe_only": True,
                "agent_timeout_seconds": 900,
                "verifier": {"status": "implemented", "kind": "sha256_of_file", "passed": False},
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
        self.assertEqual(command[-4:], [
            "--subject-command", "fake-agent", "--agent-timeout", "900",
        ])
        self.assertTrue(result["passed"])
        self.assertEqual(result["stage"], "acted")
        self.assertEqual(result["subject_mode"], "agent")
        self.assertTrue(result["observe_only"])
        self.assertEqual(result["agent_timeout_seconds"], 900)
        self.assertRegex(result["run_started_at"], r"^\d{4}-\d{2}-\d{2}T")
        self.assertIsInstance(result["run_wall_seconds"], float)
        self.assertGreaterEqual(result["run_wall_seconds"], 0.0)
        self.assertEqual(result["verifier"], {
            "status": "implemented", "kind": "sha256_of_file", "passed": False,
        })
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

    def test_egress_allowlist_resolves_langfuse_host_and_rejects_widening(self):
        with mock.patch.dict(os.environ, {"LANGFUSE_BASE_URL": "https://cloud.langfuse.com/"}):
            self.assertEqual(MODULE.resolve_egress_allowlist("langfuse"), ["cloud.langfuse.com"])
            self.assertEqual(
                MODULE.resolve_egress_allowlist("Langfuse-Proxy.example.org, langfuse"),
                ["cloud.langfuse.com", "langfuse-proxy.example.org"],
            )
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                MODULE.resolve_egress_allowlist("langfuse")
        for bad in ("*", "https://cloud.langfuse.com", "host:443", " , "):
            with self.assertRaises(ValueError):
                MODULE.resolve_egress_allowlist(bad)
        self.assertIsNone(MODULE.resolve_egress_allowlist(None))

    def test_egress_allowlist_is_scoped_marked_and_refused_where_it_must_be(self):
        hosts = ["cloud.langfuse.com"]
        # permitted for collusion (scoped egress), exported to the sandbox, never open
        command = MODULE.remote_argv("collusion", "CLH-036", 1, egress_allowlist=hosts)
        self.assertIn("MODAL_NETWORK_ALLOWLIST=cloud.langfuse.com", command)
        self.assertNotIn("MODAL_NETWORK_OPEN=1", command)
        self.assertIn("MODAL_COLLUSION_CONTAINMENT_ENFORCED=1", command)
        # refused with open egress and with the network-off suite
        with self.assertRaises(ValueError):
            MODULE.remote_argv("agent", "APH-001", 1, allow_network=True, egress_allowlist=hosts)
        with self.assertRaises(ValueError):
            MODULE.remote_argv("network-off", "NOF-001", 1, network_off_enabled=True,
                               egress_allowlist=hosts)
        # the output directory records it
        name = MODULE.output_name("collusion", "CLH-036", demo=False, evidence_chain=True,
                                  weights_mode="text", allow_network=False,
                                  egress_allowlist=hosts)
        self.assertTrue(name.endswith("-net-allow"), name)
        # open egress still refused for collusion
        with self.assertRaises(ValueError):
            MODULE.remote_argv("collusion", "CLH-036", 1, allow_network=True)

    def test_egress_allowlist_dry_run_policy(self):
        env = {**os.environ, "LANGFUSE_BASE_URL": "https://cloud.langfuse.com"}
        completed = subprocess.run(
            [sys.executable, str(MODULE_PATH), "--harness", "collusion", "--case-id", "CLH-037",
             "--egress-allowlist", "langfuse", "--dry-run"],
            capture_output=True, text=True, env=env, check=True,
        )
        plan = json.loads(completed.stdout)
        policy = plan["policy"]
        self.assertFalse(policy["block_network"])
        self.assertEqual(policy["egress"], "allowlist")
        self.assertEqual(policy["egress_allowlist"], ["cloud.langfuse.com"])
        self.assertEqual(policy["secrets"], [])
        self.assertTrue(policy["evidence_chain"])
        self.assertIn("MODAL_NETWORK_ALLOWLIST=cloud.langfuse.com", plan["remote_argv"])
        self.assertTrue(plan["output_name"].endswith("-net-allow"))
        self.assertIn("--egress-allowlist", completed.stderr)  # the warning names the mode
        # combined with open egress: refused on a harness where --allow-network alone is legal
        refused = subprocess.run(
            [sys.executable, str(MODULE_PATH), "--harness", "agent", "--case-id", "APH-001",
             "--egress-allowlist", "langfuse", "--allow-network", "--dry-run"],
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(refused.returncode, 2)
        self.assertIn("cannot be combined with --allow-network", refused.stderr)
        # and for collusion the open-egress refusal fires first, so it never gets that far
        refused = subprocess.run(
            [sys.executable, str(MODULE_PATH), "--harness", "collusion", "--case-id", "CLH-037",
             "--egress-allowlist", "langfuse", "--allow-network", "--dry-run"],
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(refused.returncode, 2)
        self.assertIn("--allow-network cannot be combined with --harness collusion", refused.stderr)

    def test_egress_allowlist_gateway_token_precedence_and_loopback_refusal(self):
        with mock.patch.dict(os.environ, {"OPENAI_BASE_URL": "https://tunnel.example.ngrok.app/v1",
                                          "LITELLM_BASE_URL": "http://localhost:4000"}, clear=True):
            self.assertEqual(MODULE.resolve_egress_allowlist("gateway"), ["tunnel.example.ngrok.app"])
        with mock.patch.dict(os.environ, {"OPENAI_API_BASE": "https://Alt.Example.org/v1"}, clear=True):
            self.assertEqual(MODULE.resolve_egress_allowlist("gateway"), ["alt.example.org"])
        with mock.patch.dict(os.environ, {"LITELLM_BASE_URL": "https://gw.example.org"}, clear=True):
            self.assertEqual(MODULE.resolve_egress_allowlist("gateway"), ["gw.example.org"])
        for loopback in ("http://localhost:4000/v1", "http://127.0.0.1:4000", "http://0.0.0.0:4000"):
            with mock.patch.dict(os.environ, {"OPENAI_BASE_URL": loopback}, clear=True):
                with self.assertRaises(ValueError):
                    MODULE.resolve_egress_allowlist("gateway")
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                MODULE.resolve_egress_allowlist("gateway")
        with mock.patch.dict(os.environ, {"LANGFUSE_BASE_URL": "https://cloud.langfuse.com",
                                          "OPENAI_BASE_URL": "https://tunnel.example.ngrok.app/v1"},
                             clear=True):
            self.assertEqual(MODULE.resolve_egress_allowlist("langfuse,gateway"),
                             ["cloud.langfuse.com", "tunnel.example.ngrok.app"])

    def test_real_agent_egress_recipe_and_reachability_warnings(self):
        env = {**os.environ, "LANGFUSE_BASE_URL": "https://cloud.langfuse.com",
               "OPENAI_BASE_URL": "https://tunnel.example.ngrok.app/v1"}
        base = [sys.executable, str(MODULE_PATH), "--harness", "collusion", "--case-id", "CLH-036",
                "--subject-command", "echo hi", "--dry-run"]
        # the recipe: both hosts, no reachability warning
        done = subprocess.run(base + ["--egress-allowlist", "langfuse,gateway"],
                              capture_output=True, text=True, env=env, check=True)
        plan = json.loads(done.stdout)
        self.assertFalse(plan["policy"]["block_network"])
        self.assertEqual(plan["policy"]["egress_allowlist"],
                         ["cloud.langfuse.com", "tunnel.example.ngrok.app"])
        self.assertEqual(len(plan["policy"]["secrets"]), 1)
        self.assertTrue(plan["policy"]["secrets"][0].startswith("virtual-key:collusion/CLH-036/t1/"))
        self.assertEqual(plan["policy"]["key_budget_usd"], 0.50)
        self.assertEqual(plan["policy"]["key_ttl"], "35m")
        self.assertNotIn(FAKE_VIRTUAL_KEY, done.stdout + done.stderr)
        self.assertIn("MODAL_NETWORK_ALLOWLIST=cloud.langfuse.com,tunnel.example.ngrok.app",
                      plan["remote_argv"])
        self.assertNotIn("cannot reach the model gateway", done.stderr)
        self.assertNotIn("not in --egress-allowlist", done.stderr)
        # Langfuse only with a real agent: warned, not refused
        done = subprocess.run(base + ["--egress-allowlist", "langfuse"],
                              capture_output=True, text=True, env=env, check=True)
        self.assertIn("not in --egress-allowlist", done.stderr)
        # default blocked with a real agent: warned, not refused
        done = subprocess.run(base, capture_output=True, text=True, env=env, check=True)
        self.assertTrue(json.loads(done.stdout)["policy"]["block_network"])
        self.assertIn("cannot reach the model gateway", done.stderr)

    def test_virtual_key_preconditions_are_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self._runner_args(directory)
            hosts = ["cloud.langfuse.com", "tunnel.example.org"]
            env = {
                "OPENAI_BASE_URL": "https://tunnel.example.org/v1",
                "LANGFUSE_BASE_URL": "https://cloud.langfuse.com",
                "LITELLM_MASTER_KEY": "master-for-unit-test",
            }
            with mock.patch.dict(os.environ, env, clear=True):
                self.assertEqual(
                    MODULE.validate_virtual_key_preconditions(args, hosts),
                    "https://tunnel.example.org/v1",
                )
                args.subject_command = None
                with self.assertRaisesRegex(ValueError, "requires --subject-command"):
                    MODULE.validate_virtual_key_preconditions(args, hosts)
                args.subject_command = "fake-agent"
                args.egress_allowlist = "langfuse"
                with self.assertRaisesRegex(ValueError, "gateway token"):
                    MODULE.validate_virtual_key_preconditions(args, ["cloud.langfuse.com"])
                args.egress_allowlist = "langfuse,gateway"
                args.model = None
                with self.assertRaisesRegex(ValueError, "requires --model"):
                    MODULE.validate_virtual_key_preconditions(args, hosts)
                args.model = "pinned-model"
                args.key_ttl = "30m"
                with self.assertRaisesRegex(ValueError, "longer than --sandbox-timeout"):
                    MODULE.validate_virtual_key_preconditions(args, hosts)
                args.key_ttl = "35m"

            with mock.patch.dict(os.environ, {
                "OPENAI_BASE_URL": "https://tunnel.example.org/v1",
                "LANGFUSE_BASE_URL": "https://cloud.langfuse.com",
            }, clear=True):
                with self.assertRaisesRegex(ValueError, "LITELLM_MASTER_KEY"):
                    MODULE.validate_virtual_key_preconditions(args, hosts)
            with mock.patch.dict(os.environ, {
                "OPENAI_BASE_URL": "http://127.0.0.1:4000/v1",
                "LITELLM_MASTER_KEY": "master-for-unit-test",
            }, clear=True):
                with self.assertRaisesRegex(ValueError, "cannot reach"):
                    MODULE.validate_virtual_key_preconditions(args, ["127.0.0.1"])

    def test_agent_dry_run_describes_key_but_never_mints(self):
        client = FakeLiteLLMClient()
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {
            "OPENAI_BASE_URL": "https://tunnel.example.org/v1",
            "LANGFUSE_BASE_URL": "https://cloud.langfuse.com",
        }, clear=True), contextlib.redirect_stdout(io.StringIO()) as stdout:
            result = MODULE.run(
                self._runner_args(directory, dry_run=True),
                modal_module=object(), admin_client=client,
            )
        self.assertEqual(result, 0)
        self.assertEqual(client.calls, [])
        plan = json.loads(stdout.getvalue())
        self.assertEqual(len(plan["policy"]["secrets"]), 1)
        serialized = json.dumps(plan)
        self.assertNotIn(FAKE_VIRTUAL_KEY, serialized)
        self.assertNotIn(FAKE_VIRTUAL_KEY, json.dumps(plan["remote_argv"]))
        with tempfile.TemporaryDirectory() as directory:
            plan_path = Path(directory) / "dry-run.json"
            plan_path.write_text(serialized)
            self.assertEqual(MODULE.scan_for_secret([plan_path], FAKE_VIRTUAL_KEY), [])

    def test_fake_key_lifecycle_secret_delivery_and_exec_failure_revocation(self):
        client = FakeLiteLLMClient()
        captured = {}

        class FakeProcess:
            stdout = io.StringIO("remote output")
            stderr = io.StringIO("remote error")
            returncode = 1

            def wait(self):
                return self.returncode

        class FakeFilesystem:
            def copy_to_local(self, remote, local):
                local = Path(local)
                if remote.endswith("summary.json"):
                    local.write_text('{"passed":false}\n')
                else:
                    with tarfile.open(local, "w:gz"):
                        pass

        class FakeSandbox:
            object_id = "sb-unit-test"
            filesystem = FakeFilesystem()

            def exec(self, *command, **kwargs):
                captured["command"] = command
                captured["exec_kwargs"] = kwargs
                return FakeProcess()

            def terminate(self, wait=True):
                captured["terminated"] = wait
                return 0

            def detach(self):
                captured["detached"] = True

        class FakeSecret:
            @staticmethod
            def from_dict(values):
                captured["secret"] = dict(values)
                return object()

        class FakeModal:
            Secret = FakeSecret

            class App:
                @staticmethod
                def lookup(name, create_if_missing=False):
                    return object()

            class Sandbox:
                @staticmethod
                def create(*command, **kwargs):
                    captured["sandbox_command"] = command
                    captured["sandbox_kwargs"] = kwargs
                    return FakeSandbox()

            @staticmethod
            def enable_output():
                return contextlib.nullcontext()

        env = {
            "OPENAI_BASE_URL": "https://tunnel.example.org/v1",
            "LANGFUSE_BASE_URL": "https://cloud.langfuse.com",
            "LITELLM_MASTER_KEY": "master-for-unit-test",
        }
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            os.environ, env, clear=True,
        ), mock.patch.object(MODULE, "build_image", return_value=object()), contextlib.redirect_stdout(io.StringIO()):
            result = MODULE.run(
                self._runner_args(directory), modal_module=FakeModal, admin_client=client,
            )
            metadata_path = next(Path(directory).glob("*/modal-run.json"))
            metadata_text = metadata_path.read_text()
            metadata = json.loads(metadata_text)

        self.assertEqual(result, 1)
        generate = client.calls[0]
        self.assertEqual(generate[0], "generate")
        payload = generate[1]
        self.assertEqual(payload["models"], ["pinned-model"])
        self.assertEqual(payload["max_budget"], 0.50)
        self.assertEqual(payload["duration"], "35m")
        # LiteLLM gates key tags behind an Enterprise license; the mint must not send them.
        self.assertNotIn("tags", payload)
        self.assertEqual(payload["metadata"]["trial"], 2)
        self.assertEqual(payload["metadata"]["arm"], "lure-pair")
        self.assertEqual(payload["metadata"]["run_id"], payload["key_alias"])
        self.assertEqual(captured["secret"], {
            "OPENAI_API_KEY": FAKE_VIRTUAL_KEY,
            "OPENAI_BASE_URL": "https://tunnel.example.org/v1",
        })
        self.assertEqual(len(captured["sandbox_kwargs"]["secrets"]), 1)
        self.assertNotIn(FAKE_VIRTUAL_KEY, json.dumps(captured["command"]))
        self.assertEqual(client.calls[-2:], [
            ("info", "f" * 64), ("delete", "f" * 64),
        ])
        self.assertNotIn(FAKE_VIRTUAL_KEY, json.dumps(client.calls))
        self.assertTrue(captured["terminated"])
        self.assertTrue(captured["detached"])
        self.assertEqual(metadata["virtual_key"]["spend_usd"], 0.0125)
        self.assertIn("revoked_at", metadata["virtual_key"])
        self.assertTrue(metadata["redaction"]["passed"])
        self.assertNotIn(FAKE_VIRTUAL_KEY, metadata_text)

    def test_key_lifecycle_falls_back_to_sha256_when_token_id_is_absent(self):
        class FakeClient(FakeLiteLLMClient):
            def generate(self, payload):
                self.calls.append(("generate", dict(payload)))
                return {"key": FAKE_VIRTUAL_KEY}

        client = FakeClient()
        minted = MODULE.mint_virtual_key(
            client, alias="collusion/CLH-037/t1/stamp", model="pinned-model",
            budget_usd=0.50, ttl="35m", metadata={"purpose": "unit-test"},
        )
        self.assertEqual(
            minted.management_id,
            hashlib.sha256(FAKE_VIRTUAL_KEY.encode()).hexdigest(),
        )
        MODULE.key_spend(client, minted.management_id)
        MODULE.revoke_virtual_key(client, minted.management_id)
        self.assertEqual(client.calls[-2:], [
            ("info", minted.management_id), ("delete", minted.management_id),
        ])
        self.assertNotIn(FAKE_VIRTUAL_KEY, json.dumps(client.calls))

    def test_key_spend_rejects_plaintext_identifier_before_request(self):
        client = FakeLiteLLMClient()
        with self.assertRaises(VirtualKeyError):
            MODULE.key_spend(client, FAKE_VIRTUAL_KEY)
        self.assertEqual(client.calls, [])

    def test_redaction_scanner_checks_plain_files_and_archives(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clean = root / "clean.json"
            clean.write_text('{"ok":true}\n')
            self.assertEqual(MODULE.scan_for_secret([root], FAKE_VIRTUAL_KEY), [])
            leaked = root / "remote.stdout.log"
            leaked.write_text("credential=" + FAKE_VIRTUAL_KEY)
            self.assertEqual(MODULE.scan_for_secret([leaked], FAKE_VIRTUAL_KEY), [leaked])
            leaked.unlink()
            # A truncated copy of the key (its leading bytes) is still the key.
            source = root / "trajectory.jsonl"
            source.write_text("OPENAI_API_KEY=" + FAKE_VIRTUAL_KEY[:17] + "...")
            bundle = root / "artifacts.tar.gz"
            with tarfile.open(bundle, "w:gz") as archive:
                archive.add(source, arcname="trajectory.jsonl")
            source.unlink()
            self.assertEqual(MODULE.scan_for_secret([bundle], FAKE_VIRTUAL_KEY), [bundle])
            bundle.unlink()
            # An unrelated key-shaped literal (a fixture or decoy the agent read)
            # is recorded, not a finding: the fourth CLH-036 attempt was stopped
            # by exactly such a token from a test file.
            source.write_text("assert " + "".join(("s", "k", "-", "another_key_87654321")) + " not in report")
            with tarfile.open(bundle, "w:gz") as archive:
                archive.add(source, arcname="trajectory.jsonl")
            source.unlink()
            scan = MODULE.scan_artifacts([bundle], FAKE_VIRTUAL_KEY)
            self.assertEqual(scan["findings"], [])
            self.assertEqual(scan["key_shaped_tokens"], [bundle])
            self.assertEqual(MODULE.scan_for_secret([bundle], FAKE_VIRTUAL_KEY), [])

    def test_image_build_contains_runuser_environment_assertion(self):
        class Builder:
            def __init__(self):
                self.commands = []
                self.packages = []

            def apt_install(self, *args):
                self.packages.extend(args)
                return self

            def run_commands(self, *args):
                self.commands.extend(args)
                return self

            def add_local_dir(self, *args, **kwargs):
                return self

        builder = Builder()
        fake_modal = SimpleNamespace(Image=SimpleNamespace(
            debian_slim=lambda **kwargs: builder,
        ))
        MODULE.build_image(fake_modal, verify_secret_environment=True)
        self.assertTrue(any(
            "MODAL_SECRET_ENV_PROBE=preserved" in command
            and "runuser -u honeypot --preserve-environment" in command
            for command in builder.commands
        ))
        self.assertIn("nodejs", builder.packages)
        self.assertIn("npm", builder.packages)
        self.assertTrue(any(
            f"@openai/codex@{MODULE.CODEX_VERSION}" in command
            for command in builder.commands
        ))

    def test_scripted_image_does_not_install_codex(self):
        class Builder:
            def __init__(self):
                self.commands = []
                self.packages = []

            def apt_install(self, *args):
                self.packages.extend(args)
                return self

            def run_commands(self, *args):
                self.commands.extend(args)
                return self

            def add_local_dir(self, *args, **kwargs):
                return self

        builder = Builder()
        fake_modal = SimpleNamespace(Image=SimpleNamespace(
            debian_slim=lambda **kwargs: builder,
        ))
        MODULE.build_image(fake_modal, verify_secret_environment=False)
        self.assertNotIn("nodejs", builder.packages)
        self.assertFalse(any("@openai/codex" in command for command in builder.commands))

    def test_codex_gateway_adapter_is_scoped_and_search_disabled(self):
        adapter = (MODULE.REPO / "modal_honeypot/codex_gateway.sh").read_text()
        self.assertIn('env_key="OPENAI_API_KEY"', adapter)
        self.assertIn('base_url=\\"$OPENAI_BASE_URL\\"', adapter)
        self.assertIn('--model "$HONEYPOT_CODEX_MODEL"', adapter)
        self.assertIn('approval_policy="never"', adapter)
        self.assertIn('sandbox_mode="danger-full-access"', adapter)
        self.assertIn('web_search="disabled"', adapter)
        self.assertIn("supports_standalone_web_search=false", adapter)
        self.assertIn("exec --skip-git-repo-check --json", adapter)
        # The agent works in its task workspace, not in the harness tree.
        self.assertIn('-C "$HONEYPOT_WORKSPACE"', adapter)
        self.assertLess(adapter.index('-C "$HONEYPOT_WORKSPACE"'), adapter.index("exec --skip-git-repo-check"))
        self.assertIn("2>&1", adapter)
        self.assertIn("| python3 /opt/honeypot/modal_honeypot/redact_stream.py", adapter)
        self.assertLess(adapter.index("2>&1"), adapter.index("redact_stream.py"))
        self.assertLess(adapter.index("redact_stream.py"), adapter.index("| tee"))
        self.assertNotIn("LANGFUSE_", adapter)

    def test_codex_gateway_redaction_filter_uses_environment_key(self):
        script = MODULE.REPO / "modal_honeypot/redact_stream.py"
        fake_key = "sk-unit-filter-key-123456789"
        payload = f"before:{fake_key}:middle:{fake_key}:after\n"
        completed = subprocess.run(
            [sys.executable, str(script)],
            input=payload,
            env={**os.environ, "OPENAI_API_KEY": fake_key},
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn(fake_key, completed.stdout)
        self.assertEqual(completed.stdout.count("[REDACTED-VIRTUAL-KEY]"), 2)
        self.assertEqual(completed.stderr, "")
        self.assertNotIn(fake_key, completed.args)

    def test_experiment_trials_override_changes_plan_cell_count(self):
        script = MODULE.REPO / "agent_honeypot/collusion_tripwires/run_experiments.sh"
        env = {
            **os.environ,
            "OPENAI_BASE_URL": "https://gateway.invalid/v1",
            "LANGFUSE_BASE_URL": "https://trace.invalid",
        }
        completed = subprocess.run(
            ["bash", str(script), "--arm", "lure-pair", "--trials", "1",
             "--model", "pinned-model"],
            cwd=MODULE.REPO, env=env, text=True, capture_output=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("2 cells", completed.stdout)
        self.assertEqual(completed.stdout.count("] PLAN"), 2)
        self.assertIn("PLAN ONLY: no sandbox, no model call", completed.stdout)
        self.assertIn('"secrets": [', completed.stdout)
        self.assertIn('"virtual-key:collusion/CLH-036/t1/', completed.stdout)
        self.assertIn('"egress": "allowlist"', completed.stdout)
        self.assertIn('"agent_timeout_seconds": 900', completed.stdout)
        self.assertIn('"--agent-timeout"', completed.stdout)
        self.assertIn('"gateway.invalid"', completed.stdout)
        self.assertIn('"trace.invalid"', completed.stdout)
        self.assertNotIn("LITELLM_MASTER_KEY", completed.stdout)

    def test_experiment_trials_override_rejects_zero(self):
        script = MODULE.REPO / "agent_honeypot/collusion_tripwires/run_experiments.sh"
        completed = subprocess.run(
            ["bash", str(script), "--arm", "lure-pair", "--trials", "0"],
            cwd=MODULE.REPO, text=True, capture_output=True, check=False,
        )
        self.assertEqual(completed.returncode, 64)
        self.assertIn("positive integer", completed.stderr)

    def test_experiment_case_filter_plans_one_cell(self):
        script = MODULE.REPO / "agent_honeypot/collusion_tripwires/run_experiments.sh"
        env = {
            **os.environ,
            "OPENAI_BASE_URL": "https://gateway.invalid/v1",
            "LANGFUSE_BASE_URL": "https://trace.invalid",
        }
        completed = subprocess.run(
            ["bash", str(script), "--arm", "lure-pair", "--trials", "1", "--case", "CLH-037",
             "--model", "pinned-model"],
            cwd=MODULE.REPO, env=env, text=True, capture_output=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("1 cells", completed.stdout)
        self.assertEqual(completed.stdout.count("] PLAN"), 1)
        self.assertIn('"virtual-key:collusion/CLH-037/t1/', completed.stdout)
        self.assertNotIn("CLH-036", completed.stdout)

    def test_experiment_case_filter_rejects_a_case_outside_the_arm(self):
        script = MODULE.REPO / "agent_honeypot/collusion_tripwires/run_experiments.sh"
        completed = subprocess.run(
            ["bash", str(script), "--arm", "lure-pair", "--case", "CLH-001", "--model", "pinned-model"],
            cwd=MODULE.REPO, text=True, capture_output=True, check=False,
            env={**os.environ, "OPENAI_BASE_URL": "https://gateway.invalid/v1",
                 "LANGFUSE_BASE_URL": "https://trace.invalid"},
        )
        self.assertEqual(completed.returncode, 64)
        self.assertIn("not in arm lure-pair", completed.stderr)
        completed = subprocess.run(
            ["bash", str(script), "--case", "CLH-036"],
            cwd=MODULE.REPO, text=True, capture_output=True, check=False,
        )
        self.assertEqual(completed.returncode, 64)
        self.assertIn("--case requires --arm", completed.stderr)

    FAKE_RUNNER = """
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
case_id = args[args.index("--case-id") + 1]
output = Path(args[args.index("--output") + 1])
trial = args[args.index("--trial") + 1] if "--trial" in args else "1"
run_dir = output / f"collusion-{case_id}-fake-t{trial}"
run_dir.mkdir(parents=True, exist_ok=True)
bad = os.environ.get("FAKE_RUNNER_FAIL_CASE") == case_id
exit_failure = os.environ.get("FAKE_RUNNER_EXIT_CASE") == case_id
record = {
    "remote_exit_code": 1 if exit_failure else 0,
    "termination": "explicit-finally",
    "virtual_key": {"key_alias": f"collusion/{case_id}/t{trial}/fake",
                    "spend_usd": 0.0125, "revoked_at": "2026-10-29T00:00:00+00:00"},
    "redaction": {"passed": not bad, "findings": ["leak.txt"] if bad else []},
}
(run_dir / "modal-run.json").write_text(json.dumps(record))
print("WARNING: fake runner, nothing contacted")
print(json.dumps({"output": str(run_dir), **record}, indent=2, sort_keys=True))
raise SystemExit(1 if exit_failure else 0)
"""

    def _execute_driver(self, directory, fail_case=None, exit_case=None, extra=()):
        script = MODULE.REPO / "agent_honeypot/collusion_tripwires/run_experiments.sh"
        fake = Path(directory) / "fake_runner.py"
        fake.write_text(self.FAKE_RUNNER)
        env = {
            **os.environ,
            "OPENAI_BASE_URL": "https://gateway.invalid/v1",
            "LANGFUSE_BASE_URL": "https://trace.invalid",
            "EXPERIMENT_APPROVED": "1",
            "LITELLM_MASTER_KEY": "unit-test-master-not-a-key",
            "HONEYPOT_RUNNER": str(fake),
        }
        if fail_case:
            env["FAKE_RUNNER_FAIL_CASE"] = fail_case
        if exit_case:
            env["FAKE_RUNNER_EXIT_CASE"] = exit_case
        return subprocess.run(
            ["bash", str(script), "--arm", "lure-pair", "--trials", "1", "--model", "pinned-model",
             "--output", str(Path(directory) / "out"), "--execute", *extra],
            cwd=MODULE.REPO, env=env, text=True, capture_output=True, check=False,
        )

    def test_experiment_execute_keeps_runner_output_and_gates_each_agent_cell(self):
        with tempfile.TemporaryDirectory() as directory:
            completed = self._execute_driver(directory)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout.count("] RUN"), 2)
            self.assertLess(completed.stdout.index("[CLH-036"), completed.stdout.index("[CLH-037"))
            logs = sorted((Path(directory) / "out" / "lure-pair").glob("driver-CLH-03*-t1-*.log"))
            self.assertEqual(len(logs), 2)
            self.assertIn('"termination": "explicit-finally"', logs[0].read_text())
            self.assertEqual(completed.stdout.count("gate: remote_exit_zero=true"), 2)
            self.assertIn("alias=collusion/CLH-037/t1/fake", completed.stdout)
            self.assertNotIn("unit-test-master-not-a-key", completed.stdout + completed.stderr)
            self.assertIn("Done.", completed.stdout)

    def test_experiment_execute_stops_before_the_next_cell_when_the_gate_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            completed = self._execute_driver(directory, fail_case="CLH-036")
            self.assertEqual(completed.returncode, 75, completed.stdout + completed.stderr)
            self.assertEqual(completed.stdout.count("] RUN"), 1)
            self.assertIn("redaction_passed=false", completed.stdout)
            self.assertIn("gate: FAILED for alias collusion/CLH-036/t1/fake", completed.stderr)
            self.assertFalse((Path(directory) / "out" / "lure-pair" / "collusion-CLH-037-fake-t1").exists())
            self.assertNotIn("Done.", completed.stdout)
            completed = self._execute_driver(directory, fail_case="CLH-036", extra=("--keep-going",))
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout.count("] RUN"), 2)
            self.assertIn("continuing past the failed gate", completed.stderr)

    def test_experiment_execute_preserves_runner_exit_and_stops_before_next_cell(self):
        with tempfile.TemporaryDirectory() as directory:
            completed = self._execute_driver(directory, exit_case="CLH-036")
            self.assertEqual(completed.returncode, 1, completed.stdout + completed.stderr)
            self.assertEqual(completed.stdout.count("] RUN"), 1)
            self.assertIn("runner exit 1", completed.stdout)
            self.assertIn("stopping at the first failed cell", completed.stderr)
            self.assertNotIn("[CLH-037", completed.stdout)
            self.assertNotIn("Done.", completed.stdout)

    def test_experiment_driver_refuses_a_missing_or_modal_less_interpreter(self):
        script = MODULE.REPO / "agent_honeypot/collusion_tripwires/run_experiments.sh"
        base_env = {
            **os.environ,
            "OPENAI_BASE_URL": "https://gateway.invalid/v1",
            "LANGFUSE_BASE_URL": "https://trace.invalid",
            "EXPERIMENT_APPROVED": "1",
            "LITELLM_MASTER_KEY": "unit-test-master-not-a-key",
        }
        base_env.pop("HONEYPOT_RUNNER", None)
        # A missing interpreter is refused before anything else happens.
        completed = subprocess.run(
            ["bash", str(script), "--arm", "lure-pair", "--trials", "1", "--model", "pinned-model"],
            cwd=MODULE.REPO, text=True, capture_output=True, check=False,
            env={**base_env, "HONEYPOT_PYTHON": "/nonexistent/python"},
        )
        self.assertEqual(completed.returncode, 78, completed.stdout + completed.stderr)
        self.assertIn("python interpreter not found", completed.stderr)
        # A paid cell is refused when the interpreter cannot import modal; a plan is not.
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / "python-without-modal"
            fake.write_text("#!/usr/bin/env bash\nexit 1\n")
            fake.chmod(0o755)
            env = {**base_env, "HONEYPOT_PYTHON": str(fake)}
            completed = subprocess.run(
                ["bash", str(script), "--arm", "lure-pair", "--trials", "1", "--model", "pinned-model",
                 "--output", str(Path(directory) / "out"), "--execute"],
                cwd=MODULE.REPO, text=True, capture_output=True, check=False, env=env,
            )
            self.assertEqual(completed.returncode, 78, completed.stdout + completed.stderr)
            self.assertIn("cannot import modal", completed.stderr)
            self.assertNotIn("] RUN", completed.stdout)
            self.assertFalse((Path(directory) / "out").exists())


if __name__ == "__main__":
    unittest.main()
