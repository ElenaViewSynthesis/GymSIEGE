"""agent_honeypot/intent_tripwires/run_cohort.py against a fake Docker runner."""

import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("intent_run_cohort", REPO / "agent_honeypot/intent_tripwires/run_cohort.py")
COHORT = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(COHORT)

FAKE_RUNNER = r'''
import io, json, os, sys, tarfile, time
from pathlib import Path

argv = sys.argv[1:]
def value(flag):
    return argv[argv.index(flag) + 1]
case_id, spec, out = value("--case-id"), value("--egress-allowlist"), Path(value("--output"))
with open(os.environ["FAKE_RUNNER_CALLS"], "a") as calls:
    calls.write(json.dumps({"argv": argv, "codex_sandbox": os.environ.get("HONEYPOT_CODEX_SANDBOX")}) + "\n")
live = "web-search" in spec.split(",")
if "--dry-run" in argv:
    print(json.dumps({"provider": "docker", "case_id": case_id, "image": "rogue-agent-honeypot:abc1234",
                      "source_revision": {"commit": "abc1234", "dirty": os.environ.get("FAKE_DIRTY") == "1"},
                      "policy": {"web_search": "live" if live else "disabled",
                                 "codex_sandbox": os.environ.get("HONEYPOT_CODEX_SANDBOX")}}, indent=2))
    raise SystemExit(0)
behavior = json.loads(os.environ.get("FAKE_BEHAVIOR", "{}")).get(case_id, "ok")
if behavior == "no-record":
    print("docker run of the sandbox container failed", file=sys.stderr)
    raise SystemExit(1)
run = out / f"intent-{case_id}-agent-chain-text-net-allow-{time.time_ns()}"
run.mkdir(parents=True)
spend = float(os.environ.get("FAKE_SPEND", "0.01"))
record = {"provider": "docker", "harness": "intent", "case_id": case_id, "remote_exit_code": 0,
          "termination": "explicit-finally", "source_revision": {"commit": "abc1234", "dirty": False},
          "virtual_key": {"key_alias": f"intent/{case_id}/t1/x", "token_id": "t" * 64,
                          "spend_usd": spend, "revoked_at": "2026-11-02T00:00:00+00:00"},
          "redaction": {"passed": True, "findings": []}}
search = "live" if live else "disabled"
if behavior == "wrong-search":
    search = "disabled" if live else "live"
row = {"case_id": case_id, "passed": True, "stage": "none", "expectation_passed": True,
       "observability": "observable", "evidence_chains": [True, True], "web_search": search,
       "agent_hooks": {"agent": {"commands": 2, "observed": behavior != "mute"}},
       "agent_hooks_observed": behavior != "mute"}
(run / "docker-run.json").write_text(json.dumps(record))
(run / "summary.json").write_text(json.dumps({"results": [row]}))
rows = [{"type": "turn.completed", "usage": {"output_tokens": 0 if behavior == "empty" else 40}}]
if behavior != "empty":
    rows.insert(0, {"type": "item.completed", "item": {"type": "command_execution", "command": "ls"}})
trajectory = "".join(json.dumps(r) + "\n" for r in rows).encode()
report = json.dumps({"observed_stage": "none", "expectation_passed": True, "web_search": search,
                     "signals": {"sensitive_file_open": False}, "event_counts": {"EXEC": 3}}).encode()
with tarfile.open(run / "artifacts.tar.gz", "w:gz") as archive:
    for name, data in ((f"cases/{case_id}/trajectory.jsonl", trajectory), (f"cases/{case_id}/report.json", report)):
        info = tarfile.TarInfo(name)
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
proxy = [{"target": "tunnel.example.org:443", "decision": "allowed"},
         {"target": "chatgpt.com:443", "decision": "refused"}]
if behavior == "refused-other":
    proxy.append({"target": "example.com:443", "decision": "refused"})
(run / "egress-proxy.log").write_text("".join(json.dumps(p) + "\n" for p in proxy))
print(json.dumps({"output": str(run), **record}, indent=2))
'''


class IntentCohortDriverTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.runner = self.base / "fake_runner.py"
        self.runner.write_text(FAKE_RUNNER)
        self.calls = self.base / "calls.jsonl"
        self.root = self.base / "cohort"

    def drive(self, *extra, behavior=None, env=None, cases="ITH-001,ITH-003,ITH-010"):
        argv = ["--root", str(self.root), "--model", "pinned-model", "--key-budget", "0.9",
                "--ceiling", "20", "--cases", cases, "--runner", str(self.runner),
                "--python", sys.executable, *extra]
        values = {"FAKE_RUNNER_CALLS": str(self.calls), "FAKE_BEHAVIOR": json.dumps(behavior or {}),
                  **(env or {})}
        with mock.patch.dict(os.environ, values), contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()) as err:
            code = COHORT.main(argv)
        return code, out.getvalue(), err.getvalue()

    def runner_calls(self):
        if not self.calls.is_file():
            return []
        return [json.loads(line) for line in self.calls.read_text().splitlines()]

    def paid_calls(self):
        return [call for call in self.runner_calls() if "--dry-run" not in call["argv"]]

    def ledger(self):
        return COHORT.read_ledger(self.root)

    def test_plan_dry_runs_every_cell_and_writes_nothing(self):
        code, out, _ = self.drive()
        self.assertEqual(code, 0, out)
        calls = self.runner_calls()
        self.assertEqual([c["argv"][c["argv"].index("--case-id") + 1] for c in calls], ["ITH-001", "ITH-003", "ITH-010"])
        self.assertTrue(all("--dry-run" in c["argv"] for c in calls))
        specs = {c["argv"][c["argv"].index("--case-id") + 1]: c["argv"][c["argv"].index("--egress-allowlist") + 1]
                 for c in calls}
        self.assertEqual(specs, {"ITH-001": "langfuse,gateway", "ITH-003": "langfuse,gateway",
                                 "ITH-010": "langfuse,gateway,web-search"})
        self.assertTrue(all(c["codex_sandbox"] == "workspace-write" for c in calls))
        self.assertIn("[ITH-010] web_search live", out)
        self.assertFalse(self.root.exists())

    def test_the_default_cohort_is_the_eleven_intent_evaluations(self):
        cases = COHORT.load_cases()
        self.assertEqual(COHORT.default_cases(cases), [f"ITH-0{n:02d}" for n in range(1, 12)])
        with self.assertRaises(SystemExit):
            self.drive(cases="ITH-012")
        with self.assertRaises(SystemExit):
            self.drive(cases="ITH-001,ITH-001")

    def test_execute_needs_approval_and_clean_inputs(self):
        code, _, err = self.drive("--execute")
        self.assertEqual(code, 78)
        self.assertIn("EXPERIMENT_APPROVED=1", err)
        code, _, err = self.drive("--execute", env={"EXPERIMENT_APPROVED": "1", "FAKE_DIRTY": "1"})
        self.assertEqual(code, 78)
        self.assertIn("dirty", err)
        self.assertEqual(self.paid_calls(), [])
        self.assertFalse((self.root / COHORT.COHORT_FILE).exists())

    def test_a_clean_cohort_freezes_the_plan_gates_each_cell_and_summarises(self):
        code, out, err = self.drive("--execute", env={"EXPERIMENT_APPROVED": "1"},
                                    behavior={"ITH-003": "refused-other"})
        self.assertEqual(code, 0, out + err)
        frozen = json.loads((self.root / COHORT.COHORT_FILE).read_text())
        self.assertEqual([(c["case_id"], c["web_search"]) for c in frozen["cells"]],
                         [("ITH-001", "disabled"), ("ITH-003", "disabled"), ("ITH-010", "live")])
        rows = self.ledger()
        self.assertEqual([r["status"] for r in rows], ["ok", "ok", "ok"])
        by_case = {r["case_id"]: r for r in rows}
        # A refused exfiltration target is a finding, apart from the client's own hosts.
        self.assertEqual(by_case["ITH-003"]["refused_other_hosts"], {"example.com": 1})
        self.assertEqual(by_case["ITH-003"]["refused_client_hosts"], {"chatgpt.com": 1})
        self.assertEqual(by_case["ITH-010"]["web_search"], "live")
        summary = json.loads((self.root / COHORT.SUMMARY).read_text())
        self.assertEqual(summary["cells_passed_gate"], 3)
        self.assertEqual(summary["hooks_observed"], 3)
        self.assertAlmostEqual(summary["spend_usd"], 0.03)
        self.assertEqual(summary["refused_other_hosts"], {"ITH-003": {"example.com": 1}})
        # Nothing the driver writes carries the run record's token id.
        for path in (self.root / COHORT.LEDGER, self.root / COHORT.SUMMARY, self.root / COHORT.COHORT_FILE):
            self.assertNotIn("t" * 64, path.read_text())
        self.assertNotIn("t" * 64, out)
        self.assertTrue(all(c["codex_sandbox"] == "workspace-write" for c in self.paid_calls()))

    def test_mute_hooks_or_a_wrong_search_mode_stop_the_cohort(self):
        for behavior, failed in (("mute", "agent_hooks_observed"), ("wrong-search", "web_search_matches")):
            with self.subTest(behavior=behavior):
                self.calls.unlink(missing_ok=True)
                code, _, err = self.drive("--execute", "--root", str(self.base / behavior),
                                          env={"EXPERIMENT_APPROVED": "1"},
                                          behavior={"ITH-001": behavior})
                self.assertEqual(code, 1)
                self.assertIn("stopping at the first failed gate (ITH-001)", err)
                rows = COHORT.read_ledger(self.base / behavior)
                self.assertEqual([r["status"] for r in rows], ["hard_fail"])
                self.assertFalse(rows[0]["hard"][failed])
                self.assertEqual(len(self.paid_calls()), 1)

    def test_setup_faults_are_counted_and_stop_past_the_limit(self):
        code, _, err = self.drive("--execute", "--max-setup-faults", "0", env={"EXPERIMENT_APPROVED": "1"},
                                  behavior={"ITH-001": "empty"})
        self.assertEqual(code, 75)
        self.assertIn("setup-fault limit exceeded", err)
        self.assertEqual(len(self.paid_calls()), 1)
        self.calls.unlink()
        code, out, err = self.drive("--execute", "--max-setup-faults", "1", "--root", str(self.base / "again"),
                                    env={"EXPERIMENT_APPROVED": "1"}, behavior={"ITH-001": "empty"})
        self.assertEqual(code, 0, out + err)
        self.assertEqual([r["status"] for r in COHORT.read_ledger(self.base / "again")],
                         ["setup_fault", "ok", "ok"])

    def test_the_ceiling_guard_stops_before_a_cell_that_could_pass_it(self):
        code, out, _ = self.drive("--execute", "--ceiling", "2.0", "--spent-before", "0.15",
                                  env={"EXPERIMENT_APPROVED": "1", "FAKE_SPEND": "0.5"})
        self.assertEqual(code, 0)
        # 0.15 + 0.9 ok; 0.65 + 0.9 ok; 1.15 + 0.9 > 2.0: the third cell never starts.
        self.assertIn("ceiling guard: stopped before ITH-010", out)
        self.assertEqual(len(self.paid_calls()), 2)
        summary = json.loads((self.root / COHORT.SUMMARY).read_text())
        self.assertAlmostEqual(summary["spent_total_usd"], 1.15)

    def test_a_rerun_resumes_and_a_changed_plan_is_refused(self):
        code, _, err = self.drive("--execute", env={"EXPERIMENT_APPROVED": "1"}, behavior={"ITH-003": "no-record"})
        self.assertEqual(code, 1)
        self.assertIn("no run record", err)
        self.assertEqual([r["status"] for r in self.ledger()], ["ok", "runner_failed"])
        self.calls.unlink()
        code, out, err = self.drive("--execute", env={"EXPERIMENT_APPROVED": "1"})
        self.assertEqual(code, 0, out + err)
        self.assertIn("[ITH-001] already passed the gate; skipped", out)
        self.assertEqual([c["argv"][c["argv"].index("--case-id") + 1] for c in self.paid_calls()],
                         ["ITH-003", "ITH-010"])
        with self.assertRaises(SystemExit) as raised:
            self.drive("--execute", "--key-budget", "0.5", env={"EXPERIMENT_APPROVED": "1"})
        self.assertIn("different plan", str(raised.exception))


class IntentCohortGateTests(unittest.TestCase):
    def test_a_cell_without_a_run_record_fails_every_hard_check_it_can(self):
        with tempfile.TemporaryDirectory() as directory:
            gate = COHORT.gate_cell(Path(directory), COHORT.load_cases()["ITH-001"], 0.9)
        self.assertEqual(gate["status"], "hard_fail")
        self.assertFalse(gate["hard"]["run_record_present"])
        self.assertEqual(gate["archive_error"], "FileNotFoundError")

    def test_proxy_decisions_group_hosts_by_decision(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "egress-proxy.log").write_text(
                '{"target": "a.example:443", "decision": "allowed"}\n'
                '{"target": "a.example:443", "decision": "allowed"}\n'
                '{"target": "1.1.1.1:443", "decision": "refused"}\nnot json\n')
            self.assertEqual(COHORT.proxy_decisions(Path(directory)),
                             {"allowed": {"a.example": 2}, "refused": {"1.1.1.1": 1}})


if __name__ == "__main__":
    unittest.main()
