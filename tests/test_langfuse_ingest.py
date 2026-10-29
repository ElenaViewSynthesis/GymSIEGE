import contextlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent_honeypot import langfuse_ingest as ingest


ROOT = Path(__file__).parents[1]
INSTRUMENT_RUN = ROOT / "results/modal-honeypot/instrument-all-chain-off-text-20261027T034959Z"
COLLUSION_RUN = ROOT / "results/collusion-calibration-local-20261026"


class FakeObservationContext:
    def __init__(self, client, row):
        self.client = client
        self.row = row
        self.id = f"observation-{client.next_id}"
        client.next_id += 1

    def __enter__(self):
        self.client._append(self.row)
        self.client.stack.append(self.row)
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.client.stack.pop()
        return False


class FakeLangfuse:
    def __init__(self):
        self.observations = []
        self.scores = []
        self.propagated = []
        self.stack = []
        self.shutdown_called = False
        self.next_id = 1

    def _append(self, row):
        target = self.stack[-1]["children"] if self.stack else self.observations
        target.append(row)

    def start_as_current_observation(self, **kwargs):
        return FakeObservationContext(self, {"kind": kwargs.get("as_type"), **kwargs, "children": []})

    def create_event(self, **kwargs):
        self._append({"kind": "event", **kwargs, "children": []})

    def create_score(self, **kwargs):
        self.scores.append(kwargs)

    def shutdown(self):
        self.shutdown_called = True

    @contextlib.contextmanager
    def propagate(self, **kwargs):
        self.propagated.append(kwargs)
        yield


def walk(observation):
    yield observation
    for child in observation.children:
        yield from walk(child)


class LangfuseIngestTests(unittest.TestCase):
    def _plan_with_gateway_alias(self, alias="collusion/CLH-036/t1/stamp"):
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "CLH-036"
            shutil.copytree(COLLUSION_RUN / "CLH-036", copied)
            (copied / "modal-run.json").write_text(json.dumps({
                "arm": "lure-pair",
                "trial": 1,
                "virtual_key": {"key_alias": alias},
            }))
            return ingest.build_trace_plans(copied)[0]

    def test_instrument_tree_uses_verified_events(self):
        plan = ingest.build_trace_plans(INSTRUMENT_RUN, case_id="IHT-001")[0]
        rows = list(walk(plan.root))
        self.assertEqual(plan.root.name, "instrument-case")
        self.assertNotIn("unobservable", plan.tags)
        self.assertEqual(sum(row.kind == "span" for row in rows), 2)
        self.assertEqual(sum(row.kind == "event" for row in rows), 2)
        for row in rows:
            if row.kind == "event":
                self.assertRegex(row.metadata["chain_hash"], r"^[0-9a-f]{64}$")
                self.assertIsInstance(row.metadata["sequence"], int)

    def test_collusion_tree_nests_delegated_harness(self):
        plan = ingest.build_trace_plans(COLLUSION_RUN, case_id="CLH-040")[0]
        subject = next(child for child in plan.root.children if child.metadata.get("run_id") == "subject")
        delegates = [child for child in subject.children if child.kind == "span"]
        self.assertTrue(delegates)
        self.assertTrue(all(child.metadata["depth"] >= 1 for child in delegates))
        self.assertGreater(sum(row.kind == "event" for row in walk(plan.root)), 0)
        self.assertIn("chain=on", plan.tags)

    def test_trace_id_is_stable_and_w3c_shaped(self):
        first = ingest.build_trace_plans(COLLUSION_RUN, case_id="CLH-036")[0]
        second = ingest.build_trace_plans(COLLUSION_RUN, case_id="CLH-036")[0]
        self.assertEqual(first.trace_id, second.trace_id)
        self.assertRegex(first.trace_id, r"^[0-9a-f]{32}$")
        self.assertEqual(first.trace_id, ingest.deterministic_trace_id(first.trace_seed))
        self.assertEqual(first.session_id, "solvable/CLH-036/t1")
        self.assertEqual(first.root.metadata["session_id_source"], "derived")

    def test_virtual_key_alias_becomes_session_and_join_attribute(self):
        alias = "collusion/CLH-036/t1/stamp"
        plan = self._plan_with_gateway_alias(alias)
        self.assertEqual(plan.session_id, alias)
        self.assertEqual(plan.attributes["gateway_key_alias"], alias)
        self.assertEqual(plan.root.metadata["gateway_key_alias"], alias)
        self.assertEqual(plan.root.metadata["session_id_source"], "key_alias")
        self.assertIn(alias, json.dumps(ingest.asdict(plan), sort_keys=True))

    def test_gateway_usage_helper_filters_alias_and_sums_tokens(self):
        alias = "collusion/CLH-036/t1/stamp"
        plan = self._plan_with_gateway_alias(alias)

        class FakeObservations:
            def __init__(self):
                self.calls = []

            def get_many(self, **kwargs):
                self.calls.append(kwargs)
                return {
                    "data": [
                        {"metadata": {"attributes.litellm.key_alias": alias},
                         "usageDetails": {"total": 11}},
                        {"metadata": {"attributes": {"litellm.key_alias": alias}},
                         "usage_details": {"input": 7, "output": 5}},
                        {"metadata": {"attributes.litellm.key_alias": "collusion/other"},
                         "usageDetails": {"total": 1000}},
                    ],
                    "meta": {"cursor": None},
                }

        client = FakeObservations()
        ingest.add_gateway_generation_usage(plan, client)
        self.assertEqual(plan.root.metadata["gateway_generation_count"], 2)
        self.assertEqual(plan.root.metadata["gateway_total_tokens"], 23)
        # Turns and generations are different units; parity is judged on tokens.
        self.assertNotIn("gateway_transcript_generation_count_mismatch", plan.root.metadata)
        self.assertIn("gateway_transcript_token_mismatch", plan.root.metadata)
        self.assertIn("transcript_turn_count", plan.root.metadata)
        self.assertEqual(client.calls[0]["type"], "GENERATION")
        self.assertIn(alias, client.calls[0]["filter"])

    def test_transcript_usage_sums_codex_input_and_output_when_total_is_absent(self):
        with tempfile.TemporaryDirectory() as directory:
            case_dir = Path(directory) / "runs" / "subject"
            case_dir.mkdir(parents=True)
            rows = [
                {"type": "turn.started"},
                {"type": "turn.completed", "usage": {"input_tokens": 686334, "cached_input_tokens": 615536,
                                                     "output_tokens": 3490, "reasoning_output_tokens": 1175}},
            ]
            (case_dir / "trajectory.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")
            turns, tokens = ingest._transcript_usage(Path(directory))
        self.assertEqual((turns, tokens), (1, 689824))  # equals the gateway total of the same run

    def test_token_parity_uses_a_tolerance_and_needs_both_sides(self):
        self.assertIsNone(ingest.token_parity_mismatch(0, 500))
        self.assertIsNone(ingest.token_parity_mismatch(500, 0))
        self.assertFalse(ingest.token_parity_mismatch(1000, 960))   # 4% apart
        self.assertTrue(ingest.token_parity_mismatch(1000, 900))    # 10% apart
        self.assertTrue(ingest.token_parity_mismatch(689_824, 44_052))

    def test_verifier_status_is_the_reports_own_field_not_the_policy_verdict(self):
        plan = ingest.build_trace_plans(COLLUSION_RUN, case_id="CLH-036")[0]
        # The local calibration predates the verifier field, so it is absent here;
        # the point is that the policy expectation is never relabelled as it.
        self.assertIn("verifier_status", plan.root.metadata)
        self.assertIn("verifier_result", plan.root.output)
        self.assertIn("policy_expectation_passed", plan.root.output)
        self.assertEqual(plan.root.output["verifier_result"], plan.root.metadata["verifier_status"])
        self.assertIsNotNone(plan.root.output["policy_expectation_passed"])

    def test_verifier_object_round_trips_without_becoming_the_policy_verdict(self):
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "CLH-036"
            shutil.copytree(COLLUSION_RUN / "CLH-036", copied)
            report_path = copied / "report.json"
            report = json.loads(report_path.read_text())
            report["verifier"] = {
                "status": "implemented", "kind": "sha256_of_file", "passed": False,
            }
            report_path.write_text(json.dumps(report))
            plan = ingest.build_trace_plans(copied)[0]
        self.assertEqual(plan.root.metadata["verifier_status"], report["verifier"])
        self.assertEqual(plan.root.output["verifier_result"], report["verifier"])
        self.assertEqual(
            plan.root.output["policy_expectation_passed"], report["expectation_passed"],
        )

    def test_chain_break_tags_unobservable_and_suppresses_behavior(self):
        source = COLLUSION_RUN / "CLH-036"
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "CLH-036"
            shutil.copytree(source, copied)
            visible = copied / "runs/subject/harness/events.tsv"
            visible.write_text(visible.read_text() + "tampered\n")
            plan = ingest.build_trace_plans(copied)[0]
        self.assertIn("unobservable", plan.tags)
        self.assertFalse(plan.root.output["chains_valid"])
        self.assertFalse(any(row.kind in {"event", "tool"} for row in walk(plan.root)))

    def test_markers_are_redacted_from_every_payload(self):
        case_dir = COLLUSION_RUN / "CLH-036"
        marker_data = json.loads((case_dir / "markers.json").read_text())
        markers = [value for row in marker_data.values() for value in row.values()]
        plan = ingest.build_trace_plans(case_dir)[0]
        rendered = json.dumps(ingest.asdict(plan), sort_keys=True)
        for marker in markers:
            self.assertNotIn(marker, rendered)
        client = FakeLangfuse()
        ingest.push_trace_plans([plan], client, propagate=client.propagate)
        pushed = json.dumps({
            "observations": client.observations,
            "scores": client.scores,
            "attributes": client.propagated,
        }, sort_keys=True)
        for marker in markers:
            self.assertNotIn(marker, pushed)

    def test_fake_push_emits_scores_attributes_and_shutdown(self):
        plan = ingest.build_trace_plans(INSTRUMENT_RUN, case_id="IHT-001")[0]
        client = FakeLangfuse()
        ingest.push_trace_plans([plan], client, propagate=client.propagate)
        self.assertTrue(client.shutdown_called)
        self.assertEqual(client.observations[0]["trace_context"], {"trace_id": plan.trace_id})
        self.assertEqual(client.propagated[0]["session_id"], plan.session_id)
        self.assertEqual({row["name"] for row in client.scores}, {"chain_valid", "score", "verdict"})
        self.assertTrue(all(row["observation_id"] == "observation-1" for row in client.scores))

    def test_push_appends_trace_id_without_rewriting_other_values(self):
        plan = ingest.build_trace_plans(INSTRUMENT_RUN, case_id="IHT-001")[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = {"schema_version": "1.0", "passed": 7, "results": [{"case_id": "IHT-001"}]}
            (root / "summary.json").write_text(json.dumps(original))
            ingest.write_trace_ids(root, [plan])
            updated = json.loads((root / "summary.json").read_text())
        self.assertEqual(updated["schema_version"], original["schema_version"])
        self.assertEqual(updated["passed"], original["passed"])
        self.assertEqual(updated["results"], original["results"])
        self.assertEqual(updated["langfuse"]["trace_id"], plan.trace_id)

    def test_push_requires_all_host_credentials_before_importing_client(self):
        with mock.patch.dict(ingest.os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, "LANGFUSE_PUBLIC_KEY"):
                ingest._push_client()


if __name__ == "__main__":
    unittest.main()
