"""The gateway routes for GLM 5.3 and Kimi K3 on Modal through OpenRouter
(modal_honeypot/modal_routes.py), offline: the route definitions and payloads, the
catalogue check, the comparison with a registered route, and the probe's stream
reading and second-turn input. Registration and the probe itself talk to the
gateway and are run by hand, not here.
"""

import importlib.util
import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout
from decimal import Decimal
from pathlib import Path
from unittest import mock


REPO = Path(__file__).parents[1]


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module    # dataclasses resolve string annotations through it
    spec.loader.exec_module(module)
    return module


routes = _load("modal_routes", REPO / "modal_honeypot" / "modal_routes.py")
hooks = _load("honeypot_gateway_hooks_for_routes", REPO / "gateway_hooks" / "honeypot_gateway_hooks.py")
runner = _load("modal_honeypot_runner_for_routes", REPO / "modal_honeypot" / "runner.py")


def endpoint(route, **overrides):
    record = {
        "provider_name": "Modal", "tag": route.tag, "status": 0, "uptime_last_1d": 100,
        "context_length": route.context,
        "pricing": {"prompt": route.input_cost, "completion": route.output_cost,
                    "input_cache_read": route.cache_read_cost, "discount": 0},
        "supported_parameters": ["reasoning", "include_reasoning", "tools", "tool_choice", "max_tokens"],
    }
    record.update(overrides)
    return record


def catalogue(*endpoints):
    return {"data": {"id": "x", "endpoints": list(endpoints)}}


OPENROUTER = [r for r in routes.ROUTES if r.via == "openrouter"]
DIRECT = next(r for r in routes.ROUTES if r.via == "modal")
DIRECT_ENV = (DIRECT.base_url_env, DIRECT.key_env)


def without_direct_env():
    return {k: v for k, v in os.environ.items() if k not in DIRECT_ENV}


class RouteDefinitions(unittest.TestCase):
    def test_three_openrouter_routes_each_pinned_to_its_modal_endpoint(self):
        tags = {r.name: (r.slug, r.tag) for r in OPENROUTER}
        self.assertEqual(tags, {
            "glm-5.3-flash-modal": ("z-ai/glm-5.3-flash", "modal/fp4"),
            "glm-5.3-modal": ("z-ai/glm-5.3", "modal"),
            "kimi-k3-modal": ("moonshotai/kimi-k3", "modal/mxfp4"),
        })

    def test_direct_route_calls_the_modal_endpoint_with_env_references_only(self):
        self.assertEqual(DIRECT.name, "kimi-k3-modal-direct")
        payload = routes.litellm_payload(DIRECT)
        self.assertEqual(payload["litellm_params"], {
            "model": "openai/moonshotai/Kimi-K3",
            "api_base": "os.environ/MODAL_KIMI_K3_BASE_URL",
            "api_key": "os.environ/BEARER",
        })
        self.assertEqual(payload["model_info"]["honeypot_route"], "modal-direct")
        self.assertEqual(payload["model_info"]["input_cost_per_token"], 3e-06)
        self.assertNotIn("wk-", json.dumps(payload))
        self.assertNotIn("https://", json.dumps(payload))

    def test_names_take_no_model_specific_path_in_the_hooks_or_the_runner(self):
        for route in routes.ROUTES:
            self.assertNotIn("/", route.name)   # key aliases and container names derive from it
            self.assertFalse(hooks.is_server_search_model(route.name))
            self.assertFalse(route.name.startswith(runner.STANDALONE_SEARCH_MODEL_PREFIXES))
            self.assertFalse(runner.standalone_web_search(route.name, "disabled"))

    def test_payload_pins_modal_without_fallback_and_carries_no_credential(self):
        for route in OPENROUTER:
            payload = routes.litellm_payload(route)
            params = payload["litellm_params"]
            self.assertEqual(payload["model_name"], route.name)
            self.assertEqual(params["model"], "openrouter/" + route.slug)
            self.assertEqual(params["api_key"], "os.environ/OPENROUTER_API_KEY")
            self.assertEqual(params["extra_body"]["provider"], {"only": [route.tag], "allow_fallbacks": False})
            self.assertEqual(params["extra_body"]["reasoning"], {"enabled": True})
            self.assertEqual(params["extra_body"]["include"], ["reasoning.encrypted_content"])
            self.assertNotIn("sk-", json.dumps(payload))

    def test_costs_are_the_listed_per_token_prices(self):
        kimi = routes.select_routes("kimi-k3-modal")[0]
        info = routes.litellm_payload(kimi)["model_info"]
        self.assertEqual(info["input_cost_per_token"], 3e-06)
        self.assertEqual(info["output_cost_per_token"], 1.5e-05)
        self.assertEqual(info["cache_read_input_token_cost"], 3e-07)
        for route in routes.ROUTES:
            for value in routes.costs(route).values():
                self.assertGreater(value, 0)   # a zero cost would make a key's max_budget void

    def test_select_routes_refuses_unknown_names(self):
        self.assertEqual(len(routes.select_routes(None)), 4)
        with self.assertRaises(ValueError):
            routes.select_routes("kimi-k3")


class CatalogueCheck(unittest.TestCase):
    route = routes.ROUTES[2]

    def test_matching_endpoint_passes(self):
        self.assertEqual(routes.check_endpoint(self.route, catalogue(endpoint(self.route))), [])

    def test_missing_tag_price_change_and_missing_tools_are_reported(self):
        self.assertTrue(routes.check_endpoint(self.route, catalogue(endpoint(self.route, tag="modal/fp4"))))
        changed = endpoint(self.route, pricing={"prompt": "0.0000035", "completion": self.route.output_cost,
                                                "input_cache_read": self.route.cache_read_cost})
        self.assertTrue(any("prompt price" in p for p in routes.check_endpoint(self.route, catalogue(changed))))
        no_tools = endpoint(self.route, supported_parameters=["reasoning"])
        self.assertTrue(any("tools" in p for p in routes.check_endpoint(self.route, catalogue(no_tools))))
        other = endpoint(self.route, provider_name="SomeoneElse")
        self.assertTrue(any("not Modal" in p for p in routes.check_endpoint(self.route, catalogue(other))))

    def test_prices_compare_as_decimals_not_strings(self):
        listed = endpoint(self.route, pricing={"prompt": "0.0000030", "completion": "0.000015",
                                               "input_cache_read": "3e-7"})
        self.assertEqual(routes.check_endpoint(self.route, catalogue(listed)), [])

    def test_check_reads_saved_catalogue_files(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            for route in routes.ROUTES:
                Path(tmp, routes.catalogue_file(route.slug)).write_text(
                    json.dumps(catalogue(endpoint(route))), encoding="utf-8")
            out = io.StringIO()
            with mock.patch.dict(os.environ, without_direct_env(), clear=True), redirect_stdout(out):
                code = routes.main(["--catalogue-dir", tmp])
        self.assertEqual(code, 0, out.getvalue())      # the direct route is skipped, not failed
        self.assertEqual(out.getvalue().count("-- ok"), 3)
        self.assertIn("kimi-k3-modal-direct: not checked", out.getvalue())


class DirectEndpointCheck(unittest.TestCase):
    def test_listing_must_serve_the_route_model_with_enough_context(self):
        ok = {"object": "list", "data": [{"id": "moonshotai/Kimi-K3", "max_model_len": 1_048_576}]}
        self.assertEqual(routes.check_models_listing(DIRECT, ok), [])
        other = {"data": [{"id": "Qwen/Qwen3.5-4B", "max_model_len": 1_048_576}]}
        self.assertTrue(routes.check_models_listing(DIRECT, other))
        short = {"data": [{"id": "moonshotai/Kimi-K3", "max_model_len": 131_072}]}
        self.assertTrue(any("context" in p for p in routes.check_models_listing(DIRECT, short)))

    def test_base_url_must_be_https_and_end_in_v1(self):
        self.assertEqual(routes.endpoint_base("https://x.modal.direct/v1/"), "https://x.modal.direct/v1")
        for bad in ("http://x.modal.direct/v1", "https://x.modal.direct"):
            with self.assertRaises(ValueError):
                routes.endpoint_base(bad)

    def test_missing_environment_fails_only_registration(self):
        with mock.patch.dict(os.environ, without_direct_env(), clear=True), redirect_stdout(io.StringIO()):
            self.assertEqual(routes.run_check([DIRECT], None, payloads=False), 0)
            self.assertEqual(routes.run_check([DIRECT], None, payloads=False, strict=True), 1)

    def test_check_reads_the_endpoint_listing_with_the_environment(self):
        env = {**without_direct_env(), DIRECT.base_url_env: "https://x.modal.direct/v1", DIRECT.key_env: "wk-a.ws-b"}
        listing = {"data": [{"id": "moonshotai/Kimi-K3", "max_model_len": 1_048_576}]}
        out = io.StringIO()
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(routes, "fetch_models", return_value=listing) as fetch, redirect_stdout(out):
            self.assertEqual(routes.run_check([DIRECT], None, payloads=False, strict=True), 0)
        fetch.assert_called_once_with("https://x.modal.direct/v1", "wk-a.ws-b")
        self.assertIn("-- ok", out.getvalue())
        self.assertNotIn("wk-a", out.getvalue())

    def test_registered_direct_route_compares_clean(self):
        payload = routes.litellm_payload(DIRECT)
        entry = {"model_name": DIRECT.name, "litellm_params": {**payload["litellm_params"], "api_key": "masked"},
                 "model_info": payload["model_info"]}
        self.assertEqual(routes.compare_registered(entry, DIRECT), [])


class RegisteredComparison(unittest.TestCase):
    def test_a_registered_copy_matches_and_a_drifted_one_does_not(self):
        route = routes.ROUTES[1]
        payload = routes.litellm_payload(route)
        entry = {"model_name": route.name,
                 "litellm_params": {**payload["litellm_params"], "api_key": "masked"},
                 "model_info": {**payload["model_info"], "id": "abc"}}
        self.assertEqual(routes.compare_registered(entry, route), [])
        drifted = json.loads(json.dumps(entry))
        drifted["litellm_params"]["extra_body"]["provider"]["allow_fallbacks"] = True
        drifted["model_info"]["output_cost_per_token"] = 0
        problems = routes.compare_registered(drifted, route)
        self.assertEqual(len(problems), 2, problems)

    def test_deployments_groups_by_model_name(self):
        models = [{"model_name": "kimi-k3-modal"}, {"model_name": "gpt-5.6-luna"}, {"model_name": "kimi-k3-modal"}]
        self.assertEqual(len(routes.deployments(models, "kimi-k3-modal")), 2)


class ProbeTurns(unittest.TestCase):
    first_output = [
        {"type": "reasoning", "id": "rs_1", "summary": [], "encrypted_content": "opaque-blob",
         "content": [{"type": "reasoning_text", "text": "count the r's"}]},
        {"type": "function_call", "id": "fc_1", "call_id": "call_1", "name": "count_letters",
         "arguments": json.dumps({"word": "strawberry", "letter": "r"})},
    ]

    def test_read_stream_keeps_the_final_response_and_counts_events(self):
        final = {"status": "completed", "output": self.first_output}
        lines = [b"event: response.created\n", b'data: {"type": "response.created"}\n', b"\n",
                 b'data: {"type": "response.output_item.done", "item": {}}\n',
                 ("data: " + json.dumps({"type": "response.completed", "response": final}) + "\n").encode(),
                 b"data: [DONE]\n"]
        response, events, errors = routes.read_stream(lines)
        self.assertEqual(response, final)
        self.assertEqual(events["response.completed"], 1)
        self.assertEqual(errors, [])
        _, _, errors = routes.read_stream([b'data: {"type": "error", "error": {"message": "no endpoint"}}\n'])
        self.assertEqual(len(errors), 1)

    def test_second_turn_returns_the_output_items_unmodified_and_answers_the_tool(self):
        first = [{"role": "user", "content": routes.PROBE_QUESTION}]
        items = routes.next_input(first, {"output": self.first_output})
        self.assertEqual(items[0], first[0])
        self.assertEqual(items[1:3], self.first_output)    # reasoning passed back as returned
        self.assertEqual(items[3], {"type": "function_call_output", "call_id": "call_1", "output": "3"})

    def test_summary_and_checks(self):
        turn1 = routes.summarize({"status": "completed", "output": self.first_output})
        self.assertEqual(turn1["reasoning_items"], 1)
        self.assertTrue(turn1["reasoning_encrypted"])
        self.assertEqual(turn1["function_calls"], [{"name": "count_letters", "arguments_valid": True}])
        turn2 = routes.summarize({"status": "completed", "output": [
            {"type": "message", "content": [{"type": "output_text", "text": "There are 3."}]}]})
        report = {"turn1": turn1, "turn2": turn2, "key_spend_usd": 0.002, "key_deleted": True}
        self.assertTrue(all(routes.probe_checks(report).values()))
        report["key_spend_usd"] = 0.0
        self.assertFalse(routes.probe_checks(report)["spend_recorded"])

    def test_body_streams_and_stores_nothing(self):
        body = routes.probe_body(routes.ROUTES[0], [])
        self.assertIs(body["store"], False)    # OpenRouter's Responses API refuses store: true
        self.assertIs(body["stream"], True)
        self.assertEqual(body["model"], "glm-5.3-flash-modal")

    def test_scrub_removes_keys_from_error_text(self):
        text = routes.scrub("HTTP 401: Received API Key = sk-abcdef123456, try again", "sk-abcdef123456")
        self.assertNotIn("abcdef", text)
        self.assertNotIn("sk-zzzzzz", routes.scrub("bad key sk-zzzzzz99"))


class PaidAndAdminGuards(unittest.TestCase):
    def test_probe_refuses_without_approval_and_register_needs_the_master_key(self):
        env = {k: v for k, v in os.environ.items() if k not in ("EXPERIMENT_APPROVED", "LITELLM_MASTER_KEY")}
        with mock.patch.dict(os.environ, env, clear=True):
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(routes.main(["--probe"]), 2)
                self.assertEqual(routes.main(["--register"]), 2)
            self.assertIn("EXPERIMENT_APPROVED", out.getvalue())
            self.assertIn("LITELLM_MASTER_KEY", out.getvalue())


if __name__ == "__main__":
    unittest.main()
