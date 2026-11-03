"""The gateway callback that makes Anthropic server-side web search round-trip
through LiteLLM's Responses bridge (gateway_hooks/honeypot_gateway_hooks.py).

The repo venv has no LiteLLM, so the pure functions are tested as they are and the
callback class is tested against a stand-in ``litellm`` package. The real classes,
the SSE serialization and the whole Codex -> gateway -> Anthropic round trip are
checked inside the gateway image by the e2e probe, not here.
"""

import asyncio
import importlib.util
import json
import os
import sys
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


REPO = Path(__file__).parents[1]
HOOKS = REPO / "gateway_hooks" / "honeypot_gateway_hooks.py"


def _load(name, stub_litellm=False):
    saved = {k: v for k, v in sys.modules.items() if k == "litellm" or k.startswith("litellm.")}
    if stub_litellm:
        _install_litellm_stub()
    try:
        spec = importlib.util.spec_from_file_location(name, HOOKS)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader
        spec.loader.exec_module(module)
        return module
    finally:
        for k in [k for k in sys.modules if k == "litellm" or k.startswith("litellm.")]:
            del sys.modules[k]
        sys.modules.update(saved)


class _ResponseObject(dict):
    """Stand-in for LiteLLM's BaseLiteLLMOpenAIResponseObject: dict and attributes."""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc


def _install_litellm_stub():
    class CustomLogger:
        pass

    logger = SimpleNamespace(info=lambda *a, **k: None, warning=lambda *a, **k: None)
    modules = {
        "litellm": types.ModuleType("litellm"),
        "litellm._logging": types.ModuleType("litellm._logging"),
        "litellm.integrations": types.ModuleType("litellm.integrations"),
        "litellm.integrations.custom_logger": types.ModuleType("litellm.integrations.custom_logger"),
        "litellm.types": types.ModuleType("litellm.types"),
        "litellm.types.llms": types.ModuleType("litellm.types.llms"),
        "litellm.types.llms.openai": types.ModuleType("litellm.types.llms.openai"),
    }
    modules["litellm._logging"].verbose_proxy_logger = logger
    modules["litellm.integrations.custom_logger"].CustomLogger = CustomLogger
    modules["litellm.types.llms.openai"].BaseLiteLLMOpenAIResponseObject = _ResponseObject
    sys.modules.update(modules)


H = _load("honeypot_gateway_hooks_pure")


class _Kind:
    """An enum-like event type, as LiteLLM's ResponsesAPIStreamEvents values are."""

    def __init__(self, value):
        self.value = value


def server_call(call_id="srvtoolu_01abc", query="codex npm latest", status="completed", **extra):
    item = {"type": "function_call", "id": call_id, "call_id": call_id, "name": "web_search",
            "arguments": json.dumps({"query": query}), "status": status}
    item.update(extra)
    return item


def local_call(call_id="toolu_01xyz"):
    return {"type": "function_call", "id": call_id, "call_id": call_id, "name": "exec_command",
            "arguments": json.dumps({"cmd": "true"}), "status": "completed"}


class ServerToolCallTests(unittest.TestCase):
    def test_server_tool_ids_are_recognised(self):
        self.assertTrue(H.is_server_tool_call(server_call()))
        self.assertTrue(H.is_server_tool_call(SimpleNamespace(**server_call())))
        self.assertTrue(H.is_server_tool_call({**server_call(), "type": "custom_tool_call"}))
        self.assertTrue(H.is_server_tool_call({**server_call(), "type": _Kind("function_call")}))

    def test_local_calls_and_other_items_are_not(self):
        self.assertFalse(H.is_server_tool_call(local_call()))
        self.assertFalse(H.is_server_tool_call({"type": "message", "id": "srvtoolu_x"}))
        self.assertFalse(H.is_server_tool_call({"type": "function_call_output", "call_id": "srvtoolu_x"}))
        self.assertFalse(H.is_server_tool_call(None))

    def test_rewritten_item_carries_the_query(self):
        new = H.search_call_item(server_call(query="latest codex"))
        self.assertEqual(new, {"type": "web_search_call", "id": "srvtoolu_01abc", "status": "completed",
                               "action": {"type": "search", "query": "latest codex"}})

    def test_status_override_and_missing_arguments(self):
        new = H.search_call_item({**server_call(), "arguments": ""}, status="in_progress")
        self.assertEqual(new["status"], "in_progress")
        self.assertEqual(new["action"], {"type": "search"})
        broken = H.search_call_item({**server_call(), "arguments": "{not json"})
        self.assertEqual(broken["action"], {"type": "search"})

    def test_web_fetch_becomes_open_page(self):
        item = {**server_call(), "name": "web_fetch", "arguments": json.dumps({"url": "https://example.org"})}
        self.assertEqual(H.search_call_item(item)["action"], {"type": "open_page", "url": "https://example.org"})


class OutputRewriteTests(unittest.TestCase):
    def test_only_server_calls_change_and_order_holds(self):
        message = {"type": "message", "role": "assistant", "content": []}
        keep = local_call()
        out, ids = H.rewrite_output([server_call(), keep, message])
        self.assertEqual(ids, {"srvtoolu_01abc"})
        self.assertEqual([i["type"] for i in out], ["web_search_call", "function_call", "message"])
        self.assertIs(out[1], keep)
        self.assertIs(out[2], message)

    def test_nothing_to_rewrite(self):
        out, ids = H.rewrite_output([local_call()])
        self.assertEqual(ids, set())
        self.assertEqual(H.rewrite_output(None), ([], set()))


def result_block(call_id="srvtoolu_01abc", marker="enc-1"):
    return {"type": "web_search_tool_result", "tool_use_id": call_id,
            "content": [{"type": "web_search_result", "url": "https://example.org", "encrypted_content": marker}]}


def echoed(query="q"):
    """A web_search_call as Codex sends it back: no id."""
    return {"type": "web_search_call", "status": "completed", "action": {"type": "search", "query": query}}


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class StashTests(unittest.TestCase):
    def test_record_and_lookup_in_order_per_key(self):
        stash = H.SearchStash()
        calls = [("srvtoolu_a", "web_search", {"type": "search", "query": "q"}),
                 ("srvtoolu_b", "web_search", {"type": "search", "query": "q"})]
        kept = stash.record("key1", calls, [result_block("srvtoolu_a"), result_block("srvtoolu_b")])
        self.assertEqual(kept, 2)
        self.assertEqual(stash.lookup("key1", {"type": "search", "query": "q"}, 0), ("srvtoolu_a", "web_search"))
        self.assertEqual(stash.lookup("key1", {"type": "search", "query": "q"}, 1), ("srvtoolu_b", "web_search"))
        self.assertIsNone(stash.lookup("key1", {"type": "search", "query": "q"}, 2))
        self.assertIsNone(stash.lookup("key2", {"type": "search", "query": "q"}, 0))
        self.assertEqual(stash.block("srvtoolu_a")["content"][0]["encrypted_content"], "enc-1")

    def test_a_call_without_its_result_is_not_kept(self):
        stash = H.SearchStash()
        self.assertEqual(stash.record("k", [("srvtoolu_a", "web_search", {"type": "search", "query": "q"})], []), 0)
        self.assertIsNone(stash.lookup("k", {"type": "search", "query": "q"}, 0))

    def test_recording_twice_does_not_duplicate(self):
        stash = H.SearchStash()
        call = [("srvtoolu_a", "web_search", {"type": "search", "query": "q"})]
        stash.record("k", call, [result_block("srvtoolu_a")])
        self.assertEqual(stash.record("k", call, [result_block("srvtoolu_a")]), 0)
        self.assertIsNone(stash.lookup("k", {"type": "search", "query": "q"}, 1))

    def test_age_and_count_bounds(self):
        clock = Clock()
        stash = H.SearchStash(ttl=10, limit=2, clock=clock)
        for n in range(3):
            stash.record("k", [(f"srvtoolu_{n}", "web_search", {"type": "search", "query": f"q{n}"})],
                         [result_block(f"srvtoolu_{n}")])
        self.assertIsNone(stash.block("srvtoolu_0"))
        self.assertIsNone(stash.lookup("k", {"type": "search", "query": "q0"}, 0))
        self.assertIsNotNone(stash.block("srvtoolu_2"))
        clock.now = 11
        stash.record("k", [], [])
        self.assertIsNone(stash.block("srvtoolu_2"))


class RestoreInputTests(unittest.TestCase):
    def stash(self):
        stash = H.SearchStash()
        stash.record("key", [("srvtoolu_01abc", "web_search", {"type": "search", "query": "q"})],
                     [result_block()])
        return stash

    def test_kept_search_is_restored_in_place(self):
        items = [{"type": "message", "role": "user", "content": []}, echoed("q"), local_call(),
                 {"type": "function_call_output", "call_id": "toolu_01xyz", "output": "ok"}]
        new, restored, dropped = H.restore_search_input(items, "key", self.stash())
        self.assertEqual((restored, dropped), (1, 0))
        self.assertEqual([i["type"] for i in new], ["message", "function_call", "function_call", "function_call_output"])
        self.assertEqual(new[1]["call_id"], "srvtoolu_01abc")
        self.assertEqual(new[1]["name"], "web_search")
        self.assertEqual(json.loads(new[1]["arguments"]), {"query": "q"})

    def test_unknown_search_other_key_and_leftovers_are_dropped(self):
        items = [echoed("other query"),
                 {"type": "function_call_output", "call_id": "srvtoolu_01abc", "output": "unsupported call"},
                 server_call(call_id="srvtoolu_unknown"), local_call()]
        new, restored, dropped = H.restore_search_input(items, "key", self.stash())
        self.assertEqual((restored, dropped), (0, 3))
        self.assertEqual([i["call_id"] for i in new], ["toolu_01xyz"])
        _, restored, dropped = H.restore_search_input([echoed("q")], "another key", self.stash())
        self.assertEqual((restored, dropped), (0, 1))

    def test_repeated_query_maps_to_successive_searches(self):
        stash = H.SearchStash()
        stash.record("k", [("srvtoolu_1", "web_search", {"type": "search", "query": "q"})], [result_block("srvtoolu_1")])
        stash.record("k", [("srvtoolu_2", "web_search", {"type": "search", "query": "q"})], [result_block("srvtoolu_2")])
        new, restored, _ = H.restore_search_input([echoed("q"), local_call(), echoed("q"), echoed("q")], "k", stash)
        self.assertEqual(restored, 2)
        self.assertEqual([i["call_id"] for i in new], ["srvtoolu_1", "toolu_01xyz", "srvtoolu_2"])

    def test_non_list_input_is_unchanged(self):
        self.assertEqual(H.restore_search_input("hello", "k", H.SearchStash()), ("hello", 0, 0))
        self.assertEqual(H.restore_search_input(None, "k", H.SearchStash()), (None, 0, 0))


class AttachResultsTests(unittest.TestCase):
    def test_results_go_on_the_assistant_message_holding_the_call(self):
        stash = H.SearchStash()
        stash.record("k", [("srvtoolu_01abc", "web_search", {"type": "search", "query": "q"})], [result_block()])
        messages = [
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": None, "tool_calls": [
                {"id": "srvtoolu_01abc", "type": "function", "function": {"name": "web_search", "arguments": "{}"}},
                {"id": "toolu_01xyz", "type": "function", "function": {"name": "exec_command", "arguments": "{}"}}]},
            {"role": "tool", "tool_call_id": "toolu_01xyz", "content": "ok"},
        ]
        self.assertEqual(H.attach_search_results(messages, stash), 1)
        self.assertEqual(messages[1]["provider_specific_fields"]["web_search_results"], [result_block()])
        self.assertNotIn("provider_specific_fields", messages[0])
        self.assertEqual(H.attach_search_results(messages, stash), 0)  # already there

    def test_nothing_kept_nothing_attached(self):
        messages = [{"role": "assistant", "tool_calls": [{"id": "srvtoolu_x", "function": {}}]}]
        self.assertEqual(H.attach_search_results(messages, H.SearchStash()), 0)
        self.assertEqual(H.attach_search_results(None, H.SearchStash()), 0)

    def test_keep_searches_reads_calls_and_surfaced_results(self):
        stash = H.SearchStash()
        response = SimpleNamespace(output=[server_call(query="q"), local_call()],
                                   provider_specific_fields={"web_search_results": [result_block()]})
        self.assertEqual(H.keep_searches(stash, "k", response), 1)
        self.assertEqual(stash.lookup("k", {"type": "search", "query": "q"}, 0), ("srvtoolu_01abc", "web_search"))
        bare = SimpleNamespace(output=[server_call(call_id="srvtoolu_x", query="z")], provider_specific_fields=None)
        self.assertEqual(H.keep_searches(stash, "k", bare), 0)


class ModelGateTests(unittest.TestCase):
    def test_default_prefixes(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(H.MODEL_PREFIXES_ENV, None)
            self.assertTrue(H.is_server_search_model("claude-opus-5-5"))
            self.assertTrue(H.is_server_search_model("anthropic/claude-opus-5-5"))
            self.assertFalse(H.is_server_search_model("gpt-5.6-luna"))
            self.assertFalse(H.is_server_search_model(None))

    def test_prefixes_from_the_environment(self):
        with mock.patch.dict(os.environ, {H.MODEL_PREFIXES_ENV: " opus-only , other/ "}):
            self.assertTrue(H.is_server_search_model("Opus-only-1"))
            self.assertFalse(H.is_server_search_model("claude-opus-5-5"))


def bridge_stream(as_objects=False):
    """The event sequence LiteLLM's bridge emits for one server search, one local
    tool call and a completed response."""
    events = [
        {"type": "response.created", "response": {"id": "resp_1", "output": []}},
        {"type": "response.output_item.added", "output_index": 0,
         "item": server_call(status="in_progress", arguments="")},
        {"type": "response.function_call_arguments.delta", "item_id": "srvtoolu_01abc", "delta": "{\"query\""},
        {"type": "response.function_call_arguments.delta", "item_id": "srvtoolu_01abc", "delta": ": \"q\"}"},
        {"type": "response.function_call_arguments.done", "item_id": "srvtoolu_01abc", "arguments": "{}"},
        {"type": "response.output_item.done", "output_index": 0, "item": server_call(query="q")},
        {"type": "response.output_item.added", "output_index": 1, "item": {**local_call(), "status": "in_progress"}},
        {"type": "response.function_call_arguments.delta", "item_id": "toolu_01xyz", "delta": "{}"},
        {"type": "response.function_call_arguments.done", "item_id": "toolu_01xyz", "arguments": "{}"},
        {"type": "response.output_item.done", "output_index": 1, "item": local_call()},
        {"type": "response.completed",
         "response": {"id": "resp_1", "output": [server_call(query="q"), local_call()]}},
    ]
    if not as_objects:
        return events

    def obj(d):
        return SimpleNamespace(**{k: obj(v) if isinstance(v, dict) and k == "response" else v
                                  for k, v in d.items()})

    out = []
    for e in events:
        o = obj(e)
        o.type = _Kind(e["type"])
        if "item" in e:
            o.item = SimpleNamespace(**e["item"])
        out.append(o)
    return out


class StreamRewriteTests(unittest.TestCase):
    def run_stream(self, events):
        rewriter = H.StreamRewriter()
        return [x for x in (rewriter.event(e) for e in events) if x is not None]

    def test_dict_events(self):
        out = self.run_stream(bridge_stream())
        kinds = [e["type"] for e in out]
        self.assertEqual(kinds, [
            "response.created",
            "response.output_item.added", "response.output_item.done",
            "response.output_item.added", "response.function_call_arguments.delta",
            "response.function_call_arguments.done", "response.output_item.done",
            "response.completed"])
        self.assertEqual(out[1]["item"]["type"], "web_search_call")
        self.assertEqual(out[1]["item"]["status"], "in_progress")
        self.assertEqual(out[2]["item"], {"type": "web_search_call", "id": "srvtoolu_01abc",
                                          "status": "completed", "action": {"type": "search", "query": "q"}})
        self.assertEqual(out[6]["item"]["name"], "exec_command")
        completed = out[-1]["response"]["output"]
        self.assertEqual([i["type"] for i in completed], ["web_search_call", "function_call"])

    def test_attribute_events_with_enum_types(self):
        out = self.run_stream(bridge_stream(as_objects=True))
        self.assertEqual(len(out), 8)
        self.assertEqual(out[2].item["action"]["query"], "q")
        self.assertEqual(out[-1].response.output[0]["type"], "web_search_call")
        self.assertEqual(out[-1].response.output[1].name if hasattr(out[-1].response.output[1], "name")
                         else out[-1].response.output[1]["name"], "exec_command")

    def test_stream_without_server_search_is_identical(self):
        events = [e for e in bridge_stream() if "srvtoolu" not in json.dumps(e)]
        before = json.dumps(events, sort_keys=True)
        out = self.run_stream(events)
        self.assertEqual(json.dumps(out, sort_keys=True), before)


def search_body():
    """Codex's standalone-search request (shape captured from the client)."""
    return {"id": "01a1a003-20c7-7ab1-ae31-31b23f7580f4", "model": "gpt-5.6-luna", "input": [],
            "commands": {"search_query": [{"q": "x"}]},
            "settings": {"allowed_callers": ["direct"], "external_web_access": True},
            "max_output_tokens": 10000}


def litellm_strip(body, params=("id", "litellm_logging_obj", "metadata")):
    """The loop LiteLLM's pass-through runs over its own parameter names."""
    taken = {}
    for key in params:
        if key in body:
            taken[key] = body.pop(key, None)
    return taken


class KeepUpstreamFieldsTests(unittest.TestCase):
    def test_the_search_id_survives_the_parameter_strip(self):
        body = H.keep_search_body({**search_body(), "litellm_logging_obj": object()}, "/v1/alpha/search")
        self.assertIsInstance(body, H.KeepUpstreamFields)
        taken = litellm_strip(body)
        self.assertEqual(body["id"], search_body()["id"])
        self.assertIsNone(taken["id"])  # LiteLLM takes no parameter from it
        self.assertNotIn("litellm_logging_obj", body)
        self.assertEqual(json.loads(json.dumps(body)), search_body())
        plain = search_body()
        litellm_strip(plain)
        self.assertNotIn("id", plain)  # what happened before the fix

    def test_other_requests_are_left_as_they_are(self):
        self.assertIs(type(H.keep_search_body(search_body(), "/v1/responses")), dict)
        self.assertIs(type(H.keep_search_body({"commands": {}, "input": []}, "/v1/alpha/search")), dict)
        self.assertIs(type(H.keep_search_body({"id": "x"}, "")), dict)
        self.assertIsInstance(H.keep_search_body(search_body(), ""), H.KeepUpstreamFields)
        self.assertEqual(H.keep_search_body(None, "/v1/alpha/search"), None)
        kept = H.KeepUpstreamFields(search_body())
        self.assertIs(H.keep_search_body(kept, "/v1/alpha/search"), kept)
        self.assertEqual(kept.pop("model"), "gpt-5.6-luna")
        self.assertEqual(kept.pop("absent", "default"), "default")


class CallbackTests(unittest.TestCase):
    """The callback class against a stand-in LiteLLM package."""

    @classmethod
    def setUpClass(cls):
        cls.M = _load("honeypot_gateway_hooks_cb", stub_litellm=True)
        cls.cb = cls.M.proxy_handler_instance

    def test_module_without_litellm_defines_no_callback(self):
        self.assertFalse(hasattr(H, "proxy_handler_instance"))
        self.assertTrue(hasattr(self.M, "proxy_handler_instance"))

    def setUp(self):
        self.cb.stash = self.M.SearchStash()

    def test_pre_call_acts_only_for_anthropic_responses(self):
        def data(model):
            return {"model": model, "input": [echoed("never kept"), local_call()]}

        key = SimpleNamespace(token="hashed-key")
        out = asyncio.run(self.cb.async_pre_call_hook(key, None, data("claude-opus-5-5"), "aresponses"))
        self.assertEqual([i["type"] for i in out["input"]], ["function_call"])  # nothing kept: dropped
        untouched = asyncio.run(self.cb.async_pre_call_hook(key, None, data("gpt-5.6-luna"), "aresponses"))
        self.assertEqual(len(untouched["input"]), 2)
        chat = asyncio.run(self.cb.async_pre_call_hook(key, None, data("claude-opus-5-5"), "acompletion"))
        self.assertEqual(len(chat["input"]), 2)

    def test_round_trip_restores_the_search_with_its_results(self):
        """Stream out (kept), next request in (restored), deployment call (results attached)."""
        events = bridge_stream()
        events[-1]["response"]["provider_specific_fields"] = {"web_search_results": [result_block()]}
        key = SimpleNamespace(request_route="/v1/responses", token="hashed-key")

        async def run_stream():
            async def source():
                for e in events:
                    yield e
            return [c async for c in self.cb.async_post_call_streaming_iterator_hook(
                key, source(), {"model": "claude-opus-5-5"})]

        asyncio.run(run_stream())
        data = {"model": "claude-opus-5-5", "input": [echoed("q"), local_call()]}
        asyncio.run(self.cb.async_pre_call_hook(key, None, data, "aresponses"))
        self.assertEqual([i["call_id"] for i in data["input"]], ["srvtoolu_01abc", "toolu_01xyz"])
        messages = [{"role": "assistant", "tool_calls": [{"id": "srvtoolu_01abc", "function": {}}]}]
        self.assertIsNone(asyncio.run(self.cb.async_pre_call_deployment_hook({"messages": messages}, None)))
        self.assertEqual(messages[0]["provider_specific_fields"]["web_search_results"], [result_block()])
        other_key = {"model": "claude-opus-5-5", "input": [echoed("q")]}
        asyncio.run(self.cb.async_pre_call_hook(SimpleNamespace(token="other"), None, other_key, "aresponses"))
        self.assertEqual(other_key["input"], [])

    def test_pass_through_pre_call_keeps_the_search_id(self):
        key = SimpleNamespace(request_route="/v1/alpha/search", token="hashed-key")
        out = asyncio.run(self.cb.async_pre_call_hook(key, None, search_body(), "pass_through_endpoint"))
        self.assertIsInstance(out, self.M.KeepUpstreamFields)
        litellm_strip(out)
        self.assertIn("id", out)
        other = SimpleNamespace(request_route="/anthropic/v1/messages", token="hashed-key")
        data = {"id": "msg", "model": "claude"}
        self.assertIs(asyncio.run(self.cb.async_pre_call_hook(other, None, data, "pass_through_endpoint")), data)

    def test_deployment_hook_never_raises(self):
        self.assertIsNone(asyncio.run(self.cb.async_pre_call_deployment_hook({"messages": [object()]}, None)))
        self.assertIsNone(asyncio.run(self.cb.async_pre_call_deployment_hook({}, None)))

    def test_pre_call_never_raises(self):
        bad = {"model": "claude-opus-5-5", "input": [object()]}
        out = asyncio.run(self.cb.async_pre_call_hook(None, None, bad, "aresponses"))
        self.assertIs(out, bad)

    def test_success_hook_rewrites_output(self):
        response = SimpleNamespace(output=[server_call(), local_call()])
        out = asyncio.run(self.cb.async_post_call_success_hook({"model": "claude-opus-5-5"}, None, response))
        self.assertIsInstance(out.output[0], _ResponseObject)
        self.assertEqual(out.output[0]["type"], "web_search_call")
        self.assertEqual(out.output[1]["name"], "exec_command")
        other = SimpleNamespace(output=[server_call()])
        asyncio.run(self.cb.async_post_call_success_hook({"model": "gpt-5.6-luna"}, None, other))
        self.assertEqual(other.output[0]["type"], "function_call")

    def collect(self, route, model, events):
        async def source():
            for e in events:
                yield e

        async def run():
            key = SimpleNamespace(request_route=route)
            return [c async for c in self.cb.async_post_call_streaming_iterator_hook(
                key, source(), {"model": model})]

        return asyncio.run(run())

    def test_stream_hook_is_gated_by_route_and_model(self):
        events = bridge_stream()
        rewritten = self.collect("/v1/responses", "claude-opus-5-5", bridge_stream())
        self.assertEqual(len(rewritten), 8)
        self.assertIsInstance(rewritten[2]["item"], _ResponseObject)
        self.assertEqual(len(self.collect("/v1/chat/completions", "claude-opus-5-5", events)), len(events))
        self.assertEqual(len(self.collect("/v1/responses", "gpt-5.6-luna", events)), len(events))

    def test_stream_hook_passes_a_bad_chunk_through(self):
        class Boom:
            @property
            def type(self):
                raise RuntimeError("bad chunk")

        boom = Boom()
        out = self.collect("/v1/responses", "claude-opus-5-5", [boom])
        self.assertEqual(out, [boom])


if __name__ == "__main__":
    unittest.main()
