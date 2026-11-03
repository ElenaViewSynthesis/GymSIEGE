"""LiteLLM proxy callback: Anthropic server-side web search through the Responses bridge.

Codex talks to the gateway in the OpenAI Responses format. For an Anthropic model,
LiteLLM bridges each Responses request to Anthropic Messages. When the model uses
Anthropic's server-side web search, Anthropic runs the search inside the same API
call, and LiteLLM 1.99.1 hands the search back to Codex as an ordinary
``function_call`` named ``web_search`` whose ``call_id`` is the server tool id
(``srvtoolu_...``). Codex cannot run that call, answers it with an
"unsupported call" output, and the next request carries that output to Anthropic
as a ``tool_result`` for a server tool, which Anthropic refuses
("unexpected tool_use_id found in tool_result blocks"). The cell then fails.

This callback makes the round trip consistent, for Anthropic targets on the
Responses route only:

* response (streaming and non-streaming): a server-tool ``function_call`` is
  rewritten into the hosted-search item Codex already understands, a
  ``web_search_call`` with a ``search`` action carrying the query, and its argument
  delta events are dropped. Codex records the search and does not try to run it.
  The search's id, query and the result blocks Anthropic returned for it are kept in
  memory, per virtual key;
* next request: Codex sends the ``web_search_call`` back without its id. Each one is
  turned back into the server-tool ``function_call`` it came from (matched by query,
  in order), and just before the call goes to Anthropic the kept result blocks are
  attached to the assistant message, so LiteLLM's own history builder restores the
  ``server_tool_use`` and ``web_search_tool_result`` blocks exactly as Anthropic
  produced them. The model sees its real history, search included.

  A search with nothing kept for it (the gateway restarted mid-session, or the
  results were never seen) is dropped from the input instead, and so are leftover
  server-tool outputs. Dropping keeps the request valid but hides the search from
  the model; the gateway log says when it happens.

It also keeps Codex's standalone-search requests intact on the gateway's
``/v1/alpha/search`` pass-through route: LiteLLM strips the body's ``id`` as one
of its own parameter names, and OpenAI's search endpoint requires it (see
``KeepUpstreamFields``).

Everything else passes through untouched, and any error inside the callback leaves
the chunk, response or request as it was. The gateway is shared with other
projects, and their traffic must not depend on this file.

The pure functions below work on plain dicts and attribute objects, so they are
tested offline without LiteLLM (tests/test_gateway_hooks.py). The callback class at
the bottom is only defined when LiteLLM is importable.

Mount it next to the gateway config and register it:

    litellm_settings:
      callbacks: ["langfuse_otel", "honeypot_gateway_hooks.proxy_handler_instance"]
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections import OrderedDict
from collections.abc import AsyncIterator, Iterable
from typing import Any

SERVER_TOOL_PREFIX = "srvtoolu_"
RESPONSES_ROUTES = frozenset({"/v1/responses", "/responses", "/openai/v1/responses"})
DEFAULT_MODEL_PREFIXES = ("claude", "anthropic/")
MODEL_PREFIXES_ENV = "HONEYPOT_SERVER_SEARCH_MODEL_PREFIXES"
STASH_TTL_SECONDS = 6 * 3600
STASH_MAX_SEARCHES = 4000

ITEM_EVENTS = frozenset({"response.output_item.added", "response.output_item.done"})
ARGUMENT_EVENTS = frozenset(
    {"response.function_call_arguments.delta", "response.function_call_arguments.done"}
)
RESPONSE_EVENTS = frozenset(
    {"response.completed", "response.incomplete", "response.failed", "response.in_progress"}
)
CALL_TYPES = frozenset({"function_call", "custom_tool_call"})
OUTPUT_TYPES = frozenset({"function_call_output", "custom_tool_call_output"})
RESULT_KEYS = ("web_search_results", "tool_results")


def field(obj: Any, name: str, default: Any = None) -> Any:
    """Read ``name`` from a dict or an attribute object."""
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def text(value: Any) -> str:
    """The plain string of an enum or string value, '' for anything else."""
    value = getattr(value, "value", value)
    return value if isinstance(value, str) else ""


def as_plain(obj: Any) -> Any:
    """A JSON-shaped copy of a dict or pydantic object (for kept result blocks)."""
    if hasattr(obj, "model_dump"):
        try:
            return obj.model_dump(mode="json", exclude_none=True)
        except Exception:
            pass
    if isinstance(obj, dict):
        return {k: as_plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [as_plain(v) for v in obj]
    return obj


def model_prefixes() -> tuple[str, ...]:
    raw = os.environ.get(MODEL_PREFIXES_ENV, "")
    prefixes = tuple(p.strip().lower() for p in raw.split(",") if p.strip())
    return prefixes or DEFAULT_MODEL_PREFIXES


def is_server_search_model(model: Any) -> bool:
    return isinstance(model, str) and model.lower().startswith(model_prefixes())


def is_server_id(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(SERVER_TOOL_PREFIX)


def is_server_tool_call(item: Any) -> bool:
    """A function or custom tool call whose id is an Anthropic server tool id."""
    if text(field(item, "type")) not in CALL_TYPES:
        return False
    return is_server_id(field(item, "call_id") or field(item, "id"))


def call_arguments(item: Any) -> dict[str, Any]:
    raw = field(item, "arguments")
    if raw is None:
        raw = field(item, "input")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
        except ValueError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def search_action(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """The Responses ``web_search_call`` action for one server tool call."""
    if name == "web_fetch":
        url = arguments.get("url")
        return {"type": "open_page", "url": url} if isinstance(url, str) else {"type": "open_page"}
    query = arguments.get("query")
    action: dict[str, Any] = {"type": "search"}
    if isinstance(query, str):
        action["query"] = query
    queries = arguments.get("queries")
    if isinstance(queries, list) and all(isinstance(q, str) for q in queries):
        action["queries"] = queries
    return action


def action_key(action: Any) -> str:
    """What identifies a search across the round trip: its action, as Codex echoes it."""
    action = as_plain(action) if action is not None else {}
    if not isinstance(action, dict):
        return ""
    kind = action.get("type") or "search"
    target = action.get("query") if kind == "search" else action.get("url")
    return json.dumps([kind, target if isinstance(target, str) else None])


def search_call_item(item: Any, status: str | None = None) -> dict[str, Any]:
    """Rewrite one server tool call into a hosted-search output item."""
    call_id = field(item, "call_id") or field(item, "id")
    item_status = status or text(field(item, "status")) or "completed"
    name = text(field(item, "name")) or "web_search"
    return {
        "type": "web_search_call",
        "id": call_id,
        "status": item_status,
        "action": search_action(name, call_arguments(item)),
    }


def server_call_item(call_id: str, name: str, action: Any) -> dict[str, Any]:
    """The server-tool ``function_call`` a ``web_search_call`` came from."""
    action = as_plain(action) if action is not None else {}
    arguments: dict[str, Any] = {}
    if isinstance(action, dict):
        if name == "web_fetch" and isinstance(action.get("url"), str):
            arguments["url"] = action["url"]
        elif isinstance(action.get("query"), str):
            arguments["query"] = action["query"]
    return {"type": "function_call", "id": call_id, "call_id": call_id, "name": name,
            "arguments": json.dumps(arguments), "status": "completed"}


def rewrite_output(items: Iterable[Any] | None) -> tuple[list[Any], set[str]]:
    """Rewrite server tool calls in a response's output list.

    Returns the new list and the ids that were rewritten.
    """
    out: list[Any] = []
    rewritten: set[str] = set()
    for item in items or ():
        if is_server_tool_call(item):
            new = search_call_item(item)
            rewritten.add(new["id"])
            out.append(new)
        else:
            out.append(item)
    return out, rewritten


def server_calls(items: Iterable[Any] | None) -> list[tuple[str, str, dict[str, Any]]]:
    """(id, tool name, action) of each server tool call in an output list, in order."""
    calls = []
    for item in items or ():
        if is_server_tool_call(item):
            new = search_call_item(item)
            calls.append((new["id"], text(field(item, "name")) or "web_search", new["action"]))
    return calls


def result_blocks(provider_fields: Any) -> list[dict[str, Any]]:
    """The server-tool result blocks LiteLLM surfaced for a response."""
    blocks: list[dict[str, Any]] = []
    for key in RESULT_KEYS:
        for block in field(provider_fields, key) or ():
            plain = as_plain(block)
            if isinstance(plain, dict) and is_server_id(plain.get("tool_use_id")):
                blocks.append(plain)
    return blocks


class SearchStash:
    """Server searches seen in responses: id, tool name and action per virtual key,
    in order, and the result blocks per id. Bounded by age and count; thread-safe."""

    def __init__(self, ttl: float = STASH_TTL_SECONDS, limit: int = STASH_MAX_SEARCHES,
                 clock=time.monotonic):
        self.ttl, self.limit, self.clock = ttl, limit, clock
        self.lock = threading.Lock()
        self.calls: dict[str, dict[str, list[str]]] = {}  # namespace -> action key -> ids
        self.entries: OrderedDict[str, dict[str, Any]] = OrderedDict()  # id -> entry

    def record(self, namespace: str, calls: list[tuple[str, str, dict[str, Any]]],
               blocks: list[dict[str, Any]]) -> int:
        """Keep each call that has its result block. Returns how many were kept."""
        by_id = {b["tool_use_id"]: b for b in blocks}
        kept = 0
        with self.lock:
            self._prune()
            for call_id, name, action in calls:
                block = by_id.get(call_id)
                if block is None or call_id in self.entries:
                    continue
                key = action_key(action)
                self.entries[call_id] = {"namespace": namespace, "key": key, "name": name,
                                         "block": block, "at": self.clock()}
                self.calls.setdefault(namespace, {}).setdefault(key, []).append(call_id)
                kept += 1
            self._prune()
        return kept

    def lookup(self, namespace: str, action: Any, occurrence: int) -> tuple[str, str] | None:
        """(id, tool name) of the n-th search with this action under this key."""
        with self.lock:
            ids = self.calls.get(namespace, {}).get(action_key(action), [])
            if occurrence < len(ids) and ids[occurrence] in self.entries:
                call_id = ids[occurrence]
                return call_id, self.entries[call_id]["name"]
        return None

    def block(self, call_id: str) -> dict[str, Any] | None:
        with self.lock:
            entry = self.entries.get(call_id)
            return entry["block"] if entry else None

    def _prune(self) -> None:
        now = self.clock()
        while self.entries:
            call_id, entry = next(iter(self.entries.items()))
            if len(self.entries) <= self.limit and now - entry["at"] <= self.ttl:
                break
            self.entries.popitem(last=False)
            ids = self.calls.get(entry["namespace"], {}).get(entry["key"], [])
            if call_id in ids:
                ids.remove(call_id)


def restore_search_input(items: Any, namespace: str, stash: SearchStash) -> tuple[Any, int, int]:
    """Turn each ``web_search_call`` in a request input back into its server-tool call.

    Returns (new input, restored, dropped). A search with nothing kept for it, a
    server-tool call without a kept result and any server-tool output are dropped.
    A string input, or anything that is not a list, is returned unchanged.
    """
    if not isinstance(items, list):
        return items, 0, 0
    kept: list[Any] = []
    restored = dropped = 0
    seen: dict[str, int] = {}
    for item in items:
        kind = text(field(item, "type"))
        call_id = field(item, "call_id")
        if kind == "web_search_call":
            action = field(item, "action")
            key = action_key(action)
            occurrence = seen.get(key, 0)
            seen[key] = occurrence + 1
            found = stash.lookup(namespace, action, occurrence)
            if found:
                kept.append(server_call_item(found[0], found[1], action))
                restored += 1
            else:
                dropped += 1
            continue
        if is_server_id(call_id) and kind in OUTPUT_TYPES:
            dropped += 1
            continue
        if is_server_id(call_id) and kind in CALL_TYPES and stash.block(call_id) is None:
            dropped += 1
            continue
        kept.append(item)
    return kept, restored, dropped


def attach_search_results(messages: Any, stash: SearchStash) -> int:
    """Attach kept result blocks to the assistant messages holding server-tool calls,
    where LiteLLM's Anthropic history builder looks for them. Returns how many."""
    if not isinstance(messages, list):
        return 0
    attached = 0
    for message in messages:
        if field(message, "role") != "assistant":
            continue
        blocks = []
        for call in field(message, "tool_calls") or ():
            call_id = field(call, "id")
            if is_server_id(call_id):
                block = stash.block(call_id)
                if block is not None:
                    blocks.append(block)
        if not blocks:
            continue
        fields = field(message, "provider_specific_fields")
        fields = dict(fields) if isinstance(fields, dict) else {}
        present = {field(b, "tool_use_id") for b in fields.get("web_search_results") or ()}
        new = [b for b in blocks if b["tool_use_id"] not in present]
        if not new:
            continue
        fields["web_search_results"] = list(fields.get("web_search_results") or ()) + new
        set_field(message, "provider_specific_fields", fields)
        attached += len(new)
    return attached


class StreamRewriter:
    """Rewrites one Responses event stream; holds the ids rewritten so far.

    ``make_item`` turns a rewritten item dict into whatever object the stream's
    serializer expects (LiteLLM's response object; a plain dict offline).
    ``on_response`` gets each final response object before its output is rewritten.
    """

    def __init__(self, make_item=lambda d: d, on_response=None):
        self.make_item = make_item
        self.on_response = on_response
        self.rewritten: set[str] = set()

    def event(self, chunk: Any) -> Any | None:
        """The chunk to forward, or None to drop it."""
        kind = text(field(chunk, "type"))
        if kind in ITEM_EVENTS:
            item = field(chunk, "item")
            if is_server_tool_call(item):
                status = "in_progress" if kind.endswith(".added") else "completed"
                new = search_call_item(item, status=status)
                self.rewritten.add(new["id"])
                return set_field(chunk, "item", self.make_item(new))
            return chunk
        if kind in ARGUMENT_EVENTS:
            item_id = field(chunk, "item_id")
            if isinstance(item_id, str) and (item_id in self.rewritten or is_server_id(item_id)):
                return None
            return chunk
        if kind in RESPONSE_EVENTS:
            response = field(chunk, "response")
            output = field(response, "output")
            if output:
                if self.on_response is not None:
                    self.on_response(response)
                new_output, ids = rewrite_output(output)
                if ids:
                    self.rewritten |= ids
                    made = [self.make_item(i) if isinstance(i, dict) and i.get("id") in ids else i
                            for i in new_output]
                    set_field(response, "output", made)
            return chunk
        return chunk


def set_field(obj: Any, name: str, value: Any) -> Any:
    if isinstance(obj, dict):
        obj[name] = value
    else:
        setattr(obj, name, value)
    return obj


def route_of(user_api_key_dict: Any) -> str:
    route = field(user_api_key_dict, "request_route")
    return route if isinstance(route, str) else ""


def namespace_of(user_api_key_dict: Any) -> str:
    """The virtual key's hashed token (what LiteLLM stores), so searches never cross keys."""
    token = field(user_api_key_dict, "token") or field(user_api_key_dict, "api_key")
    return token if isinstance(token, str) else ""


def keep_searches(stash: SearchStash, namespace: str, response: Any) -> int:
    """Record the server searches of one final response object."""
    calls = server_calls(field(response, "output"))
    if not calls:
        return 0
    return stash.record(namespace, calls, result_blocks(field(response, "provider_specific_fields")))


# Codex's standalone search (code-mode models) POSTs {base_url}/alpha/search,
# which the gateway forwards to OpenAI as a configured pass-through route.
# LiteLLM's pass-through pops every key it treats as one of its own parameters
# from the body before forwarding, and "id" is one of them; OpenAI's search
# endpoint requires that id ("Missing required parameter: 'id'"). The pre-call
# hook runs just before that strip and its returned dict becomes the body, so it
# returns the body as a KeepUpstreamFields, whose pop() leaves these keys in place.
STANDALONE_SEARCH_ROUTES = frozenset({"/v1/alpha/search", "/alpha/search"})
KEPT_UPSTREAM_KEYS = frozenset({"id"})


class KeepUpstreamFields(dict):
    """A pass-through body whose upstream fields survive LiteLLM's parameter strip.

    ``pop`` of a kept key returns None (so LiteLLM takes no parameter from it) and
    leaves the key in the body; every other key pops as usual."""

    def pop(self, key, *default):
        if key in KEPT_UPSTREAM_KEYS and key in self:
            return None
        return super().pop(key, *default)


def is_standalone_search_body(data: Any, route: str) -> bool:
    """A standalone-search request: its route, or (if the route is unknown) its shape."""
    if not isinstance(data, dict) or not isinstance(data.get("id"), str):
        return False
    if route in STANDALONE_SEARCH_ROUTES:
        return True
    return not route and "commands" in data and "input" in data


def keep_search_body(data: Any, route: str) -> Any:
    """The body to hand back from the pre-call hook of a pass-through request."""
    if is_standalone_search_body(data, route) and not isinstance(data, KeepUpstreamFields):
        return KeepUpstreamFields(data)
    return data


try:  # pragma: no cover - exercised inside the gateway image, not in the repo venv
    from litellm._logging import verbose_proxy_logger
    from litellm.integrations.custom_logger import CustomLogger
    from litellm.types.llms.openai import BaseLiteLLMOpenAIResponseObject
except ImportError:  # the repo's tests import the pure functions only
    CustomLogger = None  # type: ignore[assignment,misc]


if CustomLogger is not None:  # pragma: no cover - see tests/test_gateway_hooks.py docstring

    def _response_object(item: dict[str, Any]) -> Any:
        return BaseLiteLLMOpenAIResponseObject(**item)

    class HoneypotServerSearchBridge(CustomLogger):  # type: ignore[misc,valid-type]
        """See the module docstring."""

        def __init__(self) -> None:
            super().__init__()
            self.stash = SearchStash()

        async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
            if call_type == "pass_through_endpoint":
                try:
                    return keep_search_body(data, route_of(user_api_key_dict))
                except Exception as exc:  # never break the shared gateway
                    verbose_proxy_logger.warning("honeypot_gateway_hooks: pass-through skipped: %s", exc)
                    return data
            try:
                if call_type != "aresponses" or not is_server_search_model(data.get("model")):
                    return data
                new_input, restored, dropped = restore_search_input(
                    data.get("input"), namespace_of(user_api_key_dict), self.stash)
                if restored or dropped:
                    data["input"] = new_input
                    log = verbose_proxy_logger.warning if dropped else verbose_proxy_logger.info
                    log("honeypot_gateway_hooks: %s: %d hosted search(es) restored, %d dropped",
                        data.get("model"), restored, dropped)
            except Exception as exc:  # never break the shared gateway
                verbose_proxy_logger.warning("honeypot_gateway_hooks: pre-call skipped: %s", exc)
            return data

        async def async_pre_call_deployment_hook(self, kwargs, call_type):
            try:
                attached = attach_search_results(kwargs.get("messages"), self.stash)
                if attached:
                    verbose_proxy_logger.info(
                        "honeypot_gateway_hooks: attached %d kept search result(s)", attached)
            except Exception as exc:
                verbose_proxy_logger.warning("honeypot_gateway_hooks: deployment hook skipped: %s", exc)
            return None

        async def async_post_call_success_hook(self, data, user_api_key_dict, response):
            try:
                if not is_server_search_model(data.get("model")):
                    return response
                output = field(response, "output")
                if not output:
                    return response
                keep_searches(self.stash, namespace_of(user_api_key_dict), response)
                new_output, ids = rewrite_output(output)
                if ids:
                    set_field(response, "output", [
                        _response_object(i) if isinstance(i, dict) and i.get("id") in ids else i
                        for i in new_output])
                    verbose_proxy_logger.info(
                        "honeypot_gateway_hooks: rewrote %d server search call(s)", len(ids))
            except Exception as exc:
                verbose_proxy_logger.warning("honeypot_gateway_hooks: post-call skipped: %s", exc)
            return response

        async def async_post_call_streaming_iterator_hook(
            self, user_api_key_dict, response: AsyncIterator[Any], request_data: dict
        ):
            active = False
            try:
                active = (route_of(user_api_key_dict) in RESPONSES_ROUTES
                          and is_server_search_model(request_data.get("model")))
            except Exception:
                active = False
            if not active:
                async for chunk in response:
                    yield chunk
                return
            namespace = namespace_of(user_api_key_dict)

            def on_response(final: Any) -> None:
                try:
                    keep_searches(self.stash, namespace, final)
                except Exception as exc:
                    verbose_proxy_logger.warning("honeypot_gateway_hooks: results not kept: %s", exc)

            rewriter = StreamRewriter(make_item=_response_object, on_response=on_response)
            async for chunk in response:
                try:
                    out = rewriter.event(chunk)
                except Exception as exc:
                    verbose_proxy_logger.warning("honeypot_gateway_hooks: chunk passed through: %s", exc)
                    out = chunk
                if out is not None:
                    yield out

    proxy_handler_instance = HoneypotServerSearchBridge()
