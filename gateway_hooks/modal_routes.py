#!/usr/bin/env python3
"""Gateway routes for GLM 5.3 and Kimi K3 served by Modal, through OpenRouter or directly.

A real-agent cell names one gateway model (``--model``); the runner mints the
cell's virtual key for that name alone, and Codex speaks the Responses protocol
to the gateway. Nothing else in a cell depends on the model, so a lure cohort
(or any other suite) runs one of these models once the gateway has a route for
it. This file defines those routes and nothing else in the pipeline changes:

    glm-5.3-flash-modal  ->  openrouter/z-ai/glm-5.3-flash   Modal endpoint modal/fp4
    glm-5.3-modal        ->  openrouter/z-ai/glm-5.3         Modal endpoint modal
    kimi-k3-modal        ->  openrouter/moonshotai/kimi-k3   Modal endpoint modal/mxfp4
    kimi-k3-modal-direct ->  openai/moonshotai/Kimi-K3       the Kimi K3 Modal Endpoint itself

The direct route calls a Modal Endpoint with no OpenRouter in between. LiteLLM's
OpenAI provider sends Codex's Responses request to ``<api_base>/responses``, and the
endpoint serves the Responses API itself, with reasoning on by default. Its
``api_base`` and ``api_key`` refer to MODAL_KIMI_K3_BASE_URL (the endpoint's URL,
ending in /v1) and BEARER (the proxy token, ``wk-<id>.ws-<secret>``) in the
gateway's environment, and it charges Modal's Shared Endpoint rates for Kimi K3.

Each OpenRouter route pins OpenRouter's provider routing to the one Modal endpoint
(``provider.only`` with ``allow_fallbacks: false``: if Modal cannot serve a
request, the request fails rather than going to another provider), turns
reasoning on, and asks for the reasoning back in a form the client can return
unmodified (``include: reasoning.encrypted_content``). LiteLLM 1.99.1 sends a
Responses request for an ``openrouter/`` model to OpenRouter's own
``/responses`` endpoint and merges the route's ``extra_body`` into the body last,
so these fields reach OpenRouter as written (they replace any ``reasoning`` or
``include`` the client sent). The route charges the endpoint's listed per-token
prices, so a cell's ``max_budget`` holds. The OpenRouter key is not stored: the
route refers to ``os.environ/OPENROUTER_API_KEY`` in the gateway's environment,
like the Anthropic route.

Modes (one per run):

    (default)    check: free. Reads OpenRouter's public endpoint catalogue (no
                 key) and checks, per OpenRouter route, that the pinned Modal
                 endpoint exists, accepts tools and reasoning, has the context
                 the route states, and still lists the prices the route charges.
                 For the direct route it reads the endpoint's /v1/models with
                 MODAL_KIMI_K3_BASE_URL and BEARER from the environment (skipped
                 when they are not set, a failure under --register).
                 ``--payloads`` also prints what --register would send.
    --register   adds the routes the gateway does not have (POST /model/new with
                 LITELLM_MASTER_KEY) and verifies them through /model/info; a
                 route already there is compared, never duplicated. Writes to the
                 shared gateway.
    --probe      paid, needs EXPERIMENT_APPROVED=1. Per route: mints a virtual key
                 pinned to the route (USD 0.10 cap), makes one streamed
                 Responses call with a function tool, returns the tool's output
                 together with the first turn's output items unmodified
                 (reasoning included) in a second call, reads the key's spend,
                 and deletes the key.

No mode prints or stores a key. The master key and the probe's virtual key stay
in memory; a route's ``api_key`` is the environment reference only.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from modal_honeypot.virtual_key import (  # noqa: E402
    LiteLLMAdminClient,
    VirtualKeyError,
    admin_base_url,
    key_spend,
    mint_virtual_key,
    revoke_virtual_key,
)

CATALOGUE_URL = "https://openrouter.ai/api/v1/models/{slug}/endpoints"
KEY_ENV = "OPENROUTER_API_KEY"
PROVIDER_NAME = "Modal"
REQUIRED_PARAMETERS = ("tools", "reasoning")
GATEWAY_URL_NAMES = ("LITELLM_BASE_URL", "OPENAI_BASE_URL", "OPENAI_API_BASE")
DEFAULT_GATEWAY = "http://localhost:4000"
PROBE_CAP_USD = 0.10
PROBE_TTL = "15m"
PROBE_MAX_OUTPUT_TOKENS = 4096
SPEND_WAIT_SECONDS = 90.0
USER_AGENT = "honeypot-modal-routes/1"
FINAL_EVENTS = frozenset({"response.completed", "response.incomplete", "response.failed"})
KEY_SHAPE = re.compile(r"\b(?:sk|or)-[A-Za-z0-9_*.\-]{6,}")


@dataclass(frozen=True)
class Route:
    name: str             # the gateway model name: a cell's --model and its key's one model
    slug: str             # the upstream model: an OpenRouter model, or the Modal Endpoint's model name
    tag: str              # OpenRouter: the Modal endpoint tag pinned with provider.only ("" when direct)
    input_cost: str       # USD per token, exactly as listed (OpenRouter's catalogue, Modal's models page)
    output_cost: str
    cache_read_cost: str
    context: int          # tokens
    via: str = "openrouter"   # "openrouter", or "modal": a Modal Endpoint called directly
    base_url_env: str = ""    # modal: the variable holding the endpoint's OpenAI-compatible base URL (.../v1)
    key_env: str = KEY_ENV    # the variable holding the credential, in the gateway's environment


ROUTES: tuple[Route, ...] = (
    Route("glm-5.3-flash-modal", "z-ai/glm-5.3-flash", "modal/fp4",
          "0.00000015", "0.0000005", "0.00000003", 1_048_576),
    Route("glm-5.3-modal", "z-ai/glm-5.3", "modal",
          "0.0000014", "0.0000044", "0.00000026", 1_048_576),
    Route("kimi-k3-modal", "moonshotai/kimi-k3", "modal/mxfp4",
          "0.000003", "0.000015", "0.0000003", 1_048_576),
    # The Kimi K3 Modal Endpoint, called directly with a proxy token (wk-<id>.ws-<secret>) as the
    # bearer api_key. Costs are Modal's Shared Endpoint rates for Kimi K3.
    Route("kimi-k3-modal-direct", "moonshotai/Kimi-K3", "",
          "0.000003", "0.000015", "0.0000003", 1_048_576,
          via="modal", base_url_env="MODAL_KIMI_K3_BASE_URL", key_env="BEARER"),
)


def select_routes(names: str | None) -> tuple[Route, ...]:
    if not names:
        return ROUTES
    wanted = [n.strip() for n in names.split(",") if n.strip()]
    known = {r.name: r for r in ROUTES}
    unknown = [n for n in wanted if n not in known]
    if unknown or not wanted:
        raise ValueError(f"--routes must name routes among {', '.join(known)}")
    return tuple(known[n] for n in wanted)


def extra_body(route: Route) -> dict[str, Any]:
    return {
        "provider": {"only": [route.tag], "allow_fallbacks": False},
        "reasoning": {"enabled": True},
        "include": ["reasoning.encrypted_content"],
    }


def costs(route: Route) -> dict[str, float]:
    return {
        "input_cost_per_token": float(Decimal(route.input_cost)),
        "output_cost_per_token": float(Decimal(route.output_cost)),
        "cache_read_input_token_cost": float(Decimal(route.cache_read_cost)),
    }


def litellm_params(route: Route) -> dict[str, Any]:
    if route.via == "modal":
        # LiteLLM's OpenAI provider sends a Responses request to <api_base>/responses and
        # the key as "Authorization: Bearer"; the endpoint serves both APIs itself, with
        # reasoning on by default, so nothing is added to the body.
        return {
            "model": f"openai/{route.slug}",
            "api_base": f"os.environ/{route.base_url_env}",
            "api_key": f"os.environ/{route.key_env}",
        }
    return {
        "model": f"openrouter/{route.slug}",
        "api_key": f"os.environ/{route.key_env}",
        "extra_body": extra_body(route),
    }


def litellm_payload(route: Route) -> dict[str, Any]:
    """The /model/new body for one route. Its credentials and URL are env references."""
    where = ({"honeypot_route": "modal-direct", "modal_endpoint_env": route.base_url_env}
             if route.via == "modal" else
             {"honeypot_route": "openrouter-modal", "openrouter_endpoint": route.tag})
    return {
        "model_name": route.name,
        "litellm_params": litellm_params(route),
        "model_info": {**costs(route), "max_input_tokens": route.context, **where},
    }


# --- check: OpenRouter's public endpoint catalogue ---------------------------------

def catalogue_file(slug: str) -> str:
    return "endpoints-" + slug.replace("/", "_") + ".json"


def fetch_catalogue(slug: str, *, timeout: float = 30.0) -> Mapping[str, Any]:
    request = urllib.request.Request(CATALOGUE_URL.format(slug=slug), headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def load_catalogue(slug: str, directory: Path | None) -> Mapping[str, Any]:
    if directory is None:
        return fetch_catalogue(slug)
    return json.loads((directory / catalogue_file(slug)).read_text(encoding="utf-8"))


def find_endpoint(route: Route, catalogue: Mapping[str, Any]) -> Mapping[str, Any] | None:
    data = catalogue.get("data", catalogue)
    for endpoint in data.get("endpoints") or []:
        if endpoint.get("tag") == route.tag:
            return endpoint
    return None


def check_endpoint(route: Route, catalogue: Mapping[str, Any]) -> list[str]:
    """What is wrong with the route against the catalogue (empty when it matches)."""
    endpoint = find_endpoint(route, catalogue)
    if endpoint is None:
        return [f"OpenRouter lists no endpoint tagged {route.tag} for {route.slug}"]
    problems = []
    if endpoint.get("provider_name") != PROVIDER_NAME:
        problems.append(f"endpoint {route.tag} is served by {endpoint.get('provider_name')!r}, not Modal")
    status = endpoint.get("status")
    if isinstance(status, (int, float)) and status < 0:
        problems.append(f"endpoint {route.tag} reports status {status} (degraded or down)")
    supported = set(endpoint.get("supported_parameters") or [])
    missing = [p for p in REQUIRED_PARAMETERS if p not in supported]
    if missing:
        problems.append(f"endpoint {route.tag} does not accept {', '.join(missing)}")
    pricing = endpoint.get("pricing") or {}
    for field, ours in (("prompt", route.input_cost), ("completion", route.output_cost),
                        ("input_cache_read", route.cache_read_cost)):
        listed = pricing.get(field)
        if listed is None or Decimal(str(listed)) != Decimal(ours):
            problems.append(f"{field} price: OpenRouter lists {listed}, the route charges {ours}")
    context = endpoint.get("context_length")
    if not isinstance(context, int) or context < route.context:
        problems.append(f"context {context} is below the route's {route.context}")
    return problems


def check_models_listing(route: Route, listing: Mapping[str, Any]) -> list[str]:
    """What is wrong with a direct route against its endpoint's /v1/models (empty when it matches)."""
    models = {m.get("id"): m for m in listing.get("data") or [] if isinstance(m, Mapping)}
    if route.slug not in models:
        return [f"the endpoint serves {sorted(map(str, models)) or 'no models'}, not {route.slug}"]
    context = models[route.slug].get("max_model_len") or models[route.slug].get("context_length")
    if isinstance(context, int) and context < route.context:
        return [f"context {context} is below the route's {route.context}"]
    return []


def endpoint_base(value: str) -> str:
    base = value.strip().rstrip("/")
    if not base.startswith("https://") or not base.endswith("/v1"):
        raise ValueError("the endpoint base URL must be https:// and end in /v1")
    return base


def fetch_models(base: str, key: str, *, timeout: float = 30.0) -> Mapping[str, Any]:
    request = urllib.request.Request(endpoint_base(base) + "/models",
                                     headers={"Authorization": f"Bearer {key}", "User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def prices(route: Route) -> str:
    per_million = [f"${float(Decimal(v) * 1_000_000):g}"
                   for v in (route.input_cost, route.output_cost, route.cache_read_cost)]
    return f"per M tokens in {per_million[0]}, out {per_million[1]}, cached in {per_million[2]}"


def check_direct(route: Route, strict: bool) -> int:
    """1 if the direct route fails its check (or, when strict, cannot be checked)."""
    base, key = os.environ.get(route.base_url_env, ""), os.environ.get(route.key_env, "")
    if not (base and key):
        print(f"{route.name}: not checked -- export {route.base_url_env} and {route.key_env} "
              f"(from .env.local) to check the Modal endpoint")
        return int(strict)
    try:
        listing = fetch_models(base, key)
    except urllib.error.HTTPError as exc:
        print(f"{route.name}: the endpoint's /v1/models answered HTTP {exc.code}")
        return 1
    except (OSError, urllib.error.URLError, json.JSONDecodeError, ValueError) as exc:
        print(f"{route.name}: endpoint unavailable ({type(exc).__name__}: {scrub(str(exc), key)[:160]})")
        return 1
    problems = check_models_listing(route, listing)
    print(f"{route.name}: {route.slug} @ Modal endpoint ${route.base_url_env} -- "
          f"{'ok' if not problems else 'MISMATCH'}; {prices(route)} "
          f"(Modal's rates; its models page is not an API, so they are not checked)")
    for problem in problems:
        print(f"  - {problem}")
    return int(bool(problems))


def run_check(routes: Sequence[Route], directory: Path | None, payloads: bool, strict: bool = False) -> int:
    """Check every route. A direct route whose URL and key are not in the environment
    is reported and skipped, and fails only when strict (registration)."""
    failed = 0
    for route in routes:
        if route.via == "modal":
            failed += check_direct(route, strict)
            if payloads:
                print(json.dumps(litellm_payload(route), indent=2))
            continue
        try:
            catalogue = load_catalogue(route.slug, directory)
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            print(f"{route.name}: catalogue unavailable ({type(exc).__name__})")
            failed += 1
            continue
        problems = check_endpoint(route, catalogue)
        endpoint = find_endpoint(route, catalogue) or {}
        print(f"{route.name}: {route.slug} @ {route.tag} -- "
              f"{'ok' if not problems else 'MISMATCH'}; {prices(route)}; "
              f"uptime 1d {endpoint.get('uptime_last_1d', 'n/a')}")
        for problem in problems:
            print(f"  - {problem}")
        failed += bool(problems)
        if payloads:
            print(json.dumps(litellm_payload(route), indent=2))
    return 1 if failed else 0


# --- register: the gateway's admin API ---------------------------------------------

class GatewayAdmin(LiteLLMAdminClient):
    """The key client plus the two model-management calls registration needs."""

    def models(self) -> list[Mapping[str, Any]]:
        data = self._request("GET", "/model/info").get("data")
        return list(data) if isinstance(data, list) else []

    def add_model(self, payload: Mapping[str, object]) -> Mapping[str, object]:
        return self._request("POST", "/model/new", payload=payload)


def deployments(models: Iterable[Mapping[str, Any]], name: str) -> list[Mapping[str, Any]]:
    return [m for m in models if m.get("model_name") == name]


def compare_registered(entry: Mapping[str, Any], route: Route) -> list[str]:
    """Differences between a registered deployment and the route (non-secret fields only)."""
    params = entry.get("litellm_params") or {}
    info = entry.get("model_info") or {}
    want = litellm_payload(route)
    problems = []
    if params.get("model") != want["litellm_params"]["model"]:
        problems.append(f"model is {params.get('model')!r}, want {want['litellm_params']['model']!r}")
    if params.get("extra_body") != want["litellm_params"].get("extra_body"):
        problems.append("extra_body differs from the route's provider pin and reasoning settings")
    for field, value in costs(route).items():
        got = info.get(field)
        if not isinstance(got, (int, float)) or abs(float(got) - value) > 1e-15:
            problems.append(f"{field} is {got}, want {value}")
    return problems


def run_register(routes: Sequence[Route], admin: GatewayAdmin, directory: Path | None) -> int:
    if run_check(routes, directory, payloads=False, strict=True):
        print("refusing --register: fix the failed check first")
        return 1
    failed = 0
    current = admin.models()
    for route in routes:
        existing = deployments(current, route.name)
        if len(existing) > 1:
            print(f"{route.name}: {len(existing)} deployments share this name; remove the extras by hand")
            failed += 1
            continue
        if existing:
            problems = compare_registered(existing[0], route)
            print(f"{route.name}: already registered -- {'matches' if not problems else 'DIFFERS'}")
            for problem in problems:
                print(f"  - {problem}")
            failed += bool(problems)
            continue
        admin.add_model(litellm_payload(route))
        print(f"{route.name}: added")
    after = admin.models()
    for route in routes:
        found = deployments(after, route.name)
        problems = ["not visible in /model/info"] if len(found) != 1 else compare_registered(found[0], route)
        if problems:
            print(f"{route.name}: verify FAILED -- " + "; ".join(problems))
            failed += 1
    return 1 if failed else 0


# --- probe: one tool round trip per route ------------------------------------------

PROBE_QUESTION = "How many r's are in the word 'strawberry'? Use the count_letters tool, then answer with the number."
PROBE_TOOL = {
    "type": "function",
    "name": "count_letters",
    "description": "Count how many times a letter occurs in a word.",
    "parameters": {
        "type": "object",
        "properties": {"word": {"type": "string"}, "letter": {"type": "string"}},
        "required": ["word", "letter"],
        "additionalProperties": False,
    },
}


def probe_body(route: Route, items: list[Any]) -> dict[str, Any]:
    return {
        "model": route.name, "input": items, "tools": [PROBE_TOOL], "tool_choice": "auto",
        "store": False, "stream": True, "max_output_tokens": PROBE_MAX_OUTPUT_TOKENS,
    }


def read_stream(lines: Iterable[bytes]) -> tuple[Mapping[str, Any] | None, Counter, list[Any]]:
    """The final response object of a Responses SSE stream, the event counts, and any errors."""
    final, events, errors = None, Counter(), []
    for raw in lines:
        line = raw.decode("utf-8", "replace").strip()
        if not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if data == "[DONE]":
            break
        try:
            event = json.loads(data)
        except json.JSONDecodeError:
            events["unparsed"] += 1
            continue
        kind = event.get("type")
        events[kind] += 1
        if kind == "error":
            errors.append(event.get("error") or event.get("message") or "error event")
        if kind in FINAL_EVENTS:
            final = event.get("response")
    return final, events, errors


def summarize(response: Mapping[str, Any] | None) -> dict[str, Any]:
    """What a turn returned, without its text beyond a short answer."""
    output = list((response or {}).get("output") or [])
    reasoning = [i for i in output if i.get("type") == "reasoning"]
    calls = [i for i in output if i.get("type") == "function_call"]
    text = "".join(
        part.get("text", "") for item in output if item.get("type") == "message"
        for part in item.get("content") or [] if part.get("type") == "output_text"
    )
    return {
        "status": (response or {}).get("status"),
        "item_types": [i.get("type") for i in output],
        "reasoning_items": len(reasoning),
        "reasoning_encrypted": any(i.get("encrypted_content") for i in reasoning),
        "reasoning_text": any(i.get("content") or i.get("summary") for i in reasoning),
        "function_calls": [{"name": c.get("name"), "arguments_valid": _arguments(c) is not None} for c in calls],
        "answer": text.strip()[:120],
        "usage": (response or {}).get("usage"),
    }


def _arguments(call: Mapping[str, Any]) -> dict[str, Any] | None:
    try:
        args = json.loads(call.get("arguments") or "")
    except (TypeError, json.JSONDecodeError):
        return None
    return args if isinstance(args, dict) else None


def tool_result(call: Mapping[str, Any]) -> str:
    args = _arguments(call) or {}
    word, letter = str(args.get("word", "")), str(args.get("letter", ""))
    return str(word.lower().count(letter.lower())) if letter else "error: no letter given"


def next_input(first_input: list[Any], response: Mapping[str, Any]) -> list[Any]:
    """The second turn's input: the first turn's input, its output items exactly as
    returned (reasoning included), and one output per function call."""
    output = list(response.get("output") or [])
    results = [
        {"type": "function_call_output", "call_id": c.get("call_id"), "output": tool_result(c)}
        for c in output if c.get("type") == "function_call"
    ]
    return [*first_input, *output, *results]


def post_responses(v1_url: str, key: str, body: Mapping[str, Any], *, timeout: float = 300.0):
    request = urllib.request.Request(
        v1_url + "/responses", data=json.dumps(body).encode(), method="POST",
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json",
                 "Accept": "text/event-stream", "User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            cost = response.headers.get("x-litellm-response-cost")
            final, events, errors = read_stream(response)
    except urllib.error.HTTPError as exc:
        detail = exc.read(600).decode("utf-8", "replace")
        return None, Counter(), [scrub(f"HTTP {exc.code}: {detail}", key)], None
    except (urllib.error.URLError, TimeoutError) as exc:
        return None, Counter(), [f"{type(exc).__name__}"], None
    return final, events, [scrub(str(e), key) for e in errors], cost


def scrub(text: str, *secrets: str) -> str:
    """Error text with the given secrets and anything shaped like a key removed:
    a gateway error may echo part of the key it refused."""
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[redacted]")
    return KEY_SHAPE.sub("[redacted]", text)


def wait_for_spend(admin: LiteLLMAdminClient, key_id: str, deadline: float) -> float | None:
    spend = None
    while True:
        try:
            spend = key_spend(admin, key_id)
        except VirtualKeyError:
            spend = None
        if (spend or 0) > 0 or time.monotonic() > deadline:
            return spend
        time.sleep(5)


def probe_route(route: Route, admin: LiteLLMAdminClient, v1_url: str) -> dict[str, Any]:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    minted = mint_virtual_key(
        admin, alias=f"modal-route-probe-{route.name}-{stamp}", model=route.name,
        budget_usd=PROBE_CAP_USD, ttl=PROBE_TTL,
        metadata={"purpose": "modal-route-probe", "route": route.name, "endpoint": route.tag},
    )
    report: dict[str, Any] = {"route": route.name, "slug": route.slug, "endpoint": route.tag, "stamp": stamp}
    try:
        first = [{"role": "user", "content": PROBE_QUESTION}]
        final1, events1, errors1, cost1 = post_responses(v1_url, minted.key, probe_body(route, first))
        report["turn1"] = {**summarize(final1), "events": dict(events1), "errors": errors1, "cost_header": cost1}
        if final1 is not None and any(i.get("type") == "function_call" for i in final1.get("output") or []):
            final2, events2, errors2, cost2 = post_responses(
                v1_url, minted.key, probe_body(route, next_input(first, final1)))
            report["turn2"] = {**summarize(final2), "events": dict(events2), "errors": errors2, "cost_header": cost2}
        report["key_spend_usd"] = wait_for_spend(admin, minted.management_id, time.monotonic() + SPEND_WAIT_SECONDS)
    finally:
        try:
            revoke_virtual_key(admin, minted.management_id)
            report["key_deleted"] = True
        except VirtualKeyError:
            report["key_deleted"] = False
    report["checks"] = probe_checks(report)
    report["ok"] = all(report["checks"].values())
    return report


def probe_checks(report: Mapping[str, Any]) -> dict[str, bool]:
    t1, t2 = report.get("turn1") or {}, report.get("turn2") or {}
    calls = t1.get("function_calls") or []
    spend = report.get("key_spend_usd")
    return {
        "turn1_completed": t1.get("status") == "completed",
        "reasoning_returned": (t1.get("reasoning_items") or 0) > 0,
        "tool_called_with_valid_arguments": bool(calls) and all(c["arguments_valid"] for c in calls),
        "turn2_completed_with_answer": t2.get("status") == "completed" and bool(t2.get("answer")),
        "spend_recorded": isinstance(spend, (int, float)) and 0 < spend <= PROBE_CAP_USD,
        "key_deleted": bool(report.get("key_deleted")),
    }


# --- entry point -------------------------------------------------------------------

def gateway_from_env(explicit: str | None) -> str:
    if explicit:
        return explicit
    for name in GATEWAY_URL_NAMES:
        if os.environ.get(name):
            return os.environ[name]
    return DEFAULT_GATEWAY


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--register", action="store_true", help="add missing routes to the gateway")
    mode.add_argument("--probe", action="store_true", help="one paid tool round trip per route")
    parser.add_argument("--routes", help="comma-separated route names (default: all three)")
    parser.add_argument("--gateway-url", help=f"gateway URL (default: {', '.join(GATEWAY_URL_NAMES)} or {DEFAULT_GATEWAY})")
    parser.add_argument("--catalogue-dir", type=Path, help="read saved endpoints-<slug>.json files instead of the API")
    parser.add_argument("--payloads", action="store_true", help="check: also print the /model/new bodies")
    parser.add_argument("--report", type=Path, help="probe: write the reports (no secrets) as JSON here")
    args = parser.parse_args(argv)
    try:
        routes = select_routes(args.routes)
    except ValueError as exc:
        parser.error(str(exc))

    if not (args.register or args.probe):
        return run_check(routes, args.catalogue_dir, args.payloads)

    if args.probe and os.environ.get("EXPERIMENT_APPROVED") != "1":
        print("refusing --probe: it makes paid calls; set EXPERIMENT_APPROVED=1 on the author's go")
        return 2
    master = os.environ.get("LITELLM_MASTER_KEY", "")
    if not master:
        print("LITELLM_MASTER_KEY is not set")
        return 2
    base = admin_base_url(gateway_from_env(args.gateway_url))
    admin = GatewayAdmin(base, master)
    try:
        if args.register:
            return run_register(routes, admin, args.catalogue_dir)
        reports = [probe_route(route, admin, base + "/v1") for route in routes]
    except VirtualKeyError as exc:
        print(f"gateway error: {exc}")
        return 1
    for report in reports:
        verdict = "ok" if report["ok"] else "FAILED " + ", ".join(k for k, v in report["checks"].items() if not v)
        t1, t2 = report.get("turn1") or {}, report.get("turn2") or {}
        print(f"{report['route']}: {verdict}; spend ${report.get('key_spend_usd')}; "
              f"turn 1 {t1.get('item_types')}, turn 2 {t2.get('item_types')}, answer {t2.get('answer')!r}")
        for error in (t1.get("errors") or []) + (t2.get("errors") or []):
            print(f"  - {str(error)[:300]}")
    if args.report:
        args.report.write_text(json.dumps(reports, indent=2) + "\n", encoding="utf-8")
    return 0 if all(r["ok"] for r in reports) else 1


if __name__ == "__main__":
    sys.exit(main())
