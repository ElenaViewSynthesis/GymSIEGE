# Modal as an inference provider (GLM 5.3 and Kimi K3, through OpenRouter or directly)

Modal serves open-weight models that OpenRouter lists as provider endpoints. A
request reaches Modal when OpenRouter's provider routing is pinned to a Modal
endpoint and fallbacks are off. The honeypot gateway has one route per model
with that pin. It also has one direct route, `kimi-k3-modal-direct`, to a Kimi
K3 Modal Endpoint, with no OpenRouter in between (see "The direct route"
below). A lure run (or any other real-agent suite) uses one of these models by
naming its route as `--model`. The runner, the agent image and the scorers
stay the same.

## Calling a Modal endpoint through OpenRouter

This is the plain OpenRouter call: Chat Completions, reasoning on, provider
pinned to Modal. The assistant's `reasoning_details` go back unmodified, so the
second call continues the model's reasoning:

```python
from openai import OpenAI

client = OpenAI(
  base_url="https://openrouter.ai/api/v1",
  api_key="<OPENROUTER_API_KEY>",
)

# First API call with reasoning
response = client.chat.completions.create(
  model="z-ai/glm-5.3-flash",
  messages=[
          {
            "role": "user",
            "content": "How many r's are in the word 'strawberry'?"
          }
        ],
  extra_body={
          "provider": {
            "only": [
              "modal/fp4"
            ],
            "allow_fallbacks": False
          },
          "reasoning": {
            "enabled": True
          }
        }
)

# Extract the assistant message with reasoning_details
response = response.choices[0].message

# Preserve the assistant message with reasoning_details
messages = [
  {"role": "user", "content": "How many r's are in the word 'strawberry'?"},
  {
    "role": "assistant",
    "content": response.content,
    "reasoning_details": response.reasoning_details  # Pass back unmodified
  },
  {"role": "user", "content": "Are you sure? Think carefully."}
]

# Second API call - model continues reasoning from where it left off
response2 = client.chat.completions.create(
  model="z-ai/glm-5.3-flash",
  messages=messages,
  extra_body={
          "provider": {
            "only": [
              "modal/fp4"
            ],
            "allow_fallbacks": False
          },
          "reasoning": {
            "enabled": True
          }
        }
)
```

- `provider.only` takes the endpoint's tag, not just the provider name. Each
  model's Modal endpoint has its own tag (table below).
- With `allow_fallbacks: False`, a request Modal cannot serve fails. OpenRouter
  does not send it to another provider.
- The key is read from the environment and never written into code, config or
  a log.

## The Modal endpoints

These are the values in OpenRouter's public endpoint catalogue
(`https://openrouter.ai/api/v1/models/<slug>/endpoints`) on 2026-11-05. Prices
are USD per million tokens.

| Gateway route | OpenRouter model | Modal tag | Weights | Input | Output | Cached input | Context |
|---|---|---|---|---|---|---|---|
| `glm-5.3-flash-modal` | `z-ai/glm-5.3-flash` | `modal/fp4` | fp4 | 0.15 | 0.50 | 0.03 | 1,048,576 |
| `glm-5.3-modal` | `z-ai/glm-5.3` | `modal` | not listed | 1.40 | 4.40 | 0.26 | 1,048,576 |
| `kimi-k3-modal` | `moonshotai/kimi-k3` | `modal/mxfp4` | mxfp4 | 3.00 | 15.00 | 0.30 | 1,048,576 |

All three endpoints accept tools and reasoning. Kimi K3's tag is
`modal/mxfp4`, not `modal/fp4`: the snippet's tag works only for GLM 5.3
Flash. Kimi K3's endpoint does not list `tool_choice` as a supported parameter.
OpenRouter drops a parameter an endpoint does not support unless
`require_parameters` is set, and the routes do not set it. Codex sends
`tool_choice: "auto"`, which is the default anyway.

`gateway_hooks/modal_routes.py` holds these values. Its default mode checks
them against the live catalogue for free.

## How a lure run reaches Modal

```
run_lure_cohort.py --model kimi-k3-modal
  -> docker_honeypot/runner.py mints the cell's virtual key for kimi-k3-modal only
  -> Codex 0.164 in the cell, Responses wire format, through the egress proxy
  -> LiteLLM gateway, route kimi-k3-modal = openrouter/moonshotai/kimi-k3
  -> https://openrouter.ai/api/v1/responses, provider pinned to modal/mxfp4
  -> Modal
```

Each route's database entry, as `--register` sends it:

```json
{
  "model_name": "kimi-k3-modal",
  "litellm_params": {
    "model": "openrouter/moonshotai/kimi-k3",
    "api_key": "os.environ/OPENROUTER_API_KEY",
    "extra_body": {
      "provider": {"only": ["modal/mxfp4"], "allow_fallbacks": false},
      "reasoning": {"enabled": true},
      "include": ["reasoning.encrypted_content"]
    }
  },
  "model_info": {
    "input_cost_per_token": 3e-06,
    "output_cost_per_token": 1.5e-05,
    "cache_read_input_token_cost": 3e-07,
    "max_input_tokens": 1048576,
    "honeypot_route": "openrouter-modal",
    "openrouter_endpoint": "modal/mxfp4"
  }
}
```

- **The wire format.** LiteLLM 1.99.1 has an OpenRouter Responses config. It
  sends a Responses request for an `openrouter/` model to OpenRouter's own
  `/responses` endpoint, without converting it to Chat Completions. That
  endpoint takes the same `provider` and `reasoning` fields as Chat
  Completions. It is stateless, so Codex's `store: false` is required (it
  refuses `store: true`).
- **The route's fields win.** LiteLLM merges a route's `extra_body` into the
  outgoing body last, so the route's `provider`, `reasoning` and `include`
  replace whatever the client sent. Every cell therefore runs with the same
  pin and the same reasoning setting.
- **Reasoning round trip.** In the Responses format, `reasoning_details` become
  `reasoning` output items. `include: ["reasoning.encrypted_content"]` makes
  OpenRouter return them in a form a client can pass back unmodified. Codex
  carries them into the next request's input, just as the snippet passes
  `reasoning_details` back.
- **Costs.** The route charges the endpoint's listed per-token prices. LiteLLM
  then counts a cell's spend, and the per-cell `max_budget` holds. A route with
  no cost or a zero cost would void the cap.
- **Credentials.** The OpenRouter key is not stored in the gateway database.
  The route refers to `os.environ/OPENROUTER_API_KEY`, as the Anthropic route
  refers to `os.environ/ANTHROPIC_API_KEY`.
- **Nothing model-specific changes in a cell.** The route names avoid the
  prefixes that switch on model-specific code:
  - `claude` and `anthropic/` turn on the Anthropic search hook;
  - `gpt-` turns on Codex's standalone search.

  Lure cells run with web search disabled anyway. Message logging stays off
  gateway-wide.

## The direct route

`kimi-k3-modal-direct` calls a Kimi K3 Modal Endpoint (see
`modal-docs/modal-endpoints.md`) through LiteLLM's OpenAI provider:

```json
{
  "model_name": "kimi-k3-modal-direct",
  "litellm_params": {
    "model": "openai/moonshotai/Kimi-K3",
    "api_base": "os.environ/MODAL_KIMI_K3_BASE_URL",
    "api_key": "os.environ/BEARER"
  },
  "model_info": {
    "input_cost_per_token": 3e-06,
    "output_cost_per_token": 1.5e-05,
    "cache_read_input_token_cost": 3e-07,
    "max_input_tokens": 1048576,
    "honeypot_route": "modal-direct",
    "modal_endpoint_env": "MODAL_KIMI_K3_BASE_URL"
  }
}
```

- **URL.** `MODAL_KIMI_K3_BASE_URL` is the endpoint's URL plus `/v1`. LiteLLM
  sends Codex's Responses request to `<api_base>/responses`, and the endpoint
  serves that API itself.
- **Key.** `BEARER` is the proxy token, the id and secret joined as
  `wk-<id>.ws-<secret>`. LiteLLM sends it as `Authorization: Bearer`. The
  token must come from the workspace that owns the endpoint.
- **Reasoning.** It is on by default on the endpoint, so the route adds no
  `extra_body`. With no OpenRouter between them, there is no provider pin
  either.
- **Costs.** The route charges Modal's Shared Endpoint rates for Kimi K3,
  which are the same as OpenRouter's. If the endpoint is Dedicated, Modal bills
  its compute instead, and LiteLLM's spend is only an estimate.
- **Affinity routing.** The gateway sends no `Modal-Routing-Affinity-Key`
  header, so the turns of one cell may land on different containers and miss
  the prefix cache.
- **The free check.** It reads the endpoint's `/v1/models` with the two
  variables exported. It confirms that the endpoint serves
  `moonshotai/Kimi-K3` with a context of at least 1,048,576 tokens.

On 2026-11-05, a direct two-turn Responses call to the endpoint passed:
- turn 1 offered a function tool, and returned a reasoning item (as text) and
  a valid tool call;
- turn 2 received the turn-1 output items unmodified plus the tool's result,
  and answered correctly.

## Setup

Each step below changes shared state or spends money, so each one needs the
author's word.

1. **The key.** Put `OPENROUTER_API_KEY` in `.env.local` only. Never print it,
   commit it or pass it on a command line.
2. **The gateway's environment.** Add the key to the `litellm` service in
   `litellm-gateway/docker-compose.yml` (a gitignored folder; reproduce by hand
   when rebuilding the gateway):

   ```yaml
       environment:
         OPENROUTER_API_KEY: ${OPENROUTER_API_KEY:-}
         # the direct route (kimi-k3-modal-direct)
         MODAL_KIMI_K3_BASE_URL: ${MODAL_KIMI_K3_BASE_URL:-}
         BEARER: ${BEARER:-}
   ```

   Then recreate the gateway from WSL with `.env.local` exported. This restarts
   the shared gateway. To confirm the key arrived without printing it:

   ```bash
   docker exec litellm-gateway-litellm-1 sh -c 'test -n "$OPENROUTER_API_KEY" && echo set || echo missing'
   ```

3. **Check (free).** Compare the OpenRouter routes with the live catalogue.
   The direct route is checked against its endpoint only when
   `MODAL_KIMI_K3_BASE_URL` and `BEARER` are exported
   (`set -a; . ./.env.local; set +a`). Otherwise it is skipped, and
   `--register` refuses it. `--payloads` also prints the bodies that
   `--register` would send:

   ```bash
   .venv/bin/python gateway_hooks/modal_routes.py --payloads
   ```

4. **Register.** With `LITELLM_MASTER_KEY` exported from `.env.local`, add the
   routes the gateway lacks and verify them through `/model/info`:

   ```bash
   .venv/bin/python gateway_hooks/modal_routes.py --register
   ```

   A route that already exists is compared field by field and never
   duplicated. Two deployments under one name would load-balance between them.
   `--routes kimi-k3-modal` limits any mode to the routes named.
5. **Probe (paid, at most USD 0.10 per route).** For each route, the probe:
   - mints a virtual key pinned to the route;
   - makes one streamed Responses call with a function tool;
   - sends the tool's result back together with the first turn's output items,
     unmodified, reasoning included;
   - reads the key's spend, then deletes the key.

   It passes only if:
   - both turns complete;
   - reasoning items come back;
   - the tool is called with valid arguments;
   - the second turn answers;
   - the spend is above zero and within the cap.

   ```bash
   EXPERIMENT_APPROVED=1 .venv/bin/python gateway_hooks/modal_routes.py --probe --report <path>.json
   ```

   The report has no keys in it. Keep it with the cohort's records.

## Running a lure cohort on a Modal model

Start with a two-cell pilot, as for Luna: one pair, both forms, short budget.
Then run the cohort. Each model is its own cohort; never pool it with a GPT or
Opus cohort.

```bash
# pilot: one pair, both forms, short budget only (2 cells)
EXPERIMENT_APPROVED=1 .venv/bin/python agent_honeypot/lure_tripwires/run_lure_cohort.py \
  --root results/docker-honeypot-lure-exp/lure-kimi-pilot-$(date -u +%Y%m%dT%H%M%SZ) \
  --model kimi-k3-modal --arm lure-pilot --pairs xor-flag --budgets short --trials 1 \
  --key-budget-short 0.60 --key-budget-long 0.60 --ceiling 5.00 --seed 20261105 --execute

# cohort: all four pairs, both forms, both budgets (16 cells)
EXPERIMENT_APPROVED=1 .venv/bin/python agent_honeypot/lure_tripwires/run_lure_cohort.py \
  --root results/docker-honeypot-lure-exp/lure-kimi-v1-$(date -u +%Y%m%dT%H%M%SZ) \
  --model kimi-k3-modal \
  --key-budget-short 0.60 --key-budget-long 2.00 --ceiling 20.00 --seed <seed> --execute
```

Without `--execute`, the driver freezes and prints the plan and spends
nothing. It refuses `--execute` while the image inputs are dirty.
`tests/test_modal_routes.py` is an image input, so commit it and rebuild the
images at the new HEAD before a paid cell (or pass `--image` with a tag built
from the same inputs).

### Per-cell caps

| Route | Short cap | Long cap | Basis |
|---|---|---|---|
| `glm-5.3-flash-modal` | 0.15 | 0.40 | Luna's caps; prices under a tenth of Opus's |
| `glm-5.3-modal` | 0.30 | 1.00 | prices a fifth to a third of Opus's |
| `kimi-k3-modal` | 0.60 | 2.00 | Opus's caps; Opus's prices are a third higher |

For scale, the 16-cell Opus lure cohort spent USD 3.76; its costliest cell
spent USD 0.58. An open-weight agent may take more turns than Opus, so read the
pilot's spend and token use before fixing the cohort's caps and ceiling. The
ceiling is the author's call.

LiteLLM's spend uses the route's listed prices, and that figure is what the cap
enforces. OpenRouter bills its credits separately, with a fee on credit
purchases. Reconcile the two from OpenRouter's activity page after a cohort.

## Limits and open checks

- **An endpoint outage.** With fallbacks off, a Modal outage fails the
  request. The cell then has no model output, and the driver's setup-fault
  limit (`--max-setup-faults`, default 2) stops the cohort. The catalogue
  check reports the endpoint's uptime but cannot promise it.
- **Codex has no metadata for these names.** Codex 0.164 runs them with its
  defaults, such as context window and reasoning-summary settings. The route
  sets reasoning itself.
- **Whether Codex passes reasoning back verbatim.** The probe checks the
  gateway path with a client that passes the items back unmodified. Whether
  Codex 0.164 does the same is visible only in a real cell. The pilot's
  archived session shows the reasoning items each request carried.
- **Quantised weights.** These are quantised deployments: GLM 5.3 Flash at
  fp4, Kimi K3 at mxfp4, and GLM 5.3 unlisted. Report each cohort's results as
  "served by Modal at <quantisation>", not as the model's reference weights.
- **Prices change.** Rerun the check before each cohort. A price change makes
  the check fail until the route's costs are updated and re-registered.
