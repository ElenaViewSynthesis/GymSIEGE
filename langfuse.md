# Langfuse Python SDK

> Reference notes for the Langfuse Python SDK — install, credentials, client
> setup, and the OpenTelemetry mapping it's built on.

Already applied in this repo: `langfuse==4.15.1` is pinned in
`requirements.txt`, credentials live in `.env.local`
(`LANGFUSE_SECRET_KEY`/`LANGFUSE_PUBLIC_KEY`/`LANGFUSE_BASE_URL`), and
`solver_agent.py`'s `_assess_screenshot()` — the one LLM call this repo
makes directly from the local process rather than as an upstream script run
remotely inside a Daytona sandbox — is instrumented with a span/generation
pair. Verified end-to-end with `get_client().auth_check()` returning `True`
and a real test trace landing in the Langfuse Cloud dashboard.

## Install

```shell
pip install langfuse
```

## Configure credentials

Add Langfuse credentials as environment variables (get them from a free
Langfuse Cloud account, or self-host). If self-hosting, or using a data
region other than the default (EU), set the base URL too.

```dotenv
LANGFUSE_SECRET_KEY="sk-lf-..."
LANGFUSE_PUBLIC_KEY="pk-lf-..."
LANGFUSE_BASE_URL="https://cloud.langfuse.com" # EU region
# Other regions: US https://us.cloud.langfuse.com,
# Japan https://jp.cloud.langfuse.com, HIPAA https://hipaa.cloud.langfuse.com
```

Credentials can also be passed directly to the constructor instead of via
environment variables.

## Client setup

The Python SDK sets up OpenTelemetry automatically on client init — no
separate OTel initialization step needed (unlike the JS/TS SDK). By default
it exports Langfuse + GenAI/LLM spans; customize with `should_export_span`
(`blocked_instrumentation_scopes` still works but is deprecated).

```python
from langfuse import get_client
langfuse = get_client()
# Verify connection
if langfuse.auth_check():
    print("Langfuse client is authenticated and ready!")
else:
    print("Authentication failed. Please check your credentials and host.")
```

`get_client()` is a singleton — callable anywhere in the application.

## OpenTelemetry foundation

Langfuse SDKs are built on OpenTelemetry, which provides: standardization
with the wider observability ecosystem, robust context propagation (nested
spans stay connected even across async workloads), attribute propagation
(`userId`/`sessionId`/`metadata`/`version`/`tags` kept aligned across
observations), and ecosystem interoperability (third-party instrumentations
automatically show up inside Langfuse traces).

Concept mapping:

- **OTel Trace** — the entire lifecycle of a request as it moves through the
  application; defined by its root span, not by an explicit start/end time.
- **OTel Span** — a single unit of work with a start/end time, a name, and
  attributes; spans nest to form a parent-child hierarchy.
- **Langfuse Trace** — the set of observations sharing a `trace_id`, plus
  shared attributes like `session_id`/`user_id`. Shares its ID with the OTel
  trace. Trace-level input/output lives on the root observation (trace-level
  input/output fields are deprecated in Langfuse v4).
- **Langfuse Observation** — Langfuse's representation of an OTel span: a
  generic **Span** (non-LLM work), a **Generation** (an LLM call — carries
  `model`, `model_parameters`, `usage_details`, `cost_details`), an
  **Event** (a point-in-time action), or other types (tool calls, RAG
  retrieval steps, etc.).
- **Context propagation** — handled automatically by OpenTelemetry: a call
  into another traced function, an OTel-instrumented library, or a manually
  created span becomes a child of whatever span is currently active.
- **Attribute propagation** — `user_id`, `session_id`, `metadata`, `version`,
  `tags`, and (Python-only) request-scoped `environment` can be propagated
  to all child observations via `propagate_attributes()`.

The SDK's `LangfuseSpan`/`LangfuseGeneration` wrapper objects are native OTel
spans under the hood, with added convenience methods for Langfuse-specific
features (scoring, media handling) and `update_trace()`/
`propagate_attributes()` for trace-level attributes.

## Next steps

With the client set up, the SDK also supports: instrumenting an application
(spans/generations, as already done in `solver_agent.py`), Prompt
Management, running Experiments and creating Scores, and querying data back
out of Langfuse.
