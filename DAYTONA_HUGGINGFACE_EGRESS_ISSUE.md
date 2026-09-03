# Daytona sandbox responses drop `Content-Length`, breaking `huggingface_hub` downloads

**Labels:** `runner`, `api`, `sdk`, `bug`

> **Filename note.** This file is still named `..._EGRESS_ISSUE.md` for link
> stability, but as of 2026-09-03 the egress framing is **disproven**. See
> "What was ruled out." Outbound HTTPS to Hugging Face's CDN works from inside
> a sandbox.

## Summary

A Daytona sandbox reaches Hugging Face, authenticates against a gated dataset,
resolves every selected file, **and successfully transfers bytes from the CDN**.
Nevertheless `huggingface_hub.snapshot_download()` fails with:

```text
huggingface_hub.errors.LocalEntryNotFoundError: Distant resource does not have
a Content-Length. We also cannot find the requested files in the local cache.
```

A controlled A/B probe run simultaneously on the local client and inside a
Daytona sandbox, against the same three files with the same token, found
exactly one difference in the HTTP responses: **the `Content-Length` header is
present locally and absent inside the sandbox.** Every other header the client
depends on — `X-Linked-Size`, `X-Linked-ETag`, `X-Repo-Commit`, `X-Xet-Hash` —
arrives intact with byte-identical values.

This is a response-header integrity problem in the Daytona network path, not a
destination-reachability problem.

## Environment

- Daytona repository: `daytonaio/daytona`
- Daytona Python SDK: `0.207.0`
- Daytona API response version observed in headers: `v0.209.0`
- Local client: Python 3.12 under Ubuntu on WSL, `huggingface_hub` 1.29.0
- Sandbox: `AsyncDaytona.create()`, `Image.debian_slim("3.12")`,
  `huggingface_hub` 1.30.0
- Network policy: centrally managed on this Daytona target; per-sandbox
  network-policy overrides are rejected by the target
- Authentication: Daytona organization Secret; no plaintext token in sandbox
  creation parameters, source, or logs
- Secret mapping: `HF_TOKEN -> gymsiege-huggingface`
- Hugging Face dataset: `sunblaze-ucb/cybergym-e2e` (Xet-backed)

## Evidence

`hf_header_probe.py` in this repository runs one probe script verbatim in both
places and records only hostnames, status codes, header **presence**, and byte
counts — never a signed URL, query string, token, or Secret placeholder.

Three pinned archives, identical token, run 2026-09-03:

| Observation | Local (WSL) | Daytona sandbox |
|---|---|---|
| HEAD status | `302` | `302` |
| Redirect host | `us.aws.cdn.hf.co` | `us.aws.cdn.hf.co` |
| `X-Repo-Commit` | present | present |
| `X-Linked-ETag` | present | present |
| `X-Linked-Size` | present (e.g. `12595315`) | present (identical value) |
| `X-Xet-Hash` | present | present |
| **`Content-Length`** | **present** | **absent** |
| Ranged `GET` (`Range: bytes=0-0`) | `206`, 1 byte | `206`, 1 byte |

The ranged GET followed the redirect to completion and returned real payload
bytes from `us.aws.cdn.hf.co` **from inside the sandbox**. Sending
`Accept-Encoding: identity` (which `huggingface_hub` always does, and which
would be the obvious suspect for a size header vanishing) changed nothing in
either environment.

## What was ruled out

1. **Authorization.** An early `401 GatedRepoError` was resolved by granting
   the account dataset access and copying a valid token into the organization
   Secret. The 401 is gone.
2. **Secret `hosts` scoping.** The Secret was widened to nine exact Hugging
   Face FQDNs and re-applied; a read-only Daytona query confirmed the applied
   metadata. No change. A Secret's `hosts` list is a value-substitution trust
   boundary and grants no network reachability — see `HUGGINGFACE_HOSTS.md`.
3. **Egress to the CDN.** *Disproven as a cause.* A ranged GET from inside the
   sandbox returns `206` with payload bytes from `us.aws.cdn.hf.co`.
4. **The redirect never being followed.** `get_hf_file_metadata` follows only
   *relative* redirects, so the CDN redirect is not followed at the metadata
   stage at all. The failure happens before any CDN request would be made — yet
   the CDN is reachable anyway. Both halves of the original theory fail.
5. **`huggingface_hub` version skew.** The sandbox runs 1.30.0 and the local
   client 1.29.0, but the size-computation block
   (`file_download.py:1645-1648`) is byte-identical between the two releases.
6. **General connectivity.** GitHub, Debian package repositories, and PyPI are
   all reachable during the same bootstrap.
7. **Flakiness.** Two consecutive full bakes failed identically, with the same
   20/20 redirect observation each time.

## Why a missing `Content-Length` is fatal

`huggingface_hub` computes the expected size as
(`file_download.py:1645-1648`, identical in 1.29.0 and 1.30.0):

```python
size=_int_or_none(
    response.headers.get(constants.HUGGINGFACE_HEADER_X_LINKED_SIZE)
    or (None if response.is_redirect else response.headers.get("Content-Length"))
),
```

and then refuses to proceed without it (line 1766):

```python
expected_size = metadata.size
if expected_size is None:
    raise FileMetadataError("Distant resource does not have a Content-Length.")
```

For a **redirected** response, `X-Linked-Size` supplies the size and the
absence of `Content-Length` is harmless. For a **non-redirected** `200`
response — a small file served directly, with no `X-Linked-Size` —
`Content-Length` is the only source, and stripping it makes `size` `None` and
raises exactly the observed error.

## Open lead — not yet confirmed

The probe covered only large `src.tgz` archives, which are redirected and
therefore immune. The bake's `allow_patterns` are `projects/<task>/**` and
`data/projects/<task>/**` (`snapshot_build.py:126`), which also match small
regular files such as `project.toml` and `config.toml`.

**Hypothesis:** the failing files are those small non-redirected ones, where
the stripped `Content-Length` has no `X-Linked-Size` to fall back on.

**Test that would confirm it:** run the same A/B probe against a small
non-LFS file and check whether the sandbox's `200` response carries
`Content-Length`, and whether `Transfer-Encoding: chunked` appears in its
place — the signature of a proxy that buffers and re-frames responses.

Until that runs, the *mechanism* (missing `Content-Length`) is established but
the *specific failing file* is not.

## Expected behavior

A sandbox's HTTP responses should preserve upstream entity headers. Where the
platform's proxy re-frames a response (for example, converting to chunked
transfer-encoding and dropping `Content-Length`), that should be documented,
because widely-used clients treat those headers as load-bearing rather than
advisory.

Failing that:

1. A documented statement of which response headers a sandbox's network path
   may alter, add, or remove.
2. A sandbox-visible diagnostic reporting the effective network path
   (transparent proxy present or not) so header rewriting can be distinguished
   from server behavior without an external control.
3. Preservation of `Content-Length` specifically, since the Python HTTP
   ecosystem uses it for integrity checks and progress accounting.

## Minimal reproduction

The decisive repro is the A/B header comparison, not a download. It costs one
short-lived sandbox and transfers one byte.

Full script: `hf_header_probe.py` in this repository. Run:

```bash
.venv/bin/python hf_header_probe.py
```

It prints local and sandbox observations side by side and writes
`results/hf_header_probe.json`. The signal is a header present in the `LOCAL`
block and absent in the `DAYTONA SANDBOX` block.

The original download-level reproduction still fails identically:

```python
import asyncio

from daytona import AsyncDaytona


REPRO = r"""
set -euo pipefail
python3 -m pip install --break-system-packages -q 'huggingface_hub>=0.25'
python3 - <<'PY'
from huggingface_hub import snapshot_download

snapshot_download(
    repo_id="sunblaze-ucb/cybergym-e2e",
    repo_type="dataset",
    local_dir="/tmp/cybergym-e2e",
    allow_patterns=["projects/curl/arvo_66012/**"],
    token=True,
)
PY
"""


async def main() -> None:
    async with AsyncDaytona() as daytona:
        sandbox = await daytona.create()
        try:
            await sandbox.set_ttl(60)
            await sandbox.update_secrets({"HF_TOKEN": "gymsiege-huggingface"})
            await sandbox.stop(timeout=120)
            await sandbox.start(timeout=120)

            result = await sandbox.process.exec(REPRO, timeout=600)
            print("exit_code:", result.exit_code)
            print((result.result or "")[-4000:])
        finally:
            await sandbox.set_ttl(60)
            await sandbox.delete(wait=True, timeout=180)


asyncio.run(main())
```

## Questions

1. Does a transparent HTTP/HTTPS proxy sit in the sandbox network path on this
   target? If so, is it documented anywhere?
2. Is that proxy expected to drop `Content-Length` from upstream responses, or
   is this a defect?
3. Does it re-frame responses as `Transfer-Encoding: chunked`, and does that
   apply to all responses or only some size/content-type classes?
4. Which other entity headers may a sandbox's network path alter, add, or
   remove?
5. Is there a sandbox-visible diagnostic that reports the effective network
   path, so header rewriting can be distinguished from origin behavior without
   running an external control?

## Corrections to earlier revisions of this document

Two claims made here previously are now answered, and are kept because they
were answered in passing rather than because they remain open:

- A Daytona organization Secret's `hosts` list scopes where a Secret's value may
  be sent. It does not modify target-managed network policy and does not grant
  reachability.
- `huggingface_hub` strips the `Authorization` header when a redirect crosses to
  a different netloc, because CDN URLs are pre-signed (`file_download.py:1775-1781`).
  Listing a CDN host on the Secret could never have affected authentication.

The feature request below was originally motivated by this bug. That
motivation no longer holds — the CDN is reachable — but the request itself is
independent of it and is **not withdrawn**. It is retained on its own merits,
with the dataset failure removed as supporting evidence.

## Feature request: opt-in egress allowlist with host-side accountability

> **Relationship to this bug.** This request was first written when
> `us.aws.cdn.hf.co` was believed to be blocked. That belief was disproven on
> 2026-09-03. The request stands as a separate platform-capability ask about
> *visibility and control* over egress policy, and should be read
> independently of the `Content-Length` defect above. Compare
> [#3357 — Dynamic Network Egress Control for Running Sandboxes](https://github.com/daytonaio/daytona/issues/3357).

There is currently no supported way for an organization to unblock a specific,
known destination without either staying fully blocked or asking Daytona to
broaden the platform-wide default.

We are requesting an **opt-in, per-organization (or per-sandbox) egress
allowlist**: a mechanism where the organization explicitly adds specific
hostnames — including known HTTPS redirect destinations, such as a provider's
regional CDN — to its own allowlist, and by doing so accepts accountability for
the security implications of that broadened egress. This does not require
Daytona to change its safe default; it requires Daytona to expose the control
so the organization that owns the workload, not the platform default, is the
one making and owning that specific trust decision.

Concretely, this would mean:

- The allowlist is opt-in and explicit — nothing is unblocked by default.
- The organization (us, as the account holder) — not Daytona — is
  accountable for any security consequences of hosts we choose to allow.
- The allowlist should cover HTTPS redirect chains, not just the
  initially-requested host, since providers like Hugging Face route file
  content through a separate CDN host from their API host.
- Whatever is allowed should be visible/auditable (e.g. via the API or
  dashboard), so it is clear which hosts an organization has opted into and
  when.

This is a superset of the existing `hosts` field on a Daytona organization
Secret (see Questions above): that field scopes *where a Secret's value is
injected*, not *what a sandbox is permitted to reach*, and this feature request
is specifically about the latter.

A related observation from this investigation strengthens rather than weakens
the case: the effective network path was not *visible* from inside a sandbox.
Diagnosing it required running a controlled A/B probe against an external
reference. Whatever egress policy exists should be introspectable without that.

## Current workarounds and limitations

If the missing `Content-Length` is confirmed as the cause, candidate
workarounds are to pre-stage the affected small files into the snapshot by
another transport, or to fetch them with a client that tolerates a missing
size. Neither is attractive: both work around a platform behavior rather than
fixing it, and the second means abandoning `huggingface_hub`'s integrity check.

Mirroring the 3.70 GiB selected subset into approved private storage remains
possible but adds storage, provenance, lifecycle, and transfer overhead. The
Daytona target also has a 10 GiB snapshot disk limit, so mirroring the full
~160 GB dataset into a snapshot is neither attempted nor desired.

## Possibly related issues

- [#3357 — Dynamic Network Egress Control for Running Sandboxes](https://github.com/daytonaio/daytona/issues/3357)
- [#5151 — Allow sandbox egress to `api.osv.dev`](https://github.com/daytonaio/daytona/issues/5151)
