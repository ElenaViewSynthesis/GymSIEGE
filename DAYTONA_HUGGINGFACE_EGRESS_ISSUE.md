# Sandbox cannot download Hugging Face LFS payload redirected to `us.aws.cdn.hf.co`

**Labels:** `runner`, `api`, `sdk`, `bug`

## Summary

A Daytona sandbox can reach Hugging Face well enough to authenticate and
resolve a gated dataset, but downloading an LFS-backed file fails after the
Hub redirects the request from `huggingface.co` to `us.aws.cdn.hf.co`.

The Hugging Face token is attached only through a Daytona organization Secret.
That Secret's host list contains both `huggingface.co` and
`us.aws.cdn.hf.co`. Replacing the Secret after adding the CDN host did not
change the result.

This appears to be an effective target-level egress restriction, or an
undocumented distinction between a Secret's `hosts` metadata and the target's
network allowlist. We need a supported way to allow the redirect destination
without enabling unrestricted sandbox egress.

## Environment

- Daytona repository: `daytonaio/daytona`
- Daytona Python SDK: `0.207.0`
- Daytona API response version observed in headers: `v0.209.0`
- Local client: Python 3.12 under Ubuntu on WSL
- Sandbox: default Daytona sandbox created with `AsyncDaytona.create()`
- Network policy: centrally managed on this Daytona target; per-sandbox
  network-policy overrides are rejected by the target
- Authentication: Daytona organization Secret; no plaintext token in sandbox
  creation parameters, source, or logs
- Secret mapping: `HF_TOKEN -> gymsiege-huggingface`
- Secret hosts: `huggingface.co`, `us.aws.cdn.hf.co`
- Hugging Face dataset: `sunblaze-ucb/cybergym-e2e`

The Hugging Face account has been granted access to the auto-gated dataset.
The same token successfully enumerates and resolves the selected files from
the local WSL client.

## What was ruled out

The first attempt failed with `401 GatedRepoError`. That authorization problem
is resolved:

1. Dataset access was granted to the Hugging Face account.
2. A valid token from `huggingface-cli login` was copied into the Daytona
   organization Secret `gymsiege-huggingface`.
3. The sandbox was restarted after `update_secrets()`.
4. The 401 disappeared.
5. Outside Daytona, authenticated HEAD requests for all 20 selected archives
   return `302` and consistently redirect to `us.aws.cdn.hf.co`.

The selected files total approximately 3.70 GiB. The job is not attempting to
download the complete approximately 160 GB dataset.

GitHub, Debian package repositories, and PyPI are reachable during the same
bootstrap. The failure is specific to the Hugging Face file-transfer path.

## Actual behavior

Inside the Daytona sandbox, `huggingface_hub.snapshot_download()` lists the
repository but fails while resolving/downloading the selected files:

```text
huggingface_hub.errors.LocalEntryNotFoundError: An error happened while trying
to locate the file on the Hub and we cannot find the requested files in the
local cache. Please check your connection and try again or make sure your
Internet connection is on.
```

The failure occurs in `hf_hub_download()` / `_hf_hub_download_to_local_dir()`
after approximately 25 seconds. Adding `us.aws.cdn.hf.co` to the organization
Secret's host list and replacing the Secret produces the same failure.

The bake aborts before snapshot capture, and its temporary sandbox is deleted.
No failed or partial snapshot is retained.

## Expected behavior

One of the following should be supported and documented:

1. A target or sandbox allowlist that permits outbound HTTPS to both the Hub
   and its redirect destination.
2. Automatic allowance of an HTTPS redirect destination when both source and
   destination hosts are explicitly approved.
3. A clear API error identifying the blocked hostname and the policy layer
   that rejected it, rather than a downstream Hugging Face cache error.

Listing hosts on a Daytona organization Secret should either permit egress to
those hosts or documentation should clearly explain that Secret host scoping
does not modify the target-managed network policy.

## Feature request: opt-in egress allowlist with host-side accountability

The underlying problem is not only that this specific request fails from
inside a sandbox — it is that there is currently no supported way for an
organization to unblock a specific, known destination (here,
`huggingface.co` plus its `us.aws.cdn.hf.co` redirect target) without either
staying fully blocked or asking Daytona to broaden the platform-wide default.

We are requesting an **opt-in, per-organization (or per-sandbox) egress
allowlist**: a mechanism where the organization explicitly adds specific
hostnames — including known HTTPS redirect destinations, such as Hugging
Face's regional CDN — to its own allowlist, and by doing so accepts
accountability for the security implications of that broadened egress. This
does not require Daytona to change its safe default; it requires Daytona to
expose the control so the organization that owns the workload, not the
platform default, is the one making and owning that specific trust decision.

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
Secret (see Questions #1-2 below): that field currently appears to scope
*where a Secret's value is injected*, not *what a sandbox is permitted to
reach*, and this feature request is specifically about the latter.

## Minimal reproduction

Prerequisites:

- `DAYTONA_API_KEY` is configured.
- The Daytona organization Secret `gymsiege-huggingface` contains a Hugging
  Face read token whose account has access to
  `sunblaze-ucb/cybergym-e2e`.
- The Secret hosts include `huggingface.co` and `us.aws.cdn.hf.co`.

The example never prints the token and always arms a TTL and deletes the
sandbox.

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
            await sandbox.update_secrets(
                {"HF_TOKEN": "gymsiege-huggingface"}
            )
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

1. Does an organization Secret's `hosts` list affect network egress, or does it
   only scope where the Secret may be used/exposed?
2. How can an organization administrator add `huggingface.co` and
   `us.aws.cdn.hf.co` to the effective target-level egress allowlist?
3. Does Daytona support allowlisting hostnames reached through HTTPS redirects,
   including Hugging Face's regional CDN hosts?
4. Is there an API or sandbox diagnostic that reports the effective egress
   policy and blocked destination for a failed request?
5. Can Daytona return a policy-specific error when its proxy/firewall blocks a
   host, so the SDK user does not receive only the library's generic
   `LocalEntryNotFoundError`?

## Current workarounds and limitations

We can mirror only the 3.70 GiB selected subset into approved private storage,
or build a toolchain-only snapshot and transfer one task payload per trial.
Those approaches add storage, provenance, lifecycle, and transfer overhead and
should not be necessary if the required Hugging Face CDN host can be explicitly
allowed.

The Daytona target also has a 10 GiB snapshot disk limit, so mirroring the full
dataset into a snapshot is neither attempted nor desired.

## Possibly related issues

- [#3357 — Dynamic Network Egress Control for Running Sandboxes](https://github.com/daytonaio/daytona/issues/3357)
- [#5151 — Allow sandbox egress to `api.osv.dev`](https://github.com/daytonaio/daytona/issues/5151)
