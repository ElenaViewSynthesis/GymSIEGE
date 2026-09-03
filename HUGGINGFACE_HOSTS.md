# Hugging Face transfer hosts

Last verified: 2026-09-03 (Europe/London)

This file records the host trust boundary used by the Daytona organization
Secret `gymsiege-huggingface`. It contains no tokens, authorization headers,
signed URLs, query strings, or Secret placeholders.

> **Status: the host list is not the cause, and the cause is now confirmed.**
> On 2026-09-03 an A/B probe transferred payload bytes from
> `us.aws.cdn.hf.co` *from inside a Daytona sandbox* (`206`, ranged GET), so
> egress works. The bake fails because sandbox responses arrive with
> `Content-Length` removed and `Transfer-Encoding` added, which leaves the 20
> directly-served `crash.log` files with no resolvable size. Tracked in
> [`DAYTONA_HUGGINGFACE_EGRESS_ISSUE.md`](DAYTONA_HUGGINGFACE_EGRESS_ISSUE.md).
> This file is retained as the record of the Secret's configured scope, not as
> an open investigation.

## Configured Daytona Secret hosts

`configure_secrets.py` scopes the Hugging Face Secret to these exact FQDNs:

- `huggingface.co`
- `cas-server.xethub.hf.co`
- `cas-server.xethub-eu.hf.co`
- `transfer.xethub.hf.co`
- `transfer.xethub-eu.hf.co`
- `us.aws.cdn.hf.co`
- `us.gcp.cdn.hf.co`
- `cdn-lfs-us-1.hf.co`
- `cdn-lfs-eu-1.hf.co`

Source: Hugging Face's download-behind-a-proxy-or-firewall guidance,
<https://huggingface.co/docs/hub/datasets-downloading>. Review when
`huggingface_hub` is upgraded.

On 2026-09-03, a read-only Daytona metadata query confirmed the existing
organization Secret has exactly these nine hosts. The Secret value was neither
returned nor inspected.

### Known gap in this list

Hugging Face's current guidance also references `cas-bridge.xethub.hf.co`,
which is **not** in the list above. It has not been added, because the probe
showed the list has no bearing on the current failure and widening a token's
trust boundary without a demonstrated need is the wrong default. Add it only
if a real transfer is observed to require it.

## Xet is the current backend, not the legacy one

Worth stating explicitly, because it is easy to get backwards. Hugging Face's
storage-backends documentation says the Hub *"has adopted Xet, a modern custom
storage system"* and that *"Git LFS remains supported"* under a page titled
"Backwards Compatibility & Legacy". **Xet is current; Git LFS is the legacy
path.** The `cdn-lfs-*` entries above are the legacy hosts; the `xethub` and
`cdn.hf.co` entries are the modern ones.

`sunblaze-ucb/cybergym-e2e` is Xet-backed — every probed file returned an
`X-Xet-Hash` header. This matters for reading `huggingface_hub`: at
`file_download.py:1777` the CDN-redirect download branch is taken only when
`xet_file_data is None`, so for this dataset the client's real payload path is
Xet, and `us.aws.cdn.hf.co` is what a plain redirect-following HTTP client
reaches rather than necessarily what `hf_hub_download` itself uses.

## What a Secret's `hosts` list does

It bounds the destinations to which Daytona may substitute or send that
Secret's value. It grants no DNS, TCP, TLS, or HTTP reachability, and listing a
host is not proof the bearer token is forwarded there.

That last point is now settled in the negative for CDN hosts:
`huggingface_hub` **removes** the `Authorization` header when a redirect
crosses to a different netloc, because CDN URLs are pre-signed
(`file_download.py:1775-1781`). Listing `us.aws.cdn.hf.co` on the Secret could
never have affected authentication to it.

## Hosts observed for this repository

On 2026-09-03, authenticated no-follow `HEAD` probes both locally and inside a
Daytona sandbox resolved all selected `src.tgz` payloads from
`sunblaze-ucb/cybergym-e2e` identically:

| Source host | HTTP status | Redirect host | Files |
|---|---:|---|---:|
| `huggingface.co` | 302 | `us.aws.cdn.hf.co` | 20 |

A ranged `GET` (`Range: bytes=0-0`) following that redirect returned `206` with
one payload byte from `us.aws.cdn.hf.co` **inside the sandbox**, which is what
retired the egress theory.

`snapshot_build.py` repeats the sanitized no-follow check inside each bake
sandbox and writes the aggregate observation to the git-ignored
`results/huggingface_hosts.json`. `hf_header_probe.py` runs the fuller local-vs-
sandbox header comparison and writes `results/hf_header_probe.json`. Neither
records a redirect URL, query string, authorization header, token, or Secret
placeholder.

Note that the bake's raw `[hf_hosts]` marker line does not appear in its own
stdout — `timed_exec` parses it out of the exec result and re-emits it as a
formatted log line (`snapshot_build.py:285-295`). Grep the bake log for
`sanitized Hugging Face hosts`, not for `[hf_hosts]`.
