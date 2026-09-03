# GYMSIEGE glossary

Terms and acronyms used across this conversation, grounded in how they
actually apply to this repo rather than generic textbook definitions alone.

## Project and benchmarks

- **GYMSIEGE** — this repo's own project: a Daytona fleet-evaluation
  harness running two published security-agent benchmarks and measuring
  both agent capability and infrastructure behavior.
- **CyberGym-E2E** — upstream benchmark: find-vulnerability → PoC → patch,
  scored against real OSS-Fuzz sanitizer builds. The full upstream dataset
  covers **920 real-world vulnerabilities across 139 open-source projects**
  (matches `snapshot_build.py`'s own "not all 139 projects" comment);
  GYMSIEGE's default protocol runs a pinned 20-task subset
  (`tasks.pinned.txt`), not the full 920. Distinct from the broader,
  non-gated **`sunblaze-ucb/cybergym`** framework (1,507 tasks) — see the
  gated-dataset note below.
- **ExploitGym** — upstream benchmark: exploit-development evaluation, run
  through its own evaluator with a mandatory firewall, local LLM proxy,
  controller, hardened targets, and per-task budget accounting.
- **ARVO** ("Atlas of Reproducible Vulnerabilities in Open-source
  software," `arvo.sbs`) — dataset of reproducible OSS-Fuzz
  vulnerable/fixed commit pairs GYMSIEGE's CyberGym tasks map onto.
- **OSS-Fuzz** — Google's continuous fuzzing infrastructure for
  open-source projects; supplies the sanitizer-instrumented base-builder
  images GYMSIEGE's oracle rebuilds targets with.
- **Sanitizer / ASan** — compiler instrumentation (e.g. AddressSanitizer)
  that makes memory-safety bugs crash deterministically instead of
  silently corrupting memory; the mechanism the "sanitizer oracle" relies
  on to turn a PoC into a pass/fail signal.
- **PoC** — Proof of Concept; the artifact (`poc.bin`) an agent produces to
  demonstrate a vulnerability triggers.
- **CVE** — Common Vulnerabilities and Exposures; public vulnerability
  identifier format, used in several ExploitGym task IDs (e.g.
  `CVE-2021-32132`).
- **pass@1 / pass@k** — capability metric: whether a task succeeds on the
  first trial (`pass@1`) or on at least one of `k` trials (`pass@k`).
- **exp.hardened** — ExploitGym's hardened userspace task profile, the
  only mode GYMSIEGE's default protocol runs.

## Daytona platform

- **Daytona** — the cloud sandbox platform GYMSIEGE is built on; provides
  disposable Linux/Windows/VM sandboxes with an async SDK.
- **Sandbox** — one disposable Daytona compute environment (container or
  VM) created per trial and deleted afterward.
- **Snapshot** — a persistent, point-in-time capture of a sandbox's
  filesystem (and, for VM/Windows, optionally memory), used to create new
  sandboxes without repeating setup.
- **Cold vs. hot snapshot** — cold captures filesystem only (sandbox must
  be stopped); hot also captures memory (sandbox stays running); only
  VM/Windows sandboxes support hot snapshots.
- **Warm pool** — a pre-created, running pool of sandboxes from a snapshot
  that new create requests can claim instantly instead of provisioning
  fresh.
- **`AsyncDaytona`** — the async Python SDK client class used throughout
  this repo (`daytona==0.207.0`).
- **Computer Use** — Daytona's API for programmatic mouse/keyboard/
  screenshot/screen-recording/accessibility-tree control of a sandbox's
  desktop, used by GYMSIEGE's `ResearchAgent`.
- **AT-SPI** — Assistive Technology Service Provider Interface; the Linux
  accessibility framework Computer Use's `accessibility.*` calls read to
  inspect UI elements by role/name/state instead of pixels.
- **VNC / noVNC / x11vnc / Xvfb / xfce4** — the virtual-display stack
  Computer Use starts inside a sandbox: `Xvfb` (virtual X server), `xfce4`
  (desktop environment), `x11vnc` (VNC server), `noVNC` (browser-based VNC
  client).
- **TTL** — Time To Live; a server-side auto-expiry timer Daytona enforces
  on a sandbox (`set_ttl`), independent of the client process. GYMSIEGE's
  default is 60 minutes (`SANDBOX_SAFETY_TTL_MINUTES`), used as a safety
  net behind the primary `delete()` cleanup path.
- **Reap** — GYMSIEGE-specific term (`orchestrator.py reap`): a manual
  sweep that lists and deletes any stray sandbox matching the project's
  naming prefix, as a third cleanup layer beyond TTL and `delete()`.

## Security and isolation

- **Firewall (two-network)** — ExploitGym's own upstream containment: the
  agent's container is placed on a network that can only reach an internal
  proxy/controller, not the open internet.
- **LLM proxy / egress proxy** — a local proxy the agent's model calls are
  routed through, which blocks the agent from exfiltrating data via
  provider-side API calls (retrieval blocking).
- **`network_block_all` / `update_network_settings`** — the Daytona-level
  API GYMSIEGE calls independently, after an agent's evaluator returns, to
  cut all sandbox network egress before reading any result or artifact —
  a second containment layer on top of the benchmark's own firewall.
- **Isolated oracle / isolated re-detonation** — GYMSIEGE's own
  network-isolated re-run of an agent's frozen PoC/patch against fresh
  sanitizer builds, used as the authoritative scoring signal instead of
  the agent's own (network-attached) self-validation.
- **Vault / Secret** — Daytona's organization-level secret store;
  provider API keys are injected into sandboxes by name reference via
  `update_secrets`, never as plaintext in `create()` parameters or logs.
- **Secret `hosts` scoping** — each Daytona Secret can be created with a
  `hosts` list of exact FQDNs (`CreateSecretParams(..., hosts=[...])` in
  `configure_secrets.py`), bounding where Daytona may substitute or send
  that secret's value. `openai` scopes to `api.openai.com`;
  `huggingface` scopes to the nine hosts in `HUGGINGFACE_SECRET_HOSTS`.
  This matters because it's a narrower, per-host trust boundary than just
  "the agent has this token" — a compromised or off-script process in the
  sandbox still can't use the secret against an arbitrary host outside the
  list. Critically, it is **not** an egress allowlist: it grants no DNS,
  TCP, TLS, or HTTP reachability to any host, and listing a host is not
  proof the bearer token is actually forwarded there (modern Hugging Face
  transfers can use Hub-minted Xet credentials or pre-signed URLs at the
  storage layer instead).
- **HF CDN redirect host gap** — a theory this repo held for several
  rounds and then **disproved**, recorded because the reasoning trap is
  worth remembering. Hub API calls go to `huggingface.co` while large
  file content is served after a `302` to a separate CDN host
  (`us.aws.cdn.hf.co` here), so a download failure looked like a
  host-allowlist gap. Widening the Secret to nine FQDNs changed nothing.
  A ranged `GET` from inside a sandbox then returned `206` with real
  payload bytes from that CDN — **egress was never blocked**. The trap
  was treating "the Secret's host list is misconfigured" as the only
  hypothesis consistent with "a download fails after a redirect," and
  re-running the same bake rather than an experiment that could
  distinguish causes. Superseded by the header-stripping finding below.
- **Response-header stripping (current HF blocker)** — the actual cause
  of the CyberGym dataset failure. An A/B probe found the sandbox's
  responses identical to local except that **`Content-Length` is
  absent**. `huggingface_hub` derives a file's expected size from
  `X-Linked-Size` *or*, for a non-redirected response, `Content-Length`
  (`file_download.py:1645-1648`), and raises `FileMetadataError`
  ("Distant resource does not have a Content-Length") when neither
  exists. Large redirected archives survive on `X-Linked-Size`; small
  directly-served files have no fallback. The signature suggests a
  transparent proxy re-framing responses. Tracked in
  [`DAYTONA_HUGGINGFACE_EGRESS_ISSUE.md`](DAYTONA_HUGGINGFACE_EGRESS_ISSUE.md).
- **Xet** — Hugging Face's current storage backend for large files,
  using chunk-level deduplication; **Git LFS is the legacy path it
  replaced**, not the other way round. `sunblaze-ucb/cybergym-e2e` is
  Xet-backed (every probed file returns an `X-Xet-Hash` header), which
  matters because `huggingface_hub` takes the CDN-redirect download
  branch only when `xet_file_data is None`
  (`file_download.py:1777`). The `cdn-lfs-*` hosts in the Secret's list
  are legacy; the `xethub` and `cdn.hf.co` hosts are current.
- **Honeypot** — a decoy resource deliberately exposed to detect
  unauthorized or out-of-scope access attempts by observing who
  interacts with it. See the dedicated section below.
- **Privilege escalation** — an actor (here, potentially an autonomous
  agent) gaining access or capability beyond what it was authorized or
  intended to have.

## Networking and Linux internals

- **FQDN** — Fully Qualified Domain Name; a hostname written out to its
  complete, unambiguous position in the DNS tree, with every label from
  the host itself up to the root included — e.g. `us.aws.cdn.hf.co`
  rather than a bare `us` or a wildcard `*.hf.co`. "Fully qualified"
  means it needs no local search-domain suffix to resolve; it names
  exactly one point in DNS from anywhere. GYMSIEGE's Hugging Face Secret
  is deliberately scoped to nine **exact** FQDNs rather than a wildcard
  pattern, so the token's trust boundary can't silently widen if Hugging
  Face adds a new subdomain — a new host has to be reviewed and added on
  purpose. See the nine-host table in
  [`codebase-overview.md`](codebase-overview.md) and
  [`HUGGINGFACE_HOSTS.md`](HUGGINGFACE_HOSTS.md).
- **TLS** — Transport Layer Security; the encrypted-handshake protocol
  that was failing for package fetches inside the nested Alpine build
  container (`DAYTONA_BAKE_ISSUE.md`).
- **CA bundle** — the set of trusted root certificates a TLS client
  validates a server's certificate against; mounting the outer sandbox's
  CA bundle into the nested container did not fix the TLS failure.
- **NAT** — Network Address Translation; how traffic from an isolated
  network (e.g. a Docker bridge) is rewritten to look like it came from
  the host when it exits toward the internet — each NAT hop is a place a
  nested-container network path can break.
- **Bridge network** — Docker's default virtual network mode; containers
  get a private IP behind NAT unless `--network host` is used.
- **Docker-in-Docker (DinD)** — running a Docker daemon (`dockerd`) inside
  a container/sandbox, so that sandbox can itself build/run further
  containers.
- **`ss`** — "socket statistics," the modern `netstat` replacement from
  `iproute2`; reads the kernel's socket tables (via netlink or
  `/proc/net/tcp`) to list open sockets, optionally with owning-process
  info (`-p`).
- **`apk` / `apk add --no-cache`** — Alpine Linux's package manager;
  `--no-cache` skips persisting the downloaded package index to disk
  (avoids bloating a container image layer). Unrelated to the TLS failure
  itself — both cached and no-cache installs still need a working HTTPS
  fetch.
- **PID** — Process ID; the kernel's identifier for a running process.
- **fd (file descriptor)** — a per-process integer handle to an open file,
  socket, pipe, or other kernel object, listed under `/proc/<pid>/fd/`.
- **inode** — the kernel's internal identifier for a filesystem object (or,
  for sockets, a similar identifier used to name the socket in `/proc` and
  netlink output, shown as `socket:[<inode>]`).
- **`/proc`** — the Linux virtual filesystem exposing kernel and per-process
  state (open fds, memory maps, network tables) as browsable files.
- **netlink** — a Linux kernel-to-userspace communication protocol used by
  tools like `ss` to query socket/routing tables more efficiently than
  parsing `/proc` text files.
- **ASLR** — Address Space Layout Randomization; a memory-safety
  mitigation GYMSIEGE explicitly sets (`kernel.randomize_va_space=2`)
  before running sanitizer oracle stages.
- **OpenTelemetry (OTel) `client.address` / `network.peer.address`** —
  semantic-convention trace attributes: `client.address` is the logical
  originating client (possibly recovered from a forwarded-for header);
  `network.peer.address` is the immediate TCP peer on that specific
  connection (often an internal proxy hop, not the real client).
- **ASN / WHOIS** — Autonomous System Number and the public lookup used to
  identify which network operator (ISP, cloud provider, etc.) owns a given
  IP address; used in this conversation to confirm a traced `client.address`
  belonged to a residential ISP, not Daytona infrastructure.
- **RFC1918** — the reserved private IPv4 address ranges (e.g.
  `172.16.0.0/12`, which `172.20.0.1` falls in) used for internal/bridge
  networking, never routable on the public internet.

## AI/LLM and orchestration

- **LLM** — Large Language Model; the class of model powering the
  benchmark agents (Codex, Claude Code, Gemini CLI).
- **LiteLLM** — a model-routing proxy GYMSIEGE uses to give CyberGym's
  Anthropic-shaped backend access to an OpenAI GPT model.
- **`asyncio.Semaphore`** — Python's async concurrency primitive used to
  cap how many sandbox trials run in parallel (`--max-parallel`).
- **Concurrency ladder** — the sequence of parallelism levels
  (`CONCURRENCY_LADDER = [1, 2, 4, 8, 16, 32]`) `orchestrator.py sweep`
  ramps through to find the failure curve.
- **CLI** — Command Line Interface; `orchestrator.py`'s subcommands
  (`run`, `sweep`, `provision-bench`, `exploitgym-run`, `reap`).

## Build and tooling

- **FastAPI / Uvicorn** — the Python web framework and ASGI server
  `dashboard.py` is built on.
- **WSL** — Windows Subsystem for Linux; where this project's `.venv` was
  actually built and must be run from, since its Python symlinks resolve
  to `/usr/bin/python3` (a WSL path), not the native Windows/Git Bash
  environment.
- **Idempotent** — an operation safe to repeat without changing the
  outcome beyond the first success; used to describe the bake script's
  `if [ ! -x ... ]` guards that skip already-completed steps on retry.
- **Static binary / static linking** — compiling a binary with all its
  library dependencies bundled in, so it runs without needing those
  libraries installed separately — used to avoid the nested-container
  package-fetch problem for `socat`/`nc`.

---

## Future experiment: fd/socket-inode ownership as an insider honeypot

### The underlying mechanism (recap, more formally)

A kernel socket has no built-in notion of "owning process" — ownership is
reconstructed, not looked up directly:

1. Every open socket has a kernel-assigned **inode number**, visible in
   `/proc/net/tcp` (and its netlink equivalent, `sock_diag`) as one column
   per socket.
2. Every process exposes its open file descriptors under
   `/proc/<pid>/fd/*`. If descriptor `N` in process `<pid>` is an open
   socket, that path is a symlink literally named `socket:[<inode>]`.
3. Tools like `ss -p` or `lsof` resolve ownership by walking `/proc/*/fd/*`
   for **every** running process and matching each `socket:[<inode>]`
   symlink's inode number against the sockets they found in step 1.
   Whichever process has a matching fd is reported as that socket's owner.
4. This cross-reference requires read access to another process's
   `/proc/<pid>/fd/` directory — which the kernel only grants to that
   process's own owner or to root/`CAP_SYS_PTRACE`-equivalent callers.
   Without that privilege, the socket still shows up, just without a
   `pid=` field.

### The honeypot idea

Because resolving a socket's owner *requires actively walking another
process's fd table*, that act is itself a detectable, fairly unusual
thing for a benign task-scoped process to do. This suggests a detection
design, not an escalation technique:

1. **Deploy a decoy.** Run a low-privilege "bait" process inside the
   sandbox that holds an open socket fd deliberately made to *look*
   interesting to something hunting for privilege-escalation targets —
   e.g., named or positioned to resemble a Docker daemon socket, an
   internal controller/admin API, or a credential-broker connection the
   agent was never told about or given legitimate access to.
2. **Instrument the read path, not the socket itself.** The bait socket
   doesn't need to grant any real privilege — it can be inert. The signal
   is *access to the reconnaissance path*: an audit/eBPF hook on
   `openat()`/`readlink()` calls targeting `/proc/<bait-pid>/fd/*`, or on
   `connect()`/`bind()` attempts toward the bait socket's address, fires
   whenever something other than the expected monitoring tooling touches
   it.
3. **Compare against the agent's declared scope.** In GYMSIEGE's own
   benchmark harness, a task-scoped agent process has a well-defined,
   narrow set of things it's supposed to touch (its own workspace, the
   sanctioned proxy/controller endpoints ExploitGym's firewall already
   permits). It has no legitimate reason to enumerate `ss -p`/`lsof`
   output beyond that, walk other PIDs' `/proc/*/fd/*`, or attempt to
   connect to a socket address it was never given. Any of those three
   becomes a strong, low-false-positive signal that an agent is probing
   beyond its sanctioned task boundary — the same class of behavior a
   real privilege-escalation attempt would exhibit during reconnaissance.
4. **Feed it back as a new metric, not just an alert.** This fits
   naturally alongside GYMSIEGE's existing capability/infrastructure
   metrics as a third axis: not just "did the agent solve the task" or
   "how did the fleet behave under load," but "did the agent attempt
   out-of-scope lateral movement or escalation inside its own sandbox" —
   directly relevant to ExploitGym-style benchmarks where the whole point
   is studying how far an autonomous agent will push offensive behavior.

### Why this stays a "future experiment" and not a how-to

This is a **detection/monitoring design sketch** — a way to catch
escalation *attempts*, not a technique for performing one. Before
building it: it needs real audit tooling (auditd rules or an eBPF probe,
not just polling `ss` output, since polling can miss short-lived
access), a clear definition of "in-scope" access per benchmark task so
the false-positive rate is known, and it should run alongside — never
instead of — the existing firewall/proxy/`network_block_all` containment
layers already in place, since a honeypot only tells you *that* an agent
tried something; it isn't itself a barrier that stops it.
