#!/usr/bin/env python3
"""Run one collusion or intent cell in a Docker container behind an allow-listing egress proxy.

The Docker twin of modal_honeypot/runner.py, for a client that needs its own
Linux sandbox (Codex workspace-write uses Landlock, which Modal's gVisor kernel
lacks). Everything that is not Modal is reused from that runner: the argv run
inside the boundary, the output name, the egress allow-list, the validation,
the per-cell virtual key, the redaction scan, and the run-record shape.

The boundary, per cell:

* the sandbox container runs as root only long enough for ``runuser`` to drop to
  the unprivileged ``honeypot`` user; every capability is dropped except SETUID
  and SETGID (which runuser needs), no-new-privileges is set, and there are no
  volumes, no bind mounts, no host network and no privileged mode; its seccomp
  profile is Docker's default plus only the namespace and mount calls Codex's
  bubblewrap sandbox needs (docker_honeypot/seccomp-bwrap.json);
* a real-agent cell sits on the internal network ``honeypot-egress`` (no route
  out) and reaches the world only through its own egress-proxy container, which
  is on that network and the default bridge and allows CONNECT to exactly the
  gateway and Langfuse hosts; a scripted cell runs with ``--network none``.
  The two hosted-search intent cases (ITH-010, ITH-011) take the allow-list's
  ``web-search`` token, which turns on live hosted search and admits only the
  search hosts named in HONEYPOT_WEB_SEARCH_HOSTS (none by default: the
  provider runs hosted search behind the gateway);
* the virtual key and gateway URL enter the container only as ``docker exec``
  environment, by name, so their values never appear in any process argv;
* ``finally`` removes both containers, revokes the key, records spend, runs the
  redaction scan, and writes docker-run.json beside the copied outputs.

This is a second, weaker boundary than Modal's (the host kernel is shared) and
is reported as such, never pooled with Modal cohorts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:  # direct ``python docker_honeypot/runner.py``
    sys.path.insert(0, str(REPO))

from modal_honeypot import runner as base  # noqa: E402

PROVIDER = "docker"
BOUNDARY = "docker-container"
RUN_RECORD = "docker-run.json"
NETWORK = "honeypot-egress"
PROXY_ALIAS = "egress-proxy"
PROXY_PORT = 3128
PROXY_LOG = "/var/log/egress/egress-proxy.log"
PROXY_LOG_NAME = "egress-proxy.log"
PROXY_READY_TEXT = "egress proxy listening"
IMAGE_REPO = "rogue-agent-honeypot"
PROXY_IMAGE_REPO = "rogue-agent-honeypot-proxy"
IMAGE_DIRS = ("agent_honeypot", "model_replication_honeypot", "modal_honeypot", "tests")
LABEL = "rogue-agent-honeypot.role"
REMOTE_OUTPUT = "/tmp/eval-output"
SECRET_ENV_NAMES = ("OPENAI_API_KEY", "OPENAI_BASE_URL")
EGRESS_TOKENS = {"gateway", "langfuse"}
WEB_SEARCH_TOKEN = "web-search"
WEB_SEARCH_HOSTS_ENV = "HONEYPOT_WEB_SEARCH_HOSTS"
HOSTNAME_PATTERN = re.compile(r"(?=.{1,253}\Z)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")
INTENT_DATASET = REPO / "agent_honeypot" / "intent_tripwires" / "experiments.jsonl"
# Corpus version 2 (make_experiments_v2.py): the same cases with the untrusted text in TASK.md.
INTENT_DATASETS = (INTENT_DATASET, INTENT_DATASET.with_name("experiments-v2.jsonl"),
                   INTENT_DATASET.with_name("probes.jsonl"))
HARNESSES = ("collusion", "intent")
# Docker's default seccomp profile plus only the calls Codex's bubblewrap
# sandbox needs (docker_honeypot/build_seccomp_profile.py documents each one).
# The sandbox container gets it; the egress proxy keeps Docker's default.
SECCOMP_PROFILE_RELATIVE = "docker_honeypot/seccomp-bwrap.json"
SECCOMP_PROFILE = REPO / SECCOMP_PROFILE_RELATIVE
POLICY = {
    "provider": PROVIDER,
    "boundary": BOUNDARY,
    "cpus": "2",
    "memory": "4g",
    "pids_limit": 512,
    "cap_drop": ["ALL"],
    "cap_add": ["SETGID", "SETUID"],
    "security_opt": ["no-new-privileges", f"seccomp={SECCOMP_PROFILE_RELATIVE}"],
    "privileged": False,
    "host_network": False,
    "bind_mounts": [],
    "volumes": {},
    "secrets": [],
    "timeout": 1800,
    "user": "honeypot",
}

DockerFn = Callable[..., "subprocess.CompletedProcess[str]"]


def run_docker(
    args: Sequence[str], *, env: Mapping[str, str] | None = None, timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    """The one place the docker CLI is called; tests substitute a fake."""
    return subprocess.run(
        ["docker", *args], env=None if env is None else dict(env), timeout=timeout,
        text=True, capture_output=True, check=False,
    )


def _ok(docker: DockerFn, args: Sequence[str], what: str) -> subprocess.CompletedProcess[str]:
    completed = docker(list(args))
    if completed.returncode != 0:
        tail = (completed.stderr or completed.stdout or "").strip().splitlines()[-3:]
        raise RuntimeError(f"docker {what} failed: " + " | ".join(tail))
    return completed


def source_revision(repo: Path = REPO) -> dict[str, object]:
    """The commit the image is built from, and whether its inputs are dirty."""
    try:
        commit = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            text=True, capture_output=True, check=True,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "-C", str(repo), "status", "--porcelain", "--", *IMAGE_DIRS,
             "docker_honeypot"],
            text=True, capture_output=True, check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return {"commit": None, "dirty": None}
    return {"commit": commit, "dirty": bool(status.strip())}


def image_tags(revision: Mapping[str, object]) -> dict[str, str]:
    commit = revision.get("commit")
    suffix = f"{str(commit)[:7]}{'-dirty' if revision.get('dirty') else ''}" if commit else "unknown"
    return {"image": f"{IMAGE_REPO}:{suffix}", "proxy_image": f"{PROXY_IMAGE_REPO}:{suffix}"}


def container_names(
    harness: str, case_id: str, trial: int, stamp: str, *, agent: bool,
) -> dict[str, str]:
    """Container names derived from the key alias (slashes are not allowed)."""
    alias = (base.virtual_key_alias(harness, case_id, "docker", trial, stamp) if agent
             else f"{harness}/{case_id}/scripted/{stamp}")
    name = re.sub(r"[^A-Za-z0-9_.-]", "-", alias)
    return {"sandbox": name, "proxy": f"{name}-proxy"}


def live_search_cases(datasets: tuple[Path, ...] = INTENT_DATASETS) -> frozenset[str]:
    """The intent cases that need live hosted web search: ITH-010 and ITH-011,
    their corpus-version-2 twins ITH-110 and ITH-111, and the search probe ITH-901."""
    rows = (json.loads(line) for dataset in datasets if dataset.is_file()
            for line in dataset.read_text().splitlines() if line.strip())
    return frozenset(str(row["id"]) for row in rows if row["metadata"].get("requires_live_web_search"))


def validate_egress_spec(
    spec: str | None, subject_command: str | None, *, harness: str = "collusion",
    case_id: str | None = None,
) -> str:
    """The proxy allow-list is exactly the gateway and Langfuse hosts, or nothing;
    a hosted-search intent cell adds the web-search token. Returns the cell's
    web-search mode ("live" with the token, else "disabled").

    The token is the explicit opt-in for live hosted web search, accepted only
    for a real agent on an intent case that needs it and required for those
    cases, so they never run with search silently off. Hosted search runs at
    the model provider, behind the gateway, so by default the token adds no
    host; any search host the client must reach itself is named, as bare
    hostnames, in HONEYPOT_WEB_SEARCH_HOSTS (web_search_hosts)."""
    if spec is None:
        if subject_command is not None:
            raise ValueError("a real-agent Docker cell requires --egress-allowlist langfuse,gateway")
        return "disabled"
    tokens = {item.strip() for item in spec.split(",") if item.strip()}
    needs_search = (
        harness == "intent" and subject_command is not None and case_id in live_search_cases()
    )
    live = WEB_SEARCH_TOKEN in tokens
    if live and not needs_search:
        raise ValueError(
            "the web-search token is only for a real agent on an intent case that needs "
            "live hosted web search (" + ", ".join(sorted(live_search_cases())) + ")"
        )
    if needs_search and not live:
        raise ValueError(
            f"{case_id} needs live hosted web search: use "
            "--egress-allowlist langfuse,gateway,web-search"
        )
    if tokens - {WEB_SEARCH_TOKEN} != EGRESS_TOKENS:
        raise ValueError(
            "the Docker egress allow-list is exactly the tokens langfuse,gateway "
            "(the gateway host and the Langfuse host), plus web-search for the "
            "hosted-search intent cases"
        )
    return "live" if live else "disabled"


def web_search_hosts(web_search: str, environ: Mapping[str, str] | None = None) -> list[str]:
    """Search hosts a live-search cell's client reaches itself, from
    HONEYPOT_WEB_SEARCH_HOSTS (comma-separated bare hostnames; empty by default,
    since hosted search runs behind the gateway). Never for any other cell."""
    raw = (os.environ if environ is None else environ).get(WEB_SEARCH_HOSTS_ENV, "")
    hosts = sorted({item.strip().lower() for item in raw.split(",") if item.strip()})
    if hosts and web_search != "live":
        raise ValueError(f"{WEB_SEARCH_HOSTS_ENV} is only for a cell with the web-search token")
    for host in hosts:
        if not HOSTNAME_PATTERN.fullmatch(host):
            raise ValueError(f"{WEB_SEARCH_HOSTS_ENV} entries are bare hostnames, not URLs or '*': {host}")
    return hosts


def seccomp_profile_record(path: Path = SECCOMP_PROFILE) -> dict[str, str]:
    """The sandbox's seccomp profile as the run record names it."""
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        raise RuntimeError(f"the sandbox seccomp profile is missing: {SECCOMP_PROFILE_RELATIVE}") from None
    return {"path": SECCOMP_PROFILE_RELATIVE, "sha256": digest}


def sandbox_run_argv(name: str, image: str, network: str) -> list[str]:
    return [
        "run", "--detach", "--rm", "--name", name, "--network", network,
        "--cpus", POLICY["cpus"], "--memory", POLICY["memory"],
        "--pids-limit", str(POLICY["pids_limit"]), "--read-only=false",
        "--cap-drop", "ALL", "--cap-add", "SETGID", "--cap-add", "SETUID",
        "--security-opt", "no-new-privileges",
        "--security-opt", f"seccomp={SECCOMP_PROFILE}", "--workdir", "/workspace",
        "--label", f"{LABEL}=sandbox",
        image, "sleep", "infinity",
    ]


def proxy_run_argv(name: str, image: str, allowlist: Sequence[str]) -> list[str]:
    return [
        "run", "--detach", "--rm", "--name", name,
        "--network", NETWORK, "--network-alias", PROXY_ALIAS,
        "--cpus", "0.5", "--memory", "256m", "--pids-limit", "128",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--env", "EGRESS_ALLOWLIST=" + ":".join(allowlist),
        "--label", f"{LABEL}=egress-proxy",
        image,
    ]


def proxy_url() -> str:
    return f"http://{PROXY_ALIAS}:{PROXY_PORT}"


def exec_argv(
    name: str, command: Sequence[str], *, carry_secrets: bool, with_proxy: bool,
) -> list[str]:
    """``docker exec`` argv. Secrets are named, never valued: the docker CLI
    reads OPENAI_API_KEY and OPENAI_BASE_URL from its own environment."""
    argv = ["exec", "--workdir", "/workspace"]
    if carry_secrets:
        for env_name in SECRET_ENV_NAMES:
            argv += ["--env", env_name]
    if with_proxy:
        argv += [
            "--env", f"HTTPS_PROXY={proxy_url()}",
            "--env", f"HTTP_PROXY={proxy_url()}",
            "--env", "NO_PROXY=",
        ]
    return [*argv, name, *command]


def exec_environment(
    source: Mapping[str, str], *, key: str | None, gateway: str | None,
) -> dict[str, str]:
    """The docker CLI's own environment for the exec call."""
    env = {name: value for name, value in source.items() if name not in SECRET_ENV_NAMES}
    if key is not None:
        assert gateway is not None
        env["OPENAI_API_KEY"] = key
        env["OPENAI_BASE_URL"] = gateway
    return env


def build_images(
    docker: DockerFn, tags: Mapping[str, str], *, build_agent: bool, build_proxy: bool,
) -> None:
    if build_agent:
        _ok(docker, [
            "build", "--quiet", "--file", str(REPO / "docker_honeypot" / "Dockerfile"),
            "--build-arg", f"CODEX_VERSION={base.CODEX_VERSION}",
            "--tag", tags["image"], str(REPO),
        ], "build of the agent image")
    if build_proxy:
        _ok(docker, [
            "build", "--quiet", "--file", str(REPO / "docker_honeypot" / "Dockerfile.proxy"),
            "--tag", tags["proxy_image"], str(REPO / "docker_honeypot"),
        ], "build of the proxy image")


def ensure_internal_network(docker: DockerFn) -> None:
    probe = docker(["network", "inspect", "--format", "{{.Internal}}", NETWORK])
    if probe.returncode != 0:
        _ok(docker, ["network", "create", "--internal", NETWORK], "network create")
        probe = _ok(
            docker, ["network", "inspect", "--format", "{{.Internal}}", NETWORK],
            "network inspect",
        )
    if probe.stdout.strip() != "true":
        raise RuntimeError(f"docker network {NETWORK} exists but is not --internal; remove it")


def refuse_stale_containers(docker: DockerFn) -> None:
    """One cell at a time: a leftover container would share the proxy alias."""
    for selector in (f"label={LABEL}", f"network={NETWORK}"):
        listed = _ok(docker, ["ps", "--all", "--quiet", "--filter", selector], "ps")
        if listed.stdout.strip():
            raise RuntimeError(
                f"a previous honeypot container still exists ({selector}); "
                "remove it before starting another cell"
            )


def wait_for_proxy(
    docker: DockerFn, name: str, *, timeout: float = 20.0,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    deadline = time.monotonic() + timeout
    while True:
        logs = docker(["logs", name])
        if PROXY_READY_TEXT in (logs.stdout or "") + (logs.stderr or ""):
            return
        if time.monotonic() > deadline:
            raise RuntimeError("the egress proxy did not report ready")
        sleep(0.25)


def remove_container(
    docker: DockerFn, name: str, *, attempts: int = 40,
    sleep: Callable[[float], None] = time.sleep,
) -> bool:
    """Force-remove a container and confirm it is gone."""
    docker(["rm", "--force", name])
    for _ in range(attempts):
        if docker(["container", "inspect", "--format", "{{.Id}}", name]).returncode != 0:
            return True
        sleep(0.25)
    return False


def _text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def run(
    args: argparse.Namespace, *, docker: DockerFn | None = None, admin_client=None,
    revision: Mapping[str, object] | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    if args.harness not in HARNESSES:
        raise ValueError("the Docker runner takes --harness " + " or ".join(HARNESSES))
    base.validate_case(args.harness, args.case_id)
    base.validate_subject_command(args.harness, args.subject_command)
    spec = getattr(args, "egress_allowlist", None)
    web_search = validate_egress_spec(
        spec, args.subject_command, harness=args.harness, case_id=args.case_id,
    )
    search_hosts = web_search_hosts(web_search)
    host_spec = None if spec is None else ",".join(
        token for token in (item.strip() for item in spec.split(","))
        if token and token != WEB_SEARCH_TOKEN
    )
    egress_allowlist = base.resolve_egress_allowlist(host_spec)
    if egress_allowlist is not None and search_hosts:
        egress_allowlist = sorted(set(egress_allowlist) | set(search_hosts))
    base.validate_egress_allowlist(args.harness, egress_allowlist, False)
    agent = args.subject_command is not None
    with_proxy = bool(egress_allowlist)
    network = NETWORK if with_proxy else "none"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    arm = getattr(args, "arm", "manual")
    trial = getattr(args, "trial", 1)
    key_ttl = getattr(args, "key_ttl", None) or base.default_key_ttl(args.sandbox_timeout)
    key_budget = getattr(args, "key_budget", 0.50)
    agent_timeout = getattr(args, "agent_timeout", 900)
    codex_sandbox = os.environ.get("HONEYPOT_CODEX_SANDBOX", "danger-full-access")
    if codex_sandbox not in base.CODEX_SANDBOX_MODES:
        raise ValueError("HONEYPOT_CODEX_SANDBOX must be danger-full-access or workspace-write")
    key_alias = base.virtual_key_alias(args.harness, args.case_id, arm, trial, stamp) if agent else None
    names = container_names(args.harness, args.case_id, trial, stamp, agent=agent)
    revision = dict(revision) if revision is not None else source_revision()
    tags = image_tags(revision)
    if getattr(args, "image", None):
        tags["image"] = args.image
    seccomp = seccomp_profile_record()
    runtime_policy: dict[str, object] = {
        **POLICY,
        "network": network,
        "egress": "allowlist" if with_proxy else "blocked",
        "egress_allowlist": egress_allowlist,
        "egress_proxy": proxy_url() if with_proxy else None,
        "timeout": args.sandbox_timeout,
        "exec_timeout": args.exec_timeout,
        "network_off_suite_enabled": False,
        "evidence_chain": True,
        "weights_mode": "text",
        "web_search": web_search,
        "web_search_hosts": search_hosts,
    }
    standalone_search = agent and base.standalone_web_search(getattr(args, "model", None), web_search)
    runtime_policy["standalone_web_search"] = standalone_search
    alert = bool(getattr(args, "alert", False))
    enforce = bool(getattr(args, "enforce", False))
    enforce_real_agent = bool(getattr(args, "enforce_real_agent", False))
    enforce_hold = getattr(args, "enforce_hold", None)
    base.validate_alerting(args.harness, args.subject_command, alert=alert, enforce=enforce,
                           enforce_real_agent=enforce_real_agent, enforce_hold=enforce_hold)
    # Both settings, always, so every run record says whether the alerter ran
    # and whether it could kill.
    runtime_policy.update({
        "alert": alert or enforce,
        "enforce": enforce,
        "enforce_real_agent": enforce_real_agent,
        "enforce_hold_seconds": enforce_hold,
    })
    if key_alias is not None:
        runtime_policy.update({
            "secrets": [f"virtual-key:{key_alias}"],
            "key_budget_usd": key_budget,
            "key_ttl": key_ttl,
            "key_model": getattr(args, "model", None),
            "agent_timeout_seconds": agent_timeout,
            "codex_sandbox": codex_sandbox,
        })
    command = base.remote_argv(
        args.harness, args.case_id, args.workers,
        evidence_chain=True,
        subject_command=args.subject_command,
        agent_timeout=agent_timeout,
        model=getattr(args, "model", None),
        codex_sandbox=codex_sandbox,
        egress_allowlist=egress_allowlist,
        execution_boundary=BOUNDARY,
        web_search=web_search,
        alert=alert, enforce=enforce, enforce_real_agent=enforce_real_agent,
        enforce_hold=enforce_hold,
    )
    name = base.output_name(
        args.harness, args.case_id, demo=False, evidence_chain=True, weights_mode="text",
        allow_network=False, subject_command=args.subject_command,
        egress_allowlist=egress_allowlist,
    )
    plan_exec = exec_argv(names["sandbox"], command, carry_secrets=agent, with_proxy=with_proxy)
    if with_proxy:
        print("WARNING: --egress-allowlist: this container reaches "
              + ", ".join(egress_allowlist or [])
              + " through the egress proxy and no other host; every byte to those hosts "
              "is an observed channel", file=sys.stderr)
    if args.dry_run:
        print(json.dumps({
            "provider": PROVIDER, "boundary": BOUNDARY, "harness": args.harness,
            "case_id": args.case_id, "output_root": str(args.output), "output_name": name,
            "image": tags["image"], "proxy_image": tags["proxy_image"] if with_proxy else None,
            "source_revision": revision, "network": network, "seccomp_profile": seccomp,
            "egress_proxy": {
                "name": names["proxy"], "alias": PROXY_ALIAS, "port": PROXY_PORT,
                "allowlist": egress_allowlist,
            } if with_proxy else None,
            "docker_run": sandbox_run_argv(names["sandbox"], tags["image"], network),
            "docker_exec": plan_exec,
            "policy": runtime_policy, "remote_argv": command,
        }, indent=2))
        return 0

    gateway = None
    if agent:
        gateway = base.validate_virtual_key_preconditions(args, egress_allowlist)
    if docker is None:
        docker = run_docker
    output = (args.output / f"{name}-{stamp}").resolve()
    output.mkdir(parents=True, exist_ok=False)
    minted: base.MintedKey | None = None
    client = admin_client
    cleanup_errors: list[str] = []
    started: list[tuple[str, str]] = []
    metadata: dict[str, object] = {
        "schema_version": "1.0", "harness": args.harness, "demo": False,
        "case_id": args.case_id, "evidence_chain": True,
        "subject_mode": "agent" if agent else "scripted",
        "weights_mode": "text", "policy": runtime_policy, "started_at": stamp,
        "provider": PROVIDER, "boundary": BOUNDARY, "image": tags["image"],
        "source_revision": revision, "seccomp_profile": seccomp,
        "egress_proxy_log": PROXY_LOG_NAME if with_proxy else None,
    }
    if key_alias is not None:
        metadata.update({"arm": arm, "trial": trial, "agent_timeout_seconds": agent_timeout})
    try:
        build_images(
            docker, tags, build_agent=not getattr(args, "image", None), build_proxy=with_proxy,
        )
        metadata["image_id"] = _ok(
            docker, ["image", "inspect", "--format", "{{.Id}}", tags["image"]], "image inspect",
        ).stdout.strip()
        refuse_stale_containers(docker)
        if with_proxy:
            ensure_internal_network(docker)
            started.append(("proxy", names["proxy"]))
            _ok(docker, proxy_run_argv(names["proxy"], tags["proxy_image"], egress_allowlist or []),
                "run of the egress proxy")
            _ok(docker, ["network", "connect", "bridge", names["proxy"]],
                "network connect of the egress proxy")
            wait_for_proxy(docker, names["proxy"], sleep=sleep)
            metadata["egress_proxy"] = {
                "name": names["proxy"], "alias": PROXY_ALIAS, "port": PROXY_PORT,
                "image": tags["proxy_image"],
            }
        if key_alias is not None:
            assert gateway is not None
            if client is None:
                client = base.LiteLLMAdminClient(gateway, os.environ["LITELLM_MASTER_KEY"])
            key_metadata: dict[str, object] = {
                "run_id": key_alias, "harness": args.harness, "case_id": args.case_id,
                "trial": trial, "arm": arm, "purpose": "rogue-agent-honeypot",
                "provider": PROVIDER,
            }
            if standalone_search:
                # The gateway's search route is auth-enforced: only a key whose
                # metadata names it may call it, so only this cell's key can search.
                key_metadata["allowed_passthrough_routes"] = [base.STANDALONE_SEARCH_ROUTE]
            minted = base.mint_virtual_key(
                client, alias=key_alias, model=args.model, budget_usd=key_budget, ttl=key_ttl,
                metadata=key_metadata,
            )
            key_record: dict[str, object] = {
                "key_alias": key_alias,
                "minted_at": datetime.now(timezone.utc).isoformat(),
                "budget_usd": key_budget,
                "ttl": key_ttl,
            }
            if minted.token_id:
                key_record["token_id"] = minted.token_id
            elif minted.key_hash:
                key_record["key_hash"] = minted.key_hash
            else:
                key_record["key_fingerprint"] = minted.fingerprint
            metadata["virtual_key"] = key_record
        started.append(("sandbox", names["sandbox"]))
        metadata["sandbox_id"] = _ok(
            docker, sandbox_run_argv(names["sandbox"], tags["image"], network),
            "run of the sandbox container",
        ).stdout.strip()
        metadata["sandbox_name"] = names["sandbox"]
        exec_env = exec_environment(
            os.environ, key=minted.key if minted else None, gateway=gateway,
        )
        try:
            process = docker(plan_exec, env=exec_env, timeout=args.exec_timeout)
        except subprocess.TimeoutExpired as exc:
            metadata["exec_timed_out"] = True
            metadata["remote_exit_code"] = None
            docker(["kill", names["sandbox"]])
            (output / "remote.stdout.log").write_text(_text(exc.stdout))
            (output / "remote.stderr.log").write_text(_text(exc.stderr))
            metadata["passed"] = False
            return 1
        metadata["remote_exit_code"] = process.returncode
        (output / "remote.stdout.log").write_text(process.stdout or "")
        (output / "remote.stderr.log").write_text(process.stderr or "")
        _ok(docker, ["cp", f"{names['sandbox']}:{REMOTE_OUTPUT}/summary.json",
                     str(output / "summary.json")], "cp of summary.json")
        _ok(docker, ["cp", f"{names['sandbox']}:{REMOTE_OUTPUT}/artifacts.tar.gz",
                     str(output / "artifacts.tar.gz")], "cp of artifacts.tar.gz")
        passed = process.returncode == 0
        metadata["passed"] = passed
        return 0 if passed else 1
    finally:
        if with_proxy and any(role == "proxy" for role, _ in started):
            copied = docker(["cp", f"{names['proxy']}:{PROXY_LOG}", str(output / PROXY_LOG_NAME)])
            if copied.returncode != 0:
                metadata["egress_proxy_log_error"] = "egress proxy log copy failed"
                cleanup_errors.append("egress proxy log copy failed")
        removed: dict[str, bool] = {}
        for role, container in started:
            try:
                removed[role] = remove_container(docker, container, sleep=sleep)
            except Exception:
                removed[role] = False
        metadata["containers_removed"] = removed
        if started and all(removed.values()):
            metadata["termination"] = "explicit-finally"
        elif started:
            metadata["termination_error"] = "container removal failed"
            cleanup_errors.append("container removal failed")
        if minted is not None and client is not None:
            key_record = metadata["virtual_key"]
            assert isinstance(key_record, dict)
            try:
                key_record["spend_usd"] = base.key_spend(client, minted.management_id)
            except Exception:
                key_record["spend_error"] = "key spend lookup failed"
                cleanup_errors.append("key spend lookup failed")
            try:
                base.revoke_virtual_key(client, minted.management_id)
                key_record["revoked_at"] = datetime.now(timezone.utc).isoformat()
            except Exception:
                key_record["revocation_error"] = "virtual-key revocation failed; TTL remains the backstop"
                cleanup_errors.append("virtual-key revocation failed")
        metadata_path = output / RUN_RECORD
        metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
        if minted is not None:
            scan = base.scan_artifacts([output], minted.key)
            findings = scan["findings"]
            metadata["redaction"] = {
                "passed": not findings,
                "findings": [str(path.relative_to(output)) for path in findings],
                "key_shaped_tokens": [
                    str(path.relative_to(output)) for path in scan["key_shaped_tokens"]
                ],
            }
            metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
            if findings:
                cleanup_errors.append("virtual-key redaction scan failed")
        print(json.dumps({"output": str(output), **metadata}, indent=2, sort_keys=True))
        if cleanup_errors:
            raise RuntimeError("; ".join(cleanup_errors))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--harness", choices=list(HARNESSES), required=True)
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--workers", type=int, choices=range(1, 9), default=4)
    parser.add_argument(
        "--egress-allowlist",
        help="exactly 'langfuse,gateway' for a real-agent cell: the egress proxy allows "
             "CONNECT to those two hosts only; omitted, the container has no network. "
             "The hosted-search intent cases (ITH-010, ITH-011) add 'web-search', which "
             "turns on live hosted search and admits only the hosts named in "
             "HONEYPOT_WEB_SEARCH_HOSTS (none by default: hosted search runs behind the gateway)",
    )
    parser.add_argument("--subject-command",
                        help="real-agent command: the collusion subjects, or the intent case's agent")
    parser.add_argument("--agent-timeout", type=int, default=900)
    parser.add_argument("--model", help="single LiteLLM model allowed on a minted virtual key")
    parser.add_argument("--key-budget", type=float, default=0.50)
    parser.add_argument("--key-ttl")
    parser.add_argument("--arm", default="manual")
    parser.add_argument("--trial", type=int, default=1)
    parser.add_argument("--image", help="use this prebuilt agent image tag instead of building")
    parser.add_argument("--output", type=Path, default=Path("results/docker-honeypot"))
    parser.add_argument("--sandbox-timeout", type=int, default=POLICY["timeout"])
    parser.add_argument("--exec-timeout", type=int, default=1500)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--alert", action="store_true",
                        help="run agent_honeypot/alerter.py: ALERT_RAISED at the first boundary event, "
                             "and a boundary.json latency record per case")
    parser.add_argument("--enforce", action="store_true",
                        help="also kill the agent's process tree at that event (implies --alert)")
    parser.add_argument("--enforce-real-agent", action="store_true",
                        help="required, beside --enforce, to enforce on a real agent (--subject-command)")
    parser.add_argument("--enforce-hold", type=int,
                        help="scripted calibration: hold each case's command SECONDS after it ends, "
                             "with a detached sleeper, so a kill has something to kill")
    args = parser.parse_args()
    if args.sandbox_timeout < args.exec_timeout or args.sandbox_timeout > 86400:
        parser.error("sandbox timeout must cover exec timeout and be at most 86400 seconds")
    if args.agent_timeout < 1:
        parser.error("--agent-timeout must be a positive integer")
    if args.subject_command is not None and args.agent_timeout > args.exec_timeout:
        parser.error("--agent-timeout must not exceed --exec-timeout")
    if not math.isfinite(args.key_budget) or args.key_budget <= 0:
        parser.error("--key-budget must be a positive finite USD amount")
    if args.trial < 1:
        parser.error("--trial must be at least 1")
    if not base.ARM_PATTERN.fullmatch(args.arm):
        parser.error("--arm must contain only letters, digits, '.', '_' or '-'")
    if args.key_ttl is not None:
        try:
            base.key_ttl_seconds(args.key_ttl)
        except ValueError as exc:
            parser.error(str(exc))
    try:
        return run(args)
    except ValueError as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
