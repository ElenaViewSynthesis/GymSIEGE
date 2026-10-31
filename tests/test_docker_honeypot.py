import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import socket
import subprocess
import tarfile
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


REPO = Path(__file__).parents[1]


def _load(name, relative):
    spec = importlib.util.spec_from_file_location(name, REPO / relative)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


RUNNER = _load("docker_honeypot_runner", "docker_honeypot/runner.py")
PROXY = _load("docker_honeypot_egress_proxy", "docker_honeypot/egress_proxy.py")
SANDBOX = _load("modal_honeypot_in_sandbox_for_docker", "modal_honeypot/in_sandbox.py")
AGENT_SUBJECT = _load(
    "collusion_agent_subject_for_docker", "agent_honeypot/collusion_tripwires/agent_subject.py",
)
BASE = RUNNER.base

FAKE_VIRTUAL_KEY = "".join(("s", "k", "-", "docker_unit_key_12345678"))
MASTER = "master-for-docker-unit-test"
REVISION = {"commit": "abcdef1234567890", "dirty": False}
AGENT_ENV = {
    "OPENAI_BASE_URL": "https://tunnel.example.org/v1",
    "LANGFUSE_BASE_URL": "https://cloud.langfuse.com",
    "LITELLM_MASTER_KEY": MASTER,
    "HONEYPOT_CODEX_SANDBOX": "workspace-write",
    # A host-side key from .env.local must never be the one the container gets.
    "OPENAI_API_KEY": "host-side-key-must-not-pass",
}


class FakeLiteLLMClient:
    def __init__(self):
        self.calls = []

    def generate(self, payload):
        self.calls.append(("generate", dict(payload)))
        return {"key": FAKE_VIRTUAL_KEY, "token_id": "e" * 64}

    def info(self, key_id):
        self.calls.append(("info", key_id))
        return {"info": {"spend": 0.0125}}

    def delete(self, key_id):
        self.calls.append(("delete", key_id))
        return {"deleted_keys": [key_id]}


class FakeDocker:
    """Records every docker CLI call; simulates the daemon in memory."""

    def __init__(self, *, exec_returncode=0, exec_timeout=False, stale=False,
                 removal_sticks=False, network_exists=False):
        self.calls = []
        self.exec_returncode = exec_returncode
        self.exec_timeout = exec_timeout
        self.stale = stale
        self.removal_sticks = removal_sticks
        self.network = "true" if network_exists else None
        self.running = set()

    def __call__(self, args, *, env=None, timeout=None):
        args = list(args)
        self.calls.append({"args": args, "env": env, "timeout": timeout})
        ok = SimpleNamespace(returncode=0, stdout="", stderr="")
        head = args[0]
        if head == "build":
            return ok
        if args[:2] == ["image", "inspect"]:
            return SimpleNamespace(returncode=0, stdout="sha256:" + "a" * 64 + "\n", stderr="")
        if head == "ps":
            return SimpleNamespace(returncode=0, stdout="0123abcd\n" if self.stale else "",
                                   stderr="")
        if args[:2] == ["network", "inspect"]:
            if self.network is None:
                return SimpleNamespace(returncode=1, stdout="", stderr="No such network")
            return SimpleNamespace(returncode=0, stdout=self.network + "\n", stderr="")
        if args[:2] == ["network", "create"]:
            self.network = "true"
            return ok
        if args[:2] == ["network", "connect"]:
            return ok
        if head == "run":
            name = args[args.index("--name") + 1]
            self.running.add(name)
            return SimpleNamespace(returncode=0, stdout=f"id-{name}\n", stderr="")
        if head == "logs":
            return SimpleNamespace(returncode=0, stdout="egress proxy listening on :3128\n",
                                   stderr="")
        if head == "exec":
            if self.exec_timeout:
                raise subprocess.TimeoutExpired(["docker", *args], timeout, output=b"partial")
            return SimpleNamespace(returncode=self.exec_returncode, stdout="remote output",
                                   stderr="")
        if head == "cp":
            source, destination = args[1], Path(args[2])
            if source.endswith("summary.json"):
                destination.write_text('{"passed": true}\n')
            elif source.endswith("artifacts.tar.gz"):
                with tarfile.open(destination, "w:gz"):
                    pass
            else:
                destination.write_text(json.dumps({
                    "client": "172.18.0.3:40000", "target": "tunnel.example.org:443",
                    "decision": "allowed", "bytes_up": 10, "bytes_down": 20,
                }) + "\n")
            return ok
        if head == "kill":
            return ok
        if args[:2] == ["rm", "--force"]:
            if not self.removal_sticks:
                self.running.discard(args[2])
            return ok
        if args[:2] == ["container", "inspect"]:
            alive = args[-1] in self.running
            return SimpleNamespace(returncode=0 if alive else 1, stdout="", stderr="")
        raise AssertionError(f"unexpected docker call: {args}")

    def first(self, *prefix):
        return next(call for call in self.calls if call["args"][:len(prefix)] == list(prefix))

    def all(self, *prefix):
        return [call for call in self.calls if call["args"][:len(prefix)] == list(prefix)]


def _env_flags(argv):
    return [argv[i + 1] for i, item in enumerate(argv) if item == "--env"]


class DockerImageTests(unittest.TestCase):
    def test_dockerfile_matches_the_modal_agent_image(self):
        class Builder:
            def __init__(self):
                self.commands, self.packages = [], []

            def apt_install(self, *args):
                self.packages.extend(args)
                return self

            def run_commands(self, *args):
                self.commands.extend(args)
                return self

            def add_local_dir(self, *args, **kwargs):
                self.commands.append(("copy", args))
                return self

        builder = Builder()
        BASE.build_image(
            SimpleNamespace(Image=SimpleNamespace(debian_slim=lambda **kw: builder)),
            verify_secret_environment=True,
        )
        text = (REPO / "docker_honeypot/Dockerfile").read_text()
        joined = re.sub(r"[ \t]+", " ", re.sub(r"\\\n\s*", " ", text))
        self.assertRegex(text, r"(?m)^FROM python:3\.12-slim$")
        installs = re.findall(r"apt-get install --yes ([^&]+)&&", joined)
        packages = [pkg for chunk in installs for pkg in chunk.split()]
        self.assertEqual(sorted(packages), sorted(builder.packages))
        for command in builder.commands:
            if isinstance(command, tuple):
                continue
            normalized = command.replace("'", '"').replace(BASE.CODEX_VERSION, "${CODEX_VERSION}")
            fragments = [part.strip() for part in normalized.split("&&")]
            for fragment in fragments:
                self.assertIn(" ".join(fragment.split(" -- ")[0].replace('"', "").split()),
                              joined.replace('"', ""), fragment)
        self.assertIn(f"ARG CODEX_VERSION={BASE.CODEX_VERSION}", text)
        for directory in RUNNER.IMAGE_DIRS:
            self.assertIn(f"COPY {directory}/ /opt/honeypot/{directory}/", text)
        self.assertEqual(len(re.findall(r"(?m)^COPY ", text)), 4)
        # No secrets in the image, and root stays the exec user so runuser can drop.
        self.assertNotRegex(text, r"(?m)^(ENV|USER|VOLUME) ")
        self.assertEqual(re.findall(r"(?m)^ARG (\w+)", text), ["CODEX_VERSION"])
        for name in ("OPENAI_API_KEY", "OPENAI_BASE_URL", "LITELLM", "LANGFUSE"):
            self.assertNotIn(name, text)

    def test_build_context_admits_only_the_four_directories(self):
        rules = [
            line.strip() for line in
            (REPO / "docker_honeypot/Dockerfile.dockerignore").read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
        self.assertEqual(rules[0], "*")
        self.assertEqual(
            sorted(rule[1:].rstrip("/") for rule in rules if rule.startswith("!")),
            sorted(RUNNER.IMAGE_DIRS),
        )

    def test_proxy_image_is_unprivileged_and_secret_free(self):
        text = (REPO / "docker_honeypot/Dockerfile.proxy").read_text()
        self.assertRegex(text, r"(?m)^USER nobody$")
        self.assertIn("COPY egress_proxy.py", text)
        self.assertNotRegex(text, r"(?m)^(ENV|ARG) ")


SECCOMP_BUILD = _load("docker_honeypot_build_seccomp", "docker_honeypot/build_seccomp_profile.py")
# The author's list of calls bubblewrap needs; clone3 is left at Docker's
# default (ENOSYS) because seccomp cannot inspect its flags.
BWRAP_CALLS = {
    "unshare", "clone", "clone3", "setns", "mount", "umount2", "pivot_root", "mount_setattr",
    "open_tree", "move_mount", "fsopen", "fsconfig", "fsmount", "fspick", "sethostname",
}
NEVER_ADDED = {
    "ptrace", "keyctl", "add_key", "request_key", "bpf", "perf_event_open", "kexec_load",
    "kexec_file_load", "init_module", "finit_module", "delete_module", "process_vm_readv",
    "process_vm_writev", "userfaultfd", "open_by_handle_at",
}


def _effective(profile, caps=("CAP_SETGID", "CAP_SETUID"), arch="SCMP_ARCH_X86_64"):
    """Per syscall, the actions and argument filters that apply to this container."""
    arches = {arch, *profile.get("archMap", [{}])[0].get("subArchitectures", [])}
    applied = {}
    for rule in profile["syscalls"]:
        inc, exc = rule.get("includes", {}), rule.get("excludes", {})
        if inc.get("caps") and not set(inc["caps"]) <= set(caps):
            continue
        if exc.get("caps") and set(exc["caps"]) & set(caps):
            continue
        names_arch = {"amd64": "SCMP_ARCH_X86_64", "x86": "SCMP_ARCH_X86", "x32": "SCMP_ARCH_X32"}
        rule_arches = {names_arch.get(a, a) for a in inc.get("arches", [])}
        if rule_arches and not rule_arches & arches:
            continue
        if {names_arch.get(a, a) for a in exc.get("arches", [])} & {arch}:
            continue
        for name in rule["names"]:
            applied.setdefault(name, []).append(
                (rule["action"], json.dumps(rule.get("args"), sort_keys=True)))
    return applied


class SeccompProfileTests(unittest.TestCase):
    def setUp(self):
        self.default_bytes = (REPO / "docker_honeypot/seccomp-default.json").read_bytes()
        self.default = json.loads(self.default_bytes)
        self.profile = json.loads((REPO / "docker_honeypot/seccomp-bwrap.json").read_text())

    def test_the_vendored_default_is_the_recorded_upstream_file(self):
        provenance = self.profile["x-gymsiege-provenance"]
        self.assertEqual(hashlib.sha256(self.default_bytes).hexdigest(),
                         provenance["default_sha256"])
        self.assertEqual(provenance["default_sha256"],
                         "536529b665dd0972c37bfb569f5d4ac8a53592e7b00752bc39ff063ca9864c74")
        self.assertEqual(provenance["version"], "v0.2.3")

    def test_profile_is_the_builders_output(self):
        self.assertEqual(SECCOMP_BUILD.build(), self.profile)

    def test_default_rules_are_kept_verbatim_and_only_bwrap_calls_are_added(self):
        for key in ("defaultAction", "defaultErrnoRet", "archMap"):
            self.assertEqual(self.profile[key], self.default[key])
        kept = len(self.default["syscalls"])
        self.assertEqual(self.profile["syscalls"][:kept], self.default["syscalls"])
        added = self.profile["syscalls"][kept:]
        for rule in added:
            self.assertEqual(rule["action"], "SCMP_ACT_ALLOW")
            self.assertTrue(rule.get("comment", "").startswith("bwrap"), rule)
            # No added rule depends on a capability: they apply to this container as is.
            self.assertNotIn("caps", rule.get("includes", {}))
            self.assertNotIn("caps", rule.get("excludes", {}))
        added_names = {name for rule in added for name in rule["names"]}
        self.assertEqual(added_names, BWRAP_CALLS - {"clone3"})
        self.assertFalse(added_names & NEVER_ADDED)

    def test_effective_set_is_the_default_plus_exactly_the_bwrap_calls(self):
        default, profile = _effective(self.default), _effective(self.profile)
        def allowed(applied):
            return {name for name, rules in applied.items()
                    if any(action == "SCMP_ACT_ALLOW" for action, _ in rules)}

        self.assertEqual(allowed(profile) - allowed(default), BWRAP_CALLS - {"clone", "clone3"})
        self.assertEqual(allowed(default) - allowed(profile), set())
        # clone was already allowed without namespace flags; it gains one rule.
        self.assertEqual(len(profile["clone"]), len(default["clone"]) + 1)
        # clone3 keeps the default's ENOSYS answer.
        self.assertEqual(profile["clone3"], default["clone3"])
        self.assertEqual(profile["clone3"][0][0], "SCMP_ACT_ERRNO")
        for name in NEVER_ADDED:
            self.assertEqual(profile.get(name), default.get(name), name)

    def test_namespace_filters_admit_the_six_and_refuse_cgroup_and_time(self):
        rules = {rule["names"][0]: rule for rule in self.profile["syscalls"][len(self.default["syscalls"]):]}
        clone_mask = rules["clone"]["args"][0]
        self.assertEqual((clone_mask["op"], clone_mask["index"]), ("SCMP_CMP_MASKED_EQ", 0))
        six = 0x10000000 | 0x00020000 | 0x20000000 | 0x08000000 | 0x04000000 | 0x40000000
        self.assertEqual(clone_mask["value"] & six, 0)
        self.assertEqual(clone_mask["value"], 0x02000000)
        unshare_mask = rules["unshare"]["args"][0]["value"]
        self.assertEqual(unshare_mask & six, 0)
        self.assertEqual(unshare_mask, 0x02000000 | 0x00000080)

    def test_sandbox_argv_carries_the_profile_and_the_proxy_argv_does_not(self):
        sandbox = RUNNER.sandbox_run_argv("cell", "image:tag", "honeypot-egress")
        options = [sandbox[i + 1] for i, item in enumerate(sandbox) if item == "--security-opt"]
        self.assertEqual(options, ["no-new-privileges", f"seccomp={RUNNER.SECCOMP_PROFILE}"])
        self.assertTrue(Path(str(RUNNER.SECCOMP_PROFILE)).is_absolute())
        proxy = RUNNER.proxy_run_argv("cell-proxy", "proxy:tag", ["a.example"])
        self.assertFalse(any("seccomp" in item for item in proxy))
        record = RUNNER.seccomp_profile_record()
        self.assertEqual(record["path"], "docker_honeypot/seccomp-bwrap.json")
        self.assertEqual(record["sha256"], hashlib.sha256(
            (REPO / "docker_honeypot/seccomp-bwrap.json").read_bytes()).hexdigest())


class EgressProxyTests(unittest.TestCase):
    ALLOW = frozenset({"tunnel.example.org", "cloud.langfuse.com"})

    def test_decision_allows_only_connect_443_to_listed_hosts(self):
        decide = PROXY.decide
        self.assertEqual(decide("CONNECT tunnel.example.org:443 HTTP/1.1", self.ALLOW),
                         (True, "tunnel.example.org:443"))
        self.assertEqual(decide("CONNECT Tunnel.Example.Org:443 HTTP/1.1", self.ALLOW),
                         (True, "tunnel.example.org:443"))
        self.assertEqual(decide("CONNECT tunnel.example.org:80 HTTP/1.1", self.ALLOW),
                         (False, "tunnel.example.org:80"))
        self.assertEqual(decide("CONNECT example.com:443 HTTP/1.1", self.ALLOW),
                         (False, "example.com:443"))
        self.assertEqual(decide("CONNECT evil.tunnel.example.org:443 HTTP/1.1", self.ALLOW),
                         (False, "evil.tunnel.example.org:443"))
        # A plain GET is refused even to an allowed host, and only host:port is kept.
        self.assertEqual(
            decide("GET http://tunnel.example.org/v1/models?token=x HTTP/1.1", self.ALLOW),
            (False, "tunnel.example.org:80"),
        )
        self.assertEqual(decide("GET /v1/models HTTP/1.1", self.ALLOW), (False, "invalid"))
        self.assertEqual(decide("garbage", self.ALLOW), (False, "invalid"))
        self.assertEqual(decide("CONNECT tunnel.example.org HTTP/1.1", self.ALLOW),
                         (False, "invalid"))

    def test_allowlist_parsing_refuses_widening(self):
        self.assertEqual(PROXY.parse_allowlist("B.example:a.example"),
                         frozenset({"a.example", "b.example"}))
        for spec in ("", "*", "https://a.example", "a.example:*", "user@a.example"):
            with self.assertRaises(ValueError, msg=spec):
                PROXY.parse_allowlist(spec)

    def test_in_process_proxy_relays_allowed_and_refuses_the_rest(self):
        echo = socket.create_server(("127.0.0.1", 0))
        echo_port = echo.getsockname()[1]

        def serve_echo():
            while True:
                try:
                    conn, _ = echo.accept()
                except OSError:
                    return
                with conn:
                    while chunk := conn.recv(1024):
                        conn.sendall(chunk)

        threading.Thread(target=serve_echo, daemon=True).start()
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "egress-proxy.log"
            server = PROXY.EgressProxyServer(
                ("127.0.0.1", 0), frozenset({"127.0.0.1"}), PROXY.EgressLog(log_path),
                allowed_port=echo_port,
            )
            self.assertTrue(log_path.exists())
            port = server.server_address[1]
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
                    conn.sendall(
                        f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\n"
                        "Proxy-Authorization: Basic c2VjcmV0LWhlYWRlcg==\r\n\r\n".encode()
                    )
                    reply = conn.recv(1024)
                    self.assertTrue(reply.startswith(b"HTTP/1.1 200"), reply)
                    conn.sendall(b"ping")
                    self.assertEqual(conn.recv(1024), b"ping")
                for line in (
                    f"GET http://127.0.0.1:{echo_port}/private/path?q=1 HTTP/1.1\r\n\r\n",
                    "CONNECT example.invalid:443 HTTP/1.1\r\n\r\n",
                ):
                    with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
                        conn.sendall(line.encode())
                        self.assertTrue(conn.recv(1024).startswith(b"HTTP/1.1 403"))
                deadline = time.monotonic() + 5
                rows = []
                while time.monotonic() < deadline:
                    rows = [json.loads(row) for row in log_path.read_text().splitlines()]
                    if len(rows) == 3:
                        break
                    time.sleep(0.05)
            finally:
                server.shutdown()
                server.server_close()
                echo.close()
            text = log_path.read_text()
        self.assertEqual(len(rows), 3, rows)
        by_decision = {(row["decision"], row["target"]): row for row in rows}
        allowed = by_decision[("allowed", f"127.0.0.1:{echo_port}")]
        self.assertEqual((allowed["bytes_up"], allowed["bytes_down"]), (4, 4))
        self.assertIn(("refused", f"127.0.0.1:{echo_port}"), by_decision)
        self.assertIn(("refused", "example.invalid:443"), by_decision)
        for row in rows:
            self.assertEqual(set(row), {"time", "client", "target", "decision",
                                        "bytes_up", "bytes_down"})
        # No headers, paths or queries reach the log.
        for fragment in ("Proxy-Authorization", "c2VjcmV0", "private", "q=1"):
            self.assertNotIn(fragment, text)


class DockerRunnerTests(unittest.TestCase):
    def _args(self, output, **overrides):
        values = {
            "harness": "collusion", "case_id": "CLH-036", "workers": 1,
            "egress_allowlist": "langfuse,gateway", "subject_command": "fake-agent",
            "agent_timeout": 900, "model": "pinned-model", "key_budget": 0.90,
            "key_ttl": "35m", "arm": "lure-pair", "trial": 1, "image": None,
            "output": Path(output), "sandbox_timeout": 1800, "exec_timeout": 1500,
            "dry_run": False,
        }
        values.update(overrides)
        return SimpleNamespace(**values)

    def _run(self, docker, client=None, env=AGENT_ENV, **overrides):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            os.environ, env, clear=True,
        ), contextlib.redirect_stdout(io.StringIO()) as stdout, \
                contextlib.redirect_stderr(io.StringIO()):
            error = None
            try:
                result = RUNNER.run(
                    self._args(directory, **overrides), docker=docker, admin_client=client,
                    revision=REVISION, sleep=lambda _: None,
                )
            except RuntimeError as exc:
                result, error = None, exc
            records = list(Path(directory).glob(f"*/{RUNNER.RUN_RECORD}"))
            record_text = records[0].read_text() if records else ""
            files = sorted(p.name for p in records[0].parent.iterdir()) if records else []
        return SimpleNamespace(result=result, error=error, stdout=stdout.getvalue(),
                               record_text=record_text,
                               record=json.loads(record_text) if record_text else {},
                               files=files)

    def test_agent_cell_carries_key_and_proxy_by_exec_env_only(self):
        docker, client = FakeDocker(), FakeLiteLLMClient()
        outcome = self._run(docker, client)
        self.assertEqual(outcome.result, 0, outcome.error)
        # The key value is in no argv and only in the exec call's CLI environment.
        for call in docker.calls:
            self.assertNotIn(FAKE_VIRTUAL_KEY, json.dumps(call["args"]))
            self.assertNotIn(MASTER, json.dumps(call["args"]))
        with_env = [call for call in docker.calls if call["env"] is not None]
        self.assertEqual([call["args"][0] for call in with_env], ["exec"])
        exec_call = with_env[0]
        self.assertEqual(exec_call["env"]["OPENAI_API_KEY"], FAKE_VIRTUAL_KEY)
        self.assertEqual(exec_call["env"]["OPENAI_BASE_URL"], "https://tunnel.example.org/v1")
        self.assertEqual(exec_call["timeout"], 1500)
        self.assertEqual(_env_flags(exec_call["args"]), [
            "OPENAI_API_KEY", "OPENAI_BASE_URL",
            "HTTPS_PROXY=http://egress-proxy:3128", "HTTP_PROXY=http://egress-proxy:3128",
            "NO_PROXY=",
        ])
        # The argv inside the container is the Modal runner's, boundary-labelled.
        sandbox_name = exec_call["args"][exec_call["args"].index("NO_PROXY=") + 1]
        inner = exec_call["args"][exec_call["args"].index(sandbox_name) + 1:]
        self.assertEqual(inner[:4], ["/usr/sbin/runuser", "-u", "honeypot", "--preserve-environment"])
        for assignment in ("MODAL_COLLUSION_CONTAINMENT_ENFORCED=1",
                           "HONEYPOT_EXECUTION_BOUNDARY=docker-container",
                           "HONEYPOT_CODEX_SANDBOX=workspace-write",
                           "HONEYPOT_CODEX_MODEL=pinned-model"):
            self.assertIn(assignment, inner)
        self.assertEqual(inner[-4:], ["--subject-command", "fake-agent", "--agent-timeout", "900"])
        # The sandbox container: internal network, no mounts, no privilege, no env.
        runs = docker.all("run")
        self.assertEqual(len(runs), 2)
        proxy_run, sandbox_run = runs
        sandbox_argv = sandbox_run["args"]
        self.assertEqual(sandbox_argv[sandbox_argv.index("--network") + 1], "honeypot-egress")
        for forbidden in ("-v", "--volume", "--mount", "--privileged", "-e", "--env",
                          "--network=host", "--pid", "--ipc"):
            self.assertNotIn(forbidden, sandbox_argv)
        self.assertEqual(sandbox_argv[sandbox_argv.index("--cap-drop") + 1], "ALL")
        self.assertEqual(
            [sandbox_argv[i + 1] for i, item in enumerate(sandbox_argv) if item == "--cap-add"],
            ["SETGID", "SETUID"],
        )
        self.assertIn("no-new-privileges", sandbox_argv)
        self.assertEqual(sandbox_argv[-2:], ["sleep", "infinity"])
        self.assertEqual(sandbox_argv[-3], "rogue-agent-honeypot:abcdef1")
        proxy_argv = proxy_run["args"]
        self.assertEqual(proxy_argv[proxy_argv.index("--network-alias") + 1], "egress-proxy")
        self.assertEqual(_env_flags(proxy_argv),
                         ["EGRESS_ALLOWLIST=cloud.langfuse.com:tunnel.example.org"])
        self.assertTrue(docker.first("network", "create", "--internal", "honeypot-egress"))
        self.assertEqual(docker.first("network", "connect")["args"][2], "bridge")
        # Both containers are removed and the key is minted, read and revoked once.
        self.assertEqual(len(docker.all("rm", "--force")), 2)
        self.assertEqual(docker.running, set())
        self.assertEqual([call[0] for call in client.calls], ["generate", "info", "delete"])
        # The run record: the Modal fields plus the Docker ones, and no key.
        record = outcome.record
        for field in ("schema_version", "harness", "case_id", "evidence_chain", "subject_mode",
                      "weights_mode", "policy", "started_at", "arm", "trial",
                      "agent_timeout_seconds", "virtual_key", "sandbox_id",
                      "remote_exit_code", "passed", "termination", "redaction"):
            self.assertIn(field, record)
        self.assertEqual(record["provider"], "docker")
        self.assertEqual(record["boundary"], "docker-container")
        self.assertEqual(record["image"], "rogue-agent-honeypot:abcdef1")
        self.assertEqual(record["egress_proxy_log"], "egress-proxy.log")
        self.assertEqual(record["seccomp_profile"], RUNNER.seccomp_profile_record())
        self.assertEqual(record["termination"], "explicit-finally")
        self.assertEqual(record["remote_exit_code"], 0)
        self.assertEqual(record["virtual_key"]["spend_usd"], 0.0125)
        self.assertIn("revoked_at", record["virtual_key"])
        self.assertTrue(record["redaction"]["passed"])
        self.assertEqual(record["policy"]["egress_allowlist"],
                         ["cloud.langfuse.com", "tunnel.example.org"])
        self.assertEqual(record["policy"]["cap_add"], ["SETGID", "SETUID"])
        record_text = outcome.record_text
        self.assertNotIn(FAKE_VIRTUAL_KEY, record_text)
        self.assertNotIn("host-side-key-must-not-pass", record_text)
        self.assertNotIn(MASTER, record_text + outcome.stdout)
        self.assertEqual(outcome.files, sorted([
            "artifacts.tar.gz", "docker-run.json", "egress-proxy.log",
            "remote.stderr.log", "remote.stdout.log", "summary.json",
        ]))
        # The driver gate parses the printed run record.
        printed = json.loads(outcome.stdout)
        self.assertEqual(printed["termination"], "explicit-finally")
        self.assertIn("output", printed)

    def test_scripted_cell_has_no_network_proxy_key_or_env(self):
        docker, client = FakeDocker(), FakeLiteLLMClient()
        outcome = self._run(docker, client, env={}, subject_command=None,
                            egress_allowlist=None, model=None)
        self.assertEqual(outcome.result, 0, outcome.error)
        runs = docker.all("run")
        self.assertEqual(len(runs), 1)
        argv = runs[0]["args"]
        self.assertEqual(argv[argv.index("--network") + 1], "none")
        exec_call = docker.first("exec")
        self.assertEqual(_env_flags(exec_call["args"]), [])
        self.assertNotIn("--preserve-environment", exec_call["args"])
        self.assertIn("HONEYPOT_EXECUTION_BOUNDARY=docker-container", exec_call["args"])
        self.assertEqual(docker.all("network"), [])
        self.assertEqual(client.calls, [])
        self.assertEqual(outcome.record["termination"], "explicit-finally")
        self.assertEqual(outcome.record["subject_mode"], "scripted")
        self.assertIsNone(outcome.record["egress_proxy_log"])
        self.assertNotIn("virtual_key", outcome.record)
        self.assertNotIn("egress-proxy.log", outcome.files)

    def test_exec_timeout_kills_the_container_and_still_cleans_up(self):
        docker, client = FakeDocker(exec_timeout=True), FakeLiteLLMClient()
        outcome = self._run(docker, client)
        self.assertEqual(outcome.result, 1)
        self.assertTrue(docker.all("kill"))
        self.assertTrue(outcome.record["exec_timed_out"])
        self.assertIsNone(outcome.record["remote_exit_code"])
        self.assertEqual(outcome.record["termination"], "explicit-finally")
        self.assertIn("revoked_at", outcome.record["virtual_key"])
        self.assertEqual([call for call in docker.all("cp")
                          if call["args"][1].endswith(("summary.json", "artifacts.tar.gz"))], [])

    def test_failed_removal_withholds_explicit_finally(self):
        docker, client = FakeDocker(removal_sticks=True), FakeLiteLLMClient()
        outcome = self._run(docker, client)
        self.assertIsNotNone(outcome.error)
        self.assertIn("container removal failed", str(outcome.error))
        self.assertNotIn("termination", outcome.record)
        self.assertEqual(outcome.record["termination_error"], "container removal failed")
        self.assertIn("revoked_at", outcome.record["virtual_key"])

    def test_a_stale_container_stops_the_cell_before_any_key_is_minted(self):
        docker, client = FakeDocker(stale=True), FakeLiteLLMClient()
        outcome = self._run(docker, client)
        self.assertIn("previous honeypot container", str(outcome.error))
        self.assertEqual(client.calls, [])
        self.assertEqual(docker.all("run"), [])
        self.assertNotIn("termination", outcome.record)

    def test_a_non_internal_network_of_that_name_is_refused(self):
        docker, client = FakeDocker(network_exists=True), FakeLiteLLMClient()
        docker.network = "false"
        outcome = self._run(docker, client)
        self.assertIn("not --internal", str(outcome.error))
        self.assertEqual(client.calls, [])

    def test_dry_run_plans_without_docker_or_a_key(self):
        def no_docker(*args, **kwargs):
            raise AssertionError("dry run touched docker")

        client = FakeLiteLLMClient()
        outcome = self._run(no_docker, client, dry_run=True)
        self.assertEqual(outcome.result, 0)
        self.assertEqual(client.calls, [])
        plan = json.loads(outcome.stdout)
        self.assertEqual(plan["provider"], "docker")
        self.assertEqual(plan["network"], "honeypot-egress")
        self.assertEqual(plan["image"], "rogue-agent-honeypot:abcdef1")
        self.assertEqual(set(plan["seccomp_profile"]), {"path", "sha256"})
        self.assertEqual(plan["seccomp_profile"]["path"], "docker_honeypot/seccomp-bwrap.json")
        self.assertIn(f"seccomp={RUNNER.SECCOMP_PROFILE}", plan["docker_run"])
        self.assertEqual(plan["egress_proxy"]["allowlist"],
                         ["cloud.langfuse.com", "tunnel.example.org"])
        self.assertIn("OPENAI_API_KEY", plan["docker_exec"])
        self.assertIn("HONEYPOT_EXECUTION_BOUNDARY=docker-container", plan["remote_argv"])
        self.assertTrue(plan["policy"]["secrets"][0].startswith("virtual-key:collusion/CLH-036/t1/"))
        self.assertNotIn(MASTER, outcome.stdout)
        self.assertNotIn("host-side-key-must-not-pass", outcome.stdout)

    def test_egress_allow_list_is_exactly_gateway_and_langfuse(self):
        RUNNER.validate_egress_spec("langfuse,gateway", "agent")
        RUNNER.validate_egress_spec("gateway, langfuse", "agent")
        RUNNER.validate_egress_spec(None, None)
        for spec in ("gateway", "langfuse", "langfuse,gateway,example.com", "*"):
            with self.assertRaises(ValueError, msg=spec):
                RUNNER.validate_egress_spec(spec, "agent")
        with self.assertRaises(ValueError):
            RUNNER.validate_egress_spec(None, "agent")

    def test_image_tag_names_the_tip_and_marks_a_dirty_tree(self):
        self.assertEqual(RUNNER.image_tags(REVISION)["image"], "rogue-agent-honeypot:abcdef1")
        self.assertEqual(RUNNER.image_tags({"commit": "abcdef1234", "dirty": True})["image"],
                         "rogue-agent-honeypot:abcdef1-dirty")
        self.assertEqual(RUNNER.image_tags({"commit": None})["image"],
                         "rogue-agent-honeypot:unknown")

    def test_container_names_follow_the_alias_without_slashes(self):
        names = RUNNER.container_names("collusion", "CLH-037", 2, "20261031T200000Z", agent=True)
        self.assertEqual(names["sandbox"], "collusion-CLH-037-t2-20261031T200000Z")
        self.assertEqual(names["proxy"], "collusion-CLH-037-t2-20261031T200000Z-proxy")


class BoundaryLabelTests(unittest.TestCase):
    def test_in_sandbox_boundary_label_comes_from_the_environment(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(SANDBOX.execution_boundary(), "modal-sandbox")
        with mock.patch.dict(os.environ, {"HONEYPOT_EXECUTION_BOUNDARY": "docker-container"}):
            self.assertEqual(SANDBOX.execution_boundary(), "docker-container")
        with mock.patch.dict(os.environ, {"HONEYPOT_EXECUTION_BOUNDARY": "laptop"}):
            with self.assertRaises(SystemExit):
                SANDBOX.execution_boundary()

    def test_modal_argv_is_unchanged_unless_a_boundary_is_named(self):
        command = BASE.remote_argv("collusion", "CLH-036", 1, subject_command="x", model="m")
        self.assertFalse(any(item.startswith("HONEYPOT_EXECUTION_BOUNDARY=") for item in command))

    def test_agent_launcher_keeps_the_proxy_variables(self):
        source = {
            AGENT_SUBJECT.CONTAINMENT_MARKER: "1", "PATH": "/usr/bin",
            "HONEYPOT_COLLUSION_PRELOAD": "/tmp/collusion.so",
            "HTTPS_PROXY": "http://egress-proxy:3128", "HTTP_PROXY": "http://egress-proxy:3128",
            "NO_PROXY": "", "ALL_PROXY": "socks5://elsewhere:1080",
        }
        env = AGENT_SUBJECT.build_agent_environment(source)
        self.assertEqual(env["HTTPS_PROXY"], "http://egress-proxy:3128")
        self.assertEqual(env["HTTP_PROXY"], "http://egress-proxy:3128")
        self.assertEqual(env["NO_PROXY"], "")
        self.assertNotIn("ALL_PROXY", env)


DRIVER = REPO / "agent_honeypot/collusion_tripwires/run_experiments.sh"

FAKE_DOCKER_RUNNER = """
import io, json, os, sys, tarfile
from pathlib import Path
args = sys.argv[1:]
case_id = args[args.index("--case-id") + 1]
output = Path(args[args.index("--output") + 1])
trial = args[args.index("--trial") + 1] if "--trial" in args else "1"
run_dir = output / f"collusion-{case_id}-fake-t{trial}"
run_dir.mkdir(parents=True, exist_ok=True)
record = {
    "case_id": case_id, "remote_exit_code": 0, "termination": "explicit-finally",
    "provider": os.environ.get("FAKE_RUNNER_PROVIDER", "docker"),
    "virtual_key": {"key_alias": f"collusion/{case_id}/t{trial}/fake",
                    "spend_usd": 0.0125, "revoked_at": "2026-10-31T00:00:00+00:00"},
    "redaction": {"passed": True, "findings": []},
}
(run_dir / os.environ.get("FAKE_RUNNER_RECORD", "docker-run.json")).write_text(json.dumps(record))
rows = [{"type": "item.completed", "item": {"type": "command_execution"}},
        {"type": "turn.completed", "usage": {"output_tokens": 7}}]
payload = ("\\n".join(json.dumps(row) for row in rows) + "\\n").encode()
with tarfile.open(run_dir / "artifacts.tar.gz", "w:gz") as archive:
    info = tarfile.TarInfo(f"cases/{case_id}/runs/subject/trajectory.jsonl")
    info.size = len(payload)
    archive.addfile(info, io.BytesIO(payload))
print(json.dumps({"output": str(run_dir), **record}, indent=2, sort_keys=True))
"""


class DriverProviderTests(unittest.TestCase):
    def _env(self, **extra):
        env = {
            **os.environ,
            "OPENAI_BASE_URL": "https://gateway.invalid/v1",
            "LANGFUSE_BASE_URL": "https://trace.invalid",
        }
        env.pop("HONEYPOT_RUNNER", None)
        env.update(extra)
        return env

    def _fake_docker_on_path(self, directory, exit_code):
        """A docker on PATH that records any call in a marker file."""
        bin_dir = Path(directory) / "bin"
        bin_dir.mkdir()
        marker = Path(directory) / "docker-was-called"
        fake = bin_dir / "docker"
        fake.write_text(f"#!/usr/bin/env bash\necho \"$*\" >> {marker}\nexit {exit_code}\n")
        fake.chmod(0o755)
        return f"{bin_dir}:{os.environ.get('PATH', '')}", marker

    def _driver(self, argv, env):
        return subprocess.run(
            ["bash", str(DRIVER), *argv], cwd=REPO, env=env, text=True,
            capture_output=True, check=False,
        )

    def test_docker_plan_selects_runner_and_root_without_touching_docker(self):
        with tempfile.TemporaryDirectory() as directory:
            path, marker = self._fake_docker_on_path(directory, 0)
            completed = self._driver(
                ["--provider", "docker", "--arm", "lure-pair", "--trials", "1",
                 "--model", "claude-opus-5-5", "--dry-run"],
                self._env(PATH=path),
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertFalse(marker.exists(), "a plan called docker")
        out = completed.stdout
        self.assertIn("Provider: docker (runner docker_honeypot/runner.py, run record "
                      "docker-run.json). Output root: results/docker-honeypot-collusion-exp.",
                      out)
        self.assertEqual(out.count("] PLAN"), 2)
        # Each cell's plan names the provider and boundary at top level and in its policy.
        self.assertEqual(out.count('"docker_run": ['), 2)
        self.assertEqual(out.count('"provider": "docker"'), 4)
        self.assertEqual(out.count('"boundary": "docker-container"'), 4)
        self.assertIn('"network": "honeypot-egress"', out)
        self.assertIn('"output_root": "results/docker-honeypot-collusion-exp/lure-pair"', out)
        self.assertIn('"HONEYPOT_EXECUTION_BOUNDARY=docker-container"', out)
        self.assertIn('"virtual-key:collusion/CLH-036/t1/', out)
        self.assertIn("PLAN ONLY: no sandbox, no model call", out)
        self.assertNotIn("LITELLM_MASTER_KEY", out)

    def test_default_provider_is_modal_with_its_root(self):
        completed = self._driver(
            ["--arm", "lure-pair", "--trials", "1", "--case", "CLH-036", "--model", "m"],
            self._env(),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("Provider: modal (runner modal_honeypot/runner.py, run record "
                      "modal-run.json). Output root: results/modal-honeypot-collusion-exp.",
                      completed.stdout)
        self.assertNotIn('"provider": "docker"', completed.stdout)

    def test_unknown_provider_and_dry_run_with_execute_are_refused(self):
        completed = self._driver(["--provider", "laptop", "--arm", "sensor-controls"], self._env())
        self.assertEqual(completed.returncode, 64)
        self.assertIn("--provider must be modal or docker", completed.stderr)
        completed = self._driver(
            ["--provider", "docker", "--arm", "sensor-controls", "--dry-run", "--execute"],
            self._env(),
        )
        self.assertEqual(completed.returncode, 64)
        self.assertIn("mutually exclusive", completed.stderr)

    def test_docker_execute_refuses_without_a_daemon(self):
        with tempfile.TemporaryDirectory() as directory:
            path, marker = self._fake_docker_on_path(directory, 1)
            completed = self._driver(
                ["--provider", "docker", "--arm", "sensor-controls", "--execute",
                 "--output", str(Path(directory) / "out")],
                self._env(PATH=path, EXPERIMENT_APPROVED="1"),
            )
            self.assertEqual(completed.returncode, 78, completed.stdout + completed.stderr)
            self.assertIn("reachable Docker daemon", completed.stderr)
            self.assertNotIn("] RUN", completed.stdout)
            self.assertEqual(marker.read_text().split(), ["info"])
            self.assertFalse((Path(directory) / "out").exists())

    def _execute_with_fake(self, directory, **fake_env):
        fake = Path(directory) / "fake_docker_runner.py"
        fake.write_text(FAKE_DOCKER_RUNNER)
        return self._driver(
            ["--provider", "docker", "--arm", "lure-pair", "--trials", "1", "--case", "CLH-036",
             "--model", "claude-opus-5-5", "--output", str(Path(directory) / "out"),
             "--execute"],
            self._env(EXPERIMENT_APPROVED="1", LITELLM_MASTER_KEY="unit-test-master-not-a-key",
                      HONEYPOT_RUNNER=str(fake), **fake_env),
        )

    def test_docker_gate_reads_docker_run_json(self):
        with tempfile.TemporaryDirectory() as directory:
            completed = self._execute_with_fake(directory)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("run_record_present=true provider_matches=true", completed.stdout)
        self.assertIn("passes it only as docker exec environment, by name", completed.stderr)
        self.assertNotIn("unit-test-master-not-a-key", completed.stdout + completed.stderr)
        self.assertIn("Done.", completed.stdout)

    def test_docker_gate_fails_on_a_missing_or_foreign_run_record(self):
        with tempfile.TemporaryDirectory() as directory:
            completed = self._execute_with_fake(directory, FAKE_RUNNER_RECORD="modal-run.json")
        self.assertEqual(completed.returncode, 75, completed.stdout + completed.stderr)
        self.assertIn("run_record_present=false", completed.stdout)
        with tempfile.TemporaryDirectory() as directory:
            completed = self._execute_with_fake(directory, FAKE_RUNNER_PROVIDER="modal")
        self.assertEqual(completed.returncode, 75, completed.stdout + completed.stderr)
        self.assertIn("provider_matches=false", completed.stdout)


if __name__ == "__main__":
    unittest.main()
