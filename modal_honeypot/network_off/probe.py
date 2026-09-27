#!/usr/bin/env python3
"""Small non-mutating network probes used only inside a network-off Sandbox."""

from __future__ import annotations

import argparse
import http.server
import json
import socket
import subprocess
import threading
import urllib.request


TIMEOUT = 3.0


def tcp(host: str, port: int) -> dict[str, object]:
    with socket.create_connection((host, port), timeout=TIMEOUT):
        return {"connected": True, "target": f"{host}:{port}"}


def resolve_connect(host: str, port: int) -> dict[str, object]:
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    address = addresses[0][4][0]
    result = tcp(address, port)
    return {**result, "resolved_host": host, "resolved_address": address}


def https(url: str) -> dict[str, object]:
    request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "network-off-canary/1"})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return {"connected": True, "target": url, "status": response.status}


def command(name: str) -> dict[str, object]:
    commands = {
        "curl": ["curl", "--fail", "--silent", "--show-error", "--connect-timeout", "3", "--max-time", "4", "https://example.com/"],
        "wget": ["wget", "--quiet", "--timeout=3", "--tries=1", "--spider", "https://example.com/"],
        "git": ["git", "-c", "http.lowSpeedLimit=1", "-c", "http.lowSpeedTime=3", "ls-remote", "https://github.com/octocat/Hello-World.git", "HEAD"],
    }
    completed = subprocess.run(commands[name], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=6)
    if completed.returncode != 0:
        raise OSError(f"{name} failed with exit {completed.returncode}: {completed.stderr[-300:]}")
    return {"connected": True, "target": name, "exit_code": completed.returncode}


def loopback_tcp() -> dict[str, object]:
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    accepted: list[bool] = []

    def accept_once() -> None:
        connection, _ = server.accept()
        accepted.append(connection.recv(1) == b"x")
        connection.close()

    thread = threading.Thread(target=accept_once, daemon=True)
    thread.start()
    with socket.create_connection(("127.0.0.1", port), timeout=TIMEOUT) as client:
        client.sendall(b"x")
    thread.join(TIMEOUT)
    server.close()
    if accepted != [True]:
        raise OSError("loopback TCP control failed")
    return {"connected": True, "target": f"127.0.0.1:{port}"}


def loopback_http() -> dict[str, object]:
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_HEAD(self) -> None:
            self.send_response(204)
            self.end_headers()

        def log_message(self, *_args) -> None:
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method="HEAD"), timeout=TIMEOUT) as response:
            if response.status != 204:
                raise OSError(f"unexpected loopback status {response.status}")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(TIMEOUT)
    return {"connected": True, "target": url, "status": 204}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("kind", choices=["tcp", "resolve-connect", "https", "command", "loopback-tcp", "loopback-http"])
    parser.add_argument("target", nargs="?")
    parser.add_argument("port", nargs="?", type=int)
    args = parser.parse_args()
    try:
        if args.kind == "tcp":
            result = tcp(str(args.target), int(args.port))
        elif args.kind == "resolve-connect":
            result = resolve_connect(str(args.target), int(args.port))
        elif args.kind == "https":
            result = https(str(args.target))
        elif args.kind == "command":
            result = command(str(args.target))
        elif args.kind == "loopback-tcp":
            result = loopback_tcp()
        else:
            result = loopback_http()
    except Exception as exc:
        print(json.dumps({"network_result": "blocked", "error_type": type(exc).__name__, "detail": str(exc)[:500]}, sort_keys=True))
        return 10
    print(json.dumps({"network_result": "allowed", **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
