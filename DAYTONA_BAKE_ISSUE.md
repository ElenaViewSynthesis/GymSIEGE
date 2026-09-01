# Daytona support prompt: nested-container egress and snapshot capture

We are baking the public ExploitGym defensive-security benchmark into a
Daytona snapshot using the async Python SDK (`daytona==0.207.0`). The outer
Daytona sandbox is Debian 13. It can use HTTPS normally, install Debian
packages, clone Git repositories, and pull Docker images. Docker-in-Docker
also starts successfully after installing both `docker.io` and the Debian 13
`docker-cli` package.

The failure boundary is nested-container package traffic. An Alpine setup
container can be pulled and started, but `apk add` over HTTPS fails with a TLS
error. Passing `--network host` and mounting the outer sandbox CA bundle do
not fix it. Switching APK repositories to HTTP is not a workaround because
the target explicitly denies HTTP with 403. This prevents ExploitGym's
upstream setup scripts from downloading build dependencies inside their
nested Alpine containers.

Our current userspace-only workaround avoids nested package downloads:

- build static `socat` and OpenBSD `nc` in the outer Debian sandbox;
- install the official glibc Node distribution in the outer sandbox;
- run ExploitGym's upstream agent installer with `--codex --skip-node-build`;
- let `setup_data.sh` skip artifacts that are already present;
- pull only the ten pinned `exp.hardened` userspace challenge images;
- keep kernel and V8 tasks behind explicit custom-snapshot modes.

The bootstrap now completes far enough to stop the source sandbox for
snapshot capture, but `sandbox.create_snapshot("gymsiege-exploitgym",
timeout=3600)` can remain pending for an extended period. While it is pending,
additional read-only SDK calls may also take a long time to return.

Please clarify the supported Daytona pattern for this workload:

1. Is outbound HTTPS from Docker containers nested inside a Daytona sandbox
   supported? If so, how should the Daytona egress proxy, DNS, and CA
   certificate be propagated into the nested Docker daemon and its bridge
   containers?
2. Is there a documented DinD networking configuration that permits HTTPS
   package retrieval while retaining Daytona's outer network controls?
3. Does snapshot capture include Docker image layers under `/var/lib/docker`,
   and are there snapshot size, inode, or duration limits relevant to ten
   large C/C++ hardened images?
4. What source-sandbox state and snapshot-list transition should clients
   expect while `create_snapshot` is running, and how should a client
   distinguish slow capture from a stuck operation?
5. Is there a control-plane status/event endpoint for monitoring snapshot
   progress without launching another sandbox or issuing overlapping bake
   requests?

The required outcome is a repeatable snapshot containing userspace toolchain
artifacts and the ten Docker image layers. Agent execution remains isolated by
ExploitGym's two-network firewall, and Daytona egress is blocked after the
evaluator returns.
