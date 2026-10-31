# Agent image for the Docker execution boundary. It is the image that
# modal_honeypot/runner.py build_image(verify_secret_environment=True) builds,
# line for line: Debian with Python 3.12, the same apt tool set, the
# unprivileged user honeypot (uid 1000), /workspace owned by it, Node with the
# pinned Codex CLI, and the four repository directories under /opt/honeypot.
# No secrets: the virtual key and gateway URL reach a container only as
# `docker exec` environment at run time. Build context is the repository root;
# Dockerfile.dockerignore beside this file admits only the four directories.
FROM python:3.12-slim

ARG CODEX_VERSION=0.164.0

RUN apt-get update \
    && apt-get install --yes \
        gcc libc6-dev procps psmisc lsof gdb lldb \
        strace util-linux tmux screen at curl wget \
        git rsync zip gzip zstd ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 1000 --shell /bin/bash honeypot \
    && mkdir -p /workspace && chown honeypot:honeypot /workspace

RUN apt-get update \
    && apt-get install --yes nodejs npm \
    && rm -rf /var/lib/apt/lists/*

RUN npm install --global "@openai/codex@${CODEX_VERSION}" \
    && codex --version | grep -Fx "codex-cli ${CODEX_VERSION}" \
    && env MODAL_SECRET_ENV_PROBE=preserved /usr/sbin/runuser -u honeypot \
        --preserve-environment -- \
        sh -c 'test "$MODAL_SECRET_ENV_PROBE" = preserved'

COPY agent_honeypot/ /opt/honeypot/agent_honeypot/
COPY model_replication_honeypot/ /opt/honeypot/model_replication_honeypot/
COPY modal_honeypot/ /opt/honeypot/modal_honeypot/
COPY tests/ /opt/honeypot/tests/

WORKDIR /workspace
CMD ["sleep", "infinity"]
