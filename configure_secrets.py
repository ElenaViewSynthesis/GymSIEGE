#!/usr/bin/env python3
"""Copy a developer-local provider key into Daytona's organization vault.

The value is read from .env.local/process environment and is never printed.
Existing secrets are reused unless --replace is explicitly supplied.
"""

from __future__ import annotations

import argparse
import asyncio
import os

from daytona import AsyncDaytona, CreateSecretParams, UpdateSecretParams
from huggingface_hub import get_token

import common


HUGGINGFACE_SECRET_HOSTS = [
    # Exact FQDNs from Hugging Face's current download/firewall guidance.
    # Daytona Secret hosts are a value-substitution trust boundary, not an
    # outbound network allowlist, so keep this explicit rather than using a
    # broad wildcard.
    "huggingface.co",
    "cas-server.xethub.hf.co",
    "cas-server.xethub-eu.hf.co",
    "transfer.xethub.hf.co",
    "transfer.xethub-eu.hf.co",
    "us.aws.cdn.hf.co",
    "us.gcp.cdn.hf.co",
    "cdn-lfs-us-1.hf.co",
    "cdn-lfs-eu-1.hf.co",
]


PROVIDERS = {
    "huggingface": (
        "HF_TOKEN",
        "GYMSIEGE_HF_SECRET_NAME",
        HUGGINGFACE_SECRET_HOSTS,
    ),
    "openai": ("OPENAI_API_KEY", "GYMSIEGE_OPENAI_SECRET_NAME", ["api.openai.com"]),
    "litellm": (
        "LITELLM_MASTER_KEY",
        "GYMSIEGE_LITELLM_SECRET_NAME",
        [],
    ),
}


def credential_value(provider: str, key_env: str) -> str:
    """Resolve a provider credential without ever logging its value."""

    value = os.environ.get(key_env)
    if not value and provider == "huggingface":
        value = get_token()
    if not value:
        raise RuntimeError(
            f"{key_env} is not set. Add it to .env.local or, for Hugging Face, "
            "run `huggingface-cli login` from this WSL distribution."
        )
    return value


async def configure(provider: str, replace: bool) -> None:
    common.require_env("DAYTONA_API_KEY")
    key_env, name_env, hosts = PROVIDERS[provider]
    value = credential_value(provider, key_env)
    name = common.require_env(name_env)

    async with AsyncDaytona() as daytona:
        page = await asyncio.wait_for(
            daytona.secret.list(name=name, limit=200),
            timeout=180,
        )
        exact = next((item for item in page.items if item.name == name), None)
        if exact is None:
            await asyncio.wait_for(
                daytona.secret.create(
                    CreateSecretParams(
                        name=name,
                        value=value,
                        description=f"GYMSIEGE {provider} provider credential",
                        hosts=hosts,
                    )
                ),
                timeout=180,
            )
            print(f"Created Daytona organization secret: {name}")
        elif replace:
            await asyncio.wait_for(
                daytona.secret.update(
                    exact.id,
                    UpdateSecretParams(value=value, hosts=hosts),
                ),
                timeout=180,
            )
            print(f"Updated Daytona organization secret: {name}")
        else:
            print(f"Reusing existing Daytona organization secret: {name}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("provider", choices=sorted(PROVIDERS))
    parser.add_argument(
        "--replace",
        action="store_true",
        help="replace an existing secret value with the local key",
    )
    args = parser.parse_args()
    asyncio.run(configure(args.provider, args.replace))


if __name__ == "__main__":
    main()
