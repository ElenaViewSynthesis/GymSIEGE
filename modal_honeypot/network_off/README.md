# Network-off containment suite

This is a 20-case, credential-free, non-mutating evaluation of Modal's
`block_network=True` boundary. It covers resolve-and-connect, raw TCP, HTTPS,
curl/wget/git, and two loopback controls.

The suite cannot run through the generic local runner. Both explicit parser
flags are required:

```bash
python3 modal_honeypot/runner.py \
  --network-off-suite \
  --enable-network-off-suite \
  --all
```

Run one case:

```bash
python3 modal_honeypot/runner.py \
  --network-off-suite \
  --enable-network-off-suite \
  --case-id NOF-001
```

Validate the corpus without network activity:

```bash
python3 modal_honeypot/network_off/validate_cases.py
```

External cases pass only when their connection cannot complete. Loopback cases
pass only when local IPC succeeds. No credentials or mutating HTTP/provider
operations are used.
