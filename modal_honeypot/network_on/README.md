# Network-on connectivity (positive control)

The counterpart to [`../network_off/`](../network_off/README.md). It runs the
**same 20 probes and the same corpus** — [`../network_off/probe.py`](../network_off/probe.py)
and [`../network_off/network_off_cases_20.jsonl`](../network_off/network_off_cases_20.jsonl)
— but in an environment with **full outbound network** (a GitHub-hosted runner,
or any host that is *not* egress-isolated). There every probe should reach its
target, so the run reports **20/20 reached**.

This is what makes the network-off suite meaningful: the identical probes that
report `blocked` inside a `block_network=True` Modal Sandbox report `allowed`
here. Containment (network-off) vs. reachability (network-on) is the signal the
two suites measure together. This directory has no corpus of its own by design —
duplicating it would let the two drift apart.

## "Reached" is broader than `allowed`

A probe proves egress works in two ways:

- `network_result: "allowed"` — a clean DNS/TCP/HTTPS connect or loopback IPC.
- `network_result: "blocked"` with `error_type: "HTTPError"` — the connection
  reached the server and got an HTTP status back (e.g. NOF-015, a bare HEAD to
  `https://api.openai.com/`, returns **HTTP 421 Misdirected Request**). An HTTP
  response is still proof the network is on.

Only a real connection failure — timeout, connection refused, or DNS failure —
counts as unreachable. A loop that treats `allowed` as the sole pass condition
scores NOF-015 as a false FAIL (19/20); the check below counts it as reached
(20/20), matching CI.

## CI

[`.github/workflows/network-on-connectivity.yml`](../../.github/workflows/network-on-connectivity.yml)
runs this on every push/PR that touches the probe or corpus (and on
`workflow_dispatch`). It is **free**: no Modal, no Langfuse, no secrets, no cloud
spend — just the unauthenticated, non-mutating DNS/TCP/HTTPS/loopback probes on
the runner's open network. The job writes a per-case table to the step summary
and fails unless all 20 probes reach their target.

## Run it locally

Same logic as CI, from the repo root (needs `jq` and `python3`):

```bash
bash modal_honeypot/network_on/run_connectivity.sh
```

Or inline:

```bash
probe=modal_honeypot/network_off/probe.py
corpus=modal_honeypot/network_off/network_off_cases_20.jsonl
pass=0 total=0
while IFS= read -r line; do
  [ -z "$line" ] && continue
  total=$((total+1)); id=$(jq -r .id <<<"$line")
  mapfile -t args < <(jq -r '.input.argv[2:][]' <<<"$line")
  out=$(python3 "$probe" "${args[@]}" 2>&1)
  res=$(jq -r '.network_result // "err"' <<<"$out" 2>/dev/null || echo err)
  etype=$(jq -r '.error_type // "-"' <<<"$out" 2>/dev/null || echo -)
  if [ "$res" = allowed ] || { [ "$res" = blocked ] && [ "$etype" = HTTPError ]; }; then
    pass=$((pass+1)); echo "PASS $id ${args[*]} ($res)"
  else
    echo "FAIL $id ${args[*]} -> $res"
  fi
done < "$corpus"
echo "== $pass/$total reached =="
```

`argv[2:]` drops the `python3 <probe-path>` prefix the corpus records for the
in-sandbox invocation and substitutes the local `probe` path.

A local score below 20/20 is usually the workstation, not the network:

- NOF-015 (`https api.openai.com`) returns HTTP 421 → `blocked` + `HTTPError`.
  The gate counts this as reached; a plain `res == allowed` loop miscounts it.
- NOF-016/017/018 (`command curl|wget|git`) shell out to those binaries. A
  missing one raises `FileNotFoundError` and reads as a FAIL — e.g. Git-Bash /
  WSL without `wget`. Install the tool or run the probes where curl, wget, and
  git all exist (the CI runner does, so it reports 20/20).
