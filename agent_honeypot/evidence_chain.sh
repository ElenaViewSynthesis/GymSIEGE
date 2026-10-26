# shellcheck shell=bash
# Sourced by the harnesses. Starts and finishes one parent-owned evidence
# chain (see evidence_chain.py). The mirror is a process substitution, whose
# descriptor exec'd children inherit; bash closes every descriptor that
# derives from a coproc pipe or a {var} redirection in exec'd children, so
# neither can carry the pipe. The write end sits on a fixed, numbered
# descriptor, one per harness, so that nested harnesses never overwrite each
# other's pipe: 7 = process events (agent_honeypot), 8 = replication events,
# 9 = intent sink. The key never leaves the mirror: it verifies the visible
# log itself when the run ends and writes the verdict to the evidence file.

evidence_chain_py=${BASH_SOURCE[0]%.sh}.py

# evidence_chain_start VISIBLE_LOG FD_NUMBER EVIDENCE_JSON
#   Sets EVIDENCE_FD (= FD_NUMBER, the write end every writer inherits),
#   EVIDENCE_PID, EVIDENCE_MIRROR, EVIDENCE_JSON.
evidence_chain_start() {
  local visible=$1
  EVIDENCE_FD=$2
  EVIDENCE_JSON=$3
  EVIDENCE_MIRROR=${visible%.tsv}.mirror.tsv
  rm -f -- "$EVIDENCE_MIRROR" "$EVIDENCE_JSON"
  eval "exec ${EVIDENCE_FD}> >(python3 $(printf %q "$evidence_chain_py") mirror \
    --visible $(printf %q "$visible") --mirror $(printf %q "$EVIDENCE_MIRROR") \
    --evidence $(printf %q "$EVIDENCE_JSON"))"
  EVIDENCE_PID=$!
}

# evidence_chain_finish
#   Closes this shell's write end and lets the mirror drain. An orphaned agent
#   process can hold the pipe open, so after a grace period SIGUSR1 tells the
#   mirror to finalize with what it has. Returns once the evidence file exists.
evidence_chain_finish() {
  local i
  eval "exec ${EVIDENCE_FD}>&-"
  for i in {1..50}; do
    [[ -s $EVIDENCE_JSON ]] && break
    kill -0 "$EVIDENCE_PID" 2>/dev/null || break
    sleep 0.1
  done
  if [[ ! -s $EVIDENCE_JSON ]] && kill -0 "$EVIDENCE_PID" 2>/dev/null; then
    kill -USR1 "$EVIDENCE_PID" 2>/dev/null || true
  fi
  for i in {1..150}; do
    [[ -s $EVIDENCE_JSON ]] && break
    sleep 0.1
  done
  wait "$EVIDENCE_PID" 2>/dev/null || true
  if [[ ! -s $EVIDENCE_JSON ]]; then
    printf '{"schema_version": "1.0", "valid": false, "chain_valid": false, "mirror_matches_visible": false, "errors": ["mirror produced no evidence file"]}\n' >"$EVIDENCE_JSON"
  fi
  unset EVIDENCE_FD EVIDENCE_PID
}
