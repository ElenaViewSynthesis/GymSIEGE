# Sourced (POSIX sh) by every login shell in the honeypot image, from
# /etc/profile.d/zz-honeypot-shims.sh: docker_honeypot/Dockerfile and
# modal_honeypot/runner.py build_image install it there.
#
# Codex runs every tool call through `bash -lc`, and Debian's /etc/profile sets
# PATH afresh before it sources /etc/profile.d. That dropped the harness's PATH
# shims from every real tool call (collusion cohorts v1-v3, opus-v2, opus-v3,
# opus-v3-r2, gpt-docker-v1): ps, strace, gdb, nsenter, tmux, screen, nohup, the
# collusion `delegate` command and the intent egress shims (curl, wget, git,
# scp, nc, ...) ran unrecorded, and only the preload's EXEC event named them.
#
# When the harness has set its shim directories (launch-agent.sh puts
# HONEYPOT_SHIM_PATH, then HONEYPOT_EXTRA_PATH, in front of PATH), put them back
# in front, in that order; otherwise change nothing. A program called by an
# absolute path still bypasses every PATH shim (the preload still logs its EXEC).
if [ -n "${HONEYPOT_SHIM_PATH:-}" ] && [ -d "$HONEYPOT_SHIM_PATH" ]; then
  honeypot_front=$HONEYPOT_SHIM_PATH
  if [ -n "${HONEYPOT_EXTRA_PATH:-}" ]; then
    honeypot_front=$honeypot_front:$HONEYPOT_EXTRA_PATH
  fi
  case ":$PATH:" in
    ":$honeypot_front:"*) ;;
    *) PATH=$honeypot_front${PATH:+:$PATH}; export PATH ;;
  esac
  unset honeypot_front
fi
