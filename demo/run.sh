#!/usr/bin/env bash
# demo/run.sh — orchestration entrypoint for the lex-os one-continuous-run
# demo (issue #10). One terminal, narrating four scenes:
#
#   Scene 1: Wall 1 — type-check wall (Attempt 1)
#   Scene 2: results.demo.internal stub starts (the single allowed target)
#   Scene 3: lex-os run — the mediation loop
#               · agent does fs work as root in the box
#               · agent destroys its own box → supervisor reprovisions
#               · agent attempts a consequential delete → refused by class
#               · agent attempts to widen its grant → Wall 3 fires
#               · agent submits the report → allowed
#   Scene 4: audit verification + key event grep
#
# Requires a KVM host: this run boots a real Firecracker microVM for Wall 2
# (issue #14). Run demo/host-check.sh first; run as root.
#
# What this script does NOT do today (issues that gate the full demo):
#   · The agent is the hard-coded DemoAgent in crates/lex-os/src/demo.rs,
#     not an LLM (issue #8 replaces it). Wall 2's egress attempts come from
#     the guest's init-attack.sh, not yet from the agent itself.
#   · The naive Docker baseline pane (issue #9) is a separate command.

set -euo pipefail

# Resolve to the repo root regardless of where the script is invoked from.
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"

MANIFEST=demo/manifest.json
ATTACK_TYPECHECK=demo/attacks/01_typecheck_evil_host.lex
BENIGN_PROGRAM=examples/agent-programs/submit_report.lex
AUDIT_LOG=${AUDIT_LOG:-demo/audit.json}
STUB_PORT=${STUB_PORT:-8443}
STUB_PID=

# Building needs the toolchain (a per-user rustup), not root; the privileged
# work (KVM, tap, iptables) needs root. So when invoked under sudo, compile as
# the original user and run the prebuilt binaries as root.
CARGO=(cargo)
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
  CARGO=(sudo -u "$SUDO_USER" -H -- cargo)
fi
LEXOS="$REPO_ROOT/target/debug/lex-os"
STUB="$REPO_ROOT/target/debug/results-stub"

cleanup() {
  if [ -n "$STUB_PID" ] && kill -0 "$STUB_PID" 2>/dev/null; then
    kill "$STUB_PID" 2>/dev/null || true
    wait "$STUB_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

say() {
  printf "\n=== %s ===\n" "$*"
}

say "Pre-flight: host check"
if ! bash demo/host-check.sh; then
  echo "demo: host-check failed; this run boots a real microVM and needs KVM" >&2
  echo "      (run demo/setup-assets.sh first, and run as root on a KVM host)" >&2
  exit 1
fi

say "Pre-flight: build"
"${CARGO[@]}" build --quiet --features firecracker -p lex-os -p results-stub
if [ ! -x "$LEXOS" ] || [ ! -x "$STUB" ]; then
  echo "demo: build did not produce the binaries; build as your user first:" >&2
  echo "      cargo build --features firecracker -p lex-os -p results-stub" >&2
  exit 1
fi

say "Scene 1 — Wall 1: type-check"
echo "+ benign program against the demo grant — must pass"
"$LEXOS" check --grant "$MANIFEST" "$BENIGN_PROGRAM"
echo
echo "+ adversarial program (declares [net(\"evil.com\")]) — must be refused"
set +e
"$LEXOS" check --grant "$MANIFEST" "$ATTACK_TYPECHECK"
typecheck_exit=$?
set -e
if [ "$typecheck_exit" -ne 8 ]; then
  echo "demo: expected exit 8 (PreconditionFailed) on attack #1, got $typecheck_exit" >&2
  exit 1
fi
echo "+ exit code $typecheck_exit (PreconditionFailed) — wall held"

say "Scene 2 — results.demo.internal stub"
"$STUB" --listen "127.0.0.1:${STUB_PORT}" > demo/stub.log 2>&1 &
STUB_PID=$!
# Wait until the stub is actually accepting connections (no blind sleeps).
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if (echo > "/dev/tcp/127.0.0.1/${STUB_PORT}") 2>/dev/null; then
    break
  fi
  sleep 0.1
done
echo "+ results-stub listening on 127.0.0.1:${STUB_PORT} (pid=${STUB_PID}, log=demo/stub.log)"

say "Scene 3 — Walls 2 & 3 inside the run"
echo "+ Wall 2 (kernel egress) now fires for real: the supervisor boots a"
echo "  Firecracker microVM and the guest runs demo/init-attack.sh (installed"
echo "  as /sbin/init.demo). Its console output — allowed target OK, evil.com"
echo "  and 8.8.8.8 blocked at the host tap's iptables — is captured below."
echo "+ Wall 3 (grant narrowing) fires in the same mediation loop."
echo
"$LEXOS" run --manifest "$MANIFEST" --audit-out "$AUDIT_LOG"

say "Scene 4 — audit verification"
echo "+ hash chain"
"$LEXOS" audit verify --log "$AUDIT_LOG"
echo
echo "+ key events"
if command -v jq >/dev/null 2>&1; then
  jq -r '.[] | "\(.seq)\t\(.event.kind)\t\(.event.reason // .event.command // .event.outcome // "")"' "$AUDIT_LOG" \
    | grep -E "narrowing_blocked|command_denied|destroyed|liveness_failed|provisioned|session_ended" || true
else
  grep -oE '"kind":"[a-z_]+"' "$AUDIT_LOG" \
    | sort | uniq -c \
    | grep -E "narrowing_blocked|command_denied|destroyed|liveness_failed|provisioned|session_ended" || true
fi

say "Done"
echo "+ audit log: $AUDIT_LOG"
echo "+ stub log:  demo/stub.log"
echo "+ what's gated: a real LLM agent needs #8; the naive Docker baseline"
echo "  pane needs #9. Wall 2 (kernel egress) is live on this KVM host."
