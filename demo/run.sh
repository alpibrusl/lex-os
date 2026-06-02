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
# What this script does NOT do today (issues that gate the full demo):
#   · Wall 2 (Attempt 2 — kernel egress) needs the Firecracker backend
#     wired to a real KVM host (issue #14). The script prints the curls
#     that WOULD run inside the VM but does not actually exec them.
#   · The agent is the hard-coded DemoAgent in crates/lex-os/src/demo.rs,
#     not an LLM (issue #8 replaces it).
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

say "Pre-flight: build"
cargo build --quiet -p lex-os -p results-stub

say "Scene 1 — Wall 1: type-check"
echo "+ benign program against the demo grant — must pass"
cargo run --quiet -p lex-os -- check --grant "$MANIFEST" "$BENIGN_PROGRAM"
echo
echo "+ adversarial program (declares [net(\"evil.com\")]) — must be refused"
set +e
cargo run --quiet -p lex-os -- check --grant "$MANIFEST" "$ATTACK_TYPECHECK"
typecheck_exit=$?
set -e
if [ "$typecheck_exit" -ne 8 ]; then
  echo "demo: expected exit 8 (PreconditionFailed) on attack #1, got $typecheck_exit" >&2
  exit 1
fi
echo "+ exit code $typecheck_exit (PreconditionFailed) — wall held"

say "Scene 2 — results.demo.internal stub"
./target/debug/results-stub --listen "127.0.0.1:${STUB_PORT}" > demo/stub.log 2>&1 &
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
echo "+ Wall 2 (kernel egress) is gated on issue #14 (Firecracker on real KVM)."
echo "  Once #14 lands, the agent would exec the following inside the microVM:"
sed -n 's/^/    /; p' demo/attacks/02_curl_evil.sh | grep -E '^    (echo|curl)' | head -12
echo
echo "+ Running the mediation loop now (Wall 3 — narrowing — fires here):"
cargo run --quiet -p lex-os -- run --manifest "$MANIFEST" --audit-out "$AUDIT_LOG"

say "Scene 4 — audit verification"
echo "+ hash chain"
cargo run --quiet -p lex-os -- audit verify --log "$AUDIT_LOG"
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
echo "+ what's gated: Wall 2 needs issue #14 (KVM); a real LLM agent needs #8;"
echo "  the naive Docker baseline pane needs #9."
