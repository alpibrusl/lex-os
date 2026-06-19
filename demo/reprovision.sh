#!/usr/bin/env bash
# Prove vsock re-attach across a reprovision (issue #27, Task 2) on real KVM.
#
# A deterministic, model-free agent runs INSIDE the Firecracker microVM:
#   1. reads a file (fs.read),
#   2. deliberately disposes its own box mid-task (Destroy),
#   3. the supervisor reprovisions a FRESH microVM and re-`accept()`s its vsock
#      channel to the new guest (the bit this demo exists to prove),
#   4. the rebuilt guest writes report.md and signals done -> GoalMet.
#
# Needs a KVM host + root. No Ollama / network: the in-guest script makes no
# egress, so this runs with zero external dependencies.
#
#   sudo bash demo/reprovision.sh
#
# Without the vsock re-attach (Transport::reconnect + Agent::on_reprovision),
# step 3 fails: the supervisor keeps the dead guest's stream, the agent gives
# up after a few transport errors, and the run ends without GoalMet.

set -euo pipefail
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"

MANIFEST="${1:-demo/manifest-reprovision.json}"
AUDIT_OUT="demo/reprovision-audit.json"

# Jail firecracker: drop to the invoking user's uid and the kvm group (so the
# chrooted, non-root VMM can still open /dev/kvm). Override via env if needed.
JAIL_UID="${JAIL_UID:-${SUDO_UID:-$(id -u)}}"
JAIL_GID="${JAIL_GID:-$(getent group kvm | cut -d: -f3)}"
[ -n "$JAIL_GID" ] || { echo "reprovision: no kvm group on this host; set JAIL_GID" >&2; exit 1; }

# Build as the invoking user (root has no rustup toolchain); run as root.
CARGO=(cargo)
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
  CARGO=(sudo -u "$SUDO_USER" -H -- cargo)
fi
LEXOS="$REPO_ROOT/target/debug/lex-os"

echo "+ host check"
bash demo/host-check.sh || { echo "reprovision: host-check failed (need KVM + root + assets)" >&2; exit 1; }

echo "+ build lex-os (firecracker is the default feature)"
"${CARGO[@]}" build --quiet -p lex-os
[ -x "$LEXOS" ] || { echo "reprovision: no lex-os binary" >&2; exit 1; }

echo "+ build + inject the in-VM agent binary into the rootfs"
bash demo/setup-assets.sh >/dev/null

echo "+ booting JAILED in-VM agent with the reprovision script (manifest=$MANIFEST, jail uid=$JAIL_UID gid=$JAIL_GID)"
# NB: don't capture the run's stdout — Firecracker's guest serial console is on
# inherited stdio and interleaves with the JSON envelope. Assert against the
# clean --audit-out file (written directly by lex-os) and `lex-os audit verify`.
"$LEXOS" run --agent guest --guest-script reprovision-demo \
  --jail-uid "$JAIL_UID" --jail-gid "$JAIL_GID" \
  --manifest "$MANIFEST" --audit-out "$AUDIT_OUT"

echo
echo "+ verifying the audit hash chain"
if "$LEXOS" audit verify --log "$AUDIT_OUT" >/dev/null 2>&1; then
  chain_ok=1; else chain_ok=0; fi

echo "+ asserting the run reprovisioned the box and still reached the goal"
CHAIN_OK="$chain_ok" python3 - "$AUDIT_OUT" <<'PY'
import json, os, sys
audit_path = sys.argv[1]

# The audit-out file is a clean JSON array of chained entries; each event is
# tagged {"kind": "...", ...}. Everything we assert is derived from it.
entries = json.load(open(audit_path))
def ev(e): return e.get("event", e)
def kind(e): return ev(e).get("kind")

provisioned        = [e for e in entries if kind(e) == "provisioned"]
reprovision_events = [e for e in provisioned if ev(e).get("reprovision") is True]
allowed            = [e for e in entries if kind(e) == "command_allowed"]
report_written     = any(ev(e).get("command") == "report.write" for e in allowed)
read_done          = any(ev(e).get("command") == "fs.read" for e in allowed)
goal_met           = any(kind(e) == "session_ended" and "goal_met" in str(ev(e).get("outcome", ""))
                         for e in entries)
chain_ok           = os.environ.get("CHAIN_OK") == "1"

ok = True
def check(name, cond, got):
    global ok
    if not cond: ok = False
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}: {got}")

check("audit hash chain verified", chain_ok, chain_ok)
check("session reached goal_met", goal_met, goal_met)
check("box was reprovisioned at least once", len(reprovision_events) >= 1,
      f"{len(reprovision_events)} reprovision event(s), {len(provisioned)} total provisions")
# The discriminating checks: without a working vsock re-attach the rebuilt guest
# never connects, so report.write never runs (a hollow give-up GoalMet would
# show fs.read only).
check("fs.read ran on the first box", read_done, read_done)
check("report.write ran AFTER the reprovision", report_written, report_written)
check("two commands allowed (fs.read + report.write)", len(allowed) >= 2, len(allowed))

print()
if ok:
    print("vsock re-attach PROVEN: the box was disposed mid-task, the supervisor")
    print("rebuilt it and reconnected to the fresh guest over vsock, and the agent")
    print("resumed real work (report.write) to GoalMet on the new box.")
    sys.exit(0)
else:
    print("vsock re-attach NOT proven — see failures above.")
    sys.exit(1)
PY
