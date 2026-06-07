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

# Build as the invoking user (root has no rustup toolchain); run as root.
CARGO=(cargo)
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
  CARGO=(sudo -u "$SUDO_USER" -H -- cargo)
fi
LEXOS="$REPO_ROOT/target/debug/lex-os"

echo "+ host check"
bash demo/host-check.sh || { echo "reprovision: host-check failed (need KVM + root + assets)" >&2; exit 1; }

echo "+ build lex-os (--features firecracker)"
"${CARGO[@]}" build --quiet --features firecracker -p lex-os
[ -x "$LEXOS" ] || { echo "reprovision: no lex-os binary" >&2; exit 1; }

echo "+ build + inject the in-VM agent binary into the rootfs"
bash demo/setup-assets.sh >/dev/null

echo "+ booting in-VM agent with the deterministic reprovision script (manifest=$MANIFEST)"
"$LEXOS" run --agent guest --guest-script reprovision-demo \
  --manifest "$MANIFEST" --audit-out "$AUDIT_OUT" --output json | tee demo/reprovision-run.json

echo
echo "+ asserting the run reprovisioned the box and still reached the goal"
python3 - "$AUDIT_OUT" demo/reprovision-run.json <<'PY'
import json, sys
audit_path, run_path = sys.argv[1], sys.argv[2]
run = json.load(open(run_path))
data = run.get("data", run)

outcome = data.get("outcome", "")
reprovisions = data.get("reprovisions", 0)
verified = data.get("audit_verified", False)
commands_used = data.get("commands_used", 0)

# The audit-out file is a JSON array of chained entries; each event is tagged
# {"kind":"provisioned", ..., "reprovision": true|false}.
audit = json.load(open(audit_path))
entries = audit if isinstance(audit, list) else audit.get("entries", [])
def ev(e): return e.get("event", e)
provisioned = [e for e in entries if ev(e).get("kind") == "provisioned"]
reprovision_events = [e for e in provisioned if ev(e).get("reprovision") is True]
# report.write is the SECOND command and only happens on the rebuilt box. Its
# presence in the log is the proof the supervisor re-attached to the new guest
# over vsock and the agent resumed real work — not merely that it gave up.
report_written = any(
    ev(e).get("kind") == "command_allowed" and ev(e).get("command") == "report.write"
    for e in entries
)

ok = True
def check(name, cond, got):
    global ok
    mark = "PASS" if cond else "FAIL"
    if not cond: ok = False
    print(f"  [{mark}] {name}: {got}")

check("outcome == GoalMet", outcome == "GoalMet", outcome)
check("reprovisions >= 1", reprovisions >= 1, reprovisions)
check("audit chain verified", verified is True, verified)
check("audit has a reprovision Provisioned event", len(reprovision_events) >= 1,
      f"{len(reprovision_events)} reprovision event(s), {len(provisioned)} total provisions")
# These two are the discriminating checks: without a working vsock re-attach the
# rebuilt guest never connects, so report.write never runs and commands_used==1
# (the supervisor would otherwise read the agent's give-up as a hollow GoalMet).
check("report.write ran AFTER the reprovision", report_written, report_written)
check("commands_used >= 2 (fs.read + report.write)", commands_used >= 2, commands_used)

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
