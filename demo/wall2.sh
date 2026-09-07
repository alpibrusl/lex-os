#!/usr/bin/env bash
# Standalone Wall-2 proof (issue #14). Boots a real Firecracker microVM with
# the host-side egress wall and lets the guest's /sbin/init.demo run to
# completion so you can watch the kernel egress wall fire:
#
#   --- denied: raw IP, no DNS involved ---
#    -> blocked (no route)        <-- 8.8.8.8 dropped at the host tap
#
# Unlike demo/run.sh (whose in-process agent tears the box down in
# milliseconds), this dwells long enough for the guest to boot and probe.
# Needs a KVM host and root.
#
#   sudo bash demo/wall2.sh            # default 12s dwell
#   sudo DWELL=20 bash demo/wall2.sh   # longer dwell

set -euo pipefail
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"

# Build as the invoking user (root has no rustup toolchain); run as root.
CARGO=(cargo)
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
  CARGO=(sudo -u "$SUDO_USER" -H -- cargo)
fi
LEXOS="$REPO_ROOT/target/debug/lex-os"

# Jail firecracker: drop to the invoking user's uid and the kvm group so the
# chrooted, non-root VMM can still open /dev/kvm. Override via env if needed.
JAIL_UID="${JAIL_UID:-${SUDO_UID:-$(id -u)}}"
JAIL_GID="${JAIL_GID:-$(getent group kvm | cut -d: -f3)}"
[ -n "$JAIL_GID" ] || { echo "wall2: no kvm group on this host; set JAIL_GID" >&2; exit 1; }

echo "+ host check"
bash demo/host-check.sh || { echo "wall2: host-check failed (need KVM + root + assets)" >&2; exit 1; }

echo "+ build"
"${CARGO[@]}" build --quiet -p lex-os
[ -x "$LEXOS" ] || { echo "wall2: build produced no binary" >&2; exit 1; }

# Capture the wall's own packet counters while the box is alive (#79).
#
# The guest-side probes report what `curl` made of each target, which
# conflates three different things: the wall dropped it, the service was
# not running, or the service answered in a way curl disliked. That
# ambiguity is precisely how #79 hid — every run showed "allowed target
# unreachable" and nobody could tell a missing ACCEPT from a missing
# stub.
#
# The counters cannot be ambiguous. They are the kernel's own tally of
# what this wall permitted and refused, and a wall that passes the denial
# probes by dropping *everything* is visible here as a zero on the RETURN
# rules.
WALL_COUNTS=/tmp/lex-os-wall-counters.$$
(
  for _ in $(seq 1 120); do
    iptables -t mangle -S LEX_OS_EGRESS >/dev/null 2>&1 && break
    sleep 0.25
  done
  sleep "$(( ${DWELL:-12} * 3 / 4 ))"
  {
    echo "--- the egress wall, counted by the kernel (mangle/PREROUTING) ---"
    iptables -t mangle -L LEX_OS_EGRESS -v -n --line-numbers 2>&1
    echo "--- entered from (must be position 1, -i tap) ---"
    iptables -t mangle -L PREROUTING -v -n --line-numbers 2>&1 | sed -n '1,4p'
  } > "$WALL_COUNTS" 2>&1
) &
COUNTER_PID=$!

echo "+ booting the JAILED box (uid=$JAIL_UID gid=$JAIL_GID) — watch for the guest console and '8.8.8.8 -> blocked'"
"$LEXOS" box-smoke --manifest demo/manifest.json --dwell "${DWELL:-12}" \
  --jail-uid "$JAIL_UID" --jail-gid "$JAIL_GID"

wait "$COUNTER_PID" 2>/dev/null || true
if [ -s "$WALL_COUNTS" ]; then
  echo
  cat "$WALL_COUNTS"
  echo
  echo "Read it as: RETURN rules with packets = the allowlist let something through;"
  echo "DROP with packets = the wall refused something. Both non-zero is the proof —"
  echo "all-DROP would pass every denial probe while permitting nothing."
fi
rm -f "$WALL_COUNTS"
