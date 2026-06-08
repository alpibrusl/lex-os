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

echo "+ booting the JAILED box (uid=$JAIL_UID gid=$JAIL_GID) — watch for the guest console and '8.8.8.8 -> blocked'"
"$LEXOS" box-smoke --manifest demo/manifest.json --dwell "${DWELL:-12}" \
  --jail-uid "$JAIL_UID" --jail-gid "$JAIL_GID"
