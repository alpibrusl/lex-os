#!/usr/bin/env bash
# Boot the REAL in-VM exec path: lex-os-guest runs INSIDE the Firecracker
# microVM in its one-shot `exec` script mode (no LLM, no Ollama), the host
# supervisor mediates `proc.exec` over vsock exactly like `run --agent guest`
# mediates any other command, and — only once that's Allowed — the guest
# actually runs the command locally, inside the box, and reports the real
# output back. Needs a KVM host + root.
#
#   sudo bash demo/exec-in-vm.sh
#   sudo bash demo/exec-in-vm.sh -- echo "hello from inside the microVM"
#
# demo/manifest-exec.json grants exec: Sandboxed, so the command actually
# runs. Point at a exec: None manifest to see the denial-before-run path
# instead (the guest still boots, mediates, and reports the denial without
# ever spawning the command):
#
#   sudo bash demo/exec-in-vm.sh demo/manifest-agent-none.json -- echo nope

set -euo pipefail
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"

MANIFEST="demo/manifest-exec.json"
if [ "${1:-}" != "" ] && [ "${1:-}" != "--" ]; then
  MANIFEST="$1"
  shift
fi
if [ "${1:-}" = "--" ]; then
  shift
fi
COMMAND=("$@")
if [ ${#COMMAND[@]} -eq 0 ]; then
  COMMAND=(echo "hello from inside the microVM")
fi

# Jail firecracker: drop to the invoking user's uid and the kvm group so the
# chrooted, non-root VMM can still open /dev/kvm. Override via env if needed.
JAIL_UID="${JAIL_UID:-${SUDO_UID:-$(id -u)}}"
JAIL_GID="${JAIL_GID:-$(getent group kvm | cut -d: -f3)}"
[ -n "$JAIL_GID" ] || { echo "exec-in-vm: no kvm group on this host; set JAIL_GID" >&2; exit 1; }

# Build as the invoking user (root has no rustup toolchain); run as root.
CARGO=(cargo)
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
  CARGO=(sudo -u "$SUDO_USER" -H -- cargo)
fi
LEXOS="$REPO_ROOT/target/debug/lex-os"

echo "+ host check"
bash demo/host-check.sh || { echo "exec-in-vm: host-check failed (need KVM + root + assets)" >&2; exit 1; }

echo "+ build lex-os (firecracker is the default feature)"
"${CARGO[@]}" build --quiet -p lex-os
[ -x "$LEXOS" ] || { echo "exec-in-vm: no lex-os binary" >&2; exit 1; }

echo "+ build + inject the in-VM guest binary into the rootfs"
bash demo/setup-assets.sh >/dev/null

echo "+ booting JAILED in-VM exec (manifest=$MANIFEST jail uid=$JAIL_UID gid=$JAIL_GID) -- ${COMMAND[*]}"
"$LEXOS" --output json exec --manifest "$MANIFEST" \
  --jail-uid "$JAIL_UID" --jail-gid "$JAIL_GID" \
  --audit-out demo/exec-in-vm-audit.json \
  -- "${COMMAND[@]}"
