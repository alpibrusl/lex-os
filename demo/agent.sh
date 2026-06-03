#!/usr/bin/env bash
# Boot the REAL in-VM agent (issue #16): lex-os-guest runs INSIDE the Firecracker
# microVM, reasons via Ollama over the one allowlisted egress target, and the
# host supervisor mediates every action over vsock. Needs a KVM host + root.
#
#   sudo bash demo/agent.sh
#   sudo OLLAMA=192.168.1.165:11434 MODEL=qwen3-coder:30b bash demo/agent.sh
#
# NOTE: until the guest-NAT piece lands, the agent cannot actually reach Ollama
# from inside the VM — this run proves the vsock channel (guest boots → connects
# → supervisor drives the loop); the agent will error on the model call and
# signal done. That's the expected intermediate result.

set -euo pipefail
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"

OLLAMA="${OLLAMA:-192.168.1.165:11434}"
MODEL="${MODEL:-devstral-small-2:latest}"
# manifest-agent.json: net=allowlist (agent may call the net). manifest-agent-none.json:
# net=none → the agent's net.fetch is DENIED, showing all walls fire (it can still
# reach its model, which is the kernel egress allowlist, not the grant level).
MANIFEST="${MANIFEST:-demo/manifest-agent.json}"

# Build as the invoking user (root has no rustup toolchain); run as root.
CARGO=(cargo)
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
  CARGO=(sudo -u "$SUDO_USER" -H -- cargo)
fi
LEXOS="$REPO_ROOT/target/debug/lex-os"

echo "+ host check"
bash demo/host-check.sh || { echo "agent: host-check failed (need KVM + root + assets)" >&2; exit 1; }

echo "+ build lex-os (--features firecracker)"
"${CARGO[@]}" build --quiet --features firecracker -p lex-os
[ -x "$LEXOS" ] || { echo "agent: no lex-os binary" >&2; exit 1; }

echo "+ build + inject the in-VM agent binary into the rootfs"
bash demo/setup-assets.sh >/dev/null

echo "+ booting in-VM agent (manifest=$MANIFEST ollama=$OLLAMA model=$MODEL)"
# The manifest's egress allowlists the Ollama host as the box's ONE egress target.
# If you override OLLAMA, update the manifest's egress to match.
"$LEXOS" run --agent guest --manifest "$MANIFEST" \
  --ollama-url "http://$OLLAMA" --model "$MODEL" --audit-out demo/agent-audit.json
