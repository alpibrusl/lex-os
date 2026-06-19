#!/usr/bin/env bash
# Prove the egress wall's ALLOWED leg works AND that host-local egress is fenced
# purely by the grant (issue #27, Task 4). On a KVM host, jailed:
#
#   1. The grant's one allowlisted target (the tap-gateway results-stub at
#      169.254.42.1:443) is REACHABLE from inside the box — and only because the
#      grant lists it (the perimeter installs the matching INPUT ACCEPT).
#   2. A second host-local service on :8080 that the grant does NOT list is
#      DROPPED at the host tap, even though it is listening — closing the hole
#      where a box could reach arbitrary services on its host.
#   3. External hosts (evil.com, 8.8.8.8) are dropped as before.
#
#   sudo bash demo/egress.sh
#
# No model/Ollama needed: the in-guest init (init-attack.sh) just runs curl.

set -euo pipefail
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"

MANIFEST="demo/manifest-egress.json"
CONSOLE_LOG="demo/egress-console.log"
DWELL="${DWELL:-20}"

# Jail firecracker (Task 1): drop to the invoking user's uid and the kvm group.
JAIL_UID="${JAIL_UID:-${SUDO_UID:-$(id -u)}}"
JAIL_GID="${JAIL_GID:-$(getent group kvm | cut -d: -f3)}"
[ -n "$JAIL_GID" ] || { echo "egress: no kvm group on this host; set JAIL_GID" >&2; exit 1; }

CARGO=(cargo)
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
  CARGO=(sudo -u "$SUDO_USER" -H -- cargo)
fi
LEXOS="$REPO_ROOT/target/debug/lex-os"
STUB="$REPO_ROOT/target/debug/results-stub"

echo "+ host check"
bash demo/host-check.sh || { echo "egress: host-check failed (need KVM + root + assets)" >&2; exit 1; }

echo "+ build lex-os + results-stub (firecracker is the default feature)"
"${CARGO[@]}" build --quiet -p lex-os -p results-stub
[ -x "$LEXOS" ] && [ -x "$STUB" ] || { echo "egress: missing binaries" >&2; exit 1; }

echo "+ inject the guest init/probe into the rootfs"
bash demo/setup-assets.sh >/dev/null

# Two host-local services on 0.0.0.0 (reachable at the tap gateway once it's up):
#   :443  is in the grant (allowed)   :8080 is NOT (must be fenced).
echo "+ starting results-stub on :443 (allowlisted) and :8080 (NOT allowlisted)"
"$STUB" --listen 0.0.0.0:443  >demo/egress-stub-443.log  2>&1 &  STUB_OK=$!
"$STUB" --listen 0.0.0.0:8080 >demo/egress-stub-8080.log 2>&1 &  STUB_NO=$!
cleanup() { kill "$STUB_OK" "$STUB_NO" 2>/dev/null || true; }
trap cleanup EXIT

echo "+ booting JAILED box (uid=$JAIL_UID gid=$JAIL_GID, dwell=${DWELL}s); console -> $CONSOLE_LOG"
"$LEXOS" box-smoke --manifest "$MANIFEST" --dwell "$DWELL" \
  --jail-uid "$JAIL_UID" --jail-gid "$JAIL_GID" 2>&1 | tee "$CONSOLE_LOG"

cleanup; trap - EXIT

echo
echo "+ asserting the grant-driven egress wall (allowed leg + host-local fence)"
ok=1
check() { # name, condition(0/1), detail
  if [ "$2" = "1" ]; then echo "  [PASS] $1: $3"; else echo "  [FAIL] $1: $3"; ok=0; fi
}
grep -q "200 OK (egress allowed)"        "$CONSOLE_LOG" && a=1 || a=0
grep -q "blocked (host-local egress fenced)" "$CONSOLE_LOG" && h=1 || h=0
n_blocked=$(grep -c "blocked (no route)"  "$CONSOLE_LOG" || true)
grep -q "UNEXPECTED"                      "$CONSOLE_LOG" && bad=1 || bad=0

check "allowlisted host-local target reachable (INPUT ACCEPT from the grant)" "$a" "200 OK"
check "non-allowlisted host-local service blocked (INPUT catch-all DROP)" "$h" "blocked"
check "external hosts blocked (FORWARD DROP)" "$([ "${n_blocked:-0}" -ge 2 ] && echo 1 || echo 0)" "${n_blocked:-0} 'no route' (expect >=2: evil.com + 8.8.8.8)"
check "no wall bypassed" "$([ "$bad" = "0" ] && echo 1 || echo 0)" "no UNEXPECTED lines"

echo
if [ "$ok" = "1" ]; then
  echo "egress wall PROVEN purely from the grant: the box reaches ONLY the one"
  echo "allowlisted target; every other destination — external or host-local —"
  echo "is dropped at the host tap."
else
  echo "egress wall assertions FAILED — see above and $CONSOLE_LOG"; exit 1
fi
