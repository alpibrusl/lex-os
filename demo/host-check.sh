#!/usr/bin/env bash
# Print whether this host can run the lex-os Firecracker demo. Exits non-zero
# if any check fails so it slots into demo/run.sh's pre-flight.
#
# Run from the repo root: bash demo/host-check.sh

set -u

ok=0
fail=0

check() {
  local label=$1
  shift
  if "$@" >/dev/null 2>&1; then
    echo "  ✓ $label"
    ok=$((ok + 1))
  else
    echo "  ✗ $label"
    fail=$((fail + 1))
  fi
}

echo "+ host checks"
check "running as root"                       test "$(id -u)" -eq 0
check "/dev/kvm present"                       test -e /dev/kvm
check "x86_64 virtualization available"       sh -c 'grep -qE "vmx|svm" /proc/cpuinfo'
check "firecracker on PATH"                    command -v firecracker
check "ip (iproute2) on PATH"                  command -v ip
check "iptables on PATH"                       command -v iptables
check "guest kernel present"                   test -f demo/assets/vmlinux
check "guest rootfs present"                   test -f demo/assets/rootfs.ext4

echo "+ summary: $ok ok / $fail failed"
[ "$fail" -eq 0 ]
