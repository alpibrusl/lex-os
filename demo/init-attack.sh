#!/bin/sh
# /sbin/init.demo — runs inside the microVM as PID 1. Output goes to ttyS0,
# which Firecracker pipes to its own stdout (the supervisor captures it and
# folds it into the audit log). This script IS attack #2: it proves the
# kernel egress wall by trying to reach hosts outside the grant's allowlist.
#
# The wall is host-side iptables on the tap device (see
# crates/lex-os-perimeter/src/firecracker/net.rs). The agent is root in here
# and cannot reach those rules. At the end it powers the VM off so the
# supervisor sees the box die (issue #7 wires that to reprovision).

mount -t proc proc /proc 2>/dev/null
mount -t sysfs sys /sys 2>/dev/null
ip addr add 169.254.42.2/30 dev eth0 2>/dev/null || \
  ifconfig eth0 169.254.42.2 netmask 255.255.255.252 up 2>/dev/null
ip link set eth0 up 2>/dev/null
ip route add default via 169.254.42.1 2>/dev/null
# The allowlisted target is a hostname (results.demo.internal:443 in the
# grant). Map it to the host across the tap so curl-by-name matches the
# host-side iptables ACCEPT rule. The host must run the results-stub there.
grep -q results.demo.internal /etc/hosts 2>/dev/null || \
  echo "169.254.42.1 results.demo.internal" >> /etc/hosts

echo "[guest] uname: $(uname -a)"
echo "[guest] id: $(id)"

echo "--- allowed (the legitimate target) ---"
if wget -qT 5 -O - http://results.demo.internal:443/healthz 2>/dev/null; then
  echo " -> 200 OK (egress allowed)"
else
  echo " -> allowed target unreachable (results-stub not up, or rule missing)"
fi

echo "--- denied: named host outside the allowlist ---"
if wget -qT 5 -O - http://evil.com 2>/dev/null; then
  echo " -> UNEXPECTED: evil.com succeeded -- wall did NOT fire"
else
  echo " -> blocked (no route)"
fi

echo "--- denied: raw IP, no DNS involved ---"
if wget -qT 5 -O - http://8.8.8.8 2>/dev/null; then
  echo " -> UNEXPECTED: 8.8.8.8 succeeded -- wall did NOT fire"
else
  echo " -> blocked (no route)"
fi

echo "--- done ---"
poweroff -f
