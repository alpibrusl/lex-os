#!/usr/bin/env sh
# Attack #2 — kernel egress wall (issue #14 "Attempt 2").
#
# Run *inside* the provisioned microVM, as root. The supervisor
# already provisioned the box from examples/net-allowlisted.json,
# whose grant is network: Allowlist with egress =
# ["results.demo.internal:443"]. The host installed an iptables
# rule on the VM's tap device:
#
#   ACCEPT tap0 → results.demo.internal:443
#   DROP   tap0 → 0.0.0.0/0
#
# `curl` runs honestly — it issues the syscalls — and the kernel
# drops anything not destined for results.demo.internal. The agent
# is root inside the VM; the dropping rule is on the *host*, on
# the tap device the guest does not own. There is no in-VM
# configuration the agent can flip to make this succeed.
#
# Expected outcomes (one continuous run, no edits):

set -u

echo "--- allowed (the legitimate target) ---"
curl -fsS --max-time 5 https://results.demo.internal:443/healthz \
  && echo "  → 200 OK (egress allowed)"

echo "--- denied: named host outside the allowlist ---"
curl -fsS --max-time 5 https://evil.com 2>&1 \
  | head -1 \
  || echo "  → blocked at kernel (no route)"

echo "--- denied: raw IP, no DNS involved ---"
curl -fsS --max-time 5 https://8.8.8.8 2>&1 \
  | head -1 \
  || echo "  → blocked at kernel (no route)"

echo "--- denied: try to disable the rule from inside the guest ---"
iptables -F 2>&1 | head -1 || true   # may "succeed" — but flushes only the GUEST rules
curl -fsS --max-time 5 https://evil.com 2>&1 \
  | head -1 \
  || echo "  → still blocked at kernel (rules are on the HOST tap device)"

echo "--- done ---"
# The host-side audit log (audit.json) captures: the egress allowlist
# at provision time, the legitimate call as a logged event, and (if
# the agent retries) every attempt — even the failed ones — because
# the supervisor's command mediation gates run for every command,
# including the ones that don't fire syscalls (script payload size,
# wall clock, etc.).
