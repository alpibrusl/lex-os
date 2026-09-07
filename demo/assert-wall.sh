#!/usr/bin/env bash
# Decide whether a wall2 run actually proved anything (#54).
#
#   bash demo/assert-wall.sh <run.log>
#
# `wall2.sh` used to exit 0 whenever the microVM booted and tore down.
# The guest's probes printed to the console and nothing read them, so the
# job went green while the box was reaching a host service the grant never
# allowlisted — which is exactly what happened, undetected, until someone
# looked at the output by eye (#79).
#
# A check that cannot fail for the reason it exists is worse than no
# check: it manufactures confidence. So the decision lives here, in one
# place, taking a log file — which means it can be tested against real
# captured output on a machine with no KVM, and the gate itself has a
# regression test.
set -uo pipefail

LOG=${1:?usage: assert-wall.sh <run.log>}
[ -f "$LOG" ] || { echo "assert-wall: no such log: $LOG" >&2; exit 2; }

fail() { echo "WALL ASSERTION FAILED: $*" >&2; exit 1; }

# 1. Nothing got through that should not have. The guest says so in one
#    word, and it is the word that was on screen the whole time #79 was
#    live.
if grep -q "UNEXPECTED" "$LOG"; then
  grep "UNEXPECTED" "$LOG" >&2
  fail "a probe reached something the grant does not allow"
fi

# 2. Every denial probe actually ran and was refused. Absence is not
#    success: a guest that never booted far enough to probe prints none
#    of these, and that must not read as three passes.
for probe in "host-local egress fenced" "blocked (no route)"; do
  grep -q "$probe" "$LOG" || fail "the probe reporting '$probe' did not run"
done

# 3. The wall discriminated, rather than dropping everything.
#
#    This is the half that was missing for the whole life of the demo.
#    All three denial probes pass just as well against a wall that
#    refuses every packet, so the denials alone prove nothing about the
#    allowlist. The kernel's own counters are the evidence: RETURN rules
#    carrying traffic mean something was permitted, DROP carrying traffic
#    means something was refused, and both must be true.
counters=$(sed -n '/LEX_OS_EGRESS/,/^$/p' "$LOG")
[ -n "$counters" ] || fail "the run printed no wall counters (is the wall installed?)"

returned=$(echo "$counters" | awk '$4 == "RETURN" { total += $2 } END { print total + 0 }')
dropped=$(echo "$counters" | awk '$4 == "DROP" { total += $2 } END { print total + 0 }')

[ "$dropped" -gt 0 ] || fail "the wall dropped nothing — it refused no packet at all"
[ "$returned" -gt 0 ] || fail \
  "the wall permitted nothing: every packet was dropped, so the denial probes above
   prove nothing about the allowlist. A wall that refuses everything passes them all."

echo "wall assertions passed: $returned packet(s) permitted, $dropped refused"
