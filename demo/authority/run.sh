#!/usr/bin/env bash
# The authority-review demo in three acts. Nothing here needs KVM, a
# network, or a running box: every verdict is static.
#
#   bash demo/authority/run.sh
set -uo pipefail
cd "$(dirname "$0")/../.."

LEXOS=${LEXOS:-cargo run --quiet -p lex-os --}
HERE=demo/authority
rule() { printf '\n\033[1m%s\033[0m\n%s\n' "$1" "$(printf '─%.0s' $(seq 1 ${#1}))"; }
step() { printf '\n\033[2m$ %s\033[0m\n' "$*"; "$@"; printf '\033[2m→ exit %s\033[0m\n' "$?"; }

rule "Act 0 — what the code needs, derived from its own types"
step $LEXOS authority derive $HERE/v1_approved.lex

rule "Act 1 — the approved version passes, and the manifest's over-grant is named"
step $LEXOS authority gate --grant $HERE/manifest.json $HERE/v1_approved.lex

rule "Act 2 — the agent 'improves' the job"
# Comments stripped: both files carry a long header explaining themselves
# to a reader of this demo, and that prose is not the change.
code() { grep -v -e '^#' -e '^$' "$1"; }
code $HERE/v1_approved.lex > /tmp/lex-os-v1.code
code $HERE/v2_agent_improved.lex > /tmp/lex-os-v2.code
printf '\n\033[2m$ diff -u v1_approved.lex v2_agent_improved.lex   (comments stripped)\033[0m\n'
diff -u --label v1_approved.lex --label v2_agent_improved.lex /tmp/lex-os-v1.code /tmp/lex-os-v2.code
printf '\n\033[2mNothing above is malicious, and nothing above is a type error.\033[0m\n'
step $LEXOS authority diff --base $HERE/v1_approved.lex --head $HERE/v2_agent_improved.lex --fail-on widening
printf '\n\033[2mExit 8 is the CI gate. And the box itself refuses it:\033[0m\n'
step $LEXOS authority gate --grant $HERE/manifest.json $HERE/v2_agent_improved.lex

rule "Act 3 — the fix removes the network entirely, and the box loses it too"
step $LEXOS authority diff --base $HERE/v1_approved.lex --head $HERE/v3_narrowed.lex
step $LEXOS authority narrow --grant $HERE/manifest.json $HERE/v3_narrowed.lex --out /tmp/lex-os-narrowed.json
printf '\n\033[2mThe narrowed manifest is the one the perimeter is derived from.\nThe old code no longer fits the box it used to run in:\033[0m\n'
step $LEXOS authority gate --grant /tmp/lex-os-narrowed.json $HERE/v1_approved.lex

rule "The baseline"
printf 'The same change, in Python behind a container sandbox:\n\n'
bash $HERE/baseline/compare.sh

rule "Self-check"
# So the runbook cannot quietly stop being true: the three headline
# verdicts are asserted here, and CI runs this script on every PR.
# (`crates/lex-os-authority/tests/demo_acts.rs` asserts the same three
# against the same files at the library level.)
fail=0
check() { # description, expected-exit, command...
  local what=$1 want=$2; shift 2
  "$@" >/dev/null 2>&1; local got=$?
  if [ "$got" != "$want" ]; then
    printf '  ✗ %s (expected exit %s, got %s)\n' "$what" "$want" "$got"; fail=1
  else
    printf '  ✓ %s\n' "$what"
  fi
}
check "v1 fits the box it was approved for"        0 $LEXOS authority gate --grant $HERE/manifest.json $HERE/v1_approved.lex
check "v2 is refused before it runs"               8 $LEXOS authority gate --grant $HERE/manifest.json $HERE/v2_agent_improved.lex
check "the v1→v2 delta fails the CI gate"          8 $LEXOS authority diff --base $HERE/v1_approved.lex --head $HERE/v2_agent_improved.lex --fail-on widening
check "the v1→v3 delta does not"                   0 $LEXOS authority diff --base $HERE/v1_approved.lex --head $HERE/v3_narrowed.lex --fail-on widening
check "v1 no longer fits the narrowed box"         8 $LEXOS authority gate --grant /tmp/lex-os-narrowed.json $HERE/v1_approved.lex
exit $fail
