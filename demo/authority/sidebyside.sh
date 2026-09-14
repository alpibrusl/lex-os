#!/usr/bin/env bash
# The same change, reviewed two ways, in two columns.
#
# Every line in both columns is real output captured from this run.
# Nothing is typed in. The left column needs a built lex-os (LEXOS=...),
# the right needs deno on PATH (`npm i deno`); if either is missing the
# script says so rather than faking that side.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
LEXOS=${LEXOS:-cargo run --quiet -p lex-os --}
# The beats below run from the demo directory so the transcript shows
# relative paths; resolve a relative LEXOS against the caller's cwd first
# or it would break the moment we cd.
case "$LEXOS" in
  /*|cargo*) ;;
  *) LEXOS="$(cd "$(dirname "$LEXOS")" && pwd)/$(basename "$LEXOS")" ;;
esac
DENO_DIR="$HERE/baseline/deno"
COLS="python3 $HERE/_columns.py"

B=$'\033[1m'; D=$'\033[2m'; R=$'\033[0m'; Y=$'\033[33m'
strip() { sed -E 's/\x1b\[[0-9;]*[A-Za-z]//g'; }
rule()  { printf '%s' "$(printf '─%.0s' $(seq 1 66))"; }

heads() { printf '  %b%-66s%b    %b%s%b\n' "$B" "$1" "$R" "$B" "$2" "$R"
          printf '  %b%s%b    %b%s%b\n' "$D" "$(rule)" "$R" "$D" "$(rule)" "$R"; }
beat()  { printf '\n%b━━ %s%b\n\n' "$B" "$1" "$R"; }

L=$(mktemp); Rr=$(mktemp); trap 'rm -f "$L" "$Rr"' EXIT

command -v deno >/dev/null 2>&1 || {
  echo "  deno is not on PATH — the right column cannot be produced." >&2
  echo "  Install it with \`npm i deno\` and re-run." >&2; exit 2; }

cat <<'TXT'

  The same change, reviewed two ways
  ══════════════════════════════════

  An agent is asked to make an approved nightly report more useful. It
  adds run telemetry: read a vendor token, POST the report. A dozen
  lines, nothing malicious, and nothing that fails to type-check on
  either side.
TXT

# ── 1 ────────────────────────────────────────────────────────────────
beat "1. the change — the same change, in both languages"
diff -u "$HERE/v1_approved.lex" "$HERE/v2_agent_improved.lex" \
  | grep -E '^\+' | grep -vE '^\+\+\+|^\+#|^\+$' | sed 's/^+//' | head -11 | strip > "$L"
diff -u "$DENO_DIR/v1_report.ts" "$DENO_DIR/v2_report.ts" \
  | grep -E '^\+' | grep -vE '^\+\+\+|^\+//|^\+$' | sed 's/^+//' | head -11 | strip > "$Rr"
heads "v2_agent_improved.lex" "v2_report.ts"
$COLS "$L" "$Rr"

# ── 2 ────────────────────────────────────────────────────────────────
beat "2. at review time — before anything is merged"
( cd "$HERE"
  echo "\$ lex-os authority diff --base v1_approved.lex \\"
  echo "      --head v2_agent_improved.lex --fail-on widening"; echo
  $LEXOS authority diff --base v1_approved.lex \
      --head v2_agent_improved.lex --fail-on widening 2>&1
  echo "exit=$?" ) | strip > "$L"
( cd "$DENO_DIR"
  echo "\$ deno check v2_report.ts"; echo
  deno check v2_report.ts 2>&1; echo "exit=$?"; echo
  echo "\$ deno <subcommand that reports required permissions>"; echo
  echo "no such subcommand exists. Permissions are supplied to a"
  echo "run, never derived from a program; there is nothing to ask."; echo
  echo "\$ git diff v1..v2 -- launch.sh"; echo
  echo "no change. There is one launcher, it grants"
  echo "--allow-net=results.demo.internal, and nothing about v2"
  echo "made it move." ) | strip > "$Rr"
heads "authority is a reviewable artifact" "there is nothing to review"
$COLS "$L" "$Rr"

# ── 3 ────────────────────────────────────────────────────────────────
beat "3. at run time"
( cd "$HERE"
  echo "\$ lex-os authority gate --grant manifest.json \\"
  echo "      v2_agent_improved.lex"; echo
  # just the refusal; `gate` also reports the manifest's over-grant,
  # which is act 3's subject and would cut off mid-sentence here.
  $LEXOS authority gate --grant manifest.json v2_agent_improved.lex 2>&1 \
    | sed '/over-grant/,$d'
  echo "exit=8" ) | strip > "$L"
( cd "$DENO_DIR"
  echo "\$ deno run --allow-net=results.demo.internal \\"
  echo "      drive_v2_uncaught.ts"; echo
  deno run --allow-net=results.demo.internal drive_v2_uncaught.ts 2>&1 \
    | grep -vE '^\s*at |^$' | head -5
  echo "exit=1" ) | strip > "$Rr"
heads "refused before it runs" "refused when it got there"
$COLS "$L" "$Rr"

cat <<TXT

  ${B}Both refuse.${R} The difference is ${B}when${R}, and ${B}what the refusal is about${R}.

  Deno's wall is real and it held. But it landed on the environment
  read — that is simply what the code reached first. Permit the
  variable and it slides down to the fetch. The wall sits wherever
  execution happens to arrive, in the order it arrives, and is never a
  statement about the program. Put ${Y}pushTelemetry${R} behind a feature flag,
  an error path, or a nightly branch, and neither refusal fires today:
  the deploy looks clean and the authority question is still open. Wrap
  it in the try/catch that telemetry calls usually have, and the
  refusal is swallowed entirely.

  The left column answered it before the merge, named the host that
  caused it, and exited 8 in CI — over every path through the program,
  including the ones that will not run until Tuesday.

TXT
