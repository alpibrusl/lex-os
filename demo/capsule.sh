#!/usr/bin/env bash
# demo/capsule.sh — capability-addressed distribution end-to-end (lex-os#34).
#
# Unlike the other demos, this one needs no KVM, no root, no network: it runs
# entirely against the in-process *simulated* perimeter, so it works anywhere
# `cargo` does. It narrates one story:
#
#   A vendor "Acme" publishes the Lex package `pdf-extract`. A finance team
#   wants to use it but won't trust Acme's word about what it does. The capsule
#   binds Acme's DECLARED needs to the artifact, signed; the finance team's own
#   grant stays the ceiling.
#
# It shows the accepted install (least authority) and the three refusals:
#   (a) a compromised update that wants more than the team grants,
#   (b) a tampered contract whose signature no longer matches,
#   (c) a host that can't honor the artifact's egress need.
#
# Caveat (printed by every install): the simulated perimeter is NOT a security
# boundary. This demo proves the capability *logic*, not isolation.

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT INT TERM

say()  { printf "\n=== %s ===\n" "$*"; }
note() { printf "    %s\n" "$*"; }

# Build once, then drive the prebuilt binary (faster, quieter than cargo run).
cargo build --quiet -p lex-os
LEXOS="$REPO_ROOT/target/debug/lex-os"

# Pull a field out of an acli envelope's data/error (no jq dependency).
field() { python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('data',d.get('error',{})).get('$1',''))"; }

say "Publisher side (Acme) — one-time identity"
# A deterministic seed keeps the demo reproducible; real keys come from keygen
# with no --seed (an OS CSPRNG) and live in a key manager.
SEED=$(printf 'ac%.0s' {1..32})
"$LEXOS" --output json capsule keygen --seed "$SEED" > "$WORK/acme.keys.json"
ACME_SECRET=$("$LEXOS" --output json capsule keygen --seed "$SEED" | field secret_key)
ACME_PUBLIC=$(field public_key < "$WORK/acme.keys.json")
note "Acme public key: ${ACME_PUBLIC:0:16}…"

say "Publisher side — declare + sign what pdf-extract@2.0.0 needs"
note "Required grant (examples/capsule-requires.json): fs=read-only net=allowlist exec=none, egress=[api.acme-pdf.com]"
"$LEXOS" capsule sign \
  --artifact pdf-extract@2.0.0 \
  --content-hash "$(printf 'f1%.0s' {1..32})" \
  --requires examples/capsule-requires.json \
  --key "$ACME_SECRET" \
  --out "$WORK/pdf-extract.contract.json"
note "-> $WORK/pdf-extract.contract.json  (ships alongside the package)"

say "Consumer side (finance team) — verify the signature"
note "The team's policy (examples/capsule-consumer.json) is GENEROUS: read-WRITE fs, allowlist net, no exec."
verdict=$("$LEXOS" --output json capsule verify --contract "$WORK/pdf-extract.contract.json" | field verified)
note "signature verified: $verdict (signer ${ACME_PUBLIC:0:16}…)"

say "Consumer side — install against the team's policy (ACCEPT)"
"$LEXOS" --output json capsule install \
  --consumer examples/capsule-consumer.json \
  --contract "$WORK/pdf-extract.contract.json" 2>/dev/null > "$WORK/installed.json"
note "consumer grant : $(field consumer_grant  < "$WORK/installed.json")   (what the team WAS willing to allow)"
note "EFFECTIVE grant: $(field effective_grant < "$WORK/installed.json")   (what the box ACTUALLY runs at)"
note "effective egress: $(field effective_egress < "$WORK/installed.json")"
note "box alive: $(field box_alive < "$WORK/installed.json")  | security_boundary: $(field security_boundary < "$WORK/installed.json")"
note "^ least authority: the box runs read-only even though the team offered read-write."

say "Refusal (a) — compromised update wants EXEC + a new exfil host"
note "Signed with Acme's REAL key, so this is a legit-but-greedy update, not a forgery."
"$LEXOS" capsule sign \
  --artifact pdf-extract@2.1.0 \
  --content-hash "$(printf 'e1%.0s' {1..32})" \
  --requires examples/capsule-requires-compromised.json \
  --key "$ACME_SECRET" \
  --out "$WORK/evil.contract.json" > /dev/null
if "$LEXOS" --output json capsule install \
      --consumer examples/capsule-consumer.json \
      --contract "$WORK/evil.contract.json" 2>/dev/null > "$WORK/refused.json"; then
  echo "UNEXPECTED: compromised update was accepted" >&2; exit 1
fi
note "refused: $(field message < "$WORK/refused.json")"

say "Refusal (b) — tampering: edit the contract to look harmless after signing"
python3 - "$WORK/evil.contract.json" "$WORK/tampered.contract.json" <<'PY'
import json, sys
src, dst = sys.argv[1], sys.argv[2]
c = json.load(open(src))
c["contract"]["requires"]["exec"] = "None"          # hide the exec demand (valid enum)
c["contract"]["egress"] = ["api.acme-pdf.com"]      # drop the exfil host
json.dump(c, open(dst, "w"))
PY
if "$LEXOS" --output json capsule verify --contract "$WORK/tampered.contract.json" 2>/dev/null > "$WORK/tamper.json"; then
  echo "UNEXPECTED: tampered contract verified" >&2; exit 1
fi
note "rejected: $(field message < "$WORK/tamper.json")"
note "^ the signature covers the canonical contract bytes, so any edit breaks it."

say "Refusal (c) — offline host can't honor the artifact's egress need"
if "$LEXOS" --output json capsule install \
      --consumer examples/capsule-consumer.json \
      --contract "$WORK/pdf-extract.contract.json" \
      --offline 2>/dev/null > "$WORK/offline.json"; then
  echo "UNEXPECTED: install succeeded on an offline host" >&2; exit 1
fi
note "refused: $(field message < "$WORK/offline.json")"
note "^ refuse, don't downgrade — the same discipline as the resolver."

say "Done"
note "Accepted at least authority; refused on widening, tampering, and an unsatisfiable host."
