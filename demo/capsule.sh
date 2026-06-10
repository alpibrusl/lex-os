#!/usr/bin/env bash
# demo/capsule.sh — capability-addressed distribution end-to-end (lex-os#34).
#
# Needs no KVM, no root, no network: it runs entirely against the in-process
# *simulated* perimeter, so it works anywhere `cargo` does. It narrates one
# story:
#
#   A vendor "Acme" publishes the Lex package `pdf-extract`. A finance team
#   wants to use it but won't trust Acme's word about what it does. The capsule
#   binds Acme's DECLARED needs to the artifact, signed; the finance team's own
#   grant stays the ceiling.
#
# It shows the accepted install at least authority — with the publisher pinned
# and the archive bytes verified — and five refusals:
#   (a) a compromised update that wants more than the team grants,
#   (b) a tampered contract whose signature no longer matches,
#   (c) a host that can't honor the artifact's egress need,
#   (d) a substituted archive whose bytes don't match the contract,
#   (e) a real but untrusted publisher.
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

cargo build --quiet -p lex-os
LEXOS="$REPO_ROOT/target/debug/lex-os"

# Pull a field out of an acli envelope's data/error (no jq dependency).
field() { python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('data',d.get('error',{})).get('$1',''))"; }
pub_of() { "$LEXOS" --output json capsule keygen --seed "$1" | field public_key; }
secret_of() { "$LEXOS" --output json capsule keygen --seed "$1" | field secret_key; }

# The "published archive" — real bytes, so its hash is real.
printf 'pdf-extract 2.0.0 — the genuine published archive\n' > "$WORK/pdf-extract-2.0.0.tar"

say "Publisher identities"
ACME_SEED=$(printf 'ac%.0s' {1..32});  ACME_SECRET=$(secret_of "$ACME_SEED");  ACME_PUBLIC=$(pub_of "$ACME_SEED")
ROGUE_SEED=$(printf 'b0%.0s' {1..32}); ROGUE_SECRET=$(secret_of "$ROGUE_SEED"); ROGUE_PUBLIC=$(pub_of "$ROGUE_SEED")
note "Acme  public key: ${ACME_PUBLIC:0:16}…"
note "Rogue public key: ${ROGUE_PUBLIC:0:16}…"

# The finance team's keyring: it trusts ONLY Acme.
printf '{"trusted":["%s"]}\n' "$ACME_PUBLIC" > "$WORK/keyring.json"
note "Finance team keyring trusts: Acme only"

say "Publisher side — sign pdf-extract@2.0.0 (hash computed from the real archive)"
"$LEXOS" capsule sign \
  --artifact pdf-extract@2.0.0 \
  --artifact-file "$WORK/pdf-extract-2.0.0.tar" \
  --requires examples/capsule-requires.json \
  --key "$ACME_SECRET" \
  --out "$WORK/pdf-extract.contract.json"
note "-> contract bound to the archive's SHA-256 and signed by Acme"

say "Consumer side — install (ACCEPT: publisher pinned, bytes verified, least authority)"
"$LEXOS" --output json capsule install \
  --consumer examples/capsule-consumer.json \
  --contract "$WORK/pdf-extract.contract.json" \
  --artifact "$WORK/pdf-extract-2.0.0.tar" \
  --trusted-keys "$WORK/keyring.json" \
  --audit-out "$WORK/install.audit.json" 2>/dev/null > "$WORK/installed.json"
note "consumer grant : $(field consumer_grant  < "$WORK/installed.json")   (what the team WAS willing to allow)"
note "EFFECTIVE grant: $(field effective_grant < "$WORK/installed.json")   (what the box ACTUALLY runs at)"
note "effective egress: $(field effective_egress < "$WORK/installed.json")"
note "bytes verified: $(field artifact_bytes_verified < "$WORK/installed.json")  | signer trust checked: $(field signer_trust_checked < "$WORK/installed.json")"
note "box alive: $(field box_alive < "$WORK/installed.json")  | security_boundary: $(field security_boundary < "$WORK/installed.json")"

say "Consumer side — the decision is recorded in a tamper-evident audit log"
"$LEXOS" audit render --log "$WORK/install.audit.json" | python3 -c '
import sys, json
for line in sys.stdin:
    e = json.loads(line)["event"]
    print("    -", e["kind"])'
verified=$("$LEXOS" --output json audit verify --log "$WORK/install.audit.json" | field verified)
note "hash chain verifies: $verified  (an agent editing this log breaks the chain)"

say "Consumer side — run a workload under the effective grant (--run)"
note "The effective grant (fs=read-only) now governs a live session: reads and the"
note "allowlisted fetch are allowed, but a write is denied — at runtime, mid-session."
"$LEXOS" --output json capsule install \
  --consumer examples/capsule-consumer.json \
  --contract "$WORK/pdf-extract.contract.json" \
  --artifact "$WORK/pdf-extract-2.0.0.tar" \
  --trusted-keys "$WORK/keyring.json" \
  --audit-out "$WORK/run.audit.json" --run 2>/dev/null > "$WORK/ran.json"
note "outcome: $(field outcome < "$WORK/ran.json")  | commands run: $(field commands_used < "$WORK/ran.json")  | one chain of $(field audit_entries < "$WORK/ran.json") entries, verified: $(field audit_verified < "$WORK/ran.json")"
"$LEXOS" audit render --log "$WORK/run.audit.json" | python3 -c '
import sys, json
for line in sys.stdin:
    e = json.loads(line)["event"]
    detail = e.get("command") or e.get("outcome") or ""
    denied = " (DENIED)" if e["kind"] == "command_denied" else ""
    print("    -", e["kind"], ("· " + detail) if detail else "", denied)'

refuse() { # <label> <file-with-error-envelope>
  note "refused: $(field message < "$2")"
}

say "Refusal (a) — compromised update wants EXEC + a new exfil host"
printf 'pdf-extract 2.1.0 — compromised build\n' > "$WORK/pdf-extract-2.1.0.tar"
"$LEXOS" capsule sign --artifact pdf-extract@2.1.0 \
  --artifact-file "$WORK/pdf-extract-2.1.0.tar" \
  --requires examples/capsule-requires-compromised.json \
  --key "$ACME_SECRET" --out "$WORK/evil.contract.json" > /dev/null
if "$LEXOS" --output json capsule install --consumer examples/capsule-consumer.json \
      --contract "$WORK/evil.contract.json" --artifact "$WORK/pdf-extract-2.1.0.tar" \
      --trusted-keys "$WORK/keyring.json" 2>/dev/null > "$WORK/a.json"; then
  echo "UNEXPECTED: compromised update accepted" >&2; exit 1; fi
refuse a "$WORK/a.json"
note "^ trusted publisher, genuine bytes — still refused at the narrowing gate."

say "Refusal (b) — tampering: edit the contract after signing"
python3 - "$WORK/evil.contract.json" "$WORK/tampered.contract.json" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
c["contract"]["requires"]["exec"] = "None"          # hide the exec demand
json.dump(c, open(sys.argv[2], "w"))
PY
if "$LEXOS" --output json capsule verify --contract "$WORK/tampered.contract.json" 2>/dev/null > "$WORK/b.json"; then
  echo "UNEXPECTED: tampered contract verified" >&2; exit 1; fi
refuse b "$WORK/b.json"

say "Refusal (c) — offline host can't honor the artifact's egress need"
if "$LEXOS" --output json capsule install --consumer examples/capsule-consumer.json \
      --contract "$WORK/pdf-extract.contract.json" --artifact "$WORK/pdf-extract-2.0.0.tar" \
      --trusted-keys "$WORK/keyring.json" --offline 2>/dev/null > "$WORK/c.json"; then
  echo "UNEXPECTED: install succeeded offline" >&2; exit 1; fi
refuse c "$WORK/c.json"

say "Refusal (d) — substituted archive: bytes don't match the signed contract"
printf 'malware masquerading as pdf-extract 2.0.0\n' > "$WORK/swapped.tar"
if "$LEXOS" --output json capsule install --consumer examples/capsule-consumer.json \
      --contract "$WORK/pdf-extract.contract.json" --artifact "$WORK/swapped.tar" \
      --trusted-keys "$WORK/keyring.json" 2>/dev/null > "$WORK/d.json"; then
  echo "UNEXPECTED: substituted archive accepted" >&2; exit 1; fi
refuse d "$WORK/d.json"

say "Refusal (e) — a real but UNTRUSTED publisher (rogue signs a reasonable contract)"
"$LEXOS" capsule sign --artifact pdf-extract@2.0.0 \
  --artifact-file "$WORK/pdf-extract-2.0.0.tar" \
  --requires examples/capsule-requires.json \
  --key "$ROGUE_SECRET" --out "$WORK/rogue.contract.json" > /dev/null
if "$LEXOS" --output json capsule install --consumer examples/capsule-consumer.json \
      --contract "$WORK/rogue.contract.json" --artifact "$WORK/pdf-extract-2.0.0.tar" \
      --trusted-keys "$WORK/keyring.json" 2>/dev/null > "$WORK/e.json"; then
  echo "UNEXPECTED: untrusted signer accepted" >&2; exit 1; fi
refuse e "$WORK/e.json"
note "^ a valid signature from a key the team never pinned — refused as untrusted."

say "Done"
note "Accepted at least authority (publisher pinned, bytes verified);"
note "refused on widening, tampering, an unsatisfiable host, byte substitution, and an untrusted signer."
