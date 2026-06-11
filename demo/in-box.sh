#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Real in-box execution: free inside the box, sealed at the edge.
#
# `capsule install --run` does not stage a workload from the package's DECLARED
# effects — it INTERPRETS the entrypoint (lex-bytecode) and routes every effect
# the code actually performs through the supervisor's mediation gate, in order.
# A consequential effect that exceeds the box's authority is sealed mid-run, and
# the program sees the refusal — exactly as a real sandbox fails a syscall.
#
# Two runs of the *same* code show that the grant (here, the budget ceiling) is
# the whole story:
#   A. enough budget  → both effects run, mediated, in order      (goal_met)
#   B. zero net budget → the fs read runs, the net call is SEALED  (halted)
#
# Run:  bash demo/in-box.sh   (no KVM, root, or network — simulated perimeter)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LEXOS="$REPO_ROOT/target/debug/lex-os"
[ -x "$LEXOS" ] || { echo "build first: cargo build -p lex-os"; exit 1; }
command -v python3 >/dev/null || { echo "this demo needs python3 (for JSON readout)"; exit 1; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
say()  { printf '\n\033[1;36m=== %s\033[0m\n' "$*"; }
note() { printf '    %s\n' "$*"; }
field(){ python3 -c "import sys,json;print(json.load(sys.stdin)['data'].get('$1'))"; }

# ── A package whose entrypoint reads a file, then fetches a URL ───────────────
mkdir -p "$WORK/pkg/src"
printf '[package]\nname = "weather"\nversion = "1.0.0"\n' > "$WORK/pkg/lex.toml"
cat > "$WORK/pkg/src/main.lex" <<'EOF'
import "std.net" as net
import "std.fs" as fs
fn main() -> [net, fs_walk] Bool {
  let _ := fs.exists("/etc/hostname");
  match net.get("https://wttr.in/Paris") { Ok(_) => true, Err(_) => false }
}
EOF
tar -C "$WORK/pkg" -czf "$WORK/pkg.tar" lex.toml src/main.lex

# ── Publisher signs a contract requiring [net, fs read-only] ─────────────────
SEED="$(printf 'ac%.0s' {1..32})"
SECRET="$("$LEXOS" --output json capsule keygen --seed "$SEED" | field secret_key)"
PUBLIC="$("$LEXOS" --output json capsule keygen --seed "$SEED" | field public_key)"
printf '{"trusted":["%s"]}\n' "$PUBLIC" > "$WORK/keyring.json"
cat > "$WORK/requires.json" <<EOF
{ "goal": { "description": "weather", "done_signal": null },
  "grant": { "filesystem": "ReadOnly", "network": "Allowlist", "exec": "None" },
  "budget": { "wall_clock_secs": 5, "max_commands": 10, "max_money_cents": 0, "max_api_calls": 0 },
  "isolation_floor": "Namespace", "egress": ["wttr.in"] }
EOF
"$LEXOS" capsule sign --artifact weather@1.0.0 --artifact-file "$WORK/pkg.tar" \
  --requires "$WORK/requires.json" --key "$SECRET" --out "$WORK/contract.json" >/dev/null

# A consumer manifest at some budget; the grant covers the contract's needs.
consumer() {  # $1 = max_money_cents
cat > "$WORK/consumer.json" <<EOF
{ "goal": { "description": "host", "done_signal": null },
  "grant": { "filesystem": "ReadWrite", "network": "Allowlist", "exec": "None" },
  "budget": { "wall_clock_secs": 5, "max_commands": 10, "max_money_cents": $1, "max_api_calls": 10 },
  "isolation_floor": "Namespace", "egress": ["wttr.in"] }
EOF
}

run() {  # install + run; prints the run readout from the envelope
  "$LEXOS" --output json capsule install --consumer "$WORK/consumer.json" \
    --contract "$WORK/contract.json" --artifact "$WORK/pkg.tar" \
    --trusted-keys "$WORK/keyring.json" --audit-out "$WORK/run.audit.json" --run 2>/dev/null
}

# ── A. Enough budget: both effects run, mediated, in execution order ─────────
say "A. Free inside the box — the entrypoint runs, every effect mediated in order"
consumer 100
OUT="$(run)"
note "execution:       $(echo "$OUT" | field execution)"
note "effects performed: $(echo "$OUT" | field effects_performed)   (the code's real control flow)"
note "ran ok:          $(echo "$OUT" | field run_ok)"
note "the mediated commands, in the one install→session audit chain:"
"$LEXOS" audit render --log "$WORK/run.audit.json" 2>/dev/null \
  | sed -n 's/^/      /p' | grep -E 'command_allowed|command_requested|session_ended' | head -6

# ── B. Zero net budget: the fs read runs, the net call is SEALED at the edge ──
say "B. Sealed at the edge — the same code, a budget that won't cover the net call"
consumer 0
OUT="$(run)"
note "effects performed: $(echo "$OUT" | field effects_performed)   (both attempted, in order)"
note "ran ok:          $(echo "$OUT" | field run_ok)"
note "why it halted:   $(echo "$OUT" | field run_detail)"
note "the gate denied it *before* the effect — logged in the same chain:"
"$LEXOS" audit render --log "$WORK/run.audit.json" 2>/dev/null \
  | sed -n 's/^/      /p' | grep -E 'budget_exhausted|command_allowed|session_ended' | head -6

say "The grant is the whole story — same code, the edge decides what reaches the world."
note "Widen the mediated surface and pin signers from earned trust: see README + demo/capsule.sh."
