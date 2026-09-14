# v2 — the agent's "improvement".
#
# Asked to make the nightly report more useful, the coding agent added
# run telemetry. Read as a source diff this is unremarkable: one new
# helper, one new call, a token read from the environment like every
# other credential in the codebase. Nothing here is malicious, and
# nothing here is a type error.
#
# Read as an *authority* diff it is a different change entirely:
#
#   lex-os authority diff --base v1_approved.lex --head v2_agent_improved.lex
#     egress      + telemetry.vendor.example
#     off-lattice + env
#     verdict: WIDENING
#
# The box this code was approved for cannot reach that host, and the
# gate says so before the agent ever runs.

import "std.str" as str
import "std.int" as int
import "std.env" as env
import "std.io" as io
import "std.net" as net

fn build_report(runs :: Int, failures :: Int) -> Str
  examples {
    build_report(10, 0) => "runs=10 failures=0",
    build_report(10, 2) => "runs=10 failures=2"
  }
{
  str.concat(
    "runs=",
    str.concat(int.to_str(runs), str.concat(" failures=", int.to_str(failures))))
}

fn announce(report :: Str) -> [io] Unit {
  io.print(report)
}

fn submit(report :: Str) -> [net, net("results.demo.internal")] Result[Str, Str] {
  net.get("https://results.demo.internal/submit")
}

# New in v2: the vendor token. `[env]` sits outside the trust lattice —
# no grant refuses it — which is exactly why the authority diff reports
# it separately instead of letting it pass unmentioned.
fn telemetry_token() -> [env] Option[Str] {
  env.get("TELEMETRY_TOKEN")
}

# New in v2: a second destination. One line of source; a whole new
# egress host in the type.
fn push_telemetry(report :: Str) -> [env, net, net("telemetry.vendor.example")] Result[Str, Str] {
  match telemetry_token() {
    Some(t) => net.get("https://telemetry.vendor.example/ingest"),
    None => Err("no telemetry token")
  }
}
