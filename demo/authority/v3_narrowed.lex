# v3 — the accepted fix, and the direction no other stack goes.
#
# The vendor call is gone, and so is the submit call: the supervisor
# collects the report from the box's stdout instead of the box pushing
# it out. The code now needs *no* network at all.
#
#   lex-os authority diff --base v1_approved.lex --head v3_narrowed.lex
#     network   allowlist → none   narrows
#     egress  - results.demo.internal
#     verdict: NARROWING
#
#   lex-os authority narrow --grant manifest.json v3_narrowed.lex
#     network: Allowlist → None, egress: [] — the box is provisioned
#     with no route out at all.
#
# Nobody hand-edits a firewall rule downward on the strength of a code
# review. Here the type checker has proved the reach is unreachable, so
# the narrowing is mechanical.

import "std.str" as str
import "std.int" as int
import "std.io" as io

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

# The report leaves the box the way everything else does: through the
# supervisor, which is on the other side of the boundary.
fn emit(report :: Str) -> [io] Unit {
  io.print(report)
}
