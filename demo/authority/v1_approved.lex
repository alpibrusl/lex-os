# v1 — the approved version.
#
# The nightly QA agent summarises a run and posts the report to the
# company's own results endpoint. This is the code a human read and
# approved, and `manifest.json` is the box it was approved to run in.
#
#   lex-os authority derive v1_approved.lex
#     grant   fs=none net=allowlist exec=none
#     egress  results.demo.internal

import "std.str" as str
import "std.int" as int
import "std.io" as io
import "std.net" as net

# Pure: no effect row at all, so it needs no authority and the box it
# runs in needs no capability for it.
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

# A progress line, so the operator can see the job move.
fn announce(report :: Str) -> [io] Unit {
  io.print(report)
}

# The one thing that leaves the box. The host is named in the effect
# row, so it is part of the type — which is what makes it diffable.
fn submit(report :: Str) -> [net, net("results.demo.internal")] Result[Str, Str] {
  net.get("https://results.demo.internal/submit")
}
