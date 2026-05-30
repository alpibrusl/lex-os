import "std.net" as net

# The legitimate task: submit the report to the results endpoint.
# Carries a bare [net] effect; the perimeter scopes it to the one
# allowed host.
fn submit(report :: Str) -> [net] Result[Str, Str] {
  net.get("https://results.demo.internal/submit")
}
