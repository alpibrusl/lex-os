import "std.io" as io

# Pure-ish data work: read input, no network at all.
fn analyze(path :: Str) -> [io] Result[Str, Str] {
  io.read(path)
}
