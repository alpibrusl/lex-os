import "std.fs" as fs

import "std.io" as io

import "std.net" as net

import "std.proc" as proc

# Bounded command primitives (design doc §9).
#
# These are the typed, bounded primitives the *developer* writes. Each
# command's effect signature *is* its trust requirement: a function that
# carries `[net]` cannot run under a `network: none` grant, because the
# Lex type checker rejects it before it ever executes. The agent never
# holds raw authority — it only requests these commands, and the
# supervisor mediates each request against the grant and the budget.
#
# Commands are grouped by the reversibility classification (design doc
# §6). The grouping is a property of the effect, not an assertion the
# agent makes.
# ── Reversible / cheap (read, query, draft) ──────────────────────────
# Free to run, always logged. Trust: filesystem ≥ read-only.
fn cmd_list_dir(path :: Str) -> [fs_walk] Result[List[Str], Str] {
  fs.list_dir(path)
}

fn cmd_exists(path :: Str) -> [fs_walk] Bool {
  fs.exists(path)
}

fn cmd_read(path :: Str) -> [io] Result[Str, Str] {
  io.read(path)
}

# ── Irreversible but bounded (write a file, send, spend ≤ €X) ─────────
# Allowed within budget; prominently logged; the grant stays revocable.
# Write a report. Trust: filesystem ≥ read-write. Bounded: one file.
fn cmd_write_report(path :: Str, body :: Str) -> [io] Result[Unit, Str] {
  io.write(path, body)
}

# A single network fetch. Trust: network ≥ allowlist. Bounded: each call
# is charged against the supervisor's api-call budget.
fn cmd_fetch(url :: Str) -> [net] Result[Str, Str] {
  net.get(url)
}

# Run an allow-listed subprocess and return its stdout. Trust: exec ≥
# sandboxed. The runtime allow-lists which binaries are spawnable.
fn cmd_run(program :: Str, args :: List[Str]) -> [proc] Result[Str, Str] {
  match proc.spawn(program, args) {
    Ok(r) => Ok(r.stdout),
    Err(e) => Err(e),
  }
}

# ── Irreversible and consequential (delete data, large payment) ──────
# In a no-human system there is no approval step. A command in this
# class must be absent from the grant entirely, or bounded so tightly
# the worst case is acceptable. It is named here only so the class is
# explicit; the supervisor refuses to run anything classified
# consequential.
fn cmd_remove(path :: Str) -> [fs_write] Result[Unit, Str] {
  fs.remove(path)
}

