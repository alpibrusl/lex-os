# CLAUDE.md — lex-os

`lex-os` is the autonomous-agent runtime: a sealed, disposable box plus a
goal, supervised by something the agent cannot reach. Read the design
doc's framing before changing anything here — the safety properties are
the point, not an afterthought.

## The invariant that must never break

> Free inside the box, sealed at the edge. The grant is the whole safety
> story.

Everything the runtime enforces derives from **one** declaration, the
trust `Grant` (`lex_types::trust::Grant`, re-exported by
`lex-os-manifest`). The same grant drives the static Lex type check
*and* the supervisor's derived sandbox policy. Do not add a second,
independent source of authority — if you find yourself letting the agent
set its own limits, stop.

## Layout

- `crates/lex-os-manifest` — manifest, grant, budget, reversibility,
  isolation floor. Content-addressable.
- `crates/lex-os-audit` — hash-chained tamper-evident log. Append-only;
  never add an "edit" or "truncate" API.
- `crates/lex-os-perimeter` — `SandboxPolicy::from_grant` is the single
  grant→OS-policy mapping. New backends implement the `Perimeter` trait.
- `crates/lex-os-resolver` — *refuse, don't downgrade*. Every new failure
  mode is an error, never a silent weakening.
- `crates/lex-os-supervisor` — the mediation loop. The order of gates in
  `mediate` (log → reversibility → perimeter → budget → charge → allow)
  is load-bearing: the request is logged before any decision.
- `crates/lex-os` — the CLI; emits acli envelopes and semantic exit codes.
- `manifests/` — the manifest format + bounded commands as a Lex package.

## The loop

```sh
cargo build
cargo test                 # all crates have unit tests; keep them green
cargo clippy --all-targets # must be warning-clean
cargo fmt --check
cargo run -p lex-os -- run # the end-to-end demo should reach GoalMet
```

For the Lex package under `manifests/`:

```sh
lex check manifests/src/   # pure functions carry examples {} blocks
```

## Conventions

- Money is integer cents; never floats in a budget.
- A new command primitive goes in a `CommandRegistry`, classified by
  `Reversibility`. An `IrreversibleConsequential` command is refused by
  construction — only register one to test the refusal.
- The simulated perimeter is **not** a security boundary. It exists so
  the loop is testable everywhere. Real isolation is a backend behind the
  `Perimeter` trait.
