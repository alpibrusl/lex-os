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
  isolation floor. Content-addressable. Also the one-shot
  `EscalationGrant` (#60): a human-signed, strictly-widening delta bound
  to a single command — the manifest itself never mutates. Authority
  domains outside the trust lattice are **facets** (#66, #71): `Actuation`
  is concrete because lex-os mediates skills itself, while a downstream
  gate's domain lives type-erased in `Manifest::facets` and narrows
  through a `FacetRegistry` the consumer supplies. An *unregistered*
  facet must be byte-identical between parent and child — safe, not
  permissive.
- `crates/lex-os-audit` — hash-chained tamper-evident log. Append-only;
  never add an "edit" or "truncate" API. `Chain<E>` is generic over its
  payload (`AuditLog = Chain<Event>`) so a downstream gate reuses the
  chain without lex-os learning its vocabulary; each payload picks its
  own hash domain, and `Event`'s is frozen at `lex.os.audit.v1`.
- `crates/lex-os-perimeter` — `SandboxPolicy::from_grant` is the single
  grant→OS-policy mapping. New backends implement the `Perimeter` trait.
- `crates/lex-os-resolver` — *refuse, don't downgrade*. Every new failure
  mode is an error, never a silent weakening.
- `crates/lex-os-supervisor` — the mediation loop. The order of gates in
  `mediate` (log → reversibility → perimeter → budget → charge → allow)
  is load-bearing: the request is logged before any decision.
- `crates/lex-os-check` — the static grant↔effect wall: reject agent Lex
  code whose effects exceed the manifest grant, before it runs. Same
  grant as the runtime gates — one declaration, two enforcement points.
- `crates/lex-os-capsule` — capability-addressed distribution: a signed
  contract binding an artifact to the grant it requires; installing
  *narrows* the consumer's manifest. Refuse, don't downgrade.
- `crates/lex-os-proto` — the wire protocol between the supervisor and
  the in-guest agent binary.
- `crates/lex-os-guest` — the agent binary that runs **inside** the
  microVM: connects to the host supervisor over vsock and drives the
  reasoning loop. It is on the untrusted side of the boundary; never
  give it authority the supervisor is supposed to mediate.
- `crates/lex-os` — the CLI; emits acli envelopes and semantic exit codes.
- `manifests/` — the manifest format + bounded commands as a Lex package.

## The loop

```sh
cargo build
cargo test                 # all crates have unit tests; keep them green
cargo clippy --all-targets # must be warning-clean
cargo fmt --check
cargo run -p lex-os -- run --simulated # end-to-end demo on the simulator → GoalMet
```

The real Firecracker microVM perimeter is the **default** feature. Off a KVM
host, `run` refuses rather than silently downgrading — pass `--simulated` (used
above) for the in-process simulator, which is **not** a security boundary. On a
KVM host, plain `run` uses a real, jailed box.

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
