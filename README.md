# lex-os

> An execution environment where the "users" are agents, not humans. An
> agent is handed a sealed, disposable box plus a goal, and operates it
> without human intervention until the goal is met, the budget is
> exhausted, or it is stopped.

`lex-os` is **not** an OS in the kernel sense — it runs on top of Linux.
It is an **autonomous execution environment**: a sandboxed box given to
an agent as its "body," with a goal, supervised by something the agent
cannot reach. The closest existing analogues are CI runners and
microVM-isolated code sandboxes; this generalizes that into a
first-class, goal-driven runtime.

This repository implements the MVP from the design doc: **one agent that
can only act through mediated, policy-checked, logged commands, with a
hard budget and an isolation floor, that can trash its own box and be
reprovisioned from outside.**

## The one rule

> Agents bring judgment. Commands hold authority. The owner sets policy
> via the grant. The runtime's only real job is to make the boundary
> unbypassable and the history legible.

Two boundaries, kept strictly separate:

- **Inside the box — maximal freedom.** `sudo`, install packages, rewrite
  configs, corrupt or destroy its own filesystem. The box is disposable
  and isolated, so interior freedom costs nothing.
- **The box's edge — minimal, hard-enforced capability.** Because no
  human is watching, the perimeter is the only thing catching
  consequential mistakes. It is enforced at the kernel/VM level, derived
  from one declaration: the trust grant.

## Architecture

```
                    goal + grant + budgets
                              │
                              ▼
   ┌──────────────────────────────────────────────────────────┐
   │  SUPERVISOR  (Rust, OUTSIDE the box — trusted)             │
   │  • resolver: negotiate manifest vs environment            │
   │  • budgets / liveness / kill                              │
   │  • reprovision from manifest + checkpoint                 │
   │  • tamper-proof external audit log (hash-chained)         │
   │  • derives the sandbox policy from the grant              │
   └──────────────────────────────────────────────────────────┘
                              │ provisions / enforces
                              ▼
   ┌──────────────────────────────────────────────────────────┐
   │  THE BOX  (perimeter — Linux gives isolation)             │
   │   AGENT: full interior freedom; acts ONLY by requesting   │
   │          mediated commands                                │
   │   LEX COMMAND/EFFECT LAYER: commands = typed Lex effects, │
   │          grant checked against code at type-check time    │
   └──────────────────────────────────────────────────────────┘
```

### Crates

| Crate | Role |
| --- | --- |
| [`lex-os-manifest`](crates/lex-os-manifest) | The trust manifest: goal + capability **grant** + **budget** + isolation floor. Content-addressable. Re-exports the trust lattice from `lex-types`. |
| [`lex-os-audit`](crates/lex-os-audit) | Tamper-evident, **hash-chained** external audit log. An agent editing its own logs is designed out. |
| [`lex-os-perimeter`](crates/lex-os-perimeter) | The box's edge: derives an OS **sandbox policy** from the grant; pluggable isolation backends. |
| [`lex-os-resolver`](crates/lex-os-resolver) | Negotiates a manifest against the real host and **refuses to downgrade** when it can't be satisfied. |
| [`lex-os-supervisor`](crates/lex-os-supervisor) | The mediated command loop: capability + reversibility + **budget** gates, liveness, and **reprovision-on-death**. |
| [`lex-os-proto`](crates/lex-os-proto) | Wire protocol between the supervisor (host) and the agent running inside the microVM — vsock transport (`AF_VSOCK` guest side, Unix-socket host side). |
| [`lex-os-guest`](crates/lex-os-guest) | The agent binary that runs **inside** the box: drives an LLM reasoning loop and relays each action to the supervisor for mediation. |
| [`lex-os`](crates/lex-os) | The CLI, speaking the [acli](https://github.com/alpibrusl/acli) protocol so agents can discover and drive it. |
| [`manifests/`](manifests) | The manifest format and bounded commands as a **Lex package**. |

### Dependency graph

```
lex-os            (Rust + Lex — supervisor, resolver, perimeter, policy)
   │
lex-lang          (Rust — language; + the trust-lattice feature in lex-types)
   │
acli              (CLI standard)
```

The arrow points one way only. The trust lattice that drives **both** the
static Lex type check **and** the supervisor's derived sandbox lives in
`lex-lang`'s `lex-types` crate (`lex_types::trust`) — one declaration,
two enforcement layers.

## Try it

```sh
cargo run -p lex-os -- run                       # run the built-in demo
cargo run -p lex-os -- --output json run         # agent-friendly output
cargo run -p lex-os -- resolve                   # what does the manifest resolve to?
cargo run -p lex-os -- manifest sample > m.json  # emit a sample manifest
cargo run -p lex-os -- run --manifest m.json --audit-out audit.json
cargo run -p lex-os -- audit verify --log audit.json
cargo run -p lex-os -- introspect                # acli command tree
```

The demo agent reads files, **deliberately destroys its own box**
mid-task, and is transparently reprovisioned by the supervisor from the
manifest + last checkpoint. It then reaches for `net.fetch`, `exec.shell`
and `fs.delete_all` — all refused, because the demo grant is
filesystem-only and the consequential command has no approval path. The
session ends `GoalMet`, and the audit log is hash-verified.

### On a real microVM (KVM host + root)

The commands above use the in-process *simulated* perimeter, which runs
anywhere but is **not** a security boundary. On a Linux host with `/dev/kvm`
the same loop runs behind a real Firecracker microVM:

```sh
sudo bash demo/setup-assets.sh    # fetch firecracker + kernel + rootfs (one-time)
sudo bash demo/run.sh             # supervisor lifecycle: provision → destroy → reprovision
sudo bash demo/wall2.sh           # kernel egress wall: curl 8.8.8.8 blocked from inside the box
sudo bash demo/agent.sh           # a real LLM agent running INSIDE the microVM (local Ollama)
sudo bash demo/agent.sh demo/manifest-agent-none.json   # same, with network denied by the grant
```

## What the demo proves today

Run on a KVM host (a laptop with `/dev/kvm`), with the agent's model served
locally by [Ollama] on the LAN:

- **A real LLM agent runs *inside* a Firecracker microVM.** `lex-os-guest`
  boots in the VM, reasons with a local model (e.g. `devstral-small-2`), and
  relays every proposed action to the supervisor over vsock. The model is
  reached over the **one** egress target the grant allows — nothing else.
- **The three walls hold against that live agent**, each at a different layer:
  - **type-check wall** — a program whose effects exceed the grant is refused
    *before it runs* (`lex-os check`, exit 8);
  - **kernel egress wall** — from inside the booted microVM, traffic to a
    non-allowlisted host is dropped at the host's tap (`8.8.8.8` blocked);
  - **narrowing wall** — the agent's attempt to widen its own grant
    (`propose_child`) is rejected; the grant only ever narrows.
- With a `network: none` grant, the agent's `net.fetch` and `exec.shell` are
  **denied at mediation**, while it can still reach its model (kernel egress
  allowlist) — one manifest expressing both. It gives up after repeated
  refusals; the supervisor caps total steps regardless.
- Every step lands in the **hash-chained audit log**, verified after the run.

What this is *not* yet: the perimeter is single-tenant and runs as root (no
jailer); reprovision-on-death doesn't yet re-attach the in-VM agent's vsock;
the model is reached over the LAN rather than served in-box. It's an honest
proof-of-concept of the design, demonstrated end-to-end on real hardware —
not a hardened product.

[Ollama]: https://ollama.com

### Refuse, don't downgrade

```sh
# A sudo + open-internet manifest needs a microVM. On a namespace-only
# host the resolver refuses rather than running on a weaker boundary:
cargo run -p lex-os -- resolve --manifest sudo.json --namespaces-only
#   error: needs isolation floor `microvm` but host tops out at
#   `namespace` — refusing to downgrade   (exit code 8)
```

## The reversibility classification

Every command is sorted by blast radius and the class is enforced
structurally (design doc §6):

- **Reversible / cheap** (read, query, draft) → free, logged.
- **Irreversible but bounded** (send email, write file, spend ≤ €X) →
  within budget; prominently logged; revocable grant.
- **Irreversible and consequential** (delete data, large payment) → in a
  no-human system there is no approval step, so these must be **absent
  from the grant** or **bounded so tightly the worst case is
  acceptable.** The supervisor refuses to run one.

## Honest cautions

1. This system is exactly as safe as its boundary and its budget — not
   one bit safer. "What can this box touch, and what's its hard budget"
   is the *entire* safety design.
2. The chokepoint only holds if the agent genuinely cannot act except
   through the box's edge. A real **Firecracker microVM** backend now
   ships (requires KVM; see `demo/agent.sh`) — kernel-level egress wall
   included. The simulated perimeter remains for portability and tests,
   behind the same trait.
3. You can replay effects deterministically; you cannot necessarily
   replay the agent's reasoning. The audit log records observable
   decisions, not the agent's thoughts.

## License

EUPL-1.2. See [LICENSE](LICENSE).
