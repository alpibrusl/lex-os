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

This repository is an **honest proof-of-concept** of that design: one
agent that can only act through mediated, policy-checked, logged
commands, with a hard budget and an isolation floor, that can trash its
own box and be reprovisioned from outside. It ships both an in-process
*simulated* perimeter (runs anywhere, for tests and demos) and a real
**Firecracker microVM** backend (behind a Cargo feature; needs KVM).

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
  consequential mistakes. With the Firecracker backend it is enforced at
  the kernel/VM level. Everything it enforces derives from one
  declaration: the trust grant.

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
| [`lex-os-manifest`](crates/lex-os-manifest) | The trust manifest: goal + capability **grant** + **budget** (integer cents) + reversibility + isolation floor. Content-addressable. Re-exports the trust lattice from `lex-types`. |
| [`lex-os-audit`](crates/lex-os-audit) | Tamper-evident, **hash-chained** external audit log. An agent editing its own logs is designed out — append-only, no edit/truncate API. |
| [`lex-os-check`](crates/lex-os-check) | The **type-check wall**: runs an agent's `.lex` program through the real Lex front-end (`lex-syntax` → `lex-ast` → `lex-types`) and refuses it if its declared effects exceed the grant — *before* it runs. Backs the `check` command. |
| [`lex-os-perimeter`](crates/lex-os-perimeter) | The box's edge: `SandboxPolicy::from_grant` is the single grant→OS-policy mapping. Pluggable isolation backends behind the `Perimeter` trait — a portable simulated one and a real Firecracker microVM (feature `firecracker`). |
| [`lex-os-resolver`](crates/lex-os-resolver) | Negotiates a manifest against the real host and **refuses to downgrade** when it can't be satisfied — every failure mode is an error, never a silent weakening. |
| [`lex-os-supervisor`](crates/lex-os-supervisor) | The mediated command loop: capability + reversibility + **budget** gates, liveness, and **reprovision-on-death**. Also home to the scripted demo agent. |
| [`lex-os-proto`](crates/lex-os-proto) | Wire protocol between the supervisor (host) and the agent running inside the microVM — vsock transport (`AF_VSOCK` guest side, Unix-socket host side; feature-gated). |
| [`lex-os-guest`](crates/lex-os-guest) | The agent binary that runs **inside** the box: drives an LLM reasoning loop and relays each action to the supervisor for mediation. |
| [`lex-os`](crates/lex-os) | The CLI, speaking the [acli](https://github.com/alpibrusl/acli) protocol so agents can discover and drive it. |
| [`results-stub`](crates/results-stub) | A tiny HTTPS server used by the live demos as the *one* allowlisted egress target, so the egress wall has something legitimate to let through. |
| [`manifests/`](manifests) | The manifest format and bounded commands as a **Lex package**. |

### Dependency graph

```
lex-os            (Rust + Lex — supervisor, resolver, perimeter, policy)
   │
lex-lang          (Rust — language; + the trust-lattice feature in lex-types)
   │
acli              (CLI standard)
```

The arrow points one way only. `lex-os` pins `lex-types`, `lex-syntax`
and `lex-ast` as git dependencies of `lex-lang`. The trust lattice that
drives **both** the static Lex type check **and** the supervisor's
derived sandbox lives in `lex-lang`'s `lex-types` crate
(`lex_types::trust`) — one declaration, two enforcement layers.

## Try it

The real microVM perimeter is the default; off a KVM host, add `--simulated`
to run the demo in-process anywhere `cargo` does — no KVM, no root, no network
(it is **not** a security boundary, and every run says so):

```sh
cargo run -p lex-os -- run --simulated           # run the built-in demo
cargo run -p lex-os -- --output json run --simulated  # agent-friendly output
cargo run -p lex-os -- resolve                   # what does the manifest resolve to?
cargo run -p lex-os -- manifest sample > m.json  # emit a sample manifest
cargo run -p lex-os -- manifest hash --manifest m.json   # its content-address
cargo run -p lex-os -- run --simulated --manifest m.json --audit-out audit.json
cargo run -p lex-os -- audit verify --log audit.json     # check the hash chain
cargo run -p lex-os -- audit render --log audit.json     # NDJSON view
cargo run -p lex-os -- introspect                # acli command tree
```

The demo agent reads files, **deliberately destroys its own box**
mid-task, and is transparently reprovisioned by the supervisor from the
manifest + last checkpoint. It then reaches for `net.fetch`, `exec.shell`
and `fs.delete_all`, and tries to *widen* its own grant — all refused,
each by a different gate (see "The three walls" below). The session ends
`GoalMet`, and the audit log is hash-verified.

### The three walls

Each refusal in the demo is a distinct mechanism, not one catch-all:

```sh
# 1. Type-check wall — refuse a program whose effects exceed the grant,
#    before it runs. Needs the grant manifest and the .lex program:
cargo run -p lex-os -- check --grant examples/analyze.json \
  examples/agent-programs/submit_report.lex     # exit 8 if it over-reaches

# 2. Narrowing wall — a child manifest may only narrow a parent's grant,
#    egress and budgets; any widening is rejected:
cargo run -p lex-os -- manifest narrow --parent parent.json --child child.json

# 3. Perimeter / budget walls — enforced live inside the mediation loop:
#    net.fetch and exec.shell are denied at the perimeter (network: none),
#    fs.delete_all is refused by construction (irreversible-consequential).
```

The mediation loop logs every request **before** deciding it. The gate
order is load-bearing: log → reversibility → perimeter → budget → charge
→ allow.

### Driving a real LLM (simulated perimeter)

The agent brain is pluggable. Beyond the scripted `demo` agent, `run`
takes `--agent {ollama,anthropic,openai,guest}`. Off a KVM host, pass
`--simulated` (the real microVM perimeter is the default and would otherwise
refuse — see below):

```sh
cargo run -p lex-os -- run --simulated --agent ollama --model mistral
cargo run -p lex-os -- run --simulated --agent anthropic --model claude-...  # ANTHROPIC_API_KEY
cargo run -p lex-os -- run --simulated --agent guest                         # spawn lex-os-guest over stdio
```

### On a real microVM (KVM host + root)

The **real Firecracker microVM perimeter is the default.** On a Linux host with
`/dev/kvm`, `run` uses a real, jailed box behind a host-side egress wall. Off a
KVM host it **refuses rather than silently downgrading** — use `--simulated`
(the in-process perimeter above, which is *not* a security boundary), or build
`--no-default-features` for a portable simulator-only binary.

```sh
sudo bash demo/setup-assets.sh    # fetch firecracker + jailer + kernel + rootfs (one-time)
sudo bash demo/run.sh             # supervisor lifecycle: provision → destroy → reprovision
sudo bash demo/wall2.sh           # kernel egress wall: curl 8.8.8.8 blocked from inside the box
sudo bash demo/agent.sh           # a real LLM agent running INSIDE the microVM (local Ollama)
sudo bash demo/agent.sh demo/manifest-agent-none.json   # same, with network denied by the grant
sudo bash demo/reprovision.sh     # in-VM agent disposes its box mid-task; supervisor rebuilds it and re-attaches over vsock
sudo bash demo/egress.sh          # egress allowed leg + host-local fence: box reaches ONLY the one allowlisted target
```

`cargo run -p lex-os -- box-smoke` is the standalone Wall-2 proof: it boots a
microVM with the egress wall, streams the guest console while it runs its egress
probes, then tears it down. (CI exercises the real perimeter on a self-hosted
KVM runner — see `docs/self-hosted-kvm-runner.md`.)

## What the demo proves today

Run on a KVM host (a laptop with `/dev/kvm`), with the agent's model served
locally by [Ollama] on the LAN:

- **A real LLM agent runs *inside* a Firecracker microVM.** `lex-os-guest`
  boots in the VM, reasons with a local model, and relays every proposed
  action to the supervisor over vsock. The model is reached over the
  **one** egress target the grant allows — nothing else.
- **The three walls hold against that live agent**, each at a different layer:
  - **type-check wall** — a program whose effects exceed the grant is refused
    *before it runs* (`lex-os check`, exit 8);
  - **kernel egress wall** — from inside the booted microVM, traffic to a
    non-allowlisted host is dropped at the host's tap (`8.8.8.8` blocked). The
    allowlist is enforced purely from the grant on both the FORWARD chain
    (external targets) and the INPUT chain (host-local targets), so the box
    reaches *only* what the grant lists — not even other services on its own
    host (`demo/egress.sh`);
  - **narrowing wall** — the agent's attempt to widen its own grant
    (`propose_child`) is rejected; the grant only ever narrows.
- With a `network: none` grant, the agent's `net.fetch` and `exec.shell` are
  **denied at mediation**, while it can still reach its model (kernel egress
  allowlist) — one manifest expressing both. It gives up after repeated
  refusals; the supervisor caps total steps regardless.
- **Reprovision-on-death re-attaches the in-VM agent.** When the box dies
  mid-task, the supervisor rebuilds a fresh microVM, re-`accept()`s its vsock
  channel to the new guest, and the agent resumes where it left off — proven by
  `demo/reprovision.sh` (the rebuilt box completes `report.write`, not just a
  hollow give-up).
- **Firecracker runs jailed, not as root.** With `--jail-uid/--jail-gid` the VMM
  is launched under `jailer` — a per-VM chroot with privileges dropped to a
  non-root uid:gid — so a VM escape doesn't land in a root host context. All of
  the above (egress wall, in-VM agent over vsock, reprovision re-attach) holds
  under the jail; the demos pass these flags by default.
- Every step lands in the **hash-chained audit log**, verified after the run.

What this is *not* yet: one box runs at a time (a fixed jail id, no concurrent
multi-box scheduling) — though a box can no longer reach other services on its
host, since host-local egress is now fenced by the grant too; and the model is
reached over the LAN rather than served in-box. It's an
honest proof-of-concept of the design, demonstrated end-to-end on real
hardware — not a hardened product.

[Ollama]: https://ollama.com

### Refuse, don't downgrade

```sh
# A sudo + open-internet manifest needs a microVM. On a namespace-only
# host the resolver refuses rather than running on a weaker boundary:
cargo run -p lex-os -- resolve --manifest examples/sudo-dangerous.json --namespaces-only
#   error: needs isolation floor `microvm` but host tops out at
#   `namespace` — refusing to downgrade   (exit code 8)
```

`run` and `resolve` both take `--namespaces-only` and `--offline` to
simulate a weaker host and drive this path.

## The reversibility classification

Every command is classified by blast radius (`Reversibility` in
`lex-os-manifest`), and the class is enforced structurally:

- **Reversible / cheap** (read, query, draft) → free, logged.
- **Irreversible but bounded** (send email, write file, spend ≤ €X) →
  within budget; prominently logged; revocable grant.
- **Irreversible and consequential** (delete data, large payment) → in a
  no-human system there is no approval step, so these must be **absent
  from the grant** or **bounded so tightly the worst case is
  acceptable.** The supervisor refuses to run one *by construction* —
  denied even under a maximal grant.

## Honest cautions

1. This system is exactly as safe as its boundary and its budget — not
   one bit safer. "What can this box touch, and what's its hard budget"
   is the *entire* safety design.
2. The chokepoint only holds if the agent genuinely cannot act except
   through the box's edge. A real **Firecracker microVM** backend ships
   behind the `firecracker` feature (requires KVM; see `demo/agent.sh`)
   — kernel-level egress wall included. The simulated perimeter remains
   the default for portability and tests, behind the same trait, and is
   **not** a security boundary. So it can never be mistaken for one,
   every `run` reports which perimeter enforced it — `security_boundary:
   false` and a loud stderr warning under the simulator, `true` only on
   the real microVM build.
3. You can replay effects deterministically; you cannot necessarily
   replay the agent's reasoning. The audit log records observable
   decisions, not the agent's thoughts.

## License

EUPL-1.2. See [LICENSE](LICENSE).
