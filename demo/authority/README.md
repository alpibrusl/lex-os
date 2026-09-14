# Authority review — the sandbox is compiled, not configured

> One command, one claim: **this is a process that is strictly better in
> Lex than in any other language, and the reason is the type system.**

Every stack can sandbox an agent. What no other stack can do is answer
these two questions about a *change*:

1. What is the least authority this code provably needs — on every
   path, not on the run you happened to trace?
2. What did this change do to that authority?

Lex can answer both, because the authority is in the types and the type
checker has already proved the types honest. `lex-os` then derives the
box from that same answer. One declaration, two enforcement points,
and — new here — a reviewable artifact in between.

```
   agent writes code
        │
   authority derive   →  least grant the code provably needs
        │
   authority diff     →  delta vs the last approved version
        │                 ├─ narrowing  → applied automatically
        │                 └─ widening   → refused; a human decides
   authority gate     →  CI verdict, exit 8 on refusal
        │
   authority narrow   →  manifest tightened to the derivation
        │
   lex-os run         →  perimeter derived from *that* manifest
```

## Run it

No KVM, no network, no box. Every verdict below is static.

```sh
bash demo/authority/run.sh
```

## The story

A nightly QA agent summarises a test run and posts the report to the
company's own results endpoint. `manifest.json` is the box a human
approved it to run in.

### Act 0 — the authority is derived, not written

```
$ lex-os authority derive v1_approved.lex
  grant        fs=none net=allowlist exec=none
  authority-id grant:a55cd49607e2
  egress       results.demo.internal
  effects      io, net
  off-lattice  io (no grant refuses these — review them by eye)
  net scope    partial — a bare [net] is present, so *which* host is a perimeter question
  minimal      yes — tight on every dimension it uses:
                 network at `allowlist`: lowering to `loopback` rejects `net`
```

Nobody wrote that. It is a fold over the declared effect rows, and the
last line is the part that matters: the derivation is **minimal**, and
says why. Lower any dimension one rank and a declared effect stops being
permitted. That is not a claim in a README — it is
`Authority::minimality_witness`, checked by
`derived_grant_is_minimal` over every program in the test suite.

This is also the honest limit, stated in the output rather than buried:
`std.net.get` carries a *bare* `[net]`, so the static answer is "may
reach the network" and *which host* stays a perimeter question. Two
layers, one grant.

### Act 1 — the approved version passes, and the manifest's over-grant is named

```
$ lex-os authority gate --grant manifest.json v1_approved.lex
ALLOWED — v1_approved.lex fits manifest.json

over-grant — authority this manifest hands over and the code never uses:
  filesystem   full → none
  exec         full → none
```

`filesystem: Full` and `exec: Full` are there because the first version
of the job shelled out to a test runner. That stopped being true and
nobody narrowed it, because nobody could prove it was safe to. This is
what a hand-written policy does next to code that moves: it only ever
grows.

### Act 2 — the agent "improves" the job

Asked to make the report more useful, the coding agent adds run
telemetry. A dozen lines: one helper, one call, a token read from the
environment like every other credential in the codebase. Nothing
malicious. Nothing that fails a type check.

```
$ lex-os authority diff --base v1_approved.lex --head v2_agent_improved.lex --fail-on widening
  egress       + telemetry.vendor.example
  off-lattice  + env
verdict: WIDENING — this change reaches somewhere new; a human must approve it
→ exit 8
```

Two details worth stopping on.

**The coarse grant did not move.** v1 and v2 have the *same*
`authority-id`: `fs=none net=allowlist exec=none` either way. A review
that compared grants would have seen nothing. The egress set and the
effect surface are what caught it — which is why the review artifact is
the full derivation, not just the lattice.

**`env` is reported even though no grant refuses it.** The trust lattice
ranks three dimensions; `env`, `sql`, `approval`, `chat` and friends sit
outside it. A grant-only diff would say nothing when a program starts
reading environment variables. `off_lattice_added` says it anyway, while
being honest that the perimeter is not what stops it.

And the box refuses the program outright, before the agent runs:

```
$ lex-os authority gate --grant manifest.json v2_agent_improved.lex
REFUSED — v2_agent_improved.lex exceeds manifest.json
  network: code reaches `telemetry.vendor.example`, which is not in the
           approved egress allowlist (2 entries)
→ exit 8
```

### Act 3 — the direction no other stack goes

The accepted fix drops the network entirely: the supervisor collects the
report from the box's stdout instead of the box pushing it out.

```
$ lex-os authority diff --base v1_approved.lex --head v3_narrowed.lex
  network      allowlist → none   narrows
  egress     - results.demo.internal
verdict: NARROWING — the code proves it no longer needs some authority; safe to apply

$ lex-os authority narrow --grant manifest.json v3_narrowed.lex --out narrowed.json
  before       fs=full net=allowlist exec=full
  after        fs=none net=none exec=none
  egress       ["results.demo.internal:443", "legacy-metrics.demo.internal:443"] → []
```

The box is now provisioned with no route out at all, and the stale
`legacy-metrics` entry — decommissioned two quarters ago, still in the
allowlist — goes with it. The old code no longer fits the box it used to
run in, which is what makes this a real narrowing rather than a
cosmetic one.

Nobody hand-edits a firewall rule downward on the strength of a code
review. Here the type checker proved the reach unreachable, so the
narrowing is mechanical.

Note what `narrow` *refuses* to do. In Acts 1 and 2 it leaves the stale
egress entry alone, because the code still carries a bare `[net]`: the
runtime host is not statically known, so no entry can be proved unused
and shedding one might break the job. Refusing to narrow what it cannot
prove is the discipline, not a gap in it.

## The baseline: Deno, not Python

```sh
bash demo/authority/baseline/compare.sh
```

The comparison worth making is not against a runtime with no authority
model. It is against the best one in wide use. `baseline/deno/` is the
same change in TypeScript, launched the way Deno intends:

```sh
deno run --allow-net=results.demo.internal v1_report.ts
```

Deno's permissions are genuinely good: default deny, per-host network,
per-path filesystem, per-variable environment, enforced by the runtime.
Run v2 under that same command line and Deno **refuses** — this is
`baseline/compare.sh` executing it, not a description of it:

```
$ deno run --allow-net=results.demo.internal drive_v2.ts
report built: runs=120 failures=3
telemetry: REFUSED by Deno — NotCapable
  NotCapable: Requires env access to "TELEMETRY_TOKEN", run again with the --allow-env flag
```

That is a real wall and it holds. Note *where* it landed, though: on the
environment read, because that is what the code reached first. Permit
the variable and the refusal moves down to the fetch:

```
$ TELEMETRY_TOKEN=… deno run --allow-net=results.demo.internal \
    --allow-env=TELEMETRY_TOKEN drive_v2.ts
telemetry: REFUSED by Deno — NotCapable
  NotCapable: Requires net access to "telemetry.vendor.example:443", run again with the --allow-net flag
```

The wall is wherever execution happens to arrive, in the order it
arrives — never a statement about the program. Had `pushTelemetry` sat
behind a feature flag, an error path or a nightly branch, neither
refusal would have fired today and the deploy would have looked clean.

Four things it still cannot do, and none of them is a missing feature:

- **It cannot tell you what the program needs.** `fetch(url)` takes a
  runtime value, so the set of hosts a JavaScript program may reach is
  not a property any tool can read off the source. Lex's effect rows
  *are* that property, and the type checker has already refused any row
  that lies about its body. This is the whole asymmetry; everything else
  follows from it.
- **Authority is process-wide, not per-function.** `--allow-net=a,b`
  grants both hosts to every line that runs, transitive dependencies
  included. There is no sense in which `submit` may reach the results
  endpoint and `pushTelemetry` may not. `lex authority derive` names
  which function needs which effect.
- **There is no delta.** Nothing about v2 changes a file a CI job could
  refuse on. If a human updates the flags, that edit is the only signal
  there is — written by the same human who had to notice first.
- **The flags only ever grow.** Nobody removes `--allow-read` because
  nobody can prove it unused. `authority narrow` removes it on a proof.

So Deno's refusal arrives at run time, in the environment that has the
token, on the code path that happens to run, after the deploy — and
never at all for a path that does not run that day. `authority gate`
refuses the same change before it merges, and names the host.

The same shape applies to WASI, whose capabilities (preopened
directories, granted sockets) are likewise handed in from outside rather
than read out of the code.

`baseline/python-docker/` keeps the common case — a Dockerfile, a
seccomp profile, a Kubernetes NetworkPolicy — which is strictly weaker
again: the Dockerfile says which packages exist, not which hosts are
reached; seccomp says `connect(2)` is permitted, not to where; the
NetworkPolicy names one destination but nothing ties it to the code.

## The same derivation without lex-os

The fold lives upstream in `lex_types::authority`, so the authoring
toolchain answers the same question with no manifest in sight:

```sh
lex authority derive src/
lex authority diff --base old/ --head src/ --fail-on widening
```

`lex authority` takes a whole package, and names the **contributors** —
which function is why each effect is in the answer:

```
$ lex authority derive v2_agent_improved.lex
  env          push_telemetry, telemetry_token
  io           announce
  net          push_telemetry, submit
```

`lex-os authority` adds the half that needs a manifest — `gate` and
`narrow` — because only lex-os knows what box the code was approved for.

## Running a non-Lex agent in the box

Worth being exact about, because the two halves cover different things.
The static wall needs effect rows, so it applies to Lex code and to
nothing else; the perimeter applies to anything the box can run. A
coding agent — a Node binary — gets the runtime half in full (a
disposable microVM, the egress allowlist as its only route out, a budget
in integer cents, `exec` mediation, a hash-chained log it cannot reach)
and the static half not at all.

Where the static half earns its keep for such an agent is on the *other*
side of the box: what the agent **writes**. If its output is Lex, the
authority delta on its branch answers the question it cannot answer
about itself — *did this change claim new reach?* — which is exactly the
review in Act 2 above, run against an agent's PR instead of a human's.

## Using it in CI

```yaml
- name: authority review
  run: |
    git show "origin/${{ github.base_ref }}:agent/job.lex" > /tmp/base.lex
    lex-os authority diff --base /tmp/base.lex --head agent/job.lex \
      --fail-on widening --output json > authority.json
```

Exit `8` (`PRECONDITION_FAILED`) is the refusal, and `--output json`
gives the whole delta as an acli envelope for a PR comment. Pin
authority exactly with `--fail-on any`.

## What is checked, and where

| Claim | Checked by |
|---|---|
| the derived grant is minimal | `derived_grant_is_minimal` (every program in the suite) |
| the three acts read as written | `crates/lex-os-authority/tests/demo_acts.rs`, over *these* files |
| a widening dominates a narrowing in one change | `a_widening_dominates_a_narrowing_in_the_same_change` |
| narrowing never widens past the manifest | `narrowing_never_widens_past_the_manifest` |
| the gate agrees with `lex-os check`'s wall | shared refusal semantics; `gate_refuses_a_host_outside_the_allowlist` |

The demo files in this directory are the test fixtures. A change that
breaks the story fails CI rather than quietly making the runbook a lie.
