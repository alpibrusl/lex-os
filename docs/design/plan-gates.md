# Plan gates: where `lex-iac` and `lex-k8s` live

**Status:** accepted, amended 2026-09-06 (see *Amendments*)
**Date:** 2026-09-06
**Scope:** lex-os, lex-lang, plus two downstream repos

> **Amended after implementation and a survey of the existing `lex-*`
> packages.** Two claims in the original text were wrong, one design
> question is now decided, and the recommendation for `lex-os-gate` has
> changed. The corrections are in *Prior art* and *Amendments*; the rest
> of the document stands.

Two proposals — `lex-iac` (a gate between `terraform plan` and
`terraform apply`) and `lex-k8s` (an admission webhook plus a
RuntimeClass shim) — both claim to "reuse `lex-os-manifest`, the
narrowing wall, the audit log and the attestation graph almost
untouched". This document records what that reuse actually costs, which
of the two is a new repo, which parts belong in this workspace, and in
what order to build them.

## Decision

1. **`lex-iac` is a new repo**, and is built first.
2. **`lex-k8s` is a new repo too, but it is two projects.** Its
   admission wall (seam 1) is the same gate as `lex-iac` with a
   different frontend and belongs in that new repo. Its containerd shim
   (seam 2) is not a gate at all — it is a second consumer of
   `lex-os-perimeter` and belongs **here**, as a future `lex-os-shim`
   crate. Neither starts until `lex-iac` has shipped.
3. **Both depend on shared work in this workspace**: manifest *facets*
   with a narrowing rule, and an audit chain generic over its event
   vocabulary. Both have since landed (#66, #67). Extracting the gate
   ordering itself was originally listed here too; it is deferred —
   *Amendments* §1.
4. **lex-lang's share is small**: one `AttestationKind` variant and one
   `lex attest` subcommand.

## Why they are not crates in this workspace

`lex-iac` touches none of the runtime half of lex-os — no perimeter,
no supervisor, no guest, no proto, no capsule. It is a pure consumer of
manifest + audit + attestation. What it *does* bring is a
Terraform/OpenTofu plan-JSON model, a stateful-resource table and a cost
estimator adapter: large, vendor-tracking, churn-prone surfaces. Vendoring
those here would couple provider drift to this workspace's release
cadence, and lex-os release tags pin downstream CI.

The rule is already written down, in `manifests/lex.toml`: *promote to
its own repo when something other than lex-os needs to consume it.* Two
independent gates consuming the manifest spine is that moment.

The seam-2 shim is the opposite case. It wants `SandboxPolicy::from_grant`,
the jailer, the vsock protocol and `lex-os-guest`. That is this workspace's
core, not a downstream consumer, and it should not live in a repo whose
other half is a Kubernetes webhook.

## The blocking finding: facets, not dimensions

Both proposals assume a grant can grow a domain facet — `infra:
{allow, deny, scope}` in one, `privileged` / `hostPath` / `secrets` in
the other.

It cannot grow there. `lex_types::trust::Grant` (lex-lang,
`crates/lex-types/src/trust.rs`) is a fixed 3-tuple of totally-ordered
`Level`s over `{Filesystem, Network, Exec}`. It is hashed into a
`GrantId`, and it is consumed by the **Lex type checker**. Adding glob
lists to it would change what "trust" means to the language and break
hash stability, which lex-lang treats as a contract
(`docs/INVARIANTS.md`) with downstream CI pinned to release tags.

The precedent for what to do instead is already in this crate.
`Actuation` — the robot half of the grant,
`crates/lex-os-manifest/src/actuation.rs` — is an **optional field on
`Manifest`**, carrying its own bounds checks (`check_move_to`,
`allows(skill)`) and mediated per-request by the supervisor. The
three-dimension lattice was never touched.

> **Rule:** a new authority domain is a `Manifest` *facet* in
> `lex-os-manifest`, never a new `Grant` dimension in `lex-types`.
> The lattice stays the language's business; the facets stay the
> runtime's.

This keeps the one-declaration invariant intact: the facet lives on the
same manifest, hashed into the same `ManifestId`, narrowed by the same
wall.

### The hole the precedent leaves

`Manifest::validate_narrowing` checks the grant, the egress allowlist and
every budget ceiling. It does **not** check `actuation`, and `narrow_to`
copies the facet to the child verbatim. So facet narrowing has no
implementation today.

Both proposals depend on it being real — "a CI job cannot mint itself
`rds.*`", "a `LexManifest` that widens its parent is refused at
admission". Generalising narrowing over facets is therefore a shared
prerequisite, and it closes a live gap on the robot path at the same
time.

### Facets must be lattices, not rule lists

A facet has to have a meet for narrowing to be decidable, which
constrains its shape:

- **Allow-lists narrow** (meet = intersection, given a decidable
  containment on globs: `aws.ecs.*` covers `aws.ecs.update`).
- **Deny-lists do not.** A child that simply omits a parent's `deny`
  entry *widens*, monotonically in the wrong direction. Since the whole
  claim against Sentinel/OPA/Gatekeeper is "we narrow, they enumerate",
  shipping a `deny` list would concede the argument. Make the facet
  allow-only plus scopes, or make `deny` inherit-and-union-only so a
  child can add prohibitions but never drop them.
- **Booleans and scalars narrow** if they are ordered
  (`privileged: false` ≤ `privileged: true`).

The k8s facets pass this test as written (`secrets` and `egress` are
allow-lists; `privileged` and `hostPath` are ordered booleans). The
`lex-iac` facet does not, because of `deny`.

## The abstraction both proposals are circling

Stated plainly, both are the same pipeline with a different first stage:

```
artifact → effect rows → facet-grant check → reversibility → budget
        → audit (before deciding) → attestation (if allowed)
```

- `lex-os-check` is that pipeline for **Lex source**.
- `lex-guard` is that pipeline for **money** — already built, in Lex.
- `lex-iac` would be that pipeline for **plan JSON**.
- `lex-k8s-admission` would be that pipeline for a **PodSpec**.

The gate ordering is the supervisor's: **log → reversibility →
perimeter → budget → charge → allow**. That order is load-bearing — the
request is logged before any decision — and any implementation must
preserve it.

The original text concluded from this that the spine should be extracted
now, as a `lex-os-gate` crate. That conclusion was drawn without knowing
`lex-guard` existed, and no longer holds; see *Prior art* below.

## Prior art in the `lex-*` ecosystem

The original text was written without surveying the org's existing
packages. Four of them bear directly on this design, and one of them
invalidates a conclusion.

### `lex-guard` — the gate already exists, in Lex

`lex-guard` is agent spending guardrails, and its hot path
(`src/gate.lex`) is this pipeline:

```
append spend.intent                       ← before anything; a failed write halts
  → policy.check_stateless (lex-spec)     Allow | Deny(reason) | Inconclusive(why)
  → history_denial  (rolling windows summed back from the trail)
  → exec(intent) → append spend.outcome
```

Three things in it are better than what this document originally
specified, and should be adopted by any gate built here:

1. **`Inconclusive` is a verdict, not an error.** It is distinct from
   `Deny` and is treated as a refusal with the reason preserved —
   "refuse, don't downgrade" expressed in the type rather than in prose.
2. **Four terminal kinds, not two**: `denied` (policy), `blocked`
   (allowed but fulfilment unproven), `escalated` (allowed but held for
   a human), `outcome`. A budget refusal and an unproven delivery are
   different facts; a plan gate needs the same distinction.
3. **Stateful caps come from the log**, not from memory — `sum_outcomes`
   folds a time range of the trail. lex-os has no equivalent, and the
   budget milestone of either gate will want one.

`spend_reviewed` also binds a human approval to a specific intent
(amount *and* merchant must match), which is structurally the one-shot
`EscalationGrant` (#60) arrived at independently.

### `lex-trail`, `lex-spec`, `lex-attest`

- **`lex-trail`** — content-addressed event log in Lex, SQL-backed, with
  replay, export and anchors. Its event id is
  `sha256(kind ‖ parent ‖ payload_json ‖ ts_ms)`: a parent-pointer DAG,
  not a linear chain, with payloads as JSON strings rather than a typed
  enum.
- **`lex-spec`** — capability-precondition and spec DSL in pure Lex,
  property-checkable with SMT-LIB export. Worth a look for the narrowing
  wall: an SMT-exportable facet spec could *prove* narrowing rather than
  check it pair by pair.
- **`lex-attest`** — HTTP/JSON wrapper over `lex-trail` so non-Lex
  services can append to an evidence chain.

### Why lex-os keeps its own chain anyway

`lex-os-audit` stays, but for narrower reasons than first claimed. It
holds typed payloads (lex-trail's are JSON strings, so type safety ends
at the trail boundary), needs no SQL, and lives host-side in the
supervisor's process. What it does **not** hold over `lex-trail` is
deletion detection — see *Amendments*.

## Amendments

### 1. `lex-os-gate` is not built yet, and may never be

**Original:** extract the spine into a `lex-os-gate` crate as step 1.

**Now:** don't. With `lex-guard` in view, that would be a third
implementation of one ordering, extracted from a single example
(`lex-os-check`) to serve consumers that do not exist yet. The evidence
also says the second consumer may not want Rust: `lex-iac` is a CLI with
no perimeter and no supervisor, and the only part of it that genuinely
requires Rust is the manifest-facet check.

The shape should be extracted from **two real implementations**, not one
plus a guess. Build `lex-iac` first; revisit the extraction when a
second frontend actually exists.

This does not vacate the trust-position argument: a gate that runs
host-side in the supervisor's process, alongside the perimeter, must be
Rust. `lex-guard` runs as an agent-facing MCP server. They are not the
same position — which is exactly why one abstraction over both was
premature.

### 2. What the audit chain proves

**Original claim** (in the argument for keeping `lex-os-audit` over
`lex-trail`): the linear chain detects deletion, where a parent-pointer
DAG does not.

**Correction:** it detects deletion from the *middle* — the sequence
numbering shifts — but **not truncation of the tail**, and cannot: a
prefix of a valid chain is itself a valid chain, and nothing inside the
log proves a further entry once followed. The entry an auditor would
most want to erase is usually the last one. `lex-trail`'s `anchor.lex`
documents the same limit for its own model and answers it with an
external commitment; lex-os has no equivalent and answers it
positionally — the log lives outside the box, so the party who could
truncate it is the party being protected.

Recorded in `lex-os-audit`'s module docs and pinned by
`tail_truncation_is_not_detected`.

**Amended again (lex-os#54).** "lex-os has no equivalent" was true when
it was written and is no longer. `lex-os-audit` now has both halves of
what `lex-trail`'s `anchor.lex` describes:

- **Seals** — an Ed25519 signature over each entry's hash. The
  positional argument covered the *box*, but not a holder of the log
  who edits it and recomputes every hash afterwards. A seal is the part
  they cannot recompute.
- **Checkpoints** — a signature over `(domain, len, head)`. This is the
  external commitment, and it closes truncation for the same reason
  `lex-trail`'s anchor does: a chain cannot contradict a commitment its
  holder never had a copy of.

The positional argument stands and is now doing less work. It was
carrying two claims on its own; it carries neither alone any more.

What none of it closes: a compromised signer. A key that signs whatever
it is given produces a log that verifies and lies. The layers make a
rewrite need the key and a truncation need to reach two places — they do
not make the record true.

### 3. Deny-lists: decided

The facet is **allow-only plus scopes**. A `deny` list does not narrow —
a child that omits one of its parent's entries has widened — and the
whole claim against Sentinel/OPA/Gatekeeper is that we narrow where they
enumerate. `crates/lex-os-manifest/src/facet.rs` therefore offers no
deny-list helper, and that omission is deliberate and documented.

A facet needing prohibitions expresses them as the absence of an allow
entry.

### 4. Fixtures and a first user are an open problem

The original plan assumed both gates could borrow a real corpus of
Terraform plans and PodSpecs from elsewhere in the org. That source is
out of scope, so `lex-iac` milestone 1 needs fixtures of its own —
synthesised plan JSON, or upstream Terraform/OpenTofu test data.

This matters most for `lex-k8s`, whose sequencing is written as "not
before `lex-iac` has a user". Without an in-house consumer, "has a user"
needs redefining before milestone 4 of either repo starts.

## Build order

1. **lex-os — enabling work.** ✅ *done*
   - `lex-os-manifest`: facet trait, `validate_narrowing` and `narrow_to`
     generalised over facets, and the `actuation` narrowing hole closed
     (#66).
   - `lex-os-audit`: `Chain<E>` generic over its payload, so a gate
     reuses the hash chain without this workspace learning what
     infrastructure is (#67).
   - ~~`lex-os-gate`~~ — deferred, see *Amendments* §1.
2. **`lex-iac` repo.** Plan-JSON → effect-rows compiler, the
   stateful-resource table, the CLI, fixtures. Demoable with no cloud
   account, and the first thing that demos at all.
3. **lex-lang — attestation.** One `AttestationKind::PlanApply` variant
   (named generically so k8s admissions reuse it, not `InfraApply`) plus
   `lex attest import-apply`, mirroring `import-install`
   (`crates/lex-cli/src/attest.rs`) almost line for line. The loop it
   closes is the existing one: apply → attestation → earned trust →
   keyring → next apply. Needed for `lex-iac` milestone 4, not before.
4. **`lex-k8s` repo.** Same shape, new frontend (PodSpec + NetworkPolicy
   + RBAC), `LexManifest` CRD, webhook plumbing. Not before (2) has a
   user — and *Amendments* §4 notes that "has a user" now needs
   redefining.
5. **Revisit the shared spine.** With `lex-iac` and `lex-k8s-admission`
   both real, extract what they actually share — if anything, and in
   whichever language the evidence then supports.
6. **`lex-os-shim` crate, here.** Containerd shim v2 + RuntimeClass, on
   the simulated backend first, then Firecracker. Much later.

Step 1 landed with a runnable example per issue. Step 2 is now the
critical path: it is unblocked by every open question, and the extraction
in step 5 cannot be judged until it exists.

### Why `lex-iac` goes before `lex-k8s`

`lex-iac` milestone 2 needs a JSON fixture. `lex-k8s` milestone 2 needs
a cluster, a CRD, certificate plumbing and a Kubernetes client library.
And because seam 1 and `lex-iac` are the *same gate*, building them
concurrently means factoring the shared spine from one example while
guessing at the other. Build one, then generalise against a second real
frontend.

## Corrections to the proposal documents

Both were written against an idealised manifest. Before either becomes a
spec:

1. **The manifest JSON in the `lex-iac` proposal is not the real
   shape.** `Manifest` serialises as `{goal: {description, done_signal},
   grant: {filesystem, network, exec}, budget: {wall_clock_secs,
   max_commands, max_money_cents, max_api_calls}, isolation_floor,
   egress, actuation}`. There is no top-level `reversibility` field —
   `Reversibility` classifies a *command*, not a manifest — and
   `budget.window` does not exist. Cloud spend maps onto
   `max_money_cents`, which is already integer cents.
2. **`grant.infra` is `manifest.infra`.** Per the facet rule above.
3. **Drop `deny`.** Decided: allow-only plus scopes — see *Amendments*
   §3.

## Cautions carried forward

The proposals' own honest cautions stand, and two more belong with them:

- A gate is exactly as safe as its input is honest. A provider that
  mutates outside its declared plan is invisible to `lex-iac`; a node
  that acts outside the PodSpec is invisible to the admission wall. In
  both cases the perimeter — in-box apply, or the RuntimeClass — is what
  bounds the rest, and in both cases it is the last milestone, not the
  first.
- Whatever the spine becomes, it must not create a second source of
  authority. A gate reads the manifest; it does not let a frontend
  supply its own limits. That constraint outlives the question of
  whether `lex-os-gate` is ever extracted.
