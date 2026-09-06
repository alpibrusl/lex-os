# Plan gates: where `lex-iac` and `lex-k8s` live

**Status:** accepted (architecture decision; no code yet)
**Date:** 2026-09-06
**Scope:** lex-os, lex-lang, plus two proposed downstream repos

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
3. **Both depend on shared work in this workspace** that does not exist
   yet: manifest *facets* with a narrowing rule, an audit chain that is
   generic over its event vocabulary, and the gate ordering extracted
   from the supervisor.
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
- `lex-iac` is that pipeline for **plan JSON**.
- `lex-k8s-admission` is that pipeline for a **PodSpec**.

That shared spine belongs here, as a `lex-os-gate` crate, consumed by
both downstream repos over a git-rev pin (already the house style for
lex-os → lex-lang). The gate ordering it encodes is the supervisor's:
**log → reversibility → perimeter → budget → charge → allow**. That
order is load-bearing — the request is logged before any decision — and
extracting it must preserve it exactly.

## Build order

1. **lex-os — enabling work.**
   - `lex-os-manifest`: facet trait + `infra` facet; generalise
     `validate_narrowing` and `narrow_to` over facets; close the
     `actuation` narrowing hole.
   - `lex-os-audit`: the `Event` enum is closed. Teaching it
     `plan_requested` / `plan_accepted` / `plan_refused` would put
     Terraform vocabulary inside lex-os. Make the chain generic over its
     event payload instead, so any gate reuses the hash chain without
     this workspace knowing what infrastructure is.
   - `lex-os-gate`: the pipeline above, frontend-pluggable.
2. **lex-lang — attestation.** One `AttestationKind::PlanApply` variant
   (named generically so k8s admissions reuse it, not `InfraApply`) plus
   `lex attest import-apply`, mirroring `import-install`
   (`crates/lex-cli/src/attest.rs`) almost line for line. The loop it
   closes is the existing one: apply → attestation → earned trust →
   keyring → next apply.
3. **`lex-iac` repo.** Plan-JSON → effect-rows compiler, the
   stateful-resource table, the CLI, fixtures. Demoable with no cloud
   account.
4. **`lex-k8s` repo.** Same spine, new frontend (PodSpec + NetworkPolicy
   + RBAC), `LexManifest` CRD, webhook plumbing. Not before (3) has a
   user.
5. **`lex-os-shim` crate, here.** Containerd shim v2 + RuntimeClass, on
   the simulated backend first, then Firecracker. Much later.

Steps 1 and 2 are small and testable in this workspace. Step 3 is the
first thing that demos.

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
3. **Drop or invert `deny`.** Per the lattice constraint above.

## Cautions carried forward

The proposals' own honest cautions stand, and two more belong with them:

- A gate is exactly as safe as its input is honest. A provider that
  mutates outside its declared plan is invisible to `lex-iac`; a node
  that acts outside the PodSpec is invisible to the admission wall. In
  both cases the perimeter — in-box apply, or the RuntimeClass — is what
  bounds the rest, and in both cases it is the last milestone, not the
  first.
- Extracting `lex-os-gate` must not create a second source of authority.
  The gate reads the manifest; it does not let a frontend supply its own
  limits.
