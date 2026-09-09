# Cold-read fixtures

Deployment specimens for [the manifest cold read](../manifest-cold-read.md).

## Why these exist

The first two passes of that study both stopped in the same place, and it was
not where the study expected. Neither participant reached a gate. From the
second pass's log:

> `lex-k8s admit` needs an AdmissionReview/PodSpec plus cluster-policy
> snapshot. `lex-attest` provides neither. I cannot honestly run the admission
> wall on the service without first inventing the thing being admitted. **The
> blocker comes before the gate, not inside it.**

No application repository carries an image digest, a Secret name, a
NetworkPolicy, a ServiceAccount, a storage shape or a parent manifest — and a
manifest needs all of them. So both participants invented that context, and
the sharpest entry in either log was about the consequence:

> I invented a registry prefix. This means the most concrete-looking field in
> the YAML is actually fiction.

These files supply that context, so a participant is challenged by **the
grant** rather than by guessing what infrastructure the service would have had.

## What these are not

**Not real deployments.** Nothing here is running anywhere. Every digest,
registry host, cluster-internal DNS name and Secret name is a fixture value
chosen to be realistic and consistent, not looked up. Do not copy one into a
cluster and do not treat a digest here as an artifact that exists.

They are grounded where it costs nothing to be: ports, environment variables,
storage needs and outbound destinations come from each service's own README,
so the decisions they force are the decisions that service really forces.

## Using one

Pick the service you chose, read its file, and write the manifest it needs. The
fixture deliberately does **not** tell you:

- which `Level` each dimension should carry
- which `isolation_floor` the workload warrants
- what the budget numbers should be
- which egress entries the grant should list

Those are the questions the study is asking. Everything else is given.

The schema is at [`schema/manifest.schema.json`](../../schema/manifest.schema.json),
and there are seven worked manifests in [`demo/`](../../demo).

| Service | Fixture | The decision it puts pressure on |
| --- | --- | --- |
| `lex-attest` | [lex-attest.md](lex-attest.md) | Isolation floor and egress — it holds a signing key and publishes to caller-supplied destinations |
| `lex-oms` | [lex-oms.md](lex-oms.md) | Egress — it is the hub of a stack and talks to several named services |
| `lex-guard` | [lex-guard.md](lex-guard.md) | Budget — it exists to bound spending, so two budgets meet |

## If the fixture is wrong

Say so in the log. A fixture that makes the manifest easier than reality would
make the study worthless, and the person who spots that is the participant, not
the author.
