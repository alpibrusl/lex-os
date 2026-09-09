# The Manifest Cold Read — pass 3

**Field study — [lex-os#89](https://github.com/alpibrusl/lex-os/issues/89)**

Passes 1 and 2 asked whether someone could reconstruct the manifest
format from prose. Both failed at it, and they failed *differently* —
two authors, two invented schemas, neither the real one.

That was the wrong thing to ask. This project's own premise is that
trust rests on machine-checkable declarations rather than on anyone
reading the source, so "can you reconstruct the model from prose" tests
something the design deliberately does not depend on. Since those passes,
the thing it *does* depend on now exists:

- [`schema/manifest.schema.json`](../schema/manifest.schema.json) — every
  field, every level, what each one counts
- [`demo/*.json`](../demo) — seven worked manifests
- [`docs/cold-read-fixtures/`](cold-read-fixtures) — the deployment
  context no application repo carries

So pass 3 asks the question the design actually rests on:

> Given the formal spec, can an author **derive** a correct manifest —
> and do they understand the rules well enough to **break** them on
> purpose?

| | |
| --- | --- |
| **Time** | About 90 minutes |
| **You may** | Read anything in these repositories |
| **You may not** | Ask the person who built it |
| **Deliverable** | Two things: the manifests, and the table in part B |

---

## The one rule, unchanged

Don't ask the author. The moment you'd want to is the moment worth
recording.

---

## Part A — derive one that works

Pick a service and read its fixture:

| Service | Fixture |
| --- | --- |
| `lex-attest` | [cold-read-fixtures/lex-attest.md](cold-read-fixtures/lex-attest.md) |
| `lex-oms` | [cold-read-fixtures/lex-oms.md](cold-read-fixtures/lex-oms.md) |
| `lex-guard` | [cold-read-fixtures/lex-guard.md](cold-read-fixtures/lex-guard.md) |

Write the manifest it needs. It has to:

1. validate against `schema/manifest.schema.json`;
2. narrow the parent the fixture names —
   `lex-iac manifest narrow --parent <fixture's parent> --child <yours>`;
3. be accepted for a plan you write for it —
   `lex-iac check --grant <yours> --plan <plan.json>`.

**Reading `demo/manifest.json` first is not cheating.** It is what anyone
would do, and the previous two passes both missed those files entirely.

---

## Part B — break each rule on purpose

This is the part that distinguishes pass 3, and it exists because of a
problem the earlier passes could not detect.

Both previous participants produced confident, plausible, wrong
manifests. Nothing in the exercise could tell "understood it" from
"pattern-matched something that looked right" — a manifest that passes
proves the author produced something acceptable, not that they know why.

So the test is inverted:

> **You understand a constraint if you can produce an input that
> violates it — and say in advance what the refusal will be.**

For each rule below, write a manifest (and a plan, where the rule needs
one) that breaks *that rule and no other*, and **write down the refusal
you expect before running anything**. Then run it and record what you
actually got.

| # | The rule | Where to look |
| --- | --- | --- |
| 1 | A manifest's unknown fields are refused, not ignored | `schema/manifest.schema.json`, `lex-os#101` |
| 2 | A level is only accepted on a dimension that gives it a meaning | the schema's `Level`, `lex-lang#808` |
| 3 | A child may only narrow its parent | `lex-iac manifest narrow` |
| 4 | An empty allow-list grants nothing | lex-iac's README |
| 5 | A grant with `exec: None` cannot apply | `lex-iac apply` |
| 6 | Destroying state the grant does not name is refused | lex-iac's `reversibility` wall |
| 7 | A provider the mandate does not name is refused | lex-iac's `provenance` wall |
| 8 | An unpriced create is not an unpriced create of zero | run `check` without `--cost` |

lex-iac's walls are named in its output: `narrowing`, `reversibility`,
`budget`, `trust`, `unreadable`, `provenance`. Naming the right wall is
part of the prediction.

**Not every rule is a wall, and noticing which is part of the test.**
Some refusals happen before any wall runs — the manifest never parses, so
there is nothing to check it against. Those exit **2** ("could not run"),
not **8** ("refused"), and predicting a wall for one of them is a wrong
prediction worth recording as such. Exit codes: `0` allowed, `8` refused,
`2` could not run.

### The table to fill in

| # | Manifest you wrote | Refusal you **expected** | Refusal you **got** | Same? |
| --- | --- | --- | --- | --- |
| 1 |  |  |  |  |
| 2 |  |  |  |  |
| 3 |  |  |  |  |
| 4 |  |  |  |  |
| 5 |  |  |  |  |
| 6 |  |  |  |  |
| 7 |  |  |  |  |
| 8 |  |  |  |  |

**A mismatch is the finding.** Not a mistake to correct before
submitting — the whole point is to catch where the documented rule and
the real one part company, and a corrected table hides exactly that.

Three ways a row can be interesting, all worth recording:

- you expected a refusal and it was **admitted** — the rule is weaker
  than it reads;
- you expected one wall and got **another** — the rule is real but
  described in the wrong place;
- you could not construct a violation **at all** — either the rule is
  unbreakable by construction, which is the best outcome, or you could
  not work out what it forbids, which is the most useful finding in this
  document.

---

## Part C — the log, as before

Every point where you were unsure, guessed, or chose wrong. Categories:

- **Unsure** — didn't know what something meant
- **Guessed** — picked one and moved on
- **Chose wrong** — found out later it was wrong

| # | Category | Where | What stopped you |
| --- | --- | --- | --- |
| 1 |  |  |  |
| 2 |  |  |  |
| 3 |  |  |  |

Pass 3 should produce *fewer* of these than pass 2 in part A and more in
part B. If part A is still full of them, the schema did not do its job
and that is the headline.

---

## What counts as finishing

Not eight clean rows. **A table with three mismatches is a better result
than a table with none**, and a valid manifest in part A plus an empty
part B is the least useful outcome — it means the rules were followed
without being understood, which is precisely the state this study exists
to detect.

If you cannot break a rule, say so and say why you could not. That
sentence is worth more than the manifest.

---

<details>
<summary><b>For whoever is running this</b> — don't open if you're the participant.</summary>

<br>

**What changed since pass 2, and why.** Both earlier participants
invented a schema and proceeded confidently; neither converged on the
real one, and they did not converge on each other. Nothing in the
exercise could see the difference between comprehension and plausible
pattern-matching — which matters more here than in most projects,
because manifests are written by code agents and an agent that does not
know a field's name will invent one rather than stop.

Part B is the fix. A prediction that is wrong is visible; a manifest that
passes is not.

**What to watch for, beyond the table:**

- **Does part A get easier?** If the schema worked, the schema-shape
  questions from passes 1 and 2 should be gone and the *semantic* ones —
  which level, what unit, which isolation floor — should be sharper.
  If they are still asking what shape a field is, the schema is not
  discoverable enough.
- **Row 8 is the trap worth watching.** An unpriced create is treated as
  consequential, so a wildcard will not authorise it. Participants tend
  to read "no cost report" as "costs nothing".
- **Rows 4 and 1 pull in opposite directions on purpose.** An empty
  `allow` grants nothing; an empty `providers` is *no policy*. Someone
  who states both rules correctly has understood that one is authority
  and the other is provenance. Someone who states one rule twice has not.
- **A participant who cannot break rule 2** may have found something
  real: `Grant::new` is deliberately unvalidated in Rust, so the only
  path that refuses an axis-inappropriate level is deserialization.

**The known limits of this design.** It measures prediction, which is
closer to comprehension than "did it pass" but is not the same thing —
someone could pattern-match the refusal strings from the READMEs without
understanding the rule. Reading which *wall* they name, rather than
whether the wording matches, is the better signal.

</details>

---

*Nothing here is judged. Write plainly.*
