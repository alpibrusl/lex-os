# The Manifest Cold Read

**Field study — [lex-os#89](https://github.com/alpibrusl/lex-os/issues/89) · lex-os, lex-iac, lex-k8s**

Every manifest these three projects have ever shipped was written by the person
who designed them. We need to know whether anyone else can. The thing we want
back is **the record of where you got stuck** — not a manifest that works.

| | |
| --- | --- |
| **Time** | About 90 minutes |
| **You may** | Read any README, doc or source |
| **You may not** | Ask the person who built it |
| **Deliverable** | The log at the bottom of this file |

---

## The one rule

**Don't ask the author.** Not a hint, not a quick sanity check, not "does this
look right".

The moment you'd want to ask is exactly the moment worth recording — that
question *is* the finding. Write it in the log, make your best guess, and carry
on.

A wrong guess costs nothing here. There is no production system on the other
end of this.

---

## What you're doing

1. **Pick a service you didn't build.**
   Three suggestions below. Any real deployment works.

2. **Write its manifest.**
   The grant, the egress allowlist, and the budget. If you pick the Kubernetes
   gate, also a `LexManifest` that names a parent.

3. **Run it through the gate.**
   Until it passes, or until you decide it shouldn't. Both are legitimate
   endings.

4. **Log every point you were unsure.**
   As it happens, not from memory afterwards. The memory of being confused
   fades faster than the confusion did.

---

## Pick one

Any of these, or something else with a real deployment. What matters is that
you didn't write it.

| Service | Why it's interesting |
| --- | --- |
| `lex-oms` | HTTP order management server. Talks to several other services, so the egress allowlist is a real decision. |
| `lex-telemetry` | Ingests device data. High volume, which makes the budget a real decision. |
| `lex-attest` | Signing sidecar. Holds keys, so the isolation floor is a real decision. |

---

## Where to read

| | |
| --- | --- |
| The runtime, the grant, and the boundary | `lex-os/README.md` |
| The gate between plan and apply | `lex-iac/README.md` |
| The Kubernetes admission wall | `lex-k8s/README.md` |
| What the box defends against, and what it doesn't | `lex-iac/docs/threat-model.md` |

Then, once you have a manifest:

```bash
lex-iac check --grant your-manifest.json --plan plan.json
```

```bash
lex-k8s admit --manifest your-manifest.json < pod-review.json
```

---

## What counts as finishing

Not a manifest that passes.

Twelve honest entries in the log and a manifest the gate refuses is a **better**
result than a clean pass and an empty log — the first tells us something we can
act on, the second tells us only that you're persistent.

If you give up, log why and stop. That's a finding too, and it's the one this
project would most like to know about.

---

## The log

Fill this in as you go. One line is plenty. Categories, pick one per entry:

- **Unsure** — didn't know what something meant
- **Guessed** — picked one and moved on
- **Chose wrong** — found out later it was wrong

**Name:**
**Service:**
**Date:**

| # | Category | Where | What stopped you |
| --- | --- | --- | --- |
| 1 |  |  |  |
| 2 |  |  |  |
| 3 |  |  |  |
| 4 |  |  |  |
| 5 |  |  |  |
| 6 |  |  |  |
| 7 |  |  |  |
| 8 |  |  |  |
| 9 |  |  |  |
| 10 |  |  |  |

*"Where" is a field, a doc, or a command — `grant.exec`, `lex-iac check`,
`README.md § the four walls`.*

---

<details>
<summary><b>For whoever is running this</b> — don't open if you're the participant; it names what we expect you to trip on.</summary>

<br>

Failure modes worth watching for. These are the ones a designer can't see from
inside, which is the whole reason for the exercise.

**Granularity.**
Does the participant reach for `aws.*` because naming verbs is tedious? If so
the wall is decorative in practice, however sound it is in principle.

**Which wall refused me.**
Four walls in each gate. When a refusal arrives, do they know which knob to
turn — or do they widen the grant until it passes, which is the same as not
having one?

**The exec lattice.**
Nothing in the manifest explains `None` vs `Sandboxed` vs `Full`. Someone who
can't rank three levels can't write a ceiling.

**The budget's two meanings.**
`max_money_cents` is committed reservation on a Kubernetes namespace and
forecast spend on a Terraform plan. Same field, different meanings, both
documented far from the field.

**Absence.**
"An empty allow-list grants nothing" holds in five places and is stated in every
README. Does anyone infer it before hitting it? Do they understand the refusal
when they do?

---

**An example of a useful entry:**

| # | Category | Where | What stopped you |
| --- | --- | --- | --- |
| 4 | Guessed | `grant.exec` | Picked `Sandboxed` because it sounded like the middle one. Couldn't find anything saying what the box actually stops me doing at that level, so I don't know if it's right. |

The useful part is the second sentence. "Picked Sandboxed" alone tells us
nothing; "couldn't find anything saying what it stops me doing" is a
documentation gap with an address.

</details>

---

*Nothing here is judged. Write plainly.*
