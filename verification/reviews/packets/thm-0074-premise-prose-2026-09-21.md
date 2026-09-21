# ADR-MCPRE-068 Phase-1 — THM-0074's dependency digest moves again, for one premise sentence

## What moved, measured

`THM-0074` is `sha256:7f350985cb9bc68f…` on `origin/main` (9e0ba722) and
`sha256:f2ea5dd15b779fdf…` on this branch. The two fingerprints were read from the tree on
each side, not derived.

Comparing the two component sets, **exactly one** entry differs:

| component | main | branch |
|---|---|---|
| `encoding_version` | 1 | 1 |
| `theorem_claim` | `sha256:9f4cc66a…` | `sha256:9f4cc66a…` |
| `theorem_dependencies[THM-0023]` | `sha256:5e77ea10…` | `sha256:f64459a6…` |
| every other premise | unchanged | unchanged |

THM-0074's own `statement`, `security_consequence`, `scope` and `depends_on` are untouched by
this branch. The root's claim digest is byte-identical on both sides. The movement is
entirely inherited from one premise.

## The premise edit

`THM-0023` — "Every peer identity value is well-formed, whatever evidence produced it" — had
a scope sentence whose trailing clause named a unit this branch deletes:

> The claim is over inhabitants of the type. Callers that reimplement the rules instead of
> constructing the type are outside it — which is why the trusted-ingress facade delegating
> rather than reimplementing is part of this unit's battery.

`unit://proxy.asserted_identity_delegation` no longer exists: the obsolete-surface work
deleted the `transport::ingress::v1` seam it was the battery for. Leaving the clause would
have stated a present-tense fact about a retired battery member. The sentence now reads:

> The claim is over inhabitants of the type. Callers that reimplement the rules instead of
> constructing the type are outside it.

### Why this is a correction and not a narrowing in either direction

The clause was *justification prose*, not a conjunct. It explained why a particular battery
member existed; it added no obligation to the claim and removed none. Dropping it leaves the
scope **weaker than or equal to** the reviewed text: the set of callers the theorem declines
to speak for is unchanged, and the claim over inhabitants of the type is unchanged.

This was checked in the other direction too, and the check found a defect. An intermediate
state of the cohort had replaced the clause with a positive universal — "every one of them
asks `interpret` for the value" — which would have been **stronger** than the reviewed text
at the moment the only caller-side edge was deleted, and `verification.toml` eleven lines
away still calls that delegation an open item. That was corrected before this measurement
(commit `225d77a4`). A relocation may make an equal or weaker claim, never a stronger one.

## Class

This is the same class as `THM-0074-prose-2026-09-18.json`, which recorded this root's
dependency digest moving because `THM-0098` and `THM-0119` had scope prose naming units a
split had retired. The shape repeats because the cause repeats: a root's fingerprint is
sensitive to prose in its closure, and deleting a unit obliges every sentence that named it
to stop.

## Assertions

- **Root consequence unchanged.** THM-0074's registered security consequence is not edited,
  and its `theorem_claim` digest is identical on both sides.
- **Product behavior unchanged.** The branch's product edits are deletions of surfaces with
  no production caller; no serving-path behaviour is added, removed or reordered by the
  sentence this record is about.
- **Severity unchanged.** `direct_consequence_severity = "critical"` before and after.

## What this record does NOT do

It does not restore THM-0023's own specification review, which is now `STALE_CLAIM` and is
recorded as such. `derive_review_state` is deliberately unmoved by a correction record: the
release path still asks the owner whether they read this text. This record authorizes the
**merge path** only, which is exactly the split `_claim_corrections.py` documents.
