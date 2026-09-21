# ADR-MCPRE-068 Phase-1 — THM-0023's scope loses a clause whose subject was deleted

## The subject

`unit://proxy.asserted_identity_delegation` owned the trusted-ingress facade's delegation to
the peer-identity value owner: the property that `transport::validate_asserted_identity_value`
asked `PeerIdentityValue::interpret` rather than reimplementing the well-formedness rules.

`RA3-002` deletes that facade. Measured on this tree:

- `grep` for `proxy.asserted_identity_delegation` across `*.rs`, `*.toml`, `*.json` and
  `*.md` returns **no live declaration** — every remaining occurrence is a retirement record
  written in the past tense (`docs/architecture/control-dispositions.md`,
  `docs/architecture/components/tls-and-transport-identity.md`, two ratification packets).
- `verification/policy/verification.toml` declares **no unit with that id**.
- The two surviving caller-side sites — `transport/mod.rs:185` and
  `transport/ingress/v2_wire.rs:112` — ask `PeerIdentityValue::interpret` directly.

## The exact text

**Before** (the fingerprint the owner reviewed, `sha256:72c13626…`):

> The claim is over inhabitants of the type. Callers that reimplement the rules instead of
> constructing the type are outside it — which is why the trusted-ingress facade delegating
> rather than reimplementing is part of this unit's battery.

**After** (`sha256:264ae664…`):

> The claim is over inhabitants of the type. Callers that reimplement the rules instead of
> constructing the type are outside it.

## Field-by-field derivation

| field | before | after |
|---|---|---|
| `statement` | *Every inhabitant of PeerIdentityValue is a non-empty, length-bounded string free of…* | **unchanged, byte-identical** |
| `security_consequence` | — | **unchanged, byte-identical** |
| `scope` | trailing clause present | trailing clause removed; all other sentences byte-identical |
| `depends_on` | `[]` | `[]` |
| `review_requirement` | Owner security-specification review | **unchanged** |
| `direct_consequence_severity` | `medium` | `medium` |
| `owner` | `proxy.peer_identity_value` | **unchanged** |
| `supported_by` | 3 units | 2 — loses `unit://proxy.asserted_identity_delegation` |

## Why the old clause became false, and why removing it expands nothing

The clause was **justification prose, not a conjunct**. Read it as an obligation and the
theorem would have claimed something about the facade's behaviour; read it as what it says —
*"which is why … is part of this unit's battery"* — it explains why a particular evidence
member existed. It asserted a fact about the **battery**, not about the inhabitants of the
type.

When the battery member was retired, the clause became a present-tense statement about
something that no longer exists. It could not be kept true by any edit that preserved it.

Removing it leaves the scope **weaker than or equal to** the reviewed text in the only sense
that matters to the claim surface: the set of callers the theorem declines to speak for is
**unchanged** — *callers that reimplement the rules instead of constructing the type are
outside it* — and the claim over inhabitants of the type is unchanged. Nothing the owner
accepted is weakened, removed or materially expanded; one sentence stopped naming a deleted
object.

### The strengthening direction was checked, and it found a defect

An intermediate state of this cohort replaced the clause with a positive universal:

> so the way this theorem reaches the trusted-ingress path is that no caller reimplements:
> every one of them asks `interpret` for the value.

That is **stronger** than the reviewed text, and it was written at the exact moment the only
caller-side edge was deleted — while `verification/policy/verification.toml` eleven lines away
still records the pinning as an **OPEN** item, and
`docs/architecture/components/tls-and-transport-identity.md:278` states plainly that nothing
in the graph pins that a *future* caller constructs the type rather than reimplementing.

A relocation may make an equal or weaker claim, never a stronger one. It was corrected at
commit `225d77a4` before this measurement, and the text recorded here is weaker than both the
intermediate and the reviewed wording.

## The proposition still has its evidence

The two surviving `supported_by` units are the ones that establish it:

- `unit://proxy.peer_identity_value` — the type's own construction and projection boundary,
  which is where "every inhabitant is well-formed" is decided;
- `unit://proxy.peer_identity_value_sole_producer` — that `interpret` is the only producer,
  which is what makes the quantifier over inhabitants meaningful.

The retired unit's evidence was about a **caller**, and the theorem's scope explicitly places
callers outside the claim. Its deletion therefore removes no evidence the proposition rests
on — which is the same fact, read from the other side, that makes the clause removable.

## What this record is not

It is not an owner specification review. `derive_review_state` reports `THM-0023` as
`STALE_CLAIM` after this correction and is meant to: the specification axis asks whether a
human read **this** text. The merge path may proceed on the recorded correction; the
release/closure path still asks the owner.
