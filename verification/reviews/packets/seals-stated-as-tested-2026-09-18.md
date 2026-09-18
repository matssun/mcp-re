<!-- SPDX-License-Identifier: Apache-2.0 -->
# Phase-1 census — the seals the estate states in prose and classes as `tested`

**ADR-MCPRE-068 Phase 1**, the estate-wide measurement the first three root decompositions
kept producing by accident. It is written as its own record because it is not one root's
finding: the same shape appears under five different roots, and it is the population
ADR-MCPRE-068 Phase 0D's eleven splits left behind.

ADR-MCPRE-068 §2 named one instance and called it the record's thesis:

> THM-0091's own statement names a structural fact: *possession of the scope IS that
> permission — there is no other constructor.* That is a seal, stated in the theorem, and
> the registry records the whole claim as `test://`.

This census asks how many more there are, and the answer is measured rather than estimated.

---

## 1. The measurement

Over `verification/policy/theorems.toml` and `verification.toml` on the current tree: every
live theorem whose **statement** asserts that something cannot be constructed, and whose
`supported_by` contains **no** `structural` unit; and every unit classed `tested` whose own
**description** asserts the same.

| | count |
|---|---|
| theorems stating a seal with no structural support | **6** (THM-0091 now closed → **5**) |
| units classed `tested` whose description states a seal | **5** |
| of those theorems at `critical` | 5 of 6 |

The vocabulary the census matches is the estate's own: *unconstructible*, *no other
constructor*, *possession is the proof*, *the representation is private/closed*, *no code
outside*, *cannot be assembled*, *no caller can*, *the only mutator*.

**The eleven units ADR-MCPRE-068 Phase 0D split are correctly excluded** — they now carry a
`structural` sibling, so the filter passes over them. That is the control on the census: it
finds the shape it was built to find and does not re-report the shape already fixed.

---

## 2. The five theorems

### THM-0108 — `proxy.kms_ed25519_seam`, `critical`

The clearest case in the repository, because the statement says it three times in capitals:

> **POSSESSION IS THE PROOF, three times.** At the seam where a provider's network client
> meets the provider-agnostic Ed25519 mapping, three types each make one wrong value
> UNCONSTRUCTIBLE rather than merely checked for.

Three seals in one claim, and the unit's own description says `unconstructible` too. Three
probes, not one: a proposition that names three types makes three constructions illegal, and
one compile refusal answers for one of them.

### THM-0029 / THM-0031 / THM-0033 — the peer-identity family, `critical`/`critical`/`high`

Units `proxy.channel_associated_identity`, `proxy.authenticated_relationship_peer`,
`proxy.current_authenticated_peer`. All three make the same argument in the same words, and
it is a **signature-shaped** seal rather than a field-privacy one:

> the derivation's whole parameter list is a credential and a policy: there is no parameter
> through which a separately obtained certificate, or a separately obtained identity product,
> could enter, so pairing credential A with an identity read from certificate B is
> **unconstructible rather than merely untaken**.

That is the CO-PROVENANCE shape Phase 0D-9 met at `proxy.trust_plan` (probe S14): the
function is total and refuses nothing, and the whole security content of its signature is
which values may enter it. The falsifier is a call that must not compile, not a check that
must not be deleted — and the statements say so in terms: *unconstructible rather than
merely untaken*, and *a runtime fingerprint comparison would have been the alternative*.

THM-0031's statement goes further and says what a behavioural control could not establish:
*that both predecessors ultimately arose from a connection establishes nothing — the defect
this excludes is precisely two honest products of two DIFFERENT connections.* A test
constructs one pair; the seal quantifies over every pair.

### THM-0062 — `proxy.delegated_signing_credential`, `critical`

> The snapshot is whole-value state — one `Option<Arc<..>>` swapped **entire** — so no
> partially mutated invariant can become visible.

A different seal shape again: not *who may construct* but *what may be observed mid-change*.
Whether a compile refusal is the right witness here needs the investigation §4 describes; it
may turn out to be a `proved` proposition about the swap rather than a `structural` one
about a representation.

---

## 3. The five units

| unit | severity | the phrase |
|---|---|---|
| `proxy.dispatch_commitment` | critical | *cannot be assembled* |
| `proxy.kms_ed25519_seam` | critical | *unconstructible* |
| `proxy.operator_facing_redaction` | high | *the representation is private* |
| `http_profile.submitted_hop_identity` | high | *the representation is closed* |
| `proxy.trust_plan` | medium | *no caller can* |

`proxy.trust_plan` already has a structural sibling (`proxy.trust_plan_co_provenance`, S14)
for the co-provenance fact; the phrase matched here is a **second** seal in the same unit's
description, which is its own question rather than a duplicate hit.

`http_profile.submitted_hop_identity` is the sharpest of the five, because its description
states both the seal and the reason for it:

> The representation is **closed** — a hop IS its retained request and response, entire —
> because a curated field list is how an identity comes to omit something, and the omission
> it already made is the defect this closes.

An identity type whose closure is the whole claim, recorded as a battery.

---

## 4. What the population is NOT

**It is not a worklist, and ADR-MCPRE-068 §1 is explicit about why.** Every one of these
needs the same investigation the eleven Phase-0D splits got, and its outcome is one of
three:

- **split** — the seal is real and separable: a `structural` sibling takes it, the behavioural
  half stays `tested`, and a probe attacks the exact boundary (the Phase-0D pattern, eleven
  times, and THM-0091's S22/S23);
- **not a seal** — the prose overstates what the representation does, and the CLAIM is
  corrected rather than the class;
- **a different class** — THM-0062's *swapped entire* may be a `proved` proposition about an
  atomic replacement rather than a `structural` one about a constructor.

**What a census like this must never do is bulk-reclassify**, for exactly the reason Ruling 3
gives: *do not collapse STRUCTURAL into TESTED merely because the mechanism is called a
mutation probe* — and the converse, do not promote TESTED into STRUCTURAL merely because the
prose uses the word.

---

## 5. Why the census is the deliverable and not a count

Two facts make this record worth more than its number.

**The prose was right and the registry was wrong, every time.** In all eleven Phase-0D cases
and in both of THM-0091's, the author had already written down the seal — in a doc comment,
a unit description, or the theorem's own statement — and the registry had no way to say it.
That is ADR-MCPRE-068 §3's defect stated as a measurement: *a security proposition's evidence
has a kind, and the assurance model has no term for it.* The authors knew the kind. The model
could not record it.

**The seal-shaped sentence is a reliable detector.** This census is a regular expression over
the estate's own vocabulary, and it found five theorems and five units with no false positive
that survived reading. A repository that writes down why a value cannot be forged is a
repository whose structural propositions can be enumerated mechanically — which is what makes
the Phase-2 discharge a finite, orderable job rather than an audit of everything.

**P2-S1** — investigate the five theorems in severity order (THM-0108 first, then the peer
family, then THM-0062), each under the Phase-0D procedure and ADR-MCPRE-068 §12.1's
producer-path accounting. THM-0108 needs three probes, not one.
**P2-S2** — the five units, same procedure.
**P2-S3** — add this census to `tools/verification/evidence-class-census` so the population
is re-measured rather than re-found by hand.
