<!-- SPDX-License-Identifier: Apache-2.0 -->
# Phase-1 audit — the five roots whose decomposition already exists

**ADR-MCPRE-068 Phase 1.** Four roots had no decomposition and got one (THM-0094, THM-0095,
THM-0091, THM-0012). Three were audited through the `verifier_results` finding (THM-0074,
THM-0075, THM-0076). These five are the remainder, and they are a different case again: each
has a real decomposition already, so the Phase-1 question is not *what are the propositions*
but **are the leaves honest, and does the graph say what the claim needs.**

| root | severity | closure | direct units | owing |
|---|---|---|---|---|
| THM-0077 no deployment serves a posture nobody selected | high | 23 thm / 28 units | 2 | 8 |
| THM-0078 refusal is terminal | high | 12 / 10 | 2 | 2 |
| THM-0072 a verified receipt proves registration on the pinned service | high | 3 / 2 | 2 | 1 |
| THM-0042 retained evidence is the evidence the statement was about | high | 1 / 3 | 3 | 2 |
| THM-0071 every reachable refusal has a typed provenance | medium | 7 / 6 | 2 | 2 |

---

## 1. THM-0077 — the deepest closure and the thinnest direct support

23 theorems and 28 units in the closure; **two direct units, one file each, three and five
controls.** `proxy.trust_composition_root` and `proxy.cross_machine_legality` are the two
halves of layer A's legality boundary, and they are the right two — but the root's statement
is a universal over *every security capability held by the serving runtime*, and the direct
support is a pair of source-text inventories.

That is not a defect by itself: a universal over owners is exactly what an inventory control
establishes, and both units say so (*"measured over ALL owners, not only trust — the inventory
the controls check is the whole set of `values.<field>` reads"*). It is worth recording
because it is the one root where the direct support is deliberately narrow and the weight is
carried by 23 premises, which reads as thin support until you follow the edges.

**Finding 1-77a.** 12 theorems in this closure are named by no probe; all 12 are inside the
population of `theorem-falsifier-coverage-2026-09-18.md` and need no separate obligation here.

**Finding 1-77b.** `proxy.tls_listener_state` is 11 paths — the widest unit in the closure
after `verifier_results` — and supports THM-0048, THM-0054 and THM-0103. Three claims, one
unit, the same shape as F1 one order of magnitude smaller. **P2-77** — examine it under the
`verifier_results` procedure once that one is done; it is the second instance, not a new kind.

---

## 2. THM-0078 — the one whose leaf sizes are inverted

`proxy.exchange_lifecycle` carries **43 controls over three files** and is `high`;
`proxy.refusal_provenance` carries 14 over two and is `medium` **and owes**. The root is
*refusal is terminal, and no refusal-side effect reads as success* — and the second half of
that sentence, the one about refusal-side effects being authorized by the state they were
reached from, rests on the unit that owes a falsifier.

**Finding 1-78a.** The severity is inverted against the claim. `refusal_provenance` is
`medium` by its own direct label, inherits `high` from this root, and is the leaf the root's
second clause depends on. That is N3 working — its effective severity is `high` — and it is
also the reason its falsifier is the first one to write in this closure.

**Finding 1-78b.** `proxy.exchange_lifecycle`'s description names three propositions: which
`(state, event)` pairs are legal, that the backend projection cannot disagree with the
exchange state, and that retry consequence never moves backward. Three authorities, 43
controls, one unit — a third instance of F1's shape. **P2-78.**

---

## 3. THM-0072 — a 14-path unit under a 2-unit root

`http_profile.scitt_receipt_offline` is 14 paths and 24 controls, and its description lists
**six** propositions: the statement's own signature, its CWT attribution, the receipt's shape,
the RFC 9162 inclusion fold, the service's signature over the root the fold derived, and the
position commitment. Six authorities named in one sentence.

**Finding 1-72a.** A fourth instance of F1. It is also the cleanest candidate for the
`verifier_results` procedure at small scale, because the six are separated by RFC section
rather than by judgement.

**Finding 1-72b.** `http_profile.scitt_service_pin` — 3 paths, 3 controls, `high`, **owing** —
carries *the pin describes one reviewed document*. The root's whole distinguishing claim is
`PROJECTED FROM` a pin rather than a key supplied to the call, so this small owing unit is
where the root's novelty lives. **P2-72** — its falsifier before the other's split.

---

## 4. THM-0042 — already three authorities, and one is a seal

The only root in this group whose direct units are genuinely three different authorities:
correspondence (`scitt_retained_correspondence`), submission identity
(`submitted_hop_identity`), and a corpus on disk (`conformance.retained_corpus`). No
intermediate theorems, and none are needed — the packet convention gives a leaf a `THM` only
where it is a reusable premise across a theorem boundary or needs owner review.

**Finding 1-42a.** `http_profile.submitted_hop_identity` states a seal
(*the representation is closed — a hop IS its retained request and response, entire*) and is
classed `tested`. It is in the seal census, and it turned out to be a **third seal shape** the
Phase 0B lane cannot express — the completeness boundary held by an exhaustive destructuring.
See `seals-stated-as-tested-2026-09-18.md` §3 and **P2-S4**.

**Finding 1-42b.** `conformance.retained_corpus` is the only unit in this root's support whose
verdict is reached *over an artifact on disk rather than over a value a test constructed*, and
the scope says so. That is a `measured`-shaped proposition sitting in a `tested` unit — it has
a corpus, a protocol, and an artifact — and it is worth asking whether Ruling 4's four fields
are available for it. **P2-42.**

**Finding 1-42c, recorded because it is right.** The scope explains why the `s01` interop
vector is **demoted in place** rather than regenerated: *that no MCP-RE code produced it is the
whole value of that vector, and regenerating it would destroy a real interop claim to fix a
different one.* That is a conformance-scope decision made correctly and against the easier
option.

---

## 5. THM-0071 — the one whose quantifier is the whole claim

*Every **reachable** in-exchange refusal* — and `proxy.refusal_site_totality` (5 paths) is
what establishes the quantifier. The root shares `refusal_provenance` with THM-0078, which is
correct: one authority, two consumers.

**Finding 1-71a.** Both direct units are `medium` and the root is `medium`, so nothing here
inherits upward — this is the one root in the group whose leaves' direct labels and effective
labels agree, which makes it the cheapest to complete.

**Finding 1-71b.** `proxy.audit_record_coordinates` (5 paths, 13 controls) names three
propositions in its description — a request record always states an authorization outcome, a
response record has none to carry, and the two verdicts occupy separate coordinates. A fifth
instance of F1's shape at small scale.

---

## 6. What the five have in common

**Four of the five contain at least one unit that names several propositions in its own
description.** `tls_listener_state` (3 claims), `exchange_lifecycle` (3), `scitt_receipt_offline`
(6), `audit_record_coordinates` (3). With `verifier_results` (10) that is **five instances of
one shape**, and it is the shape ADR-MCPRE-061 question 2 exists to catch:

> An answer to question 1 that needs an "and" is evidence of a shallow authority boundary.

Every one of these units answers question 1 with a list. None of them is wrong about what it
establishes; each is wrong about how many things that is.

**P2-U1** — after `verifier_results`, apply the same procedure to `tls_listener_state`,
`exchange_lifecycle`, `scitt_receipt_offline` and `audit_record_coordinates`, in that order.
The order is by how many claims each one answers for, which is the measure of how much of the
graph its undifferentiation hides.

---

## 7. What the audit did NOT find in these five

- **No incorrect root statement.** Unlike THM-0094 and THM-0095, none of the five asserts
  something production does not do. THM-0077's universal, THM-0078's two clauses, THM-0072's
  `PROJECTED FROM`, THM-0042's field-by-field equality and THM-0071's reachability quantifier
  are each precise and each carry their own boundary sentence.
- **No missing `depends_on`.** THM-0077's 23 and THM-0078's 12 are real edges; THM-0042's and
  THM-0072's absence is correct — they rest on units, not on other claims.
- **No candidate root.** The one candidate this campaign found is in
  `not-root-reachable-census-2026-09-18.md`, and it is not in any of these closures.
