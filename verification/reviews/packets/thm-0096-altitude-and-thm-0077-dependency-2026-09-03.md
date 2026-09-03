<!-- SPDX-License-Identifier: Apache-2.0 -->
# Owner review packet — corrected THM-0096, and THM-0077's dependency delta

**One packet, two subjects, one decision.** ADR-MCPRE-059 §14.7 / §28, issue #744 D1b′.
Layer 1: this is evidence about the tree, not an approval and not authoritative state.

Requested by the owner ruling of 2026-09-03, which accepted the D1b′ implementation and
its evidence, approved THM-0093 outright, and withheld THM-0096 for THEOREM ALTITUDE
alone. The correction is textual: no code, no unit, no evidence selector and no probe
weakening moved. THM-0077's dependency map is in the same packet because the ruling made
it the next review and because the two facts are one question — what THM-0096 claims, and
what THM-0077 therefore composes.

---

## 1. THM-0096 — corrected, awaiting review

### Title

The runtime installs exactly the continuation capability its plan names

### Statement

> For the `ContinuationControlPlan` presented to continuation materialization, a plan
> naming NO store produces no correlation store — not a node-local or in-process
> substitute — and an explicit OFF posture. A plan naming a shared store materializes and
> installs exactly that store and declares the capability ON. A named store that cannot be
> provided by this build, or that cannot be established, refuses startup and names what is
> missing; it is never announced as OFF.

### Security consequence

> Continuation materialization cannot silently weaken or widen the plan it receives. A
> named shared store cannot become OFF, and cannot become another store or a node-local one
> whose scope — one process, no replica switch — is not the scope the plan names; so
> cross-replica human-approval flows cannot silently become uncorrelated. A plan naming no
> store cannot acquire a fallback capability. The posture the runtime reports is the posture
> it holds.

### Scope

Five paragraphs, verbatim in `verification/policy/theorems.toml` and rendered in
`verification/generated/theorem-index.md`. What changed, and what did not:

| paragraph | state |
|---|---|
| PLAN → RUNTIME ONLY, and the neighbours that own the adjacent facts (THM-0093, THM-0087) | **reworded** from "CONFIGURATION PROJECTION ONLY" |
| IT DOES NOT ESTABLISH WHERE THE PLAN CAME FROM, plus the one-way direction | **new** |
| the acknowledged-write fact is not used | unchanged |
| not a liveness claim | unchanged but for plan-relative wording |
| THE DECLARATION CONJUNCT IS CLAIMED AT THE STRENGTH ITS EVIDENCE HAS | unchanged |

The paragraph the ruling required, verbatim:

> IT DOES NOT ESTABLISH WHERE THE PLAN CAME FROM. THM-0096 says nothing about the origin of
> the `ContinuationControlPlan` and does not establish that the plan faithfully represents
> validated deployment configuration. That is a parent composition/configuration fact. This
> leaf therefore does not say that the OPERATOR or the VALIDATED DEPLOYMENT selected what the
> runtime installs; it says only that the runtime installs what its plan names.
>
> The direction is one way, and this claim never reaches its premise downward through its own
> consumer: validated configuration -> (parent composition facts) -> `ContinuationControlPlan`
> -> (THM-0096) -> runtime capability and posture -> (composed by) THM-0077's root claim.
> THM-0077 combines the parent composition fact with THM-0096's plan → runtime materialization
> proposition; THM-0096 is a premise of THM-0077 and obtains nothing from it.

The sentence the ruling removed is gone rather than relocated: the previous scope's *"That
the plan is a faithful projection of the validated configuration is the planner's fact,
reached through THM-0077 rather than asserted here"* is deleted. Reaching a premise through
a consumer is the defect; naming it as a boundary of this leaf, as the new paragraph does,
is not the same sentence.

### Dependencies

`depends_on = []` — unchanged, and now correct rather than tolerated. The corrected claim
states only the plan → materialization relation, so it needs no premise; the ruling's
instruction not to add an edge merely to preserve the old wording is satisfied by removing
the wording instead.

### Supporting units and evidence — unchanged

| unit | why it exists separately |
|---|---|
| `unit://proxy.continuation_materialization` | the default build profile's arm of the seam |
| `unit://proxy.continuation_materialization_shared` | the `redis_replay` arm; `test_features = ["redis_replay"]`, because the two arms are mutually exclusive at compile time and no single lane runs both |
| `unit://proxy.continuation_installation` | the composition root's half — `Established<T>`'s coupling ends at `into_parts`, and everything after the split is `app.rs`'s |

Mutation probes M89 (OFF does not install a local tier) and M90 (a named store this build
cannot carry is never announced OFF) are unchanged in weakening, anchor and `expect_red`.
Their `conjunct` strings were reworded plan-relative for consistency with the corrected
claim; neither unit declares `mutation://` evidence, so no unit fingerprint moved.

### Assumptions

None. No supporting unit carries a registered assumption, and the corrected claim adds no
premise about backend behaviour — the acknowledged-write fact remains outside it.

### Fingerprint

```
THM-0096  sha256:97fb6e966903e09f0e9fedf634f46a536bafa48384318a88200955a692e4ad4a
  theorem_claim         sha256:033bf43215d5609849ab29b30e6d84cd709306a05495236471d9dd7a6adb1b13
  theorem_dependencies  {}
  review_requirement    Owner security-specification review
```

Current review status: `UNREVIEWED` — this theorem has never carried a record, and the
correction is being reviewed before its first one.

---

## 2. THM-0077 — dependency-only review

### The claim text did not move

Confirmed by digest, not by reading: the reviewed record
`verification/reviews/specification/THM-0077.json` names
`theorem_claim = sha256:c37c7e0bbf738372218737fd9687e7d808198485c7ba74d1ea2652d40e35315d`,
and the claim's digest at this tree is the same value. Title, statement, security
consequence, scope, owner, `supported_by` and `review_requirement` are byte-identical to
what was reviewed. Only the transitive dependency closure moved.

For reading, unchanged:

> **No deployment serves a posture nobody selected.** Every security capability held by the
> serving runtime is derived from validated semantic owner state. Illegal, unsupported or
> internally contradictory deployment postures cannot be silently reinterpreted into a
> weaker posture during materialization or serving.

### Closure delta

| | reviewed record | this tree |
|---|---|---|
| members | 17 | 20 |
| added | — | **THM-0089, THM-0090, THM-0096** |
| removed | — | none |
| moved digest, same id | — | none |

The reviewed closure was THM-0005, THM-0013, THM-0025, THM-0026, THM-0027, THM-0035,
THM-0036, THM-0037, THM-0038, THM-0048, THM-0049, THM-0054, THM-0064, THM-0066, THM-0067,
THM-0073, THM-0086. THM-0089 and THM-0090 (the #742 D5 endpoint-authority pair) and
THM-0096 (this packet's leaf) are the three additions. No existing member's own digest
changed, so nothing already reviewed under this root was weakened.

### What the added THM-0096 edge now means

The edge is where the composition happens, and the registry says so at the edge:

> THE COMPOSITION HAPPENS HERE. THM-0096 does not establish that the plan represents
> validated deployment configuration, and may not: it is a premise of this root, so it
> cannot obtain that proposition downward from it. THIS claim combines the parent
> composition fact — the plan is derived from validated owner state — with THM-0096's
> plan → runtime materialization proposition, and the conjunction is what yields "no
> deployment serves a continuation posture nobody selected".

THM-0087 remains deliberately absent from this closure, per the ruling of 2026-09-01.

### Fingerprint and status

```
THM-0077  sha256:fa01e636e65ae3f0c005033819ef3d80b913e7b6bf180720a478d8de15eb5aef
  theorem_claim         sha256:c37c7e0bbf738372218737fd9687e7d808198485c7ba74d1ea2652d40e35315d  (unmoved)
  theorem_dependencies  20 members
```

Current review status: `STALE_DEPENDENCY_CLAIM: changed since review: theorem_dependencies`
— the axis reports exactly the delta above and nothing else. THM-0077 is **not**
re-affirmed by this packet; the record stays stale until the owner rules on the delta.

---

## 3. What this packet does not ask for

SDK roots and THM-0042 are deliberately not here. THM-0093 is already recorded, at
`sha256:d6ef239d78010f4f37f3b51c976f17b643e0f740cc14c425ed72da76cbc28370`, the value the
ruling named and remeasured before the record was written.

---

## 4. Addendum — the THM-0077 fingerprint in §2 was measured one edit early

Recorded at merged main `7d7a923a`, after the ruling of 2026-09-03 approved both subjects
conditional on remeasurement.

**THM-0096 remeasured exactly**, `sha256:97fb6e966903e09f0e9fedf634f46a536bafa48384318a88200955a692e4ad4a`,
and its owner specification review is recorded.

**THM-0077 did not**, and the approval is therefore NOT transferred:

```
named in §2 (branch state)  sha256:fa01e636e65ae3f0c005033819ef3d80b913e7b6bf180720a478d8de15eb5aef
at merged main 7d7a923a     sha256:2164f33aae3c49b1ac183ef0559f9b1ad7601ca440e92ca36d1a2b40387ded2a
```

**The changed component is `theorem_dependencies["THM-0096"]`, and nothing else.** The defect
is in this packet, not in the tree: §2's fingerprint was taken from the branch before the last
two wording passes over THM-0096's scope — the ASCII direction diagram was replaced by an
arrow chain that survives the generated view's line flattening, and one liveness-paragraph
sentence was made plan-relative. §1's THM-0096 fingerprint WAS updated for both; §2's THM-0077
fingerprint was not, so the packet quoted a root digest computed over a claim digest the same
packet no longer named.

What that means for the review, stated rather than assumed:

* `theorem_claim` is `sha256:c37c7e0bbf738372218737fd9687e7d808198485c7ba74d1ea2652d40e35315d`
  at merged main — identical to the reviewed record and to §2. The claim text still did not move.
* The closure is still 20 members: +THM-0089, +THM-0090, +THM-0096, none removed.
* Nineteen of the twenty dependency digests are byte-identical to the values §2 was computed
  over. The twentieth, THM-0096, now carries
  `sha256:033bf43215d5609849ab29b30e6d84cd709306a05495236471d9dd7a6adb1b13` — which is the claim
  digest inside the THM-0096 fingerprint the ruling named and approved.

So the delta is the approved correction arriving in the root's closure, and the value to
re-affirm over is `sha256:2164f33aae3c49b1ac183ef0559f9b1ad7601ca440e92ca36d1a2b40387ded2a`.
The record stays `STALE_DEPENDENCY_CLAIM` until the owner names that value; recording it on the
strength of an approval given over a different digest is precisely the transfer the
remeasurement condition exists to refuse.
