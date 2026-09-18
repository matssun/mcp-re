<!-- SPDX-License-Identifier: Apache-2.0 -->
# ADR-MCPRE-068 Phase 1 — report, 2026-09-18

**Every declared root has been examined consequence-first. Four are decomposed; eight have a
measured, ordered correction.** That is the honest division, and it is stated first because
the completion criterion is not met and saying so is the whole point of this layer.

Phase 1 is complete when every root has *one owner per leaf*. Four do. For the other eight the
obstacle is measured and identical in every case: **five units each answer for several claims
at once**, and no root above them can have one owner per leaf until they are split. The
analysis that identifies which split, in what order, and on what evidence is done; the splits
are Phase 2's first work rather than this phase's residue.

**What this report is not**: a claim that the graph is now correct. It is a claim that the
graph's defects are now *named, measured and ordered*, which is what Phase 1 was for.

---

## 1. Roots

| root | severity | state | where |
|---|---|---|---|
| THM-0094 Python SDK | critical | **decomposed** — 10 leaves + 3 beside | #985, packet |
| THM-0095 TypeScript SDK | critical | **decomposed** — 11 leaves + 3 beside | #986, packet |
| THM-0091 sidecar ingress | critical | **decomposed** — 7 leaves, 2 structural | #987, packet |
| THM-0012 runtime lifecycle | medium | **decomposed** — 2 leaves, 1 structural | #989, packet |
| THM-0074 no unearned dispatch | critical | **audited** — the `verifier_results` finding | #988, packet |
| THM-0075 no unearned attribution | critical | **audited** — same finding | #988 |
| THM-0076 Rust client | critical | **audited** — same finding | #988 |
| THM-0077 configuration lattice | high | **audited** — 23 thm / 28 units; `tls_listener_state` answers for 3 claims | packet 1-I |
| THM-0078 refusal terminality | high | **audited** — severity inverted against the claim | packet 1-I |
| THM-0071 refusal provenance | medium | **audited** — the one whose labels already agree | packet 1-I |
| THM-0072 receipt registration | high | **audited** — 6 propositions in one unit; the novelty is in a 3-control owing unit | packet 1-I |
| THM-0042 retained correspondence | high | **audited** — three real authorities; one is a third-shape seal | packet 1-I |

**Four decomposed, eight audited.** Every root has a packet or is covered by one. The eight
audited ones have their leaf inventories, their per-root findings and their Phase-2
obligations; what they do not have is one owner per leaf, and §6 says exactly what stands
between them and it.

---

## 2. What landed

| | |
|---|---|
| mechanism | **obligation succession** — without it no decomposition of an owing proposition can be stated at all (#983, merged) |
| new units | 13 (Python) + 14 (TypeScript) + 7 (ingress) + 1 (lifecycle) |
| new structural units | 4, where there were 12 |
| new probes | 7 mutation, 4 structural |
| controls newly registered (ADR-069) | **46** Python + **139** TypeScript + **4** ingress |
| production corrections | 1 — `serve::bind` now obtains a `BindScope` |
| claim corrections requested | 6 (THM-0094) + 8 (THM-0095) + 4 (THM-0091), **none taken** |

### N1 population, per change

```
origin/main                         63   (34 critical, 19 high, 10 medium)
+ THM-0094 decomposition            75   (43, 20, 12)   13 by succession
+ THM-0095 decomposition            88   (53, 21, 14)   27 by succession
THM-0091 decomposition              63   unchanged — its leaves DISCHARGE N1
THM-0012 decomposition              63   unchanged — its new leaf is structural
```

**The count moving up is the rule working, not a regression.** One wide `tested` proposition
owing one falsifier became thirteen narrow ones owing one each, over the same production
code, at no higher severity — which is what succession's five clauses check. The two roots
whose leaves could be discharged were discharged; the two whose leaves cannot be are the two
whose falsifier lane does not exist (P2-B).

---

## 3. The six estate-wide findings

Each generalises something a single root's decomposition turned up.

**F1 — ten propositions over one unit** (#988). `http_profile.verifier_results`: 56 files, 73
controls, **ten theorems**, in three critical roots' closures. Two of the ten are attacked by
nothing while N1 reads them satisfied; an edit anywhere dirties all ten; 18 unnamed controls
are a credential-chain authority with no unit. The probes already carry theorem labels, so the
split is a re-partition of labelled evidence.

**F2 — the seal census** (#988). **Seven theorems and six units** state a seal in prose and
are classed `tested`; five are critical. The first run under-counted because the registries
hard-wrap prose and a regex over wrapped text measures the wrapping. THM-0108 says *POSSESSION
IS THE PROOF, three times* and needs three probes.

**F3 — a third seal shape the lane cannot express** (#988). `submitted_hop_identity`'s seal is
a COMPLETENESS boundary held by an exhaustive destructuring, so the hostile change is an edit
to an existing type and the refusal lands at an unmarked line. Neither probe kind expresses
it.

**F4 — what the estate establishes that MCP-RE does not promise** (#988). 43 units
NOT-ROOT-REACHABLE, 28 owing. **One candidate root** — remote signing custody — stated under
the five-step procedure and deliberately not added. **Fourteen units no theorem names at
all**, three of them critical.

**F5 — falsifiers are counted per unit, claims are made per theorem** (#988). 130 theorems,
51 named by a probe, 79 by none; **22 root-reachable ones are covered by nothing that names
them**, 11 critical, **two of them declared roots**. The probe→theorem link is optional and the
structural registry has no such key at all, so THM-0091 stays in the list even after its own
decomposition lands — which is the sharpest argument for requiring it.

**F6 — one shape, five times** (#988, packet 1-I). `verifier_results` answers for 10 claims,
`scitt_receipt_offline` for 6, `tls_listener_state` for 3, `exchange_lifecycle` for 3,
`audit_record_coordinates` for 3. Each names its several propositions **in its own
description**. None is wrong about what it establishes; each is wrong about how many things
that is — ADR-MCPRE-061 question 2, five times, and the single obstacle between eight roots
and one owner per leaf.

**Two of the six censuses were corrected in flight, and both by re-deriving the number rather
than re-reading the prose.** The seal census matched a regular expression against hard-wrapped
TOML and measured the wrapping. The coverage census asked whether *some* supporting unit was
probed rather than whether *every* one was covered and none owing. A campaign whose own
measurements need correcting twice is a campaign that should say so where its numbers are
read.

---

## 4. Claim corrections, batched for owner specification review

`scripts/claim_surface_gate.py` refuses a published root claim whose `theorem_claim` has moved
since the owner's review. **The control is correct and was not worked around.** Every
decomposition landed without touching prose or `depends_on`; the corrections are §10 of each
packet, stated as exact edits.

- **THM-0094** — narrow the correlation sentence to what `_exchange` reaches; add
  `depends_on = [THM-0058, 0059, 0060, 0061]`; record the PyO3 binding as uncovered; move the
  read bound to a stated non-claim; exclude request-side attribution; state the trust-anchor
  conjunct.
- **THM-0095** — the same five, plus the post-close clause, the anchor quantifier, and the
  empty-wire-code substitution.
- **THM-0091** — say that two of the facts it already asserts are structural; record the
  seal/decision split; record that the predicates it names are now in the closure.
- **THM-0012** — none. The statement was already right.

**None weakens or withdraws a promise.** THM-0094's F1 argues its correction *strengthens*
the support, because it names the cryptographic binding instead of a store lookup that cannot
fail.

---

## 5. Phase-2 dependency order, as it stands

1. **P2-B** — the falsifier lane has no Python or TypeScript ecosystem. It blocks **27** SDK
   leaves in both members of the root family, and nothing else can discharge them.
2. **P2-T1/T2** — require the probe→theorem link and derive per-theorem coverage. Cheap,
   report-only first, and it turns F5's 25 from an estimate into a measurement.
3. **F1's split** — `verifier_results` into ten. Phase 2's largest item; P2-T1 makes its
   worklist exact.
4. **P2-S1/S2** — the seal population, severity order, THM-0108 first with three probes.
5. **P2-A** — the PyO3 and napi bindings: 1,557 lines of critical-path Rust in no unit, in no
   fingerprint, with no tests.
6. **P2-N1** — the fourteen units no theorem names.
7. **P2-E** — `transport_e2e` skips in both SDKs on two different causes.
8. **P2-S4** — the third seal shape's probe kind.

---

## 6. The completion criterion, item by item

| criterion | state |
|---|---|
| explicit consequence | **12/12** — every root's consequence is stated in its own entry and restated in its packet |
| explicit severity | **12/12** — and N3 derives the rest; 39 propositions owe more than their own label |
| consequence-first decomposition | **4/12** decomposed, 8 audited with the obstacle named |
| no implicit proposition between root and leaves | **4/12** — the four decomposed ones; F6 is what blocks the rest |
| **one owner per leaf** | **4/12** — F6's five units are the whole of what stands in the way |
| production carrier per leaf | 4/12 stated per leaf; the other eight inherit their units' paths |
| honest evidence class per leaf | 4/12, plus the seal census's 13 candidates identified estate-wide |
| typed premises visible | **12/12** — 0C/0E deliver this; `review` prints the root→premise composition |
| composition correspondence represented | partial — F1's D3 and THM-0094's C1 are the two places it was measured and found missing |
| ADR-069 unclaimed evidence dispositioned | **3 projects**: Python 109 controls, TypeScript 167, ingress 21. 189 newly registered. The Rust estate's 626 remain 069's own |
| Phase-2 obligation identified where incomplete | **yes, everywhere** — 24 numbered obligations across seven packets |

**What Phase 1 owes, precisely: F6's five splits.** Every other criterion is either met or
blocked on them. That is a better position than the phase started in, where the obstacle was
not known to exist.

**One owner escalation exists and is not blocking**: the candidate root in F4. Root membership
is ratified, and `claim_surface_gate` requires a `security-boundary.md` §2 claim row, so it is
a two-document change that needs the ratification first. Phase-1 work continued past it, as
the brief directs.

**Three questions for the milestone ruling**, each of which changes what Phase 2 does:

1. **The claim corrections** (§4). Eighteen edits across three roots, none weakening a
   promise. They are the only thing this campaign could not do for itself.
2. **The candidate root** (F4). Ratify, decline, or defer — and if declined, the nine units
   under it stay NOT-ROOT-REACHABLE with their own severities, which is a legitimate outcome
   rather than a gap.
3. **F6's order.** The packet proposes `verifier_results` first because it answers for ten
   claims. An owner who wants the smallest instance first (`audit_record_coordinates`, three
   claims, five paths) to establish the procedure cheaply would be choosing differently for a
   good reason, and it is a choice rather than a derivation.
