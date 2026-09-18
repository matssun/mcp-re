<!-- SPDX-License-Identifier: Apache-2.0 -->
# Phase-1 census — falsifiers are counted per unit, claims are made per theorem

**ADR-MCPRE-068 Phase 1.** The `verifier_results` audit found two theorems that no probe
attacks while N1 reads them as satisfied, and called it *068's own defect one layer up*. This
packet asks how general that is, and the answer is: it is the shape of the whole registry.

---

## 1. The measurement

| | count |
|---|---|
| live theorems | **130** |
| named by at least one probe (`[[probe]].theorem`) | **51** |
| named by none | **79** |
| of those 79, ROOT-REACHABLE, **every** supporting unit covered, **none** owing | **22** |
| of those 22, `critical` | **11** |

**The first draft of this table said 25 and 14, and the looser rule is the reason.** It asked
whether *some* supporting unit carried a probe; the rule that matters asks whether **every**
supporting unit is either probed or not `tested`, **and** that none of them is in
`config/assurance-obligation-debt.toml`. A theorem one of whose units honestly OWES is not
this defect — its gap is recorded where a gap is supposed to be recorded, and counting it here
would inflate a population by the propositions the ratchet is already holding.

THM-0064 is the worked example of the difference. *A non-exporting custody selection keeps the
private key off this process* is supported by `proxy.custody_exposure` (`tested`, **owing**,
registered) and `proxy.custody_exposure_sole_producer` (`structural`, probe S17). Phase 0D-11's
own landing note says so: *"NOTED, not fixed: the `tested` half carries no `mutation://`
evidence — a pre-existing N1 gap the census counts."* It is counted, in the right place, and
it is not in the 22.

Under the strict rule, the count of theorems in the "covered but owing" bucket is **zero** —
so the 22 is not a sample of a larger honest population. It is the whole of the hidden one.

### 1.1 The 22

```
critical  THM-0003  admission verdict integrity
critical  THM-0006  presenter binding
critical  THM-0009  a presented continuation cannot bypass verification
critical  THM-0051  the pipeline holds, at dispatch, the verification product it was given
critical  THM-0052  a dispatched body was released by the decision a configured PDP made
critical  THM-0054  every production listener denies unknown client revocation state
critical  THM-0062  a response-signing credential exists only while a valid delegated key does
critical  THM-0066  the serving PEP resolves actors through the deployment's own seam
critical  THM-0074  NO UNEARNED DISPATCH                                    ← a declared ROOT
critical  THM-0090  a credential leaves this proxy only to the endpoint its text names
critical  THM-0091  the sidecar signs only for a request its ingress policy admitted  ← ROOT
high      THM-0001  admitted request parameters imply a current freshness window
high      THM-0005  a degraded admission is a CANDIDATE, and requires deployment consent
high      THM-0007  a typed artifact verifier admits only its own type
high      THM-0010  continuation handles match their presented inputs in role and order
high      THM-0044  an exchange's retry consequence never under-reports what may have run
high      THM-0045  the backend is reached only by consuming a fully assembled commitment
high      THM-0047  the verifier's assurance products are not substitutable
high      THM-0048  every listener obtains its whole security posture through one seam
medium    THM-0070  the record stream is honest about what reached it
medium    THM-0081  every production refusal is inside the exchange lifecycle
medium    THM-0088  a retention artefact reads as a crossing only for an exchange that had one
```

**Two declared roots are in the list.** THM-0074 and THM-0091 are named by no probe; their
supporting units are probed, and every probe under them names a different theorem.

**THM-0091 stays in the list even after its own decomposition lands**, and that is the sharpest
single argument for P2-T1: its two new falsifiers are `structural://` probes, and **the
structural registry has no `theorem` key at all**. A claim cannot be named by a structural
probe, whatever the probe establishes.

---

## 2. What the number does and does not mean

**It is not "25 propositions are unfalsified."** `[[probe]].theorem` is an OPTIONAL field:
133 of 180 mutation probes name a theorem, 47 do not, and the structural registry has no
`theorem` key at all — its 21 probes are attached to units only. So a probe that attacks a
conjunct of THM-0064 while naming no theorem is real evidence that this census cannot see.

**What it does mean is that the graph cannot tell the difference**, and neither can a
reviewer. The registry's own rule about what a falsifier is worth is stated per conjunct —
each probe carries `conjunct`, a sentence naming the property it deletes — and the link from
that sentence to the claim it belongs to is optional. So for 79 of 130 claims there is no
mechanical answer to *what would demonstrate that this proposition could fail*, and for 25 of
them the absence is hidden behind a unit that is covered for something else.

**The `verifier_results` case shows the two are genuinely different.** There, ten theorems
share one unit and the probes DO name theorems — 4/4/1/4/6/4/2/5 — and two theorems get
nothing. That is not a labelling gap; it is a coverage gap the labelling made visible. The
same gap under an unlabelled probe set is invisible by construction.

---

## 3. Why N1 cannot see it, and why that is not N1's bug

N1 is *any proposition classified `tested` whose effective severity is Medium or higher must
name at least one registered falsifier attacking its production property.* Its subject is a
proposition, and `_assurance_graph.unmet_obligations` evaluates it over `[[unit]]` — because
the unit is where `evidence_class` and the evidence URIs live.

When one unit supports several theorems, N1 has one answer for several questions. That is
correct for the object it is evaluated over and wrong for the object the rule is about, and
the discrepancy is exactly proportional to how far the unit layer lags the theorem layer.
`http_profile.verifier_results` is the extreme: **ten claims, one answer.**

**Two candidate remedies, and they are not equivalent.**

- **R1 — split the units** so that one unit supports one proposition, and N1's object and the
  rule's subject coincide. This is what Phase 0D did eleven times and what Phase 1-A/B/C did
  for three roots. It is the real fix, and it is expensive.
- **R2 — require `[[probe]].theorem`** and derive coverage per theorem, reporting a claim
  whose closure contains no probe naming it. This is cheap, it is a reporting change rather
  than an architecture change, and it does not fix the defect — it makes it visible, which is
  what the registry could not do here.

They compose: R2 first makes R1's worklist measurable rather than estimated, which is the
order ADR-MCPRE-068 §1 insists on — *do not solve the count before solving the architecture*,
and equally, do not estimate a population a measurement could give you.

---

## 4. Obligations

| id | obligation | severity |
|---|---|---|
| **P2-T1** | make `[[probe]].theorem` required on the mutation registry and add it to the structural one, backfilling the 47 + 21 that lack it. Each backfill is an adjudication — *which claim does this probe's conjunct belong to* — and is not a mechanical rewrite | high |
| **P2-T2** | derive per-theorem falsifier coverage in `tools/verification/review` and report a root-reachable claim whose closure contains no probe naming it. Report-only first, as N1 itself was | high |
| **P2-T3** | re-measure the 25 after P2-T1. The honest expectation is that it shrinks substantially — most will turn out to be labelling — and that what remains is the real population, which is what the `verifier_results` audit found by hand for two of them | high |
| **P2-T4** | THM-0074 and THM-0091 are declared ROOTS named by no probe. Whatever P2-T1 concludes for the rest, these two are worth adjudicating first: a system promise whose falsifier cannot be named is the one case where the labelling question and the coverage question have the same answer | critical |

---

## 5. What this census does not claim

It does not claim any of the 25 propositions is false, unevidenced, or under-tested. Every
one of them rests on a unit with a declared battery and a registered falsifier; what is
missing is the statement of **which claim that falsifier falsifies**. That is a registry
expressiveness defect of exactly the kind ADR-MCPRE-068 exists to fix — *a security
proposition's evidence has a kind, and the assurance model has no term for it* — arriving one
layer up, where what has no term is not the kind but the subject.
