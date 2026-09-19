# ADR-MCPRE-068 Phase 2 — CLOSED

Derived from the tree by
[`phase2_closure.py`](phase1-closure/phase2_closure.py), which re-measures every number below
from the registries rather than carrying one forward from a packet.

```
units                      192
probes                     304
units claiming mutation    170
units with >= 1 probe      170
claiming but not attacked  []
attacked but not claiming  []
tested units at >= medium  169
  of those, no falsifier   0
debt registry rows         0
compound probes            1
evidence classes           {tested 169, structural 15, proved 7, measured 1}
probes by ecosystem        {cargo 265, python 19, typescript 19, vector 1}

PHASE 2 CLOSURE: COMPLETE
```

## 1. What the closure criterion is

Phase 1 decomposed the twelve roots; Phase 2 discharged what that decomposition left owing.
The criterion is four facts, each mechanical:

| fact | measured |
|---|---|
| every `tested` proposition at effective Medium or above names a falsifier | **0** without one |
| no unit claims `mutation://` evidence nothing attacks | **0** claiming-but-not-attacked |
| no probe attacks a unit that does not claim it | **0** attacked-but-not-claiming |
| the N1 migration ratchet holds no rows | **0** |

The third is not redundant with the second. A probe attacking a unit whose evidence does not
declare `mutation://` runs outside the attestation closure — the suite could be deleted and no
unit's fingerprint would move, which is the ADR-MCPRE-069 shape of evidence that runs and
nothing claims.

## 2. Every `tested` unit is at Medium or above

169 units are classified `tested`, and **all 169** owe a falsifier under N1. There is no tail of
Low-severity tested propositions the rule does not reach; the rule's population and the class's
population are the same set.

One unit claims `mutation://` without being `tested`: `http_profile.admission_currency` is
`proved`, and carries a test battery, a Verus obligation and a falsifier together. That is
correct rather than anomalous — a proved proposition whose test battery also exists may have
that battery falsified, and the evidence classes are about what the CLAIM rests on, not about
which lanes may run.

## 3. What the numbers do not say

**304 probes is not 304 propositions.** Many units carry several, because a proposition with
several conjuncts needs one weakening per conjunct where the conjuncts compose — the
kms_endpoint_authority trio, the denylist pairs in both SDKs, the two registration leaves.
Counting probes measures the lane's size; counting units with at least one measures the
obligation.

**265 cargo probes against 19 + 19 SDK probes is not a coverage ratio.** The cargo lane existed
before this phase with 199 probes; Phase 2 added 66 of them and built both SDK lanes from
nothing. The Phase-1 closure derived that order deliberately: the SDK lanes had no mechanism at
all, so 27 obligations and two whole system roots were blocked on building each one once.

## 4. One compound probe, and why exactly one

`M282` is the only probe carrying `also` sites. The mechanism was built because the lane was
reporting a **false verdict** — three sites each enforce `post_close_emission` completely, so a
one-anchor weakening left every control green and the lane said the conjunct was not
load-bearing.

Every other multi-site case in this registry is **composition**, not defence in depth: each
check refuses a shape the others admit, so each is a separate conjunct with its own probe. The
packets record the distinction case by case, and the mechanism's own controls refuse a probe
that names one site twice.

## 5. What the phase found, beyond discharging

Twelve controls were written or repaired because a falsifier proved the existing battery could
not see the check it was about. They are the phase's second product, and each is recorded in the
slice packet that found it:

| shape | instances |
|---|---|
| a control asserting only the accepting direction | signer-policy hardening (Python), admission authority |
| a control whose prose named the adversarial case and whose assertions did not | JSON-RPC id correlation |
| a control testing a delimiter production does not use | the trust-resolver composite key |
| a conjunct declared and never tested | the wire-code substitution (both SDKs) |
| a control that could not fail for the reason it existed for | `toEqual` and the undefined key |
| a control measuring a different failure than the one that matters | continuation establishment, admission decode |
| document equality where the proposition is about bytes | exchange binding (both SDKs) |

## 6. Three ways a probe measures nothing

The lane reports one verdict for all three, and it should — each is *this probe demonstrated
nothing*, and each is for the author to adjudicate:

1. **the battery cannot see the weakening** — write a control;
2. **the mutation is a no-op** — `JSON.stringify(JSON.parse(x))` round-trips to the same bytes;
   the attestation commitments the e2e passes as `None`;
3. **the mutation does not build** — a fabricated grant for a type with no default, a
   `Zeroizing<String>` rendered with `{}`.

All three occurred in this phase, several times each.

## 7. The ratchet is empty and stays

`config/assurance-obligation-debt.toml` holds no rows. Every one it held at the baseline was
discharged by a falsifier **measured** to turn a declared control red — never by a waiver, a
reclassification or a bulk registration.

The file remains, because it is still the ratchet: a proposition that gains an N1 obligation by
being added, reclassified or raised in severity may not be written into it. With no rows left,
that rule now says exactly one thing — **every `tested` proposition at effective Medium or above
names a falsifier, or the gate fails.**
