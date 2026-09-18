<!-- SPDX-License-Identifier: Apache-2.0 -->
# ADR-MCPRE-068 Phase 1 — THM-0074 "No unearned dispatch", decomposed consequence-first

The largest root in the estate: `critical`, 25 declared dependencies, a 48-theorem closure,
19 distinct semantic owners. Decomposed downward from the consequence, and the root statement
attacked before anything under it was.

## 1. The consequence, stated precisely

If THM-0074 is false, a caller reaches the backend of a deployment that believes it enforces
a pre-dispatch obligation, without having satisfied that obligation. The registered
consequence names five ways, and they are five different defects rather than one restated:

| # | the attack | which proposition below fails |
|---|---|---|
| A | omitting evidence entirely | R4 (ordering) |
| B | presenting evidence for a DIFFERENT exchange | R6 (correspondence) |
| C | presenting a fact the deployment did not select the authority for | R1 (selection) |
| D | handing the pipeline a security value the caller constructed | R5 (consumption) |
| E | having some OTHER exchange's establishment succeed | R6 (correspondence) |

The blast radius is the whole serving product: every deployment, every request, and the
failure is silent — a successful dispatch is indistinguishable from an earned one.

## 2. Falsifying the root statement, before decomposing it

Four attempts. The fourth succeeded and is §3.

**Attempt 1 — can the backend be reached without a `ReadyForDispatch`?** No. THM-0045 holds
the type gate and `scripts/authorization_provenance_gate.py` rule 7 measures it over
production text: `InnerPlane::prepare` takes an `AuthorizedRequestBody`, `ReadyForDispatch::new`
takes the `PreparedInnerDispatch` it returns, that body type has exactly one producer, and the
serving assembly calls it once. A pipeline that dropped the decision would not compile.

**Attempt 2 — does an unconfigured deployment dispatch unearned?** It dispatches; the unit's
own control says so by name (`an_unconfigured_deployment_still_releases_a_body`). It is not a
counterexample: the statement quantifies over obligations SELECTED, and an unconfigured
policy selects none. THM-0052 is what stops that from being a hole — the released body came
from the decision a configured policy produced, when one is configured.

**Attempt 3 — is "the same relevant request, actor, subject and exchange" four claims with
fewer than four owners?** No. Measured: request → THM-0040 (`a decision about that very
request`); exchange → THM-0051 (`the verification product of this very exchange`) with
THM-0079 making distinct exchanges distinguishable; subject → THM-0034, which is explicit
that the relation is to the SUBJECT and never to the composite actor id; actor → THM-0066
with THM-0099. Four coordinates, four owners, no coordinate resting on another's control.

**Attempt 4 — what does "selected by the validated deployment" name?** This one succeeded.

## 3. The finding: the antecedent quantified over a set nothing pinned

The statement's antecedent is *every pre-dispatch security obligation **selected by the
validated deployment***. That phrase is load-bearing: it is what makes attack C above a
violation rather than a definition. But nothing in the closure said the set of obligations
the serving runtime actually holds IS the operator's validated selection.

Measured, not argued:

```
THM-0074 closure: 48 theorems
  THM-0077 in closure: False      (No deployment serves a posture nobody selected)
  THM-0067 in closure: False      THM-0038: False   THM-0013: False   THM-0048: False
  THM-0049 in closure: False      THM-0054: False   THM-0073: False   THM-0102: False
```

The entire posture-selection family is absent. So if a deployment posture were silently
reinterpreted into a weaker one during materialization, THM-0074 would still hold — vacuously,
about a set nobody chose — and its consequence would be false while its statement was true.
That is the definition of a missing premise.

**This is not the disclaimer the root already carries.** Its scope says "this is a claim about
the selected set, not a claim that the set is right". That refuses ADEQUACY — whether the
operator chose enough obligations, which is correctly outside a dispatch claim. The missing
premise is IDENTITY — whether the set being served is the set that was validated. The scope
disclaims the first and is silent on the second, and the two are independent: a perfectly
adequate selection can be silently weakened at materialization.

**Disposition: dependency correction.** `THM-0077` added to THM-0074's `depends_on`, recorded
through the correction register. No cycle: THM-0077's own 22-theorem closure does not contain
THM-0074 (measured), and the two closures overlap in 5 theorems.

The root's STATEMENT is unchanged. Nothing is weakened, removed or expanded — the claim
already rested on this premise and now says so.

## 4. The propositions the root decomposes into

Consequence-downward. Each leaf: one proposition, one semantic owner, one production carrier,
one honest evidence class.

### R1 — SELECTION. The obligation set the runtime holds is the deployment's validated selection.
* owner: `proxy.trust_composition_root` (via THM-0077)
* carrier: `mcp-re-proxy/src/app.rs`, plus the owner types it composes from
* evidence: `tested` — and see §6, this is the newly named premise

### R2 — ESTABLISHMENT. Each selected obligation was established by ITS owning authority.
The per-obligation leaves, by authority. Nothing here is recreated by a neighbour;
R-COMPOSE is the rule and the provenance gates are what measure it.

| obligation | owner | class | falsifier |
|---|---|---|---|
| request verification product | `http_profile.verifier_results` | tested | mutation |
| admission currency (4 leaves) | `http_profile.admission_currency` | **proved** | verus + mutation |
| admission assertion authenticity | `http_profile.admission_assertion` | tested | — (§5) |
| continuation unbypassability | `http_profile.continuation_unbypassability` | **proved** | verus |
| replay admission | `proxy.replay_admission_gate` | tested | mutation |
| continuation leg binding | `proxy.continuation_leg_binding` | tested | mutation |
| authorization decision | `proxy.pdp_decision_relation` | tested | mutation |
| peer identity provenance | `proxy.serving_identity_provenance` | tested | — (§5) |

### R3 — INPUT DISCIPLINE. Each authority consulted the inputs its obligation is defined over,
and authoritative state is never substituted by something the request carried.
* owners: `proxy.serving_trust_seam` (THM-0066, THM-0099), `proxy.trust_plane_runtime`
  (THM-0097, THM-0100), `proxy.trust_document_interpretation` (THM-0098),
  `proxy.serving_identity_provenance` (THM-0080)
* this is the leaf the root's own scope states in terms, and it is the one where a
  request-carried substitute would be invisible to every behavioural control downstream

### R4 — ORDERING. Establishment happened before the invocation.
* owner: `proxy.dispatch_commitment` (THM-0045), with `proxy.exchange_lifecycle` (THM-0043)
  deciding the relation everywhere and `proxy.exchange_transition_ownership` (THM-0101)
  making the machine's state imply the stages it names ran
* carrier: the type gate — `structural` in effect, `tested` as declared (§6)

### R5 — CONSUMPTION. The pipeline consumed the EARNED product, not a value it built.
* owner: `proxy.dispatch_commitment` (THM-0051, THM-0052)
* carrier: **`scripts/serving_product_provenance_gate.py` and
  `scripts/authorization_provenance_gate.py`** — source-text gates, because
  `VerifiedMcpRequest` has public fields and the Verus obligation on `prepare_http_dispatch`
  reads `request_block` as a FIELD, so the seal is unavailable and a proved postcondition
  outranks it
* ADR-MCPRE-069: both gates were unowned. Dispositioned REGISTER — see
  `source-text-falsifiers-2026-09-18.md`

### R6 — CORRESPONDENCE. Four coordinates, four owners. Attempt 3 above.

## 5. Honest evidence classes, and the debt inside this root

Nineteen owners. Thirteen carry a registered falsifier. Six do not, and every one is already
a registered N1 obligation — so this root's decomposition manufactured no new debt and
uncovered no hidden debt:

```
http_profile.keyid_selector          IN REGISTRY eff=critical
http_profile.admission_assertion     IN REGISTRY eff=critical
http_profile.replay_key              IN REGISTRY eff=critical
proxy.serving_identity_provenance    IN REGISTRY eff=critical
http_profile.request_envelope        IN REGISTRY eff=critical
proxy.trust_composition_root         IN REGISTRY eff=high
```

`proxy.trust_composition_root`'s row is discharged by M172 on the source-text falsifier
slice, now merged. (The probe was numbered M149 when this packet was first written; main
had independently taken M149-M152 and M154, so the slice renumbered to M172-M177 before
merge.) The other five remain open and are NOT discharged here —
Phase 1 decomposes, it does not discharge.

Two owners are `proved` rather than `tested`, and the classification was checked against the
proposition rather than against the URI: `http_profile.admission_currency` carries a Verus
obligation over the currency comparison, and `http_profile.continuation_unbypassability`
over the bypass predicate. Neither was reclassified.

## 5b. Recomputed severity (N3), and what the new edge cost

`effective = max(direct, inherited)`, derived and never stored — so placing a `critical` root
above THM-0077 moves the derivation for everything in THM-0077's closure that was not already
critical. Measured by re-running the gate to a fixpoint rather than predicted:

| unit | field | was | now |
|---|---|---|---|
| `proxy.trust_composition_root` | effective, inherited | high | critical |
| `proxy.continuation_installation` | effective, inherited | high | critical |
| `proxy.continuation_materialization_shared` | effective, inherited | high | critical |

Three rows, all DERIVATION CORRECTIONS in the gate's own sense: same proposition, same
production carrier, same obligation, and `direct_consequence_severity` untouched on all
three — which is the field that would have to move for this to be a reclassification. The
registry did not grow and nothing returned to `unreviewed`, and the population was
unchanged by this edit with three of its rows now correctly sized. The absolute count
this packet first recorded (75) was a branch-local measurement and is not repeated
here: the merged Phase-1 tree is the only authority for it, and the closure report
derives it there.

This is the cost of the correction, and it is the right direction: the graph was
UNDERSTATING what depends on these three.

## 5c. The successor transition, measured after the prose corrections landed

The correction record for this edit was first written against `sha256:917caf8e`, the
fingerprint THM-0074 carried when the decomposition was performed. That value did not
survive: the held prose corrections moved two of THM-0074's own premises, so the tree that
receives this edit is a different tree. Both endpoints were re-read rather than carried
forward.

| | |
|---|---|
| `theorem_claim`, both sides | `sha256:9f4cc66a` — unchanged, as a dependency correction requires |
| from (main, after the prose corrections) | `sha256:fcf05933` |
| to (this edit applied) | `sha256:7f350985` |
| dependency closure | 48 theorems → **66** |

The closure figure is the one worth reading. Naming THM-0077 does not add one premise; it
admits THM-0077's own transitive closure, and eighteen theorems that THM-0074's antecedent
had always quantified over become visible to the derivation. That is the size of what was
unstated.

## 6. Premises, boundaries and review obligations

* **ASSUMED** — R4's ordering leaf is declared `tested` while its real carrier is a type gate
  the compiler holds. It is not reclassified here: `proxy.dispatch_commitment` also carries
  R5, whose carrier is a script, and a unit takes one evidence class. Recorded as the honest
  residue of one owner holding two carriers, not silently upgraded.
* **EXTERNAL BOUNDARY** — what the backend does once invoked. The root's scope already says
  so, and nothing below it reaches past the invocation.
* **REVIEW OBLIGATION** — none new. THM-0077 was already an owner-reviewed root; naming it
  as a premise does not create a review that did not exist.

## 7. What was NOT done here

The five open N1 obligations above are not discharged. THM-0077's own decomposition is not
performed — it is the sixth root in the Phase-1 order and gets its own packet. No unit was
split: question 2 of the twelve was asked of all nineteen owners and none answered with a
second independently describable authority that its theorem layer did not already separate.
