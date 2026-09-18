# ADR-MCPRE-068 Phase 1 — closure report

**Frozen main SHA: `06994c644a594ac3e48d48208a9e7424a40023d6`**

Every figure here was re-derived from that tree by
`tools/verification/evidence-class-census`, the four policy registries, the obligation
registry and the correction records, in one pass. Nothing is aggregated from a branch
report, a packet, or an earlier measurement. The historical trajectory in §9 is
explanatory and is explicitly NOT an authority for any final number — several counts
quoted during the campaign described trees that no longer exist.

This file is ABOUT `06994c64` and is necessarily recorded in a successor commit: writing
the report down moves the tree it describes. The SHA above is the state every figure was
measured at, not the SHA this file lives at.

The measurement is reproducible rather than asserted. `phase1-closure/phase1_closure.py`
re-derives every figure in sections 2, 3, 5 and 6 from the registries of whatever tree it
runs in; `phase1-closure/phase2_order.py` derives section 4 and 12 from the graph; and
`phase1-closure/write_closure.py` renders them, carrying no number of its own. Running the
three at `06994c64` reproduces this report. A figure that is wrong here is wrong in the
tree.

## 1. Why this report is not a score

The closure criterion is the CORRECTNESS of the assurance graph, not the size of the
obligation set. Phase 1 raised the N1 population from 63 to 87 and that is a success
condition, not a regression: a wide proposition that owed one falsifier owes several
once it is decomposed into the propositions it was silently the conjunction of. The
obligations did not appear; they became countable. Two of them were then genuinely
discharged (M172, M176) and the count fell, which is the only kind of decrease that
means anything.


## 2. Final state

| | |
|---|---|
| declared system roots | 12 |
| theorems | 130 |
| propositions (units) | 192 |
| premises, live | 43 of 47 (4 withdrawn) |
| evidence class `tested` | 169 |
| evidence class `structural` | 15 |
| evidence class `proved` | 7 |
| evidence class `measured` | 1 |
| premise class `external-boundary` | 21 |
| premise class `assumed` | 12 |
| premise class `review-obligation` | 10 |
| N1 open obligations | **87** |
| N1 critical | 55 |
| N1 high | 18 |
| N1 medium | 14 |
| N1 root-reachable | 56 |
| N1 not root-reachable | 31 |

## 3. Per root — final state, and the reason it reached it

| root | closure (thm/unit) | new units | reason(s) |
|---|---|---|---|
| THM-0074 | 67 / 73 | 11 | graph corrected; premise correction propagated; establishment completed |
| THM-0078 | 12 / 11 | 3 | establishment completed |
| THM-0075 | 17 / 22 | 2 | graph corrected; establishment completed |
| THM-0076 | 17 / 17 | 8 | premise correction propagated; establishment completed |
| THM-0094 | 12 / 22 | 18 | graph corrected; subject misdescribed, corrected; establishment completed |
| THM-0095 | 1 / 11 | 11 | establishment completed |
| THM-0077 | 23 / 31 | 5 | establishment completed |
| THM-0091 | 1 / 7 | 7 | subject misdescribed, corrected; evidence class corrected |
| THM-0012 | 1 / 2 | 1 | evidence class corrected |
| THM-0072 | 3 / 7 | 6 | establishment completed |
| THM-0042 | 1 / 3 | 0 | already correct |
| THM-0071 | 7 / 7 | 3 | establishment completed |

* **THM-0091** gained formal carriers: `client.accepted_authority_sole_producer`, `client.bind_scope_sole_producer`
* **THM-0012** gained formal carriers: `proxy.runtime_lifecycle_sole_mutator`

## 4. Phase-2 order, derived from the frozen graph

| enabling lane | N1 rows | critical | roots unblocked |
|---|---|---|---|
| `cargo-mutation-lane` | 60 | 34 | THM-0042, THM-0071, THM-0072, THM-0074, THM-0075, THM-0076, THM-0077, THM-0078, THM-0094 |
| `node-falsifier-lane` | 14 | 11 | THM-0095 |
| `python-falsifier-lane` | 13 | 10 | THM-0094 |

First ten individual obligations, severity then fan-out:

| effective | blocks | roots | lane | proposition |
|---|---|---|---|---|
| critical | 6 | 3 | `cargo-mutation-lane` | `proxy.kms_endpoint_authority` |
| critical | 4 | 3 | `cargo-mutation-lane` | `proxy.cross_machine_legality` |
| critical | 4 | 3 | `cargo-mutation-lane` | `proxy.custody_exposure` |
| critical | 4 | 3 | `cargo-mutation-lane` | `proxy.signing_role_separation` |
| critical | 4 | 2 | `cargo-mutation-lane` | `client.trust_manifest_lifecycle` |
| critical | 3 | 2 | `cargo-mutation-lane` | `client.execution_contract` |
| critical | 3 | 2 | `cargo-mutation-lane` | `proxy.replay_materialization` |
| critical | 3 | 1 | `cargo-mutation-lane` | `client.manifest_floor` |
| critical | 2 | 2 | `cargo-mutation-lane` | `client.delegation_policy_seal` |
| critical | 2 | 2 | `cargo-mutation-lane` | `proxy.continuation_installation` |

## 5. Repository-state condition

* correction records citing a packet not in the tree: **0**
* campaign branches examined: 29; holding a record, probe or unit main has never held: **0**
* unit ids that have ever stood on main: 203 (a branch holding a superseded id is not holding unmerged work)

## 6. Gates at the frozen SHA

* `claim_surface` rc=0 — claim-surface gate: OK — 12 declared root(s), 12 published claim(s), 0 open §4 area(s), 6 settled, every claimed root reviewed at its current fingerprint or carried there by a recorded Phase-1 correction (5 of them).
* `assurance_obligation` rc=0 — assurance-obligation gate: OK — 87 open N1 obligation(s), all measured and all pre-existing at the baseline (87 unreviewed, 0 reviewed-action-required, 0 reviewed-exception; 56 root-reachable). Registry did not grow, no status returned to unreviewed, and every row names an obligation that is still owed. Each remains INCOMPLETE — the registry bounds the population, it does not discharge anything.
* `check_generated` rc=0 — VERDICT: PASS
* `root_completeness` rc=0 —     THM-0095  EVIDENCE: unit://sdk_typescript.continuation_drive UNKNOWN, unit://sdk_typescript.correlation_lifecycle UNKNOWN, unit://sdk_typescript.exchange_binding UNKNOWN, unit://sdk_typescript.execution_report UNKNOWN, unit://sdk_typescript.local_failure_provenance UNKNOWN, unit://sdk_typescript.nonce_floor UNKNOWN, unit://sdk_typescript.notification_delivery UNKNOWN, unit://sdk_typescript.post_close_emission UNKNOWN, unit://sdk_typescript.reply_envelope UNKNOWN, unit://sdk_typescript.trust_anchor_completeness UNKNOWN, unit://sdk_typescript.verdict_delivery UNKNOWN


## 7. The result that a fingerprint cannot express

**THM-0074's claim digest did not change, but its assurance meaning did.**

`theorem_claim` is `sha256:9f4cc66a` on both sides of its correction. The statement, the
security consequence and the scope are byte-identical. What changed is whether the graph
contained the premise the statement had always required: its antecedent quantifies over
the obligations *selected by the validated deployment*, and nothing in its closure
established that the set the serving runtime holds IS the operator's validated selection.
The root's own scope disclaims ADEQUACY — *"not a claim that the set is right"* — where
the missing premise is IDENTITY.

Naming THM-0077 moved the dependency closure from 48 theorems to 66. Eighteen theorems,
not one, became visible to the derivation.

This is the campaign's sharpest demonstration that **claim fingerprints alone cannot
establish assurance completeness**. A fingerprint pins what a theorem SAYS. It is silent
about whether what it says is justified by anything the graph contains, and a registry
that compared only claim digests would have reported this root unchanged and correct.

## 8. ADR-MCPRE-069 — evidence that runs and nothing claims

Estate-wide measurement: of 38 `scripts/*_gate.py`, **zero** appear in any unit's
`paths`, and **six** are named by a theorem's own text as what establishes it.

| disposition | count | what |
|---|---|---|
| REGISTER | 4 | `serving_product_provenance_gate.py` (THM-0051), `authorization_provenance_gate.py` (THM-0052), `serving_identity_provenance_gate.py` (THM-0080), `refusal_provenance_gate.py` (THM-0081) — each now a declared `gate_control` with a `gate#` falsifier |
| NEW PROPOSITION | 2 | `python_runtime_gate.py` (THM-0094), `node_runtime_gate.py` (THM-0095) — no `sdk_python.*`/`sdk_typescript.*` unit states a runtime support claim, so there is nothing to register them against |
| REATTRIBUTE | 0 | — |
| NOT EVIDENCE | 0 | — |

The two NEW PROPOSITION findings were deliberately NOT forced into an existing root or
unit to close Phase 1. They are recorded at their correct semantic altitude with a
Phase-2 obligation, per the ruling that Phase 1 must not manufacture ownership.

A first draft of this disposition said REGISTER for all six. That was wrong, and the
correction matters: REGISTER puts a control inside an EXISTING claim's closure; NEW
PROPOSITION says the estate is missing a claim. They assert different things.

Separately measured and NOT dispositioned as a bulk action: **1,456 test functions inside
declared unit paths belong to no unit's battery, across 75 units.** Bulk-registering them
is explicitly forbidden — a control registered without a proposition to attack is a count,
not evidence. This is a Phase-2 population, not a Phase-1 defect.

## 9. Historical trajectory — EXPLANATORY ONLY

Not an authority for any figure above. Read only to understand why the population moved.

| main SHA | slice | N1 rows | units |
|---|---|---|---|
| `c8c506e1` | Phase 0E — N1 switched on | 63 | 138 |
| `0c3785da` | 1-A THM-0094 | 75 | 150 |
| `1a86f331` | 1-C THM-0091 | 75 | 156 |
| `05e13348` | verifier split | 75 | 165 |
| `6d28b76d` | SCITT + remaining splits | 76 | 178 |
| `17dab8a0` | 1-B THM-0095 | 89 | 191 |
| `0224cd42` | source-text falsifiers | 87 | 191 |
| `28394a14` | held prose corrections | 87 | 191 |
| `a1944a78` | 1-H THM-0012 | 87 | 192 |
| `f4ed6659` | twelve roots + THM-0074's premise | 87 | 192 |
| `06994c64` | THM-0091's claim corrections | **87** | **192** |

63 -> 87 obligations against 138 -> 192 propositions. 29 rows carry `succeeds` provenance:
they are the narrower propositions that replaced a wide predecessor, and they are ordinary
open obligations, not authorizations.

## 10. What root establishment is NOT measured here

`review --root-completeness` reports `0 of 12` in this workspace, and that figure is NOT
reported as a closure result. Establishment requires freshness records issued by
`tools/verification/attest`, which refuses to issue any when the aggregate is not PASS.
The aggregate here is INCOMPLETE for one environmental reason: the `lean` lane is
UNAVAILABLE because the Aeneas library lives only in the pinned extraction image. Eight
lanes PASS (`manifests`, `assumptions`, `generated-model`, `test`, `mutation`,
`structural`, `measured`, `verus`); one is absent.

An absent toolchain is a missing measurement, not a failed one. Root establishment is a
release-assurance (T6) question under ADR-MCPRE-059 §28.8, deliberately not a merge-path
or Phase-1 criterion — an honest unresolved gap under a declared root must not fail
ordinary development, or the incentive becomes to leave the obligation unrecorded.

The authoritative evidence at this tree is the verification platform run for PR #995 at
`0b12871f`, which passed all six lanes. That commit's tree is BYTE-IDENTICAL to the frozen
SHA (confirmed by `git diff`), so it is evidence about this tree and not about an ancestor.

## 11. Phase-1 closure criterion

| criterion | result |
|---|---|
| all declared roots decomposed consequence-first | 12 of 12, each with a packet |
| explicit security consequence per root | 12 of 12 |
| one semantic proposition per leaf | 192 units, each one proposition |
| production carrier per leaf | 192 of 192 declare non-empty `paths` |
| honest evidence class per leaf | 192 of 192 declare `evidence_class` and >= 1 evidence URI |
| no implicit proposition between leaf and root | **0** theorems with neither carrier nor premise |
| typed premises | 43 live, all typed; 4 withdrawn, correctly untyped (`scope = []`) |
| no stale/dead unit references | **0** across all policy registries and the debt registry |
| no unresolved Phase-1 claim correction | claim-surface gate OK, 5 roots carried by record |
| no unresolved Phase-1 dependency correction | 3 dependency corrections, all recorded |
| direct severity complete | 192 of 192 units, 130 of 130 theorems |
| inherited / effective severity derived | **0** units store a derived severity (N3 holds) |
| root reachability derived | 56 root-reachable / 31 not, per row |
| N1 derived | 87, obligation gate OK, registry did not grow |
| obligation succession valid | 29 successor rows, gate OK |
| generated views agree with registries | `check-generated` PASS, 6 views |
| ADR-069 dispositions represented | 4 REGISTER merged, 2 NEW PROPOSITION recorded |
| nothing lives only on a branch or packet | **0** campaign branches hold an artefact main has never held; **0** records cite a missing packet |

**Phase 1 is CLOSED at `06994c644a594ac3e48d48208a9e7424a40023d6`.**

## 12. Phase-2 entry

Phase 2 is entered under ADR-MCPRE-068's ratified scheduler, which is not "work the N1
list in row order". Shared enabling lanes precede the individual obligations they unblock:

| lane | N1 rows | critical | roots unblocked | mechanism exists? |
|---|---|---|---|---|
| `python-falsifier-lane` | 13 | 10 | THM-0094 (whole root) | **no** |
| `node-falsifier-lane` | 14 | 11 | THM-0095 (whole root) | **no** |
| `cargo-mutation-lane` | 60 | 34 | 9 roots | yes — 199 probes registered |

The cargo lane holds more Critical obligations, and it is NOT first. Its mechanism exists,
so each row is an individual falsifier against an existing lane. The Python and Node lanes
have no mechanism at all: 27 obligations and two entire roots are blocked on building each
once. That ordering is corroborated independently — THM-0095 is the only root whose whole
closure reaches no falsifier, and the two runtime gates were the campaign's only NEW
PROPOSITION dispositions.
