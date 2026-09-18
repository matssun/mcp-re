<!-- SPDX-License-Identifier: Apache-2.0 -->
# ADR-MCPRE-068 Phase 1 — the residue units, and what measurement said about each

One record for the units the Phase-1 completion criterion reported as the semantic authority
for several non-root claims after the first round of splits. It is a decomposition record,
not an exception: each entry says what the second authority was, how the existing evidence
partitioned, and what the split left owing.

The criterion is measured by `tools/verification/review`, not asserted here.

## `proxy.trust_configuration_state` -> classification + locator

THM-0035 (which revocation posture a deployment requests and which witnesses each state form
needs) and THM-0036 (which locators name a trust document at all). The unit's own description
carried both with an "and". M63/M64 already turned a THM-0035 control red and M65 a THM-0036
control; the split labelled that partition. `proxy.trust_configuration_state_sole_producer`
is unchanged and still supports both: the seal is over the state VALUE, which both
propositions are about.

## `proxy.trust_plane_runtime` -> resolution window + reload cadence

THM-0097 (what the resolver may ANSWER under the snapshot it has) and THM-0100 (how often the
snapshot is RE-READ). The theorem layer already said they were two authorities: THM-0100
`depends_on` THM-0097, and its scope says "nothing about the read itself beyond its success
or failure" — a boundary between owners written as a disclaimer.

The eleven probes partitioned without one being touched, and the run proves it: M92-M95, M98,
M99 and M135 name THM-0097 alone, M107-M109 name THM-0100 alone.

`mod.rs` and `reload/mod.rs` are members of BOTH units. Each holds one function of each
authority — `reload/mod.rs` runs the cadence loop and carries the keep-last-good budget whose
exhaustion closes the resolver; `mod.rs` holds the plane's terminal `Drop` and
`fleet_trust_bound`. Splitting the FILES to make the closures disjoint would move code to
satisfy a partition.

**ADR-MCPRE-069 finding.** M148 names its UNIT, not a theorem: no theorem claims the trust
document's read bound in terms. It sits in the resolution unit because a truncated document
is a SOFTENED snapshot. Registered as a gap, not absorbed.

## `proxy.serving_trust_seam` — NOT split, and the gate is why

THM-0066 (the root builds the seam once from the materialized authority) and THM-0099 (the
seam the root built answers a Request-slot selector from the current snapshot) ARE two
authorities — a composition fact and a runtime fact — and the description says so with an
"and". The split was implemented and then reverted, because attempting it produced the
finding rather than the decomposition.

Both registered probes, M105 and M106, turn a `revocation_serving_wiring_test` control red:
they attack what the seam ANSWERS. The composition half's three controls are in
`serving_trust_seam_test`, and they are SOURCE-TEXT rules over `app.rs` — `build_actor_resolver`
is called exactly once, its body reaches `request_trust.resolve(`, and it captures no frozen
map — with `the_rules_would_catch_each_regression` as their own self-test.

So splitting leaves the composition unit naming no `mutation://`, and
`scripts/assurance_obligation_gate.py` refused the registry row that would have recorded it:
the base registry did not hold that obligation, the unit is not its own predecessor, and the
registry may only shrink. **The gate is right.** The obligation is not what is owed here.

A source-text control cannot be falsified by a source-text mutation probe the way a
behavioural one can: the probe edits the very text the rule reads, so a weakening that
removes the matched substring turns the control red whether or not it changes behaviour, and
a weakening that changes behaviour while preserving the substring does not. Its real
falsifier is its self-test, and `the_rules_would_catch_each_regression` is already a member
of the unit. N1 asks this unit for the wrong artifact.

That is the same gap as the two provenance gates below, and the same lane closes both.

## `client.response_acceptance` -> signer authorization + binding disposition

THM-0058 (which signer is authorized in the Response slot) and THM-0059 (an unbound receipt
is never a success and never another request's answer). They fail independently in opposite
directions: a client can accept a perfectly bound answer signed by a revoked key, or a
perfectly authorized signature over an answer to somebody else's request. Neither implies the
other and neither is a weakening of the other.

THM-0076, the client-side system root, `depends_on` both and is `supported_by` both units. It
stays owned by the binding half, where `response.rs` composes the two and decides the
"never a success" disposition — the accepted third population of the criterion, a root and
one leaf under one `owner` field.

The unit named no `mutation://` evidence, so both halves succeed its obligation.

## The three the criterion still reports as residue — ONE missing lane, not three

The residue is not three unrelated pieces of work. All three units carry a second authority
whose production carrier is a **self-tested source-text gate**, and none of the three can be
registered honestly until that has an evidence form.

**`proxy.serving_trust_seam`** (THM-0066, THM-0099) — above. The composition half's controls
are source-text rules over `app.rs` in `serving_trust_seam_test`, with
`the_rules_would_catch_each_regression` as their self-test.

**`proxy.trust_composition_root`** (THM-0038, THM-0067). THM-0067 is the general inventory
claim — every field the root reads directly is a pinned ordinary parameter. THM-0038 is that
claim specialized to trust PLUS a second conjunct, "the root passes trust as owner
projections", which has no control at all. The unit's three controls are
`composition_raw_read_test`, and they have the identical shape: two source-text rules over
`app.rs` and `the_rule_would_catch_a_new_raw_read` as their self-test. The unit names no
`mutation://`.

**`proxy.dispatch_commitment`** (THM-0045, THM-0051, THM-0052). Three distinct propositions —
the assembled `ReadyForDispatch` seal, the verification product's provenance across the
pipeline, and the posture's provenance from the configured policy. The seal is measured by
cargo controls and two probes. The other two are carried by
`scripts/serving_product_provenance_gate.py` and `scripts/authorization_provenance_gate.py`,
self-tested source-text gates that run in CI and in `local_gate.sh`.

### The ADR-MCPRE-069 finding

Neither provenance gate is named in ANY unit's `paths`. They are the production carriers of
two `critical` propositions and no unit's fingerprint covers them: weakening a gate's rules
invalidates nothing and moves no digest.

### Why the lane is the prerequisite and not a detail

`structural://` resolves rustc compile-fail probes. `test://` resolves cargo and pytest
symbols. A `--selftest` flag is neither, and a gate's self-test is not a falsifier N1 can see.
Registering these owners as `tested` against whichever cargo controls happen to sit beside
them would be exactly the false TESTED classification this phase exists to remove, and
`assurance_obligation_gate.py` already refused the alternative — a registry row for an
obligation the base did not hold — when the seam split tried it.

So: one evidence form for a self-tested source-text gate, and the three residue units and the
two orphaned gates close together. It is its own slice, sequenced after the in-flight Phase-1
PRs land.

---

## A split must not touch another theorem's prose — four held corrections

`claim_surface_gate.py` failed this branch with `STALE_DEPENDENCY_CLAIM` on THM-0074 and
THM-0076, and the cause was a reflex: after renaming a unit, its old id was replaced
everywhere it appeared, including inside four other theorems' `scope` text.

`theorem_claim = statement + security_consequence + scope`. **Scope is inside the claim
digest**, so editing a sentence of prose in a theorem's scope moves that theorem's claim
fingerprint, and with it the `theorem_dependencies` closure of every theorem that depends on
it — here two published system roots, neither of which the split was about. `owner` and
`supported_by` are NOT in the fingerprint, which is why retargeting those was free and only
the prose was fatal.

The four edits are reverted, so these sentences name unit ids that no longer exist:

| theorem | sentence names | should name |
|---|---|---|
| THM-0126 | `client.response_acceptance` | `client.response_binding_disposition` |
| THM-0084 | `client.response_acceptance` | `client.response_binding_disposition` |
| THM-0074 | `proxy.trust_plane_runtime` | `proxy.trust_resolution_window` and `proxy.trust_reload_cadence` |
| (trust-document premise) | `proxy.trust_configuration_state` | `proxy.trust_document_locator` |

They are held, not dropped: each is an ADR-MCPRE-068 Phase-1 claim correction and goes in the
correction register once PR #990 puts it on main, alongside THM-0091's C1-C3 and THM-0095's
C1-C8. Applying them here would need the register the branch does not have.

**The rule the campaign takes from this:** a unit split retargets `owner`, `supported_by` and
probe `unit` fields, and stops there. Prose in a theorem's `statement`, `security_consequence`
or `scope` is claim surface, and moving it is a correction with a record, never a rename.
