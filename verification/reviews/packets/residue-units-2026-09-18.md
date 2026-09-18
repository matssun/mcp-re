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

## The two the criterion still reports as residue, and why they are not split here

**`proxy.trust_composition_root`** (THM-0038, THM-0067). THM-0067 is the general inventory
claim — every field the root reads directly is a pinned ordinary parameter. THM-0038 is that
claim specialized to trust, PLUS a second conjunct: "the root passes trust as owner
projections". That conjunct has no control. The split is therefore not a re-partition of
existing evidence but a decomposition that needs a control written first; doing it the other
way would register an owner whose proposition nothing measures.

**`proxy.dispatch_commitment`** (THM-0045, THM-0051, THM-0052). Three genuinely distinct
propositions — the assembled `ReadyForDispatch` seal, the product provenance across the
pipeline, and the posture's provenance from the configured policy. The second and third are
carried by `scripts/serving_product_provenance_gate.py` and
`scripts/authorization_provenance_gate.py`, self-tested source-text gates that run in CI and
in `local_gate.sh`.

**ADR-MCPRE-069 finding, and why the split waits on it.** Neither gate is named in ANY unit's
`paths`. They are the production carriers of two `critical` propositions, and no unit's
fingerprint covers them: weakening a gate's rules invalidates nothing. Registering the two
owners honestly needs an evidence form for a self-tested source-text gate — `structural://`
is reserved for rustc compile-fail probes and `test://` resolves cargo and pytest symbols,
neither of which a `--selftest` flag is. Classifying them `tested` against the cargo controls
that happen to sit in the same unit would be exactly the false TESTED classification this
phase exists to remove. The lane is the prerequisite, and it is its own slice.
