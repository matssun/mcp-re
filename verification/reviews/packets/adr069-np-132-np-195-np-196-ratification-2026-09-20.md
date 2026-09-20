<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-132 / NP-195 / NP-196 — ratification packet: the authorization refusal vocabulary

**Disposition:** R2 for three of thirteen — appended to the EXISTING unit
`proxy.authorization_coordinate_provenance` under **THM-0040**; no new unit, no `paths`
change, no `description` amendment, and therefore no new falsifier owed. R6 for eight, which
stay NP-132. Two are split out under RR-002 C5 as **NP-195** and **NP-196**, because they
are not NP-132's proposition at all.

All thirteen are `mcp-re-proxy` rust unit tests in the **default cargo lane**: measured,
`cargo test -p mcp-re-proxy --lib -- --list` selects 1498 controls and all thirteen are
among them. `proxy.authorization_coordinate_provenance` declares no `test_features`, so the
three appended selectors run in the lane they were measured in.

## 1. Registered (3)

- `lib#authorization::verified_action::tests::a_method_that_names_no_target_is_not_the_same_as_one_missing_its_target`
- `lib#authorization::verified_actor::tests::every_verified_dimension_is_projected_separately`
- `lib#authorization::pdp::evidence::tests::a_request_carrying_no_decision_is_not_a_refusal`

Each file — `verified_action.rs`, `verified_actor.rs`, `pdp/evidence.rs` — is already in
that unit's `paths`, so nothing is widened.

**The target algebra is THM-0040's statement, verbatim:**

> a decision naming no target matches only a not-applicable one and an absent signed target
> matches neither

The control asserts exactly the `NotApplicable` / `Absent` distinction that clause
quantifies over — `tools/list` reads `NotApplicable`, a `tools/call` with empty params reads
`Absent` — and its own comment names the failure: *"The distinction a single `Option`
destroys."* Without it, the clause quantifies over a distinction nothing establishes.

**The actor's dimensions are the comparison the statement performs:**

> the decided actor's trust domain and subject equal the request's VERIFIED actor's, and
> under credential scope its keyid does too

Three of the four projections the control asserts are those three. The fourth, `role()`, is
asserted alongside and is not claimed for the theorem; a control asserting more than a
theorem needs is ordinary, and what matters is that the control is evidence for a contained
proposition. Its comment records why the projections must be separate: *"a policy conditioned
on role receives a ROLE. It must not have to parse one out of a joined string, which is how
`actor_id()` became an operand of a relation it was never the coordinate for."*

**The no-candidate arm is the unit's own declared proposition:**

> none, two, or a reference-form binding produce no candidate at all

The battery already carried the other two arms —
`a_decision_with_no_binding_at_all_is_refused` and
`two_evidence_bindings_leave_the_pairing_ambiguous_and_are_refused`. This is the arm that
must NOT be a refusal (`Ok(None)`), and it was the unclaimed one. A registry holding two of
three arms of a stated disjunction is measuring less than the sentence says.

### Subsumption
No theorem fingerprint field changes (0 of 130 moved). The unit is already in THM-0040's
`supported_by`, so there is no theorem-level change at all here. No new product promise, no
trust boundary, no assumption, no choice between behaviours. No new unit, so no new
`mutation://` obligation: ADR-MCPRE-068's falsifier duty attaches to a new `tested` unit, and
this unit's existing falsifier is unchanged and still live.

## 2. Referred, staying NP-132 (8)

- `lib#authorization::pdp::refusal::tests::a_digest_mismatch_is_not_reported_as_a_malformed_artifact`
- `::a_request_presenting_nothing_says_so_rather_than_borrowing_a_denial`
- `::a_scope_the_deployment_does_not_accept_is_not_an_actor_mismatch`
- `::an_actor_mismatch_and_an_action_mismatch_are_different_tokens`
- `::an_explicit_deny_and_an_action_mismatch_collapse_onto_one_token`
- `::no_configured_authority_and_an_untrusted_issuer_are_different_tokens`
- `lib#authorization::verified_action::tests::a_signed_body_that_is_not_json_and_one_with_no_method_are_different_facts`
- `lib#authorization::verified_action::tests::a_malformed_request_is_reported_rather_than_refused_by_this_authority`

**THM-0040 declines this population in terms, and that is the whole argument.** Its scope:

> Nor does it establish that a refusal is reported faithfully to an operator; the refusal
> algebra is tested and deliberately carries no theorem, because its vocabulary has no
> production reader today.

A ratified theorem stating that a named body of controls is deliberately unclaimed is the
strongest possible refusal of a decomposition claim over it. Registering these anywhere
would contradict that sentence rather than decompose one.

**THM-0069 does not rescue them, and it is the theorem the slice plan named.** THM-0069 is
about what a RECORD may say. Its authorization clause is:

> the two authorization refusal arms stay distinguishable

Two arms — Core-owned and Authorization-owned provenance — and that control already exists
and is already registered: `proxy.refusal_provenance`'s
`the_two_authorization_arms_stay_distinguishable`. The eight above are one altitude below
that, inside the PDP's own token set, where an actor mismatch and an action mismatch are
different `PdpRefusal` values. A theorem about two coordinates on a record says nothing about
how many tokens live inside one of them.

`a_malformed_request_is_reported_rather_than_refused_by_this_authority` is referred WITH them
rather than registered, although its mechanical assertion (a nameless `tools/call` reads a
coordinate rather than being refused) is implied by the registered target-algebra control.
That is the point: it adds nothing to THM-0040 that the registered control does not already
carry, and what it is FOR — which authority owns the refusal, stated in its own comment as
*"Refusing it here would make an unauthorized deployment start rejecting requests because of
authorization"* — is precisely the axis the scope sentence names.

## 3. NP-195 — split under RR-002 C5

`lib#authorization::request::tests::an_unbound_deployment_says_not_claimed_rather_than_asserting_a_binding`.

Not a refusal token. It asserts that an authorization request composed on a deployment that
binds no channel carries `None` for its channel binding. THM-0040 excludes the subject by
name:

> It is authorization, and not admission, authentication, channel binding or transport
> identity.

An exclusion of the topic, not a silence about it, so no decomposition of THM-0040 reaches
it. Its own proposition — a policy conditioned on the channel must not be handed a binding
the deployment never established — is a different claim from every token distinction NP-132
enumerates, and C5 forbids one disposition over the pair.

## 4. NP-196 — split under RR-002 C5

`lib#authorization::pdp::policy::tests::a_resolver_that_trusts_nobody_is_a_deployment_that_authorizes_nothing`.

A deployment-configuration fact: the authorization-authority seam is populated separately
from the request-signer seam, and its own comment states the reason — *"an
authorization-authority seam is not populated by whatever the request-signer seam happens to
trust."* The collapse it forbids is a key trusted to SIGN a request becoming a key trusted to
ISSUE the decision that authorizes it.

THM-0039 is the nearest ratified claim and disclaims the ground:

> It does not establish that the authority SHOULD be trusted — only that the seam answered
> for that kid, which is the deployment's configuration speaking rather than this claim.

THM-0040 consumes THM-0039's conclusion and states relevance. Neither states that the two
seams are separately populated. It is also, honestly, the weakest control of the thirteen —
it asserts that a closure returning `None` returns `None`, plus two field reads — and a
future ratification should replace it rather than inherit it.

## 5. What would discharge each

**NP-132.** A theorem over the authorization refusal vocabulary, which needs a production
reader first: THM-0040's sentence says the vocabulary has none today, and that is a fact
about the system rather than about the registry. When a downstream authority branches on the
token, the proposition becomes statable and these eight are its battery.

**NP-195.** A theorem over channel-binding provenance in the authorization request.

**NP-196.** A theorem over how a deployment's two trust seams are populated — likely
alongside the startup posture, since it is a configuration property rather than a
per-request one.
