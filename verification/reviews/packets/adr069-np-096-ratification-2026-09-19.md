<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-096 residue — R6 ratification packet: one control outside every unit's source closure

**Disposition:** R1 for nine of ten. Nine controls landed in
`unit://http_profile.pdp_decision_authentication`. One `[[disposition]]` row remains —
`CD-15063`, `lib#pdp_decision::tests::the_linkage_form_and_the_evidence_form_are_not_interchangeable` —
and NP-096's `[[proposition]]` entry and record stay in place.

## What landed, and the clause that contains it

`http_profile.pdp_decision_authentication`, `description`, verbatim:

> ADR-MCPRE-065: what the AUTHORITY said, and that it was said to this enforcement point. A
> decision's JWS shape, its issuer's resolution through the authorization trust seam, its
> signature, the profile and audience it names, and the two freshness bounds — the
> verifier's own cap as well as the issuer's window. It decides nothing about the request in
> hand.

The five `claims::tests` scope-algebra controls are facts about what the SIGNED CLAIMS
carry — which dimension a scope binds, and whether a keyid is required under it — and
therefore about *what the authority said*, not about the request in hand. The three
`issue::tests` controls are the JWS shape and the signature's coverage. The `verify::tests`
control is `typ` discrimination, part of *a decision's JWS shape*.

An alternative reading exists and is recorded rather than hidden: a reviewer who reads the
scope-algebra five as the *relation* between the decision's scope and the deployment's
belongs them under THM-0040 and `proxy.pdp_decision_relation`, in a different Cargo
project. They are kept here because they never touch a request.

## The residue, and why it could not be registered

`src/pdp_decision/mod.rs` is in **no** unit's `paths` anywhere in the registry.
`tools/verification/_manifest.py::_validate_in_crate_selectors` refuses a `lib#` selector
whose module file is not declared, for the stated reason that such a control *"can be
rewritten under the same name without moving the fingerprint"*. The only ways to register
it are to widen `pdp_decision_authentication.paths` — which ADR-069 §5 forbids and this
slice's charter forbids outright — or to declare a unit over `mod.rs`, which is R2.

## Proposed shape

`mod.rs` holds the DecisionBinding form discrimination (linkage vs evidence). THM-0015 and
THM-0008 both speak about binding forms; the cheapest honest resolution is a review call on
whether `src/pdp_decision/mod.rs` belongs in
`http_profile.artifact_verification_boundary.paths` (it already declares
`src/pdp_decision/binding.rs` and holds
`pdp_decision::binding::tests::a_reference_binding_can_never_satisfy_the_evidence_form`, the
in-crate twin of this control). That is a `paths` widening and therefore an owner decision,
not a campaign one.

## N1

One row, unregistered. No obligation moves.
