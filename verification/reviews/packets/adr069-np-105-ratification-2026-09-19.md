<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-105 residue — R6 ratification packet: the admission BINDING is the tested twin of a proved plane

**Disposition:** R1 in part, R6 for the residue. Four controls landed in
`unit://http_profile.artifact_verification_boundary`. Four `[[disposition]]` rows remain and
NP-105's `[[proposition]]` entry and record stay in place.

## What landed, and the clause that contains it

`http_profile.artifact_verification_boundary`, `description`, verbatim:

> The closed artifact-type dispatch of full-request verification: a binding reported verified
> matched one explicitly supported typed verification branch and satisfied that branch's
> required binding form; every other artifact type is refused.

`unknown_artifact_type_fails_closed` and `unknown_binding_type_fails_closed` are the final
clause; `opaque_binding_carrying_reference_fields_is_malformed` and
`reference_binding_missing_its_reference_fields_is_malformed` are *"satisfied that branch's
required binding form"*, and the battery already holds their in-crate twins
`block::tests::opaque_binding_with_reference_fields_fails_closed` and
`block::tests::reference_binding_missing_fields_fails_closed`.

## The residue, and why it is outside every ratified theorem

`tests/admission_binding_test#{a_bound_current_admitted_call_passes,
a_bound_but_stale_generation_is_refused, tampering_the_admission_binding_breaks_the_signature,
no_binding_verifies_when_admission_is_not_enforced}`.

The admission plane's theorems — THM-0003, THM-0006 (*"the admitted actor named by the
assertion is the presenter of this call"*) and THM-0053 — are all about the **assertion**.
These four are about the **binding**: that tampering it breaks the signature, that a bound
but stale generation is refused, and that the binding is only demanded when admission is
enforced.

The structural obstacle is separate from the semantic one and is decisive on its own:
THM-0003 and THM-0006 rest on `http_profile.admission_currency`, whose `evidence_class` is
**`proved`**. Attaching four `tested` selectors to it would misstate the unit's class, which
ADR-MCPRE-068 forbids as directly as ADR-069 §5 forbids widening its proposition.

## Proposed shape

One theorem — *an enforced admission binding is bound to the exact presented call and to a
current generation: tampering it invalidates the signature, a stale generation is refused,
and no binding is demanded where admission is not enforced* — with one `tested` unit
`http_profile.admission_binding_enforcement` over `tests/admission_binding_test.rs` and the
binding's production carrier, direct severity `critical`, and one `mutation://` probe on the
generation-currency comparison. It is the `tested` twin of the proved plane, stated
alongside it rather than folded into it.

## N1

Four rows, unregistered. `artifact_verification_boundary` keeps
`mutation://http_profile/artifact/verification_boundary`. No debt row is added.
