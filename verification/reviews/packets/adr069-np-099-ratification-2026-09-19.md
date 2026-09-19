<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-099 — R6 ratification packet: one `Verified…` type, one proof strength

**Disposition:** referred WHOLE. Nothing was registered and nothing was removed. All eleven
`[[disposition]]` rows, the `[[proposition]]` entry and the record stay in place.

## Why not even the three substitutability controls

The analysis that scheduled this slice offered
`verified_response::facts::tests::bound_and_unbound_facts_are_not_the_same_type`,
`…unbound::tests::the_unbound_products_carry_no_request_binding_to_misread` and
`…unbound::tests::a_delegated_receipt_carries_no_trust_seam_resolution_to_misread` as R1
into `unit://http_profile.verifier_result_separation`, conditional on an ADR-MCPRE-068 class
question. The condition resolves against the registration, mechanically:

```
http_profile.verifier_result_separation
  evidence_class = "structural"
  evidence       = ["structural://http_profile/verifier/assurance_type_separation"]
  tested_symbols = []            # empty
```

`tools/verification/_manifest.py` refuses `tested_symbols` on a unit with no `test://`
evidence entry — *"declares `tested_symbols` but no test:// evidence entry claims them, so
nothing consumes what the lane would measure."* Registering the three therefore means adding
a test lane to a `structural` unit. ADR-MCPRE-068 says the class must be the TRUE one rather
than the cheapest, and a `structural` unit's evidence is a compile-fail probe naming the
edit that turns it red — not a test list. That is a class decision about an existing unit,
which is R6, not a registration.

The honest observation underneath: these three tests are *assertions about* type separation
written in the test language, while the unit's claim is that the separation is
**unconstructible**. A passing assertion is weaker evidence for the same sentence than the
compile-fail probe already registered. Folding them in would make the battery look larger
and the claim no stronger.

## The other eight: the *without an Option* family

`verified_request::tests::{a_full_product_reports_the_floor_facts_it_also_establishes,
the_floor_product_carries_the_slot_trust_resolved_it_in,
the_full_product_states_its_audience_without_an_option}`,
`verified_response::bound::tests::{a_bound_full_response_states_its_binding_without_an_option,
a_delegated_response_states_its_issuer_without_an_option,
the_seam_authorized_floor_projects_the_signer_it_resolved}`,
`verified_response::facts::tests::{an_agreement_records_both_handles_not_only_the_verdict,
the_shared_facts_carry_who_signed_and_no_authorization}`.

THM-0047 is the nearest theorem and excludes them in its own words. Statement:

> The products the verifier operations return are distinct types whose representations are
> private to their own modules, so a product that establishes a weaker proposition cannot be
> passed where a stronger one is required.

Scope: *"Type separation only … It establishes nothing about what any of the operations
verify."* The *without an Option* clause is precisely a statement about what a product
ASSERTS, which that sentence declines.

The estate has RULED on the shape — one `Verified…` type, one proof strength; an `Option`
documented *"None on the minimal path"* is a type admitting two — but a ruling is not a
theorem, and no theorem states it.

## Proposed shape

One theorem: *every verifier product states the facts its own proposition establishes
totally — no field of a `Verified…` type is optional because a weaker path exists; a weaker
path returns a different type.* Carrier `src/verified_request/`, `src/verified_response/`;
`tested`, direct severity `critical`, with the compile-fail arm staying on THM-0047.
Deciding whether the three substitutability controls become part of the new `tested` unit or
stay expressed as `structural` probes is the first question that theorem's review must
answer.

## N1

Nothing registered. No unit changed. No obligation moves.
