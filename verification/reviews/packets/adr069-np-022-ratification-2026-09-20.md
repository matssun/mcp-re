<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-022 — R6 ratification packet: the generic provider cannot mint half a binding pair

**Disposition:** referred WHOLE. Nothing was registered and nothing was removed. All three
`[[disposition]]` rows (CD-4012 … CD-4014), the `[[proposition]]` entry and the record stay in
place.

## *The TypeScript twin states this clause verbatim* is the reason, not the remedy

`sdk_typescript.authorization_binding`:

> The authorization binding specs a request carries are the ones the configured policy
> permits, serialized canonically and byte-identically to the Python twin; **the core digests
> the real artifact material and a caller is given no way to supply a precomputed digest or
> to mint half a binding pair**; and the digest retained per outstanding request identifies
> which artefacts the request was bound to without ever being re-interpreted.

`sdk_python.authorization_binding`:

> The authorization binding specs a request carries are the ones the configured policy
> permits, serialized canonically and byte-identically to the TypeScript twin, and the digest
> retained per outstanding request identifies which artefacts the request was bound to
> without ever being re-interpreted.

The Python statement is the TypeScript statement with the bolded clause deleted. So the
proposition NP-022 names is present in one root's unit and absent from the other's, and
registering the three controls under the Python statement asserts a promise it does not make.
That is the unit-layer minting ADR-MCPRE-069 §5 forbids, and it is the same edit that puts
NP-020, NP-023 and NP-024 outside this slice.

## The three controls, and why they are one proposition

`TestTheGenericProviderCannotMintHalfAPair::{test_the_wrapper_refuses_the_generic_opaque_form,
test_the_native_seam_refuses_it_independently, test_the_reference_form_is_untouched}`.

Two refusals at two independent altitudes — the Python wrapper and the native seam — plus the
anti-vacuity arm. The third is not separable: a refusal that also refused the legitimate
reference form would satisfy the first two and break the feature, so a registration holding
only the first two would be evidence for a claim the feature's own absence satisfies.

## The theorem question

`sdk_python.authorization_binding` is theorem-less by decision, not by omission. THM-0094's
ratified `scope`:

> REQUEST-SIDE ATTRIBUTION IS OUTSIDE IT. … which authorization artefacts a request is bound
> to is `sdk_python.authorization_binding`. Remove either and the answer the application
> receives still binds to the request that was sent, which is why neither is in this closure.

So there is no ratified theorem above this proposition, which makes it R6 whatever owner it
lands in. The `theorem = "THM-0094"` that `M211` and `M212` carried is corrected in this
change; see the NP-021 packet.

## Proposed shape

Take NP-020 … NP-024 as ONE ratification of `sdk_python.authorization_binding`, restoring the
TypeScript twin's clause and deciding the unit's severity, rather than five separate ones.
The five records decompose one deleted clause, and question 1 of ADR-MCPRE-061 §8 applies to
the ratification the same way it applied to the decomposition.

## Lane

`sdk/python/tests/test_authorization.py` is behind NO `importorskip`. All three controls
select and PASS on the prepared `sdk/python/.venv-cp314` (CPython 3.14.7).

## N1

Nothing registered. No obligation moves.
