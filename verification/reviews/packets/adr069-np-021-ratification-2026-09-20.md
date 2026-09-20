<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-021 — R6 ratification packet: a binding carries metadata, never the artifact

**Disposition:** referred WHOLE. Nothing was registered and nothing was removed. Both
`[[disposition]]` rows (CD-4010, CD-4011), the `[[proposition]]` entry and the record stay in
place.

## The candidate owner, quoted whole

`unit://sdk_python.authorization_binding`, `evidence_class = "tested"`,
`direct_consequence_severity = "medium"`:

> The authorization binding specs a request carries are the ones the configured policy
> permits, serialized canonically and byte-identically to the TypeScript twin, and the digest
> retained per outstanding request identifies which artefacts the request was bound to
> without ever being re-interpreted.

Three claims: the permitted SET, the canonical SERIALIZATION, and that the retained digest is
not RE-INTERPRETED.

## Why the two controls do not land there

`test_the_binding_carries_metadata_only_never_the_artifact` asserts that the artifact bytes
are absent from what travels. `test_the_reference_form_leaks_no_secret_material` asserts that
a secret handed to a reference-form provider does not reach the signed evidence. Neither is
one of the three claims above:

- *the permitted set* is about WHICH binding types ride, not about what a binding contains;
- *canonical serialization* is about byte agreement with the TypeScript twin — a binding that
  embedded the artifact in both SDKs would satisfy it;
- *the retained digest is not re-interpreted* is about the digest held per outstanding
  request, not about the evidence that is transmitted.

Registering them means writing the containment clause into the unit's `description`. That is
minting a proposition at the unit layer — the same edit that puts NP-020, NP-023 and NP-024
outside this slice — and ADR-MCPRE-069 §5 forbids it for the same reason at both layers: a
control's registration must not be what makes its proposition true.

The severity states it from the other side. This proposition is `critical` — *a signature
base carries covered values, so anything placed there is in every retained copy of the base*
— and the unit is `medium`. A `critical` proposition registered under a `medium` unit is a
claim the unit's own evidence adequacy does not match.

No other unit is a candidate: measured across all thirteen `sdk_python.*` descriptions, none
mentions secret material, leakage, or what a binding contains.

## The theorem question, and it is settled rather than open

`sdk_python.authorization_binding` is one of the twenty theorem-less units, while `M211` and
`M212` carried `theorem = "THM-0094"`. THM-0094's ratified `scope` decides which is right:

> REQUEST-SIDE ATTRIBUTION IS OUTSIDE IT. Which identity may sign, and under which custody
> class, is `sdk_python.signer_policy`; which authorization artefacts a request is bound to is
> `sdk_python.authorization_binding`. Remove either and the answer the application receives
> still binds to the request that was sent, which is why neither is in this closure.

The unit is theorem-less by decision. Attaching it contradicts that sentence rather than
decomposing one, and `scope` is a `theorem_claim` component, so changing it republishes
THM-0094. The probes were the wrong record and are corrected in this change: `M178`, `M201`,
`M202`, `M211` and `M212` — every probe on a Python unit that sentence and the read-bound
sentence exclude by name — no longer carry a `theorem` key. It is optional, no gate reads it,
and `verify-mutations` prints `probe.get("theorem", probe["unit"])`, so they now report under
their unit.

**Consequence for ratification:** this proposition has no ratified theorem above it, so it is
R6 whichever owner it lands in.

## Proposed shape

Either (a) amend `sdk_python.authorization_binding`'s `description` to carry the TypeScript
twin's clause — *"the core digests the real artifact material and a caller is given no way to
supply a precomputed digest or to mint half a binding pair"* — and raise its
`direct_consequence_severity`, taking NP-020 … NP-024 together as one ratification; or (b) a
new unit over `authorization.py`'s carriage boundary at `critical`. (a) is the smaller tree
change and is what the TypeScript side already looks like; (b) is the one that keeps the
severity honest without moving an existing unit's. That choice is the R6 question.

## Lane

`sdk/python/tests/test_authorization.py` is behind NO `importorskip`. Both controls select
and PASS on the prepared `sdk/python/.venv-cp314` (CPython 3.14.7).

## N1

Nothing registered. No unit's `description`, `paths` or severity changed. `M211` and `M212`
lose an optional annotation, which moves `sdk_python.authorization_binding`'s fingerprint;
its test and mutation evidence is re-established in this change.
