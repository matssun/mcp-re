<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-182 — R6 ratification packet: an unstated contract is not a did-not-run verdict

**Disposition:** referred, whole. One control, one `[[disposition]]` row, one record.

## Provenance

Filed inside NP-111's original fifteen, where the record's "if false" paragraph paired it with
`an_unstated_contract_produces_no_invented_disposition` as *"the same rule in two crates"*.
That pairing is right about the rule and wrong about the disposition: the proxy-side control
measures a rendering function that exists only in `proxy.rs` and is now registered; this one
measures a vocabulary that is already registered somewhere else.

## The proposition is THM-0061's first clause, verbatim

> `ExecutionStatus::Unstated` and `ExecutionStatus::NotExecuted` are distinct inhabitants, and
> a rejection body carrying no execution contract yields the silent one rather than a guess.
> An unrecognized value is carried as unrecognized and never read as a known one.

## Why it is not a registration, in two independent reasons

**It is already established, by the owner, in the owner's module.**
`client.execution_contract` holds
`lib#execution_contract::tests::a_receipt_that_says_nothing_is_not_a_receipt_that_says_it_did_not_run`
and `lib#execution_contract::tests::an_unrecognized_value_is_carried_and_never_read_as_a_known_one`.
Between them they assert everything this control asserts about `ExecutionStatus` and
`is_stated`, and this control adds `retry()`, `continuation_consumed()`, `retention_failed()`
and `retry_is_refused()` over the same `ExecutionContract::default()` value.

**Its body is in a file the owning unit does not digest.**
`client.execution_contract`'s `paths` are `execution_contract.rs` and
`result_classification.rs`. This control's body lives in `response.rs`'s `delegated_tests`
module. A `lib#` selector resolves by PROJECT, so the census would accept the registration
happily — and the unit would then derive FRESH over a control whose body it does not
fingerprint. `_fingerprint._test_sources` exists precisely to stop a control keeping its
declared name and losing its body, and it reaches integration-test targets only; a unit test
in an undeclared module is the one door it cannot see.

Widening `client.execution_contract`'s `paths` to include `response.rs` is the third
possibility and is refused outright: the slice's authority forbids widening any unit's
`paths`, and it would put a vocabulary unit's fingerprint under every edit to the client's
delegated response verifier.

## What would close it

Move the control into `execution_contract.rs`'s own `#[cfg(test)] mod tests` — where its
imports already point — and add the selector to `client.execution_contract`. Both reasons
above dissolve at once: the body is then inside the unit's `paths`, and the control's extra
assertions extend the owner's battery rather than duplicating it from next door.

Moving a test file is the operation this repository has measured as touching several tables
at once, and moving a test MODULE between files in one crate is the smaller cousin of it. It
is a source change with its own review, not a registry edit, and it did not belong in a slice
whose authority is `supported_by` and evidence organisation.

## N1

Nothing registered, so no obligation moves.
