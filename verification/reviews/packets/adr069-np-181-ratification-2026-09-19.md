<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-181 — R6 ratification packet: a verified error reply is a failed call at the place that decides

**Disposition:** referred, whole. One control, one `[[disposition]]` row, one record.

## Provenance

Filed inside NP-111's original fifteen. Split out under RR-002 C5 during the S-05/CL-CLIENT
slice, because the proposition it names is THM-0126's composition question and the control
that names it does not measure THM-0126's composition.

## The proposition

`ResponseKind::CallFailed`'s own documentation states it, and states why the distinction is
not recoverable later:

> `classify_result` reads the `result` member, and an error reply has none — so an absent
> `result` classifies as terminal and the failure would be announced to the local client as a
> completed call. The signature is equally valid either way; what differs is what the server
> said, and that difference is not recoverable once the header has been written.

The production arm is the first branch of `read_outcome`'s `DelegatedOutcome::Success` case
in `mcp-re-client-proxy/src/verified_outcome.rs`.

## Why the control does not establish it

`lib#proxy::tests::a_verified_error_reply_is_classified_as_a_failed_call_not_a_success`
rebuilds the reply and then writes the selection itself:

```rust
// The selection the serving path makes, on the reply it actually holds.
let kind = match plain.get("error").map(|e| e.get("code").and_then(Value::as_i64)) {
    Some(code) => ResponseKind::CallFailed { code },
    None => match classify_result(plain.get("result")) {
        ResultClass::Terminal => ResponseKind::Success,
        _ => unreachable!("this fixture carries an error member"),
    },
};
```

The comment is honest about what it is — *the selection the serving path makes* — and that is
the defect. It is a transcription of `read_outcome`, not a call to it. Delete the `CallFailed`
arm from `verified_outcome.rs` and this control stays green; every reply carrying an error
member would then reach the application as `Success`, and nothing in the battery would say so.

Two things it DOES establish, and both are already owned: that
`plain_response_from_verified` carries the `error` member through (NP-111's first clause), and
that `classify_result` reads `result` (`client.execution_contract`'s, under THM-0061).

## Why it is R6 and not a registration

The attractive registration is `client.verified_outcome` under THM-0126: the project matches,
the file the proposition belongs to is that unit's only path, and the statement is contained —
*"A VERIFIED rejection receipt resolves to a provable denial carrying the signed wire code,
never to a success result"* is its neighbour, and the error-member arm is the same rule for the
inner tool's failure rather than the boundary's refusal.

It is refused because the unit's battery would then hold a control that cannot go red on any
edit to the unit's only file. That is worse than leaving the control unregistered: an
unclaimed control is visible debt, while a claimed tautology reports coverage the tree does
not have, and the unit's five existing controls all DO drive `read_outcome`.

## What would close it

A sixth control in `verified_outcome.rs`'s own `mod tests`, beside
`a_verified_rejection_receipt_is_an_answer_and_never_a_success`, that performs a real
delegated signing round trip with an inner JSON-RPC error body and asserts
`read_outcome` yields `ResponseKind::CallFailed { code: Some(-32601) }`. Then
`client.verified_outcome` gains a control it can lose, and a mutation probe deleting the
`CallFailed` arm reddens it. That is production-adjacent test work, not a registry edit, and
this slice had no authority for it.

## N1

Nothing registered, so no obligation moves.
