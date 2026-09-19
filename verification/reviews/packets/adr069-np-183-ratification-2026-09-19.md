<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-183 — R6 ratification packet: a configured clock skew cannot widen the credential window

**Disposition:** referred, whole. One control, one `[[disposition]]` row, one record.

## Provenance

Filed inside NP-111's original fifteen. It is not a reply-disposition control in any reading,
and the S-05/CL-CLIENT slice split it out under RR-002 C5 rather than leave a record whose
statement had to grow a clause about credential validity to keep it.

## What it measures

`lib#response::delegated_tests::an_out_of_range_skew_cannot_widen_the_credential_window`
builds a request whose own RFC 9421 window brackets a much later verification instant, issues
a delegated credential with a 300-second TTL, and has the server sign a rejection receipt
3600 seconds later — so the RESPONSE signature is fresh at the verification instant and only
the CREDENTIAL is stale. The failure it asserts is therefore the credential window's and
nothing else's.

The control's own documentation states the defect it was written for:

> The credential's `nbf`/`exp` window is widened by the configured skew and had no cap of its
> own: `DelegationExpectations.max_clock_skew` reached `DelegationVerifyParams` raw. An
> operator who set a week got a week on the credential window — the TTL that bounds a
> compromised delegated key's exposure — while the signature gate they could observe was
> silently clamped, so testing the setting showed nothing wrong.

## Why it is R6

**NP-111 never contained it.** The record's statement listed it among fifteen clauses joined
by semicolons; no reading of *"a verified reply's disposition is the one the receipt states"*
asks how long a credential stays current. Keeping it would have meant widening the rewritten
record to cover a proposition about key exposure, which is the quiet widening ADR-MCPRE-069 §5
holds to be worse than leaving a control unregistered.

**THM-0061 does not contain it either.** That theorem's scope is *"What the receipt SAYS, and
what a client may conclude from it"*, and it explicitly establishes nothing about whether the
server's statement is true. A credential's validity window is not something the receipt says.

**The near neighbour is THM-0058, and the question is genuinely open.**
`client.response_signer_authorization` owns *which* signer a client accepts a response under,
and its statement covers a credential chaining to a trusted root, a route pin, and revocation.
Whether "and the operator's configured skew does not extend the credential's own window" is a
decomposition of that claim or a second proposition beside it is the ratification question.
The two readings differ in what they promise an operator: the first says the authorization
decision is correct, the second says the CONFIGURATION SURFACE cannot silently enlarge it —
and the control's own history is that the observable half behaved while the unobservable half
did not, which is an argument for the second. That judgement belongs to the theorem's owner.

## Proposed shape for ratification

Either a clause added to THM-0058 by its owner — a theorem-text edit, outside an evidence-
organisation slice's authority by construction — or a sibling proposition over the delegation
verify parameters:

> Every operator-configurable tolerance on the response path is clamped before it reaches a
> validity window, and no configured value can extend a delegated credential's own TTL.

Its natural companion controls are the ones over the signature freshness gate that IS clamped,
so that the two halves of the same setting are measured together rather than one of them
being the only observable.

## N1

Nothing registered, so no obligation moves.
