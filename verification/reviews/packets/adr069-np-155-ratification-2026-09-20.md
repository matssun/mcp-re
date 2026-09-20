<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-155 residue — R6 ratification packet: the signed 202, the verifier's refusal, and a refusing site no unit owns

**Disposition:** R1 in part, R6 for the residue. Eight of NP-155's twenty-nine controls landed
as `tested_symbols` under THM-0045, THM-0062, THM-0069, THM-0070 and THM-0075, with three
falsifiers demonstrated red — `M355-proxy-a-bound-rejection-is-served-as-an-unbound-one` (new),
`M356-proxy-an-expired-delegated-snapshot-keeps-signing` (new), and
`M165-a-record-states-its-half-twice-and-the-two-can-disagree` (widened). Twenty-one rows
remain. **Four** of them were examined by this slice and refused; the other seventeen were not
this slice's scope. NP-155's `[[proposition]]` entry and its record stay in place.

Nothing here says the four are unevidenced. Each is a live, passing control. The finding is
that no RATIFIED theorem contains what it asserts, so registering it would make a theorem's
battery claim something the theorem wrote down that it does not.

## The lane, measured first — and the analysis had it wrong for every proposition in the slice

ANALYSIS-CO-S3 §1 and §2 record the lane of CO-S3-P26 through P30, P34 and P35 as
`async_serve`, and §8 schedules the slice as an `async_serve` one. Measured, at
`65f054bd`:

| selection | total | `delegated_serving_test` | `delegated_production_wiring_test` | `delegated_client_server_e2e_test` |
|---|---:|---:|---:|---:|
| `cargo test -p mcp-re-proxy --test integration_async -- --list` | **167** | **12** | **1** | **16** |
| `cargo test -p mcp-re-proxy --features async_serve --test integration_async -- --list` | **197** | **12** | **1** | **16** |

All twelve controls in this work package are selected in BOTH lanes, and therefore compile and
run in the plain DEFAULT cargo lane. `--features async_serve` adds thirty tests, none of them
in these three files. The three files carry no `#![cfg(feature = "async_serve")]`.

Consequence: none of the five receiving units declares `test_features`, none was given one, and
declaring `async_serve` on any of them would have named a lane the evidence is not confined to
— the exact defect the previous slice in this queue was corrected for. The lane is stated at
each registration rather than left to be inferred.

**A second lane fact, recorded against the register.** NP-155's `**If false.**` line said the
controls run "in the Bazel `async_serve` lane". That is true and incomplete: they also run under
plain `cargo test -p mcp-re-proxy`. A record naming one lane for a battery that two lanes select
is how a feature-gated battery comes to look measured when it is not, so the record now carries
the correction explicitly.

## Residue 1 — the signed bodyless 202 (3 rows)

`CD-19142` `a_notification_is_served_a_verifiable_delegated_202`,
`CD-19149` `the_client_cores_own_notification_envelope_earns_a_202`,
`CD-19150` `the_client_facing_crate_can_verify_the_202_the_server_emits`.

THM-0075 was the proposed home, and §8 named this as the one proposition in the slice needing a
decision. It is decided here, against registration, on two independent clauses.

**Clause 2 fails.** THM-0075's scope, verbatim:

> SECURITY-BEARING SIGNED evidence only. Unsigned transport and error responses exist — a
> last-resort receipt is emitted when no valid credential does — and they are outside this
> claim, which is why it does not say every response carries evidence.

The emission half of these controls is inside the statement: the 202 is signed by the delegated
capability, and `verify_delegated_accepted_202(&ack, &note, …)` binds it to the notification it
acknowledges. But the controls do not measure only that half. Each asserts the WIRE CONTRACT:
`served.status == 202`, `ack.body.is_empty()`, and the credential riding in a covered
`mcp-re-delegation` HEADER rather than in the body's evidence block. That is a claim about WHICH
response a given request class earns and what shape it takes — precisely the subject the scope
above declines. A theorem that says in terms that it does not say every response carries
evidence does not contain a proposition fixing, for the notification class, that one does and in
what form.

**Clause 3 fails independently.** *An accepted notification is answered with a signed bodyless
202 both ends agree on* is an externally meaningful promise between a serving PEP and every
client that speaks the profile. It was settled by the #424 owner ruling — cited in the test
file's own doc comment — which makes it a chosen product behaviour, not a decomposition of an
existing one. Registering it as a battery addition would attach an unratified product promise to
a ratified theorem without a review of the promise.

**A third failure, specific to `the_client_cores_own_notification_envelope_earns_a_202`.** It
asserts that `mcp_re_client_core::build_signed_notification`'s output — an envelope with no `id`
KEY at all — is classified as a notification by the serving path. That is a cross-crate
correspondence. Its client half is THM-0125, verbatim:

> A signed NOTIFICATION carries no `id` key at all — absent, never present-and-null — while
> carrying the ordinary RFC 9421 evidence, and a continuation declared on one is refused.

THM-0125's scope is equally explicit that it does not reach the server:

> THE SHAPE, NOT THE SIGNATURE'S CORRECTNESS. That the RFC 9421 signature base is composed
> correctly and verifies is the carrier's, under the http-profile units.

So the producer's obligation is ratified and the serving classifier's agreement with it is
stated by no theorem on either side. The three rows stay together: separating this one would
leave two rows refused for the wire contract and one refused for a missing correspondence, and
the wire contract refuses all three anyway.

**What would resolve it.** A theorem over the notification acknowledgement contract — what an
accepted notification earns, what it carries, and that the two ends classify `id`-absence
identically — with THM-0075 as a dependency and THM-0125 as the client half. That is a new
externally meaningful promise and is a ratification decision, not a campaign one.

## Residue 2 — the verifier's refusal of a direct-root response (1 row)

`CD-19147` `direct_root_response_rejected_in_delegated_required_mode`.

`proxy.delegated_signing_credential` under THM-0062 was the proposed home, on the strength of
THM-0062's security_consequence:

> there is no longer-lived or root credential to fall back to, because no such mode exists

That sentence is about the PRODUCER. The control constructs no proxy at all: it builds a pre-052
direct-root response from `sign_legacy_direct_root_response_for_negative_test`, a test-only
fixture in the file, and asserts `mcp_re_http_profile::Verifier::verify_delegated_bound_response`
returns `HttpProfileError::DelegationCredentialMissing`. The production carrier is the verifier
in `mcp-re-http-profile`, which is in none of the eight paths of
`proxy.delegated_signing_credential`, and widening `paths` is outside this slice's authority.

THM-0062's scope refuses the axis in terms:

> The credential's existence, not its content: it does not establish that the credential chains
> to the deployment's root, that its scope is right, or that a verifier will accept it.

*Whether a verifier will accept it* is exactly what this control measures, in the negative
direction. Registering it under THM-0062 would make that sentence false — clause 1.

**What would resolve it.** The consumer-side theorem THM-0076, or an http-profile verification
unit under it. This slice's scope is P26–P30, P34 and P35; a home outside the proxy-side units
named there is a different slice's work and is recorded rather than taken.

## Residue 3 — a refusing site no unit's `paths` contains (a structural residue, 0 rows)

`CD-19143` `a_request_that_cannot_be_answered_never_reaches_the_backend` landed under THM-0045
in `proxy.dispatch_commitment`, on a security_consequence match:

> not a proxy that quietly serves unjudged requests or discovers a missing credential after the
> tool has already run

The registration is sound and the control is real. What is recorded here is a gap it exposes:
the site that performs the refusal is
`mcp-re-proxy/src/http_profile_serve/answering_commitment.rs::answerable_stage`, and a grep of
`verification.toml` finds that file in **no unit's `paths` at all**. It is mentioned once, in a
comment. So the stage that decides ANSWERABLE — the free-refusal point the whole pre-dispatch
argument rests on, and the one place the `SigningWindow` for the exchange is snapshotted — can
be rewritten without moving any unit's fingerprint.

`proxy.dispatch_commitment` is the natural owner: its `paths` already hold
`signing_window.rs`, `dispatch_commitment.rs` and `request_stages.rs`, and the file's own module
doc describes the same boundary the unit claims. Adding it is a `paths` WIDENING, which this
work package forbids, so it is filed rather than done.

**What would resolve it.** One `paths` addition to `proxy.dispatch_commitment`, with the
fingerprint consequences measured, in a slice authorised to widen.

## What is NOT in this packet

The remaining seventeen rows — twelve manifest, issuer-pin and revocation round trips blocked
behind NP-009, two audit-surface rows (CO-S3-P36), and the three `mtls_client_leg_e2e_test`
rows (CO-S3-P37) — were outside this work package and are neither refused nor deferred by it.
They are still `new-proposition` rows on NP-155 and still await their own passes.
