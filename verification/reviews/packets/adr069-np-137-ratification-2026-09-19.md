<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-137 residue — R6 ratification packet: the two defaults and the unowned file

**Disposition:** R2 in part, R6 for the residue. Eleven controls landed as
`unit://proxy.certificate_identity_refusal_vocabulary` under THM-0024 (probe `M285`) and
`unit://proxy.credential_currency_evidence_reporting` under THM-0032 (probe `M286`). Three
rows remain; NP-137's `[[proposition]]` entry and record stay in place.

## What landed, and the clauses that contain it

THM-0024, statement, verbatim:

> the returned source equals the field the policy configures ... The five refusals are
> distinguishable: no leaf was presented, the leaf could not be interpreted as a
> certificate, the representation carrying the configured field could not be interpreted,
> the configured field was absent, or the configured field's first value was not a
> well-formed identity ... Present-but-uninterpretable is never reported as absent, and the
> refusal names the first rule that failed.

THM-0032, statement, verbatim:

> carries that acceptance, that instant, and the controls the policy actually applied ...
> The outcome has THREE states, not two ... issuer validity window self-issued certificates
> exempt; unparseable refused ... The policy is a TOTAL classification of deployment state
> with no `Option` and four variants, so *evaluating with nothing configured* cannot be
> written.

## The residue

### 1. `certificate_identity_policy::tests::the_default_policy_is_the_uri_san`
### 2. `peer_identity_provenance::tests::the_default_provenance_is_the_channel_credential`

Both are DEFAULT-value claims, and a default is a choice between product behaviours. THM-0024
is quantified over *the field the policy configures* and says nothing about which field an
unconfigured deployment gets; THM-0080 is about the serving path's identity ROUTE and says
nothing about which provenance is selected when nothing is. Registering either under those
theorems would smuggle a product choice into a claim quantified over the configuration.

The honest shape is one small theorem over both, since they are the same proposition one
level apart:

**Proposed statement.** An unconfigured deployment's peer identity comes from the credential
that established the channel, read from its URI SAN. Neither default is a fallback: a
deployment that configured URI SANs is never silently read at a legacy Common Name, and a
deployment that configured no ingress assertion never reads a header.

**Security consequence.** The complement is a silent downgrade — the exact substitution
THM-0024's own security consequence names (*cannot be silently downgraded to a legacy Common
Name*) but does not establish, because THM-0024's claim starts after the policy is chosen.

**Supporting unit.** `proxy.peer_identity_defaults`, `tested`, critical, paths
`communication_assurance/{certificate_identity_policy.rs, peer_identity_provenance.rs}`,
two controls. Falsifier: move `#[default]` to `CommonName` / `IngressAssertion` and both go
red.

### 3. `current_authenticated_peer::tests::an_authentication_that_never_happened_cannot_be_made_current`

This one is arguably R2 under **THM-0033** — *Every
CurrentAuthenticatedRelationshipPeerFacts inhabitant originates from an inhabitant produced
by ... a free function taking an AuthenticatedRelationshipPeerFacts by value, a
CredentialCurrencyPolicy and an instant, and nothing else* — and it was left unregistered
rather than landed for one reason: the honest unit is a single control over a file
`proxy.current_authenticated_peer` already declares, and whether that control belongs in
THAT unit's battery or in a second unit beside it is a decision about an existing unit's
evidence definition, which this campaign may not take. One line of owner ruling closes it.

## Measurement correction against the analysis

The analysis put `current_authenticated_peer` in the credential-currency half, under
THM-0032. The tree disagrees: `communication_assurance/current_authenticated_peer.rs` is
`proxy.current_authenticated_peer`'s path and that unit supports **THM-0033**, the
composition, not THM-0032. Registering the control under THM-0032 would have claimed the
composition's property for the currency authority.

## Fingerprint

No ratified theorem's fingerprint moves; both attachments are `supported_by`-only.
