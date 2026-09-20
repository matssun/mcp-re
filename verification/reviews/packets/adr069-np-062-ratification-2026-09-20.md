<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-062 — ratification packet: the per-request revocation index, and the theorem the plan named

**Disposition:** R2 for eleven of twelve — two new units under **THM-0032**, falsifiers
**M346** and **M347**, both demonstrated red in the default cargo lane. R6 for the twelfth,
which stays NP-062 and whose record is rewritten to describe exactly it.

This is the record where the slice plan's theorem was the one theorem in the estate that
refuses the file, and it refuses it in terms.

## 0. THM-0054 cannot take any of the twelve

The plan expected six of twelve inside THM-0054's statement. Measured, it is zero, and the
reason is one sentence of THM-0054's own scope:

> It does not establish that the CRLs a deployment loads are current or complete, and it
> establishes nothing about the per-request revocation check, which is a separate authority
> holding the same invariant.

`mcp-re-proxy/src/client_revocation.rs` IS that separate authority. Its module header opens:

> PER-REQUEST client-certificate revocation, so a warm connection is not a hole.

So every one of the twelve is inside a population a ratified scope sentence declares out of
scope. Registering any of them under THM-0054 would contradict a fingerprinted field rather
than decompose one, which subsumption clause 2 does not permit.

THM-0131 closes the same door from the other side, and names both halves:

> It says nothing about whether a revoked peer is refused — that is THM-0054's handshake
> half and the per-request index beside it

## 1. THM-0032 is where the index's answer is stated, twice

THM-0032's statement enumerates the five facts a credential-currency evaluation computes.
Two of its clauses are about this index:

> leaf revocation       `admits`: an empty index admits, otherwise Revoked AND Unknown refuse

> The revocation index it carries is the SNAPSHOT in force for the request, not the atomic
> cell: the leaf check and the issuer check therefore cannot read two different indexes
> across a reload.

Its family already measures the CONSUMER: `proxy.credential_currency` over
`evaluate_credential_currency`, `proxy.credential_currency_evidence_reporting` over the
reporting, `proxy.currency_policy_classification` over the policy that captures the index,
and `proxy.per_request_revocation_serving` over the serving composition. None measures the
index, and the serving unit points here in its own description:

> It states nothing the predicate states: WHICH certificates the index refuses, the
> leaf/issuer strength asymmetry and the one-snapshot-per-request rule are
> `proxy.credential_currency`'s

That unit could not have taken these rows in any case: it declares
`test_features = ["async_serve"]` and all twelve are default-lane `lib#` controls. Measured:
`cargo test -p mcp-re-proxy --lib -- --list` selects 1498 controls and all twelve
`client_revocation::tests::` are among them. Neither new unit declares `test_features`, and
neither would be true if it did.

## 2. Two units, and the axis is not the plan's

The plan drew 6/6 on *inside THM-0054's statement* / *index algebra*. With THM-0054 out that
axis does not exist. The question that remains is ADR-MCPRE-061 §8 question 2 — how many
independently describable authorities — and the answer is two:

**`proxy.client_revocation_index_verdict`** (9 controls, `critical`) — WHAT the index answers
about one certificate. Listed/unlisted, zero-pad normalisation, issuer scoping, the union of
two CRLs keeping the earliest `nextUpdate`, the empty index, the uncovered issuer, the
unknown-status refusal with no policy input, and the two directions of a lapsed list.

**`proxy.client_revocation_snapshot`** (2 controls, `high`) — WHICH index a request reads.
The atomic swap, and the poisoned-lock arm that must still yield the last good index.

One unit over both would need an "and" in its answer to question 1, which this project treats
as evidence of a shallow boundary. The stale/expired pair stays inside the first unit
deliberately — *a stale CRL certifies nothing but still revokes* and *an expired CRL refuses
its issuer rather than admitting it* are opposite directions of one rule about a lapsed
list, not two authorities.

## 3. The falsifiers

**M346** flips `admits`'s `RevocationVerdict::Unknown => false` to `=> true`. Red on
`an_uncovered_issuer_is_unknown_and_refused`,
`unknown_status_is_refused_with_no_policy_input_that_could_admit_it` and
`an_expired_crl_refuses_its_issuer_rather_than_admitting_it`. `VERDICT: PASS`.

The weakening is the historical operator opt-out put back, and the carrier says so:

> the arm below is a literal `false`, so fail-closed is a property of the type rather than
> of what a caller remembered to pass. Restoring an operator opt-out means changing this
> function, which is the point.

Three reds rather than one because they are three different routes to `Unknown`.

**M347** replaces `load`'s poisoned arm with a fresh empty index. Red on
`a_poisoned_lock_still_yields_the_last_good_index_and_still_accepts_a_swap`. `VERDICT: PASS`.

That substitution is a process-wide silent disable, not an outage: an empty index admits
everything by construction, deliberately, so that a deployment configuring no CRLs is not
refused. The control's own comment names the defect — *"A `load` that answered with a
default index instead of the last-good one would silently disable revocation
process-wide."* `the_snapshot_swaps_atomically` is deliberately NOT expected red: it never
poisons the lock, so it reads through the `Ok` arm, and a probe that reddened both would
mean one of the two controls was not measuring its own half.

## 4. Referred (1), and it stays NP-062

`lib#client_revocation::tests::a_malformed_crl_is_refused_rather_than_skipped`.

It is a CONSTRUCTOR refusal: `ClientRevocationIndex::from_crl_ders` returns
`Err(TlsError::Verifier(_))` and no index is built. Both of THM-0032's clauses are about a
value that exists — what an index ADMITS, and which index is IN FORCE — and neither can be
falsified by an index that was never made. Nor is it the snapshot's: no cell is involved.

Its subject is real and is the reason it is kept rather than dropped: the carrier's own
comment says skipping would *"leave the request path enforcing a smaller revoked set than
the handshake"*, which is a disagreement between the two enforcement points in the direction
that admits. It is also not THM-0054's, for §0's reason.

## 5. What would discharge the remainder

A theorem over the parity between the two revocation enforcement points — that the
per-request index is built from exactly the CRL bytes the handshake verifier is built from,
and refuses wherever the verifier would refuse. The one control above is one clause of it,
and `crl_posture`'s own refusals would be the rest.
