<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-140 and NP-177 — R6 ratification packet: the TLS plane's stated bound, and the custody it was handed

**Disposition:** R2 in part, R6 for the residue, and the residue is TWO propositions. Three of
NP-140's nine controls landed — one as `unit://proxy.retired_plane_cadence_retraction` under
THM-0131 (probe `M329-proxy-a-retired-plane-retracts-its-cadence`) and two as R1 rows into
`proxy.listener_state_assembly` under THM-0048. The remaining six are split under RR-002 C5
into **NP-140** (4, the bound) and **NP-177** (2, custody agreement). Both entries and records
stay in place.

Measured from the tree at `adr069/px-trust-plane-premises`, 2026-09-19. All nine controls appear
in `cargo test -p mcp-re-proxy --lib -- --list`; `pub(crate) mod tls_plane;` carries no `cfg`,
so the default lane is the lane.

## The correction of law this packet carries, re-checked against the file

`ANALYSIS-proxy-premise.md` blocked NP-140 whole on THM-0102's sentence:

> that a connection is in fact closed at the configured age is an OBLIGATION this theorem names
> and does not establish — that code has no test and belongs to no unit

That reading is right about the point of law — a theorem that says "does not establish" has
withdrawn the promise, and a unit establishing it under THM-0102 would make the scope paragraph
false. It is wrong about the CARRIER. Two clauses earlier the same paragraph says:

> The bound on a live connection's age is enforced in `async_serve/connection.rs` (a graceful
> shutdown at `max_connection_age`)

NP-140's controls are `tls_plane::fleet_crl_bound_tests` and `tls_plane::handle_lifetime_tests`,
in `mcp-re-proxy/src/tls_plane/mod.rs`. The blocker was matched on the concept and not on the
carrier, and it does not apply. `REVIEW-proxy-premise-subsumption.md` §5.1 reached the same
conclusion; this packet re-read both the sentence and the file rather than inheriting it.

**What that correction does and does not buy.** It removes the WRONG reason for referring these
rows; it does not make them landable. The four that remain are referred because no ratified
theorem states the bound's TOTALITY over the CRL-less and cadence-less postures — which is a
different and much narrower finding than "THM-0102 forbids it".

The review's other two placements are also re-tested here, and one of them is REFUSED — see
NP-177 below.

## What landed, and the clauses that contain it

THM-0131, statement, verbatim:

> And a replica whose reload worker has died, or whose plane has retired, retracts the cadence
> it advertised: the maintenance verdict is latched, and no later reload can clear it.

`handle_lifetime_tests::a_retired_plane_stops_claiming_a_cadence` is the *plane has retired*
arm, word for word. It is registered as its OWN unit rather than added to
`proxy.client_revocation_currency`, which states the same proposition and already holds the
worker-death arm: that unit's `paths` are `crl_evidence.rs`, `revocation_currency.rs`,
`crl_reload_worker/supervision.rs` and `client_revocation_posture.rs`, and the retirement
happens in `tls_plane/mod.rs`. `_validate_in_crate_selectors` refuses a `lib#` selector whose
module is under no declared path, and widening an existing unit's `paths` to reach a control is
out of scope for this campaign — so a second unit under the same theorem is the honest shape.

THM-0048, statement, verbatim:

> The epoch is a function of the anchor set alone, so a replacement listener and session-cache
> boundary does not carry resumption authority across the replacement when the epoch differs: a
> different anchor set is a different state with its own empty resumption cache, while a
> rebuild that republishes the same trust keeps its cache.

The two `trust_epoch_binding_tests` rows are that sentence in both directions. They are an R1
into `proxy.listener_state_assembly` — `tls_plane/mod.rs` and `tls_listener_state/mod.rs` are
both already its paths — and the reattribution is MEASURED rather than argued: neither control
constructs a `TlsPlane` at all. `the_store_starts_under_the_epoch_of_the_planes_own_client_auth_inputs`
calls `TlsListenerSecurityState::new` directly and
`a_rebuild_republishes_the_epoch_of_the_anchor_set_the_plane_owns` calls `material.rebuild(…,
&state)`; they are the plane-side twins of `the_epoch_digests_the_anchors_this_state_owns` and
`a_rebuild_keeps_the_cache_and_the_epoch_of_the_state_it_was_built_through`, which that unit
already holds.

## NP-140 residue — what a CRL-less or cadence-less deployment is bounded by (4 controls)

`fleet_crl_bound_tests::{a_reload_cadence_bounds_established_connections_not_only_handshakes,
without_a_cadence_the_bound_is_the_crls_own_expiry,
without_a_crl_the_bound_is_the_certificate_lifetime}`,
`handle_lifetime_tests::a_snapshot_that_outlives_the_plane_still_serves`.

**Statement.** Every deployment has a stated bound on how long a revoked client may keep a
connection it already established, and the bound is a TOTAL FUNCTION of what the deployment
configured. With a reload cadence, the bound is the cadence and it applies to ESTABLISHED
connections rather than only to new handshakes. Without a cadence, the bound is the CRL's own
expiry. Without a CRL at all, the bound is the client certificate's lifetime. A snapshot taken
before the plane retired continues to serve under the bound in force when it was taken.

**Security consequence.** A revoked client keeps a connection it established before the
revocation, and nothing in the handshake path can see it — rustls runs client authentication on
a full handshake only. That is the clause that makes client revocation about established
connections rather than handshakes. The totality is the second half and is the one an operator
needs: a deployment that configured no CRL is not unbounded, it is bounded by the certificate
lifetime, and saying so is the difference between a stated posture and an unknown one. The
retired-plane clause is the availability arm — retirement must not strand a live snapshot — and
it is a deliberate non-transition, unlike `trust_plane`'s resolver and `signing_plane`'s signer.

**Scope.** The BOUND the deployment states, in `tls_plane/`. NOT that a connection is in fact
closed at the configured age — THM-0102 names that as an obligation it does not establish, and
the enforcement lives in `async_serve/connection.rs`, which is not this carrier. NOT the epoch's
derivation (THM-0048's). NOT the cadence retraction latch (THM-0131's). NOT that a CRL is
fetched, fresh, or correct.

**Severity.** `critical`, the registry's own `NP-140.consequence`.

**Why no existing theorem contains it.** THM-0102 withdraws the connection-age promise in terms
and, as shown above, is about another file. THM-0131 claims the retraction rather than the
bound and is explicit: *"It is NOT a fail-closed … What is claimed is that the advertised
property is withdrawn, not that the exposure is zero."* Nothing states that the three postures
partition the configuration space, which is what the totality clause asserts.

**`depends_on`.** `THM-0131` for the retraction semantics the fourth control leans on;
`THM-0054` arrives transitively through it.

## NP-177 — the TLS plane refuses a key source that disagrees with the declared custody (2)

`custody_agreement_tests::{a_key_source_that_disagrees_with_the_declared_custody_refuses,
agreeing_custody_passes_the_check_and_fails_on_something_else}`.

**`REVIEW-proxy-premise-subsumption.md` placed these two under THM-0064 / THM-0073 as ordinary
R2 work. That placement is REFUSED here, on the text of both theorems.**

THM-0064's subject is the CLASSIFIER and its projection — *"The custody owner classifies each
legal selection into exactly one state carrying the material that made it inhabitable, and
projects a single semantic fact — `PrivateKeyExposure`"* — and its scope draws the line this
control sits on the far side of: *"It establishes what the classified STATE asserts, not that
the remote signer implementation honours it."* A plane handed a key source that contradicts the
state falsifies nothing THM-0064 claims; the state still asserts what it asserts.

THM-0073 is a comparison between the two SIGNING ROLES' materialized public keys — *"the
response-signing role and the channel-signing role resolve to the same cryptographic
signing-key identity"* — a different relation over different values, and it says in its own
scope that it *"claims nothing about … custody"*.

THM-0082 is the nearest in spirit and still not it: *"A deployment cannot announce one signing
custody at startup and sign with another on the data plane"* is the RESPONSE-signing side, *"the
counterpart of THM-0066 on the signing side"*, measured over the composition root's own source.
This control is the CHANNEL side, measured at `TlsPlane::materialize`.

**Statement.** A deployment configured for delegated handshake custody and handed an exported
key materializes no TLS plane, and the refusal names both sides. Agreement is not refused: an
agreeing pair passes this check and fails later, on something else, so the diagnostic states
which check ran.

**Security consequence.** The deployment serves handshakes under weaker custody than its own
transcript claims. Nothing else compares these two facts — layer A classifies the custody from
the TLS key selectors, the key source produces an actual signer, and every startup line reports
the DECLARED custody — so the divergence would be invisible in exactly the place an operator
looks. The negative control is not decoration: without it the refusal assertion would pass just
as well under a `materialize` that refused everything.

**Scope.** The one place the REQUESTED custody and the ESTABLISHED custody meet, at channel
materialization. NOT what a custody selection asserts about exposure (THM-0064's). NOT the two
signing roles' separation (THM-0073's). NOT the response-signing composition root (THM-0082's).
NOT that an external KMS or token honours non-exportability, which is the provider's property.

**Severity.** `critical`, carried from NP-140 rather than reassessed.

**`depends_on`.** `THM-0064` — what the declared custody state asserts is the premise the
comparison is against.

## Evidence that already exists

All six residue controls run and pass in the default lane. **No falsifier exists for any of
them.** N1 is at 0 open estate-wide with the ratchet closed to new work, so each unit the owner
authorizes ships with its own `mutation://` probe in the same change. The shapes are already
visible: for NP-140, make the no-CRL case return no bound instead of the certificate lifetime
and `without_a_crl_the_bound_is_the_certificate_lifetime` must go red — a total selector losing
one arm; for NP-177, delete the custody comparison in `TlsPlane::materialize` and
`a_key_source_that_disagrees_with_the_declared_custody_refuses` must go red while
`agreeing_custody_passes_the_check_and_fails_on_something_else` stays green.

## The fingerprints these would carry

Each new theorem carries `theorem_id`, `theorem_claim`, `theorem_dependencies` and
`theorem_review_requirement`. The dependency closure is TRANSITIVE: NP-140 naming `THM-0131`
pulls in `THM-0054`, `THM-0048` and `THM-0103`, four entries from one edge; NP-177 naming
`THM-0064` pulls in nothing further, THM-0064's own `depends_on` being empty. `supported_by` is
not a fingerprint component (`_fingerprint.py:707-727`), so **granting either moves NO existing
theorem's fingerprint.** Making either a premise of THM-0102 would move THM-0102 and its
transitive dependents, the roots THM-0077 and THM-0074.

## What the owner is being asked

1. Ratify each statement / consequence / scope under ADR-MCPRE-059 §28, or decline it and say
   what the controls are instead.
2. Confirm or overturn this packet's refusal of the review's THM-0064 / THM-0073 placement for
   the custody-agreement pair. If the owner reads THM-0064 as reaching the ESTABLISHED custody
   as well as the classified state, NP-177 is ordinary registration work and not a question.
3. NP-140's totality clause is the part with no home. Is *the three postures partition the
   configuration space* one theorem with the established-connection clause, or two?
