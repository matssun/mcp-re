# The three unstated TLS propositions — #581 / MCPRE-145, with #598's correction — 2026-09-06

Backlog item 5 of the v0.17 AFK mandate: "TLS propositions already governed by #581/#598".
#581 asks for three theorems, each attached to the smallest authority that establishes it,
each carrying a scope sentence naming what it does **not** establish. #598 requires that the
first of them not be phrased as a lifecycle claim the production composition does not have.
Both issues are HITL; this is the AFK half.

Baseline: `assurance/exchange-transition-correspondence` head `18bd34de` (#820: THM-0101) on
main `c6cf8913` (#819: THM-0100). Slice branch `assurance/tls-propositions`.

## 1. The measurement: one of the three rows was already stated

| #581 row | measured state on this tree |
|---|---|
| 1. Resumption is offered only while the authentication epoch is current | **partly stated.** THM-0048 covers the *composition* — the epoch is a function of the anchor set, a rebuild with withdrawn trust advances it and stops resumption, no config resumes outside the store. The **store's own contract** is not stated anywhere: the tag-match rule for every read, eviction on mismatch, and that a current session actually *does* resume at the rustls level. |
| 2. A connection cannot outlive the credential that authenticated it | **genuinely unstated, and unowned.** `config_state/client_credential_window.rs` and `config_state/credential_currency_bound.rs` belonged to no `[[unit]]` at all, so the sealed relation was evidence for nothing. |
| 3. Transport identity is derived only from the verified client certificate | **already stated — the row is stale.** THM-0080 (`unit://proxy.serving_identity_provenance`, ADR-MCPRE-064 Slice 2, #619/#621) states that neither direct-TLS serving path reconstructs identity from representation and that each asks its authority exactly once through a signature admitting no second credential. THM-0031 is the authority half. #581 was filed before that landed and calls row 3 "a genuine gap"; it is not one today. |

Recording that third row as a new theorem would have created a duplicate authority over a
fact the tree already holds — the failure mode ADR-MCPRE-059 rev1 produced three times. It
is corrected in the component doc instead.

## 2. Row 1 — THM-0103, phrased at the store, per #598

`EpochBoundSessionStore` prefixes every stored value with the epoch in force at the write and
splits every read at that same width (one split, so prefix and payload cannot be taken at
different offsets); a read returns the session iff the tags match; a `get` that mismatches
**evicts**, because `get` leaves the entry in place and a stale session would otherwise sit
being re-read and re-rejected until it aged out.

Both directions are witnessed against real rustls handshakes inside the owner's module tree
(`resumption_acceptance::handshakes`), not against a `HashMap`. The `Resumed` witness is part
of the claim on purpose: **a store that silently never resumed would satisfy every refusal
conjunct** and would have quietly withdrawn the performance property ADR-055 exists to
provide.

**What the scope says, in terms.** Within a production listener the trusted client-CA set is
immutable, so the authentication epoch is a *construction-time constant* and the change
branch of the publication has never fired outside a test. THM-0103 must never be read as
establishing that a production listener's epoch advances when its anchors change — nothing
in the tree establishes that, and ADR-MCPRE-062 settled the question by choosing the
immutable-listener model, where an anchor change replaces the listener and therefore the
store and the safety property is cache **non-continuity** (THM-0048). The epoch covers the
CA set and excludes CRL contents; a revoked peer is refused per request, not by the epoch.

**Composition.** `THM-0048 depends_on ["THM-0103"]`, because THM-0048's clause "a rebuild
with withdrawn trust advances the epoch and stops resumption" *uses* the store's contract.
THM-0048 already sits under THM-0077, so the transitive closure carries THM-0103 to the root
without a second direct edge.

**Evidence completeness.** Five controls in `auth_epoch::tests` existed and were named by no
unit — the epoch is a property of the anchor *set* (order and duplication are not inputs),
the domain string, and both publication-change directions. They are registered now: a
control the fingerprint does not carry is not evidence.

## 3. Row 2 — THM-0102, and the obligation it does not discharge

`ClientCredentialWindow::new` refuses any pair where `connection_age > cert_lifetime`, where
the lifetime passes the one-hour ceiling, or where either is zero; `exposure_window()`
projects the lifetime. Possession is the statement. The defect this owner closed is on
record: `--max-client-cert-lifetime 600 --max-connection-age-secs 3000` was accepted, both
halves separately bounded against the *constant* ceiling and nothing relating them, while the
transcript reported a 600 s exposure window and a connection outlived its credential by forty
minutes.

**The honest non-claim.** That a *live* connection is actually closed at the configured age
is enforced in `async_serve/connection.rs` by a graceful shutdown on a deadline. That code
has **no test and belongs to no unit**, and it lives in the `async_serve` feature lane, so a
plain `cargo test --workspace` compiles it to nothing. THM-0102 therefore states the relation
at the level of the values a deployment chose and names the socket-level close as an
outstanding obligation rather than folding it in. Closing that obligation is its own slice:
it needs a test in the Bazel lane, and it is listed under remaining gaps.

**Composition.** THM-0102 sits directly under THM-0077 ("no deployment serves a posture
nobody selected"), beside THM-0048 and THM-0054: a deployment cannot hold a posture whose
reported exposure window its own durations contradict.

## 4. Evidence and negative controls

| conjunct | control | probe |
|---|---|---|
| `connection_age <= cert_lifetime`, over the chosen values | `a_connection_may_not_outlive…`, `an_age_equal_to_the_lifetime_is_the_last_legal_pair`, `the_public_constructor_validates_too` | M113 |
| the one-hour ceiling gates construction | `a_lifetime_past_the_ceiling…`, `the_public_constructor_validates_too` | M114 |
| `exposure_window()` is the lifetime, not the age | `the_exposure_window_is_the_lifetime…`, `every_posture_names_what_actually_bounds_the_exposure` | M115 |
| a superseded session does not resume | `a_session_stored_under_a_withdrawn_anchor…`, `a_rebuild_with_withdrawn_trust…`, `withdrawing_a_trusted_ca_stops_resumption…` | M116 |
| a mismatch is evicted, not left | `a_stale_session_is_evicted_by_get_not_left_to_be_re_rejected` | M117 |
| a current session **does** resume (the gate is not vacuous) | `a_session_stored_under_the_current_epoch_resumes`, `a_rebuild_that_republishes_the_same_trust_keeps_the_cache`, three real-handshake acceptances | M118 |

No production code changed and no test was added: every control already existed, and two of
them were unregistered.

## 5. What remains, and for whom

1. **#598's code half** — retiring or re-scoping ADR-055's dormant live-epoch machinery. A
   redesign, not a registration, so it is outside this mandate's autonomy.
2. **The socket-level connection close** — `async_serve/connection.rs` has no test, no unit,
   and a feature-gated lane. Named in THM-0102's scope as an obligation.
3. **#581 and #598 stay open** for the owner's specification review of THM-0102 and THM-0103,
   which is what makes them HITL.
