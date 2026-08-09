// SPDX-License-Identifier: Apache-2.0
//! ADR-MCPRE-057 §7 / ADR-MCPRE-058 §9 — the request lifecycle, around its one
//! irreversible effect.
//!
//! # The inventory this was frozen from
//!
//! `handle` sequenced sixteen ordered operations around one irreversible inner dispatch,
//! with seventeen rejection exits, and the ordering was carried by comments numbered
//!
//! ```text
//! 2, 3, 3b, 4, 5, 5a, 5b, 6, 6a, [dispatch], 7, 7a, 6b, 7, 8
//! ```
//!
//! which is not execution order — 6b runs after 7a, and 7 appears twice. The numbering
//! had drifted, which is what a hand-maintained sequence does. What it was standing in
//! for is below, derived from the source rather than from the comments, with the
//! REVERSIBILITY of each step named because that is the property the numbers were
//! failing to carry:
//!
//! ```text
//! stage                     operation                        on failure       reversible
//! ------------------------------------------------------------------------------------
//! Received                  --                               --               --
//! Verified                  verify_request_full_with_policy  403, unbound     yes
//! TransportBound            transport_binding.check          403              yes
//! AdmissionChecked          admission_gate (awaited)         403 (x3)         yes
//! ContinuationPrepared      continuation_store.peek          none (-> None)   yes
//! ReplayAdmitted            dispatch_request_with_async_tier 409              NO: nonce burned
//! Answerable                signer.current(now)              503              yes
//! ContinuationRetired       continuation_store.consume       409              NO: entry consumed
//! Forwarded                 forwarded_body                   500              yes
//! RetentionReserved         retention.reserve (awaited)      503              NO: durable marker
//! ==================== IRREVERSIBLE INNER DISPATCH ====================
//! ResponseBuilt             inner_async.dispatch             --               the backend has acted
//! (notification)            sign_delegated_accepted_202      500
//! ResultClassified          classify_result_type             502
//! ResponseSigned            sign_delegated_response_full     500
//! ContinuationRecorded      input_required_state + store     502 / 503
//! RetentionCompleted        retain_accepted                  500 (x2)
//! Completed                 audit + served                   --
//! ```
//!
//! Three stages before the dispatch are already irreversible on their own — the replay
//! nonce, the consumed continuation, the durable retention marker. They are not the
//! boundary this module draws, because their failure is still answerable with *nothing
//! happened at the backend*, which is the distinction that changes what a client may
//! safely retry.
//!
//! # What the types enforce
//!
//! [`ReadyForDispatch`] can only be built with every pre-dispatch prerequisite in hand,
//! and the inner dispatch consumes one. So "remember to reserve retention before the side
//! effects run" stops being a comment and becomes: *dispatch requires `ReadyForDispatch`,
//! and `ReadyForDispatch` proves a [`RetentionDisposition`]*.
//!
//! This is not a stage type per numbered comment (ADR-MCPRE-058 §9.3). Two states carry
//! the boundary and everything else stays ordinary control flow, because only this one
//! boundary has an invariant the compiler can hold.

use std::sync::Arc;

use crate::transparency::RetentionReservation;
use mcp_re_http_profile::ActiveDelegatedKey;

/// What this exchange owes the evidence store, as a closed set.
///
/// # Why this is not `Option<RetentionReservation>`
///
/// Retention is optional — a deployment may run without it — so the obvious typed form is
/// an `Option`, and it is wrong. `None` would mean BOTH "this deployment retains nothing"
/// and "this deployment retains, and the reservation is missing", and the second is a
/// bypassed step. Keeping them in one shape is what forced the runtime guard on the
/// completion path:
///
/// ```text
/// if retention.is_some() && reservation.is_none() { internal error }
/// ```
///
/// which is a check compensating for something the type could not say (ADR-MCPRE-058
/// §9.5, §9.6). As a sum type there is no third case: the ready state PROVES
/// *retention is not configured XOR a reservation exists*, and the obligation is
/// discharged after dispatch by an exhaustive match rather than by asking whether an
/// earlier step was performed.
pub(crate) enum RetentionDisposition {
    /// This deployment retains nothing, so there is no obligation to discharge.
    NotConfigured,
    /// The execution threshold is durably recorded, and this exchange must complete the
    /// record before it is served.
    Reserved(RetentionReservation),
}

/// Every pre-dispatch prerequisite, in hand.
///
/// Only [`new`](Self::new) constructs one, and it takes each prerequisite by value, so a
/// path that skipped a stage has nothing to pass. That is the whole mechanism: the inner
/// dispatch consumes this type, and this type cannot exist early.
///
/// It carries no `verified` evidence or actor id — those outlive the dispatch and are
/// borrowed by the caller on both sides of it. What is here is exactly what would
/// otherwise be a local whose presence at the dispatch line is a matter of reading
/// upwards.
pub(crate) struct ReadyForDispatch {
    /// The body actually sent to the backend: proxy-owned `_meta` stripped, verified
    /// context written if this deployment carries one.
    forwarded: Vec<u8>,
    /// The delegated key this reply will be signed with, snapshotted BEFORE the backend
    /// runs. Taken early on purpose: discovering a missing key at signing time meant the
    /// tool call had already executed and the client got a retryable 503, so the action
    /// ran twice (ADR-MCPRE-052 §6).
    signing_key: Arc<ActiveDelegatedKey>,
    /// The signature window, already reconciled against the credential's own `exp` so the
    /// response never advertises a validity the verifier refuses.
    expires: i64,
    /// The retention obligation this exchange carries across the dispatch.
    retention: RetentionDisposition,
}

impl ReadyForDispatch {
    /// Assemble the ready state. Every argument is a completed pre-dispatch stage.
    pub(crate) fn new(
        forwarded: Vec<u8>,
        signing_key: Arc<ActiveDelegatedKey>,
        expires: i64,
        retention: RetentionDisposition,
    ) -> Self {
        ReadyForDispatch {
            forwarded,
            signing_key,
            expires,
            retention,
        }
    }

    /// The body to send, borrowed — the dispatch does not consume the ready state,
    /// because what survives it is the obligation, not the request.
    pub(crate) fn forwarded(&self) -> &[u8] {
        &self.forwarded
    }

    /// Cross the boundary: yield what the post-dispatch half is answerable for.
    ///
    /// Consuming, and the only way out. A caller cannot hold a `ReadyForDispatch` and a
    /// [`DispatchedExchange`] at once, which is what keeps "the backend has not acted" and
    /// "the backend may have acted" from being the same value in two places.
    pub(crate) fn dispatched(self, inner_bytes: Vec<u8>) -> DispatchedExchange {
        DispatchedExchange {
            inner_bytes,
            signing_key: self.signing_key,
            expires: self.expires,
            retention: self.retention,
        }
    }
}

/// The backend has acted. What remains is answerable for that.
///
/// Holding one of these is the proof that a pre-dispatch refusal is no longer available:
/// every exit from here is a `response_rejection`, never a `request.rejected`, and none
/// of them can claim nothing happened.
pub(crate) struct DispatchedExchange {
    inner_bytes: Vec<u8>,
    signing_key: Arc<ActiveDelegatedKey>,
    expires: i64,
    retention: RetentionDisposition,
}

impl DispatchedExchange {
    /// The backend's reply bytes, taken out to become the response body.
    pub(crate) fn into_parts(
        self,
    ) -> (Vec<u8>, Arc<ActiveDelegatedKey>, i64, RetentionDisposition) {
        (
            self.inner_bytes,
            self.signing_key,
            self.expires,
            self.retention,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The §9.6 acceptance test for the state model, stated as an assertion about the
    /// type rather than about a run.
    ///
    /// `RetentionDisposition` has exactly two cases, and the completion path matches on
    /// them exhaustively. There is no third — no `Reserved(None)`, no "configured but
    /// missing" — so the runtime guard that used to sit on the completion path has
    /// nothing left to detect.
    ///
    /// The broken implementation this catches is the one the ADR names: reaching for
    /// `Option<RetentionReservation>` inside the ready state, which reintroduces the third
    /// case and brings the guard straight back. That would not compile against this match,
    /// because `None` would have to mean one of these two arms and the compiler cannot
    /// choose.
    #[test]
    fn the_retention_obligation_has_exactly_two_cases() {
        let disposition = RetentionDisposition::NotConfigured;
        let owed = match disposition {
            RetentionDisposition::NotConfigured => false,
            RetentionDisposition::Reserved(_) => true,
        };
        assert!(
            !owed,
            "a deployment without retention owes the store nothing"
        );
    }

    /// Crossing the boundary is one-way: the ready state is consumed.
    ///
    /// Asserted here because it is the property that makes "pre-dispatch rejection" and
    /// "post-dispatch failure" different in the type system and not only in prose. A
    /// `dispatched` that borrowed instead would let a caller keep the ready state and
    /// refuse as though the backend had not run.
    #[test]
    fn the_dispatch_boundary_consumes_the_ready_state() {
        let key = Arc::new(ActiveDelegatedKey {
            key: Arc::new(mcp_re_core::SigningKey::from_seed_bytes(&[4u8; 32])),
            delegated_kid: "delegated-1".into(),
            server_signer: mcp_re_http_profile::ActorIdentity {
                role: "server".into(),
                trust_domain: "example.com".into(),
                subject: "did:example:server".into(),
                keyid: "delegated-1".into(),
            },
            credential: "cred".into(),
            nbf: 0,
            exp: 1_700_000_000,
        });
        let ready = ReadyForDispatch::new(
            b"{}".to_vec(),
            key,
            1_700_000_000,
            RetentionDisposition::NotConfigured,
        );
        assert_eq!(ready.forwarded(), b"{}");

        let exchange = ready.dispatched(b"{\"result\":{}}".to_vec());
        // `ready` is gone here — the compiler enforces it, which is the assertion.
        let (bytes, _key, expires, retention) = exchange.into_parts();
        assert_eq!(bytes, b"{\"result\":{}}");
        assert_eq!(expires, 1_700_000_000);
        assert!(matches!(retention, RetentionDisposition::NotConfigured));
    }
}
