// SPDX-License-Identifier: Apache-2.0
//! ADR-MCPRE-057 §7 / ADR-MCPRE-058 §9 — the exchange lifecycle, around its one
//! irreversible effect.
//!
//! The states themselves live in [`crate::exchange_state`]; what is here is the ONE boundary
//! the compiler can hold — the pre-dispatch prerequisites, and the fact that crossing is
//! one-way.
//!
//! # Where the ordering lives
//!
//! Not here. The pipeline order and its legal transitions are
//! [`crate::exchange_state::transition`], and the correspondence between a step and the
//! state it establishes is [`crate::exchange_state::Established`] — a stage returns the
//! event it justifies, so the serving path cannot state one the stage did not.
//!
//! This module doc used to restate the whole sequence as a prose table, and the table had
//! drifted: it listed the retention reservation and the inner-plane admission in the
//! opposite order to the relation. Two statements of one fact is one statement and one
//! liability, and a comment is the half nothing checks.
//!
//! What is worth saying here, because no other file says it: three pre-dispatch steps are
//! already irreversible on their own — the burned replay nonce, the consumed continuation,
//! and the durable retention marker. They are NOT the boundary this module draws, because
//! their failure is still answerable with *nothing happened at the backend*, which is the
//! distinction that changes what a client may safely retry.
//!
//! # What the types enforce
//!
//! [`ReadyForDispatch`] can only be built with every pre-dispatch prerequisite in hand,
//! and it is the only thing that can transmit. So "remember to reserve retention before the
//! side effects run" stops being a comment and becomes: *transmitting requires a
//! `ReadyForDispatch`, and a `ReadyForDispatch` proves a [`RetentionDisposition`]* — and,
//! since ADR-MCPRE-065, that an authorization decision was taken, because the capability it
//! carries is obtained only from a released body.
//!
//! Since #741 the capability is real. The ready state holds a
//! [`PreparedInnerDispatch`] — the taken permit, the claimed backend, the built transport
//! request — rather than bytes the seam would look capacity up for later, so the last
//! pre-dispatch prerequisite is no longer a prediction that the plane will still admit the
//! call when it is asked to run it.
//!
//! This is not a stage type per numbered comment (ADR-MCPRE-058 §9.3). Two states carry
//! the boundary and everything else stays ordinary control flow, because only this one
//! boundary has an invariant the compiler can hold.

use crate::async_inner::DispatchedOutcome;
use crate::async_inner::PreparedInnerDispatch;
use crate::http_profile_serve::signing_window::SigningWindow;
use crate::transparency::RetentionReservation;

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
pub(crate) struct ReadyForDispatch<'a> {
    /// The capability to transmit, and the body it will transmit — the in-flight permit,
    /// the selected backend and the built transport request, all taken and none of them
    /// predicted.
    ///
    /// It carries the authorization decision with it. The serving path obtains one only
    /// from `InnerPlane::prepare`, which takes an `AuthorizedRequestBody` by value, and
    /// that type has exactly one producer: `AuthorizationPosture::release`. So a path that
    /// skipped the ADR-MCPRE-065 decision has nothing to prepare with, the failure is a
    /// compile error before the dispatch rather than a proxy that quietly serves unjudged
    /// requests, and the bytes that go out are the bytes the decision released — there is
    /// no second copy for a later stage to substitute.
    prepared: PreparedInnerDispatch<'a>,
    /// The credential this reply will be signed with and the validity it authorizes,
    /// snapshotted BEFORE the backend runs. Taken early on purpose: discovering a missing
    /// key at signing time meant the tool call had already executed and the client got a
    /// retryable 503, so the action ran twice (ADR-MCPRE-052 §6).
    ///
    /// One value rather than a key beside a number, because the two are related: the
    /// window never outlives the credential. A pair can be split and half of it replaced;
    /// a [`SigningWindow`] carries the relation wherever it goes.
    window: SigningWindow,
    /// The retention obligation this exchange carries across the dispatch.
    retention: RetentionDisposition,
}

impl<'a> ReadyForDispatch<'a> {
    /// Assemble the ready state. Every argument is a completed pre-dispatch stage.
    pub(crate) fn new(
        prepared: PreparedInnerDispatch<'a>,
        window: SigningWindow,
        retention: RetentionDisposition,
    ) -> Self {
        ReadyForDispatch {
            prepared,
            window,
            retention,
        }
    }

    /// Cross the boundary: transmit, and yield what the post-dispatch half is answerable
    /// for.
    ///
    /// Consuming, and the only way out. A caller cannot hold a `ReadyForDispatch` and a
    /// [`DispatchedExchange`] at once, which is what keeps "the backend has not acted" and
    /// "the backend may have acted" from being the same value in two places.
    ///
    /// The transmission happens HERE rather than beside this call. The seam used to hand
    /// back the body and take the outcome, so the ready state survived the dispatch and a
    /// path could — in principle — have dispatched twice from one set of prerequisites, or
    /// dispatched from bytes that were not the ones it carried. Consuming the capability
    /// inside the crossing removes both.
    pub(crate) async fn dispatch(self) -> DispatchedExchange {
        let ReadyForDispatch {
            prepared,
            window,
            retention,
        } = self;
        DispatchedExchange {
            outcome: prepared.dispatch().await,
            window,
            retention,
        }
    }
}

/// The backend has acted. What remains is answerable for that.
///
/// Holding one of these is the proof that a pre-dispatch refusal is no longer available:
/// every exit from here is a `response_rejection`, never a `request.rejected`, and none
/// of them can claim nothing happened.
pub(crate) struct DispatchedExchange {
    outcome: DispatchedOutcome,
    window: SigningWindow,
    retention: RetentionDisposition,
}

impl DispatchedExchange {
    /// What the inner plane managed to do, taken out with the obligations that outlive it.
    pub(crate) fn into_parts(self) -> (DispatchedOutcome, SigningWindow, RetentionDisposition) {
        (self.outcome, self.window, self.retention)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_re_http_profile::ActiveDelegatedKey;
    use std::sync::Arc;

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

    /// Crossing the boundary is one-way: the ready state is consumed, and transmitting is
    /// what consumes it.
    ///
    /// Asserted here because it is the property that makes "pre-dispatch rejection" and
    /// "post-dispatch failure" different in the type system and not only in prose. A
    /// `dispatch` that borrowed instead would let a caller keep the ready state and refuse
    /// as though the backend had not run — or transmit from it twice.
    ///
    /// The capability the ready state carries comes through the ONE producer: an
    /// `AuthorizedRequestBody`, released by an `AuthorizationPosture`, prepared by the
    /// inner plane. There is no other way to obtain a dispatchable body.
    #[tokio::test]
    async fn the_dispatch_boundary_consumes_the_ready_state() {
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
        let inner = |body: &[u8]| {
            assert_eq!(body, b"{}", "the bytes sent are the bytes released");
            b"{\"result\":{}}".to_vec()
        };
        let released =
            crate::authorization::AuthorizationPosture::NoPolicyConfigured.release(b"{}".to_vec());
        let prepared = crate::async_inner::AsyncInnerServer::prepare(&inner, released.bytes())
            .expect("an in-process inner always prepares");
        let ready = ReadyForDispatch::new(
            prepared,
            SigningWindow::over(key, 1_699_999_000, 60),
            RetentionDisposition::NotConfigured,
        );

        let exchange = ready.dispatch().await;
        // `ready` is gone here — the compiler enforces it, which is the assertion.
        let (outcome, window, retention) = exchange.into_parts();
        assert_eq!(
            outcome,
            DispatchedOutcome::Replied(b"{\"result\":{}}".to_vec())
        );
        // The window crosses the boundary intact — the reply is signed under the
        // credential the exchange snapshotted before the backend ran.
        assert_eq!(window.expires(), 1_699_999_060);
        assert!(matches!(retention, RetentionDisposition::NotConfigured));
    }
}
