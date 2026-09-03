// SPDX-License-Identifier: Apache-2.0
//! The OPEN leg: record a new approval so that any replica can answer it (ADR-MCPS-047).
//!
//! Separate from the answer leg because the consequence is opposite. Everything here runs
//! PAST the execution threshold: the backend has produced the elicitation this records, so
//! no refusal from this file is free and no retry undoes what already happened.

use mcp_re_core::McpReError;

use crate::continuation_store::continuation_key;
use crate::continuation_store::RetainedBases;
use crate::exchange_state::Established;
use crate::exchange_state::ExchangeEvent;
use crate::http_profile_serve::Exchange;
use crate::refusal::Refusal;

use super::ContinuationPlane;

/// How many times the CONTINUATION-RECORDED open-leg record is attempted before the leg is
/// failed.
///
/// Bounded and small: the shared tier answered the replay admission moments earlier, so the
/// only failure this can absorb is a transient one, and retrying past that would put an
/// unbounded stall in front of a response the backend has already produced.
const RECORD_ATTEMPTS: usize = 3;

impl ContinuationPlane {
    /// CONTINUATION-RECORDED — make an open leg answerable on any replica.
    ///
    /// ```text
    /// ensures   Ok  => the retained bases are in the shared tier
    ///           Err => 503 (shared tier), bound
    /// refusal   NOT free
    /// ```
    ///
    /// Retried briefly before failing the leg. Reaching here means the backend has ALREADY
    /// run, and the shared tier answered the replay admission microseconds ago — so a
    /// failure now is a transient blip rather than the outage REPLAY-ADMITTED already fails
    /// closed on. Absorbing it is what keeps a retryable 503, which re-executes the tool
    /// call, off a path that has side effects.
    pub(in crate::http_profile_serve) async fn record_open_leg(
        &self,
        ex: &Exchange<'_>,
        audience_id: &str,
        state: &str,
        response_base: Vec<u8>,
    ) -> Result<Established<()>, Refusal> {
        // D3. A deployment with no shared store cannot make this leg answerable ON ANY
        // REPLICA, and it has known that since startup. Serving the elicitation anyway
        // hands the client a signed, verified instruction to continue an exchange nothing
        // has been kept for — and the failure surfaces one leg later, as
        // `continuation_binding_failed`, which on the wire reads like an attack signal.
        //
        // The dependent leg does fail closed either way. What it cannot do is fail closed
        // in TIME, which is why the refusal belongs here.
        let Some(store) = &self.store else {
            return Err(Refusal::after_admission(
                McpReError::ReplayCacheUnavailable,
                503,
            ));
        };
        let bases = RetainedBases {
            previous_request_base: ex.verified.request_signature_base().to_vec(),
            input_required_response_base: response_base,
        };
        let key = continuation_key(audience_id, ex.actor_id, state.as_bytes());
        for _ in 0..RECORD_ATTEMPTS {
            if store.store(&key, &bases, self.ttl_secs).await.is_ok() {
                return Ok(Established::new((), ExchangeEvent::OpenLegRecorded));
            }
        }
        Err(Refusal::after_admission(
            McpReError::ReplayCacheUnavailable,
            503,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The open leg's half of the same hop: the entry is RECORDED under the carried
    /// product's actor, so the answer leg's scoping has something to be true about. A leg
    /// that opened under a body-asserted identity would be answerable by whoever asserted
    /// it, and the answer leg's control alone cannot see that.
    ///
    /// A capturing double rather than a real tier, because the fact under test is the KEY
    /// and not the write.
    #[tokio::test]
    async fn the_leg_is_recorded_under_the_carried_products_actor() {
        use super::super::answer_leg::tests as fixtures;
        use std::sync::Mutex;

        struct CapturingStore(Mutex<Vec<String>>);

        impl crate::continuation_store::AsyncContinuationStore for CapturingStore {
            fn store<'a>(
                &'a self,
                key: &'a str,
                _bases: &'a RetainedBases,
                _ttl_secs: i64,
            ) -> crate::continuation_store::ContinuationFuture<'a, ()> {
                self.0.lock().expect("keys").push(key.to_owned());
                Box::pin(async { Ok(()) })
            }

            fn peek<'a>(
                &'a self,
                _key: &'a str,
            ) -> crate::continuation_store::ContinuationFuture<'a, Option<RetainedBases>>
            {
                Box::pin(async { Ok(None) })
            }

            fn consume<'a>(
                &'a self,
                _key: &'a str,
            ) -> crate::continuation_store::ContinuationFuture<'a, bool> {
                Box::pin(async { Ok(false) })
            }
        }

        let store = std::sync::Arc::new(CapturingStore(Mutex::new(Vec::new())));
        let plane = ContinuationPlane::wired(store.clone(), 300);
        let verified = fixtures::verified_as("did:example:host-a", "key-1");
        let actor_id = verified.resolved_actor().actor_id();
        let http_req = fixtures::http_request(fixtures::BODY_ASSERTING_ANOTHER_ACTOR);
        let ex = Exchange {
            http_req: &http_req,
            verified: &verified,
            actor_id: &actor_id,
            now: 1,
            key: None,
        };

        let established = plane
            .record_open_leg(&ex, "aud", "s-1", b"irr".to_vec())
            .await
            .expect("the capturing tier accepts the write");
        crate::exchange_state::ExchangeProgress::new().establish(established);

        assert_eq!(
            store.0.lock().expect("keys").clone(),
            vec![continuation_key(
                "aud",
                &verified.resolved_actor().actor_id(),
                b"s-1"
            )]
        );
    }

    #[test]
    fn the_record_budget_is_bounded_and_small() {
        // The bound is the point: past the execution threshold an unbounded retry would
        // stall a response the backend has already produced, while zero retries would fail
        // a leg on a blip the tier answered microseconds earlier.
        assert_eq!(RECORD_ATTEMPTS, 3);
    }
}
