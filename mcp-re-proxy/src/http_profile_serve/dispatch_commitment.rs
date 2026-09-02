// SPDX-License-Identifier: Apache-2.0
//! The last three things asked before the backend is reached, in the only order that keeps
//! the durable record honest.
//!
//! Local saturation and a fully-ejected backend set are facts about this proxy, knowable
//! without writing anything, and they are settled first — by TAKING the plane's capacity
//! rather than predicting it, so nothing can refuse on them later.
//!
//! What writes comes after, in two steps that are two facts. The retention obligation is
//! ACCEPTED, which asserts nothing about execution and is rescinded by dropping the value
//! that carries it. Then the crossing is RECORDED, and that recording is the execution
//! threshold: it is the last refusal of any kind, and the request relation says so —
//! `DispatchCommitted` is the state the dispatch leaves from, so a pipeline that recorded
//! the crossing before asking the questions that could still refuse would be rejected by
//! the machine rather than merely recorded oddly.

use crate::async_inner::PreparedInnerDispatch;
use crate::async_serve::ServedHttpResponse;
use crate::authorization::AuthorizationPosture;
use crate::exchange_state::Established;
use crate::exchange_state::ExchangeEvent;
use crate::exchange_state::ExchangeProgress;
use crate::refusal::Refusal;
use crate::request_stages::RetentionDisposition;

use super::body_boundary::ForwardedBody;
use super::Exchange;
use super::HttpProfileProxy;

impl HttpProfileProxy {
    /// FORWARDED — strip the proxy-owned `_meta` so the backend sees clean MCP.
    ///
    /// ```text
    /// ensures   Ok  => a body the inner server may receive, carrying verified context
    ///                  the caller did not author
    ///           Err => 500, bound
    /// forbids   running the backend
    /// refusal   free of execution; the approval may already be spent
    /// ```
    ///
    /// Fails closed when the trusted carrier is on but the context could not be written:
    /// the inner server would otherwise get an ordinary-looking request with no verified
    /// context, which is a silent downgrade to an unauthenticated call.
    fn forward_body_stage(&self, ex: &Exchange<'_>) -> Result<Established<Vec<u8>>, Refusal> {
        let forwarded = ForwardedBody::prepare(
            &ex.http_req.body,
            ex.verified,
            self.verified_context_policy,
            ex.now,
        )
        .map_err(|e| Refusal::after_admission(e, 500))?;
        Ok(Established::new(
            forwarded.into_bytes_for_inner(ex.actor_id.as_str()),
            ExchangeEvent::ForwardBodyPrepared,
        ))
    }

    /// Assemble the two values the dispatch consumes, refusing while refusing is still
    /// possible.
    ///
    /// The body is prepared first because preparing it decides nothing; the inner plane is
    /// prepared second because its refusal is free and leaves nothing behind; the
    /// retention obligation is accepted third because it is the only one that writes; and
    /// the crossing is recorded LAST, because recording it is what makes every earlier
    /// refusal free and every later one impossible.
    ///
    /// The inner-plane capability is HELD from here to the dispatch. If the reservation
    /// then refuses, the prepared dispatch is dropped on the way out and everything it took
    /// — the in-flight permit, any claimed recovery probe — goes back without a release
    /// call. That is why the ordering is safe to state as an ordering: nothing between the
    /// two steps can leak the plane's capacity, and nothing after the reservation can
    /// refuse.
    pub(super) async fn commit_to_dispatch<'p>(
        &'p self,
        ex: &Exchange<'_>,
        authorized: AuthorizationPosture,
        progress: &mut ExchangeProgress,
    ) -> Result<(PreparedInnerDispatch<'p>, RetentionDisposition), ServedHttpResponse> {
        let forwarded = match self.forward_body_stage(ex) {
            Ok(body) => progress.establish(body),
            Err(refusal) => return Err(self.refuse(ex, refusal, progress)),
        };
        let prepared = match self.inner_async.prepare(authorized.release(forwarded)) {
            Ok(prepared) => progress.establish(prepared),
            Err(refusal) => return Err(self.refuse(ex, refusal, progress)),
        };
        let accepted = match self.retention.reserve(ex.http_req).await {
            Ok(accepted) => accepted,
            Err(refusal) => return Err(self.refuse(ex, refusal, progress)),
        };
        let retention = match self.retention.commit(accepted).await {
            Ok(disposition) => progress.establish(disposition),
            Err(refusal) => return Err(self.refuse(ex, refusal, progress)),
        };
        Ok((prepared, retention))
    }
}

#[cfg(test)]
mod tests {
    use super::ExchangeEvent;
    use crate::exchange_state::transition;
    use crate::exchange_state::ExchangeState;

    /// The order this region asks in is the relation's, not a local convention. A pipeline
    /// that recorded the crossing before asking the questions that can still refuse would
    /// be rejected by the machine rather than merely leaving an odd record.
    #[test]
    fn the_crossing_is_recorded_after_everything_that_can_refuse_and_before_the_dispatch() {
        assert!(transition(
            ExchangeState::InnerPlaneAccepted,
            ExchangeEvent::RetentionCommitted
        )
        .is_ok());
        assert!(transition(
            ExchangeState::RetentionCommitted,
            ExchangeEvent::BackendDispatched
        )
        .is_ok());
        assert!(transition(ExchangeState::Forwarded, ExchangeEvent::BackendDispatched).is_err());
        assert!(transition(ExchangeState::Forwarded, ExchangeEvent::RetentionCommitted).is_err());
    }

    /// A refusal is free right up to the crossing, and never after it.
    ///
    /// The predicate the two-stage store buys. Under one artefact the machine could not
    /// say this: the only pre-dispatch state that wrote anything wrote the thing an auditor
    /// reads as a crossing, so *refusing here is free* and *this may have executed* were
    /// true of the same state.
    #[test]
    fn the_last_state_that_can_refuse_freely_is_the_one_before_the_crossing() {
        assert!(!ExchangeState::InnerPlaneAccepted.backend_may_have_executed());
        assert!(ExchangeState::RetentionCommitted.backend_may_have_executed());
    }
}
