// SPDX-License-Identifier: Apache-2.0
//! The last three things asked before the backend is reached, in the only order that keeps
//! the durable record honest.
//!
//! Local saturation and a fully-ejected backend set are facts about this proxy, knowable
//! without writing anything. Refusing on them AFTER the retention reservation would leave a
//! durable marker asserting that the request crossed the execution threshold — for a
//! request that provably never reached a backend. The reservation is therefore the last
//! refusal of any kind before the dispatch, and the request relation says so:
//! `RetentionReserved` is its last pre-dispatch state, so a pipeline that asked in the
//! other order would be refused by the machine rather than merely recorded oddly.

use crate::async_serve::ServedHttpResponse;
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
            forwarded.into_bytes_for_inner(ex.actor_id),
            ExchangeEvent::ForwardBodyPrepared,
        ))
    }

    /// Assemble the two values the dispatch consumes, refusing while refusing is still
    /// possible.
    ///
    /// The body is prepared first because preparing it decides nothing; the inner plane is
    /// asked second because its answer is free; the reservation is taken last because it is
    /// the only one of the three that writes.
    pub(super) async fn commit_to_dispatch(
        &self,
        ex: &Exchange<'_>,
        progress: &mut ExchangeProgress,
    ) -> Result<(Vec<u8>, RetentionDisposition), ServedHttpResponse> {
        let forwarded = match self.forward_body_stage(ex) {
            Ok(body) => progress.establish(body),
            Err(refusal) => return Err(self.refuse(ex, refusal, progress)),
        };
        match self.inner_async.admit() {
            Ok(accepted) => progress.establish(accepted),
            Err(refusal) => return Err(self.refuse(ex, refusal, progress)),
        }
        let retention = match self.retention.reserve(ex.http_req).await {
            Ok(disposition) => progress.establish(disposition),
            Err(refusal) => return Err(self.refuse(ex, refusal, progress)),
        };
        Ok((forwarded, retention))
    }
}

#[cfg(test)]
mod tests {
    use super::ExchangeEvent;
    use crate::exchange_state::transition;
    use crate::exchange_state::ExchangeState;

    /// The order this region asks in is the relation's, not a local convention. A pipeline
    /// that reserved retention before asking the inner plane would be refused by the
    /// machine rather than merely leaving an odd record.
    #[test]
    fn the_reservation_is_the_last_pre_dispatch_state() {
        assert!(transition(
            ExchangeState::RetentionReserved,
            ExchangeEvent::BackendDispatched
        )
        .is_ok());
        assert!(transition(ExchangeState::Forwarded, ExchangeEvent::BackendDispatched).is_err());
        assert!(transition(ExchangeState::Forwarded, ExchangeEvent::RetentionReserved).is_err());
    }
}
