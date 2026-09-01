// SPDX-License-Identifier: Apache-2.0
//! What the inner plane managed to do, and what the exchange may therefore claim.
//!
//! One fact: **every answer the backend seam can give is mapped, once, to what this
//! exchange may say about execution.** The mapping is the security content — the bytes are
//! not.
//!
//! Three moments, and their asymmetry is deliberate:
//!
//! | moment | question | refusal |
//! |---|---|---|
//! | [`InnerPlane::prepare`] | may a dispatch begin at all? | free, and free of DURABLE consequence |
//! | [`InnerPlane::observe_reply`] | what came back for a request? | never free |
//! | [`InnerPlane::observe_acknowledgement`] | did a notification get there? | never free |
//!
//! The preparation exists because local saturation and a fully-ejected backend set are
//! facts about THIS proxy, knowable without putting a byte on the wire. Discovering them
//! from the far side of the threshold — which is what a seam returning only bytes forces —
//! turned a definitely-not-executed outage into an exchange that must claim
//! `possibly_executed` forever after, and served it as a signed HTTP 200 carrying an error
//! body.
//!
//! Since #741 it does more than ask: it TAKES what the dispatch needs and hands back a
//! [`PreparedInnerDispatch`]. The predecessor read the plane's capacity and let the
//! dispatch acquire it later, so a lost race was still discoverable after the threshold —
//! reported honestly, but too late for the retention reservation the exchange had already
//! written. There is nothing left to lose the race to.
//!
//! Past the dispatch, an outcome is never collapsed into a neighbouring one. A timeout is
//! not a failure and is not a success: the request was transmitted and the answer never
//! came, so whether the tool ran is genuinely unknown, and it stays unknown — the previous
//! behaviour, a synthesized `-32603` signed at HTTP 200, was the strongest available
//! statement that the exchange had completed normally.

use mcp_re_core::McpReError;
use mcp_re_http_profile::HttpProfileError;

use crate::async_inner::AsyncInnerServer;
use crate::async_inner::DispatchedOutcome;
use crate::async_inner::PreparedInnerDispatch;
use crate::authorization::AuthorizedRequestBody;
use crate::exchange_state::Established;
use crate::exchange_state::ExchangeEvent;
use crate::exchange_state::ExchangeProgress;
use crate::exchange_state::ResponseOrigin;
use crate::refusal::Refusal;

/// The async client to the stateless Streamable-HTTP backend, and the reading of every
/// answer it can give.
///
/// Private representation: the seam is never handed out, so nothing outside this module can
/// dispatch without the reading below being applied to the result.
pub(super) struct InnerPlane {
    inner: Box<dyn AsyncInnerServer>,
}

impl InnerPlane {
    /// Wrap the deployment's backend seam.
    pub(super) fn over(inner: Box<dyn AsyncInnerServer>) -> Self {
        InnerPlane { inner }
    }

    /// INNER-PLANE-ACCEPTED — take what a dispatch requires, and transmit nothing.
    ///
    /// ```text
    /// ensures   Ok  => the in-flight permit, the selected backend and the built
    ///                  transport request are HELD by the returned value
    ///           Err => 503, bound
    /// forbids   transmitting anything
    /// refusal   free, and free of DURABLE consequence — asked before the retention
    ///           reservation, so a saturated plane leaves nothing behind on disk
    /// ```
    ///
    /// The body is taken as an [`AuthorizedRequestBody`], by value. That is where
    /// "dispatch only from an authorized request" stops being a sentence: the type has one
    /// producer, `AuthorizationPosture::release`, so a serving path that skipped the
    /// ADR-MCPRE-065 decision has nothing to prepare with — and since the prepared value
    /// owns the bytes it will send, there is no second copy of the body for a later stage
    /// to substitute.
    ///
    /// What comes back is a capability, not a prediction, and it is not this module's to
    /// spend: it crosses the remaining pre-dispatch stages inside the exchange's ready
    /// state and is consumed there. Dropping it on any refusal path releases the permit
    /// and any recovery-probe claim, which is why no release call appears anywhere in the
    /// serving path.
    pub(super) fn prepare(
        &self,
        forwarded: AuthorizedRequestBody,
    ) -> Result<Established<PreparedInnerDispatch<'_>>, Refusal> {
        self.inner
            .prepare(forwarded.bytes())
            .map(|prepared| Established::new(prepared, ExchangeEvent::InnerPlaneAccepted))
            .map_err(|_| Refusal::after_admission(McpReError::InnerPlaneUnavailable, 503))
    }

    /// RESPONSE-OBSERVED — what did the inner plane actually manage to do?
    ///
    /// ```text
    /// ensures   Ok  => bytes authored by the BACKEND
    ///           Err => 503 / 504 / 502, bound, recorded as a RESPONSE-side fault
    /// refusal   NOT free — every arm below reports possibly-executed
    /// ```
    ///
    /// The two failing arms are two different facts and get two different codes. There is
    /// no third: *nothing was transmitted* is not an answer a committed dispatch can give,
    /// because [`DispatchedOutcome`] has no case for it.
    pub(super) fn observe_reply(
        &self,
        progress: &mut ExchangeProgress,
        outcome: DispatchedOutcome,
    ) -> Result<Established<Vec<u8>>, Refusal> {
        match outcome {
            DispatchedOutcome::Replied(bytes) => {
                progress.observe_origin(ResponseOrigin::BackendReplied);
                Ok(Established::new(bytes, ExchangeEvent::ResponseObserved))
            }
            DispatchedOutcome::Indeterminate(_) => {
                progress.observe_origin(ResponseOrigin::DispatchIndeterminate);
                Err(Refusal::after_admission(
                    McpReError::InnerDispatchIndeterminate,
                    504,
                ))
            }
            DispatchedOutcome::InvalidUpstream(clause) => Err(Refusal::after_admission(
                HttpProfileError::UpstreamResponseInvalid(clause),
                502,
            )),
        }
    }

    /// NOTIFICATION-OBSERVED — may a 202 be minted for what the inner plane managed to do?
    ///
    /// ```text
    /// ensures   Ok  => the backend RECEIVED the message
    ///           Err => 504 — transmitted, no answer
    /// refusal   NOT free — the exchange has crossed the threshold either way
    /// ```
    ///
    /// Two outcomes acknowledge and one refuses, split on whether the backend ANSWERED. The
    /// 202 says the enforcement boundary authenticated and accepted the message and the
    /// inner plane received it; it never says any action completed (#418). What the backend
    /// answered is discarded unread, as JSON-RPC requires — but WHETHER it was reached is
    /// not a detail of the answer, and a message that never left the proxy has been
    /// accepted by nothing.
    ///
    /// A message that never left the proxy no longer reaches here at all: the plane is
    /// prepared before the threshold, so *nothing was transmitted* is a pre-commitment
    /// refusal and never a notification outcome to read.
    ///
    /// [`DispatchedOutcome::InvalidUpstream`] acknowledges, and that is not a concession: a
    /// conformant Streamable-HTTP backend answers a notification with `202 Accepted` and no
    /// body, which carries no `application/json` content type and therefore arrives here as
    /// an unusable answer FROM A BACKEND THAT RECEIVED THE MESSAGE
    /// ([`crate::http_inner`]). The two refused outcomes are the two that say the message
    /// did not get there, or may not have.
    pub(super) fn observe_acknowledgement(
        &self,
        progress: &mut ExchangeProgress,
        outcome: &DispatchedOutcome,
    ) -> Result<Established<()>, Refusal> {
        match outcome {
            DispatchedOutcome::Replied(_) | DispatchedOutcome::InvalidUpstream(_) => {
                progress.observe_origin(ResponseOrigin::BackendReplied);
                Ok(Established::new(
                    (),
                    ExchangeEvent::NotificationAcknowledged,
                ))
            }
            DispatchedOutcome::Indeterminate(_) => {
                progress.observe_origin(ResponseOrigin::DispatchIndeterminate);
                Err(Refusal::after_admission(
                    McpReError::InnerDispatchIndeterminate,
                    504,
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::async_inner::NotAdmitted;
    use crate::async_inner::PreparedInnerDispatch;

    /// A seam that prepares nothing. The dispatch is never exercised here: what these
    /// controls are about is the READING of an outcome, which is this module's whole
    /// content, and every outcome is constructed directly.
    struct PreparesNothing;

    impl AsyncInnerServer for PreparesNothing {
        fn prepare<'a>(
            &'a self,
            _request: &[u8],
        ) -> Result<PreparedInnerDispatch<'a>, NotAdmitted> {
            Err(NotAdmitted("saturated"))
        }
    }

    #[test]
    fn a_saturated_plane_refuses_before_a_byte_is_transmitted() {
        // The whole reason the preparation exists. Answering saturation after the threshold
        // turns a definitely-not-executed outage into an exchange that must claim
        // possibly-executed forever after.
        let plane = InnerPlane::over(Box::new(PreparesNothing));
        let body =
            crate::authorization::AuthorizationPosture::NoPolicyConfigured.release(b"{}".to_vec());
        let Err(refused) = plane.prepare(body) else {
            panic!("a saturated plane prepares nothing");
        };
        assert_eq!(refused.status, 503);
    }

    #[test]
    fn a_timeout_is_neither_a_reply_nor_a_definite_failure() {
        // The distinction this module exists for. A transmitted request whose answer never
        // came leaves execution UNKNOWN, and the exchange records that origin so every
        // refusal downstream reports possibly-executed rather than a clean failure.
        let plane = InnerPlane::over(Box::new(PreparesNothing));
        let mut progress = ExchangeProgress::new();
        let Err(refused) =
            plane.observe_reply(&mut progress, DispatchedOutcome::Indeterminate("timeout"))
        else {
            panic!("a timeout is not a reply");
        };
        assert_eq!(refused.status, 504, "not the 503 of a request never sent");
    }

    #[test]
    fn an_unusable_answer_to_a_notification_still_says_the_backend_was_reached() {
        // Not a concession. A conformant Streamable-HTTP backend answers a notification
        // with a bodyless 202, which arrives here as an unusable answer FROM A BACKEND THAT
        // RECEIVED THE MESSAGE. The refused outcome is the one that says it may not have
        // got there.
        let plane = InnerPlane::over(Box::new(PreparesNothing));
        let mut progress = ExchangeProgress::new();
        assert!(plane
            .observe_acknowledgement(
                &mut progress,
                &DispatchedOutcome::InvalidUpstream("content-type")
            )
            .is_ok());
    }

    /// A notification the backend may not have received is not acknowledged.
    ///
    /// The 202 states that the inner plane RECEIVED the message. Minting one for a message
    /// that may never have arrived would be the enforcement boundary asserting, under
    /// signature, that a backend accepted something no backend is known to have seen — and
    /// it is the one exit a client could select by omitting `id`.
    ///
    /// The stronger case, a message that PROVABLY never left the proxy, cannot reach this
    /// reading at all any more: it is refused by [`InnerPlane::prepare`], before the
    /// exchange crosses anything.
    #[test]
    fn a_notification_the_backend_may_not_have_received_is_not_acknowledged() {
        let plane = InnerPlane::over(Box::new(PreparesNothing));
        let mut progress = ExchangeProgress::new();
        assert!(plane
            .observe_acknowledgement(&mut progress, &DispatchedOutcome::Indeterminate("timeout"))
            .is_err());
    }
}
