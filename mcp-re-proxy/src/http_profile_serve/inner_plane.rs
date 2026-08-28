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
//! | [`InnerPlane::admit`] | may a dispatch begin at all? | free, and free of DURABLE consequence |
//! | [`InnerPlane::observe_reply`] | what came back for a request? | never free |
//! | [`InnerPlane::observe_acknowledgement`] | did a notification get there? | never free |
//!
//! The admission question exists because local saturation and a fully-ejected backend set
//! are facts about THIS proxy, knowable without putting a byte on the wire. Discovering
//! them from the far side of the threshold — which is what a seam returning only bytes
//! forces — turned a definitely-not-executed outage into an exchange that must claim
//! `possibly_executed` forever after, and served it as a signed HTTP 200 carrying an error
//! body.
//!
//! Past the dispatch, an outcome is never collapsed into a neighbouring one. A timeout is
//! not a failure and is not a success: the request was transmitted and the answer never
//! came, so whether the tool ran is genuinely unknown, and it stays unknown — the previous
//! behaviour, a synthesized `-32603` signed at HTTP 200, was the strongest available
//! statement that the exchange had completed normally.

use mcp_re_core::McpReError;
use mcp_re_http_profile::HttpProfileError;

use crate::async_inner::AsyncInnerServer;
use crate::async_inner::InnerOutcome;
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

    /// INNER-PLANE-ACCEPTED — can a dispatch begin at all?
    ///
    /// ```text
    /// ensures   Ok  => the inner plane has a permit and a live backend
    ///           Err => 503, bound
    /// forbids   transmitting anything
    /// refusal   free, and free of DURABLE consequence — asked before the retention
    ///           reservation, so a saturated plane leaves nothing behind on disk
    /// ```
    pub(super) fn admit(&self) -> Result<Established<()>, Refusal> {
        self.inner
            .admit()
            .map(|_| Established::new((), ExchangeEvent::InnerPlaneAccepted))
            .map_err(|_| Refusal::after_admission(McpReError::InnerPlaneUnavailable, 503))
    }

    /// Transmit. Past this call no exit can claim nothing happened.
    pub(super) async fn dispatch(&self, forwarded: &[u8]) -> InnerOutcome {
        self.inner.dispatch(forwarded).await
    }

    /// RESPONSE-OBSERVED — what did the inner plane actually manage to do?
    ///
    /// ```text
    /// ensures   Ok  => bytes authored by the BACKEND
    ///           Err => 503 / 504 / 502, bound, recorded as a RESPONSE-side fault
    /// refusal   NOT free — every arm below reports possibly-executed
    /// ```
    ///
    /// The three failing arms are three different facts and get three different codes.
    pub(super) fn observe_reply(
        &self,
        progress: &mut ExchangeProgress,
        outcome: InnerOutcome,
    ) -> Result<Established<Vec<u8>>, Refusal> {
        match outcome {
            InnerOutcome::Replied(bytes) => {
                progress.observe_origin(ResponseOrigin::BackendReplied);
                Ok(Established::new(bytes, ExchangeEvent::ResponseObserved))
            }
            // A lost race against `admit`: the last permit went to another core between the
            // question and the dispatch. Reported as what it is, at the consequence the
            // exchange has already crossed — the floor does not move back for a more
            // precise late observation.
            InnerOutcome::NotDispatched(_) => Err(Refusal::after_admission(
                McpReError::InnerPlaneUnavailable,
                503,
            )),
            InnerOutcome::Indeterminate(_) => {
                progress.observe_origin(ResponseOrigin::DispatchIndeterminate);
                Err(Refusal::after_admission(
                    McpReError::InnerDispatchIndeterminate,
                    504,
                ))
            }
            InnerOutcome::InvalidUpstream(clause) => Err(Refusal::after_admission(
                HttpProfileError::UpstreamResponseInvalid(clause),
                502,
            )),
        }
    }

    /// NOTIFICATION-OBSERVED — may a 202 be minted for what the inner plane managed to do?
    ///
    /// ```text
    /// ensures   Ok  => the backend RECEIVED the message
    ///           Err => 503 (nothing was transmitted) / 504 (transmitted, no answer)
    /// refusal   NOT free — the exchange has crossed the threshold either way
    /// ```
    ///
    /// Two outcomes acknowledge and two refuse, split on whether the backend ANSWERED. The
    /// 202 says the enforcement boundary authenticated and accepted the message and the
    /// inner plane received it; it never says any action completed (#418). What the backend
    /// answered is discarded unread, as JSON-RPC requires — but WHETHER it was reached is
    /// not a detail of the answer, and a message that never left the proxy has been
    /// accepted by nothing.
    ///
    /// [`InnerOutcome::InvalidUpstream`] acknowledges, and that is not a concession: a
    /// conformant Streamable-HTTP backend answers a notification with `202 Accepted` and no
    /// body, which carries no `application/json` content type and therefore arrives here as
    /// an unusable answer FROM A BACKEND THAT RECEIVED THE MESSAGE
    /// ([`crate::http_inner`]). The two refused outcomes are the two that say the message
    /// did not get there, or may not have.
    pub(super) fn observe_acknowledgement(
        &self,
        progress: &mut ExchangeProgress,
        outcome: &InnerOutcome,
    ) -> Result<Established<()>, Refusal> {
        match outcome {
            InnerOutcome::Replied(_) | InnerOutcome::InvalidUpstream(_) => {
                progress.observe_origin(ResponseOrigin::BackendReplied);
                Ok(Established::new(
                    (),
                    ExchangeEvent::NotificationAcknowledged,
                ))
            }
            InnerOutcome::NotDispatched(_) => Err(Refusal::after_admission(
                McpReError::InnerPlaneUnavailable,
                503,
            )),
            InnerOutcome::Indeterminate(_) => {
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

    /// A seam that admits nothing. The dispatch is never exercised here: what these
    /// controls are about is the READING of an outcome, which is this module's whole
    /// content, and every outcome is constructed directly.
    struct AdmitsNothing;

    impl AsyncInnerServer for AdmitsNothing {
        fn admit(&self) -> Result<(), crate::async_inner::NotAdmitted> {
            Err(crate::async_inner::NotAdmitted("saturated"))
        }
        fn dispatch<'a>(
            &'a self,
            _request: &'a [u8],
        ) -> crate::async_inner::InnerResponseFuture<'a> {
            Box::pin(async { InnerOutcome::NotDispatched("never dispatched") })
        }
    }

    #[test]
    fn a_saturated_plane_refuses_before_a_byte_is_transmitted() {
        // The whole reason `admit` exists. Answering saturation after the threshold turns a
        // definitely-not-executed outage into an exchange that must claim possibly-executed
        // forever after.
        let plane = InnerPlane::over(Box::new(AdmitsNothing));
        let Err(refused) = plane.admit() else {
            panic!("a saturated plane admits nothing");
        };
        assert_eq!(refused.status, 503);
    }

    #[test]
    fn a_timeout_is_neither_a_reply_nor_a_definite_failure() {
        // The distinction this module exists for. A transmitted request whose answer never
        // came leaves execution UNKNOWN, and the exchange records that origin so every
        // refusal downstream reports possibly-executed rather than a clean failure.
        let plane = InnerPlane::over(Box::new(AdmitsNothing));
        let mut progress = ExchangeProgress::new();
        let Err(refused) =
            plane.observe_reply(&mut progress, InnerOutcome::Indeterminate("timeout"))
        else {
            panic!("a timeout is not a reply");
        };
        assert_eq!(refused.status, 504, "not the 503 of a request never sent");
    }

    #[test]
    fn a_notification_the_backend_never_received_is_not_acknowledged() {
        // A 202 states that the inner plane RECEIVED the message. Minting one for a message
        // that never left the proxy would be the enforcement boundary asserting, under
        // signature, that a backend accepted something no backend has seen — and it is the
        // one exit a client could select by omitting `id`.
        let plane = InnerPlane::over(Box::new(AdmitsNothing));
        let mut progress = ExchangeProgress::new();
        assert!(plane
            .observe_acknowledgement(&mut progress, &InnerOutcome::NotDispatched("no permit"),)
            .is_err());
    }

    #[test]
    fn an_unusable_answer_to_a_notification_still_says_the_backend_was_reached() {
        // Not a concession. A conformant Streamable-HTTP backend answers a notification
        // with a bodyless 202, which arrives here as an unusable answer FROM A BACKEND THAT
        // RECEIVED THE MESSAGE. The two refused outcomes are the two that say it did not
        // get there.
        let plane = InnerPlane::over(Box::new(AdmitsNothing));
        let mut progress = ExchangeProgress::new();
        assert!(plane
            .observe_acknowledgement(
                &mut progress,
                &InnerOutcome::InvalidUpstream("content-type")
            )
            .is_ok());
    }
}
