// SPDX-License-Identifier: Apache-2.0
//! Everything the exchange does after the backend has acted.
//!
//! Nothing here can claim nothing happened, which is why every refusal in this region is a
//! `response_rejection` rather than a `rejection`. What the bytes ARE was read once, next
//! door in [`super::reply`]; what this region does is turn that reading into a signed
//! answer, discharge the durable responsibility taken before the dispatch, and reach one of
//! the two success terminals.
//!
//! Both success exits — the bodied reply and the bodyless 202 a notification gets — go
//! through the same retention call. Retention wired onto only one of them is not a weaker
//! guarantee, it is a client-selectable one: the notification form reaches the same backend
//! and runs the same side effects, so a hostile-but-enrolled caller could choose to leave no
//! reconstructible hop by dropping the JSON-RPC `id`.

use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::OutstandingId;

use crate::async_inner::DispatchedOutcome;
use crate::async_serve::ServedHttpResponse;
use crate::exchange_state::Established;
use crate::exchange_state::ExchangeEvent;
use crate::exchange_state::ExchangeProgress;
use crate::exchange_state::OpenLeg;
use crate::refusal::Refusal;

use super::reply::ReplyClass;
use super::reply::ValidatedReply;
use super::signing_window::SigningWindow;
use super::Exchange;
use super::HttpProfileProxy;

/// The bodyless 202 terminal a one-way message reaches.
mod notification;

/// Discharging the retention responsibility, and the two success terminals.
mod accepted;

/// A signed reply, and the class the classifier read it as.
///
/// The class travels with the response because it is read exactly once, by the classifier,
/// and re-deriving it at the serving line from the response bytes would be a second reader
/// of the same document reaching its own conclusion. Which TERMINAL the class selects stays
/// the assembly's statement, made where the reply is served.
pub(super) struct SignedReply {
    response: HttpResponse,
    class: ReplyClass,
}

impl HttpProfileProxy {
    /// Make the exchange's continuation obligation durable, or refuse.
    ///
    /// A terminal reply has none and says so through the relation. An open leg has one, and
    /// it is discharged HERE — before the reply is served — because serving an
    /// `InputRequiredResult` the deployment has kept nothing for hands the client a signed,
    /// verified instruction to continue an exchange that cannot be continued.
    async fn record_continuation_leg(
        &self,
        ex: &Exchange<'_>,
        progress: &mut ExchangeProgress,
        class: &ReplyClass,
        response_base: Vec<u8>,
    ) -> Result<(), ServedHttpResponse> {
        let ReplyClass::Open(state) = class else {
            progress.advance(ExchangeEvent::ContinuationNotRequired);
            return Ok(());
        };
        match self
            .continuations
            .record_open_leg(ex, self.requests.audience_id(), state, response_base)
            .await
        {
            Ok(recorded) => {
                progress.observe_open_leg(OpenLeg::Recorded);
                progress.establish(recorded);
                Ok(())
            }
            Err(refusal) => Err(self.refuse(ex, refusal, progress)),
        }
    }

    /// Turn what the backend returned into the signed reply this exchange will serve.
    ///
    /// Four readings in the order the machine requires: the bytes are OBSERVED, the envelope
    /// is VALIDATED, the result is CLASSIFIED, and only then is anything signed. The
    /// obligation an open leg creates latches at classification — nothing downstream can
    /// decide this exchange opens no leg after the classifier decided it does.
    pub(super) async fn assemble_reply(
        &self,
        ex: &Exchange<'_>,
        progress: &mut ExchangeProgress,
        outcome: DispatchedOutcome,
        outstanding: &OutstandingId,
        window: &SigningWindow,
    ) -> Result<SignedReply, ServedHttpResponse> {
        let inner_bytes = match self.inner_async.observe_reply(progress, outcome) {
            Ok(bytes) => progress.establish(bytes),
            Err(refusal) => return Err(self.refuse(ex, refusal, progress)),
        };
        let mut response = HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: inner_bytes,
        };
        let class = match self.read_reply(progress, &response, outstanding) {
            Ok(class) => class,
            Err(refusal) => return Err(self.refuse(ex, refusal, progress)),
        };
        let response_base = match self.responses.sign_reply(ex, &mut response, window) {
            Ok(base) => progress.establish(base),
            Err(refusal) => return Err(self.refuse(ex, refusal, progress)),
        };
        self.record_continuation_leg(ex, progress, &class, response_base)
            .await?;
        Ok(SignedReply { response, class })
    }

    /// VALIDATED then CLASSIFIED — two facts about the same bytes, kept apart.
    ///
    /// "I can hold these bytes", "these bytes are a response the protocol permits here" and
    /// "this response opens a leg" are three different claims, and the machine learns each
    /// one separately.
    fn read_reply(
        &self,
        progress: &mut ExchangeProgress,
        response: &HttpResponse,
        outstanding: &OutstandingId,
    ) -> Result<ReplyClass, Refusal> {
        let validated = progress.establish(Established::new(
            ValidatedReply::of(response, outstanding)?,
            ExchangeEvent::EnvelopeValidated,
        ));
        let class = progress.establish(Established::new(
            validated.classify()?,
            ExchangeEvent::ResponseClassified,
        ));
        // The obligation is incurred HERE, before the reply is signed and long before it is
        // served. It latches: nothing downstream can decide this exchange opens no leg after
        // the classifier decided it does.
        progress.observe_open_leg(match class {
            ReplyClass::Terminal => OpenLeg::NotApplicable,
            ReplyClass::Open(_) => OpenLeg::Required,
        });
        Ok(class)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The class travels with the response, and the two classes are different claims about
    /// the exchange: one says the call is over, the other that the client may continue. A
    /// reply that carried the wrong one would let an open leg be served as a completed call,
    /// which the machine's own P2 invariant then reports as a violation.
    #[test]
    fn the_reply_carries_the_class_the_classifier_read() {
        let empty = || HttpResponse {
            status: 200,
            headers: vec![],
            body: vec![],
        };
        let terminal = SignedReply {
            response: empty(),
            class: ReplyClass::Terminal,
        };
        let open = SignedReply {
            response: empty(),
            class: ReplyClass::Open("state-1".into()),
        };
        assert!(matches!(terminal.class, ReplyClass::Terminal));
        assert!(matches!(open.class, ReplyClass::Open(ref s) if s == "state-1"));
    }
}
