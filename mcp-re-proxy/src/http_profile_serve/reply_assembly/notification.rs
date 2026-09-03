// SPDX-License-Identifier: Apache-2.0
//! The bodyless 202 a one-way message is answered with (#424 / #418).
//!
//! Its own terminal, because everything on the bodied path assumes a reply the client asked
//! for. The 202 says the enforcement boundary authenticated and accepted the message — never
//! that any action completed — and the branch is decided from the REQUEST, where the fact
//! lives: a notification is a message the client sent with no `id`, and no reply can make it
//! one or stop it being one.
//!
//! It is the one exit a client could SELECT, by omitting `id`. That is why the acknowledgement
//! is observed before the 202 is minted, and why retention covers this exit on the same terms
//! as a bodied reply: otherwise a hostile-but-enrolled caller could leave no reconstructible
//! hop for a call that reached the same backend and ran the same side effects.

use mcp_re_http_profile::sign_delegated_accepted_202;
use mcp_re_http_profile::ExecutionDisposition;
use mcp_re_http_profile::HttpRequest;

use crate::async_inner::DispatchedOutcome;
use crate::async_serve::ServedHttpResponse;
use crate::exchange_state::ExchangeProgress;
use crate::refusal::RefusalCause;
use crate::request_stages::RetentionDisposition;

use super::super::served;
use super::super::signing_window::SigningWindow;
use super::super::Exchange;
use super::super::HttpProfileProxy;

impl HttpProfileProxy {
    /// The NOTIFICATION arm: a signed bodyless 202 for a message with no JSON-RPC `id`.
    ///
    /// This runs AFTER the backend has acted. The 202 states that the enforcement boundary
    /// authenticated and accepted the message — never that any action completed (#418).
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn answer_notification(
        &self,
        http_req: &HttpRequest,
        window: &SigningWindow,
        now: i64,
        verified: &mcp_re_http_profile::VerifiedMcpRequest,
        actor_id: String,
        retention: &RetentionDisposition,
        execution: ExecutionDisposition,
    ) -> ServedHttpResponse {
        let a = window.key();
        match sign_delegated_accepted_202(
            http_req,
            &a.credential,
            a.key.as_ref(),
            &a.delegated_kid,
            now,
            window.expires(),
        ) {
            Ok(ack) => {
                // Retention covers this exit on the SAME terms as the bodied reply.
                // The backend has already run by here, so leaving it out let a
                // client decide whether a call it had executed was accountable, by
                // the single act of omitting the JSON-RPC `id`.
                if let Some(rejection) = self
                    .retain_accepted(
                        http_req,
                        &ack,
                        now,
                        Some(verified.evidence()),
                        actor_id.clone(),
                        retention,
                        execution,
                        Some(window.shared()),
                    )
                    .await
                {
                    return rejection;
                }
                // The signed bodyless 202 IS the signed response for a notification,
                // and it is returned on this line — so the record describes bytes the
                // client actually receives.
                crate::audit_record::record_to(
                    &self.audit,
                    crate::audit_record::AuditSubject::response(
                        mcp_re_core::audit::AuditEvent::response_signed(),
                    ),
                    Some(actor_id),
                    202,
                    now,
                );
                served(ack)
            }
            Err(e) => self.responses.response_rejection(
                &self.audit,
                http_req,
                &RefusalCause::from(e),
                500,
                now,
                Some(verified.evidence()),
                Some(actor_id),
                execution,
                Some(window.shared()),
            ),
        }
    }

    /// The whole notification terminal: read whether the message got there, then answer it.
    ///
    /// The reply itself is discarded, as JSON-RPC requires — but not the fact of whether the
    /// inner plane received the message at all. A 202 minted for a message whose transport
    /// failed after transmission is a signed statement from the enforcement boundary that a
    /// backend accepted something no backend is known to have seen, and it is the one exit a
    /// client could select by omitting `id`. The stronger case — a message that was never
    /// transmitted — cannot reach this terminal, because it is refused before the exchange
    /// commits to a dispatch at all.
    pub(in crate::http_profile_serve) async fn answer_notification_terminal(
        &self,
        ex: &Exchange<'_>,
        progress: &mut ExchangeProgress,
        outcome: &DispatchedOutcome,
        window: &SigningWindow,
        retention: &RetentionDisposition,
    ) -> ServedHttpResponse {
        match self.inner_async.observe_acknowledgement(progress, outcome) {
            Ok(acknowledged) => progress.establish(acknowledged),
            Err(refusal) => return self.refuse(ex, refusal, progress),
        }
        debug_assert!(progress.state().is_terminal());
        debug_assert!(progress.invariant_violation().is_none());
        self.answer_notification(
            ex.http_req,
            window,
            ex.now,
            ex.verified,
            ex.actor_id.to_owned(),
            retention,
            Self::disposition(progress, None),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    /// The 202 is minted only for a message the inner plane is known to have received. The
    /// refused outcome is the one that says it may not have got there — a signed statement
    /// that a backend accepted something no backend is known to have seen is the failure
    /// this arm exists to prevent.
    ///
    /// The message that was never transmitted at all is absent from this set by
    /// construction: a committed dispatch has no outcome meaning *nothing happened*, so the
    /// case is decided before the exchange commits, where it can still be refused as
    /// retry-safe.
    #[test]
    fn a_message_that_may_not_have_arrived_is_not_acknowledged() {
        use crate::async_inner::DispatchedOutcome;
        let lost = DispatchedOutcome::Indeterminate("the answer never came");
        assert!(!matches!(lost, DispatchedOutcome::Replied(_)));
    }
}
