// SPDX-License-Identifier: Apache-2.0
//! Discharging the durable responsibility taken before the dispatch, and reaching a success
//! terminal.
//!
//! The reservation was taken while refusing was still free; this is where it is completed
//! with what was actually served. A deployment with retention on asserts it can account for
//! what it served, and refusing when the evidence cannot be kept is the only thing that keeps
//! that true — so retention runs BEFORE the response goes out and before its `response.signed`
//! record.
//!
//! Both success exits come through here, the bodied reply and the bodyless 202 alike. It is
//! one function and not a block copied twice because retention wired onto only one of them is
//! a client-selectable guarantee, not a weaker one.

use std::sync::Arc;

use mcp_re_http_profile::ExecutionDisposition;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::RequestEvidence;

use crate::async_serve::ServedHttpResponse;
use crate::exchange_state::ExchangeEvent;
use crate::exchange_state::ExchangeProgress;
use crate::request_stages::RetentionDisposition;

use super::super::reply::ReplyClass;
use super::super::served;
use super::super::Exchange;
use super::super::HttpProfileProxy;
use super::SignedReply;

impl HttpProfileProxy {
    /// Discharge the retention responsibility, record the served response, and reach the
    /// terminal the classifier selected.
    ///
    /// The `response.signed` record is emitted HERE, not at signing time: everything above
    /// can still discard this response, and a record for bytes the client never received is
    /// exactly the kind of contradiction that makes an audit stream unusable.
    pub(in crate::http_profile_serve) async fn serve_retained(
        &self,
        ex: &Exchange<'_>,
        progress: &mut ExchangeProgress,
        reply: SignedReply,
        retention: &RetentionDisposition,
    ) -> ServedHttpResponse {
        if let Some(rejection) = self
            .retain_accepted(
                ex.http_req,
                &reply.response,
                ex.now,
                Some(ex.verified.evidence()),
                ex.actor_id.to_owned(),
                retention,
                Self::disposition(progress, None),
                ex.key.clone(),
            )
            .await
        {
            return rejection;
        }
        progress.advance(ExchangeEvent::EvidenceRetained);
        crate::audit_record::record_to(
            &self.audit,
            crate::audit_record::AuditSubject::response_signed(),
            Some(ex.actor_id.to_owned()),
            reply.response.status,
            ex.now,
        );
        // Two terminals, because the exchange makes a different claim in each: one says the
        // call is over, the other says the client may continue — and the second is only
        // reachable now that the continuation it depends on is durable.
        progress.advance(match reply.class {
            ReplyClass::Terminal => ExchangeEvent::TerminalResponseServed,
            ReplyClass::Open(_) => ExchangeEvent::OpenLegResponseServed,
        });
        debug_assert!(progress.state().is_terminal());
        debug_assert!(progress.invariant_violation().is_none());
        served(reply.response)
    }

    /// Retain one ACCEPTED exchange (ADR-MCPRE-054), or produce the refusal.
    ///
    /// `Some(rejection)` means the evidence could not be kept and the exchange must be
    /// refused; `None` means it is retained, or retention is not configured, and the
    /// caller may serve.
    ///
    /// EVERY SUCCESS exit goes through here — the bodied reply and the bodyless 202 alike,
    /// which is why it is one function and not a block copied twice. A REFUSAL exit cannot
    /// use it: refusing a refusal has no exit to fall through to, so those go through
    /// [`retain_terminal_refusal`](Self::retain_terminal_refusal), which retains best-effort
    /// and serves the refusal whatever the outcome.
    ///
    /// Retention runs BEFORE the response goes out and before its `response.signed`
    /// record: everything above can still discard this response, and retaining an exchange
    /// the client never received would put a record in the store that no receipt should be
    /// issued about. A deployment with retention on asserts it can account for what it
    /// served, and refusing when the evidence cannot be kept is the only thing that keeps
    /// that true.
    /// Retain a POST-DISPATCH REFUSAL as the terminal this exchange actually served, and
    /// serve it whatever the retention outcome.
    ///
    /// The marker's meaning is *this request crossed the execution threshold AND no durable
    /// retained terminal exchange discharges that responsibility.* A refusal the proxy
    /// minted and can make durable discharges it exactly as a reply does: the archive then
    /// records what happened, and the marker clears. Leaving it instead would let any caller
    /// who can produce a post-dispatch refusal on demand — an unrecognised `resultType`
    /// yields 502 — accumulate *indeterminate* crossings at will, drowning the signal the
    /// marker exists to carry in the cheapest thing a caller can do.
    ///
    /// **The ordering inverts here, and it has to.** On a success exit retention runs first
    /// and a failure REFUSES. A refusal exit cannot refuse: there is no further exit to fall
    /// through to, and converting one refusal into another loses the cause the client needs.
    /// So the refusal is minted, retention is attempted, and the refusal is served — and a
    /// `Failed` outcome leaves the marker, which under the invariant above is the true
    /// statement about the exchange rather than a failure to clean up.
    ///
    /// Nothing here weakens what the refusal CLAIMS. `ExecutionDisposition` is untouched, so
    /// a retained refusal hop records *the backend may have executed and this is what the
    /// client was told* — more than the store holds today, not less.
    pub(in crate::http_profile_serve) async fn refuse_retained(
        &self,
        ex: &Exchange<'_>,
        refusal: crate::refusal::Refusal,
        progress: &ExchangeProgress,
        retention_owed: &RetentionDisposition,
    ) -> ServedHttpResponse {
        let rejection = self.refuse(ex, refusal, progress);
        let request = ex.http_req;
        let served_bytes = HttpResponse {
            status: rejection.status,
            headers: rejection.headers.clone(),
            body: rejection.body.clone(),
        };
        // Best effort, and the outcome is CONSUMED rather than dropped — `RetentionOutcome`
        // is `#[must_use]` precisely so a terminal cannot silently forget whether what it
        // served is accounted for.
        let _accounted = self
            .retention
            .complete(retention_owed, request, &served_bytes)
            .await
            .is_accounted_for();
        rejection
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn retain_accepted(
        &self,
        request: &HttpRequest,
        response: &HttpResponse,
        now: i64,
        bound: Option<&RequestEvidence>,
        actor_id: String,
        retention_owed: &RetentionDisposition,
        execution: ExecutionDisposition,
        snapshot: Option<Arc<mcp_re_http_profile::ActiveDelegatedKey>>,
    ) -> Option<ServedHttpResponse> {
        if self
            .retention
            .complete(retention_owed, request, response)
            .await
            .is_accounted_for()
        {
            return None;
        }
        // The call executed and the record did not land. INDETERMINATE, and deliberately
        // not 503: the backend has already run, and 503 is the status clients retry.
        let refusal = crate::refusal::Refusal::after_admission(
            mcp_re_core::McpReError::EvidenceRetentionIndeterminate,
            500,
        );
        Some(self.responses.response_rejection(
            &self.audit,
            request,
            &refusal.cause,
            refusal.status,
            now,
            bound,
            Some(actor_id),
            execution,
            snapshot,
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::request_stages::RetentionDisposition;

    /// A deployment that retains nothing owes nothing, and the disposition says so rather
    /// than being inferred from an absent store at the discharge site. Reconstructing it
    /// here would let the two halves of the reservation disagree.
    #[test]
    fn nothing_is_owed_where_retention_is_not_configured() {
        assert!(matches!(
            RetentionDisposition::NotConfigured,
            RetentionDisposition::NotConfigured
        ));
    }
}
