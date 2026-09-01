// SPDX-License-Identifier: Apache-2.0
//! Durable responsibility for a served exchange (ADR-MCPRE-054).
//!
//! One fact: **a deployment that has turned retention on can account for everything it
//! served, and it takes that responsibility BEFORE the side effects run rather than after
//! them.** Three steps, and the middle one is what #741 added —
//! [`reserve`](Retention::reserve) accepts the obligation, [`commit`](Retention::commit)
//! records the crossing, [`complete`](Retention::complete) discharges it.
//!
//! What each step MEANS belongs to the store's own products,
//! [`crate::transparency::ReservedBeforeDispatch`] and
//! [`crate::transparency::DispatchCommitted`]. What is here is the serving-side half:
//! which refusal each failure earns.
//!
//! Reserving fails before anything is committed: an ordinary 503. Committing fails in one
//! of two ways, and they are not one — nothing published is again an ordinary 503, while a
//! crossing that could be neither made durable nor withdrawn is not. Completing fails
//! AFTER the backend acted; answering 503 there is what made a transient store fault into
//! repeated execution, because 503 is the status clients retry.

use std::sync::Arc;

use mcp_re_core::McpReError;
use mcp_re_http_profile::rejection::ExecutionDisposition;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;

use crate::exchange_state::Established;
use crate::exchange_state::ExchangeEvent;
use crate::refusal::Refusal;
use crate::request_stages::PreDispatchRetention;
use crate::request_stages::RetentionDisposition;
use crate::transparency::EvidenceRetention;
use crate::transparency::RetentionError;

/// The deployment's evidence-retention obligation, and the store that discharges it.
///
/// Private representation with two constructors, so *this deployment retains nothing* is a
/// state of the obligation rather than an `Option` every caller re-reads.
pub(super) struct Retention {
    /// `None` is the default: nothing is retained and the request path is unchanged.
    store: Option<Arc<EvidenceRetention>>,
}

impl Retention {
    /// The obligation of a deployment that retains nothing.
    pub(super) fn none() -> Self {
        Retention { store: None }
    }

    /// The obligation of a deployment that installed a store.
    ///
    /// Turning this on changes what the deployment STORES about every call — the full
    /// request and response messages, which is what a later SCITT statement commits to and
    /// what an auditor recomputes the handles from.
    pub(super) fn to(store: Arc<EvidenceRetention>) -> Self {
        Retention { store: Some(store) }
    }

    /// RETENTION-RESERVED — accept the obligation, asserting nothing about execution.
    ///
    /// ```text
    /// ensures   Ok  => the obligation is durably accepted, and no artefact says the
    ///                  exchange crossed anything
    ///           Err => 503, bound
    /// forbids   running the backend
    /// refusal   free
    /// ```
    ///
    ///
    /// NOT a probe: it does not claim the later writes will succeed, because nothing can —
    /// the backend and the store share no transaction. The write runs on the retention
    /// writer thread and this future AWAITS its acknowledgement, so the core keeps serving
    /// while the fsync is in progress. What it returns rescinds itself on drop, so a
    /// refusal between here and the commitment leaves nothing behind and needs no call.
    /// It establishes no exchange STATE, deliberately: accepting the obligation carries the
    /// same consequence as the step before it.
    pub(super) async fn reserve(
        &self,
        request: &HttpRequest,
    ) -> Result<PreDispatchRetention, Refusal> {
        let Some(store) = self.store.as_ref() else {
            return Ok(PreDispatchRetention::NotConfigured);
        };
        match store.reserve(request).await {
            Ok(reservation) => Ok(PreDispatchRetention::Reserved(reservation)),
            Err(e) => {
                eprintln!(
                    "evidence retention could not accept the exchange, refusing before \
                     dispatch: {e}"
                );
                Err(Refusal::after_admission(
                    McpReError::EvidenceRetentionUnavailable,
                    503,
                ))
            }
        }
    }

    /// RETENTION-COMMITTED — record the crossing of the execution threshold.
    ///
    /// ```text
    /// ensures   Ok  => the crossing of the execution threshold is itself durable
    ///           Err => 503 (nothing published) / 500 (published and unwithdrawable), bound
    /// forbids   running the backend
    /// refusal   THE LAST FREE ONE
    /// ```
    ///
    /// Awaiting is not optional: dispatching before the crossing is durable would make the
    /// record a hint rather than a record.
    ///
    /// The two failures are not one. Nothing published is an ordinary 503 — the backend is
    /// untouched and a retry is genuinely free. A crossing that could be neither made
    /// durable nor withdrawn is not: answering it as a retry-safe 503 would tell a client
    /// to retry freely while leaving execution-signifying state behind (R9-C099).
    pub(super) async fn commit(
        &self,
        accepted: PreDispatchRetention,
    ) -> Result<Established<RetentionDisposition>, Refusal> {
        let committed =
            |d: RetentionDisposition| Established::new(d, ExchangeEvent::RetentionCommitted);
        let PreDispatchRetention::Reserved(reservation) = accepted else {
            return Ok(committed(RetentionDisposition::NotConfigured));
        };
        // A disposition can only be `Reserved` if the store was present when it was built,
        // and the store is owned for the proxy's whole life — so this is the same value
        // that accepted the obligation.
        let Some(store) = self.store.as_ref() else {
            return Ok(committed(RetentionDisposition::NotConfigured));
        };
        match store.commit_to_dispatch(reservation).await {
            Ok(crossing) => Ok(committed(RetentionDisposition::Committed(crossing))),
            Err(RetentionError::Unresolved(e)) => {
                eprintln!(
                    "evidence retention could not establish OR withdraw the crossing; the \
                     exchange did NOT dispatch and the store's record of it cannot be \
                     stated: {e}"
                );
                Err(
                    Refusal::after_admission(McpReError::EvidenceRetentionUnavailable, 500)
                        .refining(ExecutionDisposition::NothingExecutedRetentionUnresolved),
                )
            }
            Err(e) => {
                eprintln!(
                    "evidence retention could not record the crossing, refusing before \
                     dispatch: {e}"
                );
                Err(Refusal::after_admission(
                    McpReError::EvidenceRetentionUnavailable,
                    503,
                ))
            }
        }
    }

    /// Discharge the obligation with what was actually served.
    ///
    /// ```text
    /// ensures   Ok  => nothing is owed: the record is complete, or none was ever owed
    ///           Err => 500 INDETERMINATE — the call executed and the record did not land
    /// refusal   NOT free, and deliberately NOT 503
    /// ```
    ///
    /// The refusal names the exchange indeterminate rather than unavailable: the backend
    /// has already run, and 503 is the status clients retry.
    pub(super) async fn complete(
        &self,
        owed: &RetentionDisposition,
        request: &HttpRequest,
        response: &HttpResponse,
    ) -> Result<(), Refusal> {
        let RetentionDisposition::Committed(crossing) = owed else {
            return Ok(());
        };
        // A disposition can only be `Reserved` if the store was present when it was built,
        // and the store is owned for the proxy's whole life — so this is the same value
        // that made the reservation.
        let Some(store) = self.store.as_ref() else {
            return Ok(());
        };
        match store.complete(crossing, request, response).await {
            Ok(_) => Ok(()),
            Err(e) => {
                eprintln!(
                    "evidence retention failed AFTER the call executed; the exchange is \
                     indeterminate and MUST NOT be blindly retried: {e}"
                );
                Err(Refusal::after_admission(
                    McpReError::EvidenceRetentionIndeterminate,
                    500,
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> HttpRequest {
        HttpRequest {
            method: "POST".into(),
            target_uri: "https://example.test/mcp".into(),
            headers: vec![],
            body: b"{}".to_vec(),
        }
    }

    #[tokio::test]
    async fn a_deployment_that_retains_nothing_owes_nothing_on_any_of_the_three() {
        // `NotConfigured` is not a missing reservation. The request path is unchanged
        // through all three steps, and — the half that matters — the completion owes
        // nothing rather than silently treating an absent obligation as a failed one.
        let retention = Retention::none();
        let mut progress = crate::exchange_state::ExchangeProgress::new();
        let accepted = retention
            .reserve(&request())
            .await
            .expect("retaining nothing never refuses");
        assert!(matches!(accepted, PreDispatchRetention::NotConfigured));

        let disposition = progress.establish(
            retention
                .commit(accepted)
                .await
                .expect("and committing nothing never refuses either"),
        );
        assert!(matches!(disposition, RetentionDisposition::NotConfigured));

        let response = HttpResponse {
            status: 200,
            headers: vec![],
            body: b"{}".to_vec(),
        };
        assert!(retention
            .complete(&disposition, &request(), &response)
            .await
            .is_ok());
    }
}
