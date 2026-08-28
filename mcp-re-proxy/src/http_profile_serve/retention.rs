// SPDX-License-Identifier: Apache-2.0
//! Durable responsibility for a served exchange (ADR-MCPRE-054).
//!
//! One fact: **a deployment that has turned retention on can account for everything it
//! served, and it takes that responsibility BEFORE the side effects run rather than after
//! them.** The obligation is therefore two halves that only make sense together —
//!
//! * [`Retention::reserve`] records that this request is about to cross the execution
//!   threshold. It is the LAST free refusal: nothing between it and the dispatch can
//!   refuse, and past the dispatch no refusal can say nothing happened.
//! * [`Retention::complete`] discharges the obligation with what was actually served.
//!
//! and a reservation that is never completed is precisely the marker an auditor uses to
//! find an exchange the deployment cannot account for.
//!
//! # The two failures are not the same failure
//!
//! Reserving fails BEFORE the backend acts, so it is an ordinary 503: nothing happened and
//! an ordinary retry is correct.
//!
//! Completing fails AFTER the backend acted. Answering 503 there is what made a transient
//! store fault into repeated execution — 503 is the status clients retry, and the retry's
//! fresh nonce passes replay admission. The exchange is *indeterminate*, and it says so.
//!
//! # Why the disposition is not an `Option`
//!
//! *This deployment retains nothing* and *a reservation is missing* are different facts.
//! Collapsing them is what used to require a guard on the completion path to tell them
//! apart (ADR-MCPRE-058 §9.6). [`RetentionDisposition`] keeps them apart, and this owner is
//! the only thing that reads it.

use std::sync::Arc;

use mcp_re_core::McpReError;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;

use crate::exchange_state::Established;
use crate::exchange_state::ExchangeEvent;
use crate::refusal::Refusal;
use crate::request_stages::RetentionDisposition;
use crate::transparency::EvidenceRetention;

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

    /// RETENTION-RESERVED — take durable responsibility BEFORE the side effects run.
    ///
    /// ```text
    /// ensures   Ok  => the crossing of the execution threshold is itself durable
    ///           Err => 503, bound
    /// forbids   running the backend
    /// refusal   THE LAST FREE ONE
    /// ```
    ///
    /// Ordered AFTER the inner-plane question. The marker this writes is durable and is
    /// erased only by [`complete`](Self::complete), so a free refusal downstream of it
    /// would leave on disk the record that a request crossed the execution threshold when
    /// it provably never reached a backend — and one such file per refusal, in a store with
    /// no expiry, for as long as the plane stays saturated.
    ///
    /// NOT a probe: it does not claim the later write will succeed, because nothing can —
    /// the backend and the store share no transaction. The write runs on the retention
    /// writer thread and this future AWAITS its acknowledgement, so the core keeps serving
    /// while the fsync is in progress. Awaiting is not optional: dispatching before the
    /// marker is durable would make the reservation a hint rather than a record.
    pub(super) async fn reserve(
        &self,
        request: &HttpRequest,
    ) -> Result<Established<RetentionDisposition>, Refusal> {
        let reserved =
            |d: RetentionDisposition| Established::new(d, ExchangeEvent::RetentionReserved);
        let Some(store) = self.store.as_ref() else {
            return Ok(reserved(RetentionDisposition::NotConfigured));
        };
        match store.reserve(request).await {
            Ok(reservation) => Ok(reserved(RetentionDisposition::Reserved(reservation))),
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

    /// Discharge the obligation with what was actually served.
    ///
    /// ```text
    /// ensures   Ok  => nothing is owed: the record is complete, or none was ever owed
    ///           Err => 500 INDETERMINATE — the call executed and the record did not land
    /// refusal   NOT free, and deliberately NOT 503
    /// ```
    ///
    /// The refusal names the exchange indeterminate rather than unavailable. The backend
    /// has already run, and 503 is the status clients retry — a retry whose fresh nonce
    /// passes replay admission and executes the tool a second time. That is the whole
    /// reason this code is not the reservation's.
    pub(super) async fn complete(
        &self,
        owed: &RetentionDisposition,
        request: &HttpRequest,
        response: &HttpResponse,
    ) -> Result<(), Refusal> {
        let RetentionDisposition::Reserved(reservation) = owed else {
            return Ok(());
        };
        // A disposition can only be `Reserved` if the store was present when it was built,
        // and the store is owned for the proxy's whole life — so this is the same value
        // that made the reservation.
        let Some(store) = self.store.as_ref() else {
            return Ok(());
        };
        match store.complete(reservation, request, response).await {
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
    async fn a_deployment_that_retains_nothing_owes_nothing_on_either_half() {
        // `NotConfigured` is not a missing reservation. The request path is unchanged, and
        // — the half that matters — the completion owes nothing rather than silently
        // treating an absent obligation as a failed one.
        let retention = Retention::none();
        let established = retention
            .reserve(&request())
            .await
            .expect("retaining nothing never refuses");
        let mut progress = crate::exchange_state::ExchangeProgress::new();
        let disposition = progress.establish(established);
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
