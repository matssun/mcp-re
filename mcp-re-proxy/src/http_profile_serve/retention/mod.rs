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
//! Every refusal here turns on one question: could a retry succeed? Before dispatch the
//! exchange is exactly where it was, so the answer is `pre_dispatch_refusal`'s alone — 503
//! for backpressure, and not 503 for a store that will never accept another write, nor for
//! a crossing that could be neither made durable nor withdrawn. After dispatch the backend
//! has acted, and answering 503 there is what made a transient store fault into repeated
//! execution.

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
    ///           Err => `pre_dispatch_refusal`, bound
    /// forbids   running the backend
    /// refusal   free
    /// ```
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
            Ok(reservation) => Ok(PreDispatchRetention::Reserved {
                store: Arc::clone(store),
                reservation,
            }),
            Err(e) => Err(Self::pre_dispatch_refusal(&e, "accept the exchange")),
        }
    }

    /// RETENTION-COMMITTED — record the crossing of the execution threshold.
    ///
    /// ```text
    /// ensures   Ok  => the crossing of the execution threshold is itself durable
    ///           Err => `pre_dispatch_refusal`, bound
    /// forbids   running the backend
    /// refusal   THE LAST FREE ONE
    /// ```
    ///
    /// Awaiting is not optional: dispatching before the crossing is durable would make the
    /// record a hint rather than a record.
    pub(super) async fn commit(
        &self,
        accepted: PreDispatchRetention,
    ) -> Result<Established<RetentionDisposition>, Refusal> {
        let committed =
            |d: RetentionDisposition| Established::new(d, ExchangeEvent::RetentionCommitted);
        let PreDispatchRetention::Reserved { store, reservation } = accepted else {
            return Ok(committed(RetentionDisposition::NotConfigured));
        };
        match store.commit_to_dispatch(reservation).await {
            Ok(crossing) => Ok(committed(RetentionDisposition::Committed {
                store,
                crossing,
            })),
            Err(e) => Err(Self::pre_dispatch_refusal(&e, "record the crossing")),
        }
    }

    /// What a PRE-DISPATCH retention fault is answered with.
    ///
    /// One place, because it is one decision: could a retry succeed, and is the store's
    /// record of this exchange statable? 503 says keep trying and is right for a full queue
    /// — the permit scheme's whole argument is that refusing at the ceiling is free and
    /// retry-safe. It is wrong for the other two, and for different reasons: a retired
    /// writer accepts nothing again until this replica restarts, and an unresolved crossing
    /// leaves something on disk that may read as a threshold an exchange never crossed
    /// (R9-C099), so it carries the disposition that says so.
    fn pre_dispatch_refusal(error: &RetentionError, attempted: &str) -> Refusal {
        let unavailable =
            |status| Refusal::after_admission(McpReError::EvidenceRetentionUnavailable, status);
        match error {
            RetentionError::Unresolved(_) => {
                eprintln!(
                    "evidence retention could not {attempted}: the exchange did NOT dispatch \
                     and the store's record of it cannot be stated: {error}"
                );
                unavailable(500).refining(ExecutionDisposition::NothingExecutedRetentionUnresolved)
            }
            RetentionError::StoreRetired(_) => {
                eprintln!(
                    "evidence retention could not {attempted}, and this replica will not \
                     accept the next one either: {error}"
                );
                unavailable(500)
            }
            _ => {
                eprintln!(
                    "evidence retention could not {attempted}, refusing before dispatch: \
                     {error}"
                );
                unavailable(503)
            }
        }
    }

    /// Discharge the obligation with the terminal response this exchange will actually
    /// return — success or refusal alike.
    ///
    /// ```text
    /// ensures   Retained      => the crossing is discharged and its marker is cleared
    ///           NotConfigured => nothing was ever owed
    ///           Failed        => the crossing is NOT discharged and its marker SURVIVES
    /// ```
    ///
    /// **`Failed` is a true answer, not a leftover** — see [`RetentionOutcome`]. It returns
    /// three cases rather than a `Result<(), Refusal>` because its two callers need
    /// different things from the failure: a SUCCESS exit turns it into a refusal, and a
    /// REFUSAL exit cannot, having no further exit to fall through to. A `Result` would
    /// have made the second caller discard an error.
    pub(super) async fn complete(
        &self,
        owed: &RetentionDisposition,
        request: &HttpRequest,
        response: &HttpResponse,
    ) -> RetentionOutcome {
        let RetentionDisposition::Committed { store, crossing } = owed else {
            return RetentionOutcome::NotConfigured;
        };
        match store.complete(crossing, request, response).await {
            Ok(_) => RetentionOutcome::Retained,
            Err(e) => {
                eprintln!(
                    "evidence retention failed AFTER the call executed; the exchange is \
                     indeterminate and MUST NOT be blindly retried: {e}"
                );
                RetentionOutcome::Failed
            }
        }
    }
}

mod outcome;

pub(in crate::http_profile_serve) use outcome::RetentionOutcome;

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

    fn io(kind: std::io::ErrorKind) -> std::io::Error {
        std::io::Error::new(kind, "fixture")
    }

    /// The three pre-dispatch faults are three answers, and the module's whole argument is
    /// that they are not one.
    ///
    /// Before this the file had exactly ONE control — the negative, that a deployment
    /// retaining nothing owes nothing — so every failing branch of the refusal was
    /// unmeasured. A `503` for all three would have satisfied the battery while telling a
    /// client to keep retrying a replica that will never accept another write, and while
    /// dropping the disposition that says an unresolved crossing may be on disk.
    #[test]
    fn each_pre_dispatch_fault_earns_its_own_answer() {
        // Backpressure: retry, and the permit scheme's argument is that refusing here is
        // free.
        let full = Retention::pre_dispatch_refusal(
            &RetentionError::Store(io(std::io::ErrorKind::WouldBlock)),
            "accept the exchange",
        );
        assert_eq!(full.status, 503);
        assert!(full.execution_refinement.is_none());

        // A retired writer accepts nothing again until this replica restarts, so 503 —
        // the status clients retry — is the wrong thing to say.
        let retired = Retention::pre_dispatch_refusal(
            &RetentionError::StoreRetired(io(std::io::ErrorKind::BrokenPipe)),
            "accept the exchange",
        );
        assert_eq!(retired.status, 500);
        assert!(retired.execution_refinement.is_none());

        // An unresolved crossing leaves something on disk that may read as a threshold the
        // exchange never crossed (R9-C099), and the refusal has to CARRY that.
        let unresolved = Retention::pre_dispatch_refusal(
            &RetentionError::Unresolved(io(std::io::ErrorKind::Other)),
            "record the crossing",
        );
        assert_eq!(unresolved.status, 500);
        assert_eq!(
            unresolved.execution_refinement,
            Some(ExecutionDisposition::NothingExecutedRetentionUnresolved)
        );
    }

    /// Every pre-dispatch refusal is free, whichever fault produced it.
    ///
    /// `after_admission` is the posture that says the fault is on the response side and
    /// records `mcp-re.response.rejected`; all three arms must take it, because the backend
    /// has NOT run in any of them and a `request.rejected` would contradict the accepted
    /// record for the same request.
    #[test]
    fn no_pre_dispatch_fault_claims_the_backend_ran() {
        for error in [
            RetentionError::Store(io(std::io::ErrorKind::WouldBlock)),
            RetentionError::StoreRetired(io(std::io::ErrorKind::BrokenPipe)),
            RetentionError::Unresolved(io(std::io::ErrorKind::Other)),
        ] {
            let refusal = Retention::pre_dispatch_refusal(&error, "accept the exchange");
            assert_eq!(
                refusal.cause,
                crate::refusal::RefusalCause::from(McpReError::EvidenceRetentionUnavailable),
                "a pre-dispatch retention fault is UNAVAILABLE, never INDETERMINATE: the \
                 indeterminate code is what `complete` uses once the call has executed"
            );
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
        assert_eq!(
            retention
                .complete(&disposition, &request(), &response)
                .await,
            RetentionOutcome::NotConfigured,
            "an unconfigured deployment owes nothing, which is not the same fact as a \
             record having landed"
        );
    }

    /// The three outcomes are three values, and only two of them mean the exchange is
    /// accounted for.
    ///
    /// Stated as a control because the property that matters is exactly that `Failed` does
    /// not fold into the safe side. A `bool` here — or a `Result` whose error a refusal path
    /// discards — would make *the completion did not land* indistinguishable from *nothing
    /// was owed*, and the surviving `DispatchCommitted` marker is the only evidence an
    /// operator has that an exchange is unaccounted for.
    #[test]
    fn a_failed_completion_is_not_accounted_for_and_the_other_two_are() {
        assert!(RetentionOutcome::Retained.is_accounted_for());
        assert!(RetentionOutcome::NotConfigured.is_accounted_for());
        assert!(
            !RetentionOutcome::Failed.is_accounted_for(),
            "a failed completion leaves the crossing standing; its marker is the true answer"
        );
        assert_ne!(RetentionOutcome::Retained, RetentionOutcome::NotConfigured);
    }
}
