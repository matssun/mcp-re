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

use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;

use crate::exchange_state::Established;
use crate::exchange_state::ExchangeEvent;
use crate::refusal::Refusal;
use crate::request_stages::PreDispatchRetention;
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
            // The one place that has established there is no store, so the one place that may
            // say so.
            return Ok(PreDispatchRetention::NotConfigured(
                NothingRetained::minted_by_retention(),
            ));
        };
        match store.reserve(request).await {
            Ok(reservation) => Ok(PreDispatchRetention::Reserved {
                store: Arc::clone(store),
                reservation,
            }),
            Err(e) => Err(refusal::pre_dispatch(&e, "accept the exchange")),
        }
    }

    /// RETENTION-COMMITTED — record the crossing of the execution threshold.
    ///
    /// ```text
    /// ensures   Ok  => the crossing of the execution threshold is durable, or nothing is retained
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
        let (store, reservation) = match accepted {
            PreDispatchRetention::Reserved { store, reservation } => (store, reservation),
            // The owner's own statement, forwarded: nothing here can mint another.
            PreDispatchRetention::NotConfigured(nothing) => {
                return Ok(committed(RetentionDisposition::NotConfigured(nothing)));
            }
        };
        match store.commit_to_dispatch(reservation).await {
            Ok(crossing) => Ok(committed(RetentionDisposition::Committed {
                store,
                crossing,
            })),
            Err(e) => Err(refusal::pre_dispatch(&e, "record the crossing")),
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
    /// **`Failed` is a true answer, not a leftover** — see [`RetentionOutcome`]. Three cases
    /// rather than a `Result`, because a SUCCESS exit turns a failure into a refusal and a
    /// REFUSAL exit cannot, having no further exit to fall through to.
    ///
    /// The REQUEST is not a parameter: the crossing carries the retained projection it was
    /// taken for, so no caller can discharge one exchange's crossing against another's
    /// request. The RESPONSE is the caller's, and nothing here pairs it with the crossing:
    /// both call sites take it from the reply assembly of the same exchange, which is where
    /// that pairing is owned, and a response from another exchange would be retained as
    /// this one's terminal.
    pub(super) async fn complete(
        &self,
        owed: &RetentionDisposition,
        response: &HttpResponse,
    ) -> RetentionOutcome {
        let RetentionDisposition::Committed { store, crossing } = owed else {
            // `NotConfigured` carries the owner's witness, so this arm is reached only by an
            // exchange the owner established owes nothing.
            return RetentionOutcome::NotConfigured;
        };
        match store.complete(crossing, response).await {
            Ok(_) => RetentionOutcome::Retained,
            Err(e) => {
                fault_report::report_after_dispatch(&e);
                RetentionOutcome::Failed
            }
        }
    }
}

// The continuation plane reports its store faults through the same paced reporter.
pub(in crate::http_profile_serve) mod fault_report;
mod nothing_retained;
mod outcome;
mod refusal;

pub(crate) use nothing_retained::NothingRetained;
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

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("mcp-re-retention-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            TempDir(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
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
        assert!(matches!(accepted, PreDispatchRetention::NotConfigured(_)));

        let disposition = progress.establish(
            retention
                .commit(accepted)
                .await
                .expect("and committing nothing never refuses either"),
        );
        assert!(matches!(
            disposition,
            RetentionDisposition::NotConfigured(_)
        ));

        let response = HttpResponse {
            status: 200,
            headers: vec![],
            body: b"{}".to_vec(),
        };
        assert_eq!(
            retention.complete(&disposition, &response).await,
            RetentionOutcome::NotConfigured,
            "an unconfigured deployment owes nothing, which is not the same fact as a \
             record having landed"
        );
    }

    /// The two configurations state different things, and only the unconfigured one states
    /// that nothing is retained.
    ///
    /// The witness is what makes `NotConfigured` an owner's statement rather than a value a
    /// caller writes. This measures the half the type cannot: that the owner mints it from
    /// the absence of a store, so a deployment that installed one is handed a reservation
    /// and never the arm that skips the obligation.
    #[tokio::test]
    async fn only_a_deployment_without_a_store_states_that_it_retains_nothing() {
        let none = Retention::none().reserve(&request()).await;
        assert!(matches!(none, Ok(PreDispatchRetention::NotConfigured(_))));

        let dir = TempDir::new("states-nothing");
        let store = Arc::new(EvidenceRetention::open(&dir.0).expect("open"));
        let some = Retention::to(store).reserve(&request()).await;
        assert!(matches!(some, Ok(PreDispatchRetention::Reserved { .. })));
    }

    #[tokio::test]
    async fn a_store_fault_at_reserve_is_refused_not_waved_through() {
        let dir = TempDir::new("reserve-fault");
        let mut store = EvidenceRetention::open(&dir.0).expect("open");
        store.retire_writer_for_test();
        let result = Retention::to(Arc::new(store)).reserve(&request()).await;
        let Err(refusal) = result else {
            panic!("a retired store must refuse the reservation");
        };
        assert_eq!(refusal.status, 500);
    }

    #[tokio::test]
    async fn a_store_fault_at_commit_is_refused_not_waved_through() {
        let dir = TempDir::new("commit-fault");
        let mut store = EvidenceRetention::open(&dir.0).expect("open");
        let reservation = store.reserve(&request()).await.expect("reserve");
        store.retire_writer_for_test();
        let store = Arc::new(store);
        let result = Retention::to(Arc::clone(&store))
            .commit(PreDispatchRetention::Reserved { store, reservation })
            .await;
        let Err(refusal) = result else {
            panic!("a retired store must refuse the commitment");
        };
        assert_eq!(refusal.status, 500);
    }

    #[tokio::test]
    async fn a_failed_completion_is_failed_not_retained() {
        let dir = TempDir::new("completion-fault");
        let store = Arc::new(EvidenceRetention::open(&dir.0).expect("open"));
        let retention = Retention::to(store);
        let mut progress = crate::exchange_state::ExchangeProgress::new();
        let accepted = retention.reserve(&request()).await.expect("reserve");
        let Ok(committed) = retention.commit(accepted).await else {
            panic!("a live store commits");
        };
        let disposition = progress.establish(committed);
        let response = HttpResponse {
            status: 200,
            headers: vec![],
            body: b"{}".to_vec(),
        };
        assert_eq!(
            retention.complete(&disposition, &response).await,
            RetentionOutcome::Retained
        );
        assert_eq!(
            retention.complete(&disposition, &response).await,
            RetentionOutcome::Failed,
            "a completion already taken is a failure, never a second retention"
        );
    }
}
