// SPDX-License-Identifier: Apache-2.0
//! The authoritative admission-state source (#414 rev 2 §4.3/§5.2) — what the PEP
//! consults to decide whether a workload's admission is STILL current.
//!
//! ADR-MCPRE-053 built both halves of the evidence: the authority-signed assertion,
//! and the §7 binding that ties a call to it. It deliberately did not say where the
//! *authoritative* state comes from, because which authority a deployment trusts is
//! an operator's decision. This is that seam.
//!
//! **Why a snapshot is not enough.** An assertion says an authority admitted this
//! workload at a generation. It cannot say the workload is admitted *now* — a
//! revocation between issuance and use is exactly the case the two-part design
//! exists for. Without a source to compare against, a PEP either trusts the snapshot
//! for its whole TTL (admitting a revoked workload for minutes) or refuses every
//! call. Neither is admission control.
//!
//! **Reachable-and-absent is not unreachable.** The two failures read the same to a
//! naive `Option`, and they must not:
//!
//! - `Ok(Some(state))` — the authority has a record; compare generations.
//! - `Ok(None)` — the authority is healthy and knows nothing about this workload.
//!   That is a definitive negative: the call is refused. Treating it as "unreachable"
//!   would route an unknown workload into degraded mode, where it would be SERVED on
//!   its own assertion — turning an unadmitted caller into an admitted one by being
//!   unknown, which is backwards.
//! - `Err(Unavailable)` — no answer. Only this reaches the §5.2 degraded fork, and
//!   only when the deployment opted in, bounded by P.
//!
//! The same distinction `ResolverOutcome` draws for the trust seam (C079), for the
//! same reason: an outage is not a statement about the caller.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

use mcp_re_http_profile::AdmissionStatus;
use mcp_re_http_profile::authoritative_admission::AuthoritativeAdmission;

/// A fail-closed admission-source failure: the authority could not be reached or
/// did not answer. NOT a verdict about the workload, and never a fallback to allow.
#[derive(Debug, Clone)]
pub enum AdmissionSourceError {
    /// The authoritative source could not be reached or answered.
    Unavailable { details: String },
}

impl std::fmt::Display for AdmissionSourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdmissionSourceError::Unavailable { details } => {
                write!(f, "admission source unavailable: {details}")
            }
        }
    }
}

/// A boxed source future (the lookup is awaited on the serving path).
pub type AdmissionFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, AdmissionSourceError>> + Send + 'a>>;

/// The authoritative admission state a PEP consults per call.
///
/// Implementations MUST be non-blocking: `current` is awaited on the per-core
/// request path, before the inner backend runs.
pub trait AsyncAdmissionSource: Send + Sync {
    /// The current authoritative state for `admission_id`.
    ///
    /// `Ok(None)` means the authority is healthy and has no record — a definitive
    /// negative. `Err` means no answer; see the module docs for why the two must not
    /// collapse.
    fn current<'a>(
        &'a self,
        admission_id: &'a str,
    ) -> AdmissionFuture<'a, Option<AuthoritativeAdmission>>;
}

/// The key an admission record lives under in a shared store.
pub const ADMISSION_KEY_PREFIX: &str = "mcp-re:admission:";

/// The shared-store key for a workload's authoritative admission record.
///
/// The id is used verbatim rather than digested: unlike a continuation's
/// `requestState`, an admission id is not a capability — it is a name an operator
/// assigns and must be able to read in `redis-cli` when a revocation is not taking
/// effect. Nothing is authorized by knowing it; the record it addresses only ever
/// *narrows* what a call may do.
pub fn admission_key(admission_id: &str) -> String {
    format!("{ADMISSION_KEY_PREFIX}{admission_id}")
}

// ---- In-memory source (unit tests / single-replica only) -------------------

/// A single-process in-memory admission source — unit tests and single-replica runs
/// ONLY. It cannot carry a revocation across replicas: each process holds its own
/// map, so revoking here says nothing to any other replica. A fleet wires the shared
/// store instead.
#[derive(Debug, Default)]
pub struct InMemoryAdmissionSource {
    records: Mutex<HashMap<String, AuthoritativeAdmission>>,
    /// When set, every lookup fails as unavailable — for exercising the §5.2
    /// degraded fork without taking a real store down.
    unavailable: Mutex<bool>,
}

impl InMemoryAdmissionSource {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record (or supersede) the authoritative state for a workload.
    pub fn admit(&self, admission_id: &str, generation: u64) {
        self.set(AuthoritativeAdmission::new(
            admission_id.to_owned(),
            generation,
            AdmissionStatus::Admitted,
        ));
    }

    /// Revoke a workload — the invalidation a propagation measurement times.
    pub fn revoke(&self, admission_id: &str) {
        let generation = self
            .records
            .lock()
            .unwrap_or_else(recover)
            .get(admission_id)
            .map(|r| r.generation())
            .unwrap_or(0);
        self.set(AuthoritativeAdmission::new(
            admission_id.to_owned(),
            generation,
            AdmissionStatus::Revoked,
        ));
    }

    /// Write an arbitrary authoritative record, KEYED BY ITS OWN SUBJECT.
    ///
    /// There is no separate key parameter, so a record cannot be filed under a workload
    /// it is not about. That was reachable before — `set(id, state)` took two operands
    /// nothing related — and it is the same defect the map exists to avoid: a later
    /// lookup would return a value that is correct about the generation and wrong about
    /// whose it is.
    pub fn set(&self, state: AuthoritativeAdmission) {
        self.records
            .lock()
            .unwrap_or_else(recover)
            .insert(state.admission_id().to_owned(), state);
    }

    /// Make every subsequent lookup fail as unavailable (or stop doing so).
    pub fn set_unavailable(&self, unavailable: bool) {
        *self.unavailable.lock().unwrap_or_else(recover) = unavailable;
    }
}

/// A poisoned in-memory record set, as the outage this source already reports.
///
/// A lock is poisoned because a thread panicked while holding it: runtime state, not a
/// fact about this call. `Unavailable` is what a record set nobody can trust means to an
/// admission decision, and the caller fails closed on it already.
fn poisoned<T>(_: std::sync::PoisonError<T>) -> AdmissionSourceError {
    AdmissionSourceError::Unavailable {
        details: "in-memory admission records are poisoned".to_owned(),
    }
}

/// The guard behind a poisoned lock, for the writers that have no verdict to report.
///
/// `admit`, `revoke` and `set_unavailable` return `()`, so there is nowhere to carry an
/// outage to, and the map is a plain `HashMap`. Every READER above reports the outage
/// instead, which is where a decision is actually taken on this state.
fn recover<T>(poisoned: std::sync::PoisonError<T>) -> T {
    poisoned.into_inner()
}

impl AsyncAdmissionSource for InMemoryAdmissionSource {
    fn current<'a>(
        &'a self,
        admission_id: &'a str,
    ) -> AdmissionFuture<'a, Option<AuthoritativeAdmission>> {
        Box::pin(async move {
            // Class R: a poisoned lock is runtime state, reported through the outage the
            // caller already handles.
            if *self.unavailable.lock().map_err(poisoned)? {
                return Err(AdmissionSourceError::Unavailable {
                    details: "in-memory source marked unavailable".to_owned(),
                });
            }
            Ok(self
                .records
                .lock()
                .map_err(poisoned)?
                .get(admission_id)
                .cloned())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block_on<F: Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
            .block_on(f)
    }

    #[test]
    fn an_unknown_workload_is_a_definitive_negative_not_an_outage() {
        let source = InMemoryAdmissionSource::new();
        assert!(matches!(block_on(source.current("nobody")), Ok(None)));
    }

    #[test]
    fn an_outage_is_distinguishable_from_an_unknown_workload() {
        let source = InMemoryAdmissionSource::new();
        source.admit("workload-7", 5);
        source.set_unavailable(true);
        assert!(matches!(
            block_on(source.current("workload-7")),
            Err(AdmissionSourceError::Unavailable { .. })
        ));
    }

    #[test]
    fn revoking_keeps_the_generation_and_changes_the_status() {
        // The generation is the anti-rollback counter, not a revocation signal: a
        // revoked record that also advanced the generation would be refused for the
        // wrong reason, and an auditor could not tell a revocation from a rotation.
        let source = InMemoryAdmissionSource::new();
        source.admit("workload-7", 5);
        source.revoke("workload-7");
        let state = block_on(source.current("workload-7"))
            .expect("reachable")
            .expect("record");
        assert_eq!(state.generation(), 5);
        assert_eq!(state.status(), AdmissionStatus::Revoked);
    }

    #[test]
    fn a_key_is_readable_by_an_operator() {
        assert_eq!(admission_key("workload-7"), "mcp-re:admission:workload-7");
    }
}
