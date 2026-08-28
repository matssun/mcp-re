// SPDX-License-Identifier: Apache-2.0
//! Whether the trust store is still being MAINTAINED, and what a resolver over an
//! unmaintained one is allowed to say.
//!
//! One fact: **a trust snapshot that has stopped being refreshed must stop answering.**
//! It is a fail-closed and not a log line, which is only true because the flag is read on
//! the verification path rather than reported at the moment it is set.
//!
//! An `InMemoryTrustResolver` carries no expiry, so nothing makes a frozen snapshot stop
//! being honoured on its own. A key the operator revoked in `--trust` would keep resolving
//! from the frozen map indefinitely, while the startup line still promised a
//! one-cadence propagation window.
//!
//! # Two stalenesses, because only one of them is recoverable
//!
//! Exhausting the reload failure budget is a transient condition and a later successful
//! read is the recovery it exists to allow. The owning plane being dropped, or the reload
//! thread dying, is not: nothing will ever refresh again, and a straggler reload landing
//! afterwards must not report the store fresh. Held in one flag the difference is not
//! representable and the next successful read reverses either, which is why there are two.
//!
//! # Why the refusal is `Unavailable` and not `NotFound`
//!
//! A frozen store still HOLDS the revoked key. Answering from it is the one outcome that
//! must not happen, and reporting the outage as an unknown keyid would send the operator
//! hunting a client bug. The verifier maps `Unavailable` to
//! `mcp-re.trust_resolver_unavailable`, which is what a stale store actually is.

use std::sync::atomic::Ordering;
use std::sync::Arc;

/// Whether the trust store is still fresh enough to answer.
///
/// Set by [`spawn_trust_reload_task`] when the file has been unreadable for
/// [`TRUST_RELOAD_FAILURE_BUDGET`] consecutive cadences, or when the reload thread has
/// died. Read by the resolver wrapper below on every verification, which is what makes
/// it a real fail-closed rather than a log line.
#[derive(Debug, Default)]
pub(super) struct TrustStoreFreshness {
    stale: std::sync::atomic::AtomicBool,
    /// Set by [`mark_stale_permanently`](Self::mark_stale_permanently). Separate from
    /// `stale` because the two stalenesses differ in whether a later reload may undo
    /// them: exhausting the failure budget is recoverable, and
    /// [`mark_fresh`](Self::mark_fresh) is the recovery it exists to allow, while the
    /// owner going away or the reload thread dying is not. Held in one flag, the
    /// difference is not representable and the next successful read reverses either.
    terminal: std::sync::atomic::AtomicBool,
}
impl TrustStoreFreshness {
    pub(super) fn mark_stale(&self) {
        self.stale.store(true, Ordering::SeqCst);
    }

    /// Stale, permanently: no later reload can report this store fresh again.
    ///
    /// For the two cases the store is not meant to recover from — the owning
    /// [`TrustPlane`] being dropped, and the reload thread dying — both of which say so,
    /// and neither of which could enforce it while the flag they set was one a live
    /// reload could overwrite.
    pub(super) fn mark_stale_permanently(&self) {
        self.terminal.store(true, Ordering::SeqCst);
        self.mark_stale();
    }

    pub(super) fn mark_fresh(&self) {
        if self.terminal.load(Ordering::SeqCst) {
            return;
        }
        self.stale.store(false, Ordering::SeqCst);
    }

    pub(super) fn is_stale(&self) -> bool {
        self.terminal.load(Ordering::Relaxed) || self.stale.load(Ordering::Relaxed)
    }
}
/// The request-trust resolver, refusing to answer at all once the store behind it has
/// stopped being maintained — whether because the reload exhausted its failure budget or
/// because the owning [`TrustPlane`] retired.
///
/// `Unavailable` and not `NotFound`: a frozen store still HOLDS the revoked key, so
/// answering from it is the one outcome that must not happen, and reporting the outage
/// as an unknown keyid would send the operator hunting a client bug. The verifier maps
/// this to `mcp-re.trust_resolver_unavailable`, which is what a stale store actually is.
pub(super) struct StaleFailsClosed {
    pub(super) inner: Arc<dyn mcp_re_core::TrustResolver + Send + Sync>,
    pub(super) freshness: Arc<TrustStoreFreshness>,
}
impl mcp_re_core::TrustResolver for StaleFailsClosed {
    fn resolve(
        &self,
        signer: &str,
        key_id: &str,
    ) -> Result<mcp_re_core::VerificationKey, mcp_re_core::TrustResolverError> {
        if self.freshness.is_stale() {
            return Err(mcp_re_core::TrustResolverError::Unavailable {
                details: "nothing is maintaining the trust store: either --trust has not \
                          been re-read successfully for several cadences, or the trust \
                          plane that owned the refresh is gone. A key revoked in --trust \
                          would still resolve from the frozen snapshot, so verification \
                          fails closed"
                    .to_string(),
            });
        }
        self.inner.resolve(signer, key_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recoverable_staleness_is_undone_by_a_successful_reload() {
        // The budget case. A truncated file caught mid-write must not end trust for the
        // process lifetime — the next good read is the recovery.
        let freshness = TrustStoreFreshness::default();
        freshness.mark_stale();
        assert!(freshness.is_stale());
        freshness.mark_fresh();
        assert!(!freshness.is_stale());
    }

    #[test]
    fn a_terminal_staleness_survives_a_straggler_reporting_fresh() {
        // The case one flag could not represent. Once the owner is gone or the reload
        // thread has died, nothing will refresh again — and a reload that was already in
        // flight must not be able to reverse that on its way out.
        let freshness = TrustStoreFreshness::default();
        freshness.mark_stale_permanently();
        freshness.mark_fresh();
        assert!(
            freshness.is_stale(),
            "no later reload may report an abandoned store fresh"
        );
    }
}
