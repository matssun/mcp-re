// SPDX-License-Identifier: Apache-2.0
//! What a dead trust reloader means, and the fail-closed action it becomes.
//!
//! One fact: **a trust snapshot nothing is re-reading must stop answering.** Separable from
//! the loop beside it, and the separation is the point — the loop decides what one re-read
//! does and how many failures are absorbed, and this decides what the ABSENCE of every
//! future re-read means.
//!
//! The two differ in what may undo them. Exhausting the failure budget is recoverable, and
//! the next successful read is the recovery it exists to allow; a panicked body is not, and
//! no later reload may report the store current again.

use std::sync::Arc;

use super::super::freshness::TrustStoreFreshness;

/// The `catch_unwind` and the fail-closed action it converts a panic into, AS A VALUE.
///
/// Taking the body rather than writing it inline is what makes the supervisor reachable: a
/// test can substitute a body that panics and still run THIS function. Written inline, the
/// only way to inject a panic was to spawn through `WorkerSet` directly — which measures
/// `WorkerSet` and not the supervisor, and is precisely the trap
/// `SigningPlane::for_teardown_test` fell into while advertising "one that panics".
///
/// A pure extraction: it moves no decision, adds no type, and stays private to this module.
/// There is no second worker-lifecycle framework here — `WorkerSet` still owns the thread.
///
/// The fault is TERMINAL rather than a restart, and R2 is why. The store is reconstructible
/// by re-reading the file, so a restart could rebuild it; but an `InMemoryTrustResolver`
/// carries no expiry, so between the panic and a successful restarted read the frozen
/// snapshot keeps answering — and it still holds the revoked key. A restart would publish
/// "trust is current" across that whole window, which is the unbounded revocation window the
/// reload exists to close.
pub(super) fn supervise_trust_reload(
    freshness: Arc<TrustStoreFreshness>,
    body: impl FnOnce() + Send + 'static,
) -> impl FnOnce() + Send + 'static {
    move || {
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)).is_ok() {
            return;
        }
        freshness.mark_stale_permanently();
        eprintln!(
            "mcp-re-proxy: FATAL: the trust store reload thread PANICKED. --trust is no \
             longer being re-read, so a key revoked in it would keep resolving from the \
             frozen snapshot; request verification now fails closed \
             (trust_resolver_unavailable) rather than serving a store that cannot change. \
             This replica cannot recover on its own — restart it."
        );
    }
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::*;
    use mcp_re_core::TrustResolver;

    const SIGNER: &str = "did:example:client";

    /// T1. A panic inside the reload body makes the RESOLVER refuse — not a flag change.
    ///
    /// The supervisor is run as the production code runs it, with only the body replaced.
    /// Before the extraction the only way to inject a panic was to spawn through
    /// `WorkerSet` directly, which measures `WorkerSet`; deleting the whole supervisor left
    /// every test in the workspace green (R11-726).
    ///
    /// What is asserted is `StaleFailsClosed::resolve`, which is what a request meets. The
    /// flag and the surface agreeing is ONE claim, and only the surface is the deployment's
    /// answer — a supervisor that set a flag nobody read would satisfy the flag assertion
    /// and change nothing about what is served.
    #[test]
    fn a_panicking_trust_reload_thread_makes_the_resolver_refuse() {
        let freshness = Arc::new(TrustStoreFreshness::default());
        freshness.mark_fresh();
        let resolver = crate::trust_plane::freshness::StaleFailsClosed {
            inner: Arc::new(mcp_re_core::InMemoryTrustResolver::new()),
            freshness: Arc::clone(&freshness),
        };
        assert!(
            !matches!(
                resolver.resolve(SIGNER, "kid-1"),
                Err(mcp_re_core::TrustResolverError::Unavailable { .. })
            ),
            "a maintained store answers about the key, not about itself"
        );

        // The panic is this test's INPUT, so the hook is quieted for the duration.
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let supervised = supervise_trust_reload(Arc::clone(&freshness), || {
            panic!("injected: the reload body died");
        });
        let thread = std::thread::spawn(supervised);
        let joined = thread.join();
        std::panic::set_hook(hook);

        assert!(
            joined.is_ok(),
            "the supervisor converts the panic; it does not propagate it"
        );
        assert!(
            matches!(
                resolver.resolve(SIGNER, "kid-1"),
                Err(mcp_re_core::TrustResolverError::Unavailable { .. })
            ),
            "nothing re-reads --trust after the body died, so the frozen snapshot — which \
             still holds whatever the operator revoked — must stop answering"
        );

        freshness.mark_fresh();
        assert!(
            matches!(
                resolver.resolve(SIGNER, "kid-1"),
                Err(mcp_re_core::TrustResolverError::Unavailable { .. })
            ),
            "terminal: there is no reload left to recover it, so a later success must not \
             report the store current"
        );
    }
}
