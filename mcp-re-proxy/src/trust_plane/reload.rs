// SPDX-License-Identifier: Apache-2.0
//! Keeping `--trust` re-read, and the bounded budget that stops the plane pretending it is.
//!
//! One fact: **a revocation mechanism that needs a restart is not one an operator can use
//! during an incident** — so the trust snapshot is re-read on a cadence and swapped
//! atomically, and the swap is the only way a key removed from the file stops resolving.
//!
//! # The tolerance is bounded, and that is the whole design
//!
//! A FAILED read keeps the last-good store, because a truncated file caught mid-write must
//! not empty the trust map — an empty map rejects every request and would turn an editor's
//! save into a fleet-wide outage.
//!
//! But *keep last-good* with no bound restores exactly the unbounded revocation window the
//! reload exists to close: an `InMemoryTrustResolver` carries no expiry, so nothing makes a
//! frozen snapshot stop being honoured on its own, and the replica keeps honouring a
//! removed key indefinitely while its startup line promises a one-cadence window. After
//! [`TRUST_RELOAD_FAILURE_BUDGET`] consecutive failures the resolver fails closed instead.
//! Five is far longer than a ConfigMap remount or an editor's save, and short enough that
//! an incident-time revocation is not silently ignored.
//!
//! # Supervised, for the same reason as the rotation owner
//!
//! Nothing joins this thread. A panic — a poisoned lock, a closed stderr — would otherwise
//! end reloading for the process lifetime while every surface still read healthy, which is
//! the same shape as a frozen store and must reach the same fail-closed outcome.

use std::sync::Arc;
use std::time::Duration;

use super::freshness::TrustStoreFreshness;
use super::snapshot::read_trust_file;

/// How many consecutive failed `--trust` re-reads are absorbed before the resolver
/// fails closed.
///
/// Keeping the last-good store across a blip is deliberate: a truncated file caught
/// mid-write must not empty the trust map. But "keep last-good" with no bound restores
/// exactly the unbounded revocation window the reload exists to close — the replica
/// keeps honouring a key the operator removed, indefinitely, while its startup line
/// promises a one-cadence window. Five consecutive failures is far longer than a
/// ConfigMap remount or an editor's save and short enough that an incident-time
/// revocation is not silently ignored.
const TRUST_RELOAD_FAILURE_BUDGET: u32 = 5;
/// Re-read `--trust` on a cadence and swap the snapshot atomically.
///
/// The same shape as [`spawn_crl_reload_task`], and for the same reason: a
/// revocation mechanism that needs a restart is not one an operator can use during an
/// incident. A FAILED read keeps the last-good store — a truncated file caught
/// mid-write must not empty the trust map, because an empty map rejects every request
/// and would turn an editor's save into a fleet-wide outage.
///
/// That tolerance is BOUNDED. Unlike a CRL, an `InMemoryTrustResolver` carries no
/// expiry, so nothing makes a frozen snapshot stop being honoured on its own; after
/// [`TRUST_RELOAD_FAILURE_BUDGET`] consecutive failures the resolver fails closed
/// instead. SUPERVISED for the same reason as the rotation owner: nothing joins this
/// thread, so a panic (a poisoned lock, a closed stderr) would otherwise end reloading
/// for the process lifetime while every surface still read healthy.
pub(super) fn spawn_trust_reload_task(
    workers: &mut crate::managed_worker::WorkerSet,
    store: Arc<crate::reloading_trust::ReloadingTrustStore>,
    trust_path: String,
    response_kid: String,
    interval_secs: u64,
    freshness: Arc<TrustStoreFreshness>,
) {
    let halt = workers.halt();
    workers.spawn("trust store reload", move || {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            trust_reload_loop(
                &store,
                &trust_path,
                &response_kid,
                interval_secs,
                &freshness,
                &halt,
            );
        }));
        if outcome.is_err() {
            freshness.mark_stale_permanently();
            eprintln!(
                "mcp-re-proxy: FATAL: the trust store reload thread PANICKED. --trust is no \
                 longer being re-read, so a key revoked in it would keep resolving from the \
                 frozen snapshot; request verification now fails closed \
                 (trust_resolver_unavailable) rather than serving a store that cannot change. \
                 This replica cannot recover on its own — restart it."
            );
        }
    });
}
/// The reload loop proper. Split out so the supervisor above can catch a panic from
/// anywhere inside it.
fn trust_reload_loop(
    store: &crate::reloading_trust::ReloadingTrustStore,
    trust_path: &str,
    response_kid: &str,
    interval_secs: u64,
    freshness: &TrustStoreFreshness,
    halt: &crate::managed_worker::Halt,
) {
    let mut consecutive_failures: u32 = 0;
    loop {
        // Naps in small increments, so a halt is observed within one increment rather
        // than after a whole reload interval.
        if halt.sleep(Duration::from_secs(interval_secs)) {
            // Past this return nothing re-reads `--trust` on this replica while the
            // process keeps serving, so the snapshot's revocation window is unbounded.
            // PERMANENTLY, because there is no reload left to recover it. `Halt`
            // collapses its two sources on purpose — a worker never asks why it is
            // stopping — and the security consequence is identical either way, so
            // failing closed with `trust_resolver_unavailable` is the correct side of
            // the trade for a drain as well as for a retirement.
            freshness.mark_stale_permanently();
            return;
        }
        consecutive_failures = trust_reload_cycle(
            store,
            trust_path,
            response_kid,
            freshness,
            consecutive_failures,
        );
    }
}
/// One re-read of `--trust`: swap the snapshot, or absorb the failure against the budget.
///
/// Takes and returns the running count of CONSECUTIVE failures, so the budget the
/// fail-closed hangs off is a value the caller carries rather than state reachable only
/// from inside a loop that never returns.
fn trust_reload_cycle(
    store: &crate::reloading_trust::ReloadingTrustStore,
    trust_path: &str,
    response_kid: &str,
    freshness: &TrustStoreFreshness,
    consecutive_failures: u32,
) -> u32 {
    match read_trust_file(trust_path, response_kid) {
        Ok((resolver, signers)) => {
            let enrolled = signers.len();
            let recovered = consecutive_failures > 0;
            store.store(resolver, signers);
            freshness.mark_fresh();
            if recovered {
                eprintln!(
                    "mcp-re-proxy: trust store reload RECOVERED; {enrolled} request-signer \
                     key(s) live, verification is serving again"
                );
            } else {
                eprintln!(
                    "mcp-re-proxy: trust store reloaded; {enrolled} request-signer key(s) live"
                );
            }
            0
        }
        Err(reason) => {
            let consecutive_failures = consecutive_failures.saturating_add(1);
            if consecutive_failures >= TRUST_RELOAD_FAILURE_BUDGET {
                freshness.mark_stale();
                eprintln!(
                    "mcp-re-proxy: trust store reload FAILED {consecutive_failures}x in a row \
                     ({reason}); the snapshot is now too old to carry the declared revocation \
                     window, so request verification FAILS CLOSED \
                     (trust_resolver_unavailable) until a reload succeeds. Fix the --trust \
                     mount at {trust_path}."
                );
            } else {
                eprintln!(
                    "mcp-re-proxy: WARNING: trust store reload FAILED \
                     ({consecutive_failures}/{TRUST_RELOAD_FAILURE_BUDGET}), keeping last-good \
                     store: {reason}. The last-good store still holds every key present at the \
                     last successful read, including any the operator has removed since, and it \
                     keeps resolving them for up to {TRUST_RELOAD_FAILURE_BUDGET} cadences on \
                     top of the declared window; at {TRUST_RELOAD_FAILURE_BUDGET} consecutive \
                     failures verification fails closed."
                );
            }
            consecutive_failures
        }
    }
}
/// The reload loop itself: what a halt does to the store, what a cycle does to the
/// snapshot, and how much exposure the failure budget buys before it fails closed.
///
/// These drive `trust_reload_loop`/`trust_reload_cycle` rather than the freshness flag,
/// because every other test in this module hand-drives the flag — which proves the resolver
/// honours it and nothing about whether anything sets it.
#[cfg(test)]
mod reload_loop_tests {
    use super::*;
    use crate::managed_worker::WorkerSet;
    use crate::revocation_tier::RevocationTier;
    use crate::trust_plane::delivered_window::delivered_revocation_window;
    use crate::trust_plane::snapshot::load_trust_snapshot;
    use mcp_re_core::TrustResolver;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;

    const SIGNER: &str = "did:example:client";

    /// A trust file enrolling exactly `key_id`, at a path unique to this test.
    fn trust_file(tag: &str, key_id: &str) -> std::path::PathBuf {
        let key = mcp_re_core::SigningKey::from_seed_bytes(&[7u8; 32]).public_key();
        let path = std::env::temp_dir().join(format!(
            "mcp_re_trust_reload_{tag}_{}.json",
            std::process::id()
        ));
        std::fs::write(
            &path,
            format!(
                r#"[{{"signer":"{SIGNER}","key_id":"{key_id}","public_key":"{}"}}]"#,
                key.to_b64url()
            ),
        )
        .expect("write trust file");
        path
    }

    fn empty_store() -> crate::reloading_trust::ReloadingTrustStore {
        crate::reloading_trust::ReloadingTrustStore::new(
            mcp_re_core::InMemoryTrustResolver::new(),
            std::collections::HashMap::new(),
        )
    }

    /// A clean stop on the DEPLOYMENT's shutdown flag freezes the store, and a frozen store
    /// must not keep answering.
    ///
    /// `Halt` collapses its two sources on purpose — the worker never asks why it is
    /// stopping — so the only place the consequence can be applied is the loop's own halt
    /// exit. During a graceful drain the process keeps serving after this returns, and
    /// `TrustStoreFreshness` is a plain latch rather than a time bound, so nothing else
    /// would ever notice that `--trust` had stopped being re-read.
    #[test]
    fn a_halted_reloader_marks_the_trust_store_stale() {
        let deployment = Arc::new(AtomicBool::new(false));
        let workers = WorkerSet::new(Arc::clone(&deployment));
        let halt = workers.halt();
        let freshness = TrustStoreFreshness::default();
        freshness.mark_fresh();

        // The operator's shutdown flag, with the plane still alive and still serving.
        deployment.store(true, Ordering::SeqCst);
        trust_reload_loop(
            &empty_store(),
            "/nonexistent/trust.json",
            "response-kid",
            60,
            &freshness,
            &halt,
        );

        assert!(
            freshness.is_stale(),
            "a reloader that stopped while the process keeps serving left the store \
             answering from a snapshot nothing re-reads"
        );
        freshness.mark_fresh();
        assert!(
            freshness.is_stale(),
            "the staleness must be terminal: no reload can follow a halt to recover it"
        );
    }

    /// A cycle REPLACES the map the resolver answers from, and resets the failure budget.
    #[test]
    fn a_reload_cycle_replaces_the_map_the_resolver_answers_from() {
        let path = trust_file("swap", "kid-old");
        let trust_path = path.to_string_lossy().into_owned();
        let store = load_trust_snapshot(&trust_path, "response-kid").expect("initial snapshot");
        assert!(
            store.resolve(SIGNER, "kid-old").is_ok(),
            "the enrolled key resolves before the file changes"
        );

        // The operator revokes kid-old by removing it from --trust.
        let _ = trust_file("swap", "kid-new");
        let freshness = TrustStoreFreshness::default();
        let failures = trust_reload_cycle(&store, &trust_path, "response-kid", &freshness, 3);

        let _ = std::fs::remove_file(&path);
        assert_eq!(failures, 0, "a successful read resets the failure budget");
        assert!(
            !freshness.is_stale(),
            "a successful read leaves the store fresh"
        );
        assert!(
            store.resolve(SIGNER, "kid-old").is_err(),
            "the revoked key still resolved: the reload did not replace the snapshot"
        );
        assert!(
            store.resolve(SIGNER, "kid-new").is_ok(),
            "the re-read map is the one the resolver now answers from"
        );
    }

    /// The keep-last-good tolerance is bounded, and the bound is exactly the budget.
    ///
    /// Asserted at both edges: the fourth failure must still serve — collapsing it to a
    /// fail-closed turns an editor's save into a fleet outage — and the fifth must not.
    #[test]
    fn the_failure_budget_fails_closed_on_exactly_the_fifth_consecutive_bad_read() {
        let freshness = TrustStoreFreshness::default();
        let mut failures = 0;
        for expected in 1..TRUST_RELOAD_FAILURE_BUDGET {
            failures = trust_reload_cycle(
                &empty_store(),
                "/nonexistent/trust.json",
                "response-kid",
                &freshness,
                failures,
            );
            assert_eq!(failures, expected);
            assert!(
                !freshness.is_stale(),
                "failure {expected} of {TRUST_RELOAD_FAILURE_BUDGET} must keep serving the \
                 last-good store rather than emptying the trust map"
            );
        }

        failures = trust_reload_cycle(
            &empty_store(),
            "/nonexistent/trust.json",
            "response-kid",
            &freshness,
            failures,
        );
        assert_eq!(failures, TRUST_RELOAD_FAILURE_BUDGET);
        assert!(
            freshness.is_stale(),
            "an unreadable --trust must stop verification instead of honouring a frozen \
             snapshot indefinitely"
        );
        freshness.mark_fresh();
        assert!(
            !freshness.is_stale(),
            "exhausting the budget is recoverable; only a halt or a dead thread is terminal"
        );
    }

    /// The window an operator is told is the SUM, because a reload evicts nothing the tier
    /// has already cached.
    #[test]
    fn a_caching_tier_states_the_cache_lifetime_on_top_of_the_store_cadence() {
        let line = delivered_revocation_window(
            &RevocationTier::BoundedCache { t_secs: 300 },
            crate::startup_plan::TrustReloadPlan::Every {
                secs: crate::config_state::TrustRevocationState::cadence(300),
            },
        );
        assert!(
            line.contains("600s"),
            "bounded-cache:300 with a 300s cadence delivers 600s: {line}"
        );

        let live = delivered_revocation_window(
            &RevocationTier::Live,
            crate::startup_plan::TrustReloadPlan::Every {
                secs: crate::config_state::TrustRevocationState::cadence(300),
            },
        );
        assert!(
            live.contains("300s") && !live.contains("600s"),
            "a tier with no positive cache delivers the cadence alone: {live}"
        );

        let frozen = delivered_revocation_window(
            &RevocationTier::BoundedCache { t_secs: 300 },
            crate::startup_plan::TrustReloadPlan::ReadOnceAtStartup,
        );
        assert!(
            frozen.contains("UNBOUNDED"),
            "with no cadence the store never changes: {frozen}"
        );
    }
}
