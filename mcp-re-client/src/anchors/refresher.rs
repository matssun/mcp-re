// SPDX-License-Identifier: Apache-2.0
//! The BACKGROUND REFRESH of the anchors in force, and what each attempt is allowed to do
//! to them.
//!
//! Separate from the loader next door because the two answer different questions. The
//! loader decides whether a manifest may be believed; this decides what happens to the
//! anchors already serving when one cannot be. Three outcomes and no others: a newer
//! manifest is PUBLISHED, a failure KEEPS the last good set in force, and an expiry with no
//! successor WITHDRAWS every anchor so that every response fails closed.
//!
//! The thread naps in short ticks rather than sleeping the whole interval, so a shutdown is
//! observed within one tick instead of after a full refresh cadence.

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use mcp_re_client_core::TrustedIssuerSet;
use mcp_re_client_proxy::AnchorSnapshot;

use super::AnchorLoader;

/// Re-reads the manifest on a fixed cadence and publishes accepted anchors into the
/// snapshot the routes verify against.
pub struct AnchorRefresher {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

/// What a refresh cycle did, so a caller (or a test) can assert on it without waiting
/// on a thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// A newer manifest was accepted and published.
    Published { version: u64 },
    /// The document on disk was refused; the anchors already in force are kept. A
    /// manifest at or below the floor lands here, which is the rollback being denied.
    KeptLastGood { reason: String },
    /// The manifest in force has expired and no newer one was accepted, so the anchors
    /// were WITHDRAWN. Every response now fails closed until a refresh succeeds.
    Withdrawn { expired_at: i64 },
}

/// Run one refresh cycle against `snapshot`.
///
/// `manifest_expires_at` is the expiry of the document currently in force; it is
/// updated in place when a newer one is accepted, so an expired-and-then-repaired
/// manifest restores service without a restart.
pub fn refresh_once(
    loader: &mut AnchorLoader,
    snapshot: &AnchorSnapshot,
    manifest_expires_at: &mut i64,
    now: i64,
) -> RefreshOutcome {
    match loader.load(now) {
        Ok(loaded) => {
            *manifest_expires_at = loaded.expires_at;
            snapshot.store(loaded.issuers);
            RefreshOutcome::Published {
                version: loaded.version,
            }
        }
        Err(error) => {
            if now >= *manifest_expires_at {
                // Holding these anchors would be using the stale trust picture the
                // expiry check exists to refuse. Withdraw rather than serve on it.
                snapshot.store(TrustedIssuerSet::new());
                RefreshOutcome::Withdrawn {
                    expired_at: *manifest_expires_at,
                }
            } else {
                RefreshOutcome::KeptLastGood {
                    reason: error.to_string(),
                }
            }
        }
    }
}

impl AnchorRefresher {
    /// Class A: the one assertion is the thread spawn, and it runs at startup on the main
    /// thread before a single local call is served, so failing IS the refusal to start.
    /// Without this thread the anchors are never refreshed and never withdrawn, and the
    /// client runs indefinitely against a manifest that has stopped being maintained.
    #[allow(clippy::expect_used)]
    /// Start refreshing `snapshot` every `interval`, beginning one interval from now.
    ///
    /// The caller has already performed the startup load, so the first cycle here is a
    /// re-read, not the initial one — a client never serves against anchors no refresh
    /// has produced.
    pub fn start(
        mut loader: AnchorLoader,
        snapshot: Arc<AnchorSnapshot>,
        mut manifest_expires_at: i64,
        interval: Duration,
        clock: impl Fn() -> i64 + Send + 'static,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        let handle = std::thread::Builder::new()
            .name("mcp-re-anchor-refresh".to_owned())
            .spawn(move || {
                // Wake on a short tick rather than sleeping the whole interval, so a
                // shutdown is not held up by a long refresh cadence.
                let tick = Duration::from_millis(200).min(interval);
                let mut waited = Duration::ZERO;
                while !stop_thread.load(Ordering::Relaxed) {
                    std::thread::sleep(tick);
                    // Saturating: compared against `interval` and reset on every refresh,
                    // so the far end means the interval elapsed where wrapping would
                    // restart the cadence and stall the anchor refresh.
                    waited = waited.saturating_add(tick);
                    if waited < interval {
                        continue;
                    }
                    waited = Duration::ZERO;
                    match refresh_once(&mut loader, &snapshot, &mut manifest_expires_at, clock()) {
                        RefreshOutcome::Published { version } => {
                            eprintln!("trust-anchor manifest v{version} accepted");
                        }
                        RefreshOutcome::KeptLastGood { reason } => {
                            eprintln!(
                                "trust-anchor refresh failed, keeping the anchors in force: \
                                 {reason}"
                            );
                        }
                        RefreshOutcome::Withdrawn { expired_at } => {
                            eprintln!(
                                "trust-anchor manifest expired at {expired_at} and no newer one \
                                 loaded — ANCHORS WITHDRAWN, every response now fails closed"
                            );
                        }
                    }
                }
            })
            // See the note on this function: the assertion IS the refusal to start.
            .expect("the anchor-refresh thread starts before any call is served");
        AnchorRefresher {
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for AnchorRefresher {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}
