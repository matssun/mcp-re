// SPDX-License-Identifier: Apache-2.0
//! Hot-path delegated response signing for the async serving fleet
//! (ADR-MCPRE-052 §4/§6, ADR-MCPRE-051 §5, MCPRE-122).
//!
//! Splits the delegated-signing responsibilities across the hot/cold boundary:
//!
//! - [`DelegatedServerSigner`] is the **hot-path** half the per-core fleet shares
//!   (`Send + Sync`, generic-free). It holds only an atomically-swappable snapshot
//!   of the current delegated key + its root-signed credential. Signing a response
//!   reads the snapshot and produces an in-memory Ed25519 signature — it never
//!   touches the root and never blocks. Past the credential's `exp` it yields
//!   nothing, so the caller fails closed (ADR-MCPRE-052 §6).
//!
//! - [`DelegatedRotor`] is the **cold-path** half a single owner drives (a
//!   background thread in production; a test directly). It owns the
//!   [`DelegatedSigningCustody`] state machine — where the root issuer (KMS/HSM in
//!   production) is invoked at issuance/rotation only — and republishes the fresh
//!   snapshot after each rotation. Fail-closed issuance retires the snapshot.
//!
//! The root issuer is never on the request path: the fleet reads snapshots, the
//! rotor mints them. This is the load-bearing property of ADR-MCPRE-051 §5.

use std::sync::atomic::AtomicI64;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;

use mcp_re_http_profile::ActiveDelegatedKey;
use mcp_re_http_profile::CustodyError;
use mcp_re_http_profile::DelegatedSigningCustody;
use mcp_re_http_profile::KeyLifecycleEvent;
use mcp_re_core::SigningKey;
use mcp_re_http_profile::DelegationClaims;
use mcp_re_http_profile::DelegationHeader;

/// Cold-path rotation observability (ADR-MCPRE-052 §6, MCPRE-122). Plain atomic
/// counters the single rotor owner writes and any observer (a logging line today, a
/// metrics exporter later) reads without locking. NONE of these touch the hot signing
/// path — they describe the rotor's health, not per-request work.
///
/// `time-to-expiry` is intentionally NOT stored here: it is a function of the live
/// snapshot and `now`, so it is computed on demand from
/// [`DelegatedServerSigner::seconds_to_expiry`] rather than cached and left to go stale.
#[derive(Debug, Default)]
pub struct DelegatedRotationMetrics {
    /// Total successful issue/rotate cycles.
    rotations_ok: AtomicU64,
    /// Total failed rotation attempts (root issuer unavailable at attempt time).
    rotation_failures: AtomicU64,
    /// Failures since the last success — the exponential-backoff attempt counter. Reset
    /// to 0 on any success. A non-zero value means the rotor is retrying issuance.
    consecutive_failures: AtomicU64,
    /// Unix seconds of the last successful rotation (0 before the first).
    last_success_unix: AtomicI64,
}

impl DelegatedRotationMetrics {
    /// Record a successful rotation at `now`: bump the success counter, reset the
    /// consecutive-failure streak, and stamp the success time.
    pub fn record_success(&self, now: i64) {
        self.rotations_ok.fetch_add(1, Ordering::Relaxed);
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.last_success_unix.store(now, Ordering::Relaxed);
    }

    /// Record a failed rotation attempt and return the new consecutive-failure count
    /// (≥ 1) that drives the backoff schedule.
    pub fn record_failure(&self) -> u32 {
        self.rotation_failures.fetch_add(1, Ordering::Relaxed);
        let prev = self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
        (prev + 1).min(u32::MAX as u64) as u32
    }

    /// Total successful rotations.
    pub fn rotations_ok(&self) -> u64 {
        self.rotations_ok.load(Ordering::Relaxed)
    }

    /// Total failed rotation attempts.
    pub fn rotation_failures(&self) -> u64 {
        self.rotation_failures.load(Ordering::Relaxed)
    }

    /// Failures since the last success (0 in steady state).
    pub fn consecutive_failures(&self) -> u64 {
        self.consecutive_failures.load(Ordering::Relaxed)
    }

    /// Unix seconds of the last successful rotation (0 before the first).
    pub fn last_success_unix(&self) -> i64 {
        self.last_success_unix.load(Ordering::Relaxed)
    }
}

/// The exponential-backoff base and ceiling for delegated-key issuance retries.
const ROTATION_BACKOFF_BASE_MS: u64 = 250;
const ROTATION_BACKOFF_MAX_MS: u64 = 30_000;
const ROTATION_BACKOFF_MIN_MS: u64 = 50;

/// The bounded, jittered exponential backoff for a failed delegated-key rotation
/// (ADR-MCPRE-052 §6 follow-up, MCPRE-122). PURE and deterministic given its inputs, so
/// the schedule is unit-tested without threads or a clock.
///
/// - Exponential in `consecutive_failures` (1-indexed): `250ms · 2^(n-1)`, ceilinged at
///   30s so a long root outage retries at a steady cadence rather than hot-spinning.
/// - Capped by the CURRENT key's remaining validity while it is still valid
///   (`seconds_to_expiry > 0`): the rotor keeps retrying INSIDE the overlap window and
///   never sleeps past `exp` on the first failures, so a transient root blip is caught
///   before the key expires. Once expired (`None`/`<= 0`), only the 30s ceiling applies
///   — serving is already failing closed and resumes as soon as issuance recovers.
/// - "Equal jitter": the final sleep is uniformly in `[cap/2, cap]`, decorrelating a
///   fleet of rotors so they do not stampede the root issuer in lockstep. `jitter` is a
///   caller-supplied random u64 (OS CSPRNG in production).
pub fn rotation_backoff(
    consecutive_failures: u32,
    seconds_to_expiry: Option<i64>,
    jitter: u64,
) -> Duration {
    // Exponential term, shift-capped at 2^20 to avoid overflow on a pathological streak.
    let shift = consecutive_failures.saturating_sub(1).min(20);
    let raw_ms = ROTATION_BACKOFF_BASE_MS.saturating_mul(1u64 << shift);
    let mut cap_ms = raw_ms.min(ROTATION_BACKOFF_MAX_MS);

    // While the current key is still valid, do not sleep past its expiry.
    if let Some(ttl) = seconds_to_expiry {
        if ttl > 0 {
            let ttl_ms = (ttl as u64).saturating_mul(1000);
            cap_ms = cap_ms.min(ttl_ms);
        }
    }
    cap_ms = cap_ms.max(ROTATION_BACKOFF_MIN_MS);

    // Equal jitter: half the cap, plus a uniform sample of the other half → [cap/2, cap].
    let half = cap_ms / 2;
    let jittered = half + jitter % (half + 1);
    Duration::from_millis(jittered)
}

/// The shared hot-path signer: an atomically-swappable delegated-key snapshot.
///
/// One instance is shared across every per-core runtime. `sign`-side callers read
/// [`current`](Self::current); the rotor writes via [`publish`](Self::publish) /
/// [`retire`](Self::retire). The `RwLock` is read-mostly — a brief write only at
/// rotation — so per-request reads are uncontended in steady state.
#[derive(Default)]
pub struct DelegatedServerSigner {
    active: RwLock<Option<Arc<ActiveDelegatedKey>>>,
    metrics: DelegatedRotationMetrics,
}

impl DelegatedServerSigner {
    /// A signer with no key yet — every [`current`](Self::current) fails closed
    /// until the rotor publishes the first key.
    pub fn new() -> Self {
        DelegatedServerSigner {
            active: RwLock::new(None),
            metrics: DelegatedRotationMetrics::default(),
        }
    }

    /// The cold-path rotation metrics (rotor health; never the hot path).
    pub fn metrics(&self) -> &DelegatedRotationMetrics {
        &self.metrics
    }

    /// Seconds until the current key's `exp` at `now` (`None` if no key is published).
    /// May be negative in the fail-closed window between `exp` and the next successful
    /// rotation — the caller treats `<= 0` as "already failing closed".
    pub fn seconds_to_expiry(&self, now: i64) -> Option<i64> {
        let guard = self.active.read().expect("delegated signer lock (read)");
        guard.as_ref().map(|a| a.exp - now)
    }

    /// Publish a freshly-issued/rotated delegated key snapshot for the hot path.
    pub fn publish(&self, active: ActiveDelegatedKey) {
        *self.active.write().expect("delegated signer lock (write)") = Some(Arc::new(active));
    }

    /// Retire the current snapshot — the hot path then fails closed until a new key
    /// is published. Used on fail-closed issuance (ADR-MCPRE-052 §6).
    pub fn retire(&self) {
        *self.active.write().expect("delegated signer lock (write)") = None;
    }

    /// The current delegated key snapshot IFF it is still valid at `now`. Returns
    /// `None` before the first issuance, after retirement, or once `now >= exp` —
    /// the fail-closed expiry bound (the credential is never honored past its
    /// window, matching the verifier, ADR-MCPRE-052 §6).
    pub fn current(&self, now: i64) -> Option<Arc<ActiveDelegatedKey>> {
        let guard = self.active.read().expect("delegated signer lock (read)");
        match guard.as_ref() {
            Some(a) if now < a.exp => Some(Arc::clone(a)),
            _ => None,
        }
    }
}

/// The cold-path rotation driver: owns the custody state machine and republishes
/// snapshots into a shared [`DelegatedServerSigner`]. A single owner drives it
/// (never the hot path), so the root issuer's blocking KMS/HSM calls stay off the
/// per-core runtimes.
pub struct DelegatedRotor<Issue, Factory> {
    custody: DelegatedSigningCustody<Issue, Factory>,
    signer: Arc<DelegatedServerSigner>,
}

impl<Issue, Factory> DelegatedRotor<Issue, Factory>
where
    Issue: FnMut(&DelegationHeader, &DelegationClaims) -> Option<String>,
    Factory: FnMut() -> SigningKey,
{
    /// Bind a custody state machine to the shared hot-path signer.
    pub fn new(
        custody: DelegatedSigningCustody<Issue, Factory>,
        signer: Arc<DelegatedServerSigner>,
    ) -> Self {
        DelegatedRotor { custody, signer }
    }

    /// Issue or rotate the delegated key as of `now`, then publish the fresh
    /// snapshot for the hot path. On fail-closed issuance (the root cannot issue and
    /// the current key has expired) the snapshot is retired so the hot path fails
    /// closed. Call this proactively inside the rotation-overlap window so a
    /// successor is ready before the predecessor expires (no signing gap).
    pub fn rotate(&mut self, now: i64) -> Result<(), CustodyError> {
        match self.custody.ensure_active(now) {
            Ok(()) => {
                let snapshot = self
                    .custody
                    .active_snapshot()
                    .expect("ensure_active guarantees an active key");
                self.signer.publish(snapshot);
                Ok(())
            }
            Err(e) => {
                self.signer.retire();
                Err(e)
            }
        }
    }

    /// The audited key-lifecycle events so far (issue / rotate / retire).
    pub fn audit(&self) -> &[KeyLifecycleEvent] {
        self.custody.audit()
    }

    /// How many times the ROOT issuer has been invoked (issuance + rotation only) —
    /// never incremented by the hot-path signing that reads published snapshots.
    pub fn root_invocations(&self) -> u64 {
        self.custody.root_invocations()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_re_http_profile::issue_delegation_credential;
    use mcp_re_http_profile::CustodyConfig;
    use mcp_re_http_profile::PROFILE_TAG;

    const ROOT_KID: &str = "root-kid";
    const T: i64 = 300;
    const O: i64 = 60;
    const NOW: i64 = 1_700_000_100;

    fn cfg() -> CustodyConfig {
        CustodyConfig {
            issuer_kid: ROOT_KID.into(),
            iss: "did:example:server".into(),
            profile: PROFILE_TAG.into(),
            aud: "verifier-1".into(),
            audience_hash: "aud-scope-1".into(),
            trust_epoch: "epoch-1".into(),
            server_role: "server".into(),
            server_trust_domain: "example.com".into(),
            server_subject: "did:example:server".into(),
            ttl: T,
            overlap: O,
        }
    }

    fn rotor() -> (DelegatedRotor<impl FnMut(&DelegationHeader, &DelegationClaims) -> Option<String>, impl FnMut() -> SigningKey>, Arc<DelegatedServerSigner>) {
        let root = SigningKey::from_seed_bytes(&[33u8; 32]);
        let issue = move |h: &DelegationHeader, c: &DelegationClaims| {
            Some(issue_delegation_credential(&root, h, c))
        };
        let mut n = 100u8;
        let factory = move || {
            n = n.wrapping_add(1);
            SigningKey::from_seed_bytes(&[n; 32])
        };
        let signer = Arc::new(DelegatedServerSigner::new());
        let custody = DelegatedSigningCustody::new(cfg(), issue, factory);
        (DelegatedRotor::new(custody, Arc::clone(&signer)), signer)
    }

    #[test]
    fn no_key_before_first_rotate_fails_closed() {
        let signer = DelegatedServerSigner::new();
        assert!(signer.current(NOW).is_none());
    }

    #[test]
    fn rotate_publishes_a_snapshot_the_hot_path_reads() {
        let (mut rotor, signer) = rotor();
        rotor.rotate(NOW).expect("issue");
        let snap = signer.current(NOW).expect("a key is published");
        assert_eq!(snap.delegated_kid, format!("{ROOT_KID}/delegated/1"));
        assert_eq!(rotor.root_invocations(), 1);
    }

    #[test]
    fn snapshot_fails_closed_past_expiry() {
        let (mut rotor, signer) = rotor();
        rotor.rotate(NOW).expect("issue");
        // At exp the snapshot is no longer honored (fail-closed bound).
        assert!(signer.current(NOW + T).is_none());
        assert!(signer.current(NOW + T - 1).is_some());
    }

    #[test]
    fn fail_closed_issuance_retires_the_snapshot() {
        // An issuer that always fails, with no prior key: rotate must retire.
        let issue = |_: &DelegationHeader, _: &DelegationClaims| None;
        let factory = || SigningKey::from_seed_bytes(&[7u8; 32]);
        let signer = Arc::new(DelegatedServerSigner::new());
        let custody = DelegatedSigningCustody::new(cfg(), issue, factory);
        let mut rotor = DelegatedRotor::new(custody, Arc::clone(&signer));
        assert_eq!(rotor.rotate(NOW), Err(CustodyError::FailClosedIssuance));
        assert!(signer.current(NOW).is_none());
    }

    #[test]
    fn seconds_to_expiry_tracks_the_published_key() {
        let (mut rotor, signer) = rotor();
        assert_eq!(signer.seconds_to_expiry(NOW), None, "no key ⇒ no ttl");
        rotor.rotate(NOW).expect("issue");
        assert_eq!(signer.seconds_to_expiry(NOW), Some(T));
        // Past exp the ttl goes negative (fail-closed window), unlike `current`.
        assert_eq!(signer.seconds_to_expiry(NOW + T + 5), Some(-5));
        assert!(signer.current(NOW + T + 5).is_none());
    }

    #[test]
    fn metrics_count_success_and_reset_the_failure_streak() {
        let m = DelegatedRotationMetrics::default();
        assert_eq!(m.record_failure(), 1);
        assert_eq!(m.record_failure(), 2);
        assert_eq!(m.consecutive_failures(), 2);
        assert_eq!(m.rotation_failures(), 2);
        m.record_success(NOW);
        assert_eq!(m.consecutive_failures(), 0, "success resets the streak");
        assert_eq!(m.rotations_ok(), 1);
        assert_eq!(m.last_success_unix(), NOW);
        // The failure total is cumulative — a later failure resumes the streak at 1.
        assert_eq!(m.record_failure(), 1);
        assert_eq!(m.rotation_failures(), 3);
    }

    /// The jittered result must always land in the equal-jitter band `[cap/2, cap]`.
    fn assert_in_band(consecutive: u32, ttl: Option<i64>, expected_cap_ms: u64) {
        for jitter in [0u64, 1, 7, 12_345, u64::MAX / 2, u64::MAX] {
            let d = rotation_backoff(consecutive, ttl, jitter).as_millis() as u64;
            assert!(
                d >= expected_cap_ms / 2 && d <= expected_cap_ms,
                "consec={consecutive} ttl={ttl:?} jitter={jitter}: {d}ms not in [{}, {}]",
                expected_cap_ms / 2,
                expected_cap_ms
            );
        }
    }

    #[test]
    fn backoff_is_exponential_then_ceilinged() {
        // Plenty of key life left ⇒ ttl does not cap; pure exponential up to 30s.
        assert_in_band(1, Some(300), 250); // 250 · 2^0
        assert_in_band(2, Some(300), 500); // 250 · 2^1
        assert_in_band(3, Some(300), 1_000); // 250 · 2^2
        assert_in_band(8, Some(300), 30_000); // 250·2^7 = 32s → ceilinged to 30s
        assert_in_band(50, None, 30_000); // pathological streak, still ceilinged
    }

    #[test]
    fn backoff_never_sleeps_past_a_still_valid_key() {
        // A large exponential term is capped to the key's remaining validity so a retry
        // still lands inside the overlap window before exp.
        assert_in_band(10, Some(1), 1_000); // ttl 1s dominates the 30s exponential
        assert_in_band(6, Some(2), 2_000); // ttl 2s < 250·2^5 = 8s
    }

    #[test]
    fn backoff_once_expired_uses_the_ceiling_not_the_negative_ttl() {
        // A negative/None ttl (already failing closed) must not shrink the backoff to
        // zero — the ceiling governs so issuance keeps retrying at a steady cadence.
        assert_in_band(50, Some(-120), 30_000);
        assert_in_band(50, None, 30_000);
    }
}
