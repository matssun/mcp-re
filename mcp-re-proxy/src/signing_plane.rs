// SPDX-License-Identifier: Apache-2.0
//! The signing plane (ADR-MCPRE-056 §8; ADR-MCPRE-052): response-signing custody.
//!
//! Delegated signing is the only response mode. The ROOT key — KMS, HSM or file — is the
//! credential ISSUER and is invoked at issuance and rotation only, never on the request
//! path. This plane owns the issuer, the delegated-key snapshot the fleet signs off, and
//! the cold-path worker that keeps that snapshot current.
//!
//! # What it owns, and what leaves it
//!
//! It owns the rotation worker and, inside it, the rotor and the trust-epoch watch. What
//! leaves is one `Arc<DelegatedServerSigner>`, moved into the proxy. The root issuer never
//! leaves: nothing outside this plane can mint.
//!
//! # A surviving signer must not keep signing
//!
//! This is the same hazard `trust_plane` closes for a surviving resolver, in the signing
//! domain, and it is worth stating because the failure is silent.
//!
//! The rotation worker is the ONLY thing that mints successors, and it is also the only
//! thing that polls the shared trust epoch — the operator's cross-fleet kill switch
//! (ADR-MCPRE-052 §7). Its panic path already retires the snapshot. Its CLEAN-STOP path
//! did not, because before v0.16 a clean stop could not happen: the worker ran until the
//! process exited. `WorkerSet`'s structural halt made one reachable, and a signer that
//! outlived this plane would then go on signing off the last delegated key until its
//! `exp`, with nobody left to observe an `INCR` — a frozen signing authority whose
//! revocation channel is dead.
//!
//! So [`Drop`] retires the snapshot BEFORE halting the worker. After this plane is gone
//! the hot path fails closed (`delegated_signing_unavailable`) immediately rather than at
//! `exp`, which is the honest posture: nothing is maintaining that key any more.
//!
//! Note the asymmetry with `reloading_trust::SignerDirectory`, which deliberately keeps
//! answering from its last snapshot after its plane is gone. A directory yields an
//! identity COORDINATE and admits nothing on its own; a signer PRODUCES authority. Only
//! the first is safe to leave frozen.

use std::sync::Arc;
use std::time::Duration;

use crate::app::now_unix;
use crate::cli;
use crate::delegated_server_signer::DelegatedServerSigner;
use crate::delegated_server_signer::TrustEpochAdvance;
use crate::managed_worker::WorkerSet;

/// Response-signing custody: the delegated snapshot and the worker that maintains it.
pub struct SigningPlane {
    signer: Arc<DelegatedServerSigner>,
    /// Owns the delegated rotation worker. Halted in [`Drop`] AFTER the snapshot is
    /// retired; the order is written out there rather than left to field position.
    workers: WorkerSet,
}

impl SigningPlane {
    /// The signer the PEP signs responses with. Moved into the proxy.
    pub fn signer(&self) -> Arc<DelegatedServerSigner> {
        Arc::clone(&self.signer)
    }

    /// Number of workers this plane owns. For the lifecycle tests.
    #[cfg(test)]
    pub fn worker_count(&self) -> usize {
        self.workers.len()
    }

    /// A plane holding a published delegated key whose single worker runs `body`, for the
    /// ownership and teardown tests.
    ///
    /// The key is valid for an hour — far outside any overlap window — so nothing below
    /// can stop signing by ordinary expiry rather than by the retirement under test.
    /// `body` receives the worker's [`Halt`](crate::managed_worker::Halt), so a test picks
    /// a worker that stops when asked, one that ignores the halt, or one that panics.
    #[cfg(test)]
    pub(crate) fn for_teardown_test(
        body: impl FnOnce(crate::managed_worker::Halt) + Send + 'static,
    ) -> Self {
        let signer = Arc::new(DelegatedServerSigner::new());
        signer.publish(mcp_re_http_profile::ActiveDelegatedKey {
            key: Arc::new(mcp_re_core::SigningKey::from_seed_bytes(&[3u8; 32])),
            delegated_kid: TEST_KID.to_string(),
            server_signer: mcp_re_http_profile::ActorIdentity {
                role: "server".into(),
                trust_domain: "example.com".into(),
                subject: "did:example:server".into(),
                keyid: TEST_KID.to_string(),
            },
            credential: "cred".into(),
            nbf: 0,
            exp: now_unix() + 3600,
        });
        let mut workers = WorkerSet::new(Arc::new(std::sync::atomic::AtomicBool::new(false)));
        let halt = workers.halt();
        workers.spawn("test delegated rotation", move || body(halt));
        SigningPlane { signer, workers }
    }
}

/// The delegated kid [`SigningPlane::for_teardown_test`] publishes.
#[cfg(test)]
pub(crate) const TEST_KID: &str = "delegated-1";

impl Drop for SigningPlane {
    fn drop(&mut self) {
        // Written out, in this order. The first step is a security property and the
        // second a lifecycle one; neither should read as an accident of struct layout.
        //
        // 1. Retire BEFORE the worker stops, so no signer that outlives this plane can
        //    keep signing off a key nothing is rotating and no trust-epoch advance can
        //    revoke. The hot path then fails closed immediately.
        self.signer.retire();
        // 2. Halt and reclaim. One worker, no cross-worker shutdown dependency, so
        //    `WorkerSet`'s termination semantics are the whole guarantee.
        self.workers.halt_and_reclaim();
    }
}

impl SigningPlane {
    /// Establish response-signing custody: build the issuer and the delegated snapshot,
    /// resolve the shared trust epoch, mint the first key, and start the rotation worker.
    ///
    /// Fails closed at startup rather than serving unsigned or unrevocable: if the root
    /// cannot issue the first delegated key, or a configured trust-epoch source cannot be
    /// read, this refuses to start.
    ///
    /// `root_signer` is MOVED in — it is only borrowed earlier for TLS material and the
    /// response public key. `deployment` is the caller's shutdown flag; the worker started
    /// here stops on it, and also when this plane is dropped.
    pub fn materialize(
        config: &cli::ValidatedConfig,
        root_signer: impl crate::key_source::ResponseSigner + Send + 'static,
        response_kid: &str,
        startup_now_unix: i64,
        deployment: Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<SigningPlane, String> {
        let crate::delegated_wiring::DelegatedSigningWiring {
            signer,
            mut rotor,
            overlap,
        } = crate::delegated_wiring::build_delegated_signing(config, root_signer)?;
        // Resolve the shared trust epoch BEFORE the first key is minted, so the very
        // first credential carries the globally comparable `<base>#<counter>` label
        // rather than the bare base. Minting under the bare label is what let a
        // restarted replica appear unrevoked to verifiers pinned past an `INCR`.
        let epoch_watch = build_delegated_epoch_watch(config, rotor.trust_epoch().to_string());
        if let Some(watch) = epoch_watch.as_ref() {
            // FAIL CLOSED FOR MINTING: a configured kill switch whose state cannot be
            // read means we cannot produce an epoch verifiers can compare, so we must
            // not issue at all. Refusing to start is the honest outcome — the previous
            // behaviour was to start anyway with the switch wired to nothing.
            let label = watch.current_label().ok_or_else(|| {
                "delegated-signing: --trust-epoch-redis-url is configured but the shared trust \
                 epoch could NOT be read at startup, so no credential can carry a comparable \
                 epoch. Refusing to start rather than minting keys the operator's kill switch \
                 cannot revoke (fail closed, ADR-MCPRE-052 §7)."
                    .to_string()
            })?;
            eprintln!(
                "mcp-re-proxy: delegated trust-epoch watch ACTIVE; minting under {label:?}. An \
                 operator INCR moves every replica to the next label, so verifiers pinned to the \
                 prior accepted-epoch set reject fleet-wide — and a restarted replica resolves \
                 the SAME label as its peers."
            );
            rotor.set_trust_epoch_before_first_issue(label);
        }
        // Initial issuance MUST succeed before serving: the proxy never serves without
        // an active delegated key (fail closed, ADR-MCPRE-052 §6).
        rotor.rotate(startup_now_unix).map_err(|e| {
            format!(
                "delegated-signing: initial delegated key issuance FAILED at startup ({e:?}); \
                 the root issuer must be available before serving (fail closed, ADR-MCPRE-052 §6)"
            )
        })?;
        eprintln!(
            "mcp-re-proxy: response signing = DELEGATED (ADR-MCPRE-052): the root issuer is off \
             the request path; delegated key TTL {}s / overlap {overlap}s; issuer kid \
             {response_kid:?}. Initial delegated key issued.",
            config.delegated_ttl_secs,
        );
        // Cold-path rotation worker: rotate within the overlap window before each key's
        // exp so the KMS/root stays off the per-core serving runtimes. It also watches the
        // shared trust-epoch counter and re-issues under a new epoch on an advance, so an
        // operator `INCR` revokes the outstanding delegated keys across the fleet
        // (ADR-MCPRE-052 §7).
        let mut workers = WorkerSet::new(deployment);
        spawn_delegated_rotation_task(
            &mut workers,
            rotor,
            Arc::clone(&signer),
            overlap,
            epoch_watch,
        );
        Ok(SigningPlane { signer, workers })
    }
}

/// ADR-MCPRE-052 §4/§6 + ADR-MCPRE-051 §5 (MCPRE-122): the cold-path delegated-key
/// rotation thread. A single owner drives the rotor OFF the per-core serving runtimes,
/// so the root issuer's blocking KMS/HSM calls never touch the request path. It wakes
/// within the rotation-overlap window before the current key's `exp`, mints a
/// successor, and republishes the hot-path snapshot; the fleet keeps signing off the
/// current key until then (no gap). If issuance fails while the current key is still
/// valid, serving continues until that key expires and THEN fails closed
/// (ADR-MCPRE-052 §6) — never a stale-key extension or a direct-root fallback. The
/// thread observes its halt between naps so it exits promptly on a rolling deploy.
fn spawn_delegated_rotation_task(
    workers: &mut crate::managed_worker::WorkerSet,
    mut rotor: crate::delegated_wiring::ProdDelegatedRotor,
    signer: Arc<crate::delegated_server_signer::DelegatedServerSigner>,
    overlap: i64,
    epoch_watch: Option<DelegatedEpochWatch>,
) {
    let halt = workers.halt();
    workers.spawn("delegated key rotation", move || {
        // SUPERVISION (C040). This thread is the ONLY thing that mints delegated keys, and
        // nothing observes it while it runs — `WorkerSet` reclaims it at shutdown, which is
        // far too late to matter here. Left bare, a panic on any reachable `.expect()` (the
        // CSPRNG draw, the two custody invariants) would end all rotation for the process
        // lifetime while every health surface still read steady state:
        // `DelegatedRotationMetrics.consecutive_failures` is only written BY this thread, so
        // a dead thread leaves it at 0 and the replica appears healthy right up until the
        // current key's `exp`, then 503s with no attributable cause.
        //
        // So the loop runs inside `catch_unwind` and a panic is converted into the
        // strongest honest signal available: RETIRE the snapshot, which makes the hot path
        // fail closed IMMEDIATELY (`delegated_signing_unavailable`) rather than at `exp`,
        // and record a failure so the metric stops reading healthy. The thread does not
        // resume — after a panic the rotor's state is not known good, and continuing to
        // mint from it would be worse than refusing.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            rotation_loop(&mut rotor, &signer, overlap, epoch_watch.as_ref(), &halt)
        }));
        if outcome.is_err() {
            signer.retire();
            signer.metrics().record_failure();
            eprintln!(
                "mcp-re-proxy: FATAL: the delegated rotation thread PANICKED. Delegated key \
                 rotation has stopped for the lifetime of this process and the current \
                 snapshot has been retired, so response signing now fails closed \
                 (delegated_signing_unavailable) immediately rather than at the key's exp. \
                 This replica cannot recover on its own — restart it."
            );
        }
    });
}

/// The rotation loop proper. Split out of [`spawn_delegated_rotation_task`] so the
/// supervisor above can catch a panic from anywhere inside it.
fn rotation_loop(
    rotor: &mut crate::delegated_wiring::ProdDelegatedRotor,
    signer: &Arc<crate::delegated_server_signer::DelegatedServerSigner>,
    overlap: i64,
    epoch_watch: Option<&DelegatedEpochWatch>,
    halt: &crate::managed_worker::Halt,
) {
    use crate::delegated_server_signer::rotation_backoff;
    {
        // Failures since the last success drive the backoff schedule; 0 in steady state.
        let mut consecutive_failures: u32 = 0;
        // The epoch this node is currently minting under (starts at the configured
        // baseline label from the startup issuance). An advance of the shared counter
        // moves it; verifiers pinned to the old label then reject across replicas.
        let mut last_label = rotor.trust_epoch().to_string();
        loop {
            if halt.requested() {
                return;
            }
            // In steady state, sleep until the overlap window opens (`exp - overlap`) so
            // a successor is minted while the predecessor is still valid. While retrying
            // after a failure we skip this wait and go straight to the backoff-then-retry
            // below. With no current key (startup edge / post-retirement) rotate at once.
            // The wait ALSO breaks early when the shared trust epoch advances, so
            // cross-replica revocation is bounded by the ~500ms epoch poll, not a full TTL.
            if consecutive_failures == 0 {
                let wake_at = match signer.current(now_unix()) {
                    Some(a) => (a.exp - overlap).max(now_unix()),
                    None => now_unix(),
                };
                let mut ticks = 0u32;
                while now_unix() < wake_at {
                    if halt.requested() {
                        return;
                    }
                    // Poll the shared trust epoch ~every 500ms (10 * 50ms).
                    if ticks.is_multiple_of(10) {
                        if let Some(watch) = epoch_watch.as_ref() {
                            if matches!(watch.current_label(), Some(l) if l != last_label) {
                                break;
                            }
                        }
                    }
                    ticks += 1;
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
            if halt.requested() {
                return;
            }
            // Trust-epoch advance takes priority over the scheduled rotation: swap to
            // the new epoch NOW so verifiers pinned to the prior accepted-epoch set
            // reject on the next request (cross-replica, since every replica reads the
            // same counter). ADR-MCPRE-052 §7.
            if let Some(watch) = epoch_watch.as_ref() {
                let resolved = watch.current_label();
                if resolved.is_none() {
                    // FAIL CLOSED FOR MINTING: the shared epoch is unreadable (outage)
                    // or went backwards (refused, never rebased). Either way we cannot
                    // produce a comparable epoch, so we must not issue. The current key
                    // keeps serving until its `exp`, after which the hot path fails
                    // closed on its own — no stale-epoch minting, no rebase. Back off
                    // and retry; the reader reconnects on the next read.
                    consecutive_failures = signer.metrics().record_failure();
                    let ttl = signer.seconds_to_expiry(now_unix());
                    let backoff = rotation_backoff(consecutive_failures, ttl, rotation_jitter());
                    eprintln!(
                        "mcp-re-proxy: WARNING: shared trust epoch unreadable or regressed; \
                         NOT minting (a credential without a comparable epoch is unrevokable). \
                         Current key serves until exp then fails closed. \
                         consecutive_failures {}, time-to-expiry {}s. Retrying in {}ms.",
                        consecutive_failures,
                        ttl.unwrap_or(0),
                        backoff.as_millis(),
                    );
                    if halt.sleep(backoff) {
                        return;
                    }
                    continue;
                }
                if let Some(label) = resolved {
                    if label != last_label {
                        match rotor.advance_trust_epoch(label.clone(), now_unix()) {
                            Ok(TrustEpochAdvance::Advanced) => {
                                consecutive_failures = 0;
                                last_label = label;
                                signer.metrics().record_success(now_unix());
                                eprintln!(
                                    "mcp-re-proxy: trust epoch advanced -> {last_label}: delegated \
                                     keys re-issued under the new epoch. This replica no longer \
                                     mints under the prior epoch. Credentials already issued under \
                                     it stay VERIFIABLE until verifiers are pointed at the new \
                                     epoch — update the verifiers' accepted epochs to complete the \
                                     revocation (delegation_trust_epoch_stale)."
                                );
                                continue;
                            }
                            // The root declined and the PRIOR-epoch key is still valid.
                            // `last_label` is deliberately left where it was, so the
                            // next pass re-enters this arm and retries; advancing it
                            // here would report a revocation that never happened and
                            // never look at it again.
                            Ok(TrustEpochAdvance::Declined) => {
                                consecutive_failures = signer.metrics().record_failure();
                                let ttl = signer.seconds_to_expiry(now_unix());
                                let backoff =
                                    rotation_backoff(consecutive_failures, ttl, rotation_jitter());
                                eprintln!(
                                    "mcp-re-proxy: WARNING: trust epoch advance to {label} NOT \
                                     APPLIED (root issuer declined); this replica is STILL MINTING \
                                     under the prior epoch on its current key, until that key's \
                                     exp ({}s) and then FAILS CLOSED. The break-glass revocation \
                                     is not yet in force here. consecutive_failures {}. Retrying \
                                     in {}ms.",
                                    ttl.unwrap_or(0),
                                    consecutive_failures,
                                    backoff.as_millis(),
                                );
                                if halt.sleep(backoff) {
                                    return;
                                }
                                continue;
                            }
                            Err(_) => {
                                consecutive_failures = signer.metrics().record_failure();
                                let ttl = signer.seconds_to_expiry(now_unix());
                                let backoff =
                                    rotation_backoff(consecutive_failures, ttl, rotation_jitter());
                                eprintln!(
                                    "mcp-re-proxy: WARNING: re-issue on trust-epoch advance FAILED \
                                     (root issuer unavailable); consecutive_failures {}. Retrying in {}ms.",
                                    consecutive_failures,
                                    backoff.as_millis(),
                                );
                                if halt.sleep(backoff) {
                                    return;
                                }
                                continue;
                            }
                        }
                    }
                }
            }
            // The delegated kid BEFORE the attempt, so silent no-progress is detectable.
            // `ensure_active` returns Ok when successor issuance FAILED but the current
            // key is still valid (custody.rs: the `!current_valid` guard is skipped and
            // the fallthrough `Some(a) if now < a.exp => Ok(())` wins). That is the
            // PRIMARY failure mode — a root outage during the overlap window, exactly
            // what the overlap exists to absorb — and taking it as success would reset
            // `consecutive_failures`, collapse `wake_at` to now (we are already past
            // `exp - overlap`), and re-enter this arm immediately: a tight retry loop
            // against the root KMS/HSM, minting a fresh keypair every pass, for the
            // whole overlap window. The backoff below must cover it.
            let before_kid = signer.current(now_unix()).map(|a| a.delegated_kid.clone());
            match rotor.rotate(now_unix()) {
                Ok(()) if !rotation_made_progress(signer, &before_kid, overlap) => {
                    consecutive_failures = signer.metrics().record_failure();
                    let ttl = signer.seconds_to_expiry(now_unix());
                    let backoff = rotation_backoff(consecutive_failures, ttl, rotation_jitter());
                    eprintln!(
                        "mcp-re-proxy: WARNING: delegated successor issuance FAILED (root issuer \
                         unavailable) but the current key is still valid; consecutive_failures {}, \
                         time-to-expiry {}s. Serving continues on the current key until its exp, \
                         then FAILS CLOSED (ADR-MCPRE-052 §6). Retrying in {}ms.",
                        consecutive_failures,
                        ttl.unwrap_or(0),
                        backoff.as_millis(),
                    );
                    if halt.sleep(backoff) {
                        return;
                    }
                }
                Ok(()) => {
                    consecutive_failures = 0;
                    signer.metrics().record_success(now_unix());
                    if let Some(ev) = rotor.audit().last() {
                        let ttl = signer.seconds_to_expiry(now_unix()).unwrap_or(0);
                        eprintln!(
                            "mcp-re-proxy: delegated key {} (kid {}, exp {}); time-to-expiry {}s; \
                             rotations_ok {}",
                            ev.event_type,
                            ev.delegated_kid,
                            ev.exp,
                            ttl,
                            signer.metrics().rotations_ok(),
                        );
                    }
                }
                Err(_) => {
                    consecutive_failures = signer.metrics().record_failure();
                    let ttl = signer.seconds_to_expiry(now_unix());
                    // Bounded jittered exponential backoff, capped by the current key's
                    // remaining validity (retry inside the overlap window) and a 30s
                    // ceiling once expired. OS CSPRNG jitter decorrelates a fleet.
                    let backoff = rotation_backoff(consecutive_failures, ttl, rotation_jitter());
                    eprintln!(
                        "mcp-re-proxy: WARNING: delegated key issuance FAILED (root issuer \
                         unavailable); consecutive_failures {}, time-to-expiry {}s. Serving \
                         continues only until the current delegated key expires, then FAILS CLOSED \
                         (ADR-MCPRE-052 §6) — no stale-key extension, no direct-root fallback. \
                         Retrying in {}ms.",
                        consecutive_failures,
                        ttl.unwrap_or(0),
                        backoff.as_millis(),
                    );
                    // Interruptible backoff so a persistent root outage does not hot-spin;
                    // the hot path keeps signing off the current key until its exp.
                    if halt.sleep(backoff) {
                        return;
                    }
                }
            }
        }
    }
}

/// Did the rotation attempt actually mint a successor?
///
/// `DelegatedSigningCustody::ensure_active` reports `Ok(())` in two very different
/// situations: a successor was issued, or issuance failed while the current key is
/// still valid (so the fleet keeps signing and the caller is expected to retry).
/// Only the first is progress. Without this distinction the retry loop treats a root
/// outage during the overlap window as steady state and spins on the root issuer.
///
/// Progress means the published delegated kid changed. When nothing is published at
/// all there is nothing to keep serving on, and the `Err` arm already handles that;
/// when the attempt was not yet due (we are outside the overlap window) an unchanged
/// kid is expected and not a failure.
fn rotation_made_progress(
    signer: &crate::delegated_server_signer::DelegatedServerSigner,
    before_kid: &Option<String>,
    overlap: i64,
) -> bool {
    let now = now_unix();
    let Some(active) = signer.current(now) else {
        // Nothing published: not progress, but also nothing to back off protecting.
        return false;
    };
    if active.delegated_kid != *before_kid.as_deref().unwrap_or("") {
        return true;
    }
    // Same kid. Only a rotation that was DUE and did not happen is a failure.
    now < active.exp - overlap
}

/// A fresh random u64 from the OS CSPRNG for backoff jitter. On the (astronomically
/// unlikely) CSPRNG failure, fall back to 0 (no jitter) rather than panicking the
/// rotation thread — the backoff still bounds the retry rate, only its dither is lost.
fn rotation_jitter() -> u64 {
    let mut b = [0u8; 8];
    match getrandom::fill(&mut b) {
        Ok(()) => u64::from_le_bytes(b),
        Err(_) => 0,
    }
}
/// The shared trust-epoch counter, watched by the delegated-rotation owner so an
/// operator's `INCR <trust-epoch-key>` invalidates the outstanding epoch of delegated
/// response keys across the fleet (ADR-MCPRE-052 §7). The RESPONSE-side counterpart to
/// [`build_trust_epoch_channel`], which flushes the REQUEST-trust cache on the same
/// advance. Read-only; a read error leaves the epoch unchanged (never advance on a
/// transient blip).
///
/// What an advance does and does not do: it stops this fleet MINTING under the prior
/// epoch. It does not reach credentials already issued under it — no verifier reads the
/// counter, so `accepted_epochs` is static verifier configuration and a leaked
/// credential stays verifiable until the verifiers are pointed at the new epoch
/// (docs/spec/delegated-required-validation-matrix.md §C.1, "Operational consequence").
/// The counter is therefore also a fleet availability dependency: anyone who can write
/// the shared key can advance it and make every replica mint a label the currently
/// configured verifiers reject.
///
/// The emitted label is ALWAYS `<base>#<counter>` — never the bare base label. That is
/// what makes an operator `INCR` survive a replica restart: the label is derived purely
/// from shared state, so every replica at counter `N` mints `<base>#N` regardless of
/// when it started. The previous design compared the counter against a baseline read at
/// *this process's* startup and emitted the bare base label while they matched, so a
/// replica restarting after an `INCR` adopted the advanced value as its own baseline,
/// never observed an advance, and kept minting an epoch verifiers still accepted — the
/// kill switch was process-relative rather than durable.
///
/// `high_water` makes the emitted epoch monotone WITHIN a process: a read that goes
/// backwards (store reset, failover to a stale replica, a reconnect landing on the
/// wrong instance) is refused rather than rebased, so reconnection can never re-mint
/// under an epoch a verifier has already stopped accepting. Across a restart the shared
/// counter is the only authority, by construction — a store that loses its counter is a
/// trust-store failure, not something a replica can detect locally.
struct DelegatedEpochWatch {
    reader: Box<dyn crate::trust_epoch::EpochReader>,
    base_label: String,
    high_water: std::sync::Mutex<Option<i64>>,
}

impl DelegatedEpochWatch {
    /// The label to mint under, or `None` when the shared epoch cannot be established.
    ///
    /// `None` is FAIL CLOSED FOR MINTING: the caller must not issue a credential,
    /// because it cannot produce an epoch verifiers can compare. It does not retire the
    /// current key — the fleet keeps signing off it until its `exp` and the hot path
    /// then fails closed on its own (ADR-MCPRE-052 §6). Crucially it is also not treated
    /// as "no change": a blip must never be read as an advance, nor as permission to
    /// mint under a stale label.
    fn current_label(&self) -> Option<String> {
        let counter = self.reader.read_epoch().ok()?;
        let mut hw = self.high_water.lock().ok()?;
        if matches!(*hw, Some(prev) if counter < prev) {
            // Regression. Refuse rather than rebase: minting under the lower epoch
            // would resurrect credentials the fleet's verifiers already reject.
            return None;
        }
        *hw = Some(counter);
        Some(format!("{}#{}", self.base_label, counter))
    }
}

/// Build the delegated-signing trust-epoch watcher from `--trust-epoch-redis-url`.
/// `None` when no source is configured — the epoch is then whatever
/// `--delegated-trust-epoch` fixed it to, with no cross-replica revocation signal (the
/// honest bounded behaviour for a single-node deployment).
///
/// When a URL IS configured the watcher is always returned: the reader connects lazily
/// and re-establishes after any failure, so a store that is briefly unreachable at boot
/// no longer leaves this replica permanently without the operator's kill switch. The
/// caller resolves the initial label and fails closed if it cannot.
#[cfg(feature = "redis_replay")]
fn build_delegated_epoch_watch(
    config: &cli::Config,
    base_label: String,
) -> Option<DelegatedEpochWatch> {
    let url = config.trust_epoch_redis_url.as_ref()?;
    let key = config
        .trust_epoch_key
        .as_deref()
        .unwrap_or(crate::trust_epoch::DEFAULT_TRUST_EPOCH_KEY);
    match crate::trust_epoch::RedisEpochReader::connect_lazy(url, key) {
        Ok(reader) => Some(DelegatedEpochWatch {
            reader: Box::new(reader),
            base_label,
            high_water: std::sync::Mutex::new(None),
        }),
        Err(e) => {
            // Only a malformed URL reaches here (`Client::open` parses, it does not
            // connect), so this is a configuration error, not an outage.
            eprintln!(
                "mcp-re-proxy: --trust-epoch-redis-url is not a usable Redis URL ({}); \
                 delegated trust-epoch revocation cannot be wired.",
                e.0
            );
            None
        }
    }
}

#[cfg(not(feature = "redis_replay"))]
fn build_delegated_epoch_watch(
    _config: &cli::Config,
    _base_label: String,
) -> Option<DelegatedEpochWatch> {
    None
}
#[cfg(test)]
mod rotation_progress_tests {
    use super::rotation_made_progress;
    use crate::delegated_server_signer::DelegatedServerSigner;
    use mcp_re_core::SigningKey;
    use mcp_re_http_profile::ActiveDelegatedKey;
    use mcp_re_http_profile::ActorIdentity;
    use std::sync::Arc;

    const OVERLAP: i64 = 60;

    fn key(kid: &str, exp: i64) -> ActiveDelegatedKey {
        ActiveDelegatedKey {
            key: Arc::new(SigningKey::from_seed_bytes(&[7u8; 32])),
            delegated_kid: kid.to_string(),
            server_signer: ActorIdentity {
                role: "server".into(),
                trust_domain: "example.com".into(),
                subject: "did:example:server".into(),
                keyid: kid.to_string(),
            },
            credential: "cred".into(),
            nbf: 0,
            exp,
        }
    }

    /// The defect this guards: `ensure_active` reports `Ok(())` both when a successor
    /// was minted AND when issuance failed while the current key is still valid. Taking
    /// the second as success reset `consecutive_failures`, collapsed the steady-state
    /// wake time to now (we are already past `exp - overlap`), and re-entered the
    /// rotate arm immediately — a tight loop against the root KMS/HSM, minting a fresh
    /// keypair each pass, for the entire overlap window.
    #[test]
    fn unchanged_kid_inside_the_overlap_window_is_not_progress() {
        let signer = DelegatedServerSigner::new();
        let now = crate::app::now_unix();
        // Published key is inside its overlap window: a rotation is DUE.
        signer.publish(key("K1", now + OVERLAP - 1));
        let before = Some("K1".to_string());
        assert!(
            !rotation_made_progress(&signer, &before, OVERLAP),
            "a due rotation that did not change the kid means issuance failed"
        );
    }

    #[test]
    fn a_new_kid_is_progress() {
        let signer = DelegatedServerSigner::new();
        let now = crate::app::now_unix();
        signer.publish(key("K2", now + 300));
        let before = Some("K1".to_string());
        assert!(rotation_made_progress(&signer, &before, OVERLAP));
    }

    /// Outside the overlap window an unchanged kid is expected, not a failure — the
    /// backoff must not engage in steady state.
    #[test]
    fn unchanged_kid_outside_the_overlap_window_is_not_a_failure() {
        let signer = DelegatedServerSigner::new();
        let now = crate::app::now_unix();
        signer.publish(key("K1", now + 10 * OVERLAP));
        let before = Some("K1".to_string());
        assert!(rotation_made_progress(&signer, &before, OVERLAP));
    }

    /// Nothing published: the `Err` arm owns that case; report no progress.
    #[test]
    fn nothing_published_is_not_progress() {
        let signer = DelegatedServerSigner::new();
        assert!(!rotation_made_progress(&signer, &None, OVERLAP));
    }
}
#[cfg(test)]
mod trust_epoch_watch_tests {
    use super::DelegatedEpochWatch;
    use crate::trust_epoch::EpochReadError;
    use crate::trust_epoch::EpochReader;
    use std::sync::atomic::AtomicI64;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::sync::Mutex;

    const BASE: &str = "epoch-min";

    /// A shared counter standing in for the Redis key, plus a switch that makes reads
    /// fail so an outage can be simulated deterministically.
    struct SharedCounter {
        value: AtomicI64,
        down: Mutex<bool>,
        reads: AtomicUsize,
    }

    impl SharedCounter {
        fn new(v: i64) -> Arc<Self> {
            Arc::new(SharedCounter {
                value: AtomicI64::new(v),
                down: Mutex::new(false),
                reads: AtomicUsize::new(0),
            })
        }
        fn incr(&self) {
            self.value.fetch_add(1, Ordering::SeqCst);
        }
        fn set(&self, v: i64) {
            self.value.store(v, Ordering::SeqCst);
        }
        fn set_down(&self, down: bool) {
            *self.down.lock().expect("down lock") = down;
        }
        fn reads(&self) -> usize {
            self.reads.load(Ordering::SeqCst)
        }
    }

    struct CounterReader(Arc<SharedCounter>);

    impl EpochReader for CounterReader {
        fn read_epoch(&self) -> Result<i64, EpochReadError> {
            self.0.reads.fetch_add(1, Ordering::SeqCst);
            if *self.0.down.lock().expect("down lock") {
                return Err(EpochReadError("epoch store unreachable".into()));
            }
            Ok(self.0.value.load(Ordering::SeqCst))
        }
    }

    /// Start a replica's watch over the shared counter. Constructing a NEW watch over
    /// the SAME counter is exactly what a restart looks like: no carried-over state.
    fn replica(counter: &Arc<SharedCounter>) -> DelegatedEpochWatch {
        DelegatedEpochWatch {
            reader: Box::new(CounterReader(Arc::clone(counter))),
            base_label: BASE.to_string(),
            high_water: Mutex::new(None),
        }
    }

    /// The label is derived purely from shared state, so it is globally comparable.
    #[test]
    fn label_is_always_base_hash_counter_never_the_bare_base() {
        let counter = SharedCounter::new(0);
        let w = replica(&counter);
        assert_eq!(w.current_label().as_deref(), Some("epoch-min#0"));
        counter.incr();
        assert_eq!(w.current_label().as_deref(), Some("epoch-min#1"));
    }

    /// Every replica at the same counter mints the same label, whenever it started.
    #[test]
    fn all_replicas_agree_regardless_of_start_time() {
        let counter = SharedCounter::new(4);
        let a = replica(&counter);
        assert_eq!(a.current_label().as_deref(), Some("epoch-min#4"));
        // B joins the fleet later.
        let b = replica(&counter);
        assert_eq!(b.current_label(), a.current_label());
    }

    /// THE INVARIANT (C007). An operator INCR must stay effective across a restart: the
    /// restarted replica must NOT reinterpret the current counter as a fresh local
    /// baseline and resume minting a label verifiers treat as unrevoked.
    #[test]
    fn an_increment_survives_a_replica_restart() {
        let counter = SharedCounter::new(7);
        let long_lived = replica(&counter);
        let before = long_lived.current_label().expect("readable");
        assert_eq!(before, "epoch-min#7");

        // Operator revokes the fleet.
        counter.incr();
        let after_incr = long_lived.current_label().expect("readable");
        assert_eq!(after_incr, "epoch-min#8");
        assert_ne!(after_incr, before, "the INCR must change the minted label");

        // A replica restarts: brand-new watch, no memory of the pre-INCR value.
        let restarted = replica(&counter);
        let after_restart = restarted.current_label().expect("readable");

        assert_eq!(
            after_restart, after_incr,
            "a restarted replica must resolve the SAME post-INCR label as its peers"
        );
        assert_ne!(
            after_restart, before,
            "a restart must NOT resurrect the pre-INCR epoch — that is the revocation \
             being defeated by a restart"
        );
    }

    /// An outage is fail-closed FOR MINTING: no label, so the caller must not issue.
    /// It is not silently treated as "unchanged", which would keep minting blind.
    #[test]
    fn an_outage_yields_no_label_so_minting_stops() {
        let counter = SharedCounter::new(3);
        let w = replica(&counter);
        assert!(w.current_label().is_some());
        counter.set_down(true);
        assert!(
            w.current_label().is_none(),
            "an unreadable epoch must fail closed for minting"
        );
    }

    /// Reconnect after an outage resumes at the CURRENT shared value — including an
    /// INCR that happened while this replica could not read.
    #[test]
    fn reconnect_after_an_outage_resumes_and_sees_missed_increments() {
        let counter = SharedCounter::new(1);
        let w = replica(&counter);
        assert_eq!(w.current_label().as_deref(), Some("epoch-min#1"));

        counter.set_down(true);
        assert!(w.current_label().is_none());
        // The operator revokes DURING the outage.
        counter.incr();
        counter.incr();
        assert!(w.current_label().is_none(), "still down");

        counter.set_down(false);
        assert_eq!(
            w.current_label().as_deref(),
            Some("epoch-min#3"),
            "a reconnect must observe increments missed during the outage"
        );
        assert!(
            counter.reads() >= 4,
            "each attempt re-reads; no cached verdict"
        );
    }

    /// Reconnection must not reset, rebase or otherwise weaken an already-issued
    /// revocation: a counter that goes BACKWARDS (store reset, failover to a stale
    /// replica, reconnect to the wrong instance) is refused, never adopted.
    #[test]
    fn a_regressed_counter_is_refused_not_rebased() {
        let counter = SharedCounter::new(9);
        let w = replica(&counter);
        assert_eq!(w.current_label().as_deref(), Some("epoch-min#9"));

        counter.set(2); // store rolled back
        assert!(
            w.current_label().is_none(),
            "minting under a lower epoch would resurrect credentials verifiers reject"
        );
        // Still refused on retry — it is not a transient blip that clears itself.
        assert!(w.current_label().is_none());

        // Recovery to at-or-above the high-water mark resumes minting.
        counter.set(9);
        assert_eq!(w.current_label().as_deref(), Some("epoch-min#9"));
        counter.set(11);
        assert_eq!(w.current_label().as_deref(), Some("epoch-min#11"));
    }

    /// Issuance continues normally across the whole sequence the operator cares about:
    /// steady state -> INCR -> outage -> reconnect -> restart.
    #[test]
    fn full_sequence_increment_outage_restart_reconnect_continued_issuance() {
        let counter = SharedCounter::new(0);
        let mut minted: Vec<String> = Vec::new();
        let w = replica(&counter);

        minted.push(w.current_label().expect("steady state"));
        counter.incr();
        minted.push(w.current_label().expect("after incr"));

        counter.set_down(true);
        assert!(w.current_label().is_none(), "no minting during the outage");
        counter.set_down(false);
        minted.push(w.current_label().expect("after reconnect"));

        // Restart: fresh watch, same shared counter.
        let w2 = replica(&counter);
        minted.push(w2.current_label().expect("after restart"));
        counter.incr();
        minted.push(
            w2.current_label()
                .expect("issuance continues after restart"),
        );

        assert_eq!(
            minted,
            vec![
                "epoch-min#0".to_string(),
                "epoch-min#1".to_string(),
                "epoch-min#1".to_string(),
                "epoch-min#1".to_string(),
                "epoch-min#2".to_string(),
            ],
            "labels track the shared counter only — never a per-process baseline"
        );
    }
}

#[cfg(test)]
mod handle_lifetime_tests {
    use super::*;
    use mcp_re_core::SigningKey;
    use mcp_re_http_profile::ActiveDelegatedKey;
    use mcp_re_http_profile::ActorIdentity;
    use std::sync::atomic::AtomicBool;

    const KID: &str = TEST_KID;

    fn active_key(exp: i64) -> ActiveDelegatedKey {
        ActiveDelegatedKey {
            key: Arc::new(SigningKey::from_seed_bytes(&[3u8; 32])),
            delegated_kid: KID.to_string(),
            server_signer: ActorIdentity {
                role: "server".into(),
                trust_domain: "example.com".into(),
                subject: "did:example:server".into(),
                keyid: KID.to_string(),
            },
            credential: "cred".into(),
            nbf: 0,
            exp,
        }
    }

    /// A plane holding a published key and one worker that only waits to be halted — the
    /// cooperative shape, enough to assert the ownership relationship without a root
    /// issuer or a KMS.
    fn plane() -> SigningPlane {
        SigningPlane::for_teardown_test(|halt| {
            while !halt.requested() {
                std::thread::sleep(Duration::from_millis(5));
            }
        })
    }

    /// A signer that outlives its plane must STOP signing.
    ///
    /// Nothing is rotating that key any more, and nothing is polling the shared trust
    /// epoch — so an operator `INCR` could not revoke it. Serving on until `exp` would be
    /// a signing authority whose kill switch is disconnected.
    ///
    /// Before v0.16 this could not arise: the rotation thread stopped only with the
    /// process, or on a panic that already retired the snapshot. The structural halt made
    /// a clean stop reachable while the process continues, and `Drop` is what closes it.
    #[test]
    fn a_signer_that_outlives_the_plane_stops_signing() {
        let plane = plane();
        let signer = plane.signer();
        assert_eq!(plane.worker_count(), 1);

        // Alive: the key is published and well inside its validity window.
        assert!(
            signer.current(now_unix()).is_some(),
            "a live plane must publish a usable delegated key"
        );

        drop(plane);

        assert!(
            signer.current(now_unix()).is_none(),
            "the signer kept signing after the plane that rotated its key was gone"
        );
    }

    /// The surviving signer does not keep the rotation worker alive: access to the
    /// snapshot is not custody of the machinery that maintains it.
    #[test]
    fn a_surviving_signer_does_not_keep_the_rotation_worker_alive() {
        let observed = Arc::new(AtomicBool::new(false));
        let signer;
        {
            let mut workers = WorkerSet::new(Arc::new(AtomicBool::new(false)));
            let halt = workers.halt();
            let flag = Arc::clone(&observed);
            workers.spawn("test delegated rotation", move || {
                while !halt.requested() {
                    std::thread::sleep(Duration::from_millis(5));
                }
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
            });
            let inner = Arc::new(DelegatedServerSigner::new());
            inner.publish(active_key(now_unix() + 3600));
            let plane = SigningPlane {
                signer: Arc::clone(&inner),
                workers,
            };
            signer = plane.signer();
        }
        assert!(
            observed.load(std::sync::atomic::Ordering::SeqCst),
            "the rotation worker did not observe the structural halt"
        );
        // And the surviving handle is inert rather than merely unmaintained.
        assert!(signer.current(now_unix()).is_none());
    }
}
