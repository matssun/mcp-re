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
//! leaves is one `Arc<DelegatedServerSigner>`, moved into the proxy, which reads the snapshot
//! and cannot change it. The root issuer never leaves: nothing outside this plane can mint.
//!
//! # A surviving signer must not keep signing
//!
//! This is the same hazard `trust_plane` closes for a surviving resolver, in the signing
//! domain, and it is worth stating because the failure is silent.
//!
//! The rotation worker is the ONLY thing that mints successors, and it is also the only
//! thing that polls the shared trust epoch — the operator's cross-fleet kill switch
//! (ADR-MCPRE-052 §7). A signer whose worker has stopped would go on signing off the last
//! delegated key until its `exp`, with nobody left to observe an `INCR` — a frozen signing
//! authority whose revocation channel is dead. So the invariant is: **once maintenance of a
//! signing key has stopped, no new signature is made under it.** Two things hold it:
//!
//! * The worker follows THIS PLANE's lifetime, not the deployment's shutdown flag. A
//!   shutdown drains the fleet first, and the drain still signs responses; the key stays
//!   maintained, and the epoch poll alive, until the plane is dropped after the drain.
//! * [`Drop`] retires the snapshot BEFORE halting the worker, and the worker's supervisor
//!   retires it whenever the worker ends, so the hot path fails closed
//!   (`delegated_signing_unavailable`) the moment nothing is maintaining the key.
//!
//! Note the asymmetry with `reloading_trust::SignerDirectory`, which deliberately keeps
//! answering from its last snapshot after its plane is gone. A directory yields an
//! identity COORDINATE and admits nothing on its own; a signer PRODUCES authority. Only
//! the first is safe to leave frozen.

use std::sync::Arc;

use crate::delegated_server_signer::DelegatedServerSigner;
use crate::delegated_server_signer::SigningRetirement;
use crate::managed_worker::WorkerSet;

/// Keeping a delegated key in force: when to mint the successor, and what a root outage
/// costs.
mod rotation;

/// The break-glass half: what the shared trust epoch says, and what asking it costs.
mod trust_epoch_advance;

/// The shared trust-epoch counter as this plane reads it, and the repair of a regression.
mod epoch_watch;
use epoch_watch::DelegatedEpochWatch;

/// Asking the root for a successor, and reading its answer honestly.
mod mint_successor;

/// The root issuer under a bound; `pub(crate)` for the issuer closure `delegated_wiring` builds.
pub(crate) mod bounded_root_issuer;

use rotation::spawn_delegated_rotation_task;

/// Response-signing custody: the delegated snapshot and the worker that maintains it.
pub struct SigningPlane {
    signer: Arc<DelegatedServerSigner>,
    /// What [`Drop`] withdraws signing with; the rotor that publishes has moved onto the worker.
    retirement: SigningRetirement,
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
        Self::for_teardown_test_with_rotor(move |halt, _rotor| body(halt))
    }

    /// The same, with the worker handed the rotor that published the key — as the
    /// production worker is — for the tests of what a rotor may still do after teardown.
    #[cfg(test)]
    pub(crate) fn for_teardown_test_with_rotor(
        body: impl FnOnce(crate::managed_worker::Halt, crate::delegated_wiring::ProdDelegatedRotor)
            + Send
            + 'static,
    ) -> Self {
        let rotor =
            crate::delegated_wiring::test_support::published(crate::clock::now_unix() + 3600, 3);
        let (signer, retirement) = (rotor.signer(), rotor.retirement());
        let mut workers = WorkerSet::new(Arc::new(std::sync::atomic::AtomicBool::new(false)));
        let halt = workers.halt();
        workers
            .spawn("test delegated rotation", move || body(halt, rotor))
            .expect("spawn test worker");
        SigningPlane {
            signer,
            retirement,
            workers,
        }
    }
}

impl Drop for SigningPlane {
    fn drop(&mut self) {
        // Written out, in this order. The first step is a security property and the
        // second a lifecycle one; neither should read as an accident of struct layout.
        //
        // 1. Retire BEFORE the worker stops, so no signer that outlives this plane can
        //    keep signing off a key nothing is rotating and no trust-epoch advance can
        //    revoke. The hot path then fails closed immediately.
        //
        //    PERMANENTLY, because step 2 does not stop the rotor instantly: it observes
        //    its halt only between cycles, so an in-flight mint could otherwise publish
        //    after this line and hand a signer that outlives this plane a fresh key.
        self.retirement.retire_permanently();
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
    /// `roots` is MOVED in (borrowed earlier for TLS material); taking the witness rather
    /// than a signer is what makes a plane over uncompared roles unconstructible. It takes
    /// no shutdown flag: the worker started here stops only when this plane is dropped.
    pub fn materialize(
        plan: &crate::startup_plan::SigningPlan,
        roots: crate::capability_materialization::MaterializedSigningRoles,
        startup_now_unix: i64,
    ) -> Result<SigningPlane, String> {
        Self::materialize_over(plan, roots, startup_now_unix)
    }

    /// The materialization over any root signer; reachable outside this module only through
    /// [`SigningPlane::materialize`].
    fn materialize_over(
        plan: &crate::startup_plan::SigningPlan,
        root_signer: impl crate::key_source::ResponseSigner + Send + 'static,
        startup_now_unix: i64,
    ) -> Result<SigningPlane, String> {
        // Resolve the shared epoch BEFORE the custody exists: its first credential carries it.
        let epoch_watch =
            build_delegated_epoch_watch(&plan.epoch, plan.custody.trust_epoch.clone())?;
        let mut minting = plan.clone();
        if let Some(watch) = epoch_watch.as_ref() {
            // FAIL CLOSED FOR MINTING: a configured kill switch whose state cannot be
            // read yields no epoch verifiers can compare, so nothing is issued.
            minting.custody.trust_epoch = watch.epoch().map_err(|_| {
                "delegated-signing: --trust-epoch-redis-url is configured but the shared trust \
                 epoch could NOT be read at startup; refusing to start rather than mint keys the \
                 operator's kill switch cannot revoke (fail closed, ADR-MCPRE-052 §7)."
                    .to_string()
            })?;
            eprintln!(
                "mcp-re-proxy: delegated trust-epoch watch ACTIVE; minting under {:?}. An \
                 operator INCR moves every replica to the next label, and a restarted replica \
                 resolves the SAME label as its peers.",
                minting.custody.trust_epoch.label()
            );
        } else {
            eprintln!(
                "mcp-re-proxy: NO trust-epoch source is wired (--trust-epoch-redis-url): \
                 delegated keys are minted under the bare base {:?}, which never advances; \
                 short of a restart, a credential's exp is the only thing that ends it.",
                plan.custody.trust_epoch.label()
            );
        }
        let crate::delegated_wiring::DelegatedSigningWiring {
            signer,
            mut rotor,
            window,
        } = crate::delegated_wiring::build_delegated_signing(&minting, root_signer)?;
        // Initial issuance MUST succeed before serving (fail closed, ADR-MCPRE-052 §6).
        mint_successor::rotate_and_announce(&mut rotor, startup_now_unix).map_err(|_| {
            format!(
                "delegated-signing: initial delegated key issuance FAILED at startup ({}); \
                 the root issuer must be available before serving (fail closed, ADR-MCPRE-052 §6)",
                mint_successor::issuance_failure(rotor.last_refusal())
            )
        })?;
        eprintln!(
            "mcp-re-proxy: response signing = DELEGATED (ADR-MCPRE-052): the root issuer is off \
             the request path; delegated key {window}. \
             Initial delegated key issued.",
        );
        // Cold-path rotation worker: rotates within each key's overlap window and re-issues
        // on a trust-epoch advance (ADR-MCPRE-052 §7). Its halt is this plane's alone, so
        // it keeps the key maintained through the fleet drain.
        let retirement = rotor.retirement();
        let mut workers = WorkerSet::new(Arc::new(std::sync::atomic::AtomicBool::new(false)));
        spawn_delegated_rotation_task(&mut workers, rotor, window.overlap(), epoch_watch)?;
        Ok(SigningPlane {
            signer,
            retirement,
            workers,
        })
    }
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
/// Build the delegated-signing trust-epoch watcher from the SHARED epoch plan (CF-09).
///
/// The plan is an input, not something read from configuration here. This function and the
/// trust plane's channel builder are the two CONSUMERS of one decision; while each
/// interpreted `--trust-epoch-redis-url` for itself they were two authorities that happened
/// to agree, and the code said as much — trust's refusal of a malformed URL landed first
/// only because trust is materialized first.
///
/// `Ok(None)` when no source is planned — the epoch is then whatever
/// `--delegated-trust-epoch` fixed it to, with no cross-replica revocation signal (the
/// honest bounded behaviour for a single-node deployment).
///
/// When a URL IS configured this either returns a watcher or REFUSES. The reader connects
/// lazily and re-establishes after any failure, so a store that is briefly unreachable at
/// boot does not leave this replica permanently without the operator's kill switch; the
/// caller resolves the initial label and fails closed if it cannot. But a URL that cannot
/// be parsed at all yields no watcher, and a `None` here is indistinguishable from "no
/// source configured": minting would proceed under the bare `--delegated-trust-epoch`
/// label with the `INCR` kill switch wired to nothing, which is the one thing an operator
/// who configured a URL has asked not to happen. So a malformed URL is a startup refusal
/// on this plane's own terms, not a warning line and a silent downgrade.
#[cfg(feature = "redis_replay")]
fn build_delegated_epoch_watch(
    epoch: &crate::startup_plan::TrustEpochPlan,
    base: mcp_re_http_profile::custody::TrustEpoch,
) -> Result<Option<DelegatedEpochWatch>, String> {
    let Some(source) = epoch.networked_source()? else {
        return Ok(None);
    };
    match crate::trust_epoch::RedisEpochReader::connect_lazy(source.url(), source.key()) {
        Ok(reader) => Ok(Some(DelegatedEpochWatch::new(Box::new(reader), base))),
        Err(e) => {
            // Only a malformed URL reaches here (`Client::open` parses, it does not
            // connect), so this is a configuration error, not an outage.
            Err(format!(
                "delegated-signing: --trust-epoch-redis-url is not a usable Redis URL ({}); \
                 refusing to start rather than minting delegated credentials under the bare \
                 --delegated-trust-epoch label, which the operator's INCR kill switch cannot \
                 revoke (fail closed, ADR-MCPRE-052 §7).",
                e.0
            ))
        }
    }
}

/// The same refusal, one step earlier: a build without the `redis_replay` feature has no
/// reader to construct, so a planned source cannot be honoured here either.
///
/// The message is the PLAN's, identical to the trust plane's, because the two planes were
/// refusing the same build fact with two different sentences — each naming only its own
/// half of the consequence, and which half an operator met decided by materialization
/// order (CF-09's layer-B clause).
#[cfg(not(feature = "redis_replay"))]
fn build_delegated_epoch_watch(
    epoch: &crate::startup_plan::TrustEpochPlan,
    _base: mcp_re_http_profile::custody::TrustEpoch,
) -> Result<Option<DelegatedEpochWatch>, String> {
    match epoch.unsupported_by_build() {
        Some(refusal) => Err(refusal),
        None => Ok(None),
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
        fn read_state(&self) -> Result<crate::trust_epoch::EpochState, EpochReadError> {
            self.read_epoch()
                .map(|counter| crate::trust_epoch::EpochState {
                    counter,
                    generation: None,
                })
        }
    }

    /// A store this replica may read but not write, so a regression stays refused here;
    /// the repair is `epoch_watch`'s to test.
    impl crate::trust_epoch::raise::EpochRaiser for CounterReader {
        fn raise_past(&self, _mark: i64, _to: i64) -> Result<i64, EpochReadError> {
            Err(EpochReadError("NOPERM".into()))
        }
    }

    /// Start a replica's watch over the shared counter. Constructing a NEW watch over
    /// the SAME counter is exactly what a restart looks like: no carried-over state.
    fn replica(counter: &Arc<SharedCounter>) -> DelegatedEpochWatch {
        DelegatedEpochWatch::new(
            Box::new(CounterReader(Arc::clone(counter))),
            BASE.parse().expect("base"),
        )
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

/// What a planned-but-unusable trust-epoch source does to the signing plane.
#[cfg(test)]
mod epoch_watch_wiring_tests {
    use super::build_delegated_epoch_watch;
    use crate::startup_plan::TrustEpochPlan;

    /// A plan, written out. The plan is what this function consumes now, so the fixture
    /// states the posture directly instead of assembling a whole `DeploymentRequest` around one field.
    ///
    /// The URL below is REACHABLE: layer A checks the locator's shape and nothing more —
    /// whether a Redis client can use it is a fact about the build, deliberately left to
    /// this plane — so a scheme-bearing URL that is not a Redis URL passes validation and
    /// arrives here.
    fn planned(url: &str) -> TrustEpochPlan {
        TrustEpochPlan::redis(url, crate::trust_epoch::DEFAULT_TRUST_EPOCH_KEY)
    }

    fn base() -> mcp_re_http_profile::custody::TrustEpoch {
        "epoch-1".parse().expect("base")
    }

    /// An operator who configured a kill switch must not get a replica that mints without
    /// one. A URL that cannot be turned into a reader previously became `None`, which is
    /// indistinguishable from "no source configured": the plane skipped its own
    /// fail-closed block and issued under the bare `--delegated-trust-epoch` label, which
    /// no `INCR` can revoke, behind a single warning line. The only thing that refused was
    /// the TRUST plane, in another file, and only because it happens to be materialized
    /// first.
    ///
    /// Runs in `//mcp-re-proxy:proxy_ext_unit_test`, the `redis_replay` lane, where the real
    /// function is compiled.
    #[cfg(feature = "redis_replay")]
    #[test]
    fn a_planned_but_unusable_epoch_url_refuses_instead_of_minting_unrevocably() {
        let Err(err) = build_delegated_epoch_watch(&planned("http://127.0.0.1:6379"), base())
        else {
            panic!("a kill switch that cannot be wired must refuse the plane");
        };
        assert!(
            err.contains("--trust-epoch-redis-url"),
            "the refusal must name the flag: {err}"
        );
        assert!(
            err.contains("is not a usable Redis URL"),
            "the refusal must come from the reader that could not be built: {err}"
        );
    }

    /// A planned source in a build without `redis_replay` refuses on the build fact, not
    /// on the URL. Measures the non-`redis_replay` form of `build_delegated_epoch_watch`
    /// in `//mcp-re-proxy:proxy_unit_test`.
    #[cfg(not(feature = "redis_replay"))]
    #[test]
    fn a_planned_source_this_build_cannot_read_refuses_instead_of_minting_unrevocably() {
        let Err(err) = build_delegated_epoch_watch(&planned("redis://epoch-store.invalid"), base())
        else {
            panic!("a planned source this build cannot read must refuse the plane");
        };
        assert!(
            err.contains("requires a build with the `redis_replay` feature"),
            "the refusal must name the missing feature: {err}"
        );
        assert!(
            err.contains("--trust-epoch-redis-url"),
            "the refusal must name the flag: {err}"
        );
    }

    /// Negative control: no planned source is still the honest single-node shape, not a
    /// refusal.
    #[test]
    fn no_planned_epoch_source_is_still_accepted() {
        match build_delegated_epoch_watch(&TrustEpochPlan::NoNetworkChannel, base()) {
            Ok(None) => {}
            Ok(Some(_)) => panic!("no source must yield no watcher"),
            Err(e) => panic!("an unconfigured kill switch is not a misconfiguration: {e}"),
        }
    }
}

/// The startup refusals and the rotation loop itself, driven through the real entry
/// points rather than through their pure predicates.
///
/// `rotation_made_progress` and `rotation_backoff` are separately tested above and in
/// `delegated_server_signer`; what those tests cannot show is that the loop COMPOSES
/// them — that a fail-soft `Ok(())` from a root outage is routed to the backoff arm and
/// not to the success arm. The tests here run the production loop on a thread and halt
/// it, and drive `materialize` end to end so its two startup refusals are executed.
#[cfg(test)]
mod rotation_owner_tests {
    use super::*;
    use crate::clock::now_unix;
    use crate::delegated_wiring::build_delegated_signing;
    use crate::delegated_wiring::ProdDelegatedRotor;
    use crate::key_source::KeyError;
    use crate::key_source::ResponseSigner;
    use crate::startup_plan::SigningPlan;
    use crate::startup_plan::TrustEpochPlan;
    use crate::trust_epoch::EpochReadError;
    use crate::trust_epoch::EpochReader;
    use mcp_re_core::SigningKey;
    use mcp_re_core::VerificationKey;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    const ROOT_SEED: [u8; 32] = [33u8; 32];

    /// TTL and overlap one second apart, so the overlap window opens one second after
    /// issuance: the loop reaches a DUE rotation within a test's lifetime while the
    /// predecessor stays valid for the whole run, which is precisely the state the
    /// non-progress guard has to discriminate.
    const TTL: i64 = 10;
    const OVERLAP: i64 = 9;

    /// How long each loop test lets the production loop run before halting it: the
    /// one-second wait to the overlap window plus room for several backoff retries.
    const RUN_WINDOW: Duration = Duration::from_millis(2500);

    /// A root issuer that can be taken offline and that counts what it was asked to
    /// sign, so "the plane refused BEFORE minting" is checkable.
    struct SwitchableRoot {
        key: SigningKey,
        offline: Arc<AtomicBool>,
        calls: Arc<AtomicU64>,
    }

    impl ResponseSigner for SwitchableRoot {
        fn sign_response(&self, preimage: &[u8]) -> Result<String, KeyError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.offline.load(Ordering::SeqCst) {
                return Err(KeyError::NotFound("root issuer offline".into()));
            }
            self.key.sign_response(preimage)
        }
        fn response_public_key(&self) -> Result<VerificationKey, KeyError> {
            self.key.response_public_key()
        }
    }

    fn root(offline: &Arc<AtomicBool>, calls: &Arc<AtomicU64>) -> SwitchableRoot {
        SwitchableRoot {
            key: SigningKey::from_seed_bytes(&ROOT_SEED),
            offline: Arc::clone(offline),
            calls: Arc::clone(calls),
        }
    }

    /// A root that advertises one public key and signs with another.
    struct MisadvertisingRoot;

    impl ResponseSigner for MisadvertisingRoot {
        fn sign_response(&self, preimage: &[u8]) -> Result<String, KeyError> {
            SigningKey::from_seed_bytes(&[34u8; 32]).sign_response(preimage)
        }
        fn response_public_key(&self) -> Result<VerificationKey, KeyError> {
            SigningKey::from_seed_bytes(&ROOT_SEED).response_public_key()
        }
    }

    /// A shared epoch that is never readable — an outage, or a counter that regressed.
    struct UnreadableEpoch;

    impl EpochReader for UnreadableEpoch {
        fn read_epoch(&self) -> Result<i64, EpochReadError> {
            Err(EpochReadError("epoch store unreachable".into()))
        }
        fn read_state(&self) -> Result<crate::trust_epoch::EpochState, EpochReadError> {
            Err(EpochReadError("epoch store unreachable".into()))
        }
    }

    impl crate::trust_epoch::raise::EpochRaiser for UnreadableEpoch {
        fn raise_past(&self, _mark: i64, _to: i64) -> Result<i64, EpochReadError> {
            Err(EpochReadError("epoch store unreachable".into()))
        }
    }

    fn plan(epoch: TrustEpochPlan) -> SigningPlan {
        SigningPlan {
            custody: mcp_re_http_profile::CustodyConfig {
                issuer_kid: "root-kid".to_string(),
                iss: "did:example:server".to_string(),
                profile: mcp_re_http_profile::PROFILE_TAG.to_string(),
                aud: "verifier-1".to_string(),
                audience_hash: "aud-hash".to_string(),
                trust_epoch: "epoch-1".parse().expect("epoch base"),
                server_role: "server".to_string(),
                server_trust_domain: "example.com".to_string(),
                server_subject: "did:example:server".to_string(),
                window: mcp_re_http_profile::custody::DelegatedKeyWindow::of(TTL, OVERLAP)
                    .expect("0 < overlap < ttl"),
            },
            epoch,
        }
    }

    /// Run the REAL rotation loop for `RUN_WINDOW`, then raise the deployment halt and
    /// hand the rotor back so the root-invocation count survives the thread.
    fn drive_loop(
        mut rotor: ProdDelegatedRotor,
        signer: Arc<DelegatedServerSigner>,
        watch: Option<DelegatedEpochWatch>,
    ) -> ProdDelegatedRotor {
        let deployment = Arc::new(AtomicBool::new(false));
        let workers = WorkerSet::new(Arc::clone(&deployment));
        let halt = workers.halt();
        let running = std::thread::spawn(move || {
            super::rotation::rotation_loop(&mut rotor, &signer, OVERLAP, watch.as_ref(), &halt);
            rotor
        });
        std::thread::sleep(RUN_WINDOW);
        deployment.store(true, Ordering::SeqCst);
        running.join().expect("the rotation loop must not panic")
    }

    /// A root outage during the overlap window must not become a mint loop.
    ///
    /// `ensure_active` reports `Ok(())` both when a successor was minted and when
    /// issuance failed while the current key is still valid. Taking the second reading
    /// as success resets the failure count and collapses the next wake to now, so the
    /// loop re-enters at once and keeps approaching the root for the whole window.
    #[test]
    fn a_root_outage_inside_the_overlap_window_backs_off_instead_of_re_entering() {
        let offline = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(AtomicU64::new(0));
        let mut wiring = build_delegated_signing(
            &plan(TrustEpochPlan::NoNetworkChannel),
            root(&offline, &calls),
        )
        .expect("the root states its key");
        wiring
            .rotor
            .rotate(now_unix())
            .expect("the first delegated key issues");
        // The root goes away with the predecessor still valid, so every later attempt
        // is the fail-soft `Ok(())` under the unchanged kid.
        offline.store(true, Ordering::SeqCst);
        let signer = Arc::clone(&wiring.signer);
        drive_loop(wiring.rotor, Arc::clone(&signer), None);

        let metrics = signer.metrics();
        assert!(
            metrics.consecutive_failures() >= 1,
            "a DUE rotation that published no successor must count as a failure, or \
             nothing drives the backoff"
        );
        assert_eq!(
            metrics.rotations_ok(),
            0,
            "no successor was ever minted, yet {} rotations were recorded as successful: \
             the loop read a root outage as steady state",
            metrics.rotations_ok()
        );
    }

    /// An unreadable shared epoch stops the loop MINTING, rather than falling through to
    /// a rotation under a label no verifier can compare.
    #[test]
    fn an_unreadable_shared_epoch_stops_the_loop_minting() {
        let offline = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(AtomicU64::new(0));
        let mut wiring = build_delegated_signing(
            &plan(TrustEpochPlan::NoNetworkChannel),
            root(&offline, &calls),
        )
        .expect("the root states its key");
        wiring
            .rotor
            .rotate(now_unix())
            .expect("the first delegated key issues");
        assert_eq!(wiring.rotor.root_invocations(), 1);
        let signer = Arc::clone(&wiring.signer);
        // The root is HEALTHY throughout: the only thing that may stop a mint here is
        // the epoch refusal.
        let watch =
            DelegatedEpochWatch::new(Box::new(UnreadableEpoch), "epoch-1".parse().expect("base"));
        let rotor = drive_loop(wiring.rotor, Arc::clone(&signer), Some(watch));

        assert_eq!(
            rotor.root_invocations(),
            1,
            "the shared epoch was unreadable for the whole run, so nothing may be minted \
             — a credential carrying no comparable epoch is one the operator's INCR \
             cannot revoke"
        );
        assert!(
            signer.metrics().consecutive_failures() >= 1,
            "the refusal to mint must be recorded as a failure and backed off"
        );
    }

    /// A root signing under a key it does not advertise is refused at startup exactly as an
    /// offline one is, and the refusal says which of the two happened.
    #[test]
    fn a_startup_refusal_tells_an_offline_root_from_one_signing_under_another_key() {
        let offline = Arc::new(AtomicBool::new(true));
        let calls = Arc::new(AtomicU64::new(0));
        let plan = plan(TrustEpochPlan::NoNetworkChannel);
        let down = SigningPlane::materialize_over(&plan, root(&offline, &calls), now_unix())
            .err()
            .expect("an offline root issues nothing");
        assert!(down.contains("(cause=root-unavailable: "), "{down}");
        let broken = SigningPlane::materialize_over(&plan, MisadvertisingRoot, now_unix())
            .err()
            .expect("a credential the advertised key did not sign publishes nothing");
        assert!(broken.contains("(cause=root-key-mismatch: "), "{broken}");
        assert!(broken.contains("CONTRACT VIOLATION"), "{broken}");
    }

    /// Startup is fail-closed on issuance: no active delegated key, no serving.
    #[test]
    fn materialize_refuses_when_the_root_cannot_issue_the_first_key() {
        let offline = Arc::new(AtomicBool::new(true));
        let calls = Arc::new(AtomicU64::new(0));
        let err = SigningPlane::materialize_over(
            &plan(TrustEpochPlan::NoNetworkChannel),
            root(&offline, &calls),
            now_unix(),
        )
        .err()
        .expect("a proxy must not begin serving without an active delegated key");
        assert!(
            err.contains("initial delegated key issuance FAILED"),
            "the refusal must name what failed: {err}"
        );
        assert!(
            calls.load(Ordering::SeqCst) >= 1,
            "the root was never asked, so this refused for some other reason"
        );
    }

    /// The positive control for the two refusals above: a healthy root yields a plane
    /// that is actually serving-capable and owns exactly the rotation worker.
    #[test]
    fn materialize_publishes_a_usable_key_and_owns_one_rotation_worker() {
        let offline = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(AtomicU64::new(0));
        let plane = SigningPlane::materialize_over(
            &plan(TrustEpochPlan::NoNetworkChannel),
            root(&offline, &calls),
            now_unix(),
        )
        .expect("a healthy root must establish signing custody");
        assert_eq!(plane.worker_count(), 1);
        assert!(
            plane.signer().current(now_unix()).is_some(),
            "materialize must leave the hot path with a usable delegated key"
        );
    }

    /// A CONFIGURED kill switch whose counter cannot be read at startup is a refusal,
    /// not a start with the switch wired to nothing.
    #[cfg(feature = "redis_replay")]
    #[test]
    fn materialize_refuses_when_the_configured_shared_epoch_cannot_be_read() {
        // An ephemeral port, bound to learn it and released again: the URL parses, so a
        // reader is built, and every read then fails to connect — a configured source
        // that cannot be read, without a hardcoded port.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("an ephemeral port");
        let port = listener.local_addr().expect("the bound address").port();
        drop(listener);
        let offline = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(AtomicU64::new(0));
        let err = SigningPlane::materialize_over(
            &plan(TrustEpochPlan::redis(
                &format!("redis://127.0.0.1:{port}"),
                crate::trust_epoch::DEFAULT_TRUST_EPOCH_KEY,
            )),
            root(&offline, &calls),
            now_unix(),
        )
        .err()
        .expect("a kill switch that cannot be read must refuse the plane");
        assert!(
            err.contains("could NOT be read"),
            "the refusal must name the unreadable epoch: {err}"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "the refusal must precede minting: a key issued here carries an epoch the \
             operator's INCR cannot revoke"
        );
    }
}

#[cfg(test)]
mod handle_lifetime_tests {
    use super::*;
    use crate::clock::now_unix;
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;

    /// The signing child machine's terminal transition, staged through the REAL
    /// `SigningPlane::drop` (ADR-MCPRE-057 §5.2).
    ///
    /// `delegated_server_signer`'s own tests drive `retire_permanently` directly, which
    /// proves the latch works but not that teardown uses it. Here the rotor is still
    /// running when the plane is dropped, and its in-flight mint publishes during the join
    /// window `Drop` itself opens between retiring the signer and halting the worker. The
    /// interleaving is forced rather than hoped for: the rotor publishes only after
    /// observing the halt, which `Drop` raises strictly after it has retired the signer.
    ///
    /// The broken implementation this catches: `Drop` calling `retire` instead of
    /// `retire_permanently` — which is what it did, and which leaves this plane's signer
    /// holding a fresh key and a fresh `exp` that nothing rotates and no trust-epoch
    /// advance can revoke.
    #[test]
    fn a_mint_completing_inside_the_drop_join_window_cannot_restore_signing() {
        // The worker holds the rotor, as production's does, and mints once the owner has
        // gone away: a successor under an advanced epoch, a fresh key and a fresh `exp`.
        let plane = SigningPlane::for_teardown_test_with_rotor(move |halt, mut rotor| {
            while !halt.requested() {
                std::thread::sleep(Duration::from_millis(2));
            }
            let _ = rotor.advance_trust_epoch(2, now_unix());
        });
        let signer = plane.signer();
        assert!(
            signer.current(now_unix()).is_some(),
            "a live plane must publish a usable delegated key"
        );

        drop(plane);

        assert!(
            signer.current(now_unix()).is_none(),
            "a rotation that completed during teardown republished a delegated key; \
             responses would keep being signed off a key nothing rotates and no \
             trust-epoch advance can revoke"
        );
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
            workers
                .spawn("test delegated rotation", move || {
                    while !halt.requested() {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    flag.store(true, std::sync::atomic::Ordering::SeqCst);
                })
                .expect("spawn test worker");
            let rotor = crate::delegated_wiring::test_support::published(now_unix() + 3600, 3);
            let plane = SigningPlane {
                signer: rotor.signer(),
                retirement: rotor.retirement(),
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
