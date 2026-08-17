// SPDX-License-Identifier: Apache-2.0
//! The TLS plane (ADR-MCPRE-056 §8; ADR-MCPRE-051 §6): transport custody.
//!
//! Owns the server TLS configuration the accept loop hands each handshake, the
//! per-request client-revocation index, and the worker that re-reads `--client-crl`
//! without a restart.
//!
//! # A surviving snapshot may keep serving — and that is not the odd one out
//!
//! Each plane so far has answered "what does a handle do once its owner is gone?"
//! differently, and the reason is a property of the ARTIFACT, not of the plane:
//!
//! - `trust_plane`'s resolver FAILS CLOSED. A trust map carries no expiry, so a snapshot
//!   nothing re-reads would resolve a revoked key forever.
//! - `signing_plane`'s signer is RETIRED. It produces authority, and nothing is left to
//!   rotate its key or observe a trust-epoch advance.
//! - `reloading_trust::SignerDirectory` KEEPS ANSWERING. It yields an identity coordinate
//!   and admits nothing on its own.
//! - This plane's snapshot KEEPS SERVING, for a reason none of the others can claim:
//!   **every CRL this plane loads states its own `nextUpdate`** — one that omits it is
//!   refused where it is read ([`tls::crl_next_update_required`]), at startup and on
//!   every reload, because it would never fall out of force. Past `nextUpdate` the
//!   verdict for that issuer is `Unknown`,
//!   and unknown status is refused unconditionally — `allow_unknown_status` is wired to a
//!   hard `false` on every builder, with no operator knob. So a CRL nobody is refreshing
//!   converges on refusing that issuer's certificates rather than on admitting revoked
//!   ones. The artifact bounds itself; the plane does not have to.
//!
//! That is why [`Drop`] here performs no security transition. It is a deliberate
//! conclusion from the CRL's own semantics, not the absence of the question.
//!
//! Stated as the conditional it actually is:
//!
//! > A TLS snapshot may outlive its `TlsPlane`
//! >   ONLY BECAUSE its authorization-relevant validity is self-bounded,
//! >   AND unknown revocation state cannot become admissible.
//!
//! Both clauses are load-bearing and both are enforced rather than assumed. The first is
//! enforced by refusing a CRL with no `nextUpdate`, pinned by `tls`'s
//! `crl_next_update_tests`; the second is pinned by `client_revocation`'s
//! `an_expired_crl_refuses_its_issuer_rather_than_admitting_it`, which also asserts the
//! counterfactual. **Introducing an operator knob for `allow_unknown_status` means
//! re-deriving this contract before the change lands** — with unknown admissible, a
//! surviving snapshot becomes exactly the frozen authorization state `trust_plane` fails
//! closed to avoid.
//!
//! A failed reload keeps the last-good configuration, for the same reason
//! `reloading_trust` does: a truncated file mid-write must not empty what is enforced.

use std::sync::Arc;
use std::time::Duration;

use crate::client_revocation;
use crate::config_snapshot;
use crate::managed_worker::WorkerSet;
use crate::tls;

/// The client-CRL facts observed at startup, in configuration order.
///
/// Parsed once, by the plane that had to parse them anyway, so the startup posture
/// renders facts rather than re-deriving them from DER it would have to re-open.
pub struct ClientCrlEvidence {
    /// One entry per loaded CRL. Empty when offline client-cert revocation is not
    /// configured, which is a different posture — not an empty one.
    pub postures: Vec<tls::CrlPosture>,
}

impl ClientCrlEvidence {
    /// Whether offline client-cert revocation is configured at all.
    pub fn is_empty(&self) -> bool {
        self.postures.is_empty()
    }
}

/// The serving state that must SURVIVE a `ServerConfig` rebuild, created once per plane
/// and handed to every build.
///
/// Both members bound something that is a RATE or an accumulation, so re-creating either
/// on the reload cadence resets what it bounds:
///
/// - `resumption` holds the TLS session cache and the trust epoch in force. A per-build
///   cache is emptied on every reload — a fleet-wide full-handshake storm on the cadence
///   — and a per-build epoch can never advance, which leaves the epoch-mismatch eviction
///   with no live input.
/// - `sign_budget` bounds how fast unauthenticated peers can drive a remote, billed,
///   account-throttled TLS handshake signer. A per-build bucket is refilled to full on
///   every reload, so it bounds a window rather than a rate.
struct TlsRebuildState {
    resumption: Arc<crate::tls_auth_epoch::EpochBoundSessionStore>,
    sign_budget: Arc<crate::delegated_tls::TlsHandshakeSignBudget>,
}

/// Transport custody: the serving TLS configuration and what keeps it current.
pub struct TlsPlane {
    snapshot: Arc<config_snapshot::ServerConfigSnapshot>,
    revocation: Option<Arc<client_revocation::SharedClientRevocation>>,
    crls: ClientCrlEvidence,
    is_delegated: bool,
    /// Owns the CRL reload worker. Halted in [`Drop`]; see the module note on why no
    /// security transition accompanies it.
    workers: WorkerSet,
}

impl TlsPlane {
    /// The snapshot the accept loop re-reads per connection, so a reload is observed by
    /// the next handshake rather than written where nothing looks again.
    pub fn snapshot(&self) -> Arc<config_snapshot::ServerConfigSnapshot> {
        Arc::clone(&self.snapshot)
    }

    /// The per-request revocation index, or `None` when no CRLs are configured.
    ///
    /// `None` is not "admit everything": with no CRLs rustls performs no revocation
    /// checking either, and installing an index would put a check on the request path
    /// that the handshake does not perform.
    pub fn revocation(&self) -> Option<Arc<client_revocation::SharedClientRevocation>> {
        self.revocation.clone()
    }

    /// The client-CRL facts, for the startup posture.
    pub fn crls(&self) -> &ClientCrlEvidence {
        &self.crls
    }

    /// Whether the handshake signature goes through a non-exporting device/KMS.
    ///
    /// Read by the serving runtime shape: a delegated signer blocks inside rustls'
    /// synchronous `Signer::sign`, so each core needs a worker pool rather than the
    /// single-threaded share-nothing default. Exposed as a fact because the material it
    /// describes is moved into the reload worker.
    pub fn is_delegated(&self) -> bool {
        self.is_delegated
    }

    /// Number of workers this plane owns. For the lifecycle tests.
    #[cfg(test)]
    pub fn worker_count(&self) -> usize {
        self.workers.len()
    }

    /// A plane over a self-signed, server-only TLS configuration whose single worker runs
    /// `body`, for the ownership and teardown tests.
    ///
    /// No CRLs and no revocation index: this plane's teardown obligation is halting its
    /// worker, and neither of those bears on it. `body` receives the worker's
    /// [`Halt`](crate::managed_worker::Halt), so a test picks a worker that stops when
    /// asked, one that ignores the halt, or one that panics.
    #[cfg(test)]
    pub(crate) fn for_teardown_test(
        body: impl FnOnce(crate::managed_worker::Halt) + Send + 'static,
    ) -> Self {
        use rustls::pki_types::PrivateKeyDer;
        use rustls::pki_types::PrivatePkcs8KeyDer;

        let key = rcgen::KeyPair::generate().expect("key");
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
        let cert = params.self_signed(&key).expect("self-signed");
        let server = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .expect("server config");

        let mut workers = WorkerSet::new(Arc::new(std::sync::atomic::AtomicBool::new(false)));
        let halt = workers.halt();
        workers.spawn("test crl reload", move || body(halt));
        TlsPlane {
            snapshot: Arc::new(config_snapshot::ServerConfigSnapshot::new(Arc::new(server))),
            revocation: None,
            crls: ClientCrlEvidence {
                postures: Vec::new(),
            },
            is_delegated: false,
            workers,
        }
    }
}

impl Drop for TlsPlane {
    fn drop(&mut self) {
        // No security transition, unlike `trust_plane` and `signing_plane`. See the
        // module note: a CRL past its own `nextUpdate` yields `Unknown`, and unknown is
        // refused unconditionally, so a snapshot nobody refreshes converges on refusing
        // rather than on admitting. Halting the worker is the whole obligation.
        self.workers.halt_and_reclaim();
    }
}

impl TlsPlane {
    /// Establish transport custody: load and check the CRLs, build the serving TLS
    /// configuration, and start the reload worker when a cadence is configured.
    ///
    /// Takes a [`TlsPlan`](crate::startup_plan::TlsPlan) and no configuration. Which
    /// revocation posture and which custody this deployment is in were decided by layer A;
    /// what is left here is loading the bytes, building the verifier and starting the
    /// worker the posture calls for.
    ///
    /// `material` is MOVED in — the reload worker rebuilds the verifier from the same
    /// immutable key material, so nothing outside this plane may keep a second copy. It is
    /// the ESTABLISHED custody, and the plan states the REQUESTED one; the two are checked
    /// against each other below rather than assumed to agree.
    pub fn materialize(
        plan: &crate::startup_plan::TlsPlan,
        material: TlsKeyMaterial,
        server_chain: Vec<rustls_pki_types::CertificateDer<'static>>,
        client_ca: Vec<rustls_pki_types::CertificateDer<'static>>,
        startup_now_unix: i64,
        deployment: Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<TlsPlane, String> {
        let is_delegated = material.is_delegated();
        // The one place the REQUESTED custody and the ESTABLISHED custody meet. Layer A
        // classified which the deployment asked for from its TLS key selectors; the key
        // source produced an actual signer. Nothing else compares them, so a divergence —
        // a selector that classifies as delegated while the key source yields an exported
        // key — would silently serve handshakes under weaker custody than the deployment
        // declared, and every startup line would report the declared one.
        if is_delegated != plan.custody.is_delegated() {
            return Err(format!(
                "TLS custody mismatch: the deployment is configured for {} handshake custody, \
                 but the key source established {} custody. Refusing to serve under a custody \
                 the configuration does not name",
                if plan.custody.is_delegated() {
                    "delegated"
                } else {
                    "exported-key"
                },
                material.label(),
            ));
        }
        // Offline client-cert CRLs (#3839). Loaded once at startup; a missing or
        // malformed CRL file fails closed here. OFFLINE revocation only — there is no
        // online OCSP / distribution-point fetching.
        let crl_paths = plan.client_revocation.paths();
        let client_crls = tls::load_client_crls(crl_paths)?;
        let mut postures = Vec::with_capacity(client_crls.len());
        if !client_crls.is_empty() {
            eprintln!(
                "mcp-re-proxy: offline client-cert revocation enabled — {} CRL file(s), unknown \
                 status DENIED (fail closed) (OFFLINE only; no online OCSP/CRL-DP fetching)",
                crl_paths.len(),
            );
            // ADR-MCPS-023 §A1 (MCPS-58): the verifier enforces CRL nextUpdate, so a
            // stale CRL fails every new handshake closed. Surface that at BOOT — refuse
            // to start on a stale CRL — and warn while a CRL is near expiry so a
            // refreshed CRL can be installed before the cutover. A malformed CRL is a
            // hard startup error (fail closed).
            const CRL_NEAR_EXPIRY_WARN_SECS: i64 = 6 * 3600;
            for (i, crl) in client_crls.iter().enumerate() {
                match tls::crl_freshness(crl.as_ref(), startup_now_unix, CRL_NEAR_EXPIRY_WARN_SECS)
                    .map_err(|e| e.to_string())?
                {
                    tls::CrlFreshness::Fresh => {}
                    tls::CrlFreshness::NoNextUpdate => {
                        tls::crl_next_update_required(crl.as_ref(), i).map_err(|e| {
                            format!(
                                "mcp-re-proxy refuses to start with a client CRL that never \
                                 falls out of force: {e}"
                            )
                        })?;
                    }
                    tls::CrlFreshness::NearExpiry { next_update_unix } => eprintln!(
                        "mcp-re-proxy: WARNING: client CRL #{i} is near expiry \
                         (nextUpdate={next_update_unix}); install a refreshed CRL and restart \
                         before then, or new handshakes will fail closed."
                    ),
                    tls::CrlFreshness::Stale { next_update_unix } => {
                        let msg = format!(
                            "client CRL #{i} is STALE (nextUpdate={next_update_unix} <= \
                             now={startup_now_unix}): with CRL expiration enforced, every new \
                             client handshake fails closed. Install a CRL published within its \
                             nextUpdate window."
                        );
                        return Err(format!(
                            "mcp-re-proxy refuses to start with a stale client CRL: {msg}"
                        ));
                    }
                }
            }
            // Parsed here, once, and carried as facts. Freshness is checked first, above,
            // so a stale CRL still refuses startup with its own diagnostic rather than
            // being reported as posture.
            for crl in &client_crls {
                postures.push(tls::crl_posture(crl.as_ref()).map_err(|e| e.to_string())?);
            }
        }
        let crls = ClientCrlEvidence { postures };

        // Cloned because the initial build below consumes the originals; the reload
        // re-reads only the CRLs, never these.
        let reload_chain = server_chain.clone();
        let reload_client_ca = client_ca.clone();
        let reload_crl_paths = crl_paths.to_vec();
        // The CRL verifier ALWAYS fails closed on an unknown revocation status — there
        // is no relax knob. `false` = deny-unknown, threaded to every verifier builder,
        // and the module note's self-bounding argument depends on it staying that way.
        let reload_allow_unknown = false;

        // The PER-REQUEST revocation index, built from the same CRL bytes the handshake
        // verifier is about to be given. Without this, revocation reaches only NEW
        // connections: rustls runs client authentication on a full handshake alone, so a
        // peer added to a reloaded CRL keeps serving every request on the connection it
        // already holds.
        let revocation = if client_crls.is_empty() {
            None
        } else {
            let index = client_revocation::ClientRevocationIndex::from_crl_ders(
                &client_crls
                    .iter()
                    .map(|crl| crl.as_ref().to_vec())
                    .collect::<Vec<_>>(),
                reload_allow_unknown,
            )
            .map_err(|e| e.to_string())?;
            Some(Arc::new(client_revocation::SharedClientRevocation::new(
                index,
            )))
        };

        // Created once, before the first build, and handed to every later one: the
        // session cache and the trust epoch survive a reload, and so does the delegated
        // handshake-signature bucket.
        let rebuild_state = Arc::new(TlsRebuildState {
            resumption: tls::new_resumption_state(&client_ca, reload_allow_unknown),
            sign_budget: Arc::new(crate::delegated_tls::TlsHandshakeSignBudget::default()),
        });

        // The same construction a CRL reload performs, so the serving config a reload
        // installs cannot diverge from the one startup installed.
        let server_config =
            material.rebuild(server_chain, client_ca, client_crls, false, &rebuild_state)?;
        // ADR-MCPRE-051 §6 (MCPRE-116): the serve loop reads the current config from a
        // versioned, atomically-swappable snapshot instead of a fixed `Arc`. With no
        // `--client-crl-reload-secs` the snapshot is never swapped, so behavior is
        // byte-identical to the static posture.
        let snapshot = Arc::new(config_snapshot::ServerConfigSnapshot::new(Arc::new(
            server_config,
        )));

        let mut workers = WorkerSet::new(deployment);
        // Only the `Reloading` posture starts a worker, and the cadence comes from that
        // variant rather than from an `Option` beside it.
        //
        // There was a branch here for a cadence with no CRLs, which printed "no CRL reload
        // scheduled" and carried on. It is gone because it is now unreachable: that
        // combination is refused at the boundary (CF-04 — a cadence for re-reading an empty
        // set states a control the deployment does not have). The same shape as
        // `ReplayPlan::Memory` — a branch that survived because nothing had ever asked
        // whether a configuration could reach it.
        if let crate::startup_plan::ClientRevocationPlan::Reloading {
            paths: _,
            cadence_secs,
        } = &plan.client_revocation
        {
            let custody = material.label();
            spawn_crl_reload_task(
                &mut workers,
                CrlReloadTask {
                    snapshot: Arc::clone(&snapshot),
                    server_chain: reload_chain,
                    material,
                    client_ca: reload_client_ca,
                    crl_paths: reload_crl_paths,
                    allow_unknown_status: reload_allow_unknown,
                    interval_secs: *cadence_secs,
                    revocation: revocation.clone(),
                    rebuild_state: Arc::clone(&rebuild_state),
                },
            );
            eprintln!(
                "mcp-re-proxy: in-process CRL hot-reload enabled (every {cadence_secs}s, \
                 {custody} TLS custody; refreshed --client-crl honored without restart; \
                 failed reload keeps last-good)"
            );
        }
        Ok(TlsPlane {
            snapshot,
            revocation,
            crls,
            is_delegated,
            workers,
        })
    }
}

/// ADR-MCPRE-051 §6 (MCPRE-116): the in-process CRL hot-reload task. Every
/// `interval_secs` it re-reads the `--client-crl` files and rebuilds the direct-TLS
/// verifier from the SAME immutable server key material, atomically swapping the
/// result into `snapshot`. A read/parse/build failure keeps the last-good config
/// (which still fails closed once its CRL passes `nextUpdate`), so a bad reload
/// never widens what is accepted. The task observes `SHUTDOWN` between naps so it
/// exits promptly on a rolling deploy. Spawned only when `--client-crl-reload-secs`
/// is set with a non-empty `--client-crl` on the direct-TLS path.
/// The TLS server key the verifier is rebuilt around, under either custody.
///
/// A CRL reload re-reads only the CRLs; this is carried verbatim across the rebuild.
/// Both variants exist so the reload does not depend on which custody the deployment
/// chose — a revocation control that works only on the weaker custody is the wrong way
/// round.
pub enum TlsKeyMaterial {
    /// The exported private key read from disk.
    Exported(rustls_pki_types::PrivateKeyDer<'static>),
    /// A non-exporting device/KMS signer (PKCS#11, AWS KMS, Cloud KMS).
    Delegated(Arc<dyn crate::delegated_tls::RawEd25519TlsSigner>),
}

impl TlsKeyMaterial {
    /// Whether the handshake signature goes through a non-exporting device/KMS.
    ///
    /// The serving runtime shape depends on this: a delegated signer blocks inside
    /// rustls' synchronous `Signer::sign`, so each core needs a worker pool rather than
    /// the single-threaded share-nothing default.
    fn is_delegated(&self) -> bool {
        matches!(self, TlsKeyMaterial::Delegated(_))
    }

    /// The custody word for the operator-facing startup line.
    fn label(&self) -> &'static str {
        match self {
            TlsKeyMaterial::Exported(_) => "exported-key",
            TlsKeyMaterial::Delegated(_) => "delegated",
        }
    }

    /// Rebuild the serving config around `crls`, under whichever custody applies.
    fn rebuild(
        &self,
        server_chain: Vec<rustls_pki_types::CertificateDer<'static>>,
        client_ca: Vec<rustls_pki_types::CertificateDer<'static>>,
        crls: Vec<rustls_pki_types::CertificateRevocationListDer<'static>>,
        allow_unknown_status: bool,
        state: &TlsRebuildState,
    ) -> Result<rustls::ServerConfig, String> {
        match self {
            TlsKeyMaterial::Exported(key) => {
                tls::RustlsDirectProvider::build_server_config_with_crls_resuming(
                    server_chain,
                    key.clone_key(),
                    client_ca,
                    crls,
                    allow_unknown_status,
                    &state.resumption,
                )
                .map_err(|e| e.to_string())
            }
            TlsKeyMaterial::Delegated(signer) => {
                tls::build_server_config_delegated_validated_resuming(
                    server_chain,
                    Arc::clone(signer),
                    client_ca,
                    crls,
                    allow_unknown_status,
                    &state.resumption,
                    &state.sign_budget,
                )
                .map_err(|e| e.to_string())
            }
        }
    }
}

struct CrlReloadTask {
    snapshot: Arc<config_snapshot::ServerConfigSnapshot>,
    /// The immutable server key material the verifier is rebuilt from; a reload
    /// re-reads only the CRLs, never these.
    server_chain: Vec<rustls_pki_types::CertificateDer<'static>>,
    material: TlsKeyMaterial,
    client_ca: Vec<rustls_pki_types::CertificateDer<'static>>,
    crl_paths: Vec<String>,
    allow_unknown_status: bool,
    interval_secs: u64,
    /// The per-request revocation index, republished from the same re-read bytes as
    /// the rebuilt verifier. Rebuilding only the verifier would leave the reload
    /// reaching new connections alone — which is the gap the per-request check exists
    /// to close.
    revocation: Option<Arc<client_revocation::SharedClientRevocation>>,
    /// The session cache, trust epoch and handshake-signature budget the rebuilt config
    /// is wired to — the same ones startup built, so a reload neither empties the cache
    /// nor refills the bucket.
    rebuild_state: Arc<TlsRebuildState>,
}
/// SUPERVISED like the trust reload and the rotation owner: nothing joins this thread,
/// and a panic in it would silently stop CRL reloading for the process lifetime.
///
/// Unlike the trust store, a stale CRL index bounds ITSELF — a CRL past its `nextUpdate`
/// covers nothing, so its issuer's certificates become `Unknown` and are refused. A
/// failed reload therefore never widens what is accepted, and the escalation here is a
/// loud operator signal rather than a second fail-closed transition.
fn spawn_crl_reload_task(workers: &mut crate::managed_worker::WorkerSet, task: CrlReloadTask) {
    let halt = workers.halt();
    workers.spawn("client CRL reload", move || {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crl_reload_loop(task, &halt);
        }));
        if outcome.is_err() {
            eprintln!(
                "mcp-re-proxy: FATAL: the client-CRL reload thread PANICKED. --client-crl is no \
                 longer being re-read, so a newly revoked client certificate reaches this replica \
                 only when its CRL passes nextUpdate (after which that issuer's certificates are \
                 refused outright). This replica cannot recover on its own — restart it."
            );
        }
    });
}

/// The CRL reload loop proper. Split out so the supervisor above can catch a panic.
fn crl_reload_loop(task: CrlReloadTask, halt: &crate::managed_worker::Halt) {
    let CrlReloadTask {
        snapshot,
        server_chain,
        material,
        client_ca,
        crl_paths,
        allow_unknown_status,
        interval_secs,
        revocation,
        rebuild_state,
    } = task;
    {
        let mut consecutive_failures: u32 = 0;
        loop {
            // Naps in small increments, so a halt is observed within one increment
            // rather than after a whole reload interval.
            if halt.sleep(Duration::from_secs(interval_secs)) {
                return;
            }
            let outcome = config_snapshot::reload_once(&snapshot, || {
                let crls = tls::load_client_crls(&crl_paths)?;
                // A CRL that never falls out of force is refused on reload for the same
                // reason it is refused at startup: keeping last-good is only safe while
                // last-good ages out on its own.
                for (i, crl) in crls.iter().enumerate() {
                    tls::crl_next_update_required(crl.as_ref(), i).map_err(|e| e.to_string())?;
                }
                // Build the per-request index from the SAME bytes, BEFORE the verifier
                // is rebuilt, so a malformed CRL keeps last-good on both rather than
                // swapping one and failing the other.
                let index = client_revocation::ClientRevocationIndex::from_crl_ders(
                    &crls
                        .iter()
                        .map(|crl| crl.as_ref().to_vec())
                        .collect::<Vec<_>>(),
                    allow_unknown_status,
                )
                .map_err(|e| e.to_string())?;
                let rebuilt = material.rebuild(
                    server_chain.clone(),
                    client_ca.clone(),
                    crls,
                    allow_unknown_status,
                    &rebuild_state,
                )?;
                if let Some(revocation) = revocation.as_ref() {
                    revocation.store(index);
                }
                Ok(Arc::new(rebuilt))
            });
            match outcome {
                config_snapshot::ReloadOutcome::Swapped => {
                    let recovered = consecutive_failures > 0;
                    consecutive_failures = 0;
                    if recovered {
                        eprintln!(
                            "mcp-re-proxy: client CRL reload RECOVERED; new verifier and \
                             per-request index are live"
                        );
                    } else {
                        eprintln!("mcp-re-proxy: client CRL reloaded; new verifier is live");
                    }
                }
                config_snapshot::ReloadOutcome::KeptLastGood { reason } => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    eprintln!(
                        "mcp-re-proxy: WARNING: client CRL reload FAILED {consecutive_failures}x \
                         in a row, keeping last-good config: {reason}. Newly revoked certificates \
                         are NOT reaching this replica; when the last-good CRL passes its \
                         nextUpdate its issuer's certificates are refused outright."
                    );
                }
            }
        }
    }
}

/// ADR-MCPS-023 §A1 (MCPS-58) — the operator-visible revocation posture, as lines.
///
/// A posture DIAGNOSTIC, not a structured per-request audit guarantee: the structured
/// evidence vocabulary (including `delegated_attestor_crl`, which does not exist yet)
/// lands with Mode C attested ingress (MCPS-62). The canonical ADR field names are used
/// deliberately so that future audit surface can reuse them verbatim. OCSP posture is
/// per-request — no-AIA is a per-cert fact, not a config-load one — and likewise belongs
/// to the MCPS-62 surface rather than to a startup line.
///
/// Returns lines instead of printing them, which is the whole reason it is here: these
/// were ~50 lines of `eprintln!` inside the composition root, where the only way to check
/// what an operator is told was to read a transcript. Rendering the facts the plane
/// already parsed makes the posture assertable (`posture_tests` below) and takes
/// domain-specific posture construction off the root (ADR-MCPRE-058 §7.1).
///
/// Takes the plan AND the evidence, and the split is not incidental: the exposure window
/// is a statement about what was CONFIGURED, while `per_request_crl_check` is a statement
/// about what was actually LOADED and is being enforced. Rendering the second from the
/// plan would report a mechanism as enforced because it was asked for.
pub(crate) fn revocation_posture_lines(
    plan: &crate::startup_plan::TlsPlan,
    crls: &ClientCrlEvidence,
) -> Vec<String> {
    let exposure_window = match plan.max_client_cert_lifetime {
        Some(d) => format!("{}s", d.as_secs()),
        None => "unbounded".to_string(),
    };
    // The exposure window above is only true because these two bounds hold: the
    // certificate is re-checked against the clock on EVERY request (not just at the
    // handshake), and a connection is closed at a bounded age so the peer must
    // re-handshake through the current CRL. Stated alongside the window it makes honest.
    let mut lines = vec![format!(
        "mcp-re.revocation.posture connection_max_age={} per_request_cert_validity=enforced \
         per_request_crl_check={} tls_session_resumption=epoch-bound",
        match plan.max_connection_age {
            Some(d) => format!("{}s", d.as_secs()),
            None => "unbounded".to_string(),
        },
        // The claim the CRL lines below rest on. rustls consults the CRLs during client
        // authentication, which runs on a full handshake only, so without this a revoked
        // peer serves every later request on the connection it already holds and the
        // reload cadence below describes new connections alone.
        if crls.is_empty() {
            "not_configured"
        } else {
            "enforced"
        }
    )];
    if crls.is_empty() {
        let max_lifetime = match plan.max_client_cert_lifetime {
            Some(d) => format!("{}s", d.as_secs()),
            None => "none".to_string(),
        };
        lines.push(format!(
            "mcp-re.revocation.posture revocation_mode=short_lived_cert dynamic_revocation=false \
             exposure_window={exposure_window} max_client_cert_lifetime={max_lifetime}"
        ));
    } else {
        // Facts parsed once by the plane that loaded the CRLs, rendered here.
        for (i, posture) in crls.postures.iter().enumerate() {
            let next_update = posture
                .next_update_unix
                .map(|n| n.to_string())
                .unwrap_or_else(|| "none".to_string());
            lines.push(format!(
                "mcp-re.revocation.posture revocation_mode=static_crl_snapshot \
                 dynamic_revocation=false stale_crl_policy=fail_closed crl_index={i} \
                 crl_digest={} crl_this_update={} crl_next_update={} \
                 exposure_window={exposure_window}",
                posture.crl_digest, posture.this_update_unix, next_update
            ));
        }
    }
    lines
}

/// The client-certificate half of the fleet's cross-replica revocation-lag bound
/// (ADR-MCPS-049 clause 3): how long a revoked client certificate can still be accepted
/// somewhere in the fleet.
///
/// The sibling of `trust_plane::fleet_trust_bound`, and pure for the same reason — this is
/// a derived SECURITY CLAIM, not a rendering detail. It was computed inline in the
/// composition root while its sibling was already a named, tested function, so one half of
/// one operator-facing statement had a home and the other did not.
///
/// Zero-window revocation is never claimed on either half. Each arm names what actually
/// bounds the exposure:
///
/// - no CRL at all: only the client-cert lifetime bounds it;
/// - a CRL with a reload cadence: the cadence IS the bound, and it applies per request on
///   established connections as well as at the handshake, so a peer holding a connection
///   open does not escape a republished index;
/// - a CRL without a cadence: the CRL's own `nextUpdate`, or a restart.
///
/// One `match` over the classified posture, where it was three parameters and two nested
/// conditionals. The arms are the states, so a fourth posture would not compile until it
/// stated its own bound — which is the property this claim most needs, since a posture
/// falling through to another's sentence is exactly how an operator gets a number that
/// nothing enforces.
pub fn fleet_crl_bound(plan: &crate::startup_plan::TlsPlan) -> String {
    use crate::startup_plan::ClientRevocationPlan;
    match &plan.client_revocation {
        ClientRevocationPlan::None => {
            let window = plan
                .max_client_cert_lifetime
                .map(|d| format!("{}s", d.as_secs()))
                .unwrap_or_else(|| "unbounded".to_string());
            format!("short-lived-cert only (exposure_window {window}); no client CRL")
        }
        ClientRevocationPlan::Reloading { cadence_secs, .. } => format!(
            "bounded {cadence_secs}s (the --client-crl-reload-secs cadence), enforced per \
             request on established connections as well as at the handshake"
        ),
        ClientRevocationPlan::Static { .. } => {
            "the CRL nextUpdate / a restart (no --client-crl-reload-secs) — a fleet's \
             CRL-rollout window"
                .to_string()
        }
    }
}

#[cfg(test)]
mod handle_lifetime_tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;

    /// A plane over a snapshot and one worker that only waits to be halted — enough to
    /// assert the ownership relationship without standing up TLS material.
    fn plane(config: Arc<rustls::ServerConfig>, observed: Arc<AtomicBool>) -> TlsPlane {
        let mut workers = WorkerSet::new(Arc::new(AtomicBool::new(false)));
        let halt = workers.halt();
        workers.spawn("test client CRL reload", move || {
            while !halt.requested() {
                std::thread::sleep(Duration::from_millis(5));
            }
            observed.store(true, Ordering::SeqCst);
        });
        TlsPlane {
            snapshot: Arc::new(config_snapshot::ServerConfigSnapshot::new(config)),
            revocation: None,
            crls: ClientCrlEvidence { postures: vec![] },
            is_delegated: false,
            workers,
        }
    }

    /// The DELIBERATE non-transition, asserted so it reads as a decision.
    ///
    /// A snapshot that outlives its reload worker keeps serving, unlike `trust_plane`'s
    /// resolver and `signing_plane`'s signer. The justification is the CRL's own
    /// `nextUpdate` plus unconditional refusal of unknown status — not an oversight, and
    /// not a property this test can prove on its own. What it does pin is that the plane
    /// makes no attempt to invalidate the snapshot, so a future change that starts
    /// relying on one has to come here first.
    #[test]
    fn a_snapshot_that_outlives_the_plane_still_serves() {
        let observed = Arc::new(AtomicBool::new(false));
        let snapshot;
        {
            let plane = plane(test_server_config(), Arc::clone(&observed));
            assert_eq!(plane.worker_count(), 1);
            snapshot = plane.snapshot();
            assert!(
                Arc::strong_count(&snapshot.load()) > 0,
                "a live plane must publish a serving config"
            );
        }
        assert!(
            observed.load(Ordering::SeqCst),
            "the CRL reload worker did not observe the structural halt"
        );
        // Still serving: the artifact bounds itself through its CRLs' own nextUpdate,
        // so the plane performs no fail-closed transition here.
        let _still_serving = snapshot.load();
    }

    /// A minimal self-signed server-only config, built in-process — the plane's
    /// lifecycle does not depend on what is in it, only on who owns it. Same idiom as
    /// `config_snapshot`'s own tests.
    fn test_server_config() -> Arc<rustls::ServerConfig> {
        use rustls::crypto::ring;
        use rustls::pki_types::PrivateKeyDer;
        use rustls::pki_types::PrivatePkcs8KeyDer;
        let key = rcgen::KeyPair::generate().expect("key");
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
        let cert = params.self_signed(&key).expect("self-signed");
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("versions")
                .with_no_client_auth()
                .with_single_cert(vec![cert.der().clone()], key_der)
                .expect("server config"),
        )
    }
}

/// The fleet's client-cert revocation-lag claim, tested as a derived security fact rather
/// than as rendering. Separate from `handle_lifetime_tests`, which is about what a handle
/// means after its plane is gone — a different question entirely.
/// What the revocation posture actually tells an operator.
///
/// These lines were `eprintln!`s in the composition root, which meant the only way to
/// check them was to start a proxy and read stderr — so nothing checked them. The
/// extraction is what makes the assertions below possible, and each one pins a claim that
/// would be materially misleading if it drifted.
#[cfg(test)]
mod revocation_posture_tests {
    use super::revocation_posture_lines;
    use super::ClientCrlEvidence;
    use crate::startup_plan::{ClientRevocationPlan, TlsPlan};
    use crate::tls::CrlPosture;

    /// A plan with no CRLs and the given client-cert lifetime.
    ///
    /// Written out rather than parsed. These assert what an operator is TOLD about a
    /// posture, and a posture is nameable directly now instead of being assembled out of a
    /// whole command line around two fields.
    fn plan(max_client_cert_lifetime: Option<std::time::Duration>) -> TlsPlan {
        TlsPlan {
            custody: crate::config_state::TlsCustodyState::Exported {
                key_path: "/key".to_string(),
            },
            client_revocation: ClientRevocationPlan::None,
            max_client_cert_lifetime,
            max_connection_age: Some(std::time::Duration::from_secs(300)),
        }
    }

    fn no_crls() -> ClientCrlEvidence {
        ClientCrlEvidence { postures: vec![] }
    }

    /// Without a CRL the posture must say `per_request_crl_check=not_configured`.
    ///
    /// The broken implementation this catches: reporting `enforced` whenever the field is
    /// emitted at all. `enforced` is the claim the exposure-window line rests on — that a
    /// peer holding an open connection is still re-checked — and asserting it with no CRL
    /// loaded would describe a mechanism that is not running.
    #[test]
    fn with_no_crl_the_per_request_check_is_reported_as_not_configured() {
        let lines = revocation_posture_lines(&plan(None), &no_crls());
        assert!(
            lines[0].contains("per_request_crl_check=not_configured"),
            "got: {}",
            lines[0]
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("revocation_mode=short_lived_cert")),
            "with no CRL the only mechanism is the certificate lifetime: {lines:?}"
        );
    }

    /// A disabled client-cert lifetime must render as `unbounded`, never as a number and
    /// never omitted.
    ///
    /// It is the posture `unsafe_config_violations` refuses, so if it ever reaches a
    /// transcript it has to name the thing that should have been impossible. A default
    /// substituted here would hide exactly that.
    #[test]
    fn a_disabled_certificate_lifetime_renders_as_unbounded() {
        let lines = revocation_posture_lines(&plan(None), &no_crls());
        assert!(
            lines
                .iter()
                .any(|l| l.contains("exposure_window=unbounded")),
            "got: {lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("max_client_cert_lifetime=none")),
            "got: {lines:?}"
        );
    }

    /// One line per loaded CRL, each carrying that CRL's own digest and validity window.
    ///
    /// The broken implementation this catches: rendering only the first CRL, or reusing
    /// one digest across all of them. An operator reading the transcript is checking that
    /// the index they published is the index this replica loaded, and a collapsed list
    /// answers that question wrongly rather than not at all.
    #[test]
    fn every_loaded_crl_reports_its_own_digest_and_window() {
        let crls = ClientCrlEvidence {
            postures: vec![
                CrlPosture {
                    crl_digest: "sha256:AAAA".to_string(),
                    this_update_unix: 1_700_000_000,
                    next_update_unix: Some(1_700_086_400),
                },
                CrlPosture {
                    crl_digest: "sha256:BBBB".to_string(),
                    this_update_unix: 1_700_000_001,
                    // RFC 5280 permits omission, and the line must not invent one.
                    next_update_unix: None,
                },
            ],
        };
        let lines =
            revocation_posture_lines(&plan(Some(std::time::Duration::from_secs(3600))), &crls);
        assert!(
            lines[0].contains("per_request_crl_check=enforced"),
            "got: {}",
            lines[0]
        );
        let crl_lines: Vec<&String> = lines
            .iter()
            .filter(|l| l.contains("revocation_mode=static_crl_snapshot"))
            .collect();
        assert_eq!(crl_lines.len(), 2, "one line per CRL: {lines:?}");
        assert!(crl_lines[0].contains("crl_index=0") && crl_lines[0].contains("sha256:AAAA"));
        assert!(crl_lines[1].contains("crl_index=1") && crl_lines[1].contains("sha256:BBBB"));
        assert!(
            crl_lines[1].contains("crl_next_update=none"),
            "an absent nextUpdate must say so, not be invented: {}",
            crl_lines[1]
        );
    }
}

/// The one place the REQUESTED custody and the ESTABLISHED custody meet.
#[cfg(test)]
mod custody_agreement_tests {
    use super::*;
    use crate::startup_plan::{ClientRevocationPlan, TlsPlan};

    fn exported_material() -> TlsKeyMaterial {
        use rustls::pki_types::PrivateKeyDer;
        use rustls::pki_types::PrivatePkcs8KeyDer;
        let key = rcgen::KeyPair::generate().expect("key");
        TlsKeyMaterial::Exported(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            key.serialize_der(),
        )))
    }

    fn plan(custody: crate::config_state::TlsCustodyState) -> TlsPlan {
        TlsPlan {
            custody,
            client_revocation: ClientRevocationPlan::None,
            max_client_cert_lifetime: None,
            max_connection_age: None,
        }
    }

    /// A deployment configured for delegated handshake custody must not be served by an
    /// exported key.
    ///
    /// Nothing else compares these. Layer A classifies the custody from the TLS key
    /// selectors; the key source produces an actual signer; and every startup line reports
    /// the DECLARED custody. A divergence would therefore serve handshakes under weaker
    /// custody than the transcript claims — the failure would be invisible in exactly the
    /// place an operator looks.
    #[test]
    fn a_key_source_that_disagrees_with_the_declared_custody_refuses() {
        let err = TlsPlane::materialize(
            &plan(crate::config_state::TlsCustodyState::Delegated {
                selector: crate::config_state::DelegatedTlsKey::Pkcs11 {
                    key_label: "tls".to_string(),
                },
            }),
            exported_material(),
            Vec::new(),
            Vec::new(),
            0,
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )
        .err()
        .expect("mismatched custody must refuse");
        assert!(err.contains("custody"), "{err}");
        assert!(
            err.contains("delegated") && err.contains("exported-key"),
            "the refusal must name both sides: {err}"
        );
    }

    /// Negative control: agreement is not refused. Without this the assertion above would
    /// pass just as well if `materialize` refused everything.
    ///
    /// It fails later — on the empty certificate chain — which is the point: the custody
    /// check is not what stops it, and the diagnostic proves which check ran.
    #[test]
    fn agreeing_custody_passes_the_check_and_fails_on_something_else() {
        let err = TlsPlane::materialize(
            &plan(crate::config_state::TlsCustodyState::Exported {
                key_path: "/key".to_string(),
            }),
            exported_material(),
            Vec::new(),
            Vec::new(),
            0,
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )
        .err()
        .expect("an empty chain cannot build a server config");
        assert!(
            !err.contains("custody mismatch"),
            "agreeing custody must pass the check: {err}"
        );
    }
}

#[cfg(test)]
mod fleet_crl_bound_tests {
    use super::fleet_crl_bound;
    use crate::startup_plan::{ClientRevocationPlan, TlsPlan};

    /// A plan in the posture under test. The postures are enumerated as VARIANTS, so a
    /// combination layer A refuses — a cadence with no CRLs — cannot be written here at
    /// all. The old `(has_crls, lifetime, cadence)` triple could name it, and did.
    fn plan(
        client_revocation: ClientRevocationPlan,
        max_client_cert_lifetime: Option<std::time::Duration>,
    ) -> TlsPlan {
        TlsPlan {
            custody: crate::config_state::TlsCustodyState::Exported {
                key_path: "/key".to_string(),
            },
            client_revocation,
            max_client_cert_lifetime,
            max_connection_age: None,
        }
    }

    fn crl_paths() -> Vec<String> {
        vec!["/crl.pem".to_string()]
    }

    /// With no CRL the ONLY bound is the certificate lifetime, and the line has to say so
    /// rather than imply a revocation mechanism exists.
    #[test]
    fn without_a_crl_the_bound_is_the_certificate_lifetime() {
        let bound = fleet_crl_bound(&plan(
            ClientRevocationPlan::None,
            Some(std::time::Duration::from_secs(3600)),
        ));
        assert!(bound.contains("exposure_window 3600s"), "got: {bound}");
        assert!(bound.contains("no client CRL"), "got: {bound}");
    }

    /// A disabled lifetime must not silently render as a number. `unbounded` is the honest
    /// word, and it is the posture `unsafe_config_violations` refuses — so if it ever
    /// appears in a transcript, it names the thing that should have been impossible.
    #[test]
    fn a_disabled_lifetime_renders_as_unbounded_not_as_a_number() {
        let bound = fleet_crl_bound(&plan(ClientRevocationPlan::None, None));
        assert!(bound.contains("exposure_window unbounded"), "got: {bound}");
    }

    /// The reload cadence IS the bound, and the claim must say it reaches ESTABLISHED
    /// connections. A CRL consulted only at the handshake would leave a peer holding one
    /// connection open unaffected by a republished index — a materially weaker guarantee
    /// than the number alone suggests.
    #[test]
    fn a_reload_cadence_bounds_established_connections_not_only_handshakes() {
        let bound = fleet_crl_bound(&plan(
            ClientRevocationPlan::Reloading {
                paths: crl_paths(),
                cadence_secs: 300,
            },
            None,
        ));
        assert!(bound.contains("bounded 300s"), "got: {bound}");
        assert!(
            bound.contains("established connections"),
            "the cadence claim must state that it reaches open connections, got: {bound}"
        );
    }

    /// Without a cadence the bound is the CRL's own expiry or a restart — never zero, and
    /// never the cert lifetime, which does not apply once a CRL is present.
    #[test]
    fn without_a_cadence_the_bound_is_the_crls_own_expiry() {
        let bound = fleet_crl_bound(&plan(
            ClientRevocationPlan::Static { paths: crl_paths() },
            Some(std::time::Duration::from_secs(60)),
        ));
        assert!(bound.contains("nextUpdate"), "got: {bound}");
        assert!(
            !bound.contains("exposure_window"),
            "the cert-lifetime window is not the bound once a CRL is present, got: {bound}"
        );
    }
}
