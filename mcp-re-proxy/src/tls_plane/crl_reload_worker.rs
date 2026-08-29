// SPDX-License-Identifier: Apache-2.0
//! Keeping the client-revocation posture fresh without a restart (ADR-MCPRE-051 §6).
//!
//! A separate authority from establishing the posture at boot. Establishing it decides
//! whether the deployment may start at all; this decides what happens to a running one when
//! the CRL files change on disk, and its failure mode is the opposite: a bad reload must
//! never widen what is accepted.
//!
//! Every `interval_secs` the worker re-reads the `--client-crl` files and rebuilds the
//! verifier from the SAME immutable server key material, atomically swapping the result
//! into the snapshot. A read, parse or build failure KEEPS THE LAST-GOOD config — which
//! still fails closed once its own `nextUpdate` passes, so the worst outcome of a failed
//! reload is the same refusal a missing worker would eventually produce anyway.
//!
//! The per-request revocation index is republished from the same re-read bytes, so a peer
//! added to a reloaded CRL stops being served on the connection it already holds rather
//! than at its next handshake.
//!
//! The worker observes `SHUTDOWN` between naps so a rolling deploy is not delayed by a
//! cadence.

use std::sync::Arc;
use std::time::Duration;

use super::client_revocation;
use super::config_snapshot;
use super::TlsKeyMaterial;
use super::TlsListenerSecurityState;
use crate::managed_worker::WorkerSet;

/// Start the CRL reload worker the posture calls for, and nothing otherwise.
///
/// Only the `Reloading` posture starts one, and the cadence comes from that variant rather
/// than from an `Option` beside it. There was a branch here for a cadence with NO CRLs,
/// which printed "no CRL reload scheduled" and carried on; it is gone because it is now
/// unreachable — that combination is refused at the boundary (CF-04: a cadence for
/// re-reading an empty set states a control the deployment does not have).
#[allow(clippy::too_many_arguments)]
pub(super) fn start_reload_worker(
    deployment: Arc<std::sync::atomic::AtomicBool>,
    plan: &crate::startup_plan::ChannelEstablishmentPlan,
    material: TlsKeyMaterial,
    snapshot: &Arc<config_snapshot::ServerConfigSnapshot>,
    reload_chain: Vec<rustls_pki_types::CertificateDer<'static>>,
    reload_crl_paths: Vec<String>,
    revocation: Option<Arc<client_revocation::SharedClientRevocation>>,
    rebuild_state: &Arc<TlsListenerSecurityState>,
) -> WorkerSet {
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
    if let Some(cadence_secs) = plan.client_revocation.reload_cadence_secs() {
        let custody = material.label();
        spawn_crl_reload_task(
            &mut workers,
            CrlReloadTask {
                snapshot: Arc::clone(snapshot),
                server_chain: reload_chain,
                material,
                crl_paths: reload_crl_paths,
                interval_secs: cadence_secs,
                revocation: revocation.clone(),
                rebuild_state: Arc::clone(rebuild_state),
            },
        );
        eprintln!(
            "mcp-re-proxy: in-process CRL hot-reload enabled (every {cadence_secs}s, \
             {custody} TLS custody; refreshed --client-crl honored without restart; \
             failed reload keeps last-good)"
        );
    }
    workers
}

struct CrlReloadTask {
    snapshot: Arc<config_snapshot::ServerConfigSnapshot>,
    /// The immutable server key material the verifier is rebuilt from; a reload
    /// re-reads only the CRLs, never these.
    server_chain: Vec<rustls_pki_types::CertificateDer<'static>>,
    material: TlsKeyMaterial,
    crl_paths: Vec<String>,
    interval_secs: u64,
    /// The per-request revocation index, republished from the same re-read bytes as
    /// the rebuilt verifier. Rebuilding only the verifier would leave the reload
    /// reaching new connections alone — which is the gap the per-request check exists
    /// to close.
    revocation: Option<Arc<client_revocation::SharedClientRevocation>>,
    /// The listener's own security state — anchors, epoch, session cache and
    /// handshake-signature budget. The same one startup built, so a reload rebuilds
    /// against the anchor set in force and neither empties the cache nor refills the
    /// bucket.
    rebuild_state: Arc<TlsListenerSecurityState>,
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
        crl_paths,
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
                let crls = crate::client_crl_publication::load_client_crls(&crl_paths)?;
                // A CRL that never falls out of force is refused on reload for the same
                // reason it is refused at startup: keeping last-good is only safe while
                // last-good ages out on its own.
                for (i, crl) in crls.iter().enumerate() {
                    crate::client_crl_publication::crl_next_update_required(crl.as_ref(), i)
                        .map_err(|e| e.to_string())?;
                }
                // Build the per-request index from the SAME bytes, BEFORE the verifier
                // is rebuilt, so a malformed CRL keeps last-good on both rather than
                // swapping one and failing the other.
                let index = client_revocation::ClientRevocationIndex::from_crl_ders(
                    &crls
                        .iter()
                        .map(|crl| crl.as_ref().to_vec())
                        .collect::<Vec<_>>(),
                )
                .map_err(|e| e.to_string())?;
                let rebuilt = material.rebuild(server_chain.clone(), crls, &rebuild_state)?;
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
