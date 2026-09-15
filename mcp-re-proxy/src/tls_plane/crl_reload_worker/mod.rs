// SPDX-License-Identifier: Apache-2.0
//! Keeping the client-revocation posture fresh without a restart (ADR-MCPRE-051 §6).
//!
//! A separate authority from establishing the posture at boot. Establishing it decides
//! whether the deployment may start at all; this decides what happens to a running one when
//! the CRL files change on disk, and its failure mode is the opposite: a bad reload must
//! never widen what is accepted.
//!
//! A read, parse or build failure KEEPS THE LAST-GOOD config, which still fails closed once
//! its own `nextUpdate` passes — so the worst outcome of a failed reload is the same refusal
//! a missing worker would eventually produce anyway. That is the whole reason this worker
//! may fail without the deployment refusing, and [`supervision`] is where the limit of that
//! argument is stated.

use std::sync::Arc;
use std::time::Duration;

use super::client_revocation;
use super::config_snapshot;
use super::crl_evidence::ClientCrlEvidence;
use super::revocation_currency::ClientRevocationCurrency;
use super::TlsKeyMaterial;
use super::TlsListenerSecurityState;
use crate::managed_worker::WorkerSet;

/// What a dead reload worker costs, and what the deployment stops claiming.
mod supervision;

use supervision::spawn_crl_reload_task;

/// Start the CRL reload worker the posture calls for, and nothing otherwise.
///
/// Only the `Reloading` posture starts one, and the cadence comes from that variant rather
/// than from an `Option` beside it. There was a branch here for a cadence with NO CRLs,
/// which printed "no CRL reload scheduled" and carried on; it is gone because it is now
/// unreachable — that combination is refused at the boundary (CF-04: a cadence for
/// re-reading an empty set states a control the deployment does not have). The same shape
/// as `ReplayPlan::Memory` — a branch that survived because nothing had ever asked whether
/// a configuration could reach it.
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
    currency: &Arc<ClientRevocationCurrency>,
) -> WorkerSet {
    let mut workers = WorkerSet::new(deployment);
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
                currency: Arc::clone(currency),
            },
            plan.clone(),
        );
        eprintln!(
            "mcp-re-proxy: in-process CRL hot-reload enabled (every {cadence_secs}s, \
             {custody} TLS custody; refreshed --client-crl honored without restart; \
             failed reload keeps last-good)"
        );
    }
    workers
}

pub(super) struct CrlReloadTask {
    pub(super) snapshot: Arc<config_snapshot::ServerConfigSnapshot>,
    /// The immutable server key material the verifier is rebuilt from; a reload
    /// re-reads only the CRLs, never these.
    pub(super) server_chain: Vec<rustls_pki_types::CertificateDer<'static>>,
    pub(super) material: TlsKeyMaterial,
    pub(super) crl_paths: Vec<String>,
    pub(super) interval_secs: u64,
    /// The per-request revocation index — the half of a reload that reaches connections
    /// already open. `None` where no CRLs are configured.
    pub(super) revocation: Option<Arc<client_revocation::SharedClientRevocation>>,
    /// The listener's own security state — anchors, epoch, session cache and
    /// handshake-signature budget. The same one startup built, so a reload rebuilds
    /// against the anchor set in force and neither empties the cache nor refills the
    /// bucket.
    pub(super) rebuild_state: Arc<TlsListenerSecurityState>,
    /// What this replica is enforcing and whether the cadence is being kept. The worker is
    /// the only thing that knows either after boot, so it is the only thing that can keep
    /// them true.
    pub(super) currency: Arc<ClientRevocationCurrency>,
}
/// The CRL reload loop proper. Split out so the supervisor can catch a panic.
///
/// Three things, kept apart because they fail differently: waiting, attempting, and saying
/// what happened. The attempt is where a bad CRL must not become an installed one; the
/// report is where the posture and the operator learn what is in force.
pub(super) fn crl_reload_loop(task: CrlReloadTask, halt: &crate::managed_worker::Halt) {
    let mut consecutive_failures: u32 = 0;
    loop {
        // Naps in small increments, so a halt is observed within one increment rather than
        // after a whole reload interval.
        if halt.sleep(Duration::from_secs(task.interval_secs)) {
            return;
        }
        let (outcome, installed) = attempt_reload(&task);
        consecutive_failures = report(&task.currency, outcome, installed, consecutive_failures);
    }
}

/// One reload attempt: re-read, gate, index, rebuild, swap.
///
/// Returns what the snapshot did and, on success, the evidence that was installed — the
/// caller republishes it, because a posture that keeps reporting the boot CRL is reporting a
/// CRL nobody is enforcing.
fn attempt_reload(
    task: &CrlReloadTask,
) -> (config_snapshot::ReloadOutcome, Option<ClientCrlEvidence>) {
    // Read once per attempt, so the freshness gate judges every CRL in the set against one
    // instant.
    let now_unix = crate::clock::now_unix();
    let mut installed: Option<ClientCrlEvidence> = None;
    let outcome = config_snapshot::reload_once(&task.snapshot, || {
        let crls = crate::client_crl_publication::load_client_crls(&task.crl_paths)?;
        // The SAME gate startup ran, because it is the evidence's own constructor. The
        // reload used to run the never-expires half alone, so a CRL past its `nextUpdate` —
        // which startup refuses to boot on — could be indexed, built into a verifier and
        // swapped in, after which every new handshake against that issuer failed closed and
        // this worker reported success. Building the evidence FIRST is what makes that
        // unreachable rather than merely checked: there is no inhabitant to install.
        let evidence = ClientCrlEvidence::from_checked(&crls, now_unix)?;
        // The per-request index from the SAME bytes, BEFORE the verifier is rebuilt, so a
        // malformed CRL keeps last-good on both rather than swapping one and failing the
        // other.
        let index = client_revocation::ClientRevocationIndex::from_crl_ders(
            &crls
                .iter()
                .map(|crl| crl.as_ref().to_vec())
                .collect::<Vec<_>>(),
        )
        .map_err(|e| e.to_string())?;
        let rebuilt =
            task.material
                .rebuild(task.server_chain.clone(), crls, &task.rebuild_state)?;
        if let Some(revocation) = task.revocation.as_ref() {
            revocation.store(index);
        }
        installed = Some(evidence);
        Ok(Arc::new(rebuilt))
    });
    (outcome, installed)
}

/// Publish what the attempt did, and return the running failure count.
fn report(
    currency: &ClientRevocationCurrency,
    outcome: config_snapshot::ReloadOutcome,
    installed: Option<ClientCrlEvidence>,
    consecutive_failures: u32,
) -> u32 {
    match outcome {
        config_snapshot::ReloadOutcome::Swapped => {
            // The posture now describes the CRLs that were just installed. Left unwritten,
            // it went on reporting the startup digest and window for the process lifetime —
            // a superseded CRL presented as the one in force.
            if let Some(evidence) = installed {
                currency.republish(evidence);
            }
            if consecutive_failures > 0 {
                eprintln!(
                    "mcp-re-proxy: client CRL reload RECOVERED; new verifier and per-request \
                     index are live"
                );
            } else {
                eprintln!("mcp-re-proxy: client CRL reloaded; new verifier is live");
            }
            0
        }
        config_snapshot::ReloadOutcome::KeptLastGood { reason } => {
            // Recoverable, and the next success is the recovery it exists to allow — which
            // is why this is not the flag the supervisor sets.
            currency.mark_degraded();
            let failures = consecutive_failures.saturating_add(1);
            eprintln!(
                "mcp-re-proxy: WARNING: client CRL reload FAILED {failures}x in a row, keeping \
                 last-good config: {reason}. Newly revoked certificates are NOT reaching this \
                 replica; when the last-good CRL passes its nextUpdate its issuer's \
                 certificates are refused outright."
            );
            failures
        }
    }
}
