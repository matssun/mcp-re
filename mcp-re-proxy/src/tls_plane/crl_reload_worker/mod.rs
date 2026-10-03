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
/// than from an `Option` beside it. The currency is created here, so a cadence is claimed
/// only where a worker was spawned.
// allow: the task is built here because its currency is, and only for a scheduled cadence.
#[allow(clippy::too_many_arguments)]
pub(super) fn start_reload_worker(
    deployment: Arc<std::sync::atomic::AtomicBool>,
    plan: &crate::startup_plan::ChannelEstablishmentPlan,
    material: TlsKeyMaterial,
    snapshot: &Arc<config_snapshot::ServerConfigSnapshot>,
    reload_chain: Vec<rustls_pki_types::CertificateDer<'static>>,
    reload_crl_paths: Vec<String>,
    publisher: Option<client_revocation::ClientRevocationPublisher>,
    rebuild_state: &Arc<TlsListenerSecurityState>,
    crls: ClientCrlEvidence,
) -> (WorkerSet, Arc<ClientRevocationCurrency>) {
    let mut workers = WorkerSet::new(deployment);
    let Some(cadence_secs) = plan.client_revocation.reload_cadence_secs() else {
        return (
            workers,
            Arc::new(ClientRevocationCurrency::new(crls, false)),
        );
    };
    let currency = Arc::new(ClientRevocationCurrency::new(crls, true));
    let custody = material.label();
    spawn_crl_reload_task(
        &mut workers,
        CrlReloadTask {
            snapshot: Arc::clone(snapshot),
            server_chain: reload_chain,
            material,
            crl_paths: reload_crl_paths,
            interval_secs: cadence_secs,
            publisher,
            rebuild_state: Arc::clone(rebuild_state),
            currency: Arc::clone(&currency),
        },
        plan.clone(),
    );
    eprintln!(
        "mcp-re-proxy: in-process CRL hot-reload enabled (every {cadence_secs}s, \
         {custody} TLS custody; refreshed --client-crl honored without restart; \
         failed reload keeps last-good)"
    );
    (workers, currency)
}

pub(super) struct CrlReloadTask {
    pub(super) snapshot: Arc<config_snapshot::ServerConfigSnapshot>,
    /// The immutable server key material the verifier is rebuilt from; a reload
    /// re-reads only the CRLs, never these.
    pub(super) server_chain: Vec<rustls_pki_types::CertificateDer<'static>>,
    pub(super) material: TlsKeyMaterial,
    pub(super) crl_paths: Vec<String>,
    pub(super) interval_secs: u64,
    /// The capability to publish into the per-request revocation index — the half of a reload
    /// that reaches connections already open. The only one there is: the plane hands out the
    /// read handle alone. `None` where no CRLs are configured.
    pub(super) publisher: Option<client_revocation::ClientRevocationPublisher>,
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
        // after a whole reload interval. A halt ends re-reading while the plane still
        // serves, so the cadence is retracted here.
        if halt.sleep(Duration::from_secs(task.interval_secs)) {
            task.currency.mark_stopped();
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
        let evidence =
            ClientCrlEvidence::from_checked(crls, task.rebuild_state.trust_anchors(), now_unix)?;
        // The per-request index from the SAME bytes, BEFORE the verifier is rebuilt, so a
        // malformed CRL keeps last-good on both rather than swapping one and failing the
        // other.
        let index = evidence.revocation_index()?;
        let rebuilt =
            task.material
                .rebuild(task.server_chain.clone(), &evidence, &task.rebuild_state)?;
        if let Some(publisher) = task.publisher.as_ref() {
            publisher.publish(index);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_revocation::{ClientRevocationIndex, SharedClientRevocation};
    use crate::config_snapshot::{ReloadOutcome, ServerConfigSnapshot};
    use crate::tls_plane::revocation_currency::CrlMaintenance;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// `anchors` are the client CA certificates the listener trusts — the keys a reloaded CRL
    /// must be signed by.
    fn task(
        server_chain: Vec<rustls_pki_types::CertificateDer<'static>>,
        crl_paths: Vec<String>,
        publisher: Option<client_revocation::ClientRevocationPublisher>,
        currency: Arc<ClientRevocationCurrency>,
        anchors: Vec<rustls_pki_types::CertificateDer<'static>>,
    ) -> CrlReloadTask {
        let key = rcgen::KeyPair::generate().expect("server key");
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("server params")
            .self_signed(&key)
            .expect("server cert");
        let chain = vec![cert.der().clone()];
        let key_der = || {
            rustls_pki_types::PrivateKeyDer::from(rustls_pki_types::PrivatePkcs8KeyDer::from(
                key.serialize_der(),
            ))
        };
        let rebuild_state = Arc::new(TlsListenerSecurityState::new(anchors));
        let initial = rebuild_state
            .build_exported_key_config(chain.clone(), key_der(), Vec::new())
            .expect("initial config");
        CrlReloadTask {
            snapshot: Arc::new(ServerConfigSnapshot::new(Arc::new(initial))),
            server_chain: if server_chain.is_empty() {
                server_chain
            } else {
                chain
            },
            material: TlsKeyMaterial::Exported(key_der()),
            crl_paths,
            interval_secs: 1,
            publisher,
            rebuild_state,
            currency,
        }
    }

    /// A fresh CRL on disk under a unique name, and the CA certificate that signed it; the
    /// caller removes the file.
    fn crl_file(tag: &str) -> (String, rustls_pki_types::CertificateDer<'static>) {
        let path = std::env::temp_dir().join(format!(
            "crl-reload-worker-{tag}-{}.der",
            std::process::id()
        ));
        let (der, issuer) = crate::client_crl_publication::test_support::crl_and_issuer();
        std::fs::write(&path, der.as_ref()).expect("write crl");
        (path.to_string_lossy().into_owned(), issuer)
    }

    fn chain_for_task() -> Vec<rustls_pki_types::CertificateDer<'static>> {
        let key = rcgen::KeyPair::generate().expect("key");
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("params")
            .self_signed(&key)
            .expect("cert");
        vec![cert.der().clone()]
    }

    #[test]
    fn a_halted_reload_loop_retracts_the_cadence_it_advertised() {
        let deployment = Arc::new(AtomicBool::new(false));
        let workers = WorkerSet::new(Arc::clone(&deployment));
        let halt = workers.halt();
        let currency = Arc::new(ClientRevocationCurrency::new(
            ClientCrlEvidence::from_checked(Vec::new(), &[], 0).expect("no CRLs is legal"),
            true,
        ));
        assert_eq!(
            currency.maintenance(),
            crate::tls_plane::revocation_currency::CrlMaintenance::Maintained
        );
        let t = task(
            chain_for_task(),
            Vec::new(),
            None,
            Arc::clone(&currency),
            chain_for_task(),
        );

        deployment.store(true, Ordering::SeqCst);
        crl_reload_loop(t, &halt);

        assert_eq!(currency.maintenance(), CrlMaintenance::Stopped);
    }

    #[test]
    fn a_successful_reload_republishes_the_evidence_it_installed() {
        let (path, issuer) = crl_file("ok");
        let currency = Arc::new(ClientRevocationCurrency::new(
            ClientCrlEvidence::from_checked(Vec::new(), &[], 0).expect("no CRLs is legal"),
            true,
        ));
        currency.mark_degraded();
        let (reader, publisher) = SharedClientRevocation::establish(ClientRevocationIndex::empty());
        let revocation = Arc::new(reader);
        let t = task(
            chain_for_task(),
            vec![path.clone()],
            Some(publisher),
            Arc::clone(&currency),
            vec![issuer],
        );

        let (outcome, installed) = attempt_reload(&t);
        assert!(matches!(outcome, ReloadOutcome::Swapped));
        let failures = report(&currency, outcome, installed, 1);
        let _ = std::fs::remove_file(&path);

        assert_eq!(failures, 0);
        assert!(!currency.evidence().is_empty());
        assert_eq!(currency.maintenance(), CrlMaintenance::Maintained);
        assert!(!revocation.load().is_empty());
    }

    /// A CRL on disk that no configured client CA signed is not installed: the reload keeps
    /// last-good, so replacing the file is not a way to publish revocations (or to retract
    /// them) for a deployment whose CA never issued them.
    #[test]
    fn a_reloaded_crl_no_configured_ca_signed_is_not_installed() {
        let (path, _signer_not_configured) = crl_file("unsigned-by-anchor");
        let currency = Arc::new(ClientRevocationCurrency::new(
            ClientCrlEvidence::from_checked(Vec::new(), &[], 0).expect("no CRLs is legal"),
            true,
        ));
        let (reader, publisher) = SharedClientRevocation::establish(ClientRevocationIndex::empty());
        let revocation = Arc::new(reader);
        let before = revocation.load();
        let t = task(
            chain_for_task(),
            vec![path.clone()],
            Some(publisher),
            Arc::clone(&currency),
            chain_for_task(),
        );

        let (outcome, installed) = attempt_reload(&t);
        let _ = std::fs::remove_file(&path);

        assert!(matches!(outcome, ReloadOutcome::KeptLastGood { .. }));
        assert!(installed.is_none());
        assert!(Arc::ptr_eq(&before, &revocation.load()));
    }

    #[test]
    fn a_failed_rebuild_keeps_last_good_index_and_is_degraded_not_stopped() {
        let (path, issuer) = crl_file("bad-rebuild");
        let currency = Arc::new(ClientRevocationCurrency::new(
            ClientCrlEvidence::from_checked(Vec::new(), &[], 0).expect("no CRLs is legal"),
            true,
        ));
        let (reader, publisher) = SharedClientRevocation::establish(ClientRevocationIndex::empty());
        let revocation = Arc::new(reader);
        let before = revocation.load();
        let t = task(
            Vec::new(),
            vec![path.clone()],
            Some(publisher),
            Arc::clone(&currency),
            vec![issuer],
        );

        let (outcome, installed) = attempt_reload(&t);
        assert!(matches!(outcome, ReloadOutcome::KeptLastGood { .. }));
        let failures = report(&currency, outcome, installed, 0);
        let _ = std::fs::remove_file(&path);

        assert_eq!(failures, 1);
        assert!(Arc::ptr_eq(&before, &revocation.load()));
        assert!(currency.evidence().is_empty());
        assert_eq!(currency.maintenance(), CrlMaintenance::Degraded);
    }
}
