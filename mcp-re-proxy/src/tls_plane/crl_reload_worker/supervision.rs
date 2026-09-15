// SPDX-License-Identifier: Apache-2.0
//! What a dead CRL reload worker costs, and what the deployment stops claiming.
//!
//! One fact: **a replica whose reload worker has died must stop advertising a cadence.**
//! Separable from the loop beside it, and the separation is the point — the loop decides
//! what one reload attempt does, and this decides what the ABSENCE of every future attempt
//! means. The two failed differently: the loop was careful and this was a print statement.
//!
//! Nothing here refuses a handshake, deliberately. See [`spawn_crl_reload_task`].

use std::sync::Arc;

use super::super::revocation_currency::ClientRevocationCurrency;
use super::crl_reload_loop;
use super::CrlReloadTask;

/// SUPERVISED like the trust reload and the rotation owner: nothing joins this thread,
/// and a panic in it would silently stop CRL reloading for the process lifetime.
///
/// Unlike the trust store, a stale CRL index bounds ITSELF — a CRL past its `nextUpdate`
/// covers nothing, so its issuer's certificates become `Unknown` and are refused. A failed
/// reload therefore never widens what is accepted, and this supervisor does not have to
/// refuse handshakes.
///
/// That argument is sound about SAFETY and silent about HONESTY, which is the half that was
/// missing: the supervisor printed a FATAL line and changed no state, so the deployment went
/// on advertising "in-process CRL hot-reload enabled (every Ns)" while nothing was re-reading
/// anything. Two things the self-bounding argument does not cover:
///
/// * it bounds the rustls VERIFIER, and says nothing about the per-request index, whose
///   whole reason for existing is that a peer added to a reloaded CRL stops being served on
///   the connection it already holds. A dead worker reverts that to next-handshake-only.
/// * the bound is a full CRL validity period — days — and the startup line promises minutes.
///
/// So the fault is LATCHED and the advertised property is retracted, in the same posture
/// vocabulary the promise was made in. Retracting is the whole obligation; refusing is not,
/// because the verifier genuinely does self-bound.
pub(super) fn spawn_crl_reload_task(
    workers: &mut crate::managed_worker::WorkerSet,
    task: CrlReloadTask,
    plan: crate::startup_plan::ChannelEstablishmentPlan,
) {
    let halt = workers.halt();
    let currency = Arc::clone(&task.currency);
    workers.spawn("client CRL reload", move || {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crl_reload_loop(task, &halt);
        }));
        if outcome.is_ok() {
            return;
        }
        for line in stop_and_retract(&currency, &plan) {
            eprintln!("{line}");
        }
    });
}

/// Latch the fault and say what the deployment no longer has.
///
/// Returns the lines instead of printing them, for the reason
/// [`super::super::revocation_posture_lines`] does: what an operator is told about a control that
/// has stopped is assertable in a test rather than only readable in a transcript. It was
/// readable in a transcript and nothing else, which is how a FATAL line that changed no
/// state survived.
///
/// The latch is set BEFORE anything is rendered, so a stderr write that panics on a closed
/// pipe cannot leave the deployment still advertising a cadence nothing is keeping.
fn stop_and_retract(
    currency: &ClientRevocationCurrency,
    plan: &crate::startup_plan::ChannelEstablishmentPlan,
) -> Vec<String> {
    currency.mark_stopped();
    let mut lines = vec![
        "mcp-re-proxy: FATAL: the client-CRL reload thread PANICKED. --client-crl is no longer \
         being re-read, so a newly revoked client certificate reaches this replica only when \
         its CRL passes nextUpdate (after which that issuer's certificates are refused \
         outright). This replica cannot recover on its own — restart it."
            .to_owned(),
    ];
    lines.extend(super::super::revocation_posture_lines(plan, currency));
    lines
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::startup_plan::ChannelEstablishmentPlan;
    use crate::tls_plane::revocation_currency::CrlMaintenance;
    use crate::tls_plane::revocation_posture_lines;
    use crate::tls_plane::ClientCrlEvidence;

    /// A plan that configures a reload cadence, so the posture has a promise to retract.
    fn plan_with_cadence(cadence_secs: u64) -> ChannelEstablishmentPlan {
        ChannelEstablishmentPlan {
            custody: crate::config_state::test_support::channel_custody_exported("/key"),
            client_revocation: crate::config_state::test_support::crl_plan(
                &["/crl.pem"],
                Some(cadence_secs),
            ),
            credential_window: crate::config_state::test_support::credential_window(3600, 300),
        }
    }

    /// THE defect this file carried: the supervisor printed and changed nothing, so the
    /// posture went on advertising a cadence no worker was keeping.
    ///
    /// The retraction is in the posture vocabulary the promise was made in, which is what
    /// makes it reach a log collector rather than only a human reading prose.
    #[test]
    fn a_dead_reload_worker_retracts_the_cadence_it_advertised() {
        let plan = plan_with_cadence(300);
        let currency = ClientRevocationCurrency::new(ClientCrlEvidence::default(), true);
        assert!(
            revocation_posture_lines(&plan, &currency)[0].contains("crl_reload=every_300s"),
            "the promise is made in this vocabulary"
        );

        let lines = stop_and_retract(&currency, &plan);

        assert_eq!(
            currency.maintenance(),
            CrlMaintenance::Stopped,
            "the latch is what survives the line"
        );
        assert!(lines[0].contains("PANICKED"), "{:?}", lines[0]);
        assert!(
            lines.iter().any(|l| l.contains("crl_reload=stopped")),
            "the retraction must be legible against the promise: {lines:?}"
        );
        assert!(
            !lines.iter().any(|l| l.contains("crl_reload=every_300s")),
            "the promise must not be restated beside its own retraction: {lines:?}"
        );
    }

    /// A reload that fails is not a reload that stopped, and the posture distinguishes them.
    #[test]
    fn a_failed_reload_is_degraded_and_a_dead_worker_is_stopped() {
        let plan = plan_with_cadence(300);
        let currency = ClientRevocationCurrency::new(ClientCrlEvidence::default(), true);

        currency.mark_degraded();
        let degraded = revocation_posture_lines(&plan, &currency);
        assert!(degraded[0].contains("crl_reload=degraded"), "{degraded:?}");

        let stopped = stop_and_retract(&currency, &plan);
        assert!(
            stopped.iter().any(|l| l.contains("crl_reload=stopped")),
            "{stopped:?}"
        );
    }
}
