// SPDX-License-Identifier: Apache-2.0
//! Whether anything is still refreshing this replica's client CRLs, and which ones it last
//! installed.
//!
//! One fact: **a CRL posture without its own currency is a claim about a snapshot that may
//! already have been superseded.** Both halves of that had gone wrong independently. The
//! startup evidence was written once and never rewritten, so after the first successful
//! reload the posture described a CRL nobody was enforcing. And the reload worker's panic
//! supervisor printed a FATAL line and changed no state, so the deployment went on
//! advertising a cadence nothing was keeping.
//!
//! What is legal to install is [`super::crl_evidence`]'s; this owns what is installed NOW
//! and whether the promise to keep refreshing it is being kept.
//!
//! # Four maintenance states, because there are four different things to tell an operator
//!
//! `NotScheduled` and `Stopped` are the pair that must never collapse: one is a deployment
//! that never claimed a cadence, the other is one that claimed it and is not keeping it.
//! `Degraded` and `Stopped` are the other: a failed reload is recoverable by the next one,
//! and a dead worker is not, so the flag a live reload may clear cannot be the flag the
//! supervisor sets.

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::RwLock;

use super::crl_evidence::ClientCrlEvidence;

/// Whether anything is still re-reading the CRLs, as an operator-facing fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CrlMaintenance {
    /// No reload cadence is configured. The posture is a static snapshot and always was.
    NotScheduled,
    /// The worker is running and its last reload succeeded.
    Maintained,
    /// The worker is running and its last reload failed; last-good is in force and the next
    /// reload may recover it.
    Degraded,
    /// Terminal. The worker died, or the plane that owned it retired. Nothing will re-read
    /// again, and no later reload may report otherwise.
    Stopped,
}

impl CrlMaintenance {
    /// The token an operator or a log collector greps for.
    ///
    /// `Maintained` renders as the cadence rather than as a word, because the cadence is
    /// what the startup line promises and the retraction has to be legible against it.
    pub(crate) fn wire(self, cadence_secs: Option<u64>) -> String {
        match self {
            CrlMaintenance::NotScheduled => "not_scheduled".to_owned(),
            CrlMaintenance::Maintained => cadence_secs.map_or_else(
                || "not_scheduled".to_owned(),
                |secs| format!("every_{secs}s"),
            ),
            CrlMaintenance::Degraded => "degraded".to_owned(),
            CrlMaintenance::Stopped => "stopped".to_owned(),
        }
    }
}

/// What this replica is enforcing, and whether it is still being maintained.
///
/// The two atomics are not one flag for the reason [`CrlMaintenance`] gives: a live reload
/// clears `degraded` and must never clear `stopped`, so a straggler success after the
/// worker died cannot report the cadence as kept.
#[derive(Debug)]
pub(crate) struct ClientRevocationCurrency {
    degraded: AtomicBool,
    stopped: AtomicBool,
    scheduled: bool,
    evidence: RwLock<ClientCrlEvidence>,
}

impl ClientRevocationCurrency {
    /// Seed with what startup established, and whether a cadence was configured at all.
    pub(super) fn new(initial: ClientCrlEvidence, scheduled: bool) -> Self {
        ClientRevocationCurrency {
            degraded: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            scheduled,
            evidence: RwLock::new(initial),
        }
    }

    /// The CRLs currently enforced. A poisoned lock still yields the last value: a reader
    /// of the posture must not panic because a writer did.
    pub(crate) fn evidence(&self) -> ClientCrlEvidence {
        match self.evidence.read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// A reload succeeded: these are the CRLs now in force, and the cadence is being kept.
    pub(super) fn republish(&self, evidence: ClientCrlEvidence) {
        match self.evidence.write() {
            Ok(mut guard) => *guard = evidence,
            Err(poisoned) => *poisoned.into_inner() = evidence,
        }
        self.degraded.store(false, Ordering::SeqCst);
    }

    /// A reload failed and last-good is in force. Recoverable by the next one.
    pub(super) fn mark_degraded(&self) {
        self.degraded.store(true, Ordering::SeqCst);
    }

    /// Nothing will re-read again. No later reload may report the cadence as kept.
    pub(super) fn mark_stopped(&self) {
        self.stopped.store(true, Ordering::SeqCst);
    }

    /// What an operator may be told about this replica's CRL maintenance.
    pub(crate) fn maintenance(&self) -> CrlMaintenance {
        if !self.scheduled {
            return CrlMaintenance::NotScheduled;
        }
        if self.stopped.load(Ordering::Relaxed) {
            return CrlMaintenance::Stopped;
        }
        if self.degraded.load(Ordering::Relaxed) {
            return CrlMaintenance::Degraded;
        }
        CrlMaintenance::Maintained
    }
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::*;

    fn currency(scheduled: bool) -> ClientRevocationCurrency {
        ClientRevocationCurrency::new(ClientCrlEvidence::default(), scheduled)
    }

    /// A deployment that never claimed a cadence is not one that stopped keeping it.
    #[test]
    fn an_unscheduled_reload_is_never_reported_as_stopped() {
        let c = currency(false);
        assert_eq!(c.maintenance(), CrlMaintenance::NotScheduled);
        c.mark_degraded();
        c.mark_stopped();
        assert_eq!(
            c.maintenance(),
            CrlMaintenance::NotScheduled,
            "a replica with no reload worker cannot have lost one"
        );
    }

    /// A failed reload is recoverable; the next success clears it.
    #[test]
    fn a_degraded_reload_recovers_on_the_next_success() {
        let c = currency(true);
        c.mark_degraded();
        assert_eq!(c.maintenance(), CrlMaintenance::Degraded);
        c.republish(ClientCrlEvidence::default());
        assert_eq!(c.maintenance(), CrlMaintenance::Maintained);
    }

    /// THE latch. A straggler reload landing after the worker died must not report the
    /// cadence as kept — which is exactly what one flag would have allowed.
    #[test]
    fn a_stopped_worker_is_not_cleared_by_a_later_reload() {
        let c = currency(true);
        c.mark_stopped();
        assert_eq!(c.maintenance(), CrlMaintenance::Stopped);
        c.republish(ClientCrlEvidence::default());
        assert_eq!(
            c.maintenance(),
            CrlMaintenance::Stopped,
            "nothing re-reads after the worker is gone, whatever landed afterwards"
        );
    }

    /// The retraction is legible against the promise it retracts.
    #[test]
    fn the_maintenance_token_names_the_cadence_it_is_or_is_not_keeping() {
        assert_eq!(CrlMaintenance::Maintained.wire(Some(300)), "every_300s");
        assert_eq!(CrlMaintenance::Degraded.wire(Some(300)), "degraded");
        assert_eq!(CrlMaintenance::Stopped.wire(Some(300)), "stopped");
        assert_eq!(CrlMaintenance::NotScheduled.wire(None), "not_scheduled");
    }
}
