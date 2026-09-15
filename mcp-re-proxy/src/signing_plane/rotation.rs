// SPDX-License-Identifier: Apache-2.0
//! Keeping a delegated key in force (ADR-MCPRE-052 §6–§7).
//!
//! One loop, three things it reacts to, and they are not equally urgent:
//!
//! * the **schedule** — mint the successor while the predecessor is still valid, which is
//!   what the overlap window is for;
//! * a **trust-epoch advance**, which takes PRIORITY over the schedule: swapping now is
//!   what makes cross-replica revocation take effect on the next request rather than at
//!   the end of a full TTL;
//! * a **failure**, which never extends anything. Serving continues on the current key
//!   until its `exp` and then FAILS CLOSED — no stale-key extension, no direct-root
//!   fallback.
//!
//! Two failure modes are easy to mistake for success and are treated as failures here.
//! `ensure_active` reports `Ok(())` when successor issuance failed but the current key is
//! still valid — the PRIMARY failure mode, a root outage during the overlap window, exactly
//! what the overlap exists to absorb — and taking it as success would reset the backoff,
//! collapse the wake time to now, and re-enter immediately: a tight retry loop against the
//! root KMS/HSM, minting a fresh keypair every pass, for the whole overlap window. And an
//! unreadable or regressed shared epoch is refused for MINTING, because a credential
//! without a comparable epoch is unrevokable.

use std::sync::Arc;
use std::time::Duration;

use crate::clock::now_unix;

use super::mint_successor::attempt_rotation;
use super::mint_successor::RotationStep;
use super::trust_epoch_advance::observe_trust_epoch;
use super::trust_epoch_advance::EpochStep;
use super::DelegatedEpochWatch;

/// thread observes its halt between naps so it exits promptly on a rolling deploy.
pub(super) fn spawn_delegated_rotation_task(
    workers: &mut crate::managed_worker::WorkerSet,
    mut rotor: crate::delegated_wiring::ProdDelegatedRotor,
    signer: Arc<crate::delegated_server_signer::DelegatedServerSigner>,
    overlap: i64,
    epoch_watch: Option<DelegatedEpochWatch>,
) {
    let halt = workers.halt();
    workers.spawn(
        "delegated key rotation",
        supervise_delegated_rotation(Arc::clone(&signer), move || {
            rotation_loop(&mut rotor, &signer, overlap, epoch_watch.as_ref(), &halt);
        }),
    );
}

/// The `catch_unwind` and the fail-closed action it converts a panic into, AS A VALUE.
///
/// Taking the body rather than writing it inline is what makes the supervisor reachable. It
/// was written inline, and the only way to inject a panic was to spawn through `WorkerSet`
/// directly — which measures `WorkerSet` and not this. `SigningPlane::for_teardown_test`
/// advertises "one that panics" and does exactly that, which is why deleting this
/// supervisor left every test green.
///
/// A pure extraction: it moves no decision, adds no type, and stays private to this module.
///
/// SUPERVISION (C040). This thread is the ONLY thing that mints delegated keys, and nothing
/// observes it while it runs — `WorkerSet` reclaims it at shutdown, far too late to matter.
/// Left bare, a panic on any reachable `.expect()` (the CSPRNG draw, the two custody
/// invariants) would end all rotation for the process lifetime while every health surface
/// still read steady state: `DelegatedRotationMetrics.consecutive_failures` is only written
/// BY this thread, so a dead thread leaves it at 0 and the replica appears healthy right up
/// until the current key's `exp`, then 503s with no attributable cause.
///
/// So a panic becomes the strongest honest signal available: RETIRE the snapshot, which
/// makes the hot path fail closed IMMEDIATELY (`delegated_signing_unavailable`) rather than
/// at `exp`, and record a failure so the metric stops reading healthy. The thread does not
/// resume — after a panic the rotor's state is not known good, and continuing to mint from
/// it would be worse than refusing.
fn supervise_delegated_rotation(
    signer: Arc<crate::delegated_server_signer::DelegatedServerSigner>,
    body: impl FnOnce() + Send + 'static,
) -> impl FnOnce() + Send + 'static {
    move || {
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)).is_ok() {
            return;
        }
        signer.retire_permanently();
        signer.metrics().record_failure();
        eprintln!(
            "mcp-re-proxy: FATAL: the delegated rotation thread PANICKED. Delegated key \
             rotation has stopped for the lifetime of this process and the current \
             snapshot has been retired, so response signing now fails closed \
             (delegated_signing_unavailable) immediately rather than at the key's exp. \
             This replica cannot recover on its own — restart it."
        );
    }
}

/// The rotation loop proper. Split out of [`spawn_delegated_rotation_task`] so the
/// supervisor above can catch a panic from anywhere inside it.
pub(super) fn rotation_loop(
    rotor: &mut crate::delegated_wiring::ProdDelegatedRotor,
    signer: &Arc<crate::delegated_server_signer::DelegatedServerSigner>,
    overlap: i64,
    epoch_watch: Option<&DelegatedEpochWatch>,
    halt: &crate::managed_worker::Halt,
) {
    // Failures since the last success drive the backoff schedule; 0 in steady state.
    let mut consecutive_failures: u32 = 0;
    // The epoch this node is currently minting under (starts at the configured baseline
    // label from the startup issuance). An advance of the shared counter moves it;
    // verifiers pinned to the old label then reject across replicas.
    let mut last_label = rotor.trust_epoch().to_string();
    loop {
        if halt.requested() {
            return;
        }
        // Skipped while retrying after a failure: the backoff below is the wait then, and
        // waiting for the window as well would delay a recovery the window has passed.
        if consecutive_failures == 0
            && wait_for_window(signer, overlap, epoch_watch, &last_label, halt)
        {
            return;
        }
        if halt.requested() {
            return;
        }
        match observe_trust_epoch(rotor, signer, epoch_watch, &mut last_label, halt) {
            EpochStep::Halt => return,
            EpochStep::Retry(failures) => {
                consecutive_failures = failures;
                continue;
            }
            EpochStep::Proceed => {}
        }
        match attempt_rotation(rotor, signer, overlap, halt) {
            RotationStep::Halt => return,
            RotationStep::Continue(failures) => consecutive_failures = failures,
        }
    }
}

/// Wait until the overlap window opens, or until the shared trust epoch moves.
///
/// In steady state the loop sleeps until `exp - overlap`, so a successor is minted while
/// the predecessor is still valid. The wait ALSO breaks early when the shared trust epoch
/// advances, which is what bounds cross-replica revocation by the ~500ms epoch poll rather
/// than by a full TTL. With no current key — startup edge, or post-retirement — it rotates
/// at once.
///
/// Returns `true` when a halt was requested.
fn wait_for_window(
    signer: &Arc<crate::delegated_server_signer::DelegatedServerSigner>,
    overlap: i64,
    epoch_watch: Option<&DelegatedEpochWatch>,
    last_label: &str,
    halt: &crate::managed_worker::Halt,
) -> bool {
    let wake_at = match signer.current(now_unix()) {
        // Class R: a window start that cannot be computed wakes the worker NOW. Wrapping
        // parks this worker for the life of the process, so the key is never rotated.
        Some(a) => a
            .exp
            .checked_sub(overlap)
            .unwrap_or(i64::MIN)
            .max(now_unix()),
        None => now_unix(),
    };
    let mut ticks = 0u32;
    while now_unix() < wake_at {
        if halt.requested() {
            return true;
        }
        // Poll the shared trust epoch ~every 500ms (10 * 50ms).
        if ticks.is_multiple_of(10) {
            if let Some(watch) = epoch_watch.as_ref() {
                if matches!(watch.current_label(), Some(l) if l != last_label) {
                    break;
                }
            }
        }
        // Wrapping IS the algebra: a phase counter read only through `is_multiple_of(10)`
        // names a position in a cycle and has no largest value to overflow past.
        ticks = ticks.wrapping_add(1);
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::*;
    use mcp_re_core::SigningKey;
    use mcp_re_http_profile::ActiveDelegatedKey;
    use mcp_re_http_profile::ActorIdentity;

    const NOW: i64 = 1_700_000_100;

    /// A snapshot valid for another hour, so "retired at once" is distinguishable from
    /// "expired on its own".
    fn live_key() -> ActiveDelegatedKey {
        ActiveDelegatedKey {
            key: Arc::new(SigningKey::from_seed_bytes(&[9u8; 32])),
            delegated_kid: "delegated-1".into(),
            server_signer: ActorIdentity {
                role: "server".into(),
                trust_domain: "example.com".into(),
                subject: "did:example:server".into(),
                keyid: "delegated-1".into(),
            },
            credential: "cred".into(),
            nbf: 0,
            exp: NOW + 3600,
        }
    }

    /// T2. A panic in the rotor retires the snapshot AT ONCE, while its key is still
    /// inside its own window.
    ///
    /// The window is the whole point. A dead rotor with the snapshot left in place keeps
    /// signing until `exp` and then 503s with no attributable cause, and every health
    /// surface reads steady state on the way there: `consecutive_failures` is written only
    /// by this thread, so a dead one leaves it at 0.
    ///
    /// The supervisor is run exactly as production runs it, with only the body replaced.
    /// Before the extraction that was impossible — `SigningPlane::for_teardown_test`
    /// advertises "one that panics" and spawns through `WorkerSet` directly, so it measures
    /// `WorkerSet`, and deleting this supervisor left every test green (R11-572/573/574).
    #[test]
    fn a_panicking_rotor_retires_the_snapshot_immediately_not_at_exp() {
        let signer = Arc::new(crate::delegated_server_signer::DelegatedServerSigner::new());
        signer.publish(live_key());
        assert!(
            signer.current(NOW).is_some(),
            "a live rotor signs with a key inside its window"
        );
        assert_eq!(signer.metrics().consecutive_failures(), 0);

        // The panic is this test's INPUT, so the hook is quieted for the duration.
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let supervised = supervise_delegated_rotation(Arc::clone(&signer), || {
            panic!("injected: the rotation body died");
        });
        let joined = std::thread::spawn(supervised).join();
        std::panic::set_hook(hook);

        assert!(
            joined.is_ok(),
            "the supervisor converts the panic; it does not propagate it"
        );
        assert!(
            signer.current(NOW).is_none(),
            "response signing must fail closed NOW, not in an hour when the key expires"
        );
        assert!(
            signer.metrics().consecutive_failures() > 0,
            "the metric only this thread writes must stop reading steady state"
        );

        // Terminal: a straggler mint that lands after the panic cannot restore signing.
        signer.publish(live_key());
        assert!(
            signer.current(NOW).is_none(),
            "after a panic the rotor's state is not known good; continuing to mint from it \
             would be worse than refusing"
        );
    }
}
