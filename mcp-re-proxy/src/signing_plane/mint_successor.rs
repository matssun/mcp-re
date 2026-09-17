// SPDX-License-Identifier: Apache-2.0
//! Asking the root for a successor, and reading its answer HONESTLY.
//!
//! `DelegatedSigningCustody::ensure_active` reports `Ok(())` in two very different
//! situations: a successor was issued, or issuance FAILED while the current key is still
//! valid — so the fleet keeps signing and the caller is expected to retry. Only the first is
//! progress.
//!
//! The second is the PRIMARY failure mode: a root outage during the overlap window, which is
//! exactly what the overlap exists to absorb. Taking it as success would reset the backoff,
//! collapse the wake time to now — the loop is already past `exp - overlap` — and re-enter
//! immediately: a tight retry loop against the root KMS or HSM, minting a fresh keypair
//! every pass, for the whole overlap window. That is why this module exists as its own
//! authority rather than as a boolean at the call site.
//!
//! Nothing here extends anything. Serving continues on the current key until its `exp` and
//! then FAILS CLOSED (ADR-MCPRE-052 §6) — no stale-key extension, no direct-root fallback.

use std::sync::Arc;

use crate::clock::now_unix;

use super::rotation_jitter;

/// What one scheduled rotation attempt leaves the loop with.
pub(super) enum RotationStep {
    Halt,
    Continue(u32),
}

/// Mint the successor, and read what came back HONESTLY.
///
/// `rotor.rotate` reports `Ok(())` in two very different situations, and only one of them
/// is a rotation — see [`rotation_made_progress`]. Taking the other as success would reset
/// the backoff and re-enter immediately, giving a root outage a tight retry loop that mints
/// a fresh keypair every pass for the whole overlap window.
pub(super) fn attempt_rotation(
    rotor: &mut crate::delegated_wiring::ProdDelegatedRotor,
    signer: &Arc<crate::delegated_server_signer::DelegatedServerSigner>,
    overlap: i64,
    halt: &crate::managed_worker::Halt,
) -> RotationStep {
    use crate::delegated_server_signer::rotation_backoff;
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
    let before_kid = signer
        .current(now_unix())
        .map(|a| a.delegated_kid().to_owned());
    match rotor.rotate(now_unix()) {
        Ok(()) if !rotation_made_progress(signer, &before_kid, overlap) => {
            let consecutive_failures = signer.metrics().record_failure();
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
                return RotationStep::Halt;
            }
            RotationStep::Continue(consecutive_failures)
        }
        Ok(()) => {
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
            RotationStep::Continue(0)
        }
        Err(_) => {
            let consecutive_failures = signer.metrics().record_failure();
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
                return RotationStep::Halt;
            }
            RotationStep::Continue(consecutive_failures)
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
pub(super) fn rotation_made_progress(
    signer: &crate::delegated_server_signer::DelegatedServerSigner,
    before_kid: &Option<String>,
    overlap: i64,
) -> bool {
    let now = now_unix();
    let Some(active) = signer.current(now) else {
        // Nothing published: not progress, but also nothing to back off protecting.
        return false;
    };
    if active.delegated_kid() != before_kid.as_deref().unwrap_or("") {
        return true;
    }
    // Same kid. Only a rotation that was DUE and did not happen is a failure, and a
    // window whose start cannot be computed is not evidence that nothing was due: a
    // wrapped `exp - overlap` reports progress precisely when rotation is most overdue.
    active
        .exp()
        .checked_sub(overlap)
        .is_some_and(|due_from| now < due_from)
}

/// Whether a rotation attempt actually minted a successor.
///
/// Beside its subject rather than in the plane's own file: the distinction these pin is
/// this module's whole reason to exist, and a battery one file away from the decision it
/// measures is how the decision ends up in no unit's closure.
#[cfg(test)]
mod tests {
    use super::rotation_made_progress;

    use crate::delegated_server_signer::DelegatedServerSigner;
    use mcp_re_http_profile::ActiveDelegatedKey;

    const OVERLAP: i64 = 60;

    /// `seed` stands in for the old `kid` argument: a fixture cannot name a delegated kid
    /// any more, because the kid is the thumbprint of the key the credential attests. Two
    /// seeds are two keys and therefore two kids, which is all these controls ever needed.
    fn key(seed: u8, exp: i64) -> ActiveDelegatedKey {
        crate::delegated_wiring::test_support::issued_expiring_at(exp, seed)
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
        let now = crate::clock::now_unix();
        // Published key is inside its overlap window: a rotation is DUE.
        let published = key(1, now + OVERLAP - 1);
        let before = Some(published.delegated_kid().to_owned());
        signer.publish(published);
        assert!(
            !rotation_made_progress(&signer, &before, OVERLAP),
            "a due rotation that did not change the kid means issuance failed"
        );
    }

    #[test]
    fn a_new_kid_is_progress() {
        let signer = DelegatedServerSigner::new();
        let now = crate::clock::now_unix();
        signer.publish(key(2, now + 300));
        let before = Some(key(1, now + 300).delegated_kid().to_owned());
        assert!(rotation_made_progress(&signer, &before, OVERLAP));
    }

    /// Outside the overlap window an unchanged kid is expected, not a failure — the
    /// backoff must not engage in steady state.
    #[test]
    fn unchanged_kid_outside_the_overlap_window_is_not_a_failure() {
        let signer = DelegatedServerSigner::new();
        let now = crate::clock::now_unix();
        let published = key(1, now + 10 * OVERLAP);
        let before = Some(published.delegated_kid().to_owned());
        signer.publish(published);
        assert!(rotation_made_progress(&signer, &before, OVERLAP));
    }

    /// Nothing published: the `Err` arm owns that case; report no progress.
    #[test]
    fn nothing_published_is_not_progress() {
        let signer = DelegatedServerSigner::new();
        assert!(!rotation_made_progress(&signer, &None, OVERLAP));
    }
}
