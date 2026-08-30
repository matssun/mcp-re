// SPDX-License-Identifier: Apache-2.0
//! The break-glass half of rotation: what the shared trust epoch says, and what asking it
//! costs (ADR-MCPRE-052 §7).
//!
//! Separate from the schedule because it OVERRIDES the schedule. Swapping to a new epoch
//! now — rather than at the next scheduled rotation — is what makes verifiers pinned to the
//! prior accepted-epoch set reject on the very next request, across every replica, since
//! they all read the same counter. A revocation that waited for a TTL would not be one.
//!
//! Two refusals here are easy to soften and must not be:
//!
//! * an UNREADABLE or REGRESSED epoch stops minting entirely. A credential without a
//!   comparable epoch is unrevokable, and rebasing onto a value this replica made up would
//!   produce exactly that. The current key keeps serving until its `exp`, after which the
//!   hot path fails closed on its own.
//! * a DECLINED advance leaves `last_label` where it was, so the next pass re-enters and
//!   retries. Advancing it here would report a revocation that never happened and never
//!   look at it again — and the operator''s break-glass would be silently not in force.

use std::sync::Arc;

use crate::clock::now_unix;
use crate::delegated_server_signer::TrustEpochAdvance;

use super::rotation_jitter;
use super::DelegatedEpochWatch;

/// What the shared trust epoch says to do next.
pub(super) enum EpochStep {
    /// A halt was requested.
    Halt,
    /// Back off and re-enter the loop, carrying the failure count.
    Retry(u32),
    /// Nothing to do about the epoch; go on to the scheduled rotation.
    Proceed,
}

/// A trust-epoch advance takes PRIORITY over the scheduled rotation (ADR-MCPRE-052 §7).
///
/// Swapping to the new epoch NOW is what makes verifiers pinned to the prior accepted-epoch
/// set reject on the next request, across every replica, since they all read the same
/// counter.
///
/// An unreadable or regressed epoch FAILS CLOSED FOR MINTING: a credential without a
/// comparable epoch is unrevokable, so nothing is issued. The current key keeps serving
/// until its `exp`, after which the hot path fails closed on its own — no stale-epoch
/// minting, no rebase.
pub(super) fn observe_trust_epoch(
    rotor: &mut crate::delegated_wiring::ProdDelegatedRotor,
    signer: &Arc<crate::delegated_server_signer::DelegatedServerSigner>,
    epoch_watch: Option<&DelegatedEpochWatch>,
    last_label: &mut String,
    halt: &crate::managed_worker::Halt,
) -> EpochStep {
    let Some(watch) = epoch_watch.as_ref() else {
        return EpochStep::Proceed;
    };
    let Some(label) = watch.current_label() else {
        return refuse_to_mint_without_a_comparable_epoch(signer, halt);
    };
    if label == *last_label {
        return EpochStep::Proceed;
    }
    apply_epoch_advance(rotor, signer, label, last_label, halt)
}

/// FAIL CLOSED FOR MINTING when the shared epoch is unreadable or regressed.
///
/// A credential without a comparable epoch is unrevokable, so nothing is issued — the
/// epoch is never rebased onto a value this replica made up. The current key keeps serving
/// until its `exp`, after which the hot path fails closed on its own.
fn refuse_to_mint_without_a_comparable_epoch(
    signer: &Arc<crate::delegated_server_signer::DelegatedServerSigner>,
    halt: &crate::managed_worker::Halt,
) -> EpochStep {
    use crate::delegated_server_signer::rotation_backoff;
    let consecutive_failures = signer.metrics().record_failure();
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
        return EpochStep::Halt;
    }
    EpochStep::Retry(consecutive_failures)
}

/// Ask the root to re-issue under the new epoch, and read its answer.
///
/// Three outcomes and only one advances this replica. On a DECLINE, `last_label` is
/// deliberately left where it was so the next pass re-enters and retries; advancing it
/// here would report a revocation that never happened and never look at it again.
fn apply_epoch_advance(
    rotor: &mut crate::delegated_wiring::ProdDelegatedRotor,
    signer: &Arc<crate::delegated_server_signer::DelegatedServerSigner>,
    label: String,
    last_label: &mut String,
    halt: &crate::managed_worker::Halt,
) -> EpochStep {
    use crate::delegated_server_signer::rotation_backoff;
    match rotor.advance_trust_epoch(label.clone(), now_unix()) {
        Ok(TrustEpochAdvance::Advanced) => {
            *last_label = label;
            signer.metrics().record_success(now_unix());
            eprintln!(
                "mcp-re-proxy: trust epoch advanced -> {last_label}: delegated keys re-issued \
                 under the new epoch. This replica no longer mints under the prior epoch. \
                 Credentials already issued under it stay VERIFIABLE until verifiers are \
                 pointed at the new epoch — update the verifiers' accepted epochs to complete \
                 the revocation (delegation_trust_epoch_stale)."
            );
            EpochStep::Retry(0)
        }
        // The root declined and the PRIOR-epoch key is still valid. `last_label` is
        // deliberately left where it was, so the next pass re-enters this arm and retries;
        // advancing it here would report a revocation that never happened and never look at
        // it again.
        Ok(TrustEpochAdvance::Declined) => {
            let consecutive_failures = signer.metrics().record_failure();
            let ttl = signer.seconds_to_expiry(now_unix());
            let backoff = rotation_backoff(consecutive_failures, ttl, rotation_jitter());
            eprintln!(
                "mcp-re-proxy: WARNING: trust epoch advance to {label} NOT APPLIED (root issuer \
                 declined); this replica is STILL MINTING under the prior epoch on its current \
                 key, until that key's exp ({}s) and then FAILS CLOSED. The break-glass \
                 revocation is not yet in force here. consecutive_failures {}. Retrying in {}ms.",
                ttl.unwrap_or(0),
                consecutive_failures,
                backoff.as_millis(),
            );
            if halt.sleep(backoff) {
                return EpochStep::Halt;
            }
            EpochStep::Retry(consecutive_failures)
        }
        Err(_) => {
            let consecutive_failures = signer.metrics().record_failure();
            let ttl = signer.seconds_to_expiry(now_unix());
            let backoff = rotation_backoff(consecutive_failures, ttl, rotation_jitter());
            eprintln!(
                "mcp-re-proxy: WARNING: re-issue on trust-epoch advance FAILED (root issuer \
                 unavailable); consecutive_failures {}. Retrying in {}ms.",
                consecutive_failures,
                backoff.as_millis(),
            );
            if halt.sleep(backoff) {
                return EpochStep::Halt;
            }
            EpochStep::Retry(consecutive_failures)
        }
    }
}
