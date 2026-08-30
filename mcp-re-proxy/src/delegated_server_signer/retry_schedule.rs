// SPDX-License-Identifier: Apache-2.0
//! HOW LONG a failed delegated-key rotation waits before approaching the root again.
//!
//! One authority, and a PURE one: given a failure streak, the current key's remaining
//! validity and a random sample, it yields the interval and nothing else. That is why it
//! can be unit-tested without threads or a clock, and why the schedule's three properties
//! — the exponential term, the cap by remaining validity, and the equal jitter — are
//! stated in one place rather than distributed through the rotor that sleeps on them.

use std::num::NonZeroU64;
use std::time::Duration;

/// The exponential-backoff base and ceiling for delegated-key issuance retries.
const ROTATION_BACKOFF_BASE_MS: u64 = 250;
const ROTATION_BACKOFF_MAX_MS: u64 = 30_000;
const ROTATION_BACKOFF_MIN_MS: u64 = 50;

/// The bounded, jittered exponential backoff for a failed delegated-key rotation
/// (ADR-MCPRE-052 §6 follow-up, MCPRE-122). PURE and deterministic given its inputs, so
/// the schedule is unit-tested without threads or a clock.
///
/// - Exponential in `consecutive_failures` (1-indexed): `250ms · 2^(n-1)`, ceilinged at
///   30s so a long root outage retries at a steady cadence rather than hot-spinning.
/// - Capped by the CURRENT key's remaining validity while it is still valid
///   (`seconds_to_expiry > 0`): the rotor keeps retrying INSIDE the overlap window and
///   never sleeps past `exp` on the first failures, so a transient root blip is caught
///   before the key expires. Once expired (`None`/`<= 0`), only the 30s ceiling applies
///   — serving is already failing closed and resumes as soon as issuance recovers.
/// - "Equal jitter": the final sleep is uniformly in `[cap/2, cap]`, decorrelating a
///   fleet of rotors so they do not stampede the root issuer in lockstep. `jitter` is a
///   caller-supplied random u64 (OS CSPRNG in production).
pub fn rotation_backoff(
    consecutive_failures: u32,
    seconds_to_expiry: Option<i64>,
    jitter: u64,
) -> Duration {
    // Exponential term, shift-capped at 2^20 to avoid overflow on a pathological streak.
    let shift = consecutive_failures.saturating_sub(1).min(20);
    let raw_ms = ROTATION_BACKOFF_BASE_MS.saturating_mul(1u64 << shift);
    let mut cap_ms = raw_ms.min(ROTATION_BACKOFF_MAX_MS);

    // While the current key is still valid, do not sleep past its expiry.
    if let Some(ttl) = seconds_to_expiry {
        if ttl > 0 {
            let ttl_ms = (ttl as u64).saturating_mul(1000);
            cap_ms = cap_ms.min(ttl_ms);
        }
    }
    cap_ms = cap_ms.max(ROTATION_BACKOFF_MIN_MS);

    // Equal jitter: half the cap, plus a uniform sample of the other half → [cap/2, cap].
    let half = cap_ms / 2;
    // Class B: carrying the span as a `NonZeroU64` makes the remainder OPERATOR total
    // rather than leaving its divisor's non-zeroness argued beside it. The sample is at
    // most `half`, so the sum is at most `cap_ms` and neither saturation is reachable —
    // both are named because a wrapped interval would retry against a failing root at once.
    let span = std::num::NonZeroU64::new(half.saturating_add(1)).unwrap_or(NonZeroU64::MIN);
    let jittered = half.saturating_add(jitter % span);
    Duration::from_millis(jittered)
}
