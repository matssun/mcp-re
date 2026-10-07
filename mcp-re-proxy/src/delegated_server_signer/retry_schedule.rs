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
///   fleet of rotors so they do not stampede the root issuer in lockstep. `draw` yields
///   random u64s (OS CSPRNG in production), `None` when the source fails; the sample is
///   taken by [`uniform_below`], which is unbiased.
pub fn rotation_backoff(
    consecutive_failures: u32,
    seconds_to_expiry: Option<i64>,
    draw: impl FnMut() -> Option<u64>,
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
    let jittered = half.saturating_add(uniform_below(span, draw));
    Duration::from_millis(jittered)
}

/// Draws [`uniform_below`] makes before it gives up and samples no jitter. A real source
/// is rejected with probability below `span / 2^64` per draw, so this bounds only a source
/// that repeats a rejected value.
const MAX_JITTER_DRAWS: u32 = 8;

/// A uniform sample of `0..span`, by rejection. `2^64` is not a multiple of `span`, so the
/// `2^64 mod span` lowest draws would land on some residues once more than the rest; those
/// are redrawn. A failed source, or [`MAX_JITTER_DRAWS`] rejections, yields 0: no jitter,
/// the bounded schedule unchanged.
fn uniform_below(span: NonZeroU64, mut draw: impl FnMut() -> Option<u64>) -> u64 {
    let rejected_below = 0u64.wrapping_sub(span.get()) % span;
    for _ in 0..MAX_JITTER_DRAWS {
        match draw() {
            Some(x) if x >= rejected_below => return x % span,
            Some(_) => {}
            None => return 0,
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 1d4ad626: a draw in the biased low band is redrawn, not reduced. For a 250ms cap
    /// the span is 126 and `2^64 mod 126 = 16`, so 3 is rejected and 131 gives 131 % 126.
    #[test]
    fn a_draw_in_the_biased_band_is_redrawn() {
        let mut draws = [Some(3), Some(131)].into_iter();
        let d = rotation_backoff(1, Some(300), || draws.next().flatten());
        assert_eq!(d, Duration::from_millis(125 + 5));
    }

    /// A failed source samples no jitter rather than panicking or spinning.
    #[test]
    fn a_failed_source_samples_no_jitter() {
        assert_eq!(
            rotation_backoff(1, Some(300), || None),
            Duration::from_millis(125)
        );
        assert_eq!(
            rotation_backoff(1, Some(300), || Some(0)),
            Duration::from_millis(125)
        );
    }
}
