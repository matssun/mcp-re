// SPDX-License-Identifier: Apache-2.0
//! The verifier-local admission budget — #415 §5.2.
//!
//! Everything else in `crate::admission` is what an AUTHORITY said and whether it is still
//! true. This is the separate question of what THIS enforcement point is willing to accept
//! while asking: how stale an assertion may be, how far the clocks may drift, and whether
//! an unreachable authority may be served through at all and for how long.
//!
//! It is a deployment's decision, not an authority's, and `allow_degraded_mode` is the one
//! that matters — it is the opt-in the degraded clause of the §7 currency contract is
//! stated in terms of, and its default is the fail-closed answer.

#[cfg(feature = "verify")]
use verus_builtin_macros::verus_spec;
#[cfg(feature = "verify")]
#[allow(unused_imports)]
use vstd::prelude::*;

/// The verifier-local admission freshness + fallback budget (§5.2).
///
/// # Why this is not sealed, and where the legality actually lives
///
/// The fields are `pub` and there is no constructor, so a caller can name any cell —
/// including `allow_degraded_mode: true` with a zero bound, which the command line refuses
/// outright because "a zero P still admits a revoked workload for the skew tolerance while
/// claiming no window was configured". That is not an oversight to be closed here. Verus
/// refuses `external_type_specification` on a datatype with non-public fields, and
/// `allow_degraded_mode` is the deployment opt-in the degraded clause of the §7 currency
/// theorem is stated in terms of — sealing this type would make the clause unstatable
/// (`docs/dev/sealed-owners.md`, "A proved postcondition outranks a seal").
///
/// The legality is owned one layer up and by a type that CAN hold it:
/// `config_state::AdmissionAvailability` is a tagged value whose degraded arm carries a
/// `NonZeroU64`, so the illegal cells are unconstructible there, and
/// `serving_capabilities` PROJECTS this budget from it. Possessing an `AdmissionPolicy`
/// therefore establishes nothing; what establishes the cell is where it came from.
#[derive(Debug, Clone, Copy)]
pub struct AdmissionPolicy {
    /// N — the maximum age (seconds) of an assertion the PEP will accept, beyond
    /// its own `exp`-based freshness. Bounds how stale an admitted-state snapshot
    /// may be even within its TTL.
    pub max_assertion_age: i64,
    /// Clock-skew tolerance on the assertion's `[nbf, exp]` window.
    pub max_clock_skew: i64,
    /// P — the bound (seconds) within which the PEP may serve on the LAST-KNOWN
    /// authoritative state when the live state is unreachable, IF degraded mode is
    /// enabled. Past P, an unreachable authority is fail-closed.
    pub degraded_propagation_bound: i64,
    /// Whether degraded mode is enabled at all. Default false: an unreachable
    /// authority fails closed immediately. Enabling it is an explicit deployment
    /// act, because it trades a bounded window of stale-admission risk for
    /// availability.
    pub allow_degraded_mode: bool,
}

impl Default for AdmissionPolicy {
    fn default() -> Self {
        AdmissionPolicy {
            max_assertion_age: 300,
            max_clock_skew: 30,
            degraded_propagation_bound: 0,
            allow_degraded_mode: false,
        }
    }
}

/// Whether an assertion issued at `iat` is older at `now` than the degraded bound P plus the
/// skew tolerance — the age term of the §7 degraded clause, compared exactly.
///
/// Widened to `i128` so neither side clamps: a saturating age stops at `i64::MAX`, and
/// against a bound sum at that clamp an assertion older than the bound would pass. `pub(crate)`
/// because the currency check in `crate::admission` is its consumer and this module, which
/// owns the budget, is not that module's ancestor.
#[cfg_attr(feature = "verify", verus_spec(out =>
    ensures out == (now - iat > policy.degraded_propagation_bound + policy.max_clock_skew),
))]
// Four widened `i64` operands: the difference and the sum both lie within [-2^64, 2^64],
// far inside `i128`.
#[allow(clippy::arithmetic_side_effects)]
pub(crate) fn degraded_age_exceeded(policy: &AdmissionPolicy, now: i64, iat: i64) -> bool {
    (now as i128) - (iat as i128)
        > (policy.degraded_propagation_bound as i128) + (policy.max_clock_skew as i128)
}

/// Whether an assertion issued at `iat` is older at `now` than the staleness budget N plus the
/// skew tolerance — the verifier's own cap in `verify_admission_assertion`, compared exactly.
///
/// Widened to `i128` for the same reason as [`degraded_age_exceeded`]: under saturation an
/// age clamped at `i64::MAX` equals a budget sum clamped there, and the over-age assertion
/// passes. `pub(crate)` for the same consumer, `crate::admission`.
// Four widened `i64` operands: the difference and the sum both lie within [-2^64, 2^64],
// far inside `i128`.
#[allow(clippy::arithmetic_side_effects)]
pub(crate) fn assertion_age_exceeded(policy: &AdmissionPolicy, now: i64, iat: i64) -> bool {
    (now as i128) - (iat as i128)
        > (policy.max_assertion_age as i128) + (policy.max_clock_skew as i128)
}
