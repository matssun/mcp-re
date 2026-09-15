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
