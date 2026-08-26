// SPDX-License-Identifier: Apache-2.0
//! Holding the inner plane's in-flight bound at or above the fleet's admission ceiling.
//!
//! The RULE is pure and lives in [`crate::startup_plan`]; the core count is the environment
//! reading it needs. What lives here is the wiring and the announcement, together — the
//! raise and the line explaining it are one decision, and separating them is how a
//! transcript starts describing a bound the pool does not have.
//!
//! # Why the bound matters
//!
//! The pool is PROCESS-WIDE (one instance behind the `Arc` every core shares), so its
//! in-flight bound must not sit below the fleet's aggregate admission ceiling. If it did,
//! requests that passed every security gate would be answered with a signed `inner server
//! unavailable` at a capacity cliff no configured flag names — and the shedding decision
//! would move from the admission gate, where it is deliberate, to the inner pool, where it
//! is an accident of core count.

use crate::config_state::topology::ShardTopologyRequest;
use crate::config_state::InFlightLimitBasis;
use crate::http_inner::HttpInnerPool;

/// Return `pool` bounded at or above the fleet admission ceiling, announcing any raise.
pub(crate) fn raised_to_fleet_ceiling(
    pool: HttpInnerPool,
    in_flight_limit: InFlightLimitBasis,
    shards: ShardTopologyRequest,
) -> HttpInnerPool {
    let cores = crate::async_fleet::resolve_core_count(shards.shards_or_auto());
    let ceiling = crate::startup_plan::inner_plane_ceiling(
        in_flight_limit.per_core(),
        in_flight_limit.fleet_total(),
        cores,
    );
    let Some(raised) =
        crate::startup_plan::inner_plane_raise(ceiling, crate::http_inner::DEFAULT_MAX_IN_FLIGHT)
    else {
        return pool;
    };
    eprintln!(
        "mcp-re-proxy: inner-plane in-flight bound raised to {raised} to stay at or \
         above the fleet admission ceiling ({cores} cores); the admission gate sheds, \
         not the inner pool."
    );
    pool.with_max_in_flight(raised)
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use crate::config_state::InFlightLimitBasis;

    /// The rule this wiring applies, asked of the pure decision it defers to.
    ///
    /// The wiring itself builds an `HttpInnerPool`, which needs a URL and a runtime; what
    /// is worth pinning here is that the ceiling and the raise are read from the basis
    /// rather than recomputed, and that is observable through the plan's own functions.
    #[test]
    fn the_ceiling_comes_from_the_basis_and_the_core_count_together() {
        let basis = InFlightLimitBasis::PerCore {
            requests: std::num::NonZeroUsize::new(8).expect("8 is not zero"),
        };
        let ceiling =
            crate::startup_plan::inner_plane_ceiling(basis.per_core(), basis.fleet_total(), 4);
        assert_eq!(
            ceiling,
            crate::startup_plan::inner_plane_ceiling(basis.per_core(), basis.fleet_total(), 4),
            "the ceiling is a function of its inputs, not of when it is asked"
        );
        let bound = ceiling.expect("a per-core basis always yields a ceiling");
        assert!(
            crate::startup_plan::inner_plane_raise(ceiling, bound).is_none(),
            "a pool already at the ceiling is not raised"
        );
        assert_eq!(
            crate::startup_plan::inner_plane_raise(ceiling, bound - 1),
            Some(bound),
            "a pool below the fleet ceiling is raised to it, not past it"
        );
    }
}
