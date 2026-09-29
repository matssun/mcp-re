// SPDX-License-Identifier: Apache-2.0
//! The serving fleet runs only through the lifecycle gate.
//!
//! [`crate::app::serve_fleet`] is the phase-1 execution primitive beneath
//! [`MaterializedRuntime::serve`](super::MaterializedRuntime::serve): it binds the per-core
//! listeners and serves until the drain. `serve` is what makes serving legal — it holds a
//! `RuntimeLifecycle` that reached `Materialized` by value, records the serving events only
//! once they happened, and tears the runtime down in its documented order. A crate-visible
//! `serve_fleet` taking plain arguments let any crate code serve past all of that.
//!
//! [`FleetServeAuthorized`] closes that route. `serve_fleet` cannot be called without one,
//! and the only producer is [`FleetServeAuthorized::issue`], visible to
//! `materialized_runtime` alone and called from `serve`. So crate code cannot execute the
//! serving fleet except through `MaterializedRuntime::serve`.
//!
//! The witness carries the fleet configuration it authorizes, and `serve_fleet` obtains
//! the configuration only by consuming it: the authorization and the fleet it covers are
//! one value, not two arguments a caller could pair differently.
//!
//! Sealed by module privacy, which is the lever that binds inside this crate: the field is
//! private to this module, `issue` is `pub(super)`, and nothing derives a constructor —
//! no `Default`, no `Clone`, no serialization. `structural://proxy/fleet_serve/sole_route`
//! (probes S30 and S31) compiles the two forgeries and requires the compiler to refuse them.

use crate::async_fleet::FleetConfig;

/// Authorization to serve one fleet, issued by the lifecycle gate and consumed by the
/// serve.
pub(crate) struct FleetServeAuthorized {
    fleet: FleetConfig,
}

impl FleetServeAuthorized {
    /// The only producer. `pub(super)`: `materialized_runtime` issues it inside
    /// [`MaterializedRuntime::serve`](super::MaterializedRuntime::serve), and no other
    /// module can name it.
    pub(super) fn issue(fleet: FleetConfig) -> Self {
        Self { fleet }
    }

    /// Spend the authorization for the fleet it covers.
    pub(crate) fn into_fleet_config(self) -> FleetConfig {
        self.fleet
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The authorization hands back exactly the fleet it was issued for: the witness
    /// adds a precondition to serving, never a second opinion about what is served.
    #[test]
    fn the_authorized_fleet_is_the_issued_fleet() {
        let fleet = FleetConfig {
            addr: "127.0.0.1:0".parse().expect("a literal socket address"),
            cores: 3,
            workers_per_shard: 2,
            listen_backlog: 64,
            max_in_flight_total: Some(7),
        };
        let issued = format!("{fleet:?}");
        let served = FleetServeAuthorized::issue(fleet).into_fleet_config();
        assert_eq!(format!("{served:?}"), issued);
    }
}
