// SPDX-License-Identifier: Apache-2.0
//! The admission-limit basis — `work/CONFIG-STATE-ATLAS.md` §H.2.
//!
//! Not a deployment machine: there is no posture here, no control that is on in one state
//! and off in another. It is a RESOLVED FACT — layer A has answered which of two mutually
//! exclusive ways of stating one admission limit survived, and supplied the default when
//! the operator stated neither.
//!
//! # Why the request needs a type at all
//!
//! The limit can be stated at two altitudes: `--max-in-flight` bounds each core directly,
//! `--max-in-flight-total` names a fleet-wide target that is divided evenly across the
//! resolved cores. They are alternatives, and [`InFlightLimitRequest`] holds one, so a
//! request naming both cannot be built at all.
//!
//! Recording that choice in two `Option` fields could not express it. `ServerLimits`
//! carries a fail-safe per-core default, so `Some(256)` meant either "the operator asked
//! for 256 per core" or "the operator said nothing" — and once a fleet-wide target had to
//! out-rank the default but not an explicit value, the parser had to reconstruct that
//! distinction and encode it by ERASING the field, writing `None` over the default. A
//! request that eagerly fills defaults destroys the difference between a value chosen and
//! a value never mentioned, and reconstructing it in the parser puts the rule below the
//! boundary every other legality rule is decided at: a `DeploymentRequest` built in code met none of
//! it.
//!
//! So the request states its intent once, with absence representable, and layer A applies
//! the default.
//!
//! # Where the number comes from afterwards
//!
//! The basis is NOT a per-core ceiling. Turning a fleet-wide target into one needs the
//! resolved core count, which is an environment reading, so it belongs after planning:
//!
//! ```text
//! InFlightLimitRequest  (what was asked; absence is representable)
//!         ↓ layer A: mutual exclusivity + default
//! InFlightLimitBasis    (which basis survived)
//!         ↓ + resolved cores
//! async_fleet::derived_per_core_ceiling
//!         ↓
//! the per-core ceiling every consumer enforces
//! ```

use std::num::NonZeroUsize;

use crate::deployment_request::DeploymentRequest;

/// The admission limit as the OPERATOR stated it, absence included.
///
/// Three inhabitants, because there are three things an operator can have done. The two
/// set variants are alternatives by construction, so the both-set case this type's
/// predecessor allowed cannot be written down here at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InFlightLimitRequest {
    /// The operator named no admission limit. NOT "no limit": the basis supplies the
    /// fail-safe per-core default, because unbounded in-flight is attacker-controlled
    /// buffering ahead of the verify gate.
    #[default]
    Unspecified,
    /// `--max-in-flight`: each core admits this many concurrent requests.
    PerCore(NonZeroUsize),
    /// `--max-in-flight-total`: the fleet as a whole targets this many, divided evenly
    /// across the resolved cores.
    FleetTotal(NonZeroUsize),
}

/// Which basis the admission limit is expressed in, after layer A has applied the default.
///
/// `Unspecified` is gone: every validated deployment has a basis. That is the whole point —
/// downstream never has to ask whether `None` means "a total was given", "the default
/// applies" or "there is no ceiling", because none of those reach it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InFlightLimitBasis {
    /// A per-core ceiling, applied verbatim to every core.
    PerCore { requests: NonZeroUsize },
    /// A fleet-wide target, divided evenly across the resolved cores.
    FleetTotal { requests: NonZeroUsize },
}

impl InFlightLimitBasis {
    /// The per-core ceiling this basis states DIRECTLY, or `None` when it is expressed
    /// fleet-wide and needs the core count to become one.
    ///
    /// Paired with [`fleet_total`](Self::fleet_total) so the two are read off the basis
    /// rather than matched on at each call site — exactly one is `Some`, which is what
    /// makes them safe inputs to
    /// [`derived_per_core_ceiling`](crate::async_fleet::derived_per_core_ceiling).
    pub fn per_core(&self) -> Option<usize> {
        match self {
            Self::PerCore { requests } => Some(requests.get()),
            Self::FleetTotal { .. } => None,
        }
    }

    /// The fleet-wide target this basis states, or `None` when it is expressed per core.
    pub fn fleet_total(&self) -> Option<usize> {
        match self {
            Self::PerCore { .. } => None,
            Self::FleetTotal { requests } => Some(requests.get()),
        }
    }
}

/// The fail-safe per-core ceiling for a deployment that names no admission limit.
///
/// One constant, two readers: this and [`crate::tls::ServerLimits::default`], which must
/// agree because a `ServerLimits` built directly — by a test, by an embedder driving
/// `async_serve` without a `DeploymentRequest` — gets the same bound the validated path resolves to.
pub const DEFAULT_PER_CORE_IN_FLIGHT: usize = 256;

/// The per-core ceiling an unspecified limit means, as a value whose non-zeroness is a
/// BUILD-TIME fact.
///
/// Class C: a `const` initializer is evaluated by the compiler, so a
/// `DEFAULT_PER_CORE_IN_FLIGHT` of zero stops the build rather than panicking at runtime.
const DEFAULT_PER_CORE_CEILING: NonZeroUsize = match NonZeroUsize::new(DEFAULT_PER_CORE_IN_FLIGHT) {
    Some(ceiling) => ceiling,
    None => panic!("DEFAULT_PER_CORE_IN_FLIGHT must be non-zero"),
};

/// Recognise the basis. Total and infallible: every `DeploymentRequest` states one of three things,
/// and the default makes the third a basis too.
///
/// There is no mutual-exclusivity refusal here, or anywhere at this layer: the illegal
/// combination is not representable, so there is no state to reject. What survives is the
/// parser's [`second_admission_limit`](crate::cli), which refuses an ARGUMENT LIST naming
/// two — a fact about the input, not about the request.
pub fn classify(config: &DeploymentRequest) -> InFlightLimitBasis {
    match config.in_flight_limit {
        InFlightLimitRequest::PerCore(requests) => InFlightLimitBasis::PerCore { requests },
        InFlightLimitRequest::FleetTotal(requests) => InFlightLimitBasis::FleetTotal { requests },
        InFlightLimitRequest::Unspecified => InFlightLimitBasis::PerCore {
            requests: DEFAULT_PER_CORE_CEILING,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_state::test_support::legal_config;

    fn n(v: usize) -> NonZeroUsize {
        NonZeroUsize::new(v).expect("non-zero")
    }

    fn basis_of(request: InFlightLimitRequest) -> InFlightLimitBasis {
        let mut config = legal_config();
        config.in_flight_limit = request;
        classify(&config)
    }

    /// Absence is a THIRD thing, not a synonym for the default value. The distinction is
    /// the whole reason this type exists, so it is asserted on the request rather than
    /// inferred from the basis it produces.
    #[test]
    fn an_absent_limit_is_distinguishable_from_one_that_equals_the_default() {
        assert_ne!(
            InFlightLimitRequest::Unspecified,
            InFlightLimitRequest::PerCore(n(DEFAULT_PER_CORE_IN_FLIGHT)),
            "a request that cannot tell these apart is the defect this type removes"
        );
        assert_eq!(
            InFlightLimitRequest::default(),
            InFlightLimitRequest::Unspecified
        );
    }

    /// Exactly one of the two projections is `Some`, for every basis. `derived_per_core_ceiling`
    /// takes both, and its both-set arm is the unreachable one — so a basis that could
    /// answer both would hand the gate the input nothing is supposed to produce.
    #[test]
    fn exactly_one_projection_answers_for_every_basis() {
        for basis in [
            InFlightLimitBasis::PerCore { requests: n(32) },
            InFlightLimitBasis::FleetTotal { requests: n(1000) },
        ] {
            assert_eq!(
                basis.per_core().is_some(),
                basis.fleet_total().is_none(),
                "{basis:?} answers both or neither"
            );
        }
        assert_eq!(
            InFlightLimitBasis::PerCore { requests: n(32) }.per_core(),
            Some(32)
        );
        assert_eq!(
            InFlightLimitBasis::FleetTotal { requests: n(1000) }.fleet_total(),
            Some(1000)
        );
    }

    /// The unspecified case resolves to the fail-safe default rather than to "no ceiling".
    /// Unbounded in-flight is attacker-controlled buffering ahead of the verify gate, so
    /// the absence of a flag must not disable the control.
    #[test]
    fn saying_nothing_resolves_to_the_bounded_default() {
        assert_eq!(
            basis_of(InFlightLimitRequest::Unspecified),
            InFlightLimitBasis::PerCore {
                requests: n(DEFAULT_PER_CORE_IN_FLIGHT)
            }
        );
    }

    /// Each stated basis is carried through unchanged: this classifier applies a default,
    /// it does not normalize a value the operator chose.
    #[test]
    fn a_stated_basis_is_carried_through_unchanged() {
        assert_eq!(
            basis_of(InFlightLimitRequest::PerCore(n(32))),
            InFlightLimitBasis::PerCore { requests: n(32) }
        );
        assert_eq!(
            basis_of(InFlightLimitRequest::FleetTotal(n(1000))),
            InFlightLimitBasis::FleetTotal { requests: n(1000) }
        );
    }
}
