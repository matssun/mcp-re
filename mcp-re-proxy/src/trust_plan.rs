// SPDX-License-Identifier: Apache-2.0
//! The trust plan — the trust subtree's own projection of its validated state.
//!
//! It lived in `startup_plan.rs` until MCPRE-148. A plan produced by an owner lives WITH
//! that owner and the planner re-exports it (ADR-MCPRE-061 §11,
//! `docs/dev/sealed-owners.md`); building it in the planner was the planner restating the
//! owner's semantics, which is what R-COMPOSE forbids:
//!
//! > a composition root may combine owner-provided facts; it must not recreate an owner's
//! > security semantics by destructuring its representation.
//!
//! The move changes no semantics. `TrustEpochPlan` deliberately stays in `startup_plan`:
//! it is shared with `SigningPlan`, and relocating it here would make trust the authority
//! over a fact signing also consumes — which is the CF-09 defect this tree already closed.

use crate::config_state::validation::ValidatedDeployment;
use crate::startup_plan::TrustEpochPlan;

/// How the `--trust` file is kept current.
///
/// A state, not a missing value: no tier resolves a revocation faster than the store is
/// re-read, so a deployment that reads it once has declared that revoking a request-signer
/// key costs a restart of every replica.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustReloadPlan {
    /// `--trust` is read once. Only `BoundedCache` may be in this state.
    ReadOnceAtStartup,
    /// Re-read on this cadence, so a key removed from the file stops resolving within it.
    Every {
        /// The cadence, in seconds. Non-zero because a zero cadence is a spinning reloader,
        /// which layer A refuses — so `Every { secs: 0 }` has no constructor.
        secs: std::num::NonZeroU64,
    },
}

impl TrustReloadPlan {
    /// The cadence, where there is one.
    pub fn cadence_secs(&self) -> Option<std::num::NonZeroU64> {
        match self {
            TrustReloadPlan::ReadOnceAtStartup => None,
            TrustReloadPlan::Every { secs } => Some(*secs),
        }
    }
}

/// What the trust plane must establish (ADR-MCPRE-056 §8).
///
/// Everything the plane needs and nothing it could re-decide: the classified revocation
/// state, the document it is a posture over, and the epoch mechanism normalized above it.
/// `TrustPlane` used to receive the whole `ValidatedDeployment` and answer "which posture is
/// this?" for itself — a second derivation of a fact layer A had already classified.
///
/// # A composition may combine owned facts; it may not make them replaceable again
///
/// The representation is private to this module. That is the difference between this and
/// the public bag it replaced: a plan used to pair a sealed `TrustRevocationState` with a
/// free `trust_path: String`, so the pairing held only because every construction site
/// happened to take both from the same deployment. Nothing said they had to.
///
/// `reload` is not a field. It is DERIVED from the revocation state on demand, because the
/// state is the authority on how often the document is re-read — a stored copy is a second
/// value that can disagree with the first, and the fixture in `trust_plane`'s tests had
/// already drifted that way, naming a 30s reload beside a state carrying 5s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustPlan {
    /// Which revocation posture this deployment asked for.
    revocation: crate::config_state::TrustRevocationState,
    /// The document the request-signer set is read from.
    document: crate::config_state::TrustDocumentSource,
    /// The root issuer whose key must never be enrolled as a request signer.
    response_kid: String,
    /// The shared epoch mechanism — an INPUT, so this plane cannot become its authority
    /// merely by being materialized first (CF-09).
    epoch: TrustEpochPlan,
}

impl TrustPlan {
    /// Project the plan from the retained classification and the validated locator.
    ///
    /// `response_kid` and `epoch` are passed IN rather than derived here. Both are shared
    /// with the signing plane, and a value derived inside one consumer is a value the other
    /// consumer must re-derive.
    ///
    /// The one producer, and it takes a `ValidatedDeployment` — so both owned facts come
    /// from one deployment, and no caller can supply them separately.
    pub fn from_validated(
        config: &ValidatedDeployment,
        response_kid: String,
        epoch: TrustEpochPlan,
    ) -> TrustPlan {
        TrustPlan {
            revocation: config.state().trust_revocation().clone(),
            document: config.state().trust_document().clone(),
            response_kid,
            epoch,
        }
    }

    /// The revocation posture, for the tier wrapping and the startup audit line.
    pub fn revocation(&self) -> &crate::config_state::TrustRevocationState {
        &self.revocation
    }

    /// The locator the trust document is read from.
    pub fn document_path(&self) -> &str {
        self.document.path()
    }

    /// The root issuer whose key is excluded from the request-signer set.
    pub fn response_kid(&self) -> &str {
        &self.response_kid
    }

    /// How the document is kept current, derived from the posture that decides it.
    pub fn reload(&self) -> TrustReloadPlan {
        trust_reload_plan(&self.revocation)
    }

    /// The shared epoch mechanism.
    pub fn epoch(&self) -> &TrustEpochPlan {
        &self.epoch
    }
}

/// How often `--trust` is re-read, decided from the state rather than from the request.
///
/// Three of the four states CARRY a cadence, because their Required column names one, so
/// none of them can be projected to `ReadOnceAtStartup` — the posture that would silently
/// contradict a tier whose whole claim is that the store is re-read. Only `BoundedCache`
/// consults the validated request, because only there is the cadence optional and both
/// postures legal.
fn trust_reload_plan(state: &crate::config_state::TrustRevocationState) -> TrustReloadPlan {
    // Which states require a cadence is the revocation machine's rule, so the cadence is
    // read from it rather than matched out of its variants here. Total, and reading no raw
    // value: layer A normalized the optional cadence, so there is no `Some(0)` left to
    // filter, and therefore no way for a refused request to be re-read as a legal posture.
    match state.reload_cadence() {
        Some(secs) => TrustReloadPlan::Every { secs },
        None => TrustReloadPlan::ReadOnceAtStartup,
    }
}

// Everything below is test code.
#[cfg(test)]
mod tests {
    use super::*;

    /// A deployment in the PushNetworked posture, through the boundary — the same route
    /// `config_state::test_support::trust_plan` takes, so the plan under test comes from
    /// one accepted deployment rather than from a literal.
    fn push_networked() -> ValidatedDeployment {
        let mut config = crate::config_state::test_support::legal_config();
        config.revocation_tier = crate::revocation_tier::RevocationTier::Push { t_secs: 30 };
        config.trust_reload_secs = Some(15);
        config.trust_epoch.source = Some(crate::deployment_request::TrustEpochSource::redis(
            "redis://127.0.0.1:6379",
            None,
        ));
        ValidatedDeployment::try_from(config).expect("a legal push-networked deployment")
    }

    /// The same, at the default revocation tier and with no cadence stated.
    fn default_tier() -> ValidatedDeployment {
        let config = crate::config_state::test_support::legal_config();
        ValidatedDeployment::try_from(config).expect("the accepted fixture validates")
    }

    /// The refresh posture comes from the STATE's witness, not from the request beside it.
    ///
    /// Three of the four trust states carry their cadence because their Required column
    /// names one. The structural property that buys: no reload-bearing state can be
    /// projected to `ReadOnceAtStartup`, which would silently contradict a tier whose whole
    /// claim is that the store is re-read.
    ///
    /// The projection cannot consult the request at all — `trust_reload_plan` takes only
    /// the state — so this asserts what remains: that each reload-bearing state projects
    /// its OWN carried cadence rather than some default.
    #[test]
    fn a_reload_bearing_state_cannot_be_projected_to_read_once() {
        let carried = [
            crate::config_state::test_support::revocation_posture(
                crate::revocation_tier::RevocationTier::Live,
                Some(7),
                None,
            ),
            crate::config_state::test_support::revocation_posture(
                crate::revocation_tier::RevocationTier::Push { t_secs: 30 },
                Some(7),
                None,
            ),
            crate::config_state::test_support::revocation_posture(
                crate::revocation_tier::RevocationTier::Push { t_secs: 30 },
                Some(7),
                Some(("redis://127.0.0.1:6379", "k")),
            ),
        ];
        for state in carried {
            assert_eq!(
                trust_reload_plan(&state),
                TrustReloadPlan::Every {
                    secs: crate::config_state::TrustRevocationState::cadence(7)
                },
                "{state:?} must project its own cadence, not the request's absence"
            );
        }
    }

    /// The other half of the same rule: `BoundedCache`'s cadence is OPTIONAL, so it is not
    /// a witness and both postures stay reachable through the validated request.
    ///
    /// If this collapsed to one answer it would mean the witness rule had been over-applied
    /// — an optional parameter moved into a state that does not require it.
    #[test]
    fn bounded_cache_keeps_both_refresh_postures() {
        assert_eq!(
            trust_reload_plan(&crate::config_state::test_support::revocation_posture(
                crate::revocation_tier::RevocationTier::BoundedCache { t_secs: 60 },
                None,
                None
            )),
            TrustReloadPlan::ReadOnceAtStartup,
            "an omitted cadence under bounded-cache reads the store once"
        );
        assert_eq!(
            trust_reload_plan(&crate::config_state::test_support::revocation_posture(
                crate::revocation_tier::RevocationTier::BoundedCache { t_secs: 60 },
                Some(60),
                None
            )),
            TrustReloadPlan::Every {
                secs: crate::config_state::TrustRevocationState::cadence(60)
            },
            "a supplied cadence under bounded-cache still re-reads"
        );
    }

    /// The plan carries the classified posture rather than the tier flag, and the reload
    /// cadence as a state rather than an `Option` a consumer has to interpret.
    #[test]
    fn the_trust_plan_carries_the_retained_classification() {
        let config = push_networked();
        let plan = TrustPlan::from_validated(
            &config,
            "root-1".to_string(),
            TrustEpochPlan::from_validated(&config),
        );
        assert_eq!(
            *plan.revocation(),
            crate::config_state::test_support::revocation_posture(
                crate::revocation_tier::RevocationTier::Push { t_secs: 30 },
                Some(15),
                Some((
                    "redis://127.0.0.1:6379",
                    crate::trust_epoch::DEFAULT_TRUST_EPOCH_KEY
                ))
            ),
            "the plan must hold what layer A classified, not re-read --revocation-tier"
        );
        assert_eq!(
            plan.reload(),
            TrustReloadPlan::Every {
                secs: crate::config_state::TrustRevocationState::cadence(15)
            }
        );
        assert_eq!(plan.response_kid(), "root-1");
        assert!(matches!(plan.epoch(), TrustEpochPlan::Redis { .. }));

        let default_tier = default_tier();
        let plan = TrustPlan::from_validated(
            &default_tier,
            "root-1".to_string(),
            TrustEpochPlan::from_validated(&default_tier),
        );
        assert_eq!(
            plan.reload(),
            TrustReloadPlan::ReadOnceAtStartup,
            "no cadence is a posture, not a missing value"
        );
    }

    /// The issuer kid and the epoch are INPUTS to the trust plan.
    ///
    /// This is the structural half of CF-09: with both passed in, the trust plan cannot
    /// become their authority merely by being the first consumer written. The assertion is
    /// that a plan built with a value the configuration does not name carries that value —
    /// which is only possible because nothing inside re-derives it.
    #[test]
    fn the_shared_values_are_inputs_the_trust_plan_cannot_re_derive() {
        let config = push_networked();
        assert_ne!(
            crate::startup_plan::response_issuer_kid(&config),
            "decided-above",
            "the fixture must not coincide with what a re-derivation would produce"
        );
        let plan = TrustPlan::from_validated(
            &config,
            "decided-above".to_string(),
            TrustEpochPlan::Redis {
                url: "redis://198.51.100.1:6379".to_string(),
                key: "decided-above".to_string(),
            },
        );
        assert_eq!(plan.response_kid, "decided-above");
        assert_eq!(
            plan.epoch,
            TrustEpochPlan::Redis {
                url: "redis://198.51.100.1:6379".to_string(),
                key: "decided-above".to_string(),
            }
        );
    }
}
