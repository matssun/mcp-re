// SPDX-License-Identifier: Apache-2.0
//! The `Authorization` configuration machine — ADR-MCPRE-065 §7.1/§8.
//!
//! Two states, and the parameters exist only in the one that has them:
//!
//! | State | Required | Forbidden |
//! |---|---|---|
//! | `Off` | — | decision scope, max decision age |
//! | `PdpDecision` | scope, positive max decision age | — |
//!
//! **There is no permissive third state, and its absence is the ADR's decision rather than
//! an unimplemented feature.** ADR-MCPRE-065 §7.1 gives authorization three postures —
//! not configured, authorized, refused — and a deployment that has configured an authority
//! has left the first. A `PdpDecision` deployment that let an undecorated request through
//! would be a fourth posture, *policy configured but not enforced for this request*, which
//! is exactly the `Off`/`Allow` ambiguity the three-posture rule exists to remove. The
//! analogy with [`AdmissionState`](super::AdmissionState)'s `Optional` does not carry: that
//! optionality was constituted as part of admission's own semantics, and authorization was
//! constituted with a different algebra.
//!
//! A migration or shadow posture, if one is ever needed, is a separately named
//! non-enforcing deployment posture with its own audit semantics. It must never arrive by
//! reading missing decision evidence as permission.
//!
//! `Off` forbids both parameters for the reason every dangling parameter is refused
//! (ADR-MCPRE-056 §5.4): `--authz-decision-scope` beside `--authz off` reads to an auditor
//! as *authorization is configured* while nothing is enforced.

use std::num::NonZeroU64;

use mcp_re_http_profile::pdp_decision::DecisionScope;

use crate::deployment_request::{AuthzKind, DeploymentRequest};

/// Which authorization state a configuration requests.
///
/// The representation is private to this module, so possessing an enforcing state IS the
/// statement that its parameters were supplied and checked. Consumers read an enforcing
/// deployment through [`enforced`](Self::enforced), which hands back the scope and the
/// staleness bound **as one value**: while the variants were public, a consumer could take
/// the scope from one arm and the bound from another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationState {
    kind: AuthorizationKindState,
}

/// The two states, as the owner's own representation.
#[derive(Debug, Clone, PartialEq, Eq)]
enum AuthorizationKindState {
    /// No authorization authority is installed. The serving path still runs its
    /// authorization stage and reports `NoPolicyConfigured`, which is not an allow.
    Off,
    /// The carried PDP decision is enforced.
    PdpDecision {
        accepted_scope: DecisionScope,
        max_decision_age_secs: NonZeroU64,
    },
}

/// An enforcing deployment's decision profile, as one indivisible value.
///
/// Borrowed from the state, so it is a way to READ the profile and not a way to assemble
/// one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnforcedAuthorization {
    accepted_scope: DecisionScope,
    max_decision_age_secs: NonZeroU64,
}

impl EnforcedAuthorization {
    /// The actor scope this deployment accepts a decision at.
    pub fn accepted_scope(&self) -> DecisionScope {
        self.accepted_scope
    }

    /// How stale a decision this deployment will still act on, in seconds.
    pub fn max_decision_age_secs(&self) -> NonZeroU64 {
        self.max_decision_age_secs
    }
}

impl AuthorizationState {
    /// The enforcing profile, or `None` for a deployment that installs no authority.
    pub fn enforced(&self) -> Option<EnforcedAuthorization> {
        let AuthorizationKindState::PdpDecision {
            accepted_scope,
            max_decision_age_secs,
        } = &self.kind
        else {
            return None;
        };
        Some(EnforcedAuthorization {
            accepted_scope: *accepted_scope,
            max_decision_age_secs: *max_decision_age_secs,
        })
    }
}

/// Classify the requested authorization state and check its columns.
///
/// No state is recognised when it refuses: an enforcing state cannot be built without the
/// parameters that make it inhabitable, and an `Off` state carrying them is the dangling
/// shape rather than a state at all.
pub fn classify_and_validate(
    config: &DeploymentRequest,
) -> (Option<AuthorizationState>, Vec<String>) {
    let request = &config.authorization;
    let AuthzKind::PdpDecision = request.kind else {
        let mut violations = Vec::new();
        if request.decision_scope.is_some() {
            violations.push(DANGLING_SCOPE.to_string());
        }
        if request.max_decision_age_secs.is_some() {
            violations.push(DANGLING_AGE.to_string());
        }
        if !violations.is_empty() {
            return (None, violations);
        }
        return (
            Some(AuthorizationState {
                kind: AuthorizationKindState::Off,
            }),
            Vec::new(),
        );
    };
    let (Some(accepted_scope), Some(age)) = (request.decision_scope, request.max_decision_age_secs)
    else {
        return (
            None,
            vec![
                "--authz pdp-decision requires --authz-decision-scope (principal|credential) \
                 and --authz-max-decision-age-secs: the accepted actor scope and the \
                 staleness bound are what the deployment decides, and a decision cannot \
                 supply either about itself (ADR-MCPRE-065 §8.3)"
                    .to_string(),
            ],
        );
    };
    let Some(max_decision_age_secs) = u64::try_from(age).ok().and_then(NonZeroU64::new) else {
        return (
            None,
            vec![
                "--authz-max-decision-age-secs must be a positive number of seconds: zero \
                 accepts no decision at all, and a negative bound names no window"
                    .to_string(),
            ],
        );
    };
    (
        Some(AuthorizationState {
            kind: AuthorizationKindState::PdpDecision {
                accepted_scope,
                max_decision_age_secs,
            },
        }),
        Vec::new(),
    )
}

/// The dangling-scope refusal.
const DANGLING_SCOPE: &str =
    "--authz-decision-scope names the actor scope a PDP decision is accepted at, but no \
     authorization authority is installed (--authz is not pdp-decision), so it selects \
     nothing. An auditor reading it would believe authorization is configured. Remove it, \
     or select --authz pdp-decision.";

/// The dangling-staleness refusal.
const DANGLING_AGE: &str =
    "--authz-max-decision-age-secs bounds how stale a PDP decision may be, but no \
     authorization authority is installed (--authz is not pdp-decision), so it bounds \
     nothing. Remove it, or select --authz pdp-decision.";

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::classify_and_validate;
    use crate::config_state::test_support::legal_config;
    use crate::deployment_request::{AuthzKind, DeploymentRequest};
    use mcp_re_http_profile::pdp_decision::DecisionScope;

    fn pdp(mutate: impl FnOnce(&mut DeploymentRequest)) -> DeploymentRequest {
        let mut config = legal_config();
        config.authorization.kind = AuthzKind::PdpDecision;
        config.authorization.decision_scope = Some(DecisionScope::Principal);
        config.authorization.max_decision_age_secs = Some(600);
        mutate(&mut config);
        config
    }

    #[test]
    fn a_configured_profile_carries_its_scope_and_its_staleness_bound_together() {
        let (state, violations) = classify_and_validate(&pdp(|_| {}));
        assert!(violations.is_empty(), "{violations:?}");
        let enforced = state
            .expect("a complete profile is a recognised state")
            .enforced()
            .expect("configured means enforcing");
        assert_eq!(enforced.accepted_scope(), DecisionScope::Principal);
        assert_eq!(enforced.max_decision_age_secs().get(), 600);
    }

    #[test]
    fn a_deployment_that_installs_nothing_is_off_rather_than_unrecognised() {
        let (state, violations) = classify_and_validate(&legal_config());
        assert!(violations.is_empty(), "{violations:?}");
        assert!(state.expect("off is a state").enforced().is_none());
    }

    #[test]
    fn a_scope_with_no_authority_installed_is_refused_rather_than_ignored() {
        let mut config = legal_config();
        config.authorization.decision_scope = Some(DecisionScope::Credential);
        let (state, violations) = classify_and_validate(&config);
        assert!(state.is_none(), "a dangling parameter recognises no state");
        assert!(
            violations
                .iter()
                .any(|v| v.contains("--authz-decision-scope")),
            "{violations:?}"
        );
    }

    #[test]
    fn a_staleness_bound_with_no_authority_installed_is_refused() {
        let mut config = legal_config();
        config.authorization.max_decision_age_secs = Some(600);
        let (state, violations) = classify_and_validate(&config);
        assert!(state.is_none());
        assert!(
            violations
                .iter()
                .any(|v| v.contains("--authz-max-decision-age-secs")),
            "{violations:?}"
        );
    }

    #[test]
    fn a_profile_missing_its_scope_is_refused_rather_than_defaulted() {
        let (state, violations) =
            classify_and_validate(&pdp(|c| c.authorization.decision_scope = None));
        assert!(state.is_none());
        assert!(
            violations
                .iter()
                .any(|v| v.contains("--authz-decision-scope")),
            "{violations:?}"
        );
    }

    #[test]
    fn a_zero_staleness_bound_is_refused_because_it_accepts_no_decision() {
        let (state, violations) =
            classify_and_validate(&pdp(|c| c.authorization.max_decision_age_secs = Some(0)));
        assert!(state.is_none());
        assert!(
            violations.iter().any(|v| v.contains("positive")),
            "{violations:?}"
        );
    }

    #[test]
    fn the_reference_profile_is_not_an_authority_this_machine_installs() {
        // Layer A refuses `--authz reference` outright; what this asserts is that the state
        // machine does not quietly treat it as an installed authority on the way there.
        let mut config = legal_config();
        config.authorization.kind = AuthzKind::Reference;
        let (state, violations) = classify_and_validate(&config);
        assert!(violations.is_empty(), "{violations:?}");
        assert!(state.expect("a state").enforced().is_none());
    }
}
