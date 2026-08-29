// SPDX-License-Identifier: Apache-2.0
//! The authorization flag family, parsed as one — ADR-MCPRE-065.
//!
//! `parse_args` matches one delegating arm for the whole family instead of four literal
//! arms, so the family's spelling and its meaning live together. Nothing here decides
//! whether a combination is legal: an unusable pairing reaches the
//! [`AuthorizationState`](crate::config_state::AuthorizationState) machine, which is the
//! boundary a programmatically built request also passes through.

use mcp_re_http_profile::pdp_decision::DecisionScope;

use crate::deployment_request::AuthorizationRequest;
use crate::deployment_request::AuthzKind;

/// The authorization inputs, as they accumulate across the argument list.
pub(super) struct AuthorizationFlags {
    request: AuthorizationRequest,
}

impl Default for AuthorizationFlags {
    /// Nothing selected, no parameters supplied.
    fn default() -> Self {
        AuthorizationFlags {
            request: AuthorizationRequest::off(),
        }
    }
}

impl AuthorizationFlags {
    /// Whether this flag belongs to the family.
    pub(super) fn owns(flag: &str) -> bool {
        matches!(
            flag,
            "--authz"
                | "--authz-decision-scope"
                | "--authz-max-decision-age-secs"
                | "--revocation-list"
        )
    }

    /// Read one flag of the family. `owns` decided it is one.
    pub(super) fn take(&mut self, flag: &str, value: &str) -> Result<(), String> {
        match flag {
            "--authz" => self.request.kind = selection(value)?,
            "--authz-decision-scope" => self.request.decision_scope = Some(scope(value)?),
            "--authz-max-decision-age-secs" => {
                self.request.max_decision_age_secs = Some(staleness_bound(value)?)
            }
            // ADR-MCPS-013: repeatable and/or comma-separated revocation deny-list file
            // paths. Splitting is the CLI's encoding; whether a resulting path names a
            // file, and whether anything would read it, are decided downstream.
            _ => self
                .request
                .revocation_list_paths
                .extend(value.split(',').map(str::to_string)),
        }
        Ok(())
    }

    /// The family, as the request carries it.
    pub(super) fn finish(self) -> AuthorizationRequest {
        self.request
    }
}

/// Which authorization authority the operator selected.
fn selection(value: &str) -> Result<AuthzKind, String> {
    match value {
        "off" => Ok(AuthzKind::Off),
        "reference" => Ok(AuthzKind::Reference),
        "pdp-decision" => Ok(AuthzKind::PdpDecision),
        other => Err(format!(
            "unknown --authz '{other}' (off|reference|pdp-decision)"
        )),
    }
}

/// The actor scope decisions are accepted at.
fn scope(value: &str) -> Result<DecisionScope, String> {
    match value {
        "principal" => Ok(DecisionScope::Principal),
        "credential" => Ok(DecisionScope::Credential),
        other => Err(format!(
            "unknown --authz-decision-scope '{other}' (principal|credential)"
        )),
    }
}

/// How stale a decision this enforcement point will still act on.
fn staleness_bound(value: &str) -> Result<i64, String> {
    value.parse().map_err(|_| {
        "invalid --authz-max-decision-age-secs (expected a whole number of seconds)".to_string()
    })
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::AuthorizationFlags;
    use crate::deployment_request::AuthzKind;
    use mcp_re_http_profile::pdp_decision::DecisionScope;

    fn taken(
        pairs: &[(&str, &str)],
    ) -> Result<crate::deployment_request::AuthorizationRequest, String> {
        let mut flags = AuthorizationFlags::default();
        for (flag, value) in pairs {
            flags.take(flag, value)?;
        }
        Ok(flags.finish())
    }

    #[test]
    fn the_family_is_exactly_the_four_flags_that_reach_the_authorization_axis() {
        for flag in [
            "--authz",
            "--authz-decision-scope",
            "--authz-max-decision-age-secs",
            "--revocation-list",
        ] {
            assert!(AuthorizationFlags::owns(flag), "{flag}");
        }
        assert!(!AuthorizationFlags::owns("--admission"));
        assert!(!AuthorizationFlags::owns("--authorize"));
    }

    #[test]
    fn the_production_mechanism_is_selectable_with_its_two_parameters() {
        let request = taken(&[
            ("--authz", "pdp-decision"),
            ("--authz-decision-scope", "credential"),
            ("--authz-max-decision-age-secs", "600"),
        ])
        .expect("a complete selection parses");
        assert_eq!(request.kind, AuthzKind::PdpDecision);
        assert_eq!(request.decision_scope, Some(DecisionScope::Credential));
        assert_eq!(request.max_decision_age_secs, Some(600));
    }

    #[test]
    fn a_parameter_supplied_beside_no_selection_still_parses_and_is_refused_later() {
        // The parser records what was asked for. Refusing the dangling pairing here would
        // put a policy decision in the parser, where a programmatic caller never meets it.
        let request = taken(&[("--authz-decision-scope", "principal")]).expect("parses");
        assert_eq!(request.kind, AuthzKind::Off);
        assert_eq!(request.decision_scope, Some(DecisionScope::Principal));
    }

    #[test]
    fn an_unknown_selection_names_the_three_that_exist() {
        let err = taken(&[("--authz", "biscuit")]).expect_err("refused");
        assert!(err.contains("off|reference|pdp-decision"), "{err}");
    }

    #[test]
    fn an_unknown_scope_names_the_two_the_signed_claims_can_carry() {
        let err = taken(&[("--authz-decision-scope", "role")]).expect_err("refused");
        assert!(err.contains("principal|credential"), "{err}");
    }

    #[test]
    fn a_deny_list_accumulates_across_repetition_and_commas() {
        let request =
            taken(&[("--revocation-list", "/a,/b"), ("--revocation-list", "/c")]).expect("parses");
        assert_eq!(request.revocation_list_paths, vec!["/a", "/b", "/c"]);
    }

    #[test]
    fn a_staleness_bound_that_is_not_a_number_is_refused_by_name() {
        let err = taken(&[("--authz-max-decision-age-secs", "soon")]).expect_err("refused");
        assert!(err.contains("--authz-max-decision-age-secs"), "{err}");
    }
}
