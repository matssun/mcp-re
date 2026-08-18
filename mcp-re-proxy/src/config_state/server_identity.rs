// SPDX-License-Identifier: Apache-2.0
//! The `ServerIdentity` semantic owner: who this deployment IS, resolved once.
//!
//! **A guard-only owner, like `DelegatedSigning`.** There is no mode to choose — a legal
//! deployment does not select between server-identity states — so there is no enum and no
//! classification. What this owner has is two required coordinates, a role that is not an
//! input at all, and one derived fact.
//!
//! | Field | Kind | Rule |
//! |---|---|---|
//! | `trust_domain` | required | non-empty; a coordinate of every actor this deployment names |
//! | `server_signer` | required | non-empty; the server's `subject` |
//! | role | constant | `"server"`, owned here rather than typed at each use |
//! | keyid | derived | [`DelegatedSigningFacts::issuer_kid`], already resolved by its owner |
//!
//! **Why it exists: the same fact was being assembled twice.** The server's
//! [`ActorIdentity`] was built in `app::run_validated` as the struct and again in
//! `SigningPlan::from_validated` flattened into `CustodyConfig`'s `server_role` /
//! `server_trust_domain` / `server_subject` / `iss` fields — one semantic object, two
//! derivations from the same primitives, free to disagree (CF-10). The `"server"` role was
//! a literal typed independently at both. Nothing forced them to agree; a consumer could
//! have written `"server-a"` while the other wrote `"server"` from the same validated
//! deployment, and the two would have produced different `actor_id` strings — which is a
//! replay-key component.
//!
//! **What it does NOT take.** Only the coordinates the identity is made of. `--audience`
//! is consumed independently as an audience parameter (`AudienceTuple`, `CustodyConfig::aud`)
//! and stays in the request; `--server-key-id` is a default SOURCE for
//! `DelegatedSigningFacts::issuer_kid` and is consumed nowhere else. Taking all four
//! because they were validated in one place is how a validation location gets mistaken for
//! an owner.

use mcp_re_http_profile::ActorIdentity;

use crate::config_state::delegated_signing::DelegatedSigningFacts;
use crate::deployment_request::DeploymentRequest;

/// The trust role every actor identity this deployment mints for ITSELF carries.
///
/// A constant rather than an input: no deployment chooses its own role, and the two sites
/// that used to build the identity each spelled it as a literal.
const SERVER_ROLE: &str = "server";

/// What layer A established about this deployment's own identity.
///
/// Holding one is evidence that both coordinates are present and that the canonical
/// [`ActorIdentity`] was derived once, from the resolved issuer kid rather than from
/// whichever primitive a consumer happened to reach for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerIdentityFacts {
    actor: ActorIdentity,
}

impl ServerIdentityFacts {
    /// The server's canonical actor identity.
    ///
    /// Every consumer takes this rather than assembling one. Its `actor_id()` is a replay-key
    /// component, so two consumers disagreeing about any field would be two different actors
    /// as far as the replay store is concerned.
    pub fn actor(&self) -> &ActorIdentity {
        &self.actor
    }
}

/// Check this owner's guards and derive its fact.
///
/// `None` means the identity is not inhabitable: a coordinate is missing, or the delegated
/// owner resolved no facts and therefore no issuer kid for the identity to carry. The
/// refusal beside it says which. `delegated` is taken rather than re-derived because the
/// keyid IS [`DelegatedSigningFacts::issuer_kid`] — recomputing it from
/// `--delegated-issuer-kid`/`--server-key-id` here would be the second derivation this
/// owner exists to remove.
pub fn classify_and_validate(
    config: &DeploymentRequest,
    delegated: Option<&DelegatedSigningFacts>,
) -> (Option<ServerIdentityFacts>, Vec<String>) {
    let violations = coordinate_violations(config);
    if !violations.is_empty() {
        return (None, violations);
    }
    // No refusal of its own: `DelegatedSigning` has already refused whatever left it with
    // no facts, and repeating that here would answer one defect twice.
    let Some(delegated) = delegated else {
        return (None, violations);
    };
    (
        Some(ServerIdentityFacts {
            actor: ActorIdentity {
                role: SERVER_ROLE.to_string(),
                trust_domain: config.trust_domain.clone(),
                subject: config.server_signer.clone(),
                keyid: delegated.issuer_kid().to_string(),
            },
        }),
        violations,
    )
}

/// The two coordinates the identity cannot be built without.
///
/// Stated one field at a time, in the order an operator meets them. Neither is dereferenced
/// at startup, so an empty one fails nothing — it silently stops distinguishing this
/// deployment from another that also set none.
fn coordinate_violations(config: &DeploymentRequest) -> Vec<String> {
    [
        (
            config.trust_domain.as_str(),
            "--trust-domain is empty: it is a component of every actor identity \
             (role:trust_domain:subject:keyid), so an empty domain removes a coordinate \
             from every actor this deployment names",
        ),
        (
            config.server_signer.as_str(),
            "--server-signer is empty: it is minted as the issuer of every response, and an \
             empty issuer names nobody for a verifier to resolve",
        ),
    ]
    .into_iter()
    .filter(|(value, _)| value.trim().is_empty())
    .map(|(_, message)| message.to_string())
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_state::test_support::legal_config;

    fn facts(config: &DeploymentRequest) -> (Option<ServerIdentityFacts>, Vec<String>) {
        let (delegated, _) = crate::config_state::delegated_signing::classify_and_validate(config);
        classify_and_validate(config, delegated.as_ref())
    }

    #[test]
    fn a_legal_request_yields_one_canonical_identity() {
        let config = legal_config();
        let (identity, violations) = facts(&config);
        assert!(violations.is_empty(), "{violations:?}");
        let actor = identity.expect("a legal request has an identity").actor;
        assert_eq!(actor.role, "server");
        assert_eq!(actor.trust_domain, config.trust_domain);
        assert_eq!(actor.subject, config.server_signer);
        // The keyid is the RESOLVED issuer kid, not `--server-key-id` read again.
        let (delegated, _) = crate::config_state::delegated_signing::classify_and_validate(&config);
        assert_eq!(
            actor.keyid,
            delegated.expect("legal").issuer_kid(),
            "the identity must carry the kid its owner resolved, not one re-derived here"
        );
    }

    /// The keyid follows the OVERRIDE, which is what proves it is not re-derived.
    ///
    /// With `--delegated-issuer-kid` set, `--server-key-id` is consumed by nothing. An
    /// identity that read `server_key_id` directly would still pass the test above and fail
    /// this one.
    #[test]
    fn the_identity_keyid_follows_the_resolved_issuer_not_the_server_key_id() {
        let mut config = legal_config();
        config.delegated_issuer_kid = Some("root-issuer-9".to_string());
        let actor = facts(&config).0.expect("legal").actor;
        assert_eq!(actor.keyid, "root-issuer-9");
        assert_ne!(actor.keyid, config.server_key_id);
    }

    #[test]
    fn a_missing_coordinate_leaves_no_identity_and_names_itself() {
        for (flag, mutate) in [
            (
                "--trust-domain",
                Box::new(|c: &mut DeploymentRequest| c.trust_domain = String::new())
                    as Box<dyn FnOnce(&mut DeploymentRequest)>,
            ),
            (
                "--server-signer",
                Box::new(|c: &mut DeploymentRequest| c.server_signer = String::new()),
            ),
        ] {
            let mut config = legal_config();
            mutate(&mut config);
            let (identity, violations) = facts(&config);
            assert!(identity.is_none(), "{flag}: an identity was built anyway");
            assert!(
                violations.iter().any(|v| v.contains(flag)),
                "{flag}: not named in {violations:?}"
            );
        }
    }

    /// Whitespace is emptiness here: a coordinate of spaces distinguishes nothing, and the
    /// refusal names the flag rather than leaving the absence unexplained.
    #[test]
    fn a_whitespace_coordinate_is_empty_and_names_itself() {
        for (flag, mutate) in [
            (
                "--trust-domain",
                Box::new(|c: &mut DeploymentRequest| c.trust_domain = "   ".to_string())
                    as Box<dyn FnOnce(&mut DeploymentRequest)>,
            ),
            (
                "--server-signer",
                Box::new(|c: &mut DeploymentRequest| c.server_signer = "\t \n".to_string()),
            ),
        ] {
            let mut config = legal_config();
            mutate(&mut config);
            let (identity, violations) = facts(&config);
            assert!(identity.is_none(), "{flag}: an identity was built anyway");
            assert!(
                violations.iter().any(|v| v.contains(flag)),
                "{flag}: not named in {violations:?}"
            );
        }
    }

    /// One pass, not one offender: the coordinates are reported independently.
    ///
    /// A request missing both gets both messages. An implementation that stopped at the
    /// first empty coordinate would hide the second until the operator fixed the first.
    #[test]
    fn a_request_missing_both_coordinates_reports_both_in_one_pass() {
        let mut config = legal_config();
        config.trust_domain = String::new();
        config.server_signer = "   ".to_string();
        let (identity, violations) = facts(&config);
        assert!(identity.is_none());
        assert_eq!(violations.len(), 2, "{violations:?}");
        assert!(violations[0].contains("--trust-domain"), "{violations:?}");
        assert!(violations[1].contains("--server-signer"), "{violations:?}");
    }
}
