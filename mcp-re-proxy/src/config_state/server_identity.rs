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
//! | `trust_domain` | required | non-empty, not the shipped placeholder; a coordinate of every actor this deployment names |
//! | `server_signer` | required | non-empty, not the shipped placeholder; the server's `subject` |
//! | role | constant | `"server"`, owned here rather than typed at each use |
//! | keyid | derived | [`DelegatedSigningFacts::issuer_kid`], already resolved by its owner |
//!
//! **Why it exists.** The server's [`ActorIdentity`] and the custody's issuer fields
//! (`CustodyConfig`'s `server_role` / `server_trust_domain` / `server_subject` / `iss`) are
//! one semantic object, and `actor_id()` is a replay-key component: two derivations from the
//! same primitives could disagree (CF-10). Both take it from here, and both roles a
//! deployment mints — `"server"` for itself, `"client"` for a request signer — are spelled
//! here once.
//!
//! **What it does NOT take.** Only the coordinates the identity is made of. `--audience`
//! is consumed independently as an audience parameter (`AudienceTuple`, `CustodyConfig::aud`)
//! and stays in the request; `--server-key-id` is a default SOURCE for
//! `DelegatedSigningFacts::issuer_kid` and is consumed nowhere else. Its placeholder
//! refusal below covers `--audience` as part of the one fixture policy, not as a coordinate.

use mcp_re_http_profile::ActorIdentity;

use crate::config_state::coordinate;
use crate::config_state::coordinate::CoordinateFault;
use crate::config_state::delegated_signing::DelegatedSigningFacts;
use crate::deployment_request::DeploymentRequest;

/// The trust role every actor identity this deployment mints for ITSELF carries: a constant
/// rather than an input, because no deployment chooses its own role.
const SERVER_ROLE: &str = "server";

/// The trust role of every request signer a deployment resolves. Crate-wide because the
/// transparency auditor resolves request signers under its own profile's trust domain, with
/// no server identity to build them from; it takes the role, never a second spelling of it.
pub(crate) const CLIENT_ROLE: &str = "client";

/// What layer A established about this deployment's own identity.
///
/// Holding one is evidence that both coordinates are present, that no shipped placeholder
/// was kept unless a fixture run was acknowledged, and that the canonical
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

    /// The trust domain, as the coordinate of EVERY actor this deployment names.
    pub fn trust_domain(&self) -> &str {
        &self.actor.trust_domain
    }

    /// The actor a resolved request signer is: the client role, this deployment's trust
    /// domain, and the subject and keyid its trust document resolved. The one place a client
    /// actor is built, so the request and response slots cannot disagree about the coordinate
    /// and partition the replay namespace between them.
    pub fn client_actor(&self, subject: String, keyid: &str) -> ActorIdentity {
        ActorIdentity {
            role: CLIENT_ROLE.to_string(),
            trust_domain: self.actor.trust_domain.clone(),
            subject,
            keyid: keyid.to_string(),
        }
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
pub(in crate::config_state) fn classify_and_validate(
    config: &DeploymentRequest,
    delegated: Option<&DelegatedSigningFacts>,
) -> (Option<ServerIdentityFacts>, Vec<String>) {
    let mut violations = coordinate_violations(config);
    violations.extend(placeholder_violations(config));
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

/// The trust domain the Helm chart ships as a placeholder, refused here as the chart refuses it.
const PLACEHOLDER_TRUST_DOMAIN: &str = "example.com";

/// The prefix of the chart's `--audience` and `--server-signer` placeholders, refused here as
/// the chart refuses it.
const PLACEHOLDER_DID_PREFIX: &str = "did:example:";

/// The shipped placeholders, unless the operator acknowledged a fixture run.
///
/// Every install that kept the placeholder trust domain shares one identity namespace: their
/// actors differ only by subject and keyid, so a credential minted for one names an actor the
/// others would also resolve. Two installs sharing the placeholder audience accept each
/// other's requests under a shared trust anchor, and a shared placeholder signer is one
/// issuer for both. `--allow-example-fixtures` is the fenced validation run whose trust
/// document `emit_mtls_fixtures` writes under exactly these values.
fn placeholder_violations(config: &DeploymentRequest) -> Vec<String> {
    if config.allow_example_fixtures {
        return Vec::new();
    }
    let domain = (config.trust_domain == PLACEHOLDER_TRUST_DOMAIN).then(|| {
        format!(
            "--trust-domain {PLACEHOLDER_TRUST_DOMAIN} is the shipped placeholder: every install \
             that kept it shares one identity namespace. Set this deployment's own trust \
             domain, or pass --allow-example-fixtures for a fenced fixture run"
        )
    });
    let dids = [
        ("--audience", &config.audience),
        ("--server-signer", &config.server_signer),
    ]
    .into_iter()
    .filter(|(_, value)| value.starts_with(PLACEHOLDER_DID_PREFIX))
    .map(|(flag, value)| {
        format!(
            "{flag} {value} is a {PLACEHOLDER_DID_PREFIX} placeholder: installs sharing it accept \
             each other's requests under a shared trust anchor. Set this deployment's own \
             identifier, or pass --allow-example-fixtures for a fenced fixture run"
        )
    });
    domain.into_iter().chain(dids).collect()
}

/// The two coordinates the identity cannot be built without, each in canonical form.
///
/// Stated one field at a time, in the order an operator meets them. Both are read at
/// startup only as strings minted into identities — neither is resolved as a locator — so
/// an empty one fails nothing loudly: it silently stops distinguishing this deployment from
/// another that also set none. A padded one is minted verbatim into every actor and `iss`,
/// naming a different coordinate from the one written without it.
fn coordinate_violations(config: &DeploymentRequest) -> Vec<String> {
    [
        (
            "--trust-domain",
            config.trust_domain.as_str(),
            "--trust-domain is empty: it is a component of every actor identity \
             (role:trust_domain:subject:keyid), so an empty domain removes a coordinate \
             from every actor this deployment names",
        ),
        (
            "--server-signer",
            config.server_signer.as_str(),
            "--server-signer is empty: it is minted as the issuer of every response, and an \
             empty issuer names nobody for a verifier to resolve",
        ),
    ]
    .into_iter()
    .filter_map(
        |(name, value, empty_message)| match coordinate::fault(value)? {
            CoordinateFault::Blank => Some(empty_message.to_string()),
            CoordinateFault::Padded => Some(format!(
                "{name} {value:?} has leading or trailing whitespace: it is minted verbatim into \
             every actor identity this deployment names, so it names a different coordinate \
             from the one written without it"
            )),
        },
    )
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

    /// LOAD-BEARING (r12 R12-629): the trust domain a consumer takes IS the one inside the
    /// canonical actor, so the client and server actors this deployment mints cannot
    /// disagree about the coordinate. `actor_id()` is a replay-key component, so a
    /// divergence would partition the replay namespace between the two slots.
    ///
    /// Asserted as an IDENTITY between the projection and the actor's own field rather
    /// than against a literal: a literal would pass for a projection that returned a
    /// constant that happened to match the fixture.
    #[test]
    fn the_trust_domain_projection_is_the_canonical_actors_own_coordinate() {
        let config = legal_config();
        let (identity, _) = facts(&config);
        let identity = identity.expect("a legal request is inhabitable");
        assert_eq!(identity.trust_domain(), identity.actor().trust_domain);
        assert!(
            !identity.trust_domain().is_empty(),
            "the guard refuses an empty domain before any deployment is validated"
        );
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
        config.delegated_signing.issuer_kid = Some("root-issuer-9".to_string());
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

    /// A padded coordinate is refused by name rather than minted: ` corp.example` or
    /// `did:x\n` would become an actor coordinate and an `iss` that differ byte for byte from
    /// the ones the operator meant.
    #[test]
    fn a_padded_coordinate_leaves_no_identity_and_names_itself() {
        for (flag, mutate) in [
            (
                "--trust-domain",
                Box::new(|c: &mut DeploymentRequest| c.trust_domain = " corp.example".to_string())
                    as Box<dyn FnOnce(&mut DeploymentRequest)>,
            ),
            (
                "--server-signer",
                Box::new(|c: &mut DeploymentRequest| c.server_signer = "did:x\n".to_string()),
            ),
        ] {
            let mut config = legal_config();
            mutate(&mut config);
            let (identity, violations) = facts(&config);
            assert!(identity.is_none(), "{flag}: an identity was built anyway");
            assert_eq!(violations.len(), 1, "{flag}: {violations:?}");
            assert!(
                violations[0].starts_with(flag) && violations[0].contains("whitespace"),
                "{flag}: {violations:?}"
            );
        }
    }

    /// The delegated-absent branch: legal coordinates, and a delegated owner that resolved
    /// no facts. No identity and no refusal of this owner's own — the delegated owner's is
    /// the one an operator reads — and the legality boundary reports that refusal rather than
    /// falling through to its internal "recognised no state" error.
    #[test]
    fn an_absent_delegated_fact_leaves_no_identity_and_refuses_through_its_owner() {
        let mut config = legal_config();
        config.delegated_signing.trust_epoch = None;
        let (delegated, delegated_refusals) =
            crate::config_state::delegated_signing::classify_and_validate(&config);
        assert!(delegated.is_none() && !delegated_refusals.is_empty());
        let (identity, violations) = classify_and_validate(&config, None);
        assert!(identity.is_none());
        assert!(violations.is_empty(), "{violations:?}");

        let Err(refusal) = crate::config_state::validation::ValidatedDeployment::try_from(config)
        else {
            panic!("a deployment with no delegated facts was validated");
        };
        assert!(refusal.contains("--delegated-trust-epoch"), "{refusal}");
        assert!(!refusal.contains("internal error"), "{refusal}");
    }

    /// The shipped placeholder domain is refused by name and builds no identity.
    #[test]
    fn the_placeholder_trust_domain_is_refused_without_the_fixture_acknowledgement() {
        let mut config = legal_config();
        config.trust_domain = PLACEHOLDER_TRUST_DOMAIN.to_string();
        let (identity, violations) = facts(&config);
        assert!(
            identity.is_none(),
            "an identity was built under the placeholder"
        );
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(
            violations[0].contains("--allow-example-fixtures"),
            "{violations:?}"
        );
    }

    /// The acknowledgement admits exactly the placeholder; a domain merely containing it is
    /// this deployment's own and needs none.
    #[test]
    fn the_fixture_acknowledgement_admits_the_placeholder_and_nothing_else_needs_it() {
        let mut config = legal_config();
        config.trust_domain = PLACEHOLDER_TRUST_DOMAIN.to_string();
        config.allow_example_fixtures = true;
        let (identity, violations) = facts(&config);
        assert!(violations.is_empty(), "{violations:?}");
        assert_eq!(
            identity.expect("acknowledged").trust_domain(),
            PLACEHOLDER_TRUST_DOMAIN
        );

        let config = legal_config();
        assert!(!config.allow_example_fixtures);
        assert_ne!(config.trust_domain, PLACEHOLDER_TRUST_DOMAIN);
        assert!(facts(&config).0.is_some());
    }

    /// 419b9a50: a client actor is built by the owner, with the one client role and the
    /// deployment's own trust domain, never from a literal typed at the call site.
    #[test]
    fn a_client_actor_carries_the_client_role_and_the_owners_trust_domain() {
        let (identity, _) = facts(&legal_config());
        let identity = identity.expect("a legal request is inhabitable");
        let client = identity.client_actor("did:web:agent-1".to_string(), "key-1");
        assert_eq!(client.role, CLIENT_ROLE);
        assert_ne!(client.role, identity.actor().role);
        assert_eq!(client.trust_domain, identity.actor().trust_domain);
        assert_eq!(
            (client.subject.as_str(), client.keyid.as_str()),
            ("did:web:agent-1", "key-1")
        );
    }

    /// fd50bfd0: the chart's `did:example:` audience and signer placeholders are refused as
    /// the chart refuses them, each named, and the one acknowledgement admits both.
    #[test]
    fn the_placeholder_audience_and_signer_are_refused_without_the_fixture_acknowledgement() {
        let mut config = legal_config();
        config.audience = "did:example:server-1".to_string();
        config.server_signer = "did:example:server-1".to_string();
        let (identity, violations) = facts(&config);
        assert!(
            identity.is_none(),
            "an identity was built under the placeholder"
        );
        assert_eq!(violations.len(), 2, "{violations:?}");
        assert!(
            violations[0].starts_with("--audience did:example:"),
            "{violations:?}"
        );
        assert!(
            violations[1].starts_with("--server-signer did:example:"),
            "{violations:?}"
        );

        config.allow_example_fixtures = true;
        let (identity, violations) = facts(&config);
        assert!(violations.is_empty(), "{violations:?}");
        assert!(
            identity.is_some(),
            "the acknowledgement admits the fixture identity"
        );
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
