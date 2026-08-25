// SPDX-License-Identifier: Apache-2.0
//! The vocabulary of an authorization decision — what an authority states.
//!
//! Separated from the verification that reads it and the issuance that writes it, because
//! each is a different obligation. The argument for WHY these are the claims — and in
//! particular why the actor scope is a signed, closed choice rather than an optional
//! `keyid` — is in [`super`].

use serde::Deserialize;
use serde::Serialize;

use crate::delegation::Audience;

/// Hard size bound on the inline authorization decision in the request evidence block, for
/// the same reason and at the same size as the admission assertion's: both are compact JWSs
/// over a small fixed claim set, and both are read from an unauthenticated peer before
/// anything about it has been established.
pub const MAX_AUTHORIZATION_DECISION_LEN: usize = 8192;

/// The JWS `typ` of an authorization decision — distinct from the delegation credential's
/// and the admission assertion's, so none can be presented for another.
pub const PDP_DECISION_TYP: &str = "mcp-re-authorization-decision+jws";

/// The JWS `alg` — EdDSA, as everywhere in this profile.
pub const PDP_DECISION_ALG: &str = "EdDSA";

/// What the authority decided.
///
/// Two values, and the negative one is carried rather than omitted: an authority that
/// evaluated a request and refused it has produced evidence worth binding and auditing, and
/// a profile in which only permits exist cannot tell "denied" from "never asked".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PdpDecisionOutcome {
    /// The authority permitted the decided action for the decided principal.
    #[serde(rename = "permit")]
    Permit,
    /// The authority refused it.
    #[serde(rename = "deny")]
    Deny,
}

/// The actor a decision is about, and the scope at which it binds.
///
/// A closed choice, tagged by `mcp_re_decided_scope` in the signed claims. Modelled as a sum
/// rather than a struct with an optional `keyid` so that a principal-scoped decision has no
/// keyid to omit and a credential-scoped one cannot lack it: the illegal state does not
/// exist, rather than being rejected by a check somewhere.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope")]
pub enum DecidedActor {
    /// The decision is about a PRINCIPAL and survives a signing-key rotation.
    #[serde(rename = "principal")]
    Principal {
        trust_domain: String,
        subject: String,
    },
    /// The decision is about one signing CREDENTIAL and does not survive its rotation.
    #[serde(rename = "credential")]
    Credential {
        trust_domain: String,
        subject: String,
        keyid: String,
    },
}

impl DecidedActor {
    /// The trust domain, whichever scope this is.
    pub fn trust_domain(&self) -> &str {
        match self {
            DecidedActor::Principal { trust_domain, .. }
            | DecidedActor::Credential { trust_domain, .. } => trust_domain,
        }
    }

    /// The subject, whichever scope this is.
    pub fn subject(&self) -> &str {
        match self {
            DecidedActor::Principal { subject, .. } | DecidedActor::Credential { subject, .. } => {
                subject
            }
        }
    }

    /// The signing credential this decision is scoped to, or `None` for a principal-scoped
    /// one. `None` here is the SCOPE speaking, not an absent value.
    pub fn keyid(&self) -> Option<&str> {
        match self {
            DecidedActor::Principal { .. } => None,
            DecidedActor::Credential { keyid, .. } => Some(keyid),
        }
    }

    /// Which scope this decision claims. A deployment accepts one; it never infers it.
    pub fn scope(&self) -> DecisionScope {
        match self {
            DecidedActor::Principal { .. } => DecisionScope::Principal,
            DecidedActor::Credential { .. } => DecisionScope::Credential,
        }
    }
}

/// The scope discriminator on its own, for a deployment to declare what it accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionScope {
    /// Decisions about a principal, surviving signing-key rotation.
    Principal,
    /// Decisions about one signing credential.
    Credential,
}

/// The JWS protected header of an authorization decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PdpDecisionHeader {
    pub typ: String,
    pub alg: String,
    /// The issuing authority's root key id — resolved through the trust seam, never trusted
    /// because it is named here.
    pub kid: String,
}

/// The claims of an authorization decision.
///
/// Every field earns its place by a refusal it makes possible. Nothing here is descriptive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PdpDecisionClaims {
    /// The authority that decided.
    pub iss: String,
    /// When the decision was taken. Bounds how stale a decision a verifier will act on,
    /// independently of the issuer's chosen lifetime.
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
    /// Ties to the authority's own decision record for cross-audit. Not a replay key.
    pub jti: String,
    /// Who may PROCESS this decision. Without it, a decision issued for one enforcement
    /// point is presentable at another that shares the authority.
    pub aud: Audience,
    /// The MCP-RE evidence profile this decision is valid for.
    pub mcp_re_profile: String,
    /// WHO the decision is about, and at which scope.
    ///
    /// A nested object rather than flattened claims: `serde`'s `flatten` is incompatible
    /// with `deny_unknown_fields`, and dropping the strict-unknown-field rule on a signed
    /// security artifact to gain a flatter shape would be trading a real check for a
    /// cosmetic one.
    pub mcp_re_decided_actor: DecidedActor,
    /// The JSON-RPC method the decision permits.
    pub mcp_re_decided_operation: String,
    /// The tool or resource the decided operation names, where its method names one.
    ///
    /// `None` means the decided operation names no target. It must not match a request whose
    /// operation DOES name one: a decision for `tools/list` cannot authorize a `tools/call`,
    /// and the adapter compares the typed values rather than two `Option`s.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_re_decided_target: Option<String>,
    /// Permit or deny.
    pub mcp_re_decision: PdpDecisionOutcome,
    /// The policy version the decision was taken under.
    ///
    /// Required BY THIS PROFILE, which is what makes it honest: ADR-MCPRE-065 §6 asks a
    /// success product to name the authority and version its decision was taken under, and
    /// an authority that cannot state one cannot issue decisions here. The alternative —
    /// an optional field — would let `GrantAttribution` be built from a version nobody
    /// supplied, which is attribution invented at the enforcement point.
    pub mcp_re_policy_version: String,
    /// The issuer root `key_id` — equals the header `kid`.
    pub issuer_kid: String,
}

#[cfg(test)]
mod tests {
    use super::DecidedActor;
    use super::DecisionScope;

    fn principal() -> DecidedActor {
        DecidedActor::Principal {
            trust_domain: "example.com".into(),
            subject: "did:example:a".into(),
        }
    }

    fn credential() -> DecidedActor {
        DecidedActor::Credential {
            trust_domain: "example.com".into(),
            subject: "did:example:a".into(),
            keyid: "key-1".into(),
        }
    }

    #[test]
    fn the_scope_is_carried_in_the_signed_claims_not_inferred() {
        // The property that stops one document meaning different things to differently
        // configured deployments: the discriminator is IN the payload.
        let json = serde_json::to_value(credential()).expect("serializes");
        assert_eq!(json["scope"], "credential");
        assert_eq!(
            serde_json::to_value(principal()).expect("serializes")["scope"],
            "principal"
        );
    }

    #[test]
    fn a_principal_decision_has_no_keyid_to_omit() {
        // Not `Some`/`None` over one shape: the field does not exist in this variant, so
        // there is no check that could be skipped because it was absent.
        assert_eq!(principal().keyid(), None);
        assert_eq!(principal().scope(), DecisionScope::Principal);
        assert!(serde_json::to_value(principal()).expect("serializes")["keyid"].is_null());
    }

    #[test]
    fn a_credential_decision_cannot_lack_its_keyid() {
        assert_eq!(credential().keyid(), Some("key-1"));
        assert_eq!(credential().scope(), DecisionScope::Credential);
        // Deserializing a credential-scoped payload without the keyid FAILS — the illegal
        // combination is unrepresentable rather than rejected downstream.
        let missing = serde_json::json!({
            "scope": "credential",
            "trust_domain": "example.com",
            "subject": "did:example:a",
        });
        assert!(serde_json::from_value::<DecidedActor>(missing).is_err());
    }

    #[test]
    fn the_two_scopes_share_the_dimensions_they_both_bind() {
        for actor in [principal(), credential()] {
            assert_eq!(actor.trust_domain(), "example.com");
            assert_eq!(actor.subject(), "did:example:a");
        }
    }

    #[test]
    fn an_unknown_scope_is_refused_rather_than_defaulted() {
        let unknown = serde_json::json!({
            "scope": "everything",
            "trust_domain": "example.com",
            "subject": "did:example:a",
        });
        assert!(serde_json::from_value::<DecidedActor>(unknown).is_err());
    }
}
