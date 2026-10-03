// SPDX-License-Identifier: Apache-2.0
//! Chaining an inline delegation credential to a root the deployment trusts.
//!
//! One authority: **the key that signed this response was authorized to, by a credential
//! that chains to a root resolved through the SAME trust seam every other path uses**
//! (ADR-MCPRE-052 §3 steps 2–7).
//!
//! # Why this is one function and not one per delegated operation
//!
//! The bound and unbound paths differ in what the SIGNATURE covers, not in how a credential
//! chains to a root. They carried verbatim copies — the same params, the same root-issuer
//! closure, the same outage capture, the same explanatory comment — and two copies of a
//! trust-resolution rule are two places for it to drift. The mutation battery makes the
//! difference concrete: one slot mutation here breaks all 12 delegated controls at once,
//! where before it took two mutations to reach the same set.
//!
//! # The failure it re-reports, and why
//!
//! `verify_delegation_credential`'s resolver returns `Option`, which cannot express the
//! difference between *not trusted* and *the store could not answer*. Resolving inline
//! therefore collapsed a trust-store OUTAGE into `delegation_issuer_untrusted`, sending an
//! operator to look at the caller's credentials instead of at their own store — the exact
//! confusion the C079 fix removed everywhere else — and it dropped the slot assertion, so a
//! resolver handing back a Request-slot actor would have had its key accepted as a
//! delegation root. Both are captured here and re-reported as themselves.

use crate::block::HttpResponseEvidenceBlock;
use crate::block::ResolverOutcome;
use crate::block::SignerSlot;
use crate::delegation::verify_delegation_credential;
use crate::delegation::DelegationVerifyParams;
use crate::delegation::VerifiedDelegation;
use crate::error::HttpProfileError;
use crate::ids::PROFILE_TAG;
use crate::verify::floor::trust_slot::resolve_actor_for_slot;

use super::DelegationExpectations;

/// Verify the inline delegation credential a response block carries (ADR-MCPRE-052 §3
/// steps 2–7), resolving its ROOT issuer through the SAME trust seam every other path uses.
///
/// One function rather than a copy per delegated operation: the bound and unbound paths
/// differ in what the signature covers, not in how a credential chains to a root, and two
/// copies of a trust-resolution rule are two places for it to drift.
///
/// `verify_delegation_credential`'s resolver returns `Option`, which cannot express the
/// difference between "not trusted" and "the store could not answer" — so resolving inline
/// collapsed a trust-store OUTAGE into `mcp-re.delegation_issuer_untrusted`, sending an
/// operator to look at the caller's credentials instead of at their own store (the exact
/// confusion the C079 fix removed everywhere else), and it dropped the `actor.slot != slot`
/// assertion, so a resolver handing back a Request-slot actor would have had its key
/// accepted as a delegation root. The failure is captured here and re-reported as itself.
pub(super) fn chain_to_root<R: Into<ResolverOutcome>>(
    credential: &str,
    block: &HttpResponseEvidenceBlock,
    resolve_actor: &dyn Fn(&str, SignerSlot) -> R,
    expect: &DelegationExpectations<'_>,
    is_revoked: &dyn Fn(&str) -> bool,
    now: i64,
) -> Result<VerifiedDelegation, HttpProfileError> {
    let expected_server_signer = block.server_signer.actor_id();
    let params = DelegationVerifyParams {
        now,
        max_clock_skew: expect.max_clock_skew,
        verifier_audiences: expect.verifier_audiences,
        expected_profile: PROFILE_TAG,
        expected_audience_hash: expect.expected_audience_hash,
        expected_server_signer: &expected_server_signer,
        accepted_epochs: expect.accepted_epochs,
    };
    let resolve_failure: std::cell::RefCell<Option<HttpProfileError>> =
        std::cell::RefCell::new(None);
    let verified = verify_delegation_credential(
        credential,
        &params,
        |issuer_kid| match resolve_actor_for_slot(resolve_actor, issuer_kid, SignerSlot::Response) {
            Ok(actor) => Some(actor.verification_key),
            // A definitive "not trusted" stays the credential layer's own verdict
            // (`mcp-re.delegation_issuer_untrusted`) — that IS the right token for an
            // issuer nobody vouches for. Only an OUTAGE and a wrong-slot actor are
            // propagated, because those are not statements about the credential.
            Err(HttpProfileError::UnresolvedKeyId) => None,
            Err(e) => {
                *resolve_failure.borrow_mut() = Some(e);
                None
            }
        },
        |kid| is_revoked(kid),
    );
    verified.map_err(|e| resolve_failure.into_inner().unwrap_or(e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::ActorIdentity;
    use crate::block::RequestEvidenceDigest;
    use crate::block::ResolvedActor;
    use crate::delegation::issue_delegation_credential;
    use crate::delegation::Audience;
    use crate::delegation::Cnf;
    use crate::delegation::DelegatedJwk;
    use crate::delegation::DelegationClaims;
    use crate::delegation::DelegationHeader;
    use crate::delegation::DELEGATION_ALG;
    use crate::delegation::DELEGATION_TYP;
    use crate::delegation::JWK_CRV_ED25519;
    use crate::delegation::JWK_KTY_OKP;
    use crate::delegation::KEY_USE_RESPONSE_SIGNING;
    use mcp_re_core::SigningKey;

    const NOW: i64 = 1_700_000_100;
    const ROOT_KID: &str = "root-kid";
    const DELEGATED_KID: &str = "root-kid/delegated/1";
    const VERIFIER_AUD: &str = "verifier-1";
    const AUD_SCOPE: &str = "aud-scope-1";
    const EPOCH: &str = "epoch-1";

    fn root_key() -> SigningKey {
        SigningKey::from_seed_bytes(&[33u8; 32])
    }

    fn server_signer() -> ActorIdentity {
        ActorIdentity {
            role: "server".into(),
            trust_domain: "example.com".into(),
            subject: "did:example:server".into(),
            keyid: DELEGATED_KID.into(),
        }
    }

    fn block() -> HttpResponseEvidenceBlock {
        let delegated = SigningKey::from_seed_bytes(&[44u8; 32]);
        let header = DelegationHeader {
            typ: DELEGATION_TYP.into(),
            alg: DELEGATION_ALG.into(),
            kid: ROOT_KID.into(),
        };
        let claims = DelegationClaims {
            iss: "did:example:server".into(),
            iat: 1_700_000_000,
            nbf: 1_700_000_000,
            exp: 1_700_000_300,
            jti: "evt-1".into(),
            aud: Audience::One(VERIFIER_AUD.into()),
            mcp_re_profile: PROFILE_TAG.into(),
            mcp_re_audience_hash: AUD_SCOPE.into(),
            mcp_re_server_signer: server_signer().actor_id(),
            mcp_re_key_use: KEY_USE_RESPONSE_SIGNING.into(),
            delegated_kid: DELEGATED_KID.into(),
            issuer_kid: ROOT_KID.into(),
            trust_epoch: EPOCH.into(),
            cnf: Cnf {
                jwk: DelegatedJwk {
                    kty: JWK_KTY_OKP.into(),
                    crv: JWK_CRV_ED25519.into(),
                    kid: DELEGATED_KID.into(),
                    x: delegated.public_key().to_b64url(),
                },
            },
        };
        HttpResponseEvidenceBlock {
            profile: PROFILE_TAG.into(),
            server_signer: server_signer(),
            server_delegation: Some(issue_delegation_credential(&root_key(), &header, &claims)),
            request_evidence: RequestEvidenceDigest {
                digest_alg: "sha-256".into(),
                digest_value: "unused".into(),
            },
        }
    }

    fn root_actor(slot: SignerSlot) -> ResolvedActor {
        ResolvedActor {
            identity: ActorIdentity {
                role: "server".into(),
                trust_domain: "example.com".into(),
                subject: "did:example:server".into(),
                keyid: ROOT_KID.into(),
            },
            verification_key: root_key().public_key(),
            slot,
        }
    }

    fn chain(
        resolve: &dyn Fn(&str, SignerSlot) -> ResolverOutcome,
    ) -> Result<VerifiedDelegation, HttpProfileError> {
        let block = block();
        let credential = block.server_delegation.clone().unwrap_or_default();
        let expect = DelegationExpectations {
            verifier_audiences: &[VERIFIER_AUD],
            expected_audience_hash: AUD_SCOPE,
            accepted_epochs: &[EPOCH],
            max_clock_skew: 60,
        };
        chain_to_root(&credential, &block, resolve, &expect, &|_| false, NOW)
    }

    #[test]
    fn an_outage_resolving_the_root_is_reported_as_unavailable() {
        let result = chain(&|_, _| ResolverOutcome::Unavailable);
        assert!(matches!(
            result,
            Err(HttpProfileError::TrustResolverUnavailable)
        ));
    }

    #[test]
    fn a_wrong_slot_root_actor_is_refused_not_accepted() {
        let result =
            chain(&|_, _| ResolverOutcome::Resolved(Box::new(root_actor(SignerSlot::Request))));
        assert!(matches!(result, Err(HttpProfileError::ActorSlotMismatch)));
    }

    #[test]
    fn a_definitive_not_trusted_root_stays_issuer_untrusted() {
        let result = chain(&|_, _| ResolverOutcome::NotTrusted);
        assert!(matches!(
            result,
            Err(HttpProfileError::DelegationIssuerUntrusted)
        ));
    }

    #[test]
    fn a_response_slot_root_with_a_matching_credential_verifies() {
        let result = chain(&|_, slot| match slot {
            SignerSlot::Response => {
                ResolverOutcome::Resolved(Box::new(root_actor(SignerSlot::Response)))
            }
            _ => ResolverOutcome::NotTrusted,
        });
        assert_eq!(
            result.map(|v| v.delegated_kid).ok().as_deref(),
            Some(DELEGATED_KID)
        );
    }
}
