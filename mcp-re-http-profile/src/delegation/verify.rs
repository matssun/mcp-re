// SPDX-License-Identifier: Apache-2.0
//! What must hold before a delegated key may be believed (ADR-MCPRE-052 §3 steps 2–8).
//!
//! Trust flows ONLY through the credential to the root. A delegated key is never enrolled
//! out of band, so a first-seen `delegated_kid` verifies from the credential alone — and
//! every step below is therefore load-bearing rather than defence in depth: nothing else in
//! the system has an independent opinion about this key.
//!
//! The steps are separate functions because they are separate propositions, each with its
//! own refusal on the wire. A single boolean over all of them would tell an operator that a
//! response could not be verified without saying whether the issuer is untrusted, the
//! credential expired, its scope names another service, its epoch is stale, or it has been
//! revoked — five different operational responses.
//!
//! Ordering is not free. The root signature (step 3) is checked BEFORE any claim is acted
//! on, so every later step reads values the root has signed rather than values an attacker
//! chose.

use mcp_re_core::McpReError;
use mcp_re_core::VerificationKey;

use crate::error::HttpProfileError;

use super::bounded_skew;
use super::decode_json;
use super::split_compact_jws;
use super::verify_ed25519_with;
use super::DelegationClaims;
use super::DelegationHeader;
use super::DelegationVerifyParams;
use super::VerifiedDelegation;
use super::DELEGATION_ALG;
use super::DELEGATION_TYP;
use super::JWK_CRV_ED25519;
use super::JWK_KTY_OKP;
use super::KEY_USE_RESPONSE_SIGNING;

/// Steps 2–3: the credential is internally consistent, and a trusted ROOT signed it.
///
/// `typ` and `alg` are pinned before anything is decoded — any algorithm other than EdDSA,
/// `none` included, is refused rather than dispatched on. The header `kid` must name the
/// claims' `issuer_kid`, so the credential is consistent about which root signed it, and
/// that issuer must resolve to a trusted root anchor.
fn check_root_signature(
    segments: (&str, &str, &str),
    header: &DelegationHeader,
    claims: &DelegationClaims,
    resolve_root: impl Fn(&str) -> Option<VerificationKey>,
) -> Result<(), HttpProfileError> {
    let (header_seg, payload_seg, sig_seg) = segments;
    if header.typ != DELEGATION_TYP || header.alg != DELEGATION_ALG {
        return Err(HttpProfileError::DelegationCredentialInvalid);
    }
    if header.kid != claims.issuer_kid {
        return Err(HttpProfileError::DelegationCredentialInvalid);
    }
    let root_key =
        resolve_root(&claims.issuer_kid).ok_or(HttpProfileError::DelegationIssuerUntrusted)?;
    let signing_input = format!("{header_seg}.{payload_seg}");
    verify_ed25519_with(
        signing_input.as_bytes(),
        sig_seg,
        &root_key,
        McpReError::DelegationCredentialInvalid,
    )
    .map_err(|_| HttpProfileError::DelegationCredentialInvalid)
}

/// Step 4: `nbf ≤ now ≤ exp`, widened by the BOUNDED skew on both edges.
///
/// The skew is clamped before it is applied, by the same cap the RFC 9421 signature gate
/// uses, so a misconfigured tolerance cannot widen the credential-acceptance window past it.
fn check_freshness(
    claims: &DelegationClaims,
    params: &DelegationVerifyParams<'_>,
) -> Result<(), HttpProfileError> {
    let skew = bounded_skew(params.max_clock_skew);
    if params.now + skew < claims.nbf || params.now - skew > claims.exp {
        return Err(HttpProfileError::DelegationCredentialExpired);
    }
    Ok(())
}

/// Step 5: the credential was issued for THIS service, for THIS purpose.
///
/// Four facts, and each gets its own refusal: the JWS audience, the profile tag, the
/// `(audience_hash, server_signer)` scope pair, and the key use. A credential valid for one
/// deployment must not be presentable at another, which is what the scope pair carries.
fn check_scope(
    claims: &DelegationClaims,
    params: &DelegationVerifyParams<'_>,
) -> Result<(), HttpProfileError> {
    if !params
        .verifier_audiences
        .iter()
        .any(|a| claims.aud.contains(a))
    {
        return Err(HttpProfileError::DelegationAudienceMismatch);
    }
    if claims.mcp_re_profile != params.expected_profile {
        return Err(HttpProfileError::DelegationProfileMismatch);
    }
    if claims.mcp_re_audience_hash != params.expected_audience_hash
        || claims.mcp_re_server_signer != params.expected_server_signer
    {
        return Err(HttpProfileError::DelegationAudienceMismatch);
    }
    if claims.mcp_re_key_use != KEY_USE_RESPONSE_SIGNING {
        return Err(HttpProfileError::DelegationKeyUseInvalid);
    }
    Ok(())
}

/// Steps 6–7: the trust epoch is one this deployment currently accepts, and nothing the
/// credential names has been revoked.
///
/// The revocation seam is consulted with every identifier the credential carries — the
/// delegated key, its root anchor, and the per-credential `jti`. Any hit fails closed:
/// revoking the root must not leave credentials it issued acceptable, and revoking one
/// credential must not require revoking the key.
fn check_epoch_and_revocation(
    claims: &DelegationClaims,
    params: &DelegationVerifyParams<'_>,
    is_revoked: impl Fn(&str) -> bool,
) -> Result<(), HttpProfileError> {
    if !params
        .accepted_epochs
        .iter()
        .any(|e| *e == claims.trust_epoch)
    {
        return Err(HttpProfileError::DelegationTrustEpochStale);
    }
    if is_revoked(&claims.delegated_kid)
        || is_revoked(&claims.issuer_kid)
        || is_revoked(&claims.jti)
    {
        return Err(HttpProfileError::DelegationRevoked);
    }
    Ok(())
}

/// The delegated key the credential attests, for the step-8 response-signature check.
///
/// A self-inconsistent `cnf` — wrong key type or curve, or a `jwk.kid` that is not the
/// credential's own `delegated_kid` — is an invalid credential, not a key to try anyway.
fn delegated_key(claims: &DelegationClaims) -> Result<VerificationKey, HttpProfileError> {
    let jwk = &claims.cnf.jwk;
    if jwk.kty != JWK_KTY_OKP || jwk.crv != JWK_CRV_ED25519 || jwk.kid != claims.delegated_kid {
        return Err(HttpProfileError::DelegationCredentialInvalid);
    }
    VerificationKey::from_b64url(&jwk.x).map_err(|_| HttpProfileError::DelegationCredentialInvalid)
}

/// Verify a compact JWS delegation credential against the root and the expected scope
/// (ADR-MCPRE-052 §3 steps 2–7), returning the delegated key for the response-signature
/// check (step 8).
///
/// - `resolve_root(issuer_kid) -> Some(root_key)` resolves the credential's `issuer_kid` to
///   a trusted **root** anchor (the existing trust resolver / by-`key_id` trust map);
///   `None` ⇒ untrusted issuer.
/// - `is_revoked(id) -> bool` reports whether the credential's `delegated_kid`,
///   `issuer_kid`, or `jti` is revoked at the current trust epoch.
pub fn verify_delegation_credential(
    compact_jws: &str,
    params: &DelegationVerifyParams<'_>,
    resolve_root: impl Fn(&str) -> Option<VerificationKey>,
    is_revoked: impl Fn(&str) -> bool,
) -> Result<VerifiedDelegation, HttpProfileError> {
    let segments = split_compact_jws(compact_jws)?;
    let header: DelegationHeader = decode_json(segments.0)?;
    let claims: DelegationClaims = decode_json(segments.1)?;
    check_root_signature(segments, &header, &claims, resolve_root)?;
    // Every step below reads values the root has signed.
    check_freshness(&claims, params)?;
    check_scope(&claims, params)?;
    check_epoch_and_revocation(&claims, params, is_revoked)?;
    let delegated_key = delegated_key(&claims)?;
    Ok(VerifiedDelegation {
        delegated_key,
        delegated_kid: claims.delegated_kid,
        server_signer: claims.mcp_re_server_signer,
        issuer_kid: claims.issuer_kid,
        nbf: claims.nbf,
        exp: claims.exp,
        trust_epoch: claims.trust_epoch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims() -> DelegationClaims {
        DelegationClaims {
            iss: "root".into(),
            iat: 900,
            aud: crate::Audience::One("https://example.org/mcp".into()),
            jti: "jti-1".into(),
            nbf: 1_000,
            exp: 2_000,
            issuer_kid: "root-kid".into(),
            delegated_kid: "delegated-kid".into(),
            trust_epoch: "7".into(),
            mcp_re_profile: "mcp-re/http-1".into(),
            mcp_re_audience_hash: "aud-hash".into(),
            mcp_re_server_signer: "mcp-re:server:example.org:delegated-kid".into(),
            mcp_re_key_use: KEY_USE_RESPONSE_SIGNING.into(),
            cnf: super::super::Cnf {
                jwk: super::super::DelegatedJwk {
                    kty: JWK_KTY_OKP.into(),
                    crv: JWK_CRV_ED25519.into(),
                    kid: "delegated-kid".into(),
                    x: String::new(),
                },
            },
        }
    }

    fn params<'a>(
        now: i64,
        audiences: &'a [&'a str],
        epochs: &'a [&'a str],
    ) -> DelegationVerifyParams<'a> {
        DelegationVerifyParams {
            now,
            max_clock_skew: 0,
            verifier_audiences: audiences,
            expected_profile: "mcp-re/http-1",
            expected_audience_hash: "aud-hash",
            expected_server_signer: "mcp-re:server:example.org:delegated-kid",
            accepted_epochs: epochs,
        }
    }

    /// Each scope failure keeps its own refusal. Collapsing them would tell an operator a
    /// response could not be verified without saying whether the credential belongs to
    /// another deployment, another profile, or another purpose.
    #[test]
    fn each_scope_failure_names_what_it_is() {
        let auds = ["https://example.org/mcp"];
        let epochs = ["7"];
        assert!(check_scope(&claims(), &params(1_500, &auds, &epochs)).is_ok());

        let mut other_profile = claims();
        other_profile.mcp_re_profile = "mcp-re/http-0".into();
        assert!(matches!(
            check_scope(&other_profile, &params(1_500, &auds, &epochs)),
            Err(HttpProfileError::DelegationProfileMismatch)
        ));

        let mut other_deployment = claims();
        other_deployment.mcp_re_audience_hash = "another".into();
        assert!(matches!(
            check_scope(&other_deployment, &params(1_500, &auds, &epochs)),
            Err(HttpProfileError::DelegationAudienceMismatch)
        ));

        let mut other_use = claims();
        other_use.mcp_re_key_use = "request-signing".into();
        assert!(matches!(
            check_scope(&other_use, &params(1_500, &auds, &epochs)),
            Err(HttpProfileError::DelegationKeyUseInvalid)
        ));
    }

    /// Every identifier the credential carries is consulted. Revoking the root must not
    /// leave the credentials it issued acceptable, and revoking one credential must not
    /// require revoking the key it names.
    #[test]
    fn revocation_is_consulted_with_every_identifier_the_credential_carries() {
        let auds = ["https://example.org/mcp"];
        let epochs = ["7"];
        let p = params(1_500, &auds, &epochs);
        assert!(check_epoch_and_revocation(&claims(), &p, |_| false).is_ok());
        for revoked in ["delegated-kid", "root-kid", "jti-1"] {
            assert!(matches!(
                check_epoch_and_revocation(&claims(), &p, |id| id == revoked),
                Err(HttpProfileError::DelegationRevoked)
            ));
        }
    }

    /// A stale trust epoch is a hard gate, and it is a different fact from revocation: the
    /// epoch says this deployment has moved on, revocation says this credential was
    /// withdrawn.
    #[test]
    fn a_stale_trust_epoch_is_its_own_refusal() {
        let auds = ["https://example.org/mcp"];
        let moved_on = ["8"];
        assert!(matches!(
            check_epoch_and_revocation(&claims(), &params(1_500, &auds, &moved_on), |_| false),
            Err(HttpProfileError::DelegationTrustEpochStale)
        ));
    }

    /// A `cnf` naming a key other than the credential's own `delegated_kid` is invalid, not
    /// a key to try anyway — otherwise a credential could attest one key and hand over
    /// another.
    #[test]
    fn a_cnf_that_names_another_key_is_an_invalid_credential() {
        let mut mismatched = claims();
        mismatched.cnf.jwk.kid = "someone-else".into();
        assert!(matches!(
            delegated_key(&mismatched),
            Err(HttpProfileError::DelegationCredentialInvalid)
        ));
        let mut wrong_curve = claims();
        wrong_curve.cnf.jwk.crv = "P-256".into();
        assert!(matches!(
            delegated_key(&wrong_curve),
            Err(HttpProfileError::DelegationCredentialInvalid)
        ));
    }
}
