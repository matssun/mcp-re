// SPDX-License-Identifier: Apache-2.0
//! Delegated signing-key attestation — the compact JOSE/JWS delegation credential
//! (ADR-MCPRE-052).
//!
//! The root/identity key (in the HSM/KMS, off the hot path) issues a short-lived
//! in-memory Ed25519 **delegated** signing key and binds it with a **root-signed
//! compact JWS credential** (RFC 7515 / 7519) carrying the delegated public key in
//! the `cnf` proof-of-possession claim (RFC 7800, RFC 8037 `EdDSA`). The delegated
//! key then signs the RFC 9421 response; per-request signing never touches the
//! root.
//!
//! This module is the **verifier** half: it parses and verifies the credential
//! chain to the root (ADR-MCPRE-052 §3 steps 2–7) and extracts the delegated
//! [`VerificationKey`] the response-signature check (step 8) then verifies under.
//! It lives in the HTTP-profile standards layer, never in `mcp-re-core`
//! (ADR-MCPS-018) — JOSE/JWS is one more IETF format alongside RFC 9421.
//!
//! Fail-closed throughout: any uncertainty on the credential → root chain rejects,
//! each mapped to its precise `mcp-re.delegation_*` token via [`HttpProfileError`].
//!
//! Scope boundary: presence/required-mode (§3 step 1) and the response signature
//! under `cnf.jwk` (§3 step 8) are the response-verifier's job — this module
//! returns the delegated key it needs. `alg` is pinned to `EdDSA`; no agility.

use mcp_re_core::b64url_decode;
use mcp_re_core::b64url_encode;
use mcp_re_core::verify_ed25519_with;
use mcp_re_core::McpReError;
use mcp_re_core::SigningKey;
use mcp_re_core::VerificationKey;
use serde::Deserialize;
use serde::Serialize;

use crate::error::HttpProfileError;

/// The frozen credential media type (ADR-MCPRE-052 §1; vocabulary firewall).
pub const DELEGATION_TYP: &str = "mcp-re-delegation+jwt";
/// The ONLY accepted JWS algorithm — Ed25519 per RFC 8037. No agility, no `none`.
pub const DELEGATION_ALG: &str = "EdDSA";
/// The ONLY key use this credential authorizes (ADR-MCPRE-052 §1).
pub const KEY_USE_RESPONSE_SIGNING: &str = "response-signing";
/// The `cnf.jwk` key type / curve for an Ed25519 delegated key (RFC 8037).
pub const JWK_KTY_OKP: &str = "OKP";
pub const JWK_CRV_ED25519: &str = "Ed25519";

/// The protected header of the delegation JWS (ADR-MCPRE-052 §1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationHeader {
    /// Frozen media type — must equal [`DELEGATION_TYP`].
    pub typ: String,
    /// Signature algorithm — must equal [`DELEGATION_ALG`] (`EdDSA`).
    pub alg: String,
    /// The ROOT/identity `key_id` that signed this credential; must equal the
    /// claims' `issuer_kid`.
    pub kid: String,
}

/// The Ed25519 public JWK carried in `cnf` (RFC 7800 / RFC 8037).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegatedJwk {
    /// `OKP` for Ed25519.
    pub kty: String,
    /// `Ed25519`.
    pub crv: String,
    /// The delegated key's own id — must equal the claims' `delegated_kid`.
    pub kid: String,
    /// The delegated Ed25519 public key, base64url-no-pad.
    pub x: String,
}

/// The RFC 7800 confirmation claim carrying the delegated public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cnf {
    pub jwk: DelegatedJwk,
}

/// A JWT `aud` value: a single audience or a set (RFC 7519 §4.1.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    /// Whether `who` is named in this audience — the RFC 7519 rule: a processor
    /// that does not identify itself in `aud` must reject.
    pub fn contains(&self, who: &str) -> bool {
        match self {
            Audience::One(a) => a == who,
            Audience::Many(v) => v.iter().any(|a| a == who),
        }
    }
}

/// The delegation credential claim set (ADR-MCPRE-052 §1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationClaims {
    /// Issuer identity (informational; trust flows through `issuer_kid`).
    pub iss: String,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
    /// Ties to the audit issuance event; NOT a replay-cache key (§5a).
    pub jti: String,
    /// RFC 7519 `aud`: who may PROCESS this credential (NOT the profile).
    pub aud: Audience,
    /// The MCP-RE evidence profile this credential is valid for.
    pub mcp_re_profile: String,
    /// The service/audience scope the delegated key may sign for.
    pub mcp_re_audience_hash: String,
    /// The resolved server-signer identity this delegation is bound to.
    pub mcp_re_server_signer: String,
    /// The only signature use this credential authorizes.
    pub mcp_re_key_use: String,
    /// The delegated key's own id — never the root's.
    pub delegated_kid: String,
    /// The root `key_id` — equals the protected-header `kid`.
    pub issuer_kid: String,
    /// The trust epoch at issuance — a hard verifier gate (§3 step 6).
    pub trust_epoch: String,
    /// RFC 7800 proof-of-possession: the delegated public key.
    pub cnf: Cnf,
}

/// The verified outcome of the credential chain (ADR-MCPRE-052 §3 steps 2–7).
///
/// [`delegated_key`](VerifiedDelegation::delegated_key) is what the response
/// verifier (§3 step 8) then verifies the RFC 9421 response signature under,
/// requiring the response `keyid == delegated_kid`.
#[derive(Debug, Clone)]
pub struct VerifiedDelegation {
    /// The delegated Ed25519 public key extracted from `cnf.jwk`.
    pub delegated_key: VerificationKey,
    /// The delegated key's id — the response `keyid` must equal this.
    pub delegated_kid: String,
    /// The resolved server-signer identity this delegation is bound to.
    pub server_signer: String,
    /// The root `issuer_kid` the credential chains to.
    pub issuer_kid: String,
    /// The credential's not-before / expiry (verifier freshness bounds).
    pub nbf: i64,
    pub exp: i64,
    /// The trust epoch the credential was minted under.
    pub trust_epoch: String,
}

/// The verifier's expectations for the credential scope + freshness
/// (ADR-MCPRE-052 §3). The caller supplies these from the active profile, the
/// verified request context, and the deployment's epoch policy.
pub struct DelegationVerifyParams<'a> {
    /// `now` in unix seconds, and the tolerated clock skew.
    pub now: i64,
    pub max_clock_skew: i64,
    /// This verifier's own audience identifier(s) — the credential's `aud` must
    /// name one of them.
    pub verifier_audiences: &'a [&'a str],
    /// The active HTTP profile id (`mcp_re_profile` must equal this).
    pub expected_profile: &'a str,
    /// The expected service/audience-scope hash and server signer.
    pub expected_audience_hash: &'a str,
    pub expected_server_signer: &'a str,
    /// The active accepted trust-epoch set — default `{ current }`, optionally
    /// `{ current, previous }` under a bounded rollout window (§3 step 6).
    pub accepted_epochs: &'a [&'a str],
}

/// Verify a compact JWS delegation credential against the root and the expected
/// scope (ADR-MCPRE-052 §3 steps 2–7), returning the delegated key for the
/// response-signature check (step 8).
///
/// - `resolve_root(issuer_kid) -> Some(root_key)` resolves the credential's
///   `issuer_kid` to a trusted **root** anchor (the existing trust resolver /
///   by-`key_id` trust map); `None` ⇒ untrusted issuer.
/// - `is_revoked(kid) -> bool` reports whether a `delegated_kid` or `issuer_kid`
///   is revoked at the current trust epoch.
///
/// Trust flows ONLY through the credential to the root: a delegated key is never
/// enrolled out of band, so a first-seen `delegated_kid` verifies from the
/// credential alone.
pub fn verify_delegation_credential(
    compact_jws: &str,
    params: &DelegationVerifyParams<'_>,
    resolve_root: impl Fn(&str) -> Option<VerificationKey>,
    is_revoked: impl Fn(&str) -> bool,
) -> Result<VerifiedDelegation, HttpProfileError> {
    // --- structure: exactly three base64url segments -------------------------
    let (header_seg, payload_seg, sig_seg) = split_compact_jws(compact_jws)?;

    // --- header: typ + alg pinning (step 3) ----------------------------------
    let header: DelegationHeader = decode_json(header_seg)?;
    if header.typ != DELEGATION_TYP || header.alg != DELEGATION_ALG {
        // Wrong media type or any alg other than EdDSA (incl. `none`).
        return Err(HttpProfileError::DelegationCredentialInvalid);
    }

    let claims: DelegationClaims = decode_json(payload_seg)?;

    // Header kid must name the claims' issuer_kid — the credential is internally
    // consistent about which root signed it (step 3).
    if header.kid != claims.issuer_kid {
        return Err(HttpProfileError::DelegationCredentialInvalid);
    }

    // --- issuer → trusted root anchor (step 2) -------------------------------
    let root_key = resolve_root(&claims.issuer_kid)
        .ok_or(HttpProfileError::DelegationIssuerUntrusted)?;

    // --- root signature over the JWS signing input (step 3) ------------------
    let signing_input = format!("{header_seg}.{payload_seg}");
    verify_ed25519_with(
        signing_input.as_bytes(),
        sig_seg,
        &root_key,
        McpReError::DelegationCredentialInvalid,
    )
    .map_err(|_| HttpProfileError::DelegationCredentialInvalid)?;

    // --- freshness (step 4) --------------------------------------------------
    // nbf ≤ now ≤ exp, widened by max_clock_skew on both edges.
    if params.now + params.max_clock_skew < claims.nbf
        || params.now - params.max_clock_skew > claims.exp
    {
        return Err(HttpProfileError::DelegationCredentialExpired);
    }

    // --- scope (step 5) ------------------------------------------------------
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

    // --- trust epoch: hard gate (step 6) -------------------------------------
    if !params
        .accepted_epochs
        .iter()
        .any(|e| *e == claims.trust_epoch)
    {
        return Err(HttpProfileError::DelegationTrustEpochStale);
    }

    // --- revocation (step 7) -------------------------------------------------
    if is_revoked(&claims.delegated_kid) || is_revoked(&claims.issuer_kid) {
        return Err(HttpProfileError::DelegationRevoked);
    }

    // --- cnf.jwk → delegated key (for step 8) --------------------------------
    let jwk = &claims.cnf.jwk;
    if jwk.kty != JWK_KTY_OKP || jwk.crv != JWK_CRV_ED25519 || jwk.kid != claims.delegated_kid {
        // A self-inconsistent cnf (wrong key type, or a jwk.kid that is not the
        // credential's delegated_kid) is an invalid credential.
        return Err(HttpProfileError::DelegationCredentialInvalid);
    }
    let delegated_key =
        VerificationKey::from_b64url(&jwk.x).map_err(|_| HttpProfileError::DelegationCredentialInvalid)?;

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

/// Bytes in a raw Ed25519 signature (RFC 8032 / RFC 8037 `EdDSA`). The external
/// root-signer seam MUST return exactly this — a KMS/HSM that hands back a
/// DER-wrapped or truncated signature is a contract violation, caught here rather
/// than emitted as a malformed credential (mirrors the response-signer seam).
const ED25519_SIGNATURE_LEN: usize = 64;

/// Issue (mint) a compact JWS delegation credential using an EXTERNAL root signer
/// — the Cloud KMS / HSM custody seam (ADR-MCPS-028), where the ADR-MCPRE-052 §2
/// root is held OFF the hot path and signs ONLY the credential at issuance /
/// rotation. The root private key never has to exist in this process.
///
/// `sign_root` receives the exact JWS signing input
/// (`base64url(header) "." base64url(claims)`, ASCII) and MUST return exactly the
/// 64 raw Ed25519 signature bytes (RFC 8037); any other length is rejected
/// `DelegationCredentialInvalid` rather than emitted. This is the KMS-capable
/// sibling of [`issue_delegation_credential`] (which requires an in-process
/// [`SigningKey`]); both route through the same builder, so the compact-JWS wire
/// bytes are identical for the same key and claims.
///
/// The caller builds a consistent pair: `typ`/`alg` pinned, header `kid` ==
/// claims `issuer_kid`, and `cnf.jwk` == the delegated key.
pub fn issue_delegation_credential_with_signer(
    header: &DelegationHeader,
    claims: &DelegationClaims,
    sign_root: impl FnOnce(&[u8]) -> Result<Vec<u8>, HttpProfileError>,
) -> Result<String, HttpProfileError> {
    let h = b64url_encode(&serde_json::to_vec(header).expect("delegation header serializes"));
    let p = b64url_encode(&serde_json::to_vec(claims).expect("delegation claims serialize"));
    let signing_input = format!("{h}.{p}");
    let sig = sign_root(signing_input.as_bytes())?;
    if sig.len() != ED25519_SIGNATURE_LEN {
        return Err(HttpProfileError::DelegationCredentialInvalid);
    }
    Ok(format!("{h}.{p}.{}", b64url_encode(&sig)))
}

/// Issue (mint) a compact JWS delegation credential with an IN-PROCESS root key
/// (ADR-MCPRE-052 §1) — the software-key path. Routes through
/// [`issue_delegation_credential_with_signer`], so it is wire-identical to the
/// KMS/HSM seam for the same key and claims. Production with the root in KMS/HSM
/// uses the signer seam instead, keeping the root off the hot path.
pub fn issue_delegation_credential(
    root_key: &SigningKey,
    header: &DelegationHeader,
    claims: &DelegationClaims,
) -> String {
    issue_delegation_credential_with_signer(header, claims, |input| {
        // `SigningKey::sign` returns Base64URL; decode to the raw 64 bytes the
        // seam contract speaks. An in-process Ed25519 signer is always 64 bytes.
        Ok(b64url_decode(&root_key.sign(input)).expect("own signature is valid base64url"))
    })
    .expect("in-process Ed25519 signer yields a 64-byte signature")
}

/// Split a compact JWS into its three base64url segments. Not exactly three parts,
/// or an empty segment ⇒ an invalid credential.
fn split_compact_jws(jws: &str) -> Result<(&str, &str, &str), HttpProfileError> {
    let mut parts = jws.split('.');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) if !h.is_empty() && !p.is_empty() && !s.is_empty() => {
            Ok((h, p, s))
        }
        _ => Err(HttpProfileError::DelegationCredentialInvalid),
    }
}

/// Decode a base64url-no-pad JWS segment and parse its JSON. Any failure ⇒ an
/// invalid credential.
fn decode_json<T: for<'de> Deserialize<'de>>(segment: &str) -> Result<T, HttpProfileError> {
    let bytes = b64url_decode(segment).map_err(|_| HttpProfileError::DelegationCredentialInvalid)?;
    serde_json::from_slice(&bytes).map_err(|_| HttpProfileError::DelegationCredentialInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE: &str = "mcp-re-http-v1";
    const AUD: &str = "did:example:verifier";
    const AUDIENCE_HASH: &str = "audhash-abc";
    const SERVER_SIGNER: &str = "server:example:api:root-kid";
    const EPOCH: &str = "epoch-7";
    const ISSUER_KID: &str = "root-kid";
    const DELEGATED_KID: &str = "root-kid/delegated/1";

    fn root() -> SigningKey {
        SigningKey::from_seed_bytes(&[1u8; 32])
    }
    fn delegated() -> SigningKey {
        SigningKey::from_seed_bytes(&[2u8; 32])
    }

    /// Mint a compact JWS credential signed by `root_key` (the issuer side).
    fn mint(root_key: &SigningKey, header: &DelegationHeader, claims: &DelegationClaims) -> String {
        issue_delegation_credential(root_key, header, claims)
    }

    fn good_header() -> DelegationHeader {
        DelegationHeader {
            typ: DELEGATION_TYP.into(),
            alg: DELEGATION_ALG.into(),
            kid: ISSUER_KID.into(),
        }
    }

    fn good_claims(delegated_key: &VerificationKey) -> DelegationClaims {
        DelegationClaims {
            iss: "did:example:api".into(),
            iat: 1_000,
            nbf: 1_000,
            exp: 2_000,
            jti: "evt-1".into(),
            aud: Audience::One(AUD.into()),
            mcp_re_profile: PROFILE.into(),
            mcp_re_audience_hash: AUDIENCE_HASH.into(),
            mcp_re_server_signer: SERVER_SIGNER.into(),
            mcp_re_key_use: KEY_USE_RESPONSE_SIGNING.into(),
            delegated_kid: DELEGATED_KID.into(),
            issuer_kid: ISSUER_KID.into(),
            trust_epoch: EPOCH.into(),
            cnf: Cnf {
                jwk: DelegatedJwk {
                    kty: JWK_KTY_OKP.into(),
                    crv: JWK_CRV_ED25519.into(),
                    kid: DELEGATED_KID.into(),
                    x: delegated_key.to_b64url(),
                },
            },
        }
    }

    fn params<'a>(audiences: &'a [&'a str], epochs: &'a [&'a str]) -> DelegationVerifyParams<'a> {
        DelegationVerifyParams {
            now: 1_500,
            max_clock_skew: 30,
            verifier_audiences: audiences,
            expected_profile: PROFILE,
            expected_audience_hash: AUDIENCE_HASH,
            expected_server_signer: SERVER_SIGNER,
            accepted_epochs: epochs,
        }
    }

    fn resolver(root_pub: VerificationKey) -> impl Fn(&str) -> Option<VerificationKey> {
        move |kid: &str| {
            if kid == ISSUER_KID {
                Some(root_pub.clone())
            } else {
                None
            }
        }
    }

    fn never_revoked(_: &str) -> bool {
        false
    }

    fn verify(
        jws: &str,
        p: &DelegationVerifyParams<'_>,
        root_pub: VerificationKey,
    ) -> Result<VerifiedDelegation, HttpProfileError> {
        verify_delegation_credential(jws, p, resolver(root_pub), never_revoked)
    }

    #[test]
    fn valid_credential_accepts_and_yields_delegated_key() {
        let (r, d) = (root(), delegated());
        let jws = mint(&r, &good_header(), &good_claims(&d.public_key()));
        let v = verify(&jws, &params(&[AUD], &[EPOCH]), r.public_key()).expect("valid");
        assert_eq!(v.delegated_kid, DELEGATED_KID);
        assert_eq!(v.server_signer, SERVER_SIGNER);
        assert_eq!(v.delegated_key.to_bytes(), d.public_key().to_bytes());
    }

    #[test]
    fn wrong_alg_is_credential_invalid() {
        let (r, d) = (root(), delegated());
        let mut h = good_header();
        h.alg = "none".into();
        let jws = mint(&r, &h, &good_claims(&d.public_key()));
        assert_eq!(
            verify(&jws, &params(&[AUD], &[EPOCH]), r.public_key()).unwrap_err(),
            HttpProfileError::DelegationCredentialInvalid
        );
    }

    #[test]
    fn wrong_typ_is_credential_invalid() {
        let (r, d) = (root(), delegated());
        let mut h = good_header();
        h.typ = "jwt".into();
        let jws = mint(&r, &h, &good_claims(&d.public_key()));
        assert_eq!(
            verify(&jws, &params(&[AUD], &[EPOCH]), r.public_key()).unwrap_err(),
            HttpProfileError::DelegationCredentialInvalid
        );
    }

    #[test]
    fn bad_root_signature_is_credential_invalid() {
        let (r, d) = (root(), delegated());
        // Sign with a DIFFERENT root than the resolver trusts.
        let attacker = SigningKey::from_seed_bytes(&[9u8; 32]);
        let jws = mint(&attacker, &good_header(), &good_claims(&d.public_key()));
        assert_eq!(
            verify(&jws, &params(&[AUD], &[EPOCH]), r.public_key()).unwrap_err(),
            HttpProfileError::DelegationCredentialInvalid
        );
    }

    #[test]
    fn unknown_issuer_is_untrusted() {
        let (r, d) = (root(), delegated());
        let mut h = good_header();
        let mut c = good_claims(&d.public_key());
        h.kid = "unknown-root".into();
        c.issuer_kid = "unknown-root".into();
        let jws = mint(&r, &h, &c);
        assert_eq!(
            verify(&jws, &params(&[AUD], &[EPOCH]), r.public_key()).unwrap_err(),
            HttpProfileError::DelegationIssuerUntrusted
        );
    }

    #[test]
    fn expired_and_not_yet_valid() {
        let (r, d) = (root(), delegated());
        let jws = mint(&r, &good_header(), &good_claims(&d.public_key()));
        let mut expired = params(&[AUD], &[EPOCH]);
        expired.now = 3_000; // > exp + skew
        assert_eq!(
            verify(&jws, &expired, r.public_key()).unwrap_err(),
            HttpProfileError::DelegationCredentialExpired
        );
        let mut early = params(&[AUD], &[EPOCH]);
        early.now = 100; // < nbf - skew
        assert_eq!(
            verify(&jws, &early, r.public_key()).unwrap_err(),
            HttpProfileError::DelegationCredentialExpired
        );
    }

    #[test]
    fn verifier_not_in_aud_is_audience_mismatch() {
        let (r, d) = (root(), delegated());
        let jws = mint(&r, &good_header(), &good_claims(&d.public_key()));
        // Verifier presents a different audience than the credential's `aud`.
        assert_eq!(
            verify(&jws, &params(&["did:example:other"], &[EPOCH]), r.public_key()).unwrap_err(),
            HttpProfileError::DelegationAudienceMismatch
        );
    }

    #[test]
    fn wrong_audience_hash_or_server_signer_is_audience_mismatch() {
        let (r, d) = (root(), delegated());
        let mut c = good_claims(&d.public_key());
        c.mcp_re_audience_hash = "other-scope".into();
        let jws = mint(&r, &good_header(), &c);
        assert_eq!(
            verify(&jws, &params(&[AUD], &[EPOCH]), r.public_key()).unwrap_err(),
            HttpProfileError::DelegationAudienceMismatch
        );
    }

    #[test]
    fn wrong_profile_is_profile_mismatch() {
        let (r, d) = (root(), delegated());
        let mut c = good_claims(&d.public_key());
        c.mcp_re_profile = "someone-else".into();
        let jws = mint(&r, &good_header(), &c);
        assert_eq!(
            verify(&jws, &params(&[AUD], &[EPOCH]), r.public_key()).unwrap_err(),
            HttpProfileError::DelegationProfileMismatch
        );
    }

    #[test]
    fn wrong_key_use_is_key_use_invalid() {
        let (r, d) = (root(), delegated());
        let mut c = good_claims(&d.public_key());
        c.mcp_re_key_use = "request-signing".into();
        let jws = mint(&r, &good_header(), &c);
        assert_eq!(
            verify(&jws, &params(&[AUD], &[EPOCH]), r.public_key()).unwrap_err(),
            HttpProfileError::DelegationKeyUseInvalid
        );
    }

    #[test]
    fn stale_trust_epoch_is_rejected_without_revocation() {
        let (r, d) = (root(), delegated());
        let jws = mint(&r, &good_header(), &good_claims(&d.public_key()));
        // Verifier's accepted set has advanced past the credential's epoch.
        assert_eq!(
            verify(&jws, &params(&[AUD], &["epoch-8"]), r.public_key()).unwrap_err(),
            HttpProfileError::DelegationTrustEpochStale
        );
    }

    #[test]
    fn bounded_rollout_window_accepts_previous_epoch() {
        let (r, d) = (root(), delegated());
        let jws = mint(&r, &good_header(), &good_claims(&d.public_key()));
        // Explicit { current, previous } window includes the credential's epoch.
        verify(&jws, &params(&[AUD], &["epoch-8", EPOCH]), r.public_key()).expect("accepted in window");
    }

    #[test]
    fn revoked_delegated_or_issuer_is_revoked() {
        let (r, d) = (root(), delegated());
        let jws = mint(&r, &good_header(), &good_claims(&d.public_key()));
        let p = params(&[AUD], &[EPOCH]);
        let err = verify_delegation_credential(
            &jws,
            &p,
            resolver(r.public_key()),
            |kid: &str| kid == DELEGATED_KID,
        )
        .unwrap_err();
        assert_eq!(err, HttpProfileError::DelegationRevoked);
    }

    #[test]
    fn cnf_kid_not_delegated_kid_is_credential_invalid() {
        let (r, d) = (root(), delegated());
        let mut c = good_claims(&d.public_key());
        c.cnf.jwk.kid = "some-other-kid".into();
        let jws = mint(&r, &good_header(), &c);
        assert_eq!(
            verify(&jws, &params(&[AUD], &[EPOCH]), r.public_key()).unwrap_err(),
            HttpProfileError::DelegationCredentialInvalid
        );
    }

    #[test]
    fn not_three_segments_is_credential_invalid() {
        let (r, _d) = (root(), delegated());
        assert_eq!(
            verify("only.two", &params(&[AUD], &[EPOCH]), r.public_key()).unwrap_err(),
            HttpProfileError::DelegationCredentialInvalid
        );
    }

    // --- external root-signer seam (ADR-MCPS-028 / KMS off the hot path) ------

    /// A KMS/HSM-shaped root signer: it exposes ONLY a raw-64-byte signing
    /// operation over the JWS signing input; the root key never leaves it. Here
    /// the "device" holds an in-process key, but the seam is the same one a Cloud
    /// KMS `sign_raw_ed25519` backend plugs into.
    fn kms_root(root: &SigningKey) -> impl Fn(&[u8]) -> Result<Vec<u8>, HttpProfileError> + '_ {
        move |input: &[u8]| Ok(b64url_decode(&root.sign(input)).expect("valid b64url"))
    }

    #[test]
    fn signer_seam_is_wire_identical_to_the_in_process_path() {
        // The KMS seam and the in-process key must produce byte-for-byte the same
        // compact JWS — this is what keeps the frozen corpus + external KAT valid.
        let (r, d) = (root(), delegated());
        let header = good_header();
        let claims = good_claims(&d.public_key());
        let in_process = issue_delegation_credential(&r, &header, &claims);
        let via_seam =
            issue_delegation_credential_with_signer(&header, &claims, kms_root(&r)).expect("mint");
        assert_eq!(in_process, via_seam);
    }

    #[test]
    fn seam_minted_credential_verifies_to_the_root() {
        let (r, d) = (root(), delegated());
        let jws =
            issue_delegation_credential_with_signer(&good_header(), &good_claims(&d.public_key()), kms_root(&r))
                .expect("mint");
        let v = verify(&jws, &params(&[AUD], &[EPOCH]), r.public_key()).expect("valid");
        assert_eq!(v.delegated_kid, DELEGATED_KID);
        assert_eq!(v.delegated_key.to_bytes(), d.public_key().to_bytes());
    }

    #[test]
    fn seam_rejects_a_non_64_byte_signature() {
        // A KMS that returns a DER-wrapped / truncated signature is a contract
        // violation, caught at minting rather than emitted as a bad credential.
        let d = delegated();
        for bad_len in [0usize, 63, 65, 72] {
            let err = issue_delegation_credential_with_signer(
                &good_header(),
                &good_claims(&d.public_key()),
                |_input| Ok(vec![0u8; bad_len]),
            )
            .unwrap_err();
            assert_eq!(err, HttpProfileError::DelegationCredentialInvalid, "len {bad_len}");
        }
    }

    #[test]
    fn seam_propagates_a_backend_failure() {
        // A KMS outage / permission error surfaces as the mint error, fail-closed.
        let d = delegated();
        let err = issue_delegation_credential_with_signer(
            &good_header(),
            &good_claims(&d.public_key()),
            |_input| Err(HttpProfileError::DelegationCredentialInvalid),
        )
        .unwrap_err();
        assert_eq!(err, HttpProfileError::DelegationCredentialInvalid);
    }
}
