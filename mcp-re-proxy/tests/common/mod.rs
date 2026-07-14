// SPDX-License-Identifier: Apache-2.0
//! Shared harness for the ROOT-AUTHORITY lifecycle lanes (ADR-MCPRE-052): a
//! `TestRootAuthorityProvider` that mints disposable roots, and a single
//! `run_rotation_scenario` the hermetic (in-memory) and live (Cloud KMS) lanes both
//! drive — so the two prove the SAME trust-anchor rotation/overlap/revocation, only
//! the root SOURCE differs (in-memory keys vs KMS-held keys).
//!
//! This is test-support, never shipped. The production root-rotation controller is a
//! separate, governed mechanism (see docs/spec/root-authority-rotation.md); this
//! provisions throwaway roots so the lifecycle can be tested WITHOUT a human creating
//! a KMS key for every run.

#![allow(dead_code)] // each test binary uses a subset

use mcp_re_client_core::load_signed_manifest;
use mcp_re_client_core::sign_manifest;
use mcp_re_client_core::ManifestIssuer;
use mcp_re_client_core::RetiringIssuer;
use mcp_re_client_core::RevocationSource;
use mcp_re_client_core::TrustAnchorManifest;
use mcp_re_client_core::TrustManifestError;

use mcp_re_core::b64url_decode;
use mcp_re_core::SigningKey;
use mcp_re_core::VerificationKey;

use mcp_re_http_profile::issue_delegation_credential_with_signer;
use mcp_re_http_profile::verify_delegation_credential;
use mcp_re_http_profile::Audience;
use mcp_re_http_profile::Cnf;
use mcp_re_http_profile::DelegatedJwk;
use mcp_re_http_profile::DelegationClaims;
use mcp_re_http_profile::DelegationHeader;
use mcp_re_http_profile::DelegationVerifyParams;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::DELEGATION_ALG;
use mcp_re_http_profile::DELEGATION_TYP;
use mcp_re_http_profile::JWK_CRV_ED25519;
use mcp_re_http_profile::JWK_KTY_OKP;
use mcp_re_http_profile::KEY_USE_RESPONSE_SIGNING;
use mcp_re_http_profile::PROFILE_TAG;

pub const AUD: &str = "verifier-1";
pub const AUD_SCOPE: &str = "aud-scope-1";
pub const EPOCH: &str = "epoch-1";
pub const SERVER_SIGNER: &str = "server:example.com:did:example:server:server-key";
pub const ORG_KID: &str = "org-admin-manifest-key";

/// A minted trust anchor: its id, its public key, and a signer over the JWS signing
/// input (raw 64-byte Ed25519). In-memory roots wrap a local key; KMS roots wrap a
/// Cloud KMS `asymmetricSign` call — both feed the SAME issuance seam.
pub struct RootAuthority {
    pub issuer_kid: String,
    pub public_key: VerificationKey,
    sign: Box<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>,
}

impl RootAuthority {
    /// Wrap an explicit signer (used by the live KMS lane).
    pub fn new(
        issuer_kid: impl Into<String>,
        public_key: VerificationKey,
        sign: Box<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>,
    ) -> Self {
        RootAuthority {
            issuer_kid: issuer_kid.into(),
            public_key,
            sign,
        }
    }

    fn sign_raw(&self, input: &[u8]) -> Vec<u8> {
        (self.sign)(input)
    }

    /// Mint a delegation credential (compact JWS) under this root for a fresh
    /// delegated key, returning `(compact_jws, delegated_kid)`.
    pub fn issue_credential(&self, delegated: &SigningKey, seq: u32, now: i64) -> String {
        let delegated_kid = format!("{}/delegated/{seq}", self.issuer_kid);
        let header = DelegationHeader {
            typ: DELEGATION_TYP.into(),
            alg: DELEGATION_ALG.into(),
            kid: self.issuer_kid.clone(),
        };
        let claims = DelegationClaims {
            iss: "did:example:issuer".into(),
            iat: now,
            nbf: now,
            exp: now + 300,
            jti: format!("evt-{}-{seq}", self.issuer_kid),
            aud: Audience::One(AUD.into()),
            mcp_re_profile: PROFILE_TAG.into(),
            mcp_re_audience_hash: AUD_SCOPE.into(),
            mcp_re_server_signer: SERVER_SIGNER.into(),
            mcp_re_key_use: KEY_USE_RESPONSE_SIGNING.into(),
            delegated_kid: delegated_kid.clone(),
            issuer_kid: self.issuer_kid.clone(),
            trust_epoch: EPOCH.into(),
            cnf: Cnf {
                jwk: DelegatedJwk {
                    kty: JWK_KTY_OKP.into(),
                    crv: JWK_CRV_ED25519.into(),
                    kid: delegated_kid.clone(),
                    x: delegated.public_key().to_b64url(),
                },
            },
        };
        issue_delegation_credential_with_signer(&header, &claims, |input| Ok(self.sign_raw(input)))
            .expect("root signs a 64-byte credential")
    }

    fn as_manifest_issuer(&self) -> ManifestIssuer {
        ManifestIssuer {
            issuer_kid: self.issuer_kid.clone(),
            public_key: self.public_key.to_b64url(),
            role: "server".into(),
            trust_domain: "example.com".into(),
            subject: "did:example:issuer".into(),
        }
    }

    fn as_retiring_issuer(&self, valid_until: i64) -> RetiringIssuer {
        RetiringIssuer {
            issuer_kid: self.issuer_kid.clone(),
            public_key: self.public_key.to_b64url(),
            role: "server".into(),
            trust_domain: "example.com".into(),
            subject: "did:example:issuer".into(),
            valid_until,
        }
    }
}

/// A provider that mints disposable roots on demand — the "no human creates a key"
/// mechanism. Hermetic tests use [`InMemoryTestRootAuthorityProvider`]; the live lane
/// constructs KMS-backed [`RootAuthority`]s directly from provisioned key versions.
pub trait TestRootAuthorityProvider {
    fn create_root(&mut self, label: &str) -> RootAuthority;
}

/// Mints in-memory Ed25519 roots — the hermetic analogue of the KMS provisioner.
pub struct InMemoryTestRootAuthorityProvider {
    seed: u8,
}

impl InMemoryTestRootAuthorityProvider {
    pub fn new() -> Self {
        InMemoryTestRootAuthorityProvider { seed: 40 }
    }
}

impl TestRootAuthorityProvider for InMemoryTestRootAuthorityProvider {
    fn create_root(&mut self, label: &str) -> RootAuthority {
        self.seed = self.seed.wrapping_add(1);
        let key = SigningKey::from_seed_bytes(&[self.seed; 32]);
        let public_key = key.public_key();
        RootAuthority::new(
            format!("inmem-root-{label}"),
            public_key,
            Box::new(move |input: &[u8]| {
                b64url_decode(&key.sign(input)).expect("own signature is valid base64url")
            }),
        )
    }
}

fn org_resolver(signer_kid: &str, org_pub: VerificationKey) -> impl Fn(&str) -> Option<VerificationKey> {
    let kid = signer_kid.to_string();
    move |k: &str| if k == kid { Some(org_pub.clone()) } else { None }
}

fn verify_params<'a>(now: i64) -> DelegationVerifyParams<'a> {
    DelegationVerifyParams {
        now,
        max_clock_skew: 60,
        verifier_audiences: &[AUD],
        expected_profile: PROFILE_TAG,
        expected_audience_hash: AUD_SCOPE,
        expected_server_signer: SERVER_SIGNER,
        accepted_epochs: &[EPOCH],
    }
}

/// Verify a credential against the trust anchors a signed manifest loads at `now`.
fn verify_credential_under_manifest(
    compact_jws: &str,
    signed_manifest: &mcp_re_client_core::SignedTrustAnchorManifest,
    org_key: &SigningKey,
    min_version: u64,
    now: i64,
) -> Result<(), HttpProfileError> {
    let loaded = load_signed_manifest(
        signed_manifest,
        org_resolver(ORG_KID, org_key.public_key()),
        PROFILE_TAG,
        min_version,
        now,
    )
    .expect("manifest loads");
    let set = loaded.issuer_set;
    verify_delegation_credential(
        compact_jws,
        &verify_params(now),
        |issuer_kid| set.resolve_root(issuer_kid, now).map(|a| a.verification_key),
        |id| set.is_revoked(id),
    )
    .map(|_| ())
}

/// THE shared scenario: given two roots and an org manifest-signing key, drive the
/// full trust-anchor rotation — A-only → A+B overlap → B-only(A retired) → A revoked —
/// through SIGNED manifests, asserting acceptance/rejection at each phase. Run
/// identically by the in-memory (CI) and Cloud KMS (live) lanes.
pub fn run_rotation_scenario(root_a: &RootAuthority, root_b: &RootAuthority, org_key: &SigningKey) {
    let now = 1_700_000_100;
    let d1 = SigningKey::from_seed_bytes(&[91u8; 32]);
    let d2 = SigningKey::from_seed_bytes(&[92u8; 32]);
    let cred_a = root_a.issue_credential(&d1, 1, now);
    let cred_b = root_b.issue_credential(&d2, 1, now);

    let expires = now + 100_000;
    let overlap_until = now + 1_000;

    // Phase 1 — manifest v1: Root A is the only trust anchor.
    let m1 = TrustAnchorManifest {
        profile: PROFILE_TAG.into(),
        manifest_version: 1,
        current_issuers: vec![root_a.as_manifest_issuer()],
        retiring_issuers: vec![],
        revoked_issuers: vec![],
        issued_at: now,
        expires_at: expires,
    };
    let s1 = sign_manifest(&m1, org_key, ORG_KID);
    verify_credential_under_manifest(&cred_a, &s1, org_key, 1, now).expect("A accepted under v1");
    assert_eq!(
        verify_credential_under_manifest(&cred_b, &s1, org_key, 1, now).unwrap_err(),
        HttpProfileError::DelegationIssuerUntrusted,
        "B unknown under v1 (not yet introduced)"
    );

    // Phase 2 — manifest v2: Root B introduced (current), Root A retiring in overlap.
    let m2 = TrustAnchorManifest {
        profile: PROFILE_TAG.into(),
        manifest_version: 2,
        current_issuers: vec![root_b.as_manifest_issuer()],
        retiring_issuers: vec![root_a.as_retiring_issuer(overlap_until)],
        revoked_issuers: vec![],
        issued_at: now,
        expires_at: expires,
    };
    let s2 = sign_manifest(&m2, org_key, ORG_KID);
    verify_credential_under_manifest(&cred_a, &s2, org_key, 2, now).expect("A still accepted during overlap");
    verify_credential_under_manifest(&cred_b, &s2, org_key, 2, now).expect("B accepted during overlap");
    // Past the overlap deadline: A no longer a trusted anchor, B still is. Short-TTL
    // delegated credentials are re-minted continuously, so mint FRESH ones at `past` —
    // the question under test is the ROOT's trust, not the credential's freshness.
    let past = overlap_until + 1;
    let cred_a_past = root_a.issue_credential(&d1, 2, past);
    let cred_b_past = root_b.issue_credential(&d2, 2, past);
    assert_eq!(
        verify_credential_under_manifest(&cred_a_past, &s2, org_key, 2, past).unwrap_err(),
        HttpProfileError::DelegationIssuerUntrusted,
        "A rejected after the overlap window closes"
    );
    verify_credential_under_manifest(&cred_b_past, &s2, org_key, 2, past).expect("B accepted after cutover");

    // Phase 3 — manifest v3: Root A REVOKED (compromise). It stays LISTED (so its
    // material still resolves and the rejection reason is the decisive `Revoked`, not a
    // vague `Untrusted`) but is named in revoked_issuers; Root B stays current. This is
    // the compromise-response posture — one decisive action invalidates all of A's
    // descendants; a later manifest can drop A's entry entirely once it has propagated.
    let m3 = TrustAnchorManifest {
        profile: PROFILE_TAG.into(),
        manifest_version: 3,
        current_issuers: vec![root_a.as_manifest_issuer(), root_b.as_manifest_issuer()],
        retiring_issuers: vec![],
        revoked_issuers: vec![root_a.issuer_kid.clone()],
        issued_at: now,
        expires_at: expires,
    };
    let s3 = sign_manifest(&m3, org_key, ORG_KID);
    assert_eq!(
        verify_credential_under_manifest(&cred_a, &s3, org_key, 3, now).unwrap_err(),
        HttpProfileError::DelegationRevoked,
        "revoking Root A invalidates its credential immediately, before exp"
    );
    verify_credential_under_manifest(&cred_b, &s3, org_key, 3, now).expect("B unaffected by A's revocation");

    // Rollback protection: after accepting v3, a replayed v2 (which un-revokes A) is refused.
    assert_eq!(
        load_signed_manifest(&s2, org_resolver(ORG_KID, org_key.public_key()), PROFILE_TAG, 3, now).unwrap_err(),
        TrustManifestError::Stale { version: 2, min_version: 3 },
        "a rollback to the pre-revocation manifest is refused"
    );
}
