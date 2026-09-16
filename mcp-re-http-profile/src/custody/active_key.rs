// SPDX-License-Identifier: Apache-2.0
//! The active delegated key: the credential the fleet verifies against, and the window this
//! deployment serves under, as ONE value.
//!
//! The window used to be two `i64` fields set beside a `credential` string, and the two were
//! never compared. They also answered different questions: the fields carried what this
//! issuance **requested**, while `credential` carries what the root **issued**. A root that
//! clamps a requested validity — ordinary, legitimate issuer behaviour — left the producer
//! signing, and [`SigningWindow`](../../../mcp_re_proxy/http_profile_serve/signing_window)
//! advertising validity, under a window every verifier in the fleet had already stopped
//! accepting. Nothing had to go wrong for that to happen; the type admitted it.
//!
//! So the request is not an authority here. The credential is, and it is the only one: `nbf`
//! and `exp` are derived from the compact JWS that will be published and are not settable at
//! all. Delete every comparison in this file and an inconsistent inhabitant is still
//! unconstructible, because there is no second representation left to disagree.
//!
//! **What this file does NOT establish.** That the credential verifies under the root. That
//! is the issuance seam's obligation and it is discharged there: the production issuer
//! (`delegated_wiring::build_delegated_signing`) re-verifies the root's own signature over
//! the JWS signing input under the key the root advertises, and fails the issuance closed
//! otherwise. This owner therefore treats the bytes `Issue` returns as coming from inside a
//! ratified trusted-root boundary and adds no second signature check — what it establishes
//! is the different claim that those bytes attest *this* issuance: this key, this identity,
//! this deployment's delegation context, and a window that is a window.

use std::sync::Arc;

use mcp_re_core::SigningKey;

use crate::block::ActorIdentity;
use crate::delegation::delegated_key_of;
use crate::delegation::parse_credential;
use crate::delegation::DelegationClaims;
use crate::delegation::DelegationHeader;
use crate::error::HttpProfileError;

/// An owned, cheaply-cloned snapshot of the current delegated key and its root-signed
/// credential (ADR-MCPRE-052 §4). A hot-path response signer publishes one and signs per
/// request off it — the root is never touched on that path; issuance and rotation stay
/// inside the custody state machine.
///
/// The representation is private and [`issued`](Self::issued) is its only producer, so
/// holding one of these means the credential attests the key inside it and the window
/// projected by [`nbf`](Self::nbf)/[`exp`](Self::exp) is the credential's own.
#[derive(Clone)]
pub struct ActiveDelegatedKey {
    /// The in-memory delegated Ed25519 signing key (shared, never the root). Shared via
    /// `Arc` because a delegated `SigningKey` is deliberately not `Clone`.
    key: Arc<SigningKey>,
    /// The server-signer identity naming this delegated key. Supplied rather than derived:
    /// `role`/`trust_domain`/`subject` come from deployment configuration and the claims
    /// carry only their canonical escaped join, so inverting that join would be a third
    /// representation of one identity. It is checked against the claims instead.
    server_signer: ActorIdentity,
    /// The inline root-signed delegation credential (compact JWS) — the published bytes.
    credential: String,
    /// Read out of `credential`, never supplied.
    delegated_kid: String,
    /// Read out of `credential`, never supplied. `exp` is the fail-closed bound: a signer
    /// MUST stop signing off this snapshot once `now >= exp`.
    nbf: i64,
    exp: i64,
}

impl ActiveDelegatedKey {
    /// Take the credential an issuance returned as the authority on everything it states.
    ///
    /// `requested` is what [`build`](super::DelegatedSigningCustody::build) asked the root to
    /// attest. It is not an authority on the window — the root may legitimately clamp a
    /// requested validity, and a verifier reads the credential, not the request — but it IS
    /// the statement of what this issuance was supposed to establish, so everything else must
    /// come back unchanged.
    ///
    /// Comparing the whole returned claim set against the requested one, rather than
    /// enumerating the fields that matter, is deliberate: [`DelegationClaims`] is
    /// `deny_unknown_fields`, so the set is closed, and a claim added later is covered here
    /// the day it is added instead of the day someone remembers to extend a list.
    pub(super) fn issued(
        key: Arc<SigningKey>,
        server_signer: ActorIdentity,
        requested: (&DelegationHeader, &DelegationClaims),
        credential: String,
    ) -> Result<Self, HttpProfileError> {
        let (requested_header, requested_claims) = requested;
        let (header, claims) = parse_credential(&credential)?;

        // The delegated key identity and its binding to the key actually held. `cnf` is the
        // rule that a wrong key type, a wrong curve, or a `jwk.kid` that is not the
        // credential's own `delegated_kid` is an invalid credential; it belongs to the
        // verifier and is borrowed rather than restated. What is added here is the half a
        // verifier cannot check: that the attested key is the one in this process.
        if delegated_key_of(&claims)?.to_bytes() != key.public_key().to_bytes() {
            return Err(HttpProfileError::DelegationCredentialInvalid);
        }

        // The identity the response block will carry is the one the root signed.
        if claims.mcp_re_server_signer != server_signer.actor_id() {
            return Err(HttpProfileError::DelegationCredentialInvalid);
        }

        // The static delegation context: issuer, audience, profile, scope, epoch, key use,
        // `jti`, `cnf`. Everything except the window, which the root owns.
        let mut as_requested = requested_claims.clone();
        as_requested.iat = claims.iat;
        as_requested.nbf = claims.nbf;
        as_requested.exp = claims.exp;
        if header != *requested_header || claims != as_requested {
            return Err(HttpProfileError::DelegationCredentialInvalid);
        }

        // The temporal relation itself. A credential whose window is empty or inverted is
        // not a narrower credential, it is an incoherent one, and `exp` is what the whole
        // fail-closed path is decided on.
        if claims.nbf >= claims.exp {
            return Err(HttpProfileError::DelegationCredentialInvalid);
        }

        Ok(ActiveDelegatedKey {
            key,
            server_signer,
            credential,
            delegated_kid: claims.delegated_kid,
            nbf: claims.nbf,
            exp: claims.exp,
        })
    }

    /// The delegated signing key. Never the root.
    pub fn key(&self) -> &SigningKey {
        &self.key
    }

    /// The delegated key id — the RFC 9421 `keyid` the response signs under, and the block's
    /// `server_signer.keyid`. Read out of the credential.
    pub fn delegated_kid(&self) -> &str {
        &self.delegated_kid
    }

    /// The server-signer identity naming this delegated key.
    pub fn server_signer(&self) -> &ActorIdentity {
        &self.server_signer
    }

    /// The inline root-signed delegation credential (compact JWS).
    pub fn credential(&self) -> &str {
        &self.credential
    }

    /// The credential's own not-before.
    pub fn nbf(&self) -> i64 {
        self.nbf
    }

    /// The credential's own expiry — the fail-closed bound. A signer MUST stop signing off
    /// this snapshot once `now >= exp`.
    pub fn exp(&self) -> i64 {
        self.exp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegation::issue_delegation_credential;
    use crate::delegation::Audience;
    use crate::delegation::Cnf;
    use crate::delegation::DelegatedJwk;
    use crate::delegation::DELEGATION_ALG;
    use crate::delegation::DELEGATION_TYP;
    use crate::delegation::JWK_CRV_ED25519;
    use crate::delegation::JWK_KTY_OKP;
    use crate::delegation::KEY_USE_RESPONSE_SIGNING;
    use crate::keyid::jwk_thumbprint_ed25519;

    const ROOT_KID: &str = "root-kid";
    const NBF: i64 = 1_000;
    const EXP: i64 = 1_300;

    fn root() -> SigningKey {
        SigningKey::from_seed_bytes(&[33u8; 32])
    }

    fn delegated() -> SigningKey {
        SigningKey::from_seed_bytes(&[101u8; 32])
    }

    /// What an issuance over `key` asks the root to attest.
    fn requested(key: &SigningKey) -> (DelegationHeader, DelegationClaims, ActorIdentity) {
        let x = key.public_key().to_b64url();
        let kid = jwk_thumbprint_ed25519(&x);
        let server_signer = ActorIdentity {
            role: "server".into(),
            trust_domain: "example.com".into(),
            subject: "did:example:server".into(),
            keyid: kid.clone(),
        };
        let header = DelegationHeader {
            typ: DELEGATION_TYP.to_owned(),
            alg: DELEGATION_ALG.to_owned(),
            kid: ROOT_KID.to_owned(),
        };
        let claims = DelegationClaims {
            iss: "did:example:server".into(),
            iat: NBF,
            nbf: NBF,
            exp: EXP,
            jti: format!("{ROOT_KID}#{kid}#0"),
            aud: Audience::One("verifier-1".into()),
            mcp_re_profile: "mcp-re-http-v1".into(),
            mcp_re_audience_hash: "aud-scope-1".into(),
            mcp_re_server_signer: server_signer.actor_id(),
            mcp_re_key_use: KEY_USE_RESPONSE_SIGNING.to_owned(),
            delegated_kid: kid.clone(),
            issuer_kid: ROOT_KID.to_owned(),
            trust_epoch: "epoch-1".into(),
            cnf: Cnf {
                jwk: DelegatedJwk {
                    kty: JWK_KTY_OKP.to_owned(),
                    crv: JWK_CRV_ED25519.to_owned(),
                    kid,
                    x,
                },
            },
        };
        (header, claims, server_signer)
    }

    /// Mint `returned` over the root and offer it as the answer to `requested`.
    fn offer(
        key: &SigningKey,
        requested_claims: &DelegationClaims,
        header: &DelegationHeader,
        returned: &DelegationClaims,
    ) -> Result<ActiveDelegatedKey, HttpProfileError> {
        let (_, _, server_signer) = requested(key);
        let credential = issue_delegation_credential(&root(), header, returned);
        ActiveDelegatedKey::issued(
            Arc::new(SigningKey::from_seed_bytes(&[101u8; 32])),
            server_signer,
            (header, requested_claims),
            credential,
        )
    }

    /// The row itself. The window is the CREDENTIAL's, not the request's — so a root that
    /// clamps the validity it was asked for is served under what it issued.
    ///
    /// Before the seal this control could not be written: both values came from the same
    /// argument, so it would have passed over any implementation at all.
    #[test]
    fn the_window_served_under_is_the_one_the_root_issued_not_the_one_requested() {
        let key = delegated();
        let (header, request, _) = requested(&key);
        let mut clamped = request.clone();
        clamped.exp = EXP - 100;
        let active = offer(&key, &request, &header, &clamped).expect("a clamp is legitimate");
        assert_eq!(active.exp(), EXP - 100, "the credential decides the window");
        assert_eq!(active.nbf(), NBF);
    }

    /// The ordinary case, so the refusals below are not true of everything.
    #[test]
    fn a_credential_attesting_this_issuance_is_accepted_and_read_for_its_window() {
        let key = delegated();
        let (header, request, _) = requested(&key);
        let active = offer(&key, &request, &header, &request).expect("the exact request");
        assert_eq!((active.nbf(), active.exp()), (NBF, EXP));
        assert_eq!(active.delegated_kid(), request.delegated_kid);
    }

    /// A credential attesting a DIFFERENT key publishes nothing: the snapshot's RFC 9421
    /// `keyid` would name a key this process does not hold, and no response it signed would
    /// verify anywhere in the fleet.
    ///
    /// Everything here is self-consistent — the credential attests exactly what its caller
    /// says the issuance asked for — so the claim-set comparison is satisfied and cannot be
    /// what refuses. That is deliberate: the caller states what it asked for, and a check
    /// against a caller's statement quantifies over one call site. Only the comparison
    /// against the key the value will actually HOLD quantifies over the type.
    #[test]
    fn a_credential_for_another_key_is_not_a_key_to_serve_on() {
        let other = SigningKey::from_seed_bytes(&[102u8; 32]);
        let (header, other_request, other_signer) = requested(&other);
        let credential = issue_delegation_credential(&root(), &header, &other_request);
        assert!(ActiveDelegatedKey::issued(
            Arc::new(delegated()),
            other_signer,
            (&header, &other_request),
            credential,
        )
        .is_err());
    }

    /// Each scoped claim, one at a time. The comparison is whole-claim-set rather than a
    /// list of fields, so this table is the evidence that it reaches every one of them.
    #[test]
    fn a_claim_the_root_did_not_echo_is_refused_field_by_field() {
        let key = delegated();
        let (header, request, _) = requested(&key);
        type Mutation = (&'static str, fn(&mut DelegationClaims));
        let mutations: Vec<Mutation> = vec![
            ("iss", |c| c.iss = "did:example:elsewhere".into()),
            ("jti", |c| c.jti = "another-credential".into()),
            ("aud", |c| c.aud = Audience::One("verifier-2".into())),
            ("profile", |c| c.mcp_re_profile = "mcp-re-http-v2".into()),
            ("audience_hash", |c| {
                c.mcp_re_audience_hash = "aud-scope-2".into()
            }),
            ("server_signer", |c| {
                c.mcp_re_server_signer = "server:elsewhere".into()
            }),
            ("key_use", |c| c.mcp_re_key_use = "request-signing".into()),
            ("issuer_kid", |c| c.issuer_kid = "another-root".into()),
            ("trust_epoch", |c| c.trust_epoch = "epoch-2".into()),
        ];
        for (name, mutate) in mutations {
            let mut returned = request.clone();
            mutate(&mut returned);
            assert!(
                offer(&key, &request, &header, &returned).is_err(),
                "a credential differing in `{name}` was accepted"
            );
        }
    }

    /// The header is part of what was asked for: a credential minted under another
    /// algorithm or naming another root is not this issuance's answer.
    #[test]
    fn a_header_the_root_did_not_echo_is_refused() {
        let key = delegated();
        let (header, request, server_signer) = requested(&key);
        let mut other_header = header.clone();
        other_header.kid = "another-root".into();
        let credential = issue_delegation_credential(&root(), &other_header, &request);
        assert!(ActiveDelegatedKey::issued(
            Arc::new(delegated()),
            server_signer,
            (&header, &request),
            credential,
        )
        .is_err());
    }

    /// An empty or inverted window is not a narrower credential; it is an incoherent one,
    /// and `exp` is what the whole fail-closed path is decided on.
    #[test]
    fn a_window_that_is_not_a_window_is_refused() {
        let key = delegated();
        let (header, request, _) = requested(&key);
        for exp in [NBF, NBF - 1] {
            let mut returned = request.clone();
            returned.exp = exp;
            assert!(
                offer(&key, &request, &header, &returned).is_err(),
                "nbf={NBF} exp={exp} was accepted as a window"
            );
        }
    }

    /// Bytes that are not a credential at all.
    #[test]
    fn an_unreadable_credential_publishes_nothing() {
        let key = delegated();
        let (header, request, server_signer) = requested(&key);
        for bad in ["", "cred", "a.b", "a.b.c", "....."] {
            assert!(
                ActiveDelegatedKey::issued(
                    Arc::new(delegated()),
                    server_signer.clone(),
                    (&header, &request),
                    bad.to_owned(),
                )
                .is_err(),
                "{bad:?} was accepted as a credential"
            );
        }
    }
}
