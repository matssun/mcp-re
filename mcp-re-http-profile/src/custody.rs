// SPDX-License-Identifier: Apache-2.0
//! Delegated-signing custody state machine (ADR-MCPRE-051 §5, ADR-MCPRE-052 §4/§6,
//! MCPRE-122).
//!
//! The root/identity key stays in the HSM/KMS and is touched **only** at issuance
//! and rotation (never per request). It mints short-TTL in-memory Ed25519
//! **delegated** keys, each bound by a root-signed credential; per-request response
//! signing uses the current in-memory delegated key (microseconds). This is the
//! load-bearing property: **KMS/HSM is never on the hot path.**
//!
//! This state machine is pure and clock-injected (`now` is a parameter): it does
//! no I/O, holds no timer, and generates no randomness itself — the root issuer and
//! the delegated-key factory are injected, so the production wiring supplies a KMS
//! issuer + an OS-RNG key factory while tests supply deterministic ones. The KMS is
//! thus a *swap of the injected issuer*, not a code fork.
//!
//! Guarantees (proven by the tests below):
//! - **Zero root ops on the hot path**: signing N responses within one key's life
//!   invokes the root issuer 0 times.
//! - **Rotation overlap, no gap**: a successor is minted at `exp − O` while the
//!   predecessor is still valid; signing never gaps.
//! - **Fail-closed issuance**: if the root cannot issue and the current key has
//!   expired, signing STOPS (fail-closed) rather than extend a stale key.
//! - **Audited lifecycle**: every issue / rotate / retire is a
//!   `mcp-re.delegated_key.*` event (the frozen ADR-052 §7 vocabulary).

use std::sync::Arc;

use mcp_re_core::audit::event_type;
use mcp_re_core::SigningKey;

use crate::block::ActorIdentity;
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
use crate::error::HttpProfileError;
use crate::evidence::RequestEvidence;
use crate::message::HttpRequest;
use crate::message::HttpResponse;
use crate::sign::sign_delegated_response_full;

/// A failure of the custody layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustodyError {
    /// The root could not issue/rotate and the current delegated key has expired:
    /// signing STOPS (ADR-MCPRE-052 §6). Fail-closed, never extend a stale key.
    FailClosedIssuance,
    /// The response-signing step itself failed (evidence assembly / signing).
    Sign(HttpProfileError),
}

/// One audited key-lifecycle event (ADR-MCPRE-052 §7). Carries no key material and
/// no nonce/correlation data (ADR-MCPS-020 startup-line discipline).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyLifecycleEvent {
    /// One of the frozen `mcp-re.delegated_key.*` tokens.
    pub event_type: &'static str,
    pub delegated_kid: String,
    pub issuer_kid: String,
    pub nbf: i64,
    pub exp: i64,
    pub jti: String,
    /// Event timestamp (the injected `now`).
    pub at: i64,
}

/// Static custody policy (the parts of the credential that do not change per key).
pub struct CustodyConfig {
    /// The root `issuer_kid` the credential chains to.
    pub issuer_kid: String,
    /// The issuer identity string (`iss`).
    pub iss: String,
    /// The active HTTP profile id.
    pub profile: String,
    /// The credential audience (`aud`): who may process the credential.
    pub aud: String,
    /// The service/audience-scope hash the delegated key is scoped to.
    pub audience_hash: String,
    /// The current trust epoch minted into each credential.
    pub trust_epoch: String,
    /// The server-signer identity template — `role` / `trust_domain` / `subject`
    /// are fixed; `keyid` is set to each delegated key's id.
    pub server_role: String,
    pub server_trust_domain: String,
    pub server_subject: String,
    /// Delegated-key TTL `T` and rotation-overlap window `O` (0 < O < T), seconds.
    pub ttl: i64,
    pub overlap: i64,
}

/// The currently-active delegated key and its credential. `key` is an `Arc`
/// because a delegated `SigningKey` is deliberately not `Clone`, and the hot-path
/// signer needs a shared handle to sign off ([`DelegatedSigningCustody::active_snapshot`]).
struct ActiveKey {
    key: Arc<SigningKey>,
    delegated_kid: String,
    server_signer: ActorIdentity,
    credential: String,
    nbf: i64,
    exp: i64,
}

/// An owned, cheaply-cloned snapshot of the current delegated key + its root-signed
/// credential (ADR-MCPRE-052 §4). A hot-path response signer publishes this and
/// signs per request off it — the root is never touched on that path; issuance and
/// rotation stay inside the custody state machine. `key` is shared (`Arc`) because
/// the delegated `SigningKey` is intentionally non-`Clone`.
#[derive(Clone)]
pub struct ActiveDelegatedKey {
    /// The in-memory delegated Ed25519 signing key (shared, never the root).
    pub key: Arc<SigningKey>,
    /// The delegated key id — the RFC 9421 `keyid` the response signs under, and
    /// the block's `server_signer.keyid`.
    pub delegated_kid: String,
    /// The server-signer identity naming this delegated key.
    pub server_signer: ActorIdentity,
    /// The inline root-signed delegation credential (compact JWS).
    pub credential: String,
    /// Credential not-before / expiry (`exp` is the fail-closed bound: a signer
    /// MUST stop signing off this snapshot once `now >= exp`).
    pub nbf: i64,
    pub exp: i64,
}

/// The delegated-signing custody state machine.
///
/// `Issue` is the root issuer (KMS/HSM in production): given a header+claims it
/// returns the compact JWS credential, or `None` when the root is unavailable.
/// `Factory` yields a fresh in-memory delegated signing key.
pub struct DelegatedSigningCustody<Issue, Factory> {
    cfg: CustodyConfig,
    issue: Issue,
    factory: Factory,
    active: Option<ActiveKey>,
    audit: Vec<KeyLifecycleEvent>,
    root_invocations: u64,
    counter: u64,
}

impl<Issue, Factory> DelegatedSigningCustody<Issue, Factory>
where
    Issue: FnMut(&DelegationHeader, &DelegationClaims) -> Option<String>,
    Factory: FnMut() -> SigningKey,
{
    /// Build a custody state machine. No key is issued until the first
    /// [`sign_response`](Self::sign_response) or [`ensure_active`](Self::ensure_active).
    pub fn new(cfg: CustodyConfig, issue: Issue, factory: Factory) -> Self {
        Self {
            cfg,
            issue,
            factory,
            active: None,
            audit: Vec::new(),
            root_invocations: 0,
            counter: 0,
        }
    }

    /// The audited lifecycle events so far.
    pub fn audit(&self) -> &[KeyLifecycleEvent] {
        &self.audit
    }

    /// How many times the ROOT issuer was invoked (issuance + rotation only). A
    /// per-request signing path must never increase this.
    pub fn root_invocations(&self) -> u64 {
        self.root_invocations
    }

    /// The current delegated key id, if a key is active.
    pub fn active_kid(&self) -> Option<&str> {
        self.active.as_ref().map(|a| a.delegated_kid.as_str())
    }

    /// Ensure a usable delegated key exists at `now`, issuing or rotating as
    /// needed. Fail-closed if the root cannot issue and the current key has
    /// expired (ADR-MCPRE-052 §6).
    pub fn ensure_active(&mut self, now: i64) -> Result<(), CustodyError> {
        let needs = match &self.active {
            None => true,
            // Rotate once we enter the overlap window before expiry, or if expired.
            Some(a) => now >= a.exp - self.cfg.overlap,
        };
        if needs {
            let is_rotation = self
                .active
                .as_ref()
                .map(|a| now < a.exp)
                .unwrap_or(false);

            let key = (self.factory)();
            self.counter += 1;
            let (kid, signer, header, claims) = self.build(now, &key);
            self.root_invocations += 1;
            match (self.issue)(&header, &claims) {
                Some(credential) => {
                    self.audit.push(KeyLifecycleEvent {
                        event_type: if is_rotation {
                            event_type::DELEGATED_KEY_ROTATED
                        } else {
                            event_type::DELEGATED_KEY_ISSUED
                        },
                        delegated_kid: kid.clone(),
                        issuer_kid: self.cfg.issuer_kid.clone(),
                        nbf: claims.nbf,
                        exp: claims.exp,
                        jti: claims.jti.clone(),
                        at: now,
                    });
                    self.active = Some(ActiveKey {
                        key: Arc::new(key),
                        delegated_kid: kid,
                        server_signer: signer,
                        credential,
                        nbf: claims.nbf,
                        exp: claims.exp,
                    });
                }
                None => {
                    // Issuance failed. If the current key is still valid we keep
                    // signing with it and retry the successor later (no gap yet).
                    let current_valid = self.active.as_ref().map(|a| now < a.exp).unwrap_or(false);
                    if !current_valid {
                        // The current key (if any) has expired: retire it and stop.
                        if let Some(a) = self.active.take() {
                            self.audit.push(KeyLifecycleEvent {
                                event_type: event_type::DELEGATED_KEY_RETIRED,
                                delegated_kid: a.delegated_kid,
                                issuer_kid: self.cfg.issuer_kid.clone(),
                                nbf: a.nbf,
                                exp: a.exp,
                                jti: String::new(),
                                at: now,
                            });
                        }
                        return Err(CustodyError::FailClosedIssuance);
                    }
                }
            }
        }
        match &self.active {
            Some(a) if now < a.exp => Ok(()),
            _ => Err(CustodyError::FailClosedIssuance),
        }
    }

    /// Sign `response` with the current delegated key, issuing/rotating as needed.
    /// The root is NOT touched here unless a rotation is due.
    pub fn sign_response(
        &mut self,
        now: i64,
        response: &mut HttpResponse,
        request: &HttpRequest,
        request_evidence: &RequestEvidence,
    ) -> Result<(), CustodyError> {
        self.ensure_active(now)?;
        let a = self.active.as_ref().expect("ensure_active guarantees a key");
        sign_delegated_response_full(
            response,
            request,
            request_evidence,
            &a.server_signer,
            &a.credential,
            a.key.as_ref(),
            &a.delegated_kid,
            now,
            now + self.cfg.ttl,
        )
        .map_err(CustodyError::Sign)
    }

    /// An owned snapshot of the current delegated key + credential (`None` before
    /// first issuance or after fail-closed retirement). A hot-path signer publishes
    /// this and signs off it without touching the root (ADR-MCPRE-052 §4).
    pub fn active_snapshot(&self) -> Option<ActiveDelegatedKey> {
        self.active.as_ref().map(|a| ActiveDelegatedKey {
            key: Arc::clone(&a.key),
            delegated_kid: a.delegated_kid.clone(),
            server_signer: a.server_signer.clone(),
            credential: a.credential.clone(),
            nbf: a.nbf,
            exp: a.exp,
        })
    }

    /// Build the (delegated_kid, server_signer, header, claims) for a fresh key.
    fn build(
        &self,
        now: i64,
        key: &SigningKey,
    ) -> (String, ActorIdentity, DelegationHeader, DelegationClaims) {
        let delegated_kid = format!("{}/delegated/{}", self.cfg.issuer_kid, self.counter);
        let server_signer = ActorIdentity {
            role: self.cfg.server_role.clone(),
            trust_domain: self.cfg.server_trust_domain.clone(),
            subject: self.cfg.server_subject.clone(),
            keyid: delegated_kid.clone(),
        };
        let header = DelegationHeader {
            typ: DELEGATION_TYP.to_owned(),
            alg: DELEGATION_ALG.to_owned(),
            kid: self.cfg.issuer_kid.clone(),
        };
        let claims = DelegationClaims {
            iss: self.cfg.iss.clone(),
            iat: now,
            nbf: now,
            exp: now + self.cfg.ttl,
            jti: format!("{}#{}", self.cfg.issuer_kid, self.counter),
            aud: Audience::One(self.cfg.aud.clone()),
            mcp_re_profile: self.cfg.profile.clone(),
            mcp_re_audience_hash: self.cfg.audience_hash.clone(),
            mcp_re_server_signer: server_signer.actor_id(),
            mcp_re_key_use: KEY_USE_RESPONSE_SIGNING.to_owned(),
            delegated_kid: delegated_kid.clone(),
            issuer_kid: self.cfg.issuer_kid.clone(),
            trust_epoch: self.cfg.trust_epoch.clone(),
            cnf: Cnf {
                jwk: DelegatedJwk {
                    kty: JWK_KTY_OKP.to_owned(),
                    crv: JWK_CRV_ED25519.to_owned(),
                    kid: delegated_kid.clone(),
                    x: key.public_key().to_b64url(),
                },
            },
        };
        (delegated_kid, server_signer, header, claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegation::issue_delegation_credential;

    const ROOT_KID: &str = "root-kid";
    const T: i64 = 300;
    const O: i64 = 60;

    fn cfg() -> CustodyConfig {
        CustodyConfig {
            issuer_kid: ROOT_KID.into(),
            iss: "did:example:server".into(),
            profile: "mcp-re-http-v1".into(),
            aud: "verifier-1".into(),
            audience_hash: "aud-scope-1".into(),
            trust_epoch: "epoch-1".into(),
            server_role: "server".into(),
            server_trust_domain: "example.com".into(),
            server_subject: "did:example:server".into(),
            ttl: T,
            overlap: O,
        }
    }

    /// A software root issuer over a fixed key (stands in for the KMS/HSM).
    fn ok_issuer() -> impl FnMut(&DelegationHeader, &DelegationClaims) -> Option<String> {
        let root = SigningKey::from_seed_bytes(&[33u8; 32]);
        move |h: &DelegationHeader, c: &DelegationClaims| Some(issue_delegation_credential(&root, h, c))
    }

    /// A deterministic delegated-key factory (distinct key per call).
    fn factory() -> impl FnMut() -> SigningKey {
        let mut n = 100u8;
        move || {
            n = n.wrapping_add(1);
            SigningKey::from_seed_bytes(&[n; 32])
        }
    }

    /// Zero root ops on the hot path: many signs within one key's life ⇒ the root
    /// issuer is invoked exactly once (the initial issuance).
    #[test]
    fn signing_never_touches_the_root_within_a_key_life() {
        let mut c = DelegatedSigningCustody::new(cfg(), ok_issuer(), factory());
        c.ensure_active(1_000).expect("issue");
        assert_eq!(c.root_invocations(), 1);
        // 50 signs well within [1_000, 1_000 + T - O) — no rotation.
        for i in 0..50 {
            c.ensure_active(1_000 + i).expect("still active");
        }
        assert_eq!(c.root_invocations(), 1, "the hot path must not touch the root");
        assert_eq!(c.audit().len(), 1);
        assert_eq!(c.audit()[0].event_type, "mcp-re.delegated_key.issued");
    }

    /// Rotation overlap: crossing `exp − O` mints a successor (a `rotated` event)
    /// while the predecessor is still valid — no gap.
    #[test]
    fn rotation_mints_successor_in_the_overlap_window() {
        let mut c = DelegatedSigningCustody::new(cfg(), ok_issuer(), factory());
        c.ensure_active(1_000).expect("issue");
        let first = c.active_kid().unwrap().to_string();
        // Predecessor exp = 1_300; overlap opens at 1_240.
        c.ensure_active(1_250).expect("rotate");
        let second = c.active_kid().unwrap().to_string();
        assert_ne!(first, second, "a successor key is active");
        assert_eq!(c.root_invocations(), 2);
        let kinds: Vec<_> = c.audit().iter().map(|e| e.event_type).collect();
        assert_eq!(
            kinds,
            vec!["mcp-re.delegated_key.issued", "mcp-re.delegated_key.rotated"]
        );
    }

    /// Continuity: stepping the clock across several key lifetimes always yields a
    /// usable key while issuance succeeds — no signing gap.
    #[test]
    fn continuous_availability_across_rotations() {
        let mut c = DelegatedSigningCustody::new(cfg(), ok_issuer(), factory());
        for now in (1_000..1_000 + 3 * T).step_by(30) {
            c.ensure_active(now)
                .unwrap_or_else(|e| panic!("gap at {now}: {e:?}"));
        }
        assert!(c.root_invocations() >= 3, "multiple rotations occurred");
    }

    /// Fail-closed: once the root cannot issue and the current key expires, signing
    /// STOPS (fail-closed), and the expired key is retired in the audit trail.
    #[test]
    fn fail_closed_when_issuance_fails_after_expiry() {
        // Issuer succeeds once, then fails forever after.
        let root = SigningKey::from_seed_bytes(&[33u8; 32]);
        let mut calls = 0u32;
        let issuer = move |h: &DelegationHeader, cl: &DelegationClaims| {
            calls += 1;
            if calls == 1 {
                Some(issue_delegation_credential(&root, h, cl))
            } else {
                None
            }
        };
        let mut c = DelegatedSigningCustody::new(cfg(), issuer, factory());
        c.ensure_active(1_000).expect("first issue ok");
        // Before expiry, a failed successor is tolerated (current key still valid).
        assert!(c.ensure_active(1_250).is_ok());
        // Past the current key's exp (1_300) with issuance failing ⇒ fail-closed.
        assert_eq!(
            c.ensure_active(1_400).unwrap_err(),
            CustodyError::FailClosedIssuance
        );
        assert!(c.active_kid().is_none(), "no key remains active");
        assert!(
            c.audit()
                .iter()
                .any(|e| e.event_type == "mcp-re.delegated_key.retired"),
            "the expired key is retired in the audit trail"
        );
    }
}
