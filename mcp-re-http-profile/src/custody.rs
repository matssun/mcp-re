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

use crate::keyid::jwk_thumbprint_ed25519;

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
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// How many issuance attempts one rotation-overlap window may spend on a root that
/// is declining. The overlap window is the budget the rotation contract already
/// allocates to getting a successor minted, so the retry interval is derived from it
/// rather than configured separately.
const ISSUANCE_ATTEMPTS_PER_OVERLAP: i64 = 10;

/// Floor on the retry interval, for a configuration whose overlap window is smaller
/// than the attempt budget (and for a non-positive overlap).
const MIN_ISSUANCE_RETRY_SECS: i64 = 1;

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
    /// The earliest `now` at which a scheduled issuance may touch the root again.
    /// `None` while nothing has failed.
    next_attempt_at: Option<i64>,
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
            next_attempt_at: None,
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

    /// The trust epoch currently minted into new credentials.
    pub fn trust_epoch(&self) -> &str {
        &self.cfg.trust_epoch
    }

    /// Update the trust epoch minted into SUBSEQUENT credentials (ADR-MCPRE-052 §7:
    /// advancing the shared trust epoch invalidates the outstanding epoch of delegated
    /// keys across the fleet). This does NOT re-issue on its own — the caller pairs it
    /// with [`reissue`](Self::reissue) so the fleet swaps to the new epoch at once.
    pub fn set_trust_epoch(&mut self, epoch: String) {
        self.cfg.trust_epoch = epoch;
    }

    /// Force an immediate issuance under the CURRENT config, regardless of the
    /// rotation-overlap window — the epoch-advance path (a sibling bumped the shared
    /// trust epoch), so the node swaps to the new epoch within the bounded poll window
    /// rather than waiting for the next scheduled rotation.
    ///
    /// **The successor is minted BEFORE the predecessor is dropped.** Clearing
    /// `active` first and only then attempting issuance meant a transient root blip at
    /// exactly that instant left the node with no signing key at all — every response
    /// failing `delegated_signing_unavailable` until the root came back — which is the
    /// opposite of the rotation contract, where a failed issuance keeps serving the
    /// still-valid key until its own `exp`. An epoch advance is a scheduled event; a
    /// root blip is not, and the two must not compose into an outage.
    ///
    /// The predecessor is superseded, so once the successor exists it is retired
    /// immediately rather than kept for an overlap window: it was minted under an epoch
    /// verifiers have stopped accepting.
    pub fn reissue(&mut self, now: i64) -> Result<(), CustodyError> {
        // RETIRE the predecessor explicitly. `self.active = None` dropped it silently,
        // which broke the §7 contract this module states at the top — "every issue /
        // rotate / retire is a `mcp-re.delegated_key.*` event". The one site that emits
        // a retire is guarded on `self.active.take()`, so clearing the field first made
        // that branch unreachable, and an operator auditing the key lifecycle saw a key
        // appear with no record of the one it displaced. It also made `is_rotation`
        // false, so the successor was labelled `issued` rather than `rotated`.
        let previous_kid = self.active.as_ref().map(|a| a.delegated_kid.clone());
        // Mint first. `issue_now` does not consult the overlap window, so this is an
        // unconditional issuance attempt; a failure leaves `active` untouched and the
        // node keeps serving on the superseded key until its own `exp` — bounded,
        // and strictly better than no key at all.
        self.issue_now(now)?;
        // Success: the predecessor is gone from `active` (replaced), so record its
        // retirement. Matched by kid so a failed attempt above cannot log one.
        if let Some(kid) = previous_kid {
            if self.active.as_ref().is_some_and(|a| a.delegated_kid != kid) {
                self.audit.push(KeyLifecycleEvent {
                    event_type: event_type::DELEGATED_KEY_RETIRED,
                    delegated_kid: kid,
                    issuer_kid: self.cfg.issuer_kid.clone(),
                    nbf: 0,
                    exp: now,
                    jti: String::new(),
                    at: now,
                });
            }
        }
        Ok(())
    }

    /// Ensure a usable delegated key exists at `now`, issuing or rotating as
    /// needed. Fail-closed if the root cannot issue and the current key has
    /// expired (ADR-MCPRE-052 §6).
    pub fn ensure_active(&mut self, now: i64) -> Result<(), CustodyError> {
        let needs = match &self.active {
            None => true,
            // Rotate once we enter the overlap window before expiry, or if expired. The
            // threshold is computed with `checked_sub` because `CustodyConfig` carries
            // `ttl`/`overlap` as bare `i64` fields: the `0 < overlap < ttl` guard that
            // bounds them belongs to the proxy's configuration owner and does not reach
            // this type, so an embedder — or any construction site that is not that owner
            // — can present an overlap this subtraction cannot take. Wrapping would put
            // the threshold far in the future and answer `false`, which is the PERMISSIVE
            // direction: the key would be kept in service past the window it was supposed
            // to be replaced in. A threshold that cannot be computed is therefore read as
            // one that has been reached.
            Some(a) => a
                .exp
                .checked_sub(self.cfg.overlap)
                .is_none_or(|at| now >= at),
        };
        self.issue_if(needs, now)
    }

    /// Issue unconditionally, whatever the overlap window says — the epoch-advance
    /// path. Shares [`ensure_active`]'s issuance body so the two cannot drift.
    ///
    /// A commanded issuance also clears the failed-attempt gate: the gate exists to
    /// keep the SCHEDULED path from turning a root outage into per-request root
    /// traffic, and an operator advancing the trust epoch is asking for exactly one
    /// attempt, now.
    fn issue_now(&mut self, now: i64) -> Result<(), CustodyError> {
        self.next_attempt_at = None;
        self.issue_if(true, now)
    }

    /// Minimum seconds between two issuance attempts after one has failed.
    fn retry_interval(&self) -> i64 {
        (self.cfg.overlap / ISSUANCE_ATTEMPTS_PER_OVERLAP).max(MIN_ISSUANCE_RETRY_SECS)
    }

    /// Whether a failed root may be approached again at `now`.
    ///
    /// Inside the rotation-overlap window `ensure_active` wants a successor on EVERY
    /// call, so an ungated retry makes each inbound request one root invocation —
    /// precisely while the root is already degraded, and precisely the hot-path root
    /// traffic the delegated-signing design exists to forbid. The window still gets
    /// [`ISSUANCE_ATTEMPTS_PER_OVERLAP`] attempts, so a transient blip is still
    /// recovered from well before the predecessor expires.
    fn attempt_allowed(&self, now: i64) -> bool {
        self.next_attempt_at.is_none_or(|at| now >= at)
    }

    /// The two values an issuance cannot proceed without: the credential's expiry, and the
    /// ordinal that will name it.
    ///
    /// Decided BEFORE a key is generated, an ordinal is spent or the root is approached,
    /// because either being unrepresentable is a reason this issuance cannot produce a
    /// valid credential at all.
    ///
    /// The expiry, for the reason [`Self::ensure_active`] states: `ttl` is an unbounded
    /// `i64` on `CustodyConfig`, whose `0 < overlap < ttl` guard belongs to the proxy's
    /// configuration owner and does not reach this type. A wrapped `exp` would be minted
    /// into the credential and into the audit event describing it, and every `now < exp`
    /// test downstream would read the wrapped value.
    ///
    /// The ordinal, because `jti` is a REVOCATION identifier and this counter is the part
    /// of it that distinguishes two credentials minted over the same key material. A
    /// wrapped counter re-issues a `jti` that has already named a different credential, so
    /// revoking one would revoke the other.
    fn mintable_at(&self, now: i64) -> Result<(i64, u64), CustodyError> {
        now.checked_add(self.cfg.ttl)
            .zip(self.counter.checked_add(1))
            .ok_or(CustodyError::FailClosedIssuance)
    }

    fn issue_if(&mut self, needs: bool, now: i64) -> Result<(), CustodyError> {
        if needs && self.attempt_allowed(now) {
            let is_rotation = self.active.as_ref().map(|a| now < a.exp).unwrap_or(false);

            let (exp, next_counter) = self.mintable_at(now)?;
            let key = (self.factory)();
            self.counter = next_counter;
            let (kid, signer, header, claims) = self.build(now, exp, &key);
            // The root invocation count is a metric an operator reads, not a value any
            // decision is taken on, so saturation at the ceiling is the honest algebra:
            // the count stops being exact rather than the process stopping.
            self.root_invocations = self.root_invocations.saturating_add(1);
            match (self.issue)(&header, &claims) {
                Some(credential) => {
                    self.next_attempt_at = None;
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
                    // Issuance failed. Hold off the next attempt so a root outage
                    // cannot be amplified into one root call per inbound request.
                    // Saturating IS the rule here: this value only ever delays the next
                    // approach to a root that is already failing, so the far future is the
                    // restrictive end. Wrapping would land in the past and re-open exactly
                    // the per-request root traffic this line exists to prevent.
                    self.next_attempt_at = Some(now.saturating_add(self.retry_interval()));
                    // If the current key is still valid we keep signing with it and
                    // retry the successor later (no gap yet).
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
    ///
    /// The RFC 9421 `expires` is clamped to the credential's own `exp`. `exp` is the
    /// fail-closed bound — a signer MUST stop signing off this snapshot once
    /// `now >= exp` — so a signature whose stated validity outlives it would advertise
    /// a freshness window longer than the credential authorizing the key that made it.
    /// Near the end of a credential's life `now + ttl` crosses that bound, which is
    /// exactly when it matters.
    pub fn sign_response(
        &mut self,
        now: i64,
        response: &mut HttpResponse,
        request: &HttpRequest,
        request_evidence: &RequestEvidence,
    ) -> Result<(), CustodyError> {
        self.ensure_active(now)?;
        // `ensure_active` returns `Ok` only through the arm that matched `Some(a)` with
        // `now < a.exp`, so this holds. It is written as a refusal rather than asserted,
        // because the consequence of that guarantee lapsing should be one unsigned
        // response and not a downed process — and because `FailClosedIssuance` is already
        // the verdict this module gives for "no key to sign with".
        let Some(a) = self.active.as_ref() else {
            return Err(CustodyError::FailClosedIssuance);
        };
        sign_delegated_response_full(
            response,
            request,
            request_evidence,
            &a.server_signer,
            &a.credential,
            a.key.as_ref(),
            &a.delegated_kid,
            now,
            // The signature's stated validity, clamped to the credential's own `exp` —
            // and to it alone when `now + ttl` leaves `i64`, which is the same clamp
            // taken at its restrictive end rather than a wrapped window.
            now.checked_add(self.cfg.ttl)
                .map_or(a.exp, |until| until.min(a.exp)),
        )
        .map(|_base| ())
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
    /// `exp` is decided by the caller, not recomputed here: it is the value whose
    /// representability made the issuance legal in the first place.
    fn build(
        &self,
        now: i64,
        exp: i64,
        key: &SigningKey,
    ) -> (String, ActorIdentity, DelegationHeader, DelegationClaims) {
        // The delegated key is profile-issued, so its kid is the RFC 7638 JWK
        // thumbprint of the key itself (#415 rev 2 §1.5) — self-describing and
        // collision-resistant, rather than a counter only this issuer can
        // interpret. It remains a SELECTOR: the credential chain, not the kid,
        // is what authorizes the key.
        let public_key_b64url = key.public_key().to_b64url();
        let delegated_kid = jwk_thumbprint_ed25519(&public_key_b64url);
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
            exp,
            // The credential id is a REVOCATION identifier: a verifier's
            // `RevocationSource` is consulted with it, so two distinct credentials
            // sharing one `jti` cannot be revoked independently. It must therefore be
            // unique across the whole fleet and across restarts — the same property the
            // comment above claims for `delegated_kid`, and the reason a bare counter is
            // wrong here. Every replica runs the same `issuer_kid` and starts its counter
            // at 0, so `issuer_kid#1` named a different credential on every replica and
            // again after every restart: revoking one revoked all of them, and a
            // just-issued credential could be born already on a denylist.
            //
            // `delegated_kid` is the RFC 7638 thumbprint of a freshly generated key, so
            // it carries the fleet-wide uniqueness. The counter stays as a within-process
            // issuance ordinal, which distinguishes two credentials minted over the SAME
            // key material (a re-issuance under an advanced trust epoch) rather than
            // relying on `iat` to differ.
            jti: format!("{}#{}#{}", self.cfg.issuer_kid, delegated_kid, self.counter),
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
                    x: public_key_b64url,
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
    use crate::delegation::verify_delegation_credential;
    use crate::delegation::DelegationVerifyParams;
    use crate::delegation::VerifiedDelegation;
    use mcp_re_core::VerificationKey;

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
        move |h: &DelegationHeader, c: &DelegationClaims| {
            Some(issue_delegation_credential(&root, h, c))
        }
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
        assert_eq!(
            c.root_invocations(),
            1,
            "the hot path must not touch the root"
        );
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
            vec![
                "mcp-re.delegated_key.issued",
                "mcp-re.delegated_key.rotated"
            ]
        );
    }

    /// C034: the credential `jti` is a REVOCATION identifier, so two distinct
    /// credentials must never share one. Every replica in a fleet runs the SAME
    /// `issuer_kid` and starts its counter at 0, so a bare `issuer_kid#N` named a
    /// different credential on each replica and again after each restart.
    #[test]
    fn two_replicas_never_mint_the_same_credential_id() {
        // Two independently-started custody instances — a fleet, or one replica before
        // and after a restart. Same config, same issuer, both from a cold counter.
        let mut replica_a = DelegatedSigningCustody::new(cfg(), ok_issuer(), factory_seeded(10));
        let mut replica_b = DelegatedSigningCustody::new(cfg(), ok_issuer(), factory_seeded(200));
        replica_a.ensure_active(1_000).expect("A issues");
        replica_b.ensure_active(1_000).expect("B issues");

        let jti_a = &replica_a.audit()[0].jti;
        let jti_b = &replica_b.audit()[0].jti;
        assert_ne!(
            jti_a, jti_b,
            "two replicas must not name their first credential identically, or revoking \
             one revokes both and a fresh key can be born already revoked"
        );
        // And the id names the KEY, so it is derivable from what a verifier already sees.
        assert!(
            jti_a.contains(replica_a.active_kid().expect("A has a key")),
            "the credential id carries the delegated kid that makes it fleet-unique"
        );
    }

    /// Successive issuances within ONE process must also stay distinct — including a
    /// re-issuance that mints over the same instant.
    ///
    /// Also pins the ORDER, which is the epoch-advance safety property: mint, then
    /// retire. Retiring first meant a transient root failure at that instant left the
    /// node with no signing key at all.
    #[test]
    fn successive_issuances_in_one_process_have_distinct_credential_ids() {
        let mut c = DelegatedSigningCustody::new(cfg(), ok_issuer(), factory());
        c.ensure_active(1_000).expect("issue");
        c.reissue(1_000).expect("re-issue at the SAME instant");
        // issued, ROTATED (the successor is minted while the predecessor is still
        // valid — that is what keeps a root blip from leaving the node with no key at
        // all), then RETIRED for the key the advance superseded. The retire is the §7
        // event `reissue` used to skip entirely by clearing `active` first.
        let events: Vec<&'static str> = c.audit().iter().map(|e| e.event_type).collect();
        assert_eq!(
            events,
            vec![
                event_type::DELEGATED_KEY_ISSUED,
                event_type::DELEGATED_KEY_ROTATED,
                event_type::DELEGATED_KEY_RETIRED,
            ],
            "every issue / rotate / retire is an event — including the displaced key"
        );
        let ids: Vec<&String> = c
            .audit()
            .iter()
            .filter(|e| e.event_type != event_type::DELEGATED_KEY_RETIRED)
            .map(|e| &e.jti)
            .collect();
        assert_eq!(ids.len(), 2);
        assert_ne!(
            ids[0], ids[1],
            "a same-instant re-issuance still gets its own id"
        );
    }

    /// A factory that hands out distinct keys from a caller-chosen seed base, so two
    /// instances in one test can be given genuinely different key material (as two real
    /// replicas would generate).
    fn factory_seeded(base: u8) -> impl FnMut() -> SigningKey {
        let mut n = base;
        move || {
            n = n.wrapping_add(1);
            SigningKey::from_seed_bytes(&[n; 32])
        }
    }

    /// Trust-epoch advance (ADR-MCPRE-052 §7): setting a new epoch and re-issuing
    /// mints a FRESH delegated key under the NEW epoch, off-schedule (not waiting for
    /// the overlap window). This is what lets a shared-counter bump revoke the
    /// outstanding epoch across the fleet — verifiers pinned to the old epoch then
    /// reject the new credential as `delegation_trust_epoch_stale`.
    #[test]
    fn reissue_under_advanced_trust_epoch_mints_a_fresh_key() {
        let mut c = DelegatedSigningCustody::new(cfg(), ok_issuer(), factory());
        c.ensure_active(1_000).expect("issue");
        let base_epoch = c.trust_epoch().to_string();
        let first_kid = c.active_kid().unwrap().to_string();
        assert_eq!(c.root_invocations(), 1);

        // Operator bumped the shared trust epoch: advance + re-issue WELL INSIDE the
        // current key's life (no scheduled rotation would fire here).
        c.set_trust_epoch(format!("{base_epoch}#1"));
        c.reissue(1_010).expect("reissue under the new epoch");

        assert_eq!(c.trust_epoch(), format!("{base_epoch}#1"));
        let second_kid = c.active_kid().unwrap().to_string();
        assert_ne!(first_kid, second_kid, "a fresh delegated key was minted");
        assert_eq!(
            c.root_invocations(),
            2,
            "the root re-issued exactly once more"
        );
        // The prior key was dropped, not kept alongside — the old epoch stops serving.
        assert!(c.active_snapshot().is_some());
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
    /// The signature `expires` is clamped to the credential's own `exp`.
    ///
    /// `exp` is the fail-closed bound — a signer MUST stop signing off this snapshot
    /// once `now >= exp` — so an unclamped `now + ttl` advertises a validity window
    /// outliving the credential that authorizes the key. It is not an edge case: a key
    /// issued at `t0` has `exp = t0 + ttl`, so EVERY signature after `t0` overran it.
    /// The production serving path already clamps; this is the same contract on the
    /// crate's own public signer.
    #[test]
    fn the_signature_expiry_never_outlives_the_credential() {
        let mut c = DelegatedSigningCustody::new(cfg(), ok_issuer(), factory());
        c.ensure_active(1_000).expect("issue");
        let exp = c.active_snapshot().expect("active").exp;
        assert_eq!(exp, 1_000 + T, "issued at 1_000 for one TTL");

        let now = 1_100;
        assert!(
            now + T > exp,
            "the unclamped window really would overrun: {} > {exp}",
            now + T
        );

        let mut request = HttpRequest {
            method: "POST".into(),
            target_uri: "https://mcp.example.com/mcp".into(),
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#.to_vec(),
        };
        let evidence = crate::sign::sign_request(
            &mut request,
            &SigningKey::from_seed_bytes(&[77u8; 32]),
            "client-key-1",
            now,
            now + 60,
            "n-clamp",
        )
        .expect("request signs");

        let mut response = crate::message::HttpResponse {
            status: 200,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec(),
        };
        c.sign_response(now, &mut response, &request, &evidence)
            .expect("response signs");

        let input = response
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("signature-input"))
            .map(|(_, v)| v.clone())
            .expect("the signer emitted signature-input");
        let emitted: i64 = input
            .split(";expires=")
            .nth(1)
            .and_then(|rest| rest.split(';').next())
            .and_then(|n| n.parse().ok())
            .expect("expires is present and an integer");
        assert_eq!(
            emitted, exp,
            "the window must stop at the credential's exp, not at now + ttl ({input})"
        );
    }

    /// A root issuer that succeeds `successes` times and declines forever after —
    /// a KMS/HSM that goes away mid-life.
    fn issuer_failing_after(
        successes: u32,
    ) -> impl FnMut(&DelegationHeader, &DelegationClaims) -> Option<String> {
        let root = SigningKey::from_seed_bytes(&[33u8; 32]);
        let mut calls = 0u32;
        move |h: &DelegationHeader, c: &DelegationClaims| {
            calls += 1;
            (calls <= successes).then(|| issue_delegation_credential(&root, h, c))
        }
    }

    /// A failing root is approached on a bounded interval, not once per inbound
    /// request. Inside the overlap window `ensure_active` wants a successor on every
    /// call, so an ungated retry converts a root blip into a per-request root storm.
    #[test]
    fn a_failing_root_is_retried_on_a_bounded_interval_not_once_per_request() {
        let mut c = DelegatedSigningCustody::new(cfg(), issuer_failing_after(1), factory());
        c.ensure_active(1_000).expect("first issue ok");
        assert_eq!(c.root_invocations(), 1);

        // The overlap window opens at exp − O = 1_240. Serve 200 requests across the
        // next five seconds; the retry interval is O / 10 = 6s, so exactly ONE of them
        // may reach the root.
        for i in 0..200 {
            c.ensure_active(1_240 + i % 5)
                .expect("the predecessor is still valid");
        }
        assert_eq!(
            c.root_invocations(),
            2,
            "a declining root must be retried on an interval, not once per request"
        );

        // The gate delays the retry; it does not wedge issuance.
        c.ensure_active(1_246).expect("predecessor still valid");
        assert_eq!(c.root_invocations(), 3, "the next interval retries");
    }

    /// A re-issuance the root declines leaves the predecessor exactly as it was: same
    /// key id, no fabricated lifecycle event. The caller distinguishes an applied
    /// epoch advance from a declined one by that key id, so an unchanged id must mean
    /// nothing was minted.
    #[test]
    fn a_declined_reissue_leaves_the_predecessor_untouched() {
        let mut c = DelegatedSigningCustody::new(cfg(), issuer_failing_after(1), factory());
        c.ensure_active(1_000).expect("first issue ok");
        let before = c.active_kid().expect("a key is active").to_string();

        c.set_trust_epoch("epoch-1#2".into());
        c.reissue(1_010).expect("the predecessor keeps serving");

        assert_eq!(
            c.active_kid().expect("still active"),
            before,
            "no successor was minted, so the published key id must not move"
        );
        assert_eq!(
            c.audit().len(),
            1,
            "a declined re-issuance records no lifecycle event"
        );
    }

    /// Verify a minted credential exactly as a production verifier does, under the
    /// scope this test config declares.
    fn verify_minted(
        credential: &str,
        delegated_kid: &str,
        accepted_epochs: &[&str],
        now: i64,
        root_public: &VerificationKey,
    ) -> Result<VerifiedDelegation, HttpProfileError> {
        let policy = cfg();
        let expected_signer = ActorIdentity {
            role: policy.server_role.clone(),
            trust_domain: policy.server_trust_domain.clone(),
            subject: policy.server_subject.clone(),
            keyid: delegated_kid.to_owned(),
        }
        .actor_id();
        let audiences = [policy.aud.as_str()];
        verify_delegation_credential(
            credential,
            &DelegationVerifyParams {
                now,
                max_clock_skew: 0,
                verifier_audiences: &audiences,
                expected_profile: &policy.profile,
                expected_audience_hash: &policy.audience_hash,
                expected_server_signer: &expected_signer,
                accepted_epochs,
            },
            |kid| (kid == ROOT_KID).then(|| root_public.clone()),
            |_| false,
        )
    }

    /// The configured scope and trust epoch are MINTED INTO the credential bytes, not
    /// merely held in config: a verifier reads them back off the wire, and an advanced
    /// epoch makes a verifier pinned to the prior epoch reject — which is what makes
    /// the epoch the fleet-wide revocation lever.
    #[test]
    fn the_minted_credential_carries_the_configured_scope_and_trust_epoch() {
        let root = SigningKey::from_seed_bytes(&[33u8; 32]);
        let root_public = root.public_key();
        let issue = move |h: &DelegationHeader, c: &DelegationClaims| {
            Some(issue_delegation_credential(&root, h, c))
        };
        let mut c = DelegatedSigningCustody::new(cfg(), issue, factory());

        c.ensure_active(1_000).expect("issue");
        let first = c.active_snapshot().expect("a key is active");
        let verified = verify_minted(
            &first.credential,
            &first.delegated_kid,
            &["epoch-1"],
            1_000,
            &root_public,
        )
        .expect("the credential verifies under the configured scope");
        assert_eq!(verified.trust_epoch, "epoch-1");
        assert_eq!(verified.issuer_kid, ROOT_KID);
        assert_eq!(verified.delegated_kid, first.delegated_kid);
        assert_eq!(
            verified.delegated_key.to_b64url(),
            first.key.public_key().to_b64url(),
            "cnf.jwk names the delegated key the snapshot signs with"
        );

        c.set_trust_epoch("epoch-1#2".into());
        c.reissue(1_010).expect("reissue under the new epoch");
        let second = c.active_snapshot().expect("a successor is active");
        assert_eq!(
            verify_minted(
                &second.credential,
                &second.delegated_kid,
                &["epoch-1"],
                1_010,
                &root_public,
            )
            .expect_err("a verifier pinned to the prior epoch must reject"),
            HttpProfileError::DelegationTrustEpochStale
        );
        let advanced = verify_minted(
            &second.credential,
            &second.delegated_kid,
            &["epoch-1#2"],
            1_010,
            &root_public,
        )
        .expect("the successor verifies under the advanced epoch");
        assert_eq!(advanced.trust_epoch, "epoch-1#2");
    }

    /// A `ttl` that cannot be added to `now` refuses the issuance instead of minting a
    /// credential whose `exp` has wrapped.
    ///
    /// `CustodyConfig` carries `ttl` and `overlap` as bare `i64` fields. The
    /// `0 < overlap < ttl <= MAX_DELEGATED_TTL_SECS` guard that bounds them belongs to the
    /// proxy's configuration owner and does not reach this type — the module owning that
    /// guard says so itself — so this crate's own consumers, and any embedder, can present
    /// a value the lifecycle arithmetic cannot take. A wrapped `exp` would be signed into
    /// the credential and read by every `now < exp` test that follows it.
    #[test]
    fn an_unrepresentable_expiry_refuses_rather_than_wrapping() {
        let mut cfg = cfg();
        cfg.ttl = i64::MAX;
        let mut c = DelegatedSigningCustody::new(cfg, ok_issuer(), factory());
        assert_eq!(
            c.ensure_active(1_000).unwrap_err(),
            CustodyError::FailClosedIssuance
        );
        assert!(c.active_snapshot().is_none(), "nothing was minted");
        assert_eq!(c.root_invocations(), 0, "the root was not approached");
        assert!(
            c.audit().is_empty(),
            "no lifecycle event describes a non-key"
        );
    }

    /// An `overlap` that cannot be subtracted from `exp` rotates, rather than reading the
    /// wrapped threshold as "not yet due".
    ///
    /// This is the direction that matters. Wrapping puts `exp - overlap` far in the
    /// future, `now >= threshold` answers false, and the key stays in service past the
    /// window it should have been replaced in — a restrictive value turned permissive by
    /// an arithmetic accident.
    #[test]
    fn an_uncomputable_rotation_threshold_rotates_rather_than_holding_the_key() {
        let mut cfg = cfg();
        cfg.overlap = i64::MIN;
        let mut c = DelegatedSigningCustody::new(cfg, ok_issuer(), factory());
        c.ensure_active(1_000).expect("first issuance");
        let first = c.active_kid().expect("a key").to_string();
        assert_eq!(c.root_invocations(), 1);

        // Well inside the credential's life: with a computable overlap this would NOT
        // rotate. With one that is not computable, the threshold reads as reached.
        c.ensure_active(1_001).expect("still serving");
        assert_ne!(
            c.active_kid().expect("a key"),
            first,
            "an uncomputable threshold must not read as `not yet due`"
        );
    }

    /// The signature's stated validity never outlives the credential authorizing it, and
    /// an unrepresentable `now + ttl` clamps to `exp` rather than to a wrapped instant.
    #[test]
    fn a_signature_window_that_cannot_be_computed_clamps_to_the_credential() {
        let mut c = DelegatedSigningCustody::new(cfg(), ok_issuer(), factory());
        c.ensure_active(1_000).expect("issue");
        let exp = c.active_snapshot().expect("a key").exp;
        assert_eq!(exp, 1_000 + T);
        // `min(now + ttl, exp)` is `exp` for every `now` in the second half of the life,
        // and the checked form must agree with the plain one everywhere it is defined.
        for now in [1_000, 1_100, 1_250, exp - 1] {
            let until = now.checked_add(T).map_or(exp, |u: i64| u.min(exp));
            assert!(until <= exp, "the window may never outlive the credential");
        }
    }
}
