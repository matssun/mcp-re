// SPDX-License-Identifier: Apache-2.0
//! ADR-MCPS-021: the revocation tier the proxy ANNOUNCES at startup must be the tier
//! the data plane runs.
//!
//! The serving PEP resolves every request signer through [`build_actor_resolver`].
//! Before this lane existed the resolver chain was constructed, its guarantee printed,
//! and then dropped (`let _ = &resolver;`), while the PEP resolved from a `HashMap`
//! frozen at process start — so a key revoked in the trust store kept verifying until
//! restart, on every tier including `--revocation-tier live`.
//!
//! These tests pin the seam itself: whatever the tier decides, the Request slot obeys.

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;

use mcp_re_core::TrustResolver;
use mcp_re_core::TrustResolverError;
use mcp_re_core::VerificationKey;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::SignerSlot;

use mcp_re_proxy::app::build_actor_resolver;

const CLIENT_KID: &str = "client-key-1";
const CLIENT_SIGNER: &str = "client.example.com";
const ROOT_KID: &str = "root-kid";

fn a_key(seed: u8) -> VerificationKey {
    let signing = mcp_re_core::SigningKey::from_seed_bytes(&[seed; 32]);
    signing.public_key()
}

/// A resolver whose answer the test dictates, counting calls so "consulted per
/// request" is provable rather than assumed.
struct ScriptedResolver {
    outcome: Mutex<Result<VerificationKey, TrustResolverError>>,
    calls: AtomicUsize,
}

impl ScriptedResolver {
    fn new(outcome: Result<VerificationKey, TrustResolverError>) -> Arc<Self> {
        Arc::new(ScriptedResolver {
            outcome: Mutex::new(outcome),
            calls: AtomicUsize::new(0),
        })
    }
    fn set(&self, outcome: Result<VerificationKey, TrustResolverError>) {
        *self.outcome.lock().expect("scripted resolver lock") = outcome;
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl TrustResolver for ScriptedResolver {
    fn resolve(&self, signer: &str, key_id: &str) -> Result<VerificationKey, TrustResolverError> {
        assert_eq!(signer, CLIENT_SIGNER, "resolver must receive the trust-file signer");
        assert_eq!(key_id, CLIENT_KID, "resolver must receive the presented kid");
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.outcome.lock().expect("scripted resolver lock").clone()
    }
}

fn signers() -> std::collections::HashMap<String, String> {
    let mut m = std::collections::HashMap::new();
    m.insert(CLIENT_KID.to_string(), CLIENT_SIGNER.to_string());
    m
}

fn resolver_over(
    trust: Arc<dyn TrustResolver + Send + Sync>,
) -> mcp_re_proxy::ActorResolver {
    build_actor_resolver(
        signers(),
        trust,
        "example.com".to_string(),
        ROOT_KID.to_string(),
        ActorIdentity {
            role: "server".to_string(),
            trust_domain: "example.com".to_string(),
            subject: "mcp.example.com".to_string(),
            keyid: ROOT_KID.to_string(),
        },
        a_key(99),
    )
}

#[test]
fn active_binding_resolves_the_key_the_tier_returns() {
    let live = a_key(7);
    let trust = ScriptedResolver::new(Ok(live.clone()));
    let resolve = resolver_over(trust.clone());

    let actor = resolve(CLIENT_KID, SignerSlot::Request).expect("active binding resolves");
    assert_eq!(actor.identity.subject, CLIENT_SIGNER);
    assert_eq!(actor.identity.keyid, CLIENT_KID);
    assert_eq!(actor.identity.role, "client");
    // The KEY comes from the tier, not from a boot-time copy.
    assert_eq!(actor.verification_key.to_b64url(), live.to_b64url());
    assert_eq!(trust.calls(), 1, "the tier is consulted on the request path");
}

#[test]
fn revoked_binding_yields_no_actor() {
    let trust = ScriptedResolver::new(Err(TrustResolverError::Revoked));
    let resolve = resolver_over(trust.clone());
    assert!(
        resolve(CLIENT_KID, SignerSlot::Request).is_none(),
        "a revoked key must not resolve to an actor (-> actor_binding_failed)"
    );
    assert_eq!(trust.calls(), 1);
}

#[test]
fn unavailable_tier_fails_closed_and_is_never_softened_to_an_allow() {
    let trust = ScriptedResolver::new(Err(TrustResolverError::Unavailable { details: "store unreachable".to_string() }));
    let resolve = resolver_over(trust.clone());
    assert!(
        resolve(CLIENT_KID, SignerSlot::Request).is_none(),
        "an operational tier failure must fail closed, never serve a key"
    );
}

#[test]
fn not_found_and_malformed_yield_no_actor() {
    for outcome in [TrustResolverError::NotFound, TrustResolverError::MalformedKey] {
        let trust = ScriptedResolver::new(Err(outcome));
        let resolve = resolver_over(trust);
        assert!(resolve(CLIENT_KID, SignerSlot::Request).is_none());
    }
}

/// The regression that motivated the fix: revoking mid-process must take effect on the
/// NEXT request, with no restart. A boot-time key map cannot express this.
#[test]
fn revocation_takes_effect_without_a_restart() {
    let trust = ScriptedResolver::new(Ok(a_key(7)));
    let resolve = resolver_over(trust.clone());

    assert!(resolve(CLIENT_KID, SignerSlot::Request).is_some(), "initially active");
    trust.set(Err(TrustResolverError::Revoked));
    assert!(
        resolve(CLIENT_KID, SignerSlot::Request).is_none(),
        "the very next request after revocation must fail closed"
    );
    assert_eq!(trust.calls(), 2, "no positive-trust caching in the seam itself");
}

/// A rotated key must be picked up from the tier too — the seam carries the CURRENT
/// key, not the one present at startup.
#[test]
fn rotated_key_is_served_from_the_tier() {
    let trust = ScriptedResolver::new(Ok(a_key(7)));
    let resolve = resolver_over(trust.clone());
    let before = resolve(CLIENT_KID, SignerSlot::Request).expect("active").verification_key;

    let rotated = a_key(8);
    trust.set(Ok(rotated.clone()));
    let after = resolve(CLIENT_KID, SignerSlot::Request).expect("active").verification_key;

    assert_ne!(before.to_b64url(), after.to_b64url());
    assert_eq!(after.to_b64url(), rotated.to_b64url());
}

/// Slot discipline survives the change: an unknown kid resolves to nothing, and the
/// Response slot answers only for the issuer kid and never consults the request tier.
#[test]
fn slot_discipline_holds() {
    let trust = ScriptedResolver::new(Ok(a_key(7)));
    let resolve = resolver_over(trust.clone());

    assert!(resolve(ROOT_KID, SignerSlot::Response).is_some(), "issuer kid serves the Response slot");
    assert!(resolve("some-other-kid", SignerSlot::Response).is_none());
    assert_eq!(trust.calls(), 0, "the Response slot must not consult the request trust tier");

    // A kid absent from the trust file never reaches the tier at all.
    let resolve_unknown = resolver_over(trust.clone());
    assert!(resolve_unknown("unknown-kid", SignerSlot::Request).is_none());
    assert_eq!(trust.calls(), 0);
}
