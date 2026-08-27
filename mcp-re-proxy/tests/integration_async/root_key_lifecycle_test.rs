// SPDX-License-Identifier: Apache-2.0
//! Trust-anchor (MASTER/root key) lifecycle — rotation, overlap, and revocation
//! (ADR-MCPRE-052). The complement to the delegated-KEY lifecycle: a delegated key
//! rotates every few minutes under ONE root (the hot path, covered elsewhere); this
//! proves the RARE, high-stakes ceremony of rotating the ROOT the whole fleet chains
//! to, with a controlled overlap, and revoking a root outright.
//!
//! Everything here is hermetic: two roots (Root A, Root B) are in-memory Ed25519 keys
//! standing in for two KMS roots through the SAME issuer seam a Cloud KMS backend
//! plugs into (`issue_delegation_credential`), so the trust decisions are exercised
//! deterministically. A separate `#[ignore]` live lane
//! (`gcp_kms_root_rotation_live_test`) drives the identical scenarios across two
//! DISPOSABLE Cloud KMS keys.
//!
//! Categories (per the ADR-052 root-key proof obligation):
//!   1. ROOT ROTATION — a credential under Root A is accepted while A is current;
//!      during overlap {A, B} both verify; after A is retired past its cutover only B
//!      verifies. This is trust-anchor rotation, NOT delegated-key rotation.
//!   2. ROOT REVOCATION — revoking issuer_kid A rejects EVERY credential A anchors,
//!      immediately (`delegation_revoked`), even before the credential's own exp and
//!      without individually revoking each delegated key.
//!
//! (Category 3 — root ISSUANCE FAILURE / disabled KMS → serve until the current
//! delegated key expires then fail closed, never extend, never fall back to
//! direct-root — is a SERVER-side rotor property, proven by
//! `mcp-re-proxy/tests/delegated_production_wiring_test.rs::issuance_failure_serves_the_valid_key_then_fails_closed_at_expiry`.)

use mcp_re_client_core::build_signed_request;
use mcp_re_client_core::verify_delegated_response;
use mcp_re_client_core::ActorIdentity;
use mcp_re_client_core::ArtifactBinding;
use mcp_re_client_core::ArtifactType;
use mcp_re_client_core::AudienceTuple;
use mcp_re_client_core::CompositeResponseTrust;
use mcp_re_client_core::DelegatedOutcome;
use mcp_re_client_core::DelegatedResponseTrust;
use mcp_re_client_core::DelegationPolicy;
use mcp_re_client_core::RequestSigningInputs;
use mcp_re_client_core::ResolvedActor;
use mcp_re_client_core::ResponseExpectation;
use mcp_re_client_core::SignedRequest;
use mcp_re_client_core::SignerSlot;
use mcp_re_client_core::StaticRevocationList;
use mcp_re_client_core::TrustedIssuerSet;

use mcp_re_core::SigningKey;
use mcp_re_http_profile::issue_delegation_credential;
use mcp_re_http_profile::CustodyConfig;
use mcp_re_http_profile::CustodyError;
use mcp_re_http_profile::DelegatedSigningCustody;
use mcp_re_http_profile::DelegationClaims;
use mcp_re_http_profile::DelegationHeader;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::PROFILE_TAG;

use mcp_re_proxy::DelegatedRotor;
use mcp_re_proxy::DelegatedServerSigner;

use std::sync::Arc;

use serde_json::json;
use serde_json::Map;
use serde_json::Value;

const CLIENT_SEED: [u8; 32] = [11u8; 32];
const ROOT_A_SEED: [u8; 32] = [33u8; 32];
const ROOT_B_SEED: [u8; 32] = [44u8; 32];
const CLIENT_KEY_ID: &str = "client-key-1";
const ROOT_A_KID: &str = "root-A";
const ROOT_B_KID: &str = "root-B";
const AUD: &str = "verifier-1";
const AUD_SCOPE: &str = "aud-scope-1";
const EPOCH: &str = "epoch-1";
const TARGET: &str = "https://mcp.example.com/mcp?route=a";
const NOW: i64 = 1_700_000_100;
const CREATED: i64 = 1_700_000_000;
const EXPIRES: i64 = 1_700_000_600;

fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_SEED)
}
fn root_pub(seed: &[u8; 32]) -> mcp_re_core::VerificationKey {
    SigningKey::from_seed_bytes(seed).public_key()
}
fn audience() -> AudienceTuple {
    AudienceTuple {
        audience_id: AUD.into(),
        target_uri: TARGET.into(),
        route: Some("a".into()),
    }
}

/// The ROOT issuer actor for the `Response` slot: only its `keyid` (= issuer_kid) and
/// its verification key matter to the credential-chain check. The server-signer
/// identity is a SEPARATE thing carried in the credential and stays constant across a
/// root swap.
fn root_actor(issuer_kid: &str, seed: &[u8; 32]) -> ResolvedActor {
    ResolvedActor {
        identity: ActorIdentity {
            role: "server".into(),
            trust_domain: "example.com".into(),
            subject: "did:example:issuer".into(),
            keyid: issuer_kid.into(),
        },
        verification_key: root_pub(seed),
        slot: SignerSlot::Response,
    }
}

fn signed_request() -> SignedRequest {
    let inputs = RequestSigningInputs::new(
        CLIENT_KEY_ID.to_string(),
        audience(),
        vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthDpop,
            b"access-token-xyz",
        )],
        "nonce-root-lifecycle-padded",
        CREATED,
        EXPIRES,
    );
    let params: Map<String, Value> = json!({ "name": "read" }).as_object().cloned().unwrap();
    build_signed_request(
        &json!(1),
        "tools/call",
        params,
        TARGET,
        &inputs,
        &client_key(),
    )
    .expect("client signs request")
}

fn expectation(signed: &SignedRequest) -> ResponseExpectation {
    ResponseExpectation::new(signed.request().clone(), signed.evidence().clone())
}

fn policy() -> DelegationPolicy {
    DelegationPolicy::new(
        vec![AUD.to_string()],
        AUD_SCOPE,
        vec![EPOCH.to_string()],
        60,
    )
}

/// Custody config for a given ROOT issuer_kid. The server-signer identity
/// (`server_*`) is identical for both roots — a root rotation changes the ANCHOR, not
/// the server's own identity.
fn custody_cfg(issuer_kid: &str) -> CustodyConfig {
    CustodyConfig {
        issuer_kid: issuer_kid.into(),
        iss: "did:example:issuer".into(),
        profile: PROFILE_TAG.into(),
        aud: AUD.into(),
        audience_hash: AUD_SCOPE.into(),
        trust_epoch: EPOCH.into(),
        server_role: "server".into(),
        server_trust_domain: "example.com".into(),
        server_subject: "did:example:server".into(),
        ttl: 300,
        overlap: 60,
    }
}

/// Mint a delegated 200 response whose credential chains to the given ROOT (by seed +
/// issuer_kid), bound to `signed`. This is the server/issuer side using the SAME seam
/// a KMS root plugs into.
fn mint_under(
    root_seed: [u8; 32],
    issuer_kid: &str,
    signed: &SignedRequest,
    now: i64,
) -> HttpResponse {
    let issue = move |h: &DelegationHeader, c: &DelegationClaims| {
        let root = SigningKey::from_seed_bytes(&root_seed);
        Some(issue_delegation_credential(&root, h, c))
    };
    let mut n = 100u8;
    let factory = move || {
        n = n.wrapping_add(1);
        SigningKey::from_seed_bytes(&[n; 32])
    };
    let mut custody = DelegatedSigningCustody::new(custody_cfg(issuer_kid), issue, factory);
    let mut resp = HttpResponse {
        status: 200,
        headers: vec![("content-type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec(),
    };
    custody
        .sign_response(now, &mut resp, signed.request(), signed.evidence())
        .expect("mint a delegated response under the root");
    resp
}

/// Verify a delegated response against a trust-anchor set at `now`.
///
/// The set is the [`DelegatedResponseTrust`] authority: ONE value answering both root
/// resolution and issuer revocation (MCPRE-172). Earlier forms of this helper passed it
/// in two argument positions, which is exactly the mis-wiring C064/C065 named.
fn verify_with(
    resp: &HttpResponse,
    signed: &SignedRequest,
    set: &TrustedIssuerSet,
    now: i64,
) -> Result<DelegatedOutcome, HttpProfileError> {
    verify_delegated_response(resp, set, &expectation(signed), &policy(), now).map(|v| v.outcome)
}

// --- Category 1: ROOT ROTATION (trust-anchor rotation) -----------------------

#[test]
fn root_a_credential_accepted_while_a_is_current() {
    let signed = signed_request();
    let resp = mint_under(ROOT_A_SEED, ROOT_A_KID, &signed, NOW);
    let set = TrustedIssuerSet::new().with_current(root_actor(ROOT_A_KID, &ROOT_A_SEED));
    assert_eq!(
        verify_with(&resp, &signed, &set, NOW).unwrap(),
        DelegatedOutcome::Success
    );
}

#[test]
fn during_overlap_both_roots_are_accepted() {
    let signed = signed_request();
    let resp_a = mint_under(ROOT_A_SEED, ROOT_A_KID, &signed, NOW);
    let resp_b = mint_under(ROOT_B_SEED, ROOT_B_KID, &signed, NOW);
    // Overlap: Root A retired but still inside its window; Root B current.
    let overlap_deadline = NOW + 1_000;
    let set = TrustedIssuerSet::new()
        .with_current(root_actor(ROOT_B_KID, &ROOT_B_SEED))
        .with_retired(root_actor(ROOT_A_KID, &ROOT_A_SEED), overlap_deadline);
    assert_eq!(
        verify_with(&resp_a, &signed, &set, NOW).unwrap(),
        DelegatedOutcome::Success,
        "outgoing Root A still accepted during overlap"
    );
    assert_eq!(
        verify_with(&resp_b, &signed, &set, NOW).unwrap(),
        DelegatedOutcome::Success,
        "incoming Root B accepted during overlap"
    );
}

#[test]
fn after_overlap_old_root_rejected_new_root_accepted() {
    let signed = signed_request();
    let resp_a = mint_under(ROOT_A_SEED, ROOT_A_KID, &signed, NOW);
    let resp_b = mint_under(ROOT_B_SEED, ROOT_B_KID, &signed, NOW);
    // Overlap ENDED: Root A retired with a deadline already in the past; only B current.
    let past_deadline = NOW - 1;
    let set = TrustedIssuerSet::new()
        .with_current(root_actor(ROOT_B_KID, &ROOT_B_SEED))
        .with_retired(root_actor(ROOT_A_KID, &ROOT_A_SEED), past_deadline);
    assert_eq!(
        verify_with(&resp_a, &signed, &set, NOW).unwrap_err(),
        HttpProfileError::DelegationIssuerUntrusted,
        "Root A rejected once its overlap window closed — even though the credential's own exp has not passed"
    );
    assert_eq!(
        verify_with(&resp_b, &signed, &set, NOW).unwrap(),
        DelegatedOutcome::Success,
        "Root B accepted after cutover"
    );
}

#[test]
fn retirement_window_boundary_is_inclusive_then_closes() {
    let signed = signed_request();
    let resp_a = mint_under(ROOT_A_SEED, ROOT_A_KID, &signed, NOW);
    let deadline = NOW + 100;
    let set = TrustedIssuerSet::new().with_retired(root_actor(ROOT_A_KID, &ROOT_A_SEED), deadline);
    // At the deadline instant: still trusted (inclusive).
    assert_eq!(
        verify_with(&resp_a, &signed, &set, deadline).unwrap(),
        DelegatedOutcome::Success
    );
    // One second past: untrusted.
    assert_eq!(
        verify_with(&resp_a, &signed, &set, deadline + 1).unwrap_err(),
        HttpProfileError::DelegationIssuerUntrusted
    );
}

// --- Category 2: ROOT REVOCATION --------------------------------------------

#[test]
fn revoked_issuer_invalidates_all_descendants_before_exp() {
    let signed = signed_request();
    // A credential under Root A whose own exp is comfortably in the future.
    let resp_a = mint_under(ROOT_A_SEED, ROOT_A_KID, &signed, NOW);
    // Root A is still CURRENT (resolvable) but REVOKED — one decisive action.
    let set = TrustedIssuerSet::new()
        .with_current(root_actor(ROOT_A_KID, &ROOT_A_SEED))
        .revoke(ROOT_A_KID);
    assert_eq!(
        verify_with(&resp_a, &signed, &set, NOW).unwrap_err(),
        HttpProfileError::DelegationIssuerUntrusted,
        "revoking the issuer_kid rejects the credential before its exp, without touching the delegated key. The reason is UNTRUSTED rather than REVOKED because `resolve_issuer` fails closed on a revoked root before the credential's signature is reached — the structural refusal, bought at the cost of the more precise diagnostic"
    );
}

#[test]
fn revoking_one_root_does_not_disturb_the_other() {
    let signed = signed_request();
    let resp_a = mint_under(ROOT_A_SEED, ROOT_A_KID, &signed, NOW);
    let resp_b = mint_under(ROOT_B_SEED, ROOT_B_KID, &signed, NOW);
    // Root A revoked (e.g. compromised); Root B untouched and current.
    let set = TrustedIssuerSet::new()
        .with_current(root_actor(ROOT_A_KID, &ROOT_A_SEED))
        .with_current(root_actor(ROOT_B_KID, &ROOT_B_SEED))
        .revoke(ROOT_A_KID);
    assert_eq!(
        verify_with(&resp_a, &signed, &set, NOW).unwrap_err(),
        HttpProfileError::DelegationIssuerUntrusted
    );
    assert_eq!(
        verify_with(&resp_b, &signed, &set, NOW).unwrap(),
        DelegatedOutcome::Success,
        "revoking Root A leaves Root B fully trusted"
    );
}

/// MCPRE-172 negative control: the mis-wiring that could verify under a REVOKED root is
/// no longer constructible through the production API, and the revoked root fails closed.
///
/// # What used to be possible
///
/// `verify_delegated_response` took the root resolver and the `RevocationSource` as two
/// INDEPENDENT arguments, and `TrustedIssuerSet::response_resolver` handed out a resolver
/// on its own. A caller could therefore write
///
/// ```text
/// let resolver = set.response_resolver(NOW);          // knows the revocation
/// let empty    = StaticRevocationList::new();         // knows nothing
/// verify_delegated_response(&resp, &resolver, &expectation, &policy, &empty, NOW)
/// ```
///
/// and the revocation the operator recorded was never consulted. It failed in the
/// PERMISSIVE direction: the revoked root resolves and its credential's signature checks
/// out. Two mitigations stood around it — `response_resolver` refused a revoked issuer
/// defensively, and an `_anchored` entry point took the set once — but the unsafe pairing
/// remained expressible, and its safety depended on caller discipline.
///
/// # What holds now
///
/// The verifier takes ONE `DelegatedResponseTrust`, and TWO doors are shut, not one.
///
/// `response_resolver` is gone, and `resolve_root` — the raw lifecycle lookup, which
/// answers rotation and still returns a revoked root's actor — is `pub(crate)`. Both
/// forms of the mis-wiring therefore **do not compile**; two `compile_fail` doctests in
/// `mcp-re-client-core` pin that.
///
/// What remains public is `resolve_issuer`, and it fails closed on a revoked issuer
/// WITHOUT consulting the caller's revocation half. So the last reachable reconstruction
/// — compose it beside an empty revocation source — also fails, which is the second
/// assertion below.
///
/// The refusal reads `delegation_issuer_untrusted` rather than `delegation_revoked`,
/// because the credential's signature is never reached. A structural guarantee is worth
/// more than the more precise diagnostic, and the precise one was only available while a
/// caller could still get the pairing wrong.
#[test]
fn a_revoked_root_fails_closed_and_the_split_seam_is_gone() {
    let signed = signed_request();
    let resp_a = mint_under(ROOT_A_SEED, ROOT_A_KID, &signed, NOW);
    let set = TrustedIssuerSet::new()
        .with_current(root_actor(ROOT_A_KID, &ROOT_A_SEED))
        .revoke(ROOT_A_KID);

    // The set is BOTH halves of the trust picture, and it is passed once.
    assert_eq!(
        verify_with(&resp_a, &signed, &set, NOW).unwrap_err(),
        HttpProfileError::DelegationIssuerUntrusted,
        "a credential under a revoked root must fail closed"
    );

    // The reconstruction attempt. `resolve_issuer` is the only public resolution
    // interface left, so this is the closest a caller can now get to the old split: take
    // it, compose it beside a revocation source that knows NOTHING, and verify.
    //
    // It still fails, and it fails for a structural reason rather than a cooperative
    // one: `resolve_issuer` refuses a revoked issuer without consulting the caller's
    // revocation half at all. The empty half is not merely overruled — it is never asked.
    let resolve = |kid: &str, slot: SignerSlot, now: i64| set.resolve_issuer(kid, slot, now);
    let knows_nothing = StaticRevocationList::new();
    let recomposed = CompositeResponseTrust::new(&resolve, &knows_nothing);
    assert_eq!(
        verify_delegated_response(&resp_a, &recomposed, &expectation(&signed), &policy(), NOW)
            .map(|v| v.outcome)
            .unwrap_err(),
        HttpProfileError::DelegationIssuerUntrusted,
        "the split seam cannot be rebuilt through the remaining public API"
    );

    // The same set with the revocation removed accepts it — so the refusal above is the
    // revocation doing the work, not an unrelated failure in the fixture.
    let not_revoked = TrustedIssuerSet::new().with_current(root_actor(ROOT_A_KID, &ROOT_A_SEED));
    assert_eq!(
        verify_with(&resp_a, &signed, &not_revoked, NOW).unwrap(),
        DelegatedOutcome::Success,
        "without the revocation the very same credential verifies"
    );
}

// --- Unknown issuer ----------------------------------------------------------

#[test]
fn unknown_issuer_is_rejected() {
    let signed = signed_request();
    // A credential minted under Root A, but the verifier trusts ONLY Root B.
    let resp_a = mint_under(ROOT_A_SEED, ROOT_A_KID, &signed, NOW);
    let set = TrustedIssuerSet::new().with_current(root_actor(ROOT_B_KID, &ROOT_B_SEED));
    assert_eq!(
        verify_with(&resp_a, &signed, &set, NOW).unwrap_err(),
        HttpProfileError::DelegationIssuerUntrusted,
        "an issuer absent from the trust-anchor set is untrusted"
    );
}

// --- Category 3: ROOT ISSUANCE FAILURE (disabled / unavailable KMS root) -----

#[test]
fn root_issuance_failure_serves_until_delegated_key_expiry_then_fails_closed() {
    // The SERVER-side master-key-outage contract (ADR-MCPRE-052 §6): K1 mints, then
    // the ROOT issuer (KMS) becomes unavailable so NO successor can be minted. The
    // rotor keeps serving the still-valid K1 (never a signing gap), and at K1's OWN
    // exp the hot path fails closed — it never EXTENDS K1 past its exp and never falls
    // back to direct-root signing (that mode does not exist). Driven through the
    // public rotor/signer API at integration altitude.
    let mut attempts = 0u32;
    let issue = move |h: &DelegationHeader, c: &DelegationClaims| {
        attempts += 1;
        if attempts == 1 {
            let root = SigningKey::from_seed_bytes(&ROOT_A_SEED);
            Some(issue_delegation_credential(&root, h, c))
        } else {
            None // the KMS root is unavailable for every successor issuance
        }
    };
    let mut n = 100u8;
    let factory = move || {
        n = n.wrapping_add(1);
        SigningKey::from_seed_bytes(&[n; 32])
    };
    let signer = Arc::new(DelegatedServerSigner::new());
    let custody = DelegatedSigningCustody::new(custody_cfg(ROOT_A_KID), issue, factory);
    let mut rotor = DelegatedRotor::new(custody, Arc::clone(&signer));

    // K1 mints and serves.
    rotor.rotate(NOW).expect("K1 mints via the root");
    let k1 = signer
        .current(NOW)
        .expect("K1 serves")
        .delegated_kid
        .clone();

    // Successor cannot be minted (root down). K1 is KEPT (not retired) while valid — no
    // serving gap, no stale successor. (custody_cfg: ttl 300, overlap 60.)
    let in_overlap = NOW + 300 - 60;
    rotor
        .rotate(in_overlap)
        .expect("K1 kept despite the failed successor issuance");
    assert_eq!(
        signer
            .current(in_overlap)
            .expect("K1 still serves")
            .delegated_kid,
        k1,
        "still K1 — no stale successor minted, no signing gap"
    );
    assert!(
        signer.current(NOW + 300 - 1).is_some(),
        "serves right up to just before exp"
    );

    // At K1's own exp: fail closed. No stale-key extension.
    assert!(
        signer.current(NOW + 300).is_none(),
        "fails closed at K1 exp — K1 is never extended"
    );

    // Past exp with the root still down: the rotor retires and surfaces the fail-closed
    // error; the hot path stays closed (there is no direct-root fallback).
    assert_eq!(
        rotor.rotate(NOW + 300 + 1),
        Err(CustodyError::FailClosedIssuance)
    );
    assert!(
        signer.current(NOW + 300 + 1).is_none(),
        "stays fail-closed; no direct-root fallback"
    );
}

#[test]
fn empty_trust_anchor_set_trusts_no_root() {
    let signed = signed_request();
    let resp_a = mint_under(ROOT_A_SEED, ROOT_A_KID, &signed, NOW);
    let set = TrustedIssuerSet::new();
    assert_eq!(
        verify_with(&resp_a, &signed, &set, NOW).unwrap_err(),
        HttpProfileError::DelegationIssuerUntrusted,
        "an empty set (no roots deliberately added) trusts nothing — a delegated-required verifier never silently trusts a root"
    );
}
