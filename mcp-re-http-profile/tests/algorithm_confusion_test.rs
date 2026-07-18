// SPDX-License-Identifier: Apache-2.0
//! Algorithm-confusion regression (#415 rev 2 §13.1, issue #432).
//!
//! The bug this pins was introduced BY the agility interface, which is what makes
//! it worth a dedicated test. When the allowlist was a list of strings, a policy
//! could name `ml-dsa-65`; the parameter gate accepted a message DECLARING
//! `ml-dsa-65`; and verification then called the Ed25519 verifier regardless. So a
//! genuine Ed25519 signature over a base declaring ML-DSA verified — the declared
//! algorithm was a lie the verifier had no way to notice, because it only ever
//! compared a string against a list.
//!
//! A string allowlist cannot express the property that makes it safe: "…and this
//! crate has a verifier for that". So the registry is typed.

use mcp_re_core::SigningKey;
use mcp_re_http_profile::policy::ProfileAlgorithm;
use mcp_re_http_profile::sigbase::signature_base;
use mcp_re_http_profile::sigbase::SourceMessage;
use mcp_re_http_profile::*;

const CREATED: i64 = 1_700_000_000;
const EXPIRES: i64 = 1_700_000_300;
const NOW: i64 = 1_700_000_100;

fn key() -> SigningKey {
    SigningKey::from_seed_bytes(&[11u8; 32])
}

fn resolver() -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> {
    |kid: &str, slot: SignerSlot| {
        (kid == "k1" && slot == SignerSlot::Request).then(|| ResolvedActor {
            identity: ActorIdentity {
                role: "client".into(),
                trust_domain: "example.com".into(),
                subject: "did:example:client".into(),
                keyid: kid.into(),
            },
            verification_key: key().public_key(),
            slot,
        })
    }
}

/// Sign a request whose signature base DECLARES `alg` while an Ed25519 key does
/// the signing. This is the attack shape: not a rewritten header (the base covers
/// `alg`, so a rewrite breaks the signature), but a signer who genuinely commits
/// to a false algorithm claim.
fn signed_declaring(alg: &str) -> HttpRequest {
    let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#.to_vec();
    let mut r = HttpRequest {
        method: "POST".into(),
        target_uri: "https://mcp.example.com/mcp".into(),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("Content-Digest".into(), content_digest_sha256(&body)),
        ],
        body,
    };
    let comps: Vec<CoveredComponent> =
        ["@method", "@target-uri", "content-digest", "content-type"]
            .iter()
            .map(|n| CoveredComponent::new(n))
            .collect();
    let params = SignatureParams {
        created: Some(CREATED),
        expires: Some(EXPIRES),
        nonce: Some("n".into()),
        keyid: Some("k1".into()),
        alg: Some(alg.to_owned()),
        tag: Some(PROFILE_TAG.into()),
    };
    let base = signature_base(&comps, &params, &SourceMessage::Request(&r)).unwrap();
    let sig = mcp_re_core::b64url_decode(&key().sign(&base)).unwrap();
    use base64::Engine;
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&sig);
    r.headers.push((
        "Signature-Input".into(),
        format!("mcp-re={}", params.serialize_with(&comps)),
    ));
    r.headers.push(("Signature".into(), format!("mcp-re=:{sig_b64}:")));
    r
}

/// THE regression. A policy that would enable the confusion cannot be built: the
/// unsafe configuration is refused at CONSTRUCTION, so a deployment learns its
/// policy is unimplementable when it writes it — not when an attacker exercises it.
#[test]
fn a_policy_enabling_algorithm_confusion_cannot_be_constructed() {
    assert_eq!(
        VerifierPolicy::new(&["ed25519", "ml-dsa-65"], 30).unwrap_err(),
        HttpProfileError::UnsupportedAlgorithm,
        "allowlisting an algorithm with no verifier is what enabled the confusion"
    );
}

/// And the message itself: an Ed25519 signature declaring ML-DSA is rejected under
/// the default policy, because the token resolves to no algorithm this crate can
/// verify. Previously this same message was ACCEPTED whenever a local policy had
/// been told to allow `ml-dsa-65`.
#[test]
fn an_ed25519_signature_declaring_ml_dsa_is_rejected() {
    let r = signed_declaring("ml-dsa-65");
    let err = verify_request_with_policy(&r, &resolver(), &VerifierPolicy::default(), NOW)
        .unwrap_err();
    assert_eq!(err, HttpProfileError::UnsupportedAlgorithm);
    assert_eq!(err.wire_code(), "mcp-re.unsupported_version");
}

/// The same message declaring the truth verifies — so the rejection above is the
/// algorithm gate doing its job, not an unrelated failure.
#[test]
fn the_same_signature_declaring_ed25519_verifies() {
    let r = signed_declaring("ed25519");
    verify_request_with_policy(&r, &resolver(), &VerifierPolicy::default(), NOW)
        .expect("an honest algorithm claim verifies");
}

/// The registry maps a token to a VERIFIER. Only algorithms with one exist, which
/// is the invariant that makes `accepted_algorithm` safe to dispatch on.
#[test]
fn only_implemented_algorithms_resolve() {
    assert_eq!(ProfileAlgorithm::from_token("ed25519"), Some(ProfileAlgorithm::Ed25519));
    for unimplemented in ["ml-dsa-65", "rsa-pss-sha512", "ecdsa-p256-sha256", "hmac-sha256"] {
        assert_eq!(
            ProfileAlgorithm::from_token(unimplemented),
            None,
            "{unimplemented} has no verifier here; IANA registration is not an implementation"
        );
    }
}
