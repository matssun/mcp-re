// SPDX-License-Identifier: Apache-2.0
//! Test-only verified requests, produced by the request verifier itself.
//!
//! Kept out of the production tree by `#[cfg(test)]` on the `mod` declaration: nothing here
//! may be reachable from a serving path.
//!
//! A `VerifiedMcpRequest` cannot be written as a literal outside `mcp-re-http-profile`, so
//! every value here is what `Verifier::verify_request` returned for a request this harness
//! signed. The resolver it verifies through trusts exactly one keyid, for the subject the
//! caller names, which is how a control obtains a request resolved to a chosen actor
//! without asserting one.
//!
//! Signing inserts the request evidence block into the body's `_meta`, so the signed body
//! differs from the body passed in. A control that hands the authority a body must hand it
//! [`Signed::body`], the bytes the signature covers.

use mcp_re_core::SigningKey;
use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ArtifactType;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::HttpContinuation;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::VerifiedMcpRequest;
use mcp_re_http_profile::Verifier;
use mcp_re_http_profile::VerifierPolicy;
use mcp_re_http_profile::PROFILE_TAG;

/// The target every harness request is addressed to.
const TARGET: &str = "https://example.test/mcp";
/// The bearer token the request's DPoP artifact binding commits to.
const ACCESS_TOKEN: &str = "harness-access-token";
/// The signature's `created`; the verifier runs at [`NOW`], inside the window.
pub(crate) const CREATED: i64 = 1_700_000_000;
/// The signature's `expires`.
pub(crate) const EXPIRES: i64 = 1_700_000_300;
/// The instant every harness verification runs at.
pub(crate) const NOW: i64 = 1_700_000_100;

/// A body naming a method that names no target, for a control that needs a request and
/// nothing in particular in it.
pub(crate) const LIST: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;

/// What a harness request is signed as, and for whom.
pub(crate) struct RequestSpec<'a> {
    /// The JSON-RPC body before the evidence block is inserted.
    pub(crate) body: &'a [u8],
    /// The subject the harness resolver trusts `keyid` for.
    pub(crate) subject: &'a str,
    /// The signing keyid.
    pub(crate) keyid: &'a str,
    /// The audience the request is addressed to and verified for.
    pub(crate) audience_id: &'a str,
    /// The MRTR continuation the request evidence block carries.
    pub(crate) continuation: Option<HttpContinuation>,
}

/// A request the harness signed, and what the verifier returned for it.
pub(crate) struct Signed {
    /// The verification product.
    pub(crate) verified: VerifiedMcpRequest,
    /// The signed body: the input body with the evidence block in its `_meta`.
    pub(crate) body: Vec<u8>,
}

/// The audience a harness request is addressed to.
pub(crate) fn audience(audience_id: &str) -> AudienceTuple {
    AudienceTuple {
        audience_id: audience_id.into(),
        target_uri: TARGET.into(),
        route: None,
    }
}

/// Sign `spec` and verify it under the full profile.
pub(crate) fn sign_and_verify(spec: RequestSpec<'_>) -> Signed {
    let key = SigningKey::from_seed_bytes(&[7u8; 32]);
    let block = HttpRequestEvidenceBlock {
        profile: PROFILE_TAG.into(),
        audience: audience(spec.audience_id),
        artifact_bindings: vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthDpop,
            ACCESS_TOKEN.as_bytes(),
        )],
        continuation: spec.continuation,
        admission: None,
        admission_assertion: None,
        authorization_decision: None,
    };
    let mut request = HttpRequest {
        method: "POST".into(),
        target_uri: TARGET.into(),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("Authorization".into(), format!("Bearer {ACCESS_TOKEN}")),
        ],
        body: spec.body.to_vec(),
    };
    sign_request_full(
        &mut request,
        &block,
        &key,
        spec.keyid,
        CREATED,
        EXPIRES,
        "n",
    )
    .expect("the harness request signs");
    let (subject, keyid, public) = (
        spec.subject.to_owned(),
        spec.keyid.to_owned(),
        key.public_key(),
    );
    let resolve = move |presented: &str, slot: SignerSlot| {
        (presented == keyid && slot == SignerSlot::Request).then(|| ResolvedActor {
            identity: ActorIdentity {
                role: "client".into(),
                trust_domain: "example.org".into(),
                subject: subject.clone(),
                keyid: keyid.clone(),
            },
            verification_key: public.clone(),
            slot,
        })
    };
    let verified = Verifier::new(&VerifierPolicy::default(), &resolve)
        .verify_request(&request, &block.audience, &|_: &ArtifactBinding| None, NOW)
        .expect("the harness request verifies");
    Signed {
        verified,
        body: request.body,
    }
}

/// A request signed over `body` by `did:example:agent-1` under `key-a`.
pub(super) fn verified_over(body: &[u8]) -> Signed {
    verified_over_as(body, "did:example:agent-1", "key-a")
}

/// A verified request re-pointed at `body`, a body the verifier refuses to cover.
///
/// The transport contract refuses a body naming no method, and a `tools/call` naming no
/// tool, before any verification product exists, so no verified request covers either.
/// The authorities downstream still refuse them on their own account, and a control for
/// that refusal needs a product that covers such a body. This one is a real product with
/// its content digest replaced, which is a state verification never returns.
pub(super) fn covering_unverifiable(body: &[u8]) -> VerifiedMcpRequest {
    let mut verified = verified_over(LIST).verified;
    verified.floor.content_digest = mcp_re_http_profile::content_digest_sha256(body);
    verified
}

/// The same, with the resolved actor's subject and keyid chosen by the caller.
pub(crate) fn verified_over_as(body: &[u8], subject: &str, keyid: &str) -> Signed {
    sign_and_verify(RequestSpec {
        body,
        subject,
        keyid,
        audience_id: "aud",
        continuation: None,
    })
}
