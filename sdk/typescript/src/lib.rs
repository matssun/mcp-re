// SPDX-License-Identifier: Apache-2.0
//! `mcp-re-sdk-core` — the napi-rs native addon for the MCP-RE TypeScript SDK,
//! exposing the audited `mcp-re-client-core` RFC 9421 signing / verification seam
//! (ADR-MCPRE-050 sole carrier).
//!
//! The wire is RFC 9421 HTTP Message Signatures + RFC 9530 Content-Digest. There is
//! NO object/JCS `_meta` signature and NO canonicalization preimage.

use napi::bindgen_prelude::Buffer;
use napi_derive::napi;

use mcp_re_client_core::build_signed_request;
use mcp_re_client_core::verify_signed_response;
use mcp_re_client_core::ActorIdentity;
use mcp_re_client_core::ArtifactBinding;
use mcp_re_client_core::ArtifactType;
use mcp_re_client_core::AudienceTuple;
use mcp_re_client_core::HttpRequest;
use mcp_re_client_core::HttpResponse;
use mcp_re_client_core::RequestEvidence;
use mcp_re_client_core::RequestSigningInputs;
use mcp_re_client_core::ResolvedActor;
use mcp_re_client_core::ResponseExpectation;
use mcp_re_client_core::SignerSlot;
use mcp_re_client_core::PROFILE_TAG;
use mcp_re_core::SigningKey;
use mcp_re_core::VerificationKey;
use serde_json::Map;
use serde_json::Value;

fn parse_json(s: &str, what: &str) -> napi::Result<Value> {
    serde_json::from_str(s).map_err(|e| napi::Error::from_reason(format!("invalid {what} json: {e}")))
}
fn seed_to_key(seed: &[u8]) -> napi::Result<SigningKey> {
    if seed.len() != 32 {
        return Err(napi::Error::from_reason("signing seed must be exactly 32 bytes"));
    }
    let mut s = [0u8; 32];
    s.copy_from_slice(seed);
    Ok(SigningKey::from_seed_bytes(&s))
}

/// One HTTP header (name/value pair) on the RFC 9421 request/response.
#[napi(object)]
pub struct HttpHeader {
    pub key: String,
    pub value: String,
}

/// A signed RFC 9421 request.
#[napi(object)]
pub struct SignedRequestJs {
    pub method: String,
    pub target_uri: String,
    pub headers: Vec<HttpHeader>,
    pub body: Buffer,
    pub evidence_digest_alg: String,
    pub evidence_digest_value: String,
}

/// The audited SDK core version string.
#[napi]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// The RFC 9421 profile tag the signature is emitted/verified under.
#[napi]
pub fn profile_tag() -> String {
    PROFILE_TAG.to_string()
}

/// Sign an MCP request as an RFC 9421 + RFC 9530 message.
#[napi]
#[allow(clippy::too_many_arguments)]
pub fn sign_request(
    seed: Buffer,
    key_id: String,
    id_json: String,
    method: String,
    params_json: String,
    target_uri: String,
    audience_id: String,
    route: Option<String>,
    dpop_token: String,
    nonce: String,
    created: f64,
    expires: f64,
) -> napi::Result<SignedRequestJs> {
    let key = seed_to_key(seed.as_ref())?;
    let id = parse_json(&id_json, "id")?;
    let params: Map<String, Value> = match parse_json(&params_json, "params")? {
        Value::Object(m) => m,
        _ => return Err(napi::Error::from_reason("params must be a JSON object")),
    };
    let audience = AudienceTuple {
        audience_id,
        target_uri: target_uri.clone(),
        route,
    };
    let binding = ArtifactBinding::opaque_digest(ArtifactType::OauthDpop, dpop_token.as_bytes());
    let inputs = RequestSigningInputs::new(key_id, audience, vec![binding], nonce, created as i64, expires as i64)
        .with_headers(vec![("Authorization".to_owned(), format!("Bearer {dpop_token}"))]);
    let signed = build_signed_request(&id, &method, params, &target_uri, &inputs, &key)
        .map_err(|e| napi::Error::from_reason(format!("mcp-re: {}", e.wire_code())))?;
    let req = signed.request();
    Ok(SignedRequestJs {
        method: req.method.clone(),
        target_uri: req.target_uri.clone(),
        headers: req
            .headers
            .iter()
            .map(|(k, v)| HttpHeader { key: k.clone(), value: v.clone() })
            .collect(),
        body: Buffer::from(req.body.clone()),
        evidence_digest_alg: signed.evidence().digest_alg.clone(),
        evidence_digest_value: signed.evidence().digest_value.clone(),
    })
}

/// The outcome of verifying a signed RFC 9421 response.
#[napi(object)]
pub struct VerifyResultJs {
    pub ok: bool,
    pub server_keyid: String,
}

/// Verify a signed RFC 9421 response bound to the request the client sent.
#[napi]
#[allow(clippy::too_many_arguments)]
pub fn verify_response(
    status: u16,
    resp_headers: Vec<HttpHeader>,
    resp_body: Buffer,
    req_method: String,
    req_target_uri: String,
    req_headers: Vec<HttpHeader>,
    req_body: Buffer,
    req_evidence_digest_alg: String,
    req_evidence_digest_value: String,
    server_key_id: String,
    server_pubkey_b64url: String,
    server_role: String,
    server_trust_domain: String,
    server_subject: String,
    now: f64,
) -> napi::Result<VerifyResultJs> {
    let server_pub = VerificationKey::from_b64url(&server_pubkey_b64url)
        .map_err(|_| napi::Error::from_reason("invalid server public key"))?;
    let skid = server_key_id.clone();
    let sident = ActorIdentity {
        role: server_role,
        trust_domain: server_trust_domain,
        subject: server_subject,
        keyid: server_key_id.clone(),
    };
    let resolve = move |kid: &str, slot: SignerSlot| match slot {
        SignerSlot::Response if kid == skid => Some(ResolvedActor {
            identity: sident.clone(),
            verification_key: server_pub.clone(),
            slot,
        }),
        _ => None,
    };
    let to_pairs = |hs: Vec<HttpHeader>| hs.into_iter().map(|h| (h.key, h.value)).collect::<Vec<_>>();
    let response = HttpResponse {
        status,
        headers: to_pairs(resp_headers),
        body: resp_body.to_vec(),
    };
    let request = HttpRequest {
        method: req_method,
        target_uri: req_target_uri,
        headers: to_pairs(req_headers),
        body: req_body.to_vec(),
    };
    let evidence = RequestEvidence {
        digest_alg: req_evidence_digest_alg,
        digest_value: req_evidence_digest_value,
    };
    let expectation =
        ResponseExpectation::new(request, evidence).with_expected_server_signer(server_key_id);
    let verified = verify_signed_response(&response, &resolve, &expectation, now as i64)
        .map_err(|e| napi::Error::from_reason(format!("mcp-re: {}", e.wire_code())))?;
    Ok(VerifyResultJs {
        ok: true,
        server_keyid: verified.resolved_server_actor.identity.keyid,
    })
}
