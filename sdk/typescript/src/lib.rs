// SPDX-License-Identifier: Apache-2.0
//! `mcp-re-sdk-core` — the napi-rs native addon for the MCP-RE TypeScript SDK,
//! exposing the audited `mcp-re-client-core` RFC 9421 signing / verification seam
//! (ADR-MCPRE-050 sole carrier).
//!
//! The wire is RFC 9421 HTTP Message Signatures + RFC 9530 Content-Digest; the
//! signature rides in the HTTP headers, not a JSON-RPC `_meta` block.
//!
//! Two custody classes are exposed (ADR-MCPS-044 §Compliance): `signRequest` takes a
//! raw seed (software custody), and `signRequestWithSigner` takes only a sign
//! callback, so the private key never enters the SDK (non-exporting custody).

use napi::bindgen_prelude::Buffer;
use napi::bindgen_prelude::Function;
use napi_derive::napi;

use mcp_re_client_core::build_authorization;
use mcp_re_client_core::build_signed_notification;
use mcp_re_client_core::build_signed_notification_with_signer;
use mcp_re_client_core::build_signed_request;
use mcp_re_client_core::build_signed_request_with_signer;
use mcp_re_client_core::verify_delegated_accepted_202;
use mcp_re_client_core::verify_delegated_response;
use mcp_re_client_core::ArtifactBinding;
use mcp_re_client_core::ArtifactType;
use mcp_re_client_core::AudienceTuple;
use mcp_re_client_core::DelegationPolicy;
use mcp_re_client_core::HttpContinuation;
use mcp_re_client_core::HttpProfileError;
use mcp_re_client_core::HttpRequest;
use mcp_re_client_core::HttpResponse;
use mcp_re_client_core::ProvidedAuthorization;
use mcp_re_client_core::RequestEvidence;
use mcp_re_client_core::RequestEvidenceDigest;
use mcp_re_client_core::RequestSigningInputs;
use mcp_re_client_core::ResponseExpectation;
mod trust;
use trust::pinned_root_resolver;

use mcp_re_client_core::CompositeResponseTrust;
use mcp_re_client_core::StaticRevocationList;
use mcp_re_client_core::PROFILE_TAG;
use mcp_re_core::SigningKey;
use mcp_re_core::VerificationKey;
use serde_json::Map;
use serde_json::Value;

fn parse_json(s: &str, what: &str) -> napi::Result<Value> {
    serde_json::from_str(s)
        .map_err(|e| napi::Error::from_reason(format!("invalid {what} json: {e}")))
}
fn seed_to_key(seed: &[u8]) -> napi::Result<SigningKey> {
    if seed.len() != 32 {
        return Err(napi::Error::from_reason(
            "signing seed must be exactly 32 bytes",
        ));
    }
    let mut s = [0u8; 32];
    s.copy_from_slice(seed);
    Ok(SigningKey::from_seed_bytes(&s))
}
fn params_object(params_json: &str) -> napi::Result<Map<String, Value>> {
    match parse_json(params_json, "params")? {
        Value::Object(m) => Ok(m),
        _ => Err(napi::Error::from_reason("params must be a JSON object")),
    }
}

/// The RFC 9421 signing inputs shared by both custody paths: the signed audience
/// tuple, the DPoP artifact binding whose credential is the covered `Authorization`
/// header, and — for an ADR-MCPS-047 MRTR answer leg — the signed continuation.
///
/// The continuation is folded in only when all five handles are present, built from
/// the two evidence-handle digests the client already holds (its OPEN-leg sign handle
/// and the verified response handle) plus the opaque `requestState`; no raw signature
/// bases are retained.
#[allow(clippy::too_many_arguments)]
fn signing_inputs(
    key_id: String,
    audience_id: String,
    target_uri: &str,
    route: Option<String>,
    dpop_token: &str,
    nonce: String,
    created: f64,
    expires: f64,
    cont_prev_alg: Option<String>,
    cont_prev_value: Option<String>,
    cont_irr_alg: Option<String>,
    cont_irr_value: Option<String>,
    cont_request_state: Option<String>,
    provided: ProvidedAuthorization,
) -> RequestSigningInputs {
    let audience = AudienceTuple {
        audience_id,
        target_uri: target_uri.to_owned(),
        route,
    };
    // DPoP stays the built-in, header-derived binding: its credential is the covered
    // `Authorization: Bearer` header, so it is never provider-supplied. Provider bindings
    // are appended after it.
    let mut bindings = vec![ArtifactBinding::opaque_digest(
        ArtifactType::OauthDpop,
        dpop_token.as_bytes(),
    )];
    bindings.extend(provided.bindings);
    let mut inputs = RequestSigningInputs::new(
        key_id,
        audience,
        bindings,
        nonce,
        created as i64,
        expires as i64,
    )
    .with_headers(vec![(
        "Authorization".to_owned(),
        format!("Bearer {dpop_token}"),
    )]);
    if let (Some(pa), Some(pv), Some(ia), Some(iv), Some(state)) = (
        cont_prev_alg,
        cont_prev_value,
        cont_irr_alg,
        cont_irr_value,
        cont_request_state,
    ) {
        let continuation = HttpContinuation::from_handles(
            RequestEvidenceDigest {
                digest_alg: pa,
                digest_value: pv,
            },
            RequestEvidenceDigest {
                digest_alg: ia,
                digest_value: iv,
            },
            state.as_bytes(),
        );
        inputs = inputs.with_continuation(continuation);
    }
    if let Some(jws) = provided.decision {
        // The document goes in; the `pdp-decision` binding over it is minted there, from
        // these exact bytes, so nothing in this file can make the two disagree.
        inputs = inputs.with_authorization_decision(jws);
    }
    inputs
}

/// Deserialize a provider list into the bindings and decision it contributes.
///
/// The rule lives in `mcp-re-client-core`, not here: the spec JSON is a public seam that
/// the TypeScript wrapper classes do not stand in front of, and one implementation is what
/// keeps this binding and the PyO3 one from drifting apart on it.
fn provided_authorization(bindings_json: Option<&str>) -> napi::Result<ProvidedAuthorization> {
    let Some(json) = bindings_json else {
        return Ok(ProvidedAuthorization::default());
    };
    build_authorization(json)
        .map_err(|r| napi::Error::from_reason(format!("mcp-re: {}", r.wire_code())))
}

fn to_signed_request(signed: mcp_re_client_core::SignedRequest) -> SignedRequestJs {
    let req = signed.request();
    SignedRequestJs {
        method: req.method.clone(),
        target_uri: req.target_uri.clone(),
        headers: req
            .headers
            .iter()
            .map(|(k, v)| HttpHeader {
                key: k.clone(),
                value: v.clone(),
            })
            .collect(),
        body: Buffer::from(req.body.clone()),
        evidence_digest_alg: signed.evidence().digest_alg.clone(),
        evidence_digest_value: signed.evidence().digest_value.clone(),
    }
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

/// Sign exact preimage bytes with a raw seed, returning the 64-byte detached Ed25519
/// signature — the primitive a `SigningDevice` (the HSM/KMS stand-in) is built on.
///
/// This is the same operation the software signing path performs internally, so a
/// device-delegated signature is byte-identical to the in-process one.
#[napi]
pub fn sign_preimage(seed: Buffer, preimage: Buffer) -> napi::Result<Buffer> {
    let key = seed_to_key(seed.as_ref())?;
    let sig = mcp_re_core::b64url_decode(&key.sign(preimage.as_ref()))
        .map_err(|_| napi::Error::from_reason("mcp-re: mcp-re.invalid_signature"))?;
    Ok(Buffer::from(sig))
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
    // ADR-MCPS-047 MRTR answer leg: bind this request to the `InputRequiredResult` it
    // answers. All five are `Some` together (or all `None` for an ordinary request):
    // the previous-request evidence digest (this client's OPEN-leg sign handle), the
    // input-required-response evidence digest (the OPEN-leg verify handle), and the
    // opaque `requestState`. The continuation rides inside the signed evidence block.
    cont_prev_alg: Option<String>,
    cont_prev_value: Option<String>,
    cont_irr_alg: Option<String>,
    cont_irr_value: Option<String>,
    cont_request_state: Option<String>,
    // Provider-supplied artifact bindings (ADR-MCPS-044 §Authorization-binding hook), as
    // a JSON array of specs carrying the artifact MATERIAL; the core digests it. Absent
    // means DPoP only — the frozen parity vectors sign through this path unchanged.
    bindings_json: Option<String>,
) -> napi::Result<SignedRequestJs> {
    let key = seed_to_key(seed.as_ref())?;
    let id = parse_json(&id_json, "id")?;
    let params = params_object(&params_json)?;
    let inputs = signing_inputs(
        key_id,
        audience_id,
        &target_uri,
        route,
        &dpop_token,
        nonce,
        created,
        expires,
        cont_prev_alg,
        cont_prev_value,
        cont_irr_alg,
        cont_irr_value,
        cont_request_state,
        provided_authorization(bindings_json.as_deref())?,
    );
    let signed = build_signed_request(&id, &method, params, &target_uri, &inputs, &key)
        .map_err(|e| napi::Error::from_reason(format!("mcp-re: {}", e.wire_code())))?;
    Ok(to_signed_request(signed))
}

/// Sign an MCP request under NON-EXPORTING custody: the private key never enters the
/// SDK (ADR-MCPS-044 §Compliance).
///
/// `signCallback` is the only thing held — `(preimage: Buffer) => Buffer` — a KMS/HSM
/// client call in production, invoked synchronously on the Node main thread. The SDK
/// composes the RFC 9421 signature base, hands those exact bytes to the device, and
/// takes back the detached Ed25519 signature; it never sees key material.
///
/// The produced evidence is byte-identical to the software path for the same inputs —
/// the key has only moved behind the device. A device that cannot sign, or that
/// returns anything other than 64 signature bytes, fails closed as
/// `mcp-re.invalid_signature`.
#[napi]
#[allow(clippy::too_many_arguments)]
pub fn sign_request_with_signer(
    sign_callback: Function<Buffer, Buffer>,
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
    cont_prev_alg: Option<String>,
    cont_prev_value: Option<String>,
    cont_irr_alg: Option<String>,
    cont_irr_value: Option<String>,
    cont_request_state: Option<String>,
    // Provider-supplied artifact bindings (ADR-MCPS-044 §Authorization-binding hook), as
    // a JSON array of specs carrying the artifact MATERIAL; the core digests it. Absent
    // means DPoP only — the frozen parity vectors sign through this path unchanged.
    bindings_json: Option<String>,
) -> napi::Result<SignedRequestJs> {
    let id = parse_json(&id_json, "id")?;
    let params = params_object(&params_json)?;
    let inputs = signing_inputs(
        key_id,
        audience_id,
        &target_uri,
        route,
        &dpop_token,
        nonce,
        created,
        expires,
        cont_prev_alg,
        cont_prev_value,
        cont_irr_alg,
        cont_irr_value,
        cont_request_state,
        provided_authorization(bindings_json.as_deref())?,
    );
    // The device seam. Any failure — the callback throwing, returning a non-Buffer
    // value, or returning a wrong-length signature — is an unusable signature and
    // fails closed rather than emitting unsigned or malformed evidence.
    let sign_base = |preimage: &[u8]| -> Result<Vec<u8>, HttpProfileError> {
        let out = sign_callback
            .call(Buffer::from(preimage.to_vec()))
            .map_err(|_| HttpProfileError::InvalidSignature)?;
        let sig = out.to_vec();
        if sig.len() != 64 {
            return Err(HttpProfileError::InvalidSignature);
        }
        Ok(sig)
    };
    let signed =
        build_signed_request_with_signer(&id, &method, params, &target_uri, &inputs, sign_base)
            .map_err(|e| napi::Error::from_reason(format!("mcp-re: {}", e.wire_code())))?;
    Ok(to_signed_request(signed))
}

/// The signing inputs for a notification: the request inputs minus the continuation,
/// which a message that receives no result cannot carry.
#[allow(clippy::too_many_arguments)]
fn notification_inputs(
    key_id: String,
    audience_id: String,
    target_uri: &str,
    route: Option<String>,
    dpop_token: &str,
    nonce: String,
    created: f64,
    expires: f64,
    bindings_json: Option<String>,
) -> napi::Result<RequestSigningInputs> {
    Ok(signing_inputs(
        key_id,
        audience_id,
        target_uri,
        route,
        dpop_token,
        nonce,
        created,
        expires,
        None,
        None,
        None,
        None,
        None,
        provided_authorization(bindings_json.as_deref())?,
    ))
}

/// Sign a one-way MCP **notification** — a JSON-RPC message with a `method` and no
/// `id` — as an RFC 9421 + RFC 9530 message.
///
/// Signed by the ordinary request rules; only the JSON-RPC envelope differs. The answer
/// is a signed bodyless `202`, checked with `verifyAccepted202`, not a bodied reply.
/// There are no continuation arguments: a message that receives no result cannot be an
/// ADR-MCPS-047 answer leg.
#[napi]
#[allow(clippy::too_many_arguments)]
pub fn sign_notification(
    seed: Buffer,
    key_id: String,
    method: String,
    params_json: String,
    target_uri: String,
    audience_id: String,
    route: Option<String>,
    dpop_token: String,
    nonce: String,
    created: f64,
    expires: f64,
    bindings_json: Option<String>,
) -> napi::Result<SignedRequestJs> {
    let key = seed_to_key(seed.as_ref())?;
    let params = params_object(&params_json)?;
    let inputs = notification_inputs(
        key_id,
        audience_id,
        &target_uri,
        route,
        &dpop_token,
        nonce,
        created,
        expires,
        bindings_json,
    )?;
    let signed = build_signed_notification(&method, params, &target_uri, &inputs, &key)
        .map_err(|e| napi::Error::from_reason(format!("mcp-re: {}", e.wire_code())))?;
    Ok(to_signed_request(signed))
}

/// Non-exporting-custody variant of `signNotification`: the private key never enters
/// the SDK. Wire-identical to the software path.
#[napi]
#[allow(clippy::too_many_arguments)]
pub fn sign_notification_with_signer(
    sign_callback: Function<Buffer, Buffer>,
    key_id: String,
    method: String,
    params_json: String,
    target_uri: String,
    audience_id: String,
    route: Option<String>,
    dpop_token: String,
    nonce: String,
    created: f64,
    expires: f64,
    bindings_json: Option<String>,
) -> napi::Result<SignedRequestJs> {
    let params = params_object(&params_json)?;
    let inputs = notification_inputs(
        key_id,
        audience_id,
        &target_uri,
        route,
        &dpop_token,
        nonce,
        created,
        expires,
        bindings_json,
    )?;
    let sign_base = |preimage: &[u8]| -> Result<Vec<u8>, HttpProfileError> {
        let out = sign_callback
            .call(Buffer::from(preimage.to_vec()))
            .map_err(|_| HttpProfileError::InvalidSignature)?;
        let sig = out.to_vec();
        if sig.len() != 64 {
            return Err(HttpProfileError::InvalidSignature);
        }
        Ok(sig)
    };
    let signed =
        build_signed_notification_with_signer(&method, params, &target_uri, &inputs, sign_base)
            .map_err(|e| napi::Error::from_reason(format!("mcp-re: {}", e.wire_code())))?;
    Ok(to_signed_request(signed))
}

/// The outcome of verifying a delegated-signed bodyless `202 Accepted`.
///
/// `ok` means the acknowledgement VERIFIED: the credential chained to the trusted root
/// and the delegated signature covered the acknowledgement AND bound it to the exact
/// notification transmission this client sent.
///
/// **What that claims, exactly: the enforcement boundary authenticated and accepted the
/// message.** NOT that the action completed, that the inner application observed it, or
/// that anything was done about it — a verified acknowledgement of
/// `notifications/cancelled` does not mean anything was cancelled.
#[napi(object)]
pub struct AcceptedResultJs {
    pub ok: bool,
    /// The delegated key id that signed the acknowledgement — never the root, which
    /// stays off the request path (ADR-MCPRE-052).
    pub server_keyid: String,
}

/// Verify the delegated-signed bodyless `202` a server returns for a one-way
/// notification, bound to the exact transmission this client sent.
///
/// The binding is INSTANCE-level (owner ruling C019b): the acknowledgement covers
/// `mcp-re-request-evidence`, the digest of the request's own signature base, which
/// includes its nonce. An acknowledgement captured for one transmission therefore does
/// not verify for a byte-identical retransmission.
#[napi]
#[allow(clippy::too_many_arguments)]
pub fn verify_accepted_202(
    status: u16,
    resp_headers: Vec<HttpHeader>,
    resp_body: Buffer,
    req_method: String,
    req_target_uri: String,
    req_headers: Vec<HttpHeader>,
    req_body: Buffer,
    issuer_key_id: String,
    issuer_pubkey_b64url: String,
    issuer_role: String,
    issuer_trust_domain: String,
    issuer_subject: String,
    verifier_audiences: Vec<String>,
    expected_audience_hash: String,
    accepted_epochs: Vec<String>,
    max_clock_skew: f64,
    revoked_identifiers: Vec<String>,
    now: f64,
) -> napi::Result<AcceptedResultJs> {
    let issuer_pub = VerificationKey::from_b64url(&issuer_pubkey_b64url)
        .map_err(|_| napi::Error::from_reason("invalid issuer public key"))?;
    let resolve = pinned_root_resolver(
        issuer_key_id,
        issuer_role,
        issuer_trust_domain,
        issuer_subject,
        issuer_pub,
    );
    let to_pairs =
        |hs: Vec<HttpHeader>| hs.into_iter().map(|h| (h.key, h.value)).collect::<Vec<_>>();
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
    let policy = DelegationPolicy::new(
        verifier_audiences,
        &expected_audience_hash,
        accepted_epochs,
        max_clock_skew as i64,
    );
    let revocation = StaticRevocationList::from_identifiers(revoked_identifiers);
    let trust = CompositeResponseTrust::new(&resolve, &revocation);
    let actor = verify_delegated_accepted_202(&response, &request, &trust, &policy, now as i64)
        .map_err(|e| napi::Error::from_reason(format!("mcp-re: {}", e.wire_code())))?;
    Ok(AcceptedResultJs {
        ok: true,
        server_keyid: actor.identity.keyid,
    })
}

/// The outcome of verifying a delegated-required RFC 9421 response.
#[napi(object)]
pub struct VerifyResultJs {
    pub ok: bool,
    pub server_keyid: String,
    /// `"success"` for an accepted answer; `"rejection"` for a verified rejection
    /// receipt — genuine evidence, but NOT an acceptance.
    pub outcome: String,
    /// The wire code carried by a verified rejection receipt; absent on success.
    pub wire_code: Option<String>,
    /// Whether a rejection receipt is bound to this client's request.
    pub bound: bool,
    /// The ADR-MCPRE-058 §10 execution/retry contract the server derived from its
    /// exchange machine and signed into the rejection body. Absent on success and on a
    /// receipt that stated nothing.
    ///
    /// An ABSENT `execution_status` is not `"not_executed"`. The server states a
    /// disposition when it has one, and collapsing silence into "nothing ran" is
    /// exactly the read that makes a post-dispatch refusal look retry-safe.
    pub execution_status: Option<String>,
    /// `retry_safety`: what a retry of this refused request would cost.
    pub retry_safety: Option<String>,
    /// `continuation_status`: whether the exchange consumed a human approval.
    pub continuation_status: Option<String>,
    /// `retention_status`: whether the server's evidence-retention obligation failed.
    pub retention_status: Option<String>,
    /// The verified response's evidence-handle digest algorithm — the
    /// `input_required_response_evidence` handle an MRTR answer leg binds to
    /// (ADR-MCPS-047). Read from the VERIFIED response only.
    pub resp_evidence_digest_alg: String,
    /// The verified response's evidence-handle digest value (base64url, no pad).
    pub resp_evidence_digest_value: String,
    /// `result.requestState` (a string) from the verified response body IFF the
    /// audited classifier reads it as an `InputRequiredResult`; else absent. The
    /// opaque MRTR state the answer leg re-presents. Read only after the response
    /// verified as genuine evidence.
    ///
    /// The discriminator itself is deliberately not restated here — it lives in
    /// `mcp_re_http_profile::result_class`, and a doc comment repeating it is one
    /// more copy to drift. A verified reply that declares itself non-terminal
    /// without a usable state is an ERROR, never an absent state.
    pub request_state: Option<String>,
}

/// Verify a delegated-required RFC 9421 response bound to the request the client sent.
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
    issuer_key_id: String,
    issuer_pubkey_b64url: String,
    issuer_role: String,
    issuer_trust_domain: String,
    issuer_subject: String,
    verifier_audiences: Vec<String>,
    expected_audience_hash: String,
    accepted_epochs: Vec<String>,
    max_clock_skew: f64,
    revoked_identifiers: Vec<String>,
    now: f64,
) -> napi::Result<VerifyResultJs> {
    let issuer_pub = VerificationKey::from_b64url(&issuer_pubkey_b64url)
        .map_err(|_| napi::Error::from_reason("invalid issuer public key"))?;
    let resolve = pinned_root_resolver(
        issuer_key_id,
        issuer_role,
        issuer_trust_domain,
        issuer_subject,
        issuer_pub,
    );
    let to_pairs =
        |hs: Vec<HttpHeader>| hs.into_iter().map(|h| (h.key, h.value)).collect::<Vec<_>>();
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
    let expectation = ResponseExpectation::new(request, evidence);
    let policy = DelegationPolicy::new(
        verifier_audiences,
        &expected_audience_hash,
        accepted_epochs,
        max_clock_skew as i64,
    );
    let revocation = StaticRevocationList::from_identifiers(revoked_identifiers);
    let trust = CompositeResponseTrust::new(&resolve, &revocation);
    let verified = verify_delegated_response(&response, &trust, &expectation, &policy, now as i64)
        .map_err(|e| napi::Error::from_reason(format!("mcp-re: {}", e.wire_code())))?;
    // A verified rejection receipt is genuine evidence but NOT an acceptance — surface
    // the outcome so the caller does not read a signed replay/trust rejection as a
    // success. (An unsigned / direct-root / forged answer never reaches here: it fails
    // verify_delegated_response above and is raised as an error.)
    let ev = &verified.verified;
    let (outcome, wire_code, bound, execution) = match verified.outcome {
        mcp_re_client_core::DelegatedOutcome::Success => (
            "success".to_owned(),
            None,
            true,
            mcp_re_client_core::ExecutionContract::default(),
        ),
        mcp_re_client_core::DelegatedOutcome::Rejection {
            wire_code,
            execution,
        } => ("rejection".to_owned(), wire_code, ev.is_bound(), execution),
    };
    // The response evidence handle (D_irr): the answer leg binds to it. Read from the
    // VERIFIED response evidence, never from unverified bytes.
    let resp_digest = ev.response_signature_base_digest().clone();
    // `result.requestState` only if this is an InputRequiredResult — a terminal reply
    // has none. Read after verification: content-digest covered the body. Classified
    // by the audited core, which REFUSES rather than reporting as terminal both a reply
    // that declares itself non-terminal without a usable state and one whose
    // `resultType` is outside the set MCP 2026-07-28 defines (MCPRE-495).
    let request_state = mcp_re_client_core::continuation_state(resp_body.as_ref())
        .map_err(|e| napi::Error::from_reason(format!("mcp-re: {}", e.wire_code())))?;
    Ok(VerifyResultJs {
        ok: true,
        server_keyid: ev.accepted_signer().identity.keyid.clone(),
        outcome,
        wire_code,
        bound,
        execution_status: execution.execution_status,
        retry_safety: execution.retry_safety,
        continuation_status: execution.continuation_status,
        retention_status: execution.retention_status,
        resp_evidence_digest_alg: resp_digest.digest_alg,
        resp_evidence_digest_value: resp_digest.digest_value,
        request_state,
    })
}
