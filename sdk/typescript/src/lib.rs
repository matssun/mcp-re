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

use mcp_re_client_core::build_signed_request;
use mcp_re_client_core::build_signed_request_with_signer;
use mcp_re_client_core::HttpProfileError;
use mcp_re_client_core::verify_delegated_response;
use mcp_re_client_core::ActorIdentity;
use mcp_re_client_core::ArtifactBinding;
use mcp_re_client_core::ArtifactType;
use mcp_re_client_core::AudienceTuple;
use mcp_re_client_core::BindingType;
use mcp_re_client_core::DelegationPolicy;
use mcp_re_client_core::HttpContinuation;
use mcp_re_client_core::HttpRequest;
use mcp_re_client_core::HttpResponse;
use mcp_re_client_core::RequestEvidence;
use mcp_re_client_core::RequestEvidenceDigest;
use mcp_re_client_core::RequestSigningInputs;
use mcp_re_client_core::ResolvedActor;
use mcp_re_client_core::ResponseExpectation;
use mcp_re_client_core::SignerSlot;
use mcp_re_client_core::StaticRevocationList;
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
fn params_object(params_json: &str) -> napi::Result<Map<String, Value>> {
    match parse_json(params_json, "params")? {
        Value::Object(m) => Ok(m),
        _ => Err(napi::Error::from_reason("params must be a JSON object")),
    }
}

/// The binding form a provider asks for (ADR-MCPS-044 §Authorization-binding hook).
#[derive(serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
enum BindingForm {
    /// The digest is over artifact bytes the client holds.
    OpaqueBytes,
    /// The digest is over artifact bytes the client holds, and the record additionally
    /// names the external authorization system that issued them, for cross-audit.
    AuthzSystemReference,
}

/// One provider-supplied artifact binding, before the core digests it.
///
/// `material_b64url` is the ARTIFACT ITSELF (base64url, no pad) — never a digest. The
/// core hashes it, so a caller cannot pass off a precomputed digest as the binding, and
/// the raw bytes never reach the evidence block.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
struct BindingSpec {
    artifact_type: ArtifactType,
    form: BindingForm,
    material_b64url: String,
    #[serde(default)]
    authorization_system_id: Option<String>,
    #[serde(default)]
    reference_scheme_id: Option<String>,
    #[serde(default)]
    reference_value: Option<String>,
}

/// Turn provider specs into validated `ArtifactBinding`s, digesting the real material.
///
/// Bindings are appended to the built-in DPoP binding, which stays header-derived.
fn build_bindings(bindings_json: &str) -> napi::Result<Vec<ArtifactBinding>> {
    let specs: Vec<BindingSpec> = serde_json::from_str(bindings_json)
        .map_err(|e| napi::Error::from_reason(format!("invalid bindings json: {e}")))?;
    specs
        .into_iter()
        .map(|s| {
            let material = mcp_re_core::b64url_decode(&s.material_b64url).map_err(|_| {
                napi::Error::from_reason("artifact material must be base64url (no pad)")
            })?;
            // The core digests the artifact; the caller never supplies digest_value.
            let mut b = ArtifactBinding::opaque_digest(s.artifact_type, &material);
            if matches!(s.form, BindingForm::AuthzSystemReference) {
                b.binding_type = BindingType::ReferenceDigest;
                b.authorization_system_id = s.authorization_system_id;
                b.reference_scheme_id = s.reference_scheme_id;
                b.reference_value = s.reference_value;
            }
            // Fail closed on a malformed shape: an opaque binding carrying reference
            // fields, or a reference binding missing any of them.
            b.validate()
                .map_err(|e| napi::Error::from_reason(format!("mcp-re: {}", e.wire_code())))?;
            Ok(b)
        })
        .collect()
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
    extra_bindings: Vec<ArtifactBinding>,
) -> RequestSigningInputs {
    let audience = AudienceTuple {
        audience_id,
        target_uri: target_uri.to_owned(),
        route,
    };
    // DPoP stays the built-in, header-derived binding: its credential is the covered
    // `Authorization: Bearer` header, so it is never provider-supplied. Provider bindings
    // are appended after it.
    let mut bindings =
        vec![ArtifactBinding::opaque_digest(ArtifactType::OauthDpop, dpop_token.as_bytes())];
    bindings.extend(extra_bindings);
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
    inputs
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
        match bindings_json.as_deref() {
            Some(j) => build_bindings(j)?,
            None => Vec::new(),
        },
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
        match bindings_json.as_deref() {
            Some(j) => build_bindings(j)?,
            None => Vec::new(),
        },
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
    let signed = build_signed_request_with_signer(&id, &method, params, &target_uri, &inputs, sign_base)
        .map_err(|e| napi::Error::from_reason(format!("mcp-re: {}", e.wire_code())))?;
    Ok(to_signed_request(signed))
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
    /// The verified response's evidence-handle digest algorithm — the
    /// `input_required_response_evidence` handle an MRTR answer leg binds to
    /// (ADR-MCPS-047). Read from the VERIFIED response only.
    pub resp_evidence_digest_alg: String,
    /// The verified response's evidence-handle digest value (base64url, no pad).
    pub resp_evidence_digest_value: String,
    /// `result.requestState` (a string) from the verified response body IFF it is an
    /// `InputRequiredResult` (`result.resultType == "input_required"`); else absent.
    /// The opaque MRTR state the answer leg re-presents. Read only after the response
    /// verified as genuine evidence.
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
    let ikid = issuer_key_id.clone();
    // The trusted ROOT ISSUER anchor for the Response slot: the credential chains to
    // it. The delegated key itself is authorized by the credential, never enrolled.
    let iident = ActorIdentity {
        role: issuer_role,
        trust_domain: issuer_trust_domain,
        subject: issuer_subject,
        keyid: issuer_key_id,
    };
    let resolve = move |kid: &str, slot: SignerSlot| match slot {
        SignerSlot::Response if kid == ikid => Some(ResolvedActor {
            identity: iident.clone(),
            verification_key: issuer_pub.clone(),
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
    let expectation = ResponseExpectation::new(request, evidence);
    let policy = DelegationPolicy::new(
        verifier_audiences,
        &expected_audience_hash,
        accepted_epochs,
        max_clock_skew as i64,
    );
    let revocation = StaticRevocationList::from_identifiers(revoked_identifiers);
    let verified =
        verify_delegated_response(&response, &resolve, &expectation, &policy, &revocation, now as i64)
            .map_err(|e| napi::Error::from_reason(format!("mcp-re: {}", e.wire_code())))?;
    // A verified rejection receipt is genuine evidence but NOT an acceptance — surface
    // the outcome so the caller does not read a signed replay/trust rejection as a
    // success. (An unsigned / direct-root / forged answer never reaches here: it fails
    // verify_delegated_response above and is raised as an error.)
    let (outcome, wire_code, bound) = match verified.outcome {
        mcp_re_client_core::DelegatedOutcome::Success => ("success".to_owned(), None, true),
        mcp_re_client_core::DelegatedOutcome::Rejection { bound, wire_code } => {
            ("rejection".to_owned(), wire_code, bound)
        }
    };
    // The response evidence handle (D_irr): the answer leg binds to it. Read from the
    // VERIFIED response evidence, never from unverified bytes.
    let resp_digest = verified.verified.response_signature_base_digest.clone();
    // `result.requestState` only if this is an InputRequiredResult — a terminal reply
    // has none. Read after verification: content-digest covered the body.
    let request_state = serde_json::from_slice::<Value>(resp_body.as_ref())
        .ok()
        .as_ref()
        .and_then(|v| v.get("result"))
        .filter(|r| r.get("resultType").and_then(|t| t.as_str()) == Some("input_required"))
        .and_then(|r| r.get("requestState"))
        .and_then(|s| s.as_str())
        .map(str::to_owned);
    Ok(VerifyResultJs {
        ok: true,
        server_keyid: verified.verified.resolved_server_actor.identity.keyid,
        outcome,
        wire_code,
        bound,
        resp_evidence_digest_alg: resp_digest.digest_alg,
        resp_evidence_digest_value: resp_digest.digest_value,
        request_state,
    })
}
