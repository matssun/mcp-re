// SPDX-License-Identifier: Apache-2.0
//! PyO3 binding exposing the audited `mcp-re-client-core` RFC 9421 signing /
//! verification seam to the MCP-RE Python SDK (ADR-MCPRE-050 sole carrier).
//!
//! The wire is RFC 9421 HTTP Message Signatures + RFC 9530 Content-Digest — the SDK
//! signs and verifies the HTTP evidence carrier only; the signature rides in the HTTP
//! headers, not a JSON-RPC `_meta` block.
//!
//! Two custody classes are exposed (ADR-MCPS-044 §Compliance): `sign_request` takes a
//! raw seed (software custody), and `sign_request_with_signer` takes only a sign
//! callback, so the private key never enters the SDK (non-exporting custody).

mod trust;
use trust::pinned_root_resolver;

use pyo3::prelude::*;
use pyo3::types::PyBytes;

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
use mcp_re_client_core::CompositeResponseTrust;
use mcp_re_client_core::DelegationPolicy;
use mcp_re_client_core::HttpContinuation;
use mcp_re_client_core::HttpProfileError;
use mcp_re_client_core::HttpRequest;
use mcp_re_client_core::HttpResponse;
use mcp_re_client_core::ProvidedAuthorization;
use mcp_re_client_core::RequestEvidenceDigest;
use mcp_re_client_core::RequestSigningInputs;
use mcp_re_client_core::ResponseExpectation;
use mcp_re_client_core::StaticRevocationList;
use mcp_re_client_core::PROFILE_TAG;
use mcp_re_core::SigningKey;
use mcp_re_core::VerificationKey;
use serde_json::Map;
use serde_json::Value;

fn err(e: HttpProfileError) -> PyErr {
    pyo3::exceptions::PyValueError::new_err(format!("mcp-re: {}", e.wire_code()))
}
fn seed_to_key(seed: &[u8]) -> PyResult<SigningKey> {
    if seed.len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "signing seed must be exactly 32 bytes",
        ));
    }
    let mut s = [0u8; 32];
    s.copy_from_slice(seed);
    Ok(SigningKey::from_seed_bytes(&s))
}
fn parse_json(s: &str, what: &str) -> PyResult<Value> {
    serde_json::from_str(s)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("invalid {what} json: {e}")))
}
fn params_object(params_json: &str) -> PyResult<Map<String, Value>> {
    match parse_json(params_json, "params")? {
        Value::Object(m) => Ok(m),
        _ => Err(pyo3::exceptions::PyValueError::new_err(
            "params must be a JSON object",
        )),
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
    key_id: &str,
    audience_id: &str,
    target_uri: &str,
    route: Option<String>,
    dpop_token: &str,
    nonce: &str,
    created: i64,
    expires: i64,
    cont_prev_alg: Option<String>,
    cont_prev_value: Option<String>,
    cont_irr_alg: Option<String>,
    cont_irr_value: Option<String>,
    cont_request_state: Option<String>,
    provided: ProvidedAuthorization,
) -> RequestSigningInputs {
    let audience = AudienceTuple {
        audience_id: audience_id.to_owned(),
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
    let mut inputs = RequestSigningInputs::new(key_id, audience, bindings, nonce, created, expires)
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
/// the Python wrapper classes do not stand in front of, and one implementation is what
/// keeps this binding and the N-API one from drifting apart on it.
fn provided_authorization(bindings_json: Option<&str>) -> PyResult<ProvidedAuthorization> {
    let Some(json) = bindings_json else {
        return Ok(ProvidedAuthorization::default());
    };
    build_authorization(json)
        .map_err(|r| pyo3::exceptions::PyValueError::new_err(format!("mcp-re: {}", r.wire_code())))
}

fn to_signed_request(signed: mcp_re_client_core::SignedRequest) -> PySignedRequest {
    let req = signed.request();
    PySignedRequest {
        method: req.method.clone(),
        target_uri: req.target_uri.clone(),
        headers: req.headers.clone(),
        body_bytes: req.body.clone(),
        evidence_digest_alg: signed.evidence().digest_alg.clone(),
        evidence_digest_value: signed.evidence().digest_value.clone(),
    }
}

/// The audited SDK core version string.
#[pyfunction]
fn core_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The RFC 9421 profile tag the signature is emitted/verified under.
#[pyfunction]
fn profile_tag() -> &'static str {
    PROFILE_TAG
}

/// Sign exact preimage bytes with a raw seed, returning the 64-byte detached Ed25519
/// signature — the primitive a `SigningDevice` (the HSM/KMS stand-in) is built on.
///
/// This is the same operation the software signing path performs internally, so a
/// device-delegated signature is byte-identical to the in-process one.
#[pyfunction]
fn sign_preimage<'py>(
    py: Python<'py>,
    seed: &[u8],
    preimage: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let key = seed_to_key(seed)?;
    let sig = mcp_re_core::b64url_decode(&key.sign(preimage))
        .map_err(|_| err(HttpProfileError::InvalidSignature))?;
    Ok(PyBytes::new(py, &sig))
}

/// A signed RFC 9421 request: the HTTP method + `@target-uri` + headers (carrying
/// `Signature`/`Signature-Input`/`Content-Digest`) + body, plus the request
/// evidence handle that binds a later signed response.
#[pyclass]
struct PySignedRequest {
    #[pyo3(get)]
    method: String,
    #[pyo3(get)]
    target_uri: String,
    #[pyo3(get)]
    headers: Vec<(String, String)>,
    body_bytes: Vec<u8>,
    #[pyo3(get)]
    evidence_digest_alg: String,
    #[pyo3(get)]
    evidence_digest_value: String,
}

#[pymethods]
impl PySignedRequest {
    /// The serialized JSON-RPC request body bytes to POST.
    fn body<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.body_bytes)
    }
}

/// Sign an MCP request as an RFC 9421 + RFC 9530 message.
///
/// `dpop_token` is bound as an OAuth-DPoP artifact binding whose credential is the
/// covered `Authorization: Bearer` header. `created`/`expires` are Unix seconds.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
#[pyo3(signature = (
    seed, key_id, id_json, method, params_json, target_uri, audience_id, route,
    dpop_token, nonce, created, expires,
    cont_prev_alg=None, cont_prev_value=None, cont_irr_alg=None, cont_irr_value=None,
    cont_request_state=None, bindings_json=None,
))]
fn sign_request(
    seed: &[u8],
    key_id: &str,
    id_json: &str,
    method: &str,
    params_json: &str,
    target_uri: &str,
    audience_id: &str,
    route: Option<String>,
    dpop_token: &str,
    nonce: &str,
    created: i64,
    expires: i64,
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
) -> PyResult<PySignedRequest> {
    let key = seed_to_key(seed)?;
    let id = parse_json(id_json, "id")?;
    let params = params_object(params_json)?;
    let inputs = signing_inputs(
        key_id,
        audience_id,
        target_uri,
        route,
        dpop_token,
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
    let signed =
        build_signed_request(&id, method, params, target_uri, &inputs, &key).map_err(err)?;
    Ok(to_signed_request(signed))
}

/// Sign an MCP request under NON-EXPORTING custody: the private key never enters the
/// SDK (ADR-MCPS-044 §Compliance).
///
/// `sign_callback` is the only thing held — `(preimage: bytes) -> bytes` — a KMS/HSM
/// client call in production, invoked synchronously while the GIL is held. The SDK
/// composes the RFC 9421 signature base, hands those exact bytes to the device, and
/// takes back the detached Ed25519 signature; it never sees key material.
///
/// The produced evidence is byte-identical to the software path for the same inputs —
/// the key has only moved behind the device. A device that cannot sign, or that
/// returns anything other than signature bytes, fails closed as
/// `mcp-re.invalid_signature`.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
#[pyo3(signature = (
    sign_callback, key_id, id_json, method, params_json, target_uri, audience_id, route,
    dpop_token, nonce, created, expires,
    cont_prev_alg=None, cont_prev_value=None, cont_irr_alg=None, cont_irr_value=None,
    cont_request_state=None, bindings_json=None,
))]
fn sign_request_with_signer(
    py: Python<'_>,
    sign_callback: Py<PyAny>,
    key_id: &str,
    id_json: &str,
    method: &str,
    params_json: &str,
    target_uri: &str,
    audience_id: &str,
    route: Option<String>,
    dpop_token: &str,
    nonce: &str,
    created: i64,
    expires: i64,
    cont_prev_alg: Option<String>,
    cont_prev_value: Option<String>,
    cont_irr_alg: Option<String>,
    cont_irr_value: Option<String>,
    cont_request_state: Option<String>,
    // Provider-supplied artifact bindings (ADR-MCPS-044 §Authorization-binding hook), as
    // a JSON array of specs carrying the artifact MATERIAL; the core digests it. Absent
    // means DPoP only — the frozen parity vectors sign through this path unchanged.
    bindings_json: Option<String>,
) -> PyResult<PySignedRequest> {
    let id = parse_json(id_json, "id")?;
    let params = params_object(params_json)?;
    let inputs = signing_inputs(
        key_id,
        audience_id,
        target_uri,
        route,
        dpop_token,
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
    // The device seam. Any failure — the callback raising, returning a non-bytes
    // value, or returning a wrong-length signature — is an unusable signature and
    // fails closed rather than emitting unsigned or malformed evidence.
    let sign_base = |preimage: &[u8]| -> Result<Vec<u8>, HttpProfileError> {
        let out = sign_callback
            .call1(py, (PyBytes::new(py, preimage),))
            .map_err(|_| HttpProfileError::InvalidSignature)?;
        let sig: Vec<u8> = out
            .extract(py)
            .map_err(|_| HttpProfileError::InvalidSignature)?;
        if sig.len() != 64 {
            return Err(HttpProfileError::InvalidSignature);
        }
        Ok(sig)
    };
    let signed =
        build_signed_request_with_signer(&id, method, params, target_uri, &inputs, sign_base)
            .map_err(err)?;
    Ok(to_signed_request(signed))
}

/// Sign a one-way MCP **notification** — a JSON-RPC message with a `method` and no
/// `id` — as an RFC 9421 + RFC 9530 message.
///
/// Signed by the ordinary request rules; only the JSON-RPC envelope differs. The
/// answer is a signed bodyless `202`, checked with [`verify_accepted_202`], not a
/// bodied reply. There are no continuation arguments: a message that receives no
/// result cannot be an ADR-MCPS-047 answer leg.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
#[pyo3(signature = (
    seed, key_id, method, params_json, target_uri, audience_id, route,
    dpop_token, nonce, created, expires, bindings_json=None,
))]
fn sign_notification(
    seed: &[u8],
    key_id: &str,
    method: &str,
    params_json: &str,
    target_uri: &str,
    audience_id: &str,
    route: Option<String>,
    dpop_token: &str,
    nonce: &str,
    created: i64,
    expires: i64,
    bindings_json: Option<String>,
) -> PyResult<PySignedRequest> {
    let key = seed_to_key(seed)?;
    let params = params_object(params_json)?;
    let inputs = notification_inputs(
        key_id,
        audience_id,
        target_uri,
        route,
        dpop_token,
        nonce,
        created,
        expires,
        bindings_json,
    )?;
    let signed =
        build_signed_notification(method, params, target_uri, &inputs, &key).map_err(err)?;
    Ok(to_signed_request(signed))
}

/// Non-exporting-custody variant of [`sign_notification`]: the private key never
/// enters the SDK. Wire-identical to the software path.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
#[pyo3(signature = (
    sign_callback, key_id, method, params_json, target_uri, audience_id, route,
    dpop_token, nonce, created, expires, bindings_json=None,
))]
fn sign_notification_with_signer(
    py: Python<'_>,
    sign_callback: Py<PyAny>,
    key_id: &str,
    method: &str,
    params_json: &str,
    target_uri: &str,
    audience_id: &str,
    route: Option<String>,
    dpop_token: &str,
    nonce: &str,
    created: i64,
    expires: i64,
    bindings_json: Option<String>,
) -> PyResult<PySignedRequest> {
    let params = params_object(params_json)?;
    let inputs = notification_inputs(
        key_id,
        audience_id,
        target_uri,
        route,
        dpop_token,
        nonce,
        created,
        expires,
        bindings_json,
    )?;
    let sign_base = |preimage: &[u8]| -> Result<Vec<u8>, HttpProfileError> {
        let out = sign_callback
            .call1(py, (PyBytes::new(py, preimage),))
            .map_err(|_| HttpProfileError::InvalidSignature)?;
        let sig: Vec<u8> = out
            .extract(py)
            .map_err(|_| HttpProfileError::InvalidSignature)?;
        if sig.len() != 64 {
            return Err(HttpProfileError::InvalidSignature);
        }
        Ok(sig)
    };
    let signed =
        build_signed_notification_with_signer(method, params, target_uri, &inputs, sign_base)
            .map_err(err)?;
    Ok(to_signed_request(signed))
}

/// The signing inputs for a notification: the request inputs minus the continuation,
/// which a message that receives no result cannot carry.
#[allow(clippy::too_many_arguments)]
fn notification_inputs(
    key_id: &str,
    audience_id: &str,
    target_uri: &str,
    route: Option<String>,
    dpop_token: &str,
    nonce: &str,
    created: i64,
    expires: i64,
    bindings_json: Option<String>,
) -> PyResult<RequestSigningInputs> {
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
#[pyclass]
struct PyAcceptedResult {
    #[pyo3(get)]
    ok: bool,
    /// The delegated key id that signed the acknowledgement — never the root, which
    /// stays off the request path (ADR-MCPRE-052).
    #[pyo3(get)]
    server_keyid: String,
}

/// Verify the delegated-signed bodyless `202` a server returns for a one-way
/// notification, bound to the exact transmission this client sent.
///
/// The binding is INSTANCE-level (owner ruling C019b): the acknowledgement covers
/// `mcp-re-request-evidence`, the digest of the request's own signature base, which
/// includes its nonce. An acknowledgement captured for one transmission therefore does
/// not verify for a byte-identical retransmission.
///
/// Same trust inputs as `verify_response`: the ROOT ISSUER anchor, the audience scope,
/// the accepted trust epochs, and the client's static denylist. Anything unsigned,
/// direct-root-signed, revoked, stale-epoch, or bound to a different transmission fails
/// closed as a `ValueError` carrying the frozen wire code.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
fn verify_accepted_202(
    status: u16,
    resp_headers: Vec<(String, String)>,
    resp_body: &[u8],
    req_method: &str,
    req_target_uri: &str,
    req_headers: Vec<(String, String)>,
    req_body: &[u8],
    issuer_key_id: &str,
    issuer_pubkey_b64url: &str,
    issuer_role: &str,
    issuer_trust_domain: &str,
    issuer_subject: &str,
    verifier_audiences: Vec<String>,
    expected_audience_hash: &str,
    accepted_epochs: Vec<String>,
    max_clock_skew: i64,
    revoked_identifiers: Vec<String>,
    now: i64,
) -> PyResult<PyAcceptedResult> {
    let issuer_pub = VerificationKey::from_b64url(issuer_pubkey_b64url)
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("invalid issuer public key"))?;
    let resolve = pinned_root_resolver(
        issuer_key_id,
        issuer_role,
        issuer_trust_domain,
        issuer_subject,
        issuer_pub,
    );
    let response = HttpResponse {
        status,
        headers: resp_headers,
        body: resp_body.to_vec(),
    };
    let request = HttpRequest {
        method: req_method.to_owned(),
        target_uri: req_target_uri.to_owned(),
        headers: req_headers,
        body: req_body.to_vec(),
    };
    let policy = DelegationPolicy::new(
        verifier_audiences,
        expected_audience_hash,
        accepted_epochs,
        max_clock_skew,
    );
    let revocation = StaticRevocationList::from_identifiers(revoked_identifiers);
    let trust = CompositeResponseTrust::new(&resolve, &revocation);
    let actor =
        verify_delegated_accepted_202(&response, &request, &trust, &policy, now).map_err(err)?;
    Ok(PyAcceptedResult {
        ok: true,
        server_keyid: actor.identity.keyid,
    })
}

/// The outcome of verifying a delegated-required RFC 9421 response.
///
/// `ok` means the evidence VERIFIED (the credential chained to the trusted root and
/// the delegated signature covered the message) — it does NOT mean the request
/// succeeded. `outcome` distinguishes a verified SUCCESS (`"success"`) from a verified
/// REJECTION receipt (`"rejection"`): a delegated-signed fail-closed answer (e.g. a
/// replay or trust rejection) verifies as genuine evidence but is NOT an acceptance.
/// For a rejection, `wire_code` carries the server's frozen `mcp-re.*` reason from the
/// verified body. A caller decides acceptance on `outcome == "success"`.
#[pyclass]
struct PyVerifyResult {
    #[pyo3(get)]
    ok: bool,
    #[pyo3(get)]
    server_keyid: String,
    #[pyo3(get)]
    outcome: String,
    #[pyo3(get)]
    wire_code: Option<String>,
    #[pyo3(get)]
    bound: bool,
    /// The ADR-MCPRE-058 §10 execution/retry contract the server derived from its
    /// exchange machine and signed into the rejection body. Absent on success and on a
    /// receipt that stated nothing.
    ///
    /// An ABSENT `execution_status` is not `"not_executed"`. The server states a
    /// disposition when it has one, and collapsing silence into "nothing ran" is
    /// exactly the read that makes a post-dispatch refusal look retry-safe.
    #[pyo3(get)]
    execution_status: Option<String>,
    /// `retry_safety`: what a retry of this refused request would cost.
    #[pyo3(get)]
    retry_safety: Option<String>,
    /// `continuation_status`: whether the exchange consumed a human approval.
    #[pyo3(get)]
    continuation_status: Option<String>,
    /// `retention_status`: whether the server's evidence-retention obligation failed.
    #[pyo3(get)]
    retention_status: Option<String>,
    /// The verified response's evidence-handle digest algorithm — the
    /// `input_required_response_evidence` handle an MRTR answer leg binds to
    /// (ADR-MCPS-047). Read from the VERIFIED response only.
    #[pyo3(get)]
    resp_evidence_digest_alg: String,
    /// The verified response's evidence-handle digest value (base64url, no pad).
    #[pyo3(get)]
    resp_evidence_digest_value: String,
    /// `result.requestState` (a string) from the verified response body IFF the
    /// audited classifier reads it as an `InputRequiredResult`; else `None`. The
    /// opaque MRTR state the answer leg re-presents. Read only after the response
    /// verified as genuine evidence.
    ///
    /// The discriminator itself is deliberately not restated here — it lives in
    /// `mcp_re_http_profile::result_class`, and a doc comment repeating it is one
    /// more copy to drift. A verified reply that declares itself non-terminal
    /// without a usable state is an ERROR, never an absent state.
    #[pyo3(get)]
    request_state: Option<String>,
}

/// Verify a delegated-required RFC 9421 response bound to the request the client
/// sent (ADR-MCPRE-052). Delegated-required is the ONLY response mode: the response
/// is signed by an in-memory delegated key whose inline compact-JWS credential must
/// chain to the trusted ROOT ISSUER (`issuer_*`) and be scoped to
/// `expected_audience_hash` at one of `accepted_epochs`. A response that is unsigned,
/// direct-root-signed, carries a revoked identifier, is scoped to a stale trust
/// epoch, or is bound to a different request fails closed (no downgrade).
///
/// `revoked_identifiers` is the client's static denylist (any mix of `delegated_kid`,
/// `issuer_kid`, or credential `jti`); an empty list is the explicit TTL-only posture.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
fn verify_response(
    status: u16,
    resp_headers: Vec<(String, String)>,
    resp_body: &[u8],
    req_method: &str,
    req_target_uri: &str,
    req_headers: Vec<(String, String)>,
    req_body: &[u8],
    issuer_key_id: &str,
    issuer_pubkey_b64url: &str,
    issuer_role: &str,
    issuer_trust_domain: &str,
    issuer_subject: &str,
    verifier_audiences: Vec<String>,
    expected_audience_hash: &str,
    accepted_epochs: Vec<String>,
    max_clock_skew: i64,
    revoked_identifiers: Vec<String>,
    now: i64,
) -> PyResult<PyVerifyResult> {
    let issuer_pub = VerificationKey::from_b64url(issuer_pubkey_b64url)
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("invalid issuer public key"))?;
    let resolve = pinned_root_resolver(
        issuer_key_id,
        issuer_role,
        issuer_trust_domain,
        issuer_subject,
        issuer_pub,
    );
    let response = HttpResponse {
        status,
        headers: resp_headers,
        body: resp_body.to_vec(),
    };
    let request = HttpRequest {
        method: req_method.to_owned(),
        target_uri: req_target_uri.to_owned(),
        headers: req_headers,
        body: req_body.to_vec(),
    };
    let expectation = ResponseExpectation::new(request);
    let policy = DelegationPolicy::new(
        verifier_audiences,
        expected_audience_hash,
        accepted_epochs,
        max_clock_skew,
    );
    let revocation = StaticRevocationList::from_identifiers(revoked_identifiers);
    let trust = CompositeResponseTrust::new(&resolve, &revocation);
    let verified =
        verify_delegated_response(&response, &trust, &expectation, &policy, now).map_err(err)?;
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
    let request_state = mcp_re_client_core::continuation_state(resp_body).map_err(err)?;
    Ok(PyVerifyResult {
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

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(core_version, m)?)?;
    m.add_function(wrap_pyfunction!(profile_tag, m)?)?;
    m.add_function(wrap_pyfunction!(sign_preimage, m)?)?;
    m.add_function(wrap_pyfunction!(sign_request, m)?)?;
    m.add_function(wrap_pyfunction!(sign_request_with_signer, m)?)?;
    m.add_function(wrap_pyfunction!(sign_notification, m)?)?;
    m.add_function(wrap_pyfunction!(sign_notification_with_signer, m)?)?;
    m.add_function(wrap_pyfunction!(verify_response, m)?)?;
    m.add_function(wrap_pyfunction!(verify_accepted_202, m)?)?;
    m.add_class::<PySignedRequest>()?;
    m.add_class::<PyVerifyResult>()?;
    m.add_class::<PyAcceptedResult>()?;
    Ok(())
}
