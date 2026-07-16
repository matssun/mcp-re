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

use pyo3::prelude::*;
use pyo3::types::PyBytes;

use mcp_re_client_core::build_signed_request;
use mcp_re_client_core::build_signed_request_with_signer;
use mcp_re_client_core::verify_delegated_response;
use mcp_re_client_core::ActorIdentity;
use mcp_re_client_core::ArtifactBinding;
use mcp_re_client_core::ArtifactType;
use mcp_re_client_core::AudienceTuple;
use mcp_re_client_core::BindingType;
use mcp_re_client_core::DelegationPolicy;
use mcp_re_client_core::HttpContinuation;
use mcp_re_client_core::HttpProfileError;
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
fn build_bindings(bindings_json: &str) -> PyResult<Vec<ArtifactBinding>> {
    let specs: Vec<BindingSpec> = serde_json::from_str(bindings_json).map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("invalid bindings json: {e}"))
    })?;
    specs
        .into_iter()
        .map(|s| {
            let material = mcp_re_core::b64url_decode(&s.material_b64url).map_err(|_| {
                pyo3::exceptions::PyValueError::new_err(
                    "artifact material must be base64url (no pad)",
                )
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
            b.validate().map_err(err)?;
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
    extra_bindings: Vec<ArtifactBinding>,
) -> RequestSigningInputs {
    let audience = AudienceTuple {
        audience_id: audience_id.to_owned(),
        target_uri: target_uri.to_owned(),
        route,
    };
    // DPoP stays the built-in, header-derived binding: its credential is the covered
    // `Authorization: Bearer` header, so it is never provider-supplied. Provider bindings
    // are appended after it.
    let mut bindings =
        vec![ArtifactBinding::opaque_digest(ArtifactType::OauthDpop, dpop_token.as_bytes())];
    bindings.extend(extra_bindings);
    let mut inputs =
        RequestSigningInputs::new(key_id, audience, bindings, nonce, created, expires)
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
        match bindings_json.as_deref() {
            Some(j) => build_bindings(j)?,
            None => Vec::new(),
        },
    );
    let signed = build_signed_request(&id, method, params, target_uri, &inputs, &key).map_err(err)?;
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
        match bindings_json.as_deref() {
            Some(j) => build_bindings(j)?,
            None => Vec::new(),
        },
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
    /// The verified response's evidence-handle digest algorithm — the
    /// `input_required_response_evidence` handle an MRTR answer leg binds to
    /// (ADR-MCPS-047). Read from the VERIFIED response only.
    #[pyo3(get)]
    resp_evidence_digest_alg: String,
    /// The verified response's evidence-handle digest value (base64url, no pad).
    #[pyo3(get)]
    resp_evidence_digest_value: String,
    /// `result.requestState` (a string) from the verified response body IFF it is an
    /// `InputRequiredResult` (`result.resultType == "input_required"`); else `None`.
    /// The opaque MRTR state the answer leg re-presents. Read only after the response
    /// verified as genuine evidence.
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
    req_evidence_digest_alg: &str,
    req_evidence_digest_value: &str,
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
    let ikid = issuer_key_id.to_owned();
    // The trusted ROOT ISSUER anchor for the Response slot: the credential chains to
    // it. The delegated key itself is authorized by the credential, never enrolled.
    let iident = ActorIdentity {
        role: issuer_role.to_owned(),
        trust_domain: issuer_trust_domain.to_owned(),
        subject: issuer_subject.to_owned(),
        keyid: issuer_key_id.to_owned(),
    };
    let resolve = move |kid: &str, slot: SignerSlot| match slot {
        SignerSlot::Response if kid == ikid => Some(ResolvedActor {
            identity: iident.clone(),
            verification_key: issuer_pub.clone(),
            slot,
        }),
        _ => None,
    };
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
    let evidence = RequestEvidence {
        digest_alg: req_evidence_digest_alg.to_owned(),
        digest_value: req_evidence_digest_value.to_owned(),
    };
    let expectation = ResponseExpectation::new(request, evidence);
    let policy = DelegationPolicy::new(
        verifier_audiences,
        expected_audience_hash,
        accepted_epochs,
        max_clock_skew,
    );
    let revocation = StaticRevocationList::from_identifiers(revoked_identifiers);
    let verified =
        verify_delegated_response(&response, &resolve, &expectation, &policy, &revocation, now)
            .map_err(err)?;
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
    let request_state = serde_json::from_slice::<Value>(resp_body)
        .ok()
        .as_ref()
        .and_then(|v| v.get("result"))
        .filter(|r| {
            r.get("resultType").and_then(|t| t.as_str()) == Some("input_required")
        })
        .and_then(|r| r.get("requestState"))
        .and_then(|s| s.as_str())
        .map(str::to_owned);
    Ok(PyVerifyResult {
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

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(core_version, m)?)?;
    m.add_function(wrap_pyfunction!(profile_tag, m)?)?;
    m.add_function(wrap_pyfunction!(sign_preimage, m)?)?;
    m.add_function(wrap_pyfunction!(sign_request, m)?)?;
    m.add_function(wrap_pyfunction!(sign_request_with_signer, m)?)?;
    m.add_function(wrap_pyfunction!(verify_response, m)?)?;
    m.add_class::<PySignedRequest>()?;
    m.add_class::<PyVerifyResult>()?;
    Ok(())
}
