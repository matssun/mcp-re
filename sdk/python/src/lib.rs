// SPDX-License-Identifier: Apache-2.0
//! PyO3 binding exposing the audited `mcp-re-client-core` RFC 9421 signing /
//! verification seam to the MCP-RE Python SDK (ADR-MCPRE-050 sole carrier).
//!
//! The wire is RFC 9421 HTTP Message Signatures + RFC 9530 Content-Digest — the SDK
//! signs and verifies the HTTP evidence carrier only; the signature rides in the HTTP
//! headers, not a JSON-RPC `_meta` block. The private key never leaves the
//! process boundary the SDK is given (a raw seed here; a KMS/HSM seam is additive).

use pyo3::prelude::*;
use pyo3::types::PyBytes;

use mcp_re_client_core::build_signed_request;
use mcp_re_client_core::verify_delegated_response;
use mcp_re_client_core::ActorIdentity;
use mcp_re_client_core::ArtifactBinding;
use mcp_re_client_core::ArtifactType;
use mcp_re_client_core::AudienceTuple;
use mcp_re_client_core::DelegationPolicy;
use mcp_re_client_core::HttpProfileError;
use mcp_re_client_core::HttpRequest;
use mcp_re_client_core::HttpResponse;
use mcp_re_client_core::RequestEvidence;
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
) -> PyResult<PySignedRequest> {
    let key = seed_to_key(seed)?;
    let id = parse_json(id_json, "id")?;
    let params: Map<String, Value> = match parse_json(params_json, "params")? {
        Value::Object(m) => m,
        _ => return Err(pyo3::exceptions::PyValueError::new_err("params must be a JSON object")),
    };
    let audience = AudienceTuple {
        audience_id: audience_id.to_owned(),
        target_uri: target_uri.to_owned(),
        route,
    };
    let binding = ArtifactBinding::opaque_digest(ArtifactType::OauthDpop, dpop_token.as_bytes());
    let inputs = RequestSigningInputs::new(key_id, audience, vec![binding], nonce, created, expires)
        .with_headers(vec![("Authorization".to_owned(), format!("Bearer {dpop_token}"))]);
    let signed = build_signed_request(&id, method, params, target_uri, &inputs, &key).map_err(err)?;
    let req = signed.request();
    Ok(PySignedRequest {
        method: req.method.clone(),
        target_uri: req.target_uri.clone(),
        headers: req.headers.clone(),
        body_bytes: req.body.clone(),
        evidence_digest_alg: signed.evidence().digest_alg.clone(),
        evidence_digest_value: signed.evidence().digest_value.clone(),
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
    Ok(PyVerifyResult {
        ok: true,
        server_keyid: verified.verified.resolved_server_actor.identity.keyid,
        outcome,
        wire_code,
        bound,
    })
}

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(core_version, m)?)?;
    m.add_function(wrap_pyfunction!(profile_tag, m)?)?;
    m.add_function(wrap_pyfunction!(sign_request, m)?)?;
    m.add_function(wrap_pyfunction!(verify_response, m)?)?;
    m.add_class::<PySignedRequest>()?;
    m.add_class::<PyVerifyResult>()?;
    Ok(())
}
