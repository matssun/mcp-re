// SPDX-License-Identifier: Apache-2.0
//! RFC 9421 signed request construction (ADR-MCPRE-050, MCPRE-101).
//!
//! Client-side mirror of the proxy's `verify_request_full`: given an ordinary MCP
//! request (method + params) plus the signing inputs (signer/audience/artifact
//! bindings/freshness), it composes the HTTP-profile request evidence block into
//! the JSON-RPC body `_meta` (protected by the covered `Content-Digest`) and signs
//! the RFC 9421 HTTP Message Signature over the reconstructed `HttpRequest`.
//!
//! The signed evidence is `Signature`/`Signature-Input` (RFC 9421) + `Content-Digest`
//! (RFC 9530) on the HTTP message, not a JSON-RPC `_meta` block. The returned
//! [`SignedRequest`] exposes the
//! resulting [`RequestEvidence`] handle so the caller can bind the signed response
//! (`response.request_evidence == request.evidence`).
//!
//! Purity: this module builds and signs in-process only. Nonce generation, clock
//! reads, key custody, and transport live in the mode-specific layers above this
//! seam (ADR-MCPS-044).

use mcp_re_core::SigningKey;
use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::sign_request_full_with_signer;
use mcp_re_http_profile::AdmissionBinding;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::HttpContinuation;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::RequestEvidence;
use mcp_re_http_profile::PROFILE_TAG;
use serde_json::json;
use serde_json::Map;
use serde_json::Value;

/// The already-resolved inputs for one RFC 9421 signed request.
///
/// Every field is a value the mode-specific layer has already produced: the signer
/// key id (from the key-custody layer), the resolved [`AudienceTuple`] (audience
/// id + `@target-uri` + optional route — MCPS-43), the required, non-empty
/// artifact bindings (from an authorization-binding provider — MCPS-45), and the
/// freshness triple `nonce`/`created`/`expires` (RFC 9421 signature parameters,
/// Unix seconds).
#[derive(Debug, Clone)]
pub struct RequestSigningInputs {
    /// Identifier of the signing key (named in the RFC 9421 `keyid`; never the key).
    pub key_id: String,
    /// The resolved audience tuple (verifier id + absolute `@target-uri` + route).
    pub audience: AudienceTuple,
    /// The authorization/artifact bindings bound into the signed evidence block.
    /// Required, non-empty — a request with no binding fails validation closed.
    pub artifact_bindings: Vec<ArtifactBinding>,
    /// Opaque anti-replay nonce (>= 128 bits entropy), already drawn (RFC 9421
    /// `nonce`).
    pub nonce: String,
    /// Signature creation time, Unix seconds (RFC 9421 `created`).
    pub created: i64,
    /// Signature expiry time, Unix seconds (RFC 9421 `expires`).
    pub expires: i64,
    /// Optional multi-round-trip continuation binding (ADR-MCPS-047). `None` for an
    /// ordinary first-round request. Set via [`RequestSigningInputs::with_continuation`].
    pub continuation: Option<HttpContinuation>,
    /// Additional request headers to include (and cover) in the signed HTTP request
    /// — e.g. `Authorization: Bearer <token>` whose bytes an OAuth-DPoP artifact
    /// binding digests. Empty by default. Set via [`RequestSigningInputs::with_headers`].
    pub extra_headers: Vec<(String, String)>,
    /// The §7 admission evidence this call acts under: the binding, plus the
    /// authority-signed assertion it commits to. Both or neither — a binding the
    /// verifier cannot check against an assertion enforces nothing. Set via
    /// [`RequestSigningInputs::with_admission`].
    pub admission: Option<(AdmissionBinding, String)>,
}

impl RequestSigningInputs {
    /// Build inputs for an ordinary first-round request.
    pub fn new(
        key_id: impl Into<String>,
        audience: AudienceTuple,
        artifact_bindings: Vec<ArtifactBinding>,
        nonce: impl Into<String>,
        created: i64,
        expires: i64,
    ) -> Self {
        RequestSigningInputs {
            key_id: key_id.into(),
            audience,
            artifact_bindings,
            nonce: nonce.into(),
            created,
            expires,
            continuation: None,
            extra_headers: Vec::new(),
            admission: None,
        }
    }

    /// Add request headers to include AND cover in the signature (e.g. an
    /// `Authorization: Bearer` header an OAuth-DPoP artifact binding digests).
    pub fn with_headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.extra_headers = headers;
        self
    }

    /// Bind this request to the verified `InputRequiredResult` it answers
    /// (ADR-MCPS-047): the continuation rides inside the signed evidence block.
    pub fn with_continuation(mut self, continuation: HttpContinuation) -> Self {
        self.continuation = Some(continuation);
        self
    }

    /// Declare the admission this call acts under (#414 §4.3 / #415 §7): the
    /// binding and the authority-signed assertion it commits to, both inside the
    /// signed evidence block.
    ///
    /// The assertion travels with the call rather than being fetched by the
    /// verifier, exactly as the delegation credential does on the response side.
    /// What it proves is what an authority SAID, at a generation; whether that is
    /// still true is the PEP's currency check, against authoritative state this
    /// client never sees.
    pub fn with_admission(
        mut self,
        binding: AdmissionBinding,
        assertion_jws: impl Into<String>,
    ) -> Self {
        self.admission = Some((binding, assertion_jws.into()));
        self
    }

    /// The HTTP-profile request evidence block this input set authors.
    fn evidence_block(&self) -> HttpRequestEvidenceBlock {
        HttpRequestEvidenceBlock {
            profile: PROFILE_TAG.to_owned(),
            audience: self.audience.clone(),
            artifact_bindings: self.artifact_bindings.clone(),
            continuation: self.continuation.clone(),
            admission: self.admission.as_ref().map(|(b, _)| b.clone()),
            admission_assertion: self.admission.as_ref().map(|(_, jws)| jws.clone()),
        }
    }
}

/// A fully signed RFC 9421 request: the reconstructed [`HttpRequest`] (method +
/// `@target-uri` + headers carrying `Signature`/`Signature-Input`/`Content-Digest` +
/// body with the composed evidence block) plus the [`RequestEvidence`] handle that
/// binds a later signed response.
#[derive(Debug, Clone)]
pub struct SignedRequest {
    request: HttpRequest,
    evidence: RequestEvidence,
}

impl SignedRequest {
    /// The signed HTTP request (method, `@target-uri`, headers, body) to send.
    pub fn request(&self) -> &HttpRequest {
        &self.request
    }

    /// The serialized JSON-RPC request body bytes.
    pub fn body(&self) -> &[u8] {
        &self.request.body
    }

    /// The signed request headers (RFC 9421 `Signature`/`Signature-Input`, RFC 9530
    /// `Content-Digest`) to place on the outbound HTTP request.
    pub fn headers(&self) -> &[(String, String)] {
        &self.request.headers
    }

    /// The [`RequestEvidence`] handle (digest over the RFC 9421 signature base) that
    /// binds a later signed response (`response.request_evidence == this`).
    pub fn evidence(&self) -> &RequestEvidence {
        &self.evidence
    }

    /// Consume the signed request, returning the owned [`HttpRequest`].
    pub fn into_request(self) -> HttpRequest {
        self.request
    }
}

/// Construct and sign an RFC 9421 MCP-RE request with a local in-process key.
///
/// `id`/`method`/`params` are the ordinary MCP request fields. `target_uri` is the
/// canonical absolute `@target-uri` both sides sign over (must equal
/// `inputs.audience.target_uri`). The client core is the sole author of the request
/// evidence block by construction: the body is rebuilt from `id`/`jsonrpc`/`method`/
/// `params`, so no caller value can reach the body-root `_meta` the block occupies.
/// `params._meta` is ordinary MCP metadata and is passed through, covered by the
/// `Content-Digest` like the rest of the body.
pub fn build_signed_request(
    id: &Value,
    method: &str,
    params: Map<String, Value>,
    target_uri: &str,
    inputs: &RequestSigningInputs,
    signing_key: &SigningKey,
) -> Result<SignedRequest, HttpProfileError> {
    build_signed_request_with(
        Some(id),
        method,
        params,
        target_uri,
        inputs,
        |request, block| {
            sign_request_full(
                request,
                block,
                signing_key,
                &inputs.key_id,
                inputs.created,
                inputs.expires,
                &inputs.nonce,
            )
        },
    )
}

/// The shared request-construction core, generic over HOW the RFC 9421 message is
/// signed. `sign` receives the reconstructed [`HttpRequest`] (body already the
/// clean JSON-RPC) and the evidence block, composes + signs, and returns the
/// [`RequestEvidence`]. This is the single seam every signing mechanism (in-process
/// key, KMS/HSM via [`sign_request_with_signer`], delegated service) flows through.
pub(crate) fn build_signed_request_with(
    id: Option<&Value>,
    method: &str,
    params: Map<String, Value>,
    target_uri: &str,
    inputs: &RequestSigningInputs,
    sign: impl FnOnce(
        &mut HttpRequest,
        &HttpRequestEvidenceBlock,
    ) -> Result<RequestEvidence, HttpProfileError>,
) -> Result<SignedRequest, HttpProfileError> {
    // The @target-uri the client signs MUST match the audience tuple's target_uri
    // (the verifier cross-checks them); a mismatch is a client misconfiguration —
    // fail closed rather than emit evidence that can never verify.
    if target_uri != inputs.audience.target_uri {
        return Err(HttpProfileError::AudienceMismatch);
    }

    // `params._meta` is ORDINARY MCP metadata (`progressToken` and friends) and is
    // passed through untouched. The request evidence block lives at the body ROOT
    // `_meta`, which `sign_request_full` composes in and which a caller cannot reach:
    // the body below is rebuilt from `id`/`jsonrpc`/`method`/`params` alone. It is
    // covered by `Content-Digest` either way, so caller metadata is signed, not trusted.
    // `id` ABSENT is what makes a message a JSON-RPC notification (§4.1), and the
    // serving path classifies on exactly that: a `method` with no `id` key. `null` is
    // not the same thing — it is a present id, so a notification signed with one would
    // be dispatched as a request and answered with a bodied reply the client is not
    // expecting. The key is therefore omitted, never emitted as null.
    let mut envelope = Map::new();
    if let Some(id) = id {
        envelope.insert("id".to_owned(), id.clone());
    }
    envelope.insert("jsonrpc".to_owned(), json!("2.0"));
    envelope.insert("method".to_owned(), json!(method));
    envelope.insert("params".to_owned(), Value::Object(params));
    let body = serde_json::to_vec(&Value::Object(envelope))
        .map_err(|_| HttpProfileError::MalformedEvidence("request body serialization"))?;

    let mut headers = vec![("content-type".to_owned(), "application/json".to_owned())];
    headers.extend(inputs.extra_headers.iter().cloned());
    let mut request = HttpRequest {
        method: "POST".to_owned(),
        target_uri: target_uri.to_owned(),
        headers,
        body,
    };
    let block = inputs.evidence_block();
    // Hold the block to the SAME structural rules the verifier applies, before signing
    // it. `artifact_bindings` is documented as required and non-empty, and the server
    // rejects an empty (or structurally invalid) set as `malformed_evidence` — but the
    // client would compose it, sign it, and spend a round trip discovering that, then
    // report it as a server-side evidence fault rather than the local misconfiguration
    // it is. This is the same fail-fast the `@target-uri` / audience cross-check above
    // already performs: never emit evidence that can never verify. Reusing
    // `HttpRequestEvidenceBlock::validate` rather than re-spelling the rules keeps the
    // two ends from drifting apart.
    block.validate(PROFILE_TAG)?;
    let evidence = sign(&mut request, &block)?;
    Ok(SignedRequest { request, evidence })
}

/// Non-exporting-custody variant: sign the RFC 9421 request through an external
/// signer closure (Cloud KMS / HSM) that returns the raw 64-byte Ed25519 signature
/// over the exact signature base. Wire-identical to [`build_signed_request`].
pub fn build_signed_request_with_signer(
    id: &Value,
    method: &str,
    params: Map<String, Value>,
    target_uri: &str,
    inputs: &RequestSigningInputs,
    sign_base: impl FnOnce(&[u8]) -> Result<Vec<u8>, HttpProfileError>,
) -> Result<SignedRequest, HttpProfileError> {
    // sign_request_with_signer signs but does NOT compose the evidence block; the
    // full-profile client composes the block first, then signs over it.
    build_signed_request_with(
        Some(id),
        method,
        params,
        target_uri,
        inputs,
        |request, block| {
            sign_request_full_with_signer(
                request,
                block,
                sign_base,
                &inputs.key_id,
                inputs.created,
                inputs.expires,
                &inputs.nonce,
            )
        },
    )
}

/// Construct and sign a one-way MCP **notification** — a JSON-RPC message with a
/// `method` and no `id` (§4.1) — with a local in-process key.
///
/// A notification is signed by the ORDINARY request rules: same evidence block, same
/// covered components, same freshness triple. Nothing about the signing changes, which
/// is why this is a thin sibling of [`build_signed_request`] rather than a second
/// profile. What differs is only the JSON-RPC envelope (no `id`) and therefore the
/// answer: an accepted notification earns a signed bodyless `202`, verified with
/// [`crate::verify_delegated_accepted_202`], not a bodied reply.
///
/// A notification cannot carry an ADR-MCPS-047 continuation: an answer leg answers an
/// `InputRequiredResult`, and a message with no `id` can receive no such result. A
/// continuation on `inputs` is therefore a client construction error and fails closed
/// here rather than being signed into evidence that describes an exchange that cannot
/// exist.
pub fn build_signed_notification(
    method: &str,
    params: Map<String, Value>,
    target_uri: &str,
    inputs: &RequestSigningInputs,
    signing_key: &SigningKey,
) -> Result<SignedRequest, HttpProfileError> {
    reject_continuation_on_notification(inputs)?;
    build_signed_request_with(
        None,
        method,
        params,
        target_uri,
        inputs,
        |request, block| {
            sign_request_full(
                request,
                block,
                signing_key,
                &inputs.key_id,
                inputs.created,
                inputs.expires,
                &inputs.nonce,
            )
        },
    )
}

/// Non-exporting-custody variant of [`build_signed_notification`]. Wire-identical.
pub fn build_signed_notification_with_signer(
    method: &str,
    params: Map<String, Value>,
    target_uri: &str,
    inputs: &RequestSigningInputs,
    sign_base: impl FnOnce(&[u8]) -> Result<Vec<u8>, HttpProfileError>,
) -> Result<SignedRequest, HttpProfileError> {
    reject_continuation_on_notification(inputs)?;
    build_signed_request_with(
        None,
        method,
        params,
        target_uri,
        inputs,
        |request, block| {
            sign_request_full_with_signer(
                request,
                block,
                sign_base,
                &inputs.key_id,
                inputs.created,
                inputs.expires,
                &inputs.nonce,
            )
        },
    )
}

fn reject_continuation_on_notification(
    inputs: &RequestSigningInputs,
) -> Result<(), HttpProfileError> {
    if inputs.continuation.is_some() {
        return Err(HttpProfileError::MalformedEvidence(
            "continuation on a notification",
        ));
    }
    Ok(())
}

/// Convenience for the common `tools/call` case.
pub fn build_signed_tool_call(
    id: &Value,
    tool_name: &str,
    arguments: Value,
    target_uri: &str,
    inputs: &RequestSigningInputs,
    signing_key: &SigningKey,
) -> Result<SignedRequest, HttpProfileError> {
    let mut params = Map::new();
    params.insert("name".to_string(), Value::String(tool_name.to_string()));
    params.insert("arguments".to_string(), arguments);
    build_signed_request(id, "tools/call", params, target_uri, inputs, signing_key)
}

#[cfg(test)]
mod evidence_precondition_tests {
    //! C090: the client must not sign a request whose evidence block the verifier is
    //! guaranteed to reject. `artifact_bindings` is documented as required and
    //! non-empty and the server enforces exactly that
    //! (`HttpRequestEvidenceBlock::validate` → `malformed_evidence`), but the client
    //! composed, signed, and sent an empty set — spending a round trip to be told, and
    //! reporting a local misconfiguration as a server-side evidence fault.

    use super::*;
    use mcp_re_http_profile::ArtifactType;

    const TARGET: &str = "https://mcp.example.com/mcp?route=a";

    fn audience() -> AudienceTuple {
        AudienceTuple {
            audience_id: "verifier-1".into(),
            target_uri: TARGET.into(),
            route: Some("a".into()),
        }
    }

    fn inputs(bindings: Vec<ArtifactBinding>) -> RequestSigningInputs {
        RequestSigningInputs::new(
            "client-key-1",
            audience(),
            bindings,
            "nonce-1",
            1_000,
            1_300,
        )
    }

    fn sign(bindings: Vec<ArtifactBinding>) -> Result<SignedRequest, HttpProfileError> {
        let params: Map<String, Value> = serde_json::json!({ "name": "read" })
            .as_object()
            .cloned()
            .unwrap();
        build_signed_request(
            &Value::from(1),
            "tools/call",
            params,
            TARGET,
            &inputs(bindings),
            &SigningKey::from_seed_bytes(&[11u8; 32]),
        )
    }

    /// Sign with a caller-supplied `params._meta`, as an MCP client carrying a
    /// `progressToken` does.
    fn sign_with_caller_meta() -> SignedRequest {
        let params: Map<String, Value> = serde_json::json!({
            "name": "read",
            "_meta": { "progressToken": "tok-1" },
        })
        .as_object()
        .cloned()
        .unwrap();
        build_signed_request(
            &Value::from(1),
            "tools/call",
            params,
            TARGET,
            &inputs(vec![ArtifactBinding::opaque_digest(
                ArtifactType::OauthDpop,
                b"access-token",
            )]),
            &SigningKey::from_seed_bytes(&[11u8; 32]),
        )
        .expect("a well-formed request signs")
    }

    /// The client core used to `params.remove("_meta")` here, claiming it had to be the
    /// sole author of the evidence block. The block lives at the body ROOT, so the strip
    /// reached only ordinary MCP metadata and silently dropped it after the caller
    /// believed it was sent — invisibly, because the request still signed and verified.
    #[test]
    fn caller_params_meta_survives_signing() {
        let signed = sign_with_caller_meta();
        let body: Value = serde_json::from_slice(signed.request().body.as_slice())
            .expect("the signed body is json");
        assert_eq!(
            body["params"]["_meta"]["progressToken"],
            Value::from("tok-1"),
            "ordinary MCP params metadata must reach the wire"
        );
    }

    /// And it is COVERED, not merely passed through: the evidence block the client
    /// authors still lands at the body root, where the verifier reads it, so caller
    /// metadata and evidence occupy different keys and neither can shadow the other.
    #[test]
    fn the_evidence_block_still_lands_at_the_body_root() {
        let signed = sign_with_caller_meta();
        let body: Value = serde_json::from_slice(signed.request().body.as_slice())
            .expect("the signed body is json");
        assert!(
            body["_meta"].is_object(),
            "the request evidence block is written to the ROOT _meta, not params._meta"
        );
        assert!(
            body["_meta"].get("progressToken").is_none(),
            "caller metadata must not be promoted into the evidence block's namespace"
        );
    }

    #[test]
    fn signing_with_no_artifact_binding_is_refused_locally() {
        assert_eq!(
            sign(Vec::new()).err(),
            Some(HttpProfileError::MalformedEvidence(
                "empty artifact_bindings"
            )),
            "the client refuses to sign what the verifier must reject, and reports the \
             SAME reason the verifier would — so the two ends cannot drift"
        );
    }

    #[test]
    fn signing_with_a_structurally_invalid_binding_is_refused_locally() {
        // Not just emptiness: the client reuses the verifier's whole predicate, so a
        // present-but-malformed binding is caught here too. An empty digest value can
        // never satisfy the binding's own validation.
        let mut broken = ArtifactBinding::opaque_digest(ArtifactType::OauthDpop, b"token");
        broken.digest_value = String::new();
        assert!(
            sign(vec![broken]).is_err(),
            "a structurally invalid binding is refused before signing"
        );
    }

    #[test]
    fn a_valid_binding_still_signs() {
        // The converse, so the precondition cannot be read as "bindings are broken".
        let ok = ArtifactBinding::opaque_digest(ArtifactType::OauthDpop, b"access-token");
        let signed = sign(vec![ok]).expect("a well-formed request signs");
        assert!(
            !signed.headers().is_empty(),
            "the signed request carries RFC 9421 headers"
        );
    }
}

#[cfg(test)]
mod notification_tests {
    //! C055: the client half of the one-way notification profile. The signing rules are
    //! the ordinary request rules — what has to be exactly right is the JSON-RPC
    //! envelope, because the serving path classifies a notification by the ABSENCE of
    //! `id` and answers a misclassified message with a bodied reply the client never
    //! awaits.

    use super::*;
    use mcp_re_http_profile::ArtifactType;
    use mcp_re_http_profile::RequestEvidenceDigest;

    const TARGET: &str = "https://mcp.example.com/mcp?route=a";

    fn inputs() -> RequestSigningInputs {
        RequestSigningInputs::new(
            "client-key-1",
            AudienceTuple {
                audience_id: "verifier-1".into(),
                target_uri: TARGET.into(),
                route: Some("a".into()),
            },
            vec![ArtifactBinding::opaque_digest(
                ArtifactType::OauthDpop,
                b"access-token",
            )],
            "nonce-notification-1",
            1_000,
            1_300,
        )
    }

    fn key() -> SigningKey {
        SigningKey::from_seed_bytes(&[11u8; 32])
    }

    fn signed_notification() -> SignedRequest {
        build_signed_notification(
            "notifications/initialized",
            Map::new(),
            TARGET,
            &inputs(),
            &key(),
        )
        .expect("a well-formed notification signs")
    }

    fn body_of(signed: &SignedRequest) -> Value {
        serde_json::from_slice(signed.request().body.as_slice()).expect("the signed body is json")
    }

    /// The classification the serving path performs, restated here so the client's
    /// envelope is checked against the rule that actually decides its fate.
    fn reads_as_a_notification(body: &Value) -> bool {
        body.get("method").is_some() && body.get("id").is_none()
    }

    #[test]
    fn a_signed_notification_carries_no_id_at_all() {
        let body = body_of(&signed_notification());
        assert!(
            reads_as_a_notification(&body),
            "the serving path classifies on an absent id: {body}"
        );
        assert_eq!(body["method"], Value::from("notifications/initialized"));
        assert_eq!(body["jsonrpc"], Value::from("2.0"));
    }

    /// `"id": null` is a PRESENT id, so it would be dispatched as a request and answered
    /// with a bodied reply nothing is waiting for. The key is omitted, not nulled.
    #[test]
    fn the_id_key_is_absent_rather_than_null() {
        let body = body_of(&signed_notification());
        let object = body.as_object().expect("the body is a json object");
        assert!(!object.contains_key("id"), "no id key may appear: {body}");
    }

    #[test]
    fn a_signed_notification_carries_the_ordinary_rfc_9421_evidence() {
        let signed = signed_notification();
        let names: Vec<String> = signed
            .headers()
            .iter()
            .map(|(k, _)| k.to_ascii_lowercase())
            .collect();
        for required in ["signature", "signature-input", "content-digest"] {
            assert!(
                names.iter().any(|n| n == required),
                "a notification is signed by the ordinary request rules; missing {required}"
            );
        }
        assert!(
            body_of(&signed)["_meta"].is_object(),
            "the request evidence block rides in the body root, as on any request"
        );
    }

    /// An answer leg answers an `InputRequiredResult`; a message with no `id` can
    /// receive no result at all, so a continuation here describes an exchange that
    /// cannot exist. Refused locally rather than signed into evidence.
    #[test]
    fn a_continuation_on_a_notification_is_refused_locally() {
        let digest = || RequestEvidenceDigest {
            digest_alg: "sha-256".into(),
            digest_value: "AAAA".into(),
        };
        let with_continuation = inputs().with_continuation(HttpContinuation::from_handles(
            digest(),
            digest(),
            b"state-1",
        ));
        assert_eq!(
            build_signed_notification(
                "notifications/cancelled",
                Map::new(),
                TARGET,
                &with_continuation,
                &key(),
            )
            .err(),
            Some(HttpProfileError::MalformedEvidence(
                "continuation on a notification"
            )),
        );
    }

    /// The two custody classes must produce the same bytes here for the same reason they
    /// do on the request path: non-exporting custody moves the key behind a device, it
    /// does not change the signed message.
    #[test]
    fn both_custody_classes_emit_identical_notification_bytes() {
        let software = signed_notification();
        let delegated = build_signed_notification_with_signer(
            "notifications/initialized",
            Map::new(),
            TARGET,
            &inputs(),
            |preimage| {
                mcp_re_core::b64url_decode(&key().sign(preimage))
                    .map_err(|_| HttpProfileError::InvalidSignature)
            },
        )
        .expect("the device path signs");
        assert_eq!(software.request().body, delegated.request().body);
        assert_eq!(software.headers(), delegated.headers());
    }
}
