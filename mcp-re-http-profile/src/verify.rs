// SPDX-License-Identifier: Apache-2.0
//! Verifier side of the proof path. Everything fails closed: missing or
//! duplicated evidence headers, unknown tag, wrong algorithm, stale window,
//! unresolved keyid, digest mismatch, missing covered component, and any
//! cryptographic failure all reject.
//!
//! Verification order (v0.11 grill C.1): content-digest first, then evidence
//! parse, then keyid resolution through the caller's trust seam, then the
//! signature over the reconstructed base, then handle derivation.

use mcp_re_core::verify_ed25519_with;
use mcp_re_core::McpReError;

use crate::artifact::verify_artifact_binding;
use crate::block::ActorIdentity;
use crate::block::ArtifactBinding;
use crate::block::ArtifactType;
use crate::block::AudienceTuple;
use crate::block::HttpRequestEvidenceBlock;
use crate::block::HttpResponseEvidenceBlock;
use crate::block::ResolvedActor;
use crate::block::SignerSlot;
use crate::body::authorization_bearer_bytes;
use crate::body::extract_meta_block;
use crate::delegation::verify_delegation_credential;
use crate::delegation::DelegationVerifyParams;
use crate::digest::verify_content_digest_sha256;
use crate::error::HttpProfileError;
use crate::evidence::RequestEvidence;
use crate::ids::ALG_ED25519;
use crate::ids::PROFILE_TAG;
use crate::ids::REQUEST_EVIDENCE_BLOCK_KEY;
use crate::ids::REQUEST_LABEL;
use crate::ids::REQUIRED_REQUEST_COMPONENTS;
use crate::ids::RESPONSE_EVIDENCE_BLOCK_KEY;
use crate::ids::REQUIRED_RESPONSE_COMPONENTS;
use crate::ids::REQUIRED_RESPONSE_REQ_COMPONENTS;
use crate::ids::RESPONSE_LABEL;
use crate::message::reject_content_encoding;
use crate::message::required_header;
use crate::message::single_header;
use crate::message::HttpRequest;
use crate::message::HttpResponse;
use crate::sigbase::signature_base;
use crate::sigbase::CoveredComponent;
use crate::sigbase::SignatureParams;
use crate::sigbase::SourceMessage;
use crate::sign::base64_standard_decode;

/// The verifier's structured product for a request (MCPRE-100): the resolved
/// signer identity, the evidence handle (for response binding, MRTR, audit), the
/// covered content digest, and the accepted freshness window. Downstream
/// consumers (replay-key construction, response/body-block validation, signed
/// rejections) read this context instead of re-parsing headers/body.
///
/// The verifier no longer returns "signature valid" alone — it returns a
/// *verified evidence context*. In particular `resolved_actor` carries the
/// trust-resolution output, so `resolved_actor.actor_id()` — not the raw
/// `key_id` — is the identity replay and audit bind to.
#[derive(Debug, Clone)]
pub struct VerifiedHttpRequestEvidence {
    /// The profile id (`tag`) the signature was accepted under (`PROFILE_TAG`).
    pub profile_id: String,
    /// The RFC 9421 dictionary label of the verified signature (`REQUEST_LABEL`).
    pub signature_label: String,
    /// The resolved signing actor (identity + key + vouched slot).
    pub resolved_actor: ResolvedActor,
    /// The request signature-base handle (`SHA-256` over the reconstructed base).
    pub evidence: RequestEvidence,
    /// The verified `Content-Digest` header value covered by the signature.
    pub content_digest: String,
    pub created: i64,
    pub expires: i64,
    pub nonce: String,
    /// The presented keyid. Distinct from `resolved_actor.actor_id()`: a keyid
    /// is a wire selector, not a trust-resolution output.
    pub key_id: String,
    /// The verified audience tuple from the request body block. `None` on the
    /// minimal proof path; `Some` after `verify_request_full` (MCPRE-101).
    pub audience: Option<AudienceTuple>,
    /// `audience_hash` over the canonical audience tuple — the replay-key
    /// component (MCPRE-102). `None` on the minimal path.
    pub audience_hash: Option<String>,
    /// The parsed, validated request evidence block (audience, artifact
    /// bindings, optional continuation). `None` on the minimal path; carried
    /// here so replay/MRTR wiring (MCPRE-102) need not re-parse the body.
    pub request_block: Option<HttpRequestEvidenceBlock>,
}

/// The verifier's structured product for a response (MCPRE-100): the resolved
/// server signer and the response signature-base handle. `bound_request_evidence`
/// is the request handle this response is bound to; the seam-only path leaves it
/// `None` and the MCPRE-101/102 dispatcher wiring populates it from the verified
/// request context (it is not recomputed here to avoid re-parsing the request).
#[derive(Debug, Clone)]
pub struct VerifiedHttpResponseEvidence {
    /// The resolved server/response signer (identity + key + `Response` slot).
    pub resolved_server_actor: ResolvedActor,
    /// The response signature-base handle (`SHA-256` over the reconstructed base).
    pub response_signature_base_digest: RequestEvidence,
    /// The request evidence this response binds to, taken from the verified
    /// request context. `None` on the seam-only path; `Some` after
    /// `verify_response_full` (MCPRE-101).
    pub bound_request_evidence: Option<RequestEvidence>,
    /// The `request_evidence` the response body block carried. Compared against
    /// `bound_request_evidence`; a mismatch is `request_binding_mismatch`. `None`
    /// on the seam-only path.
    pub body_request_evidence: Option<RequestEvidence>,
    /// The `server_signer` identity the response body block declared, verified
    /// to match the keyid the response signature was accepted under. `None` on
    /// the seam-only path.
    pub server_signer: Option<ActorIdentity>,
}

/// Resolve a keyid through the trust seam for a specific signing slot and apply
/// the typed defense-in-depth cross-check (MCPRE-100). The seam is the primary
/// slot-authorization authority: a key not trusted for `slot` resolves to `None`
/// and fails `actor_binding_failed`. The verifier additionally asserts the
/// returned actor is vouched for the slot it asked for — never a role-string
/// comparison — so a resolver that hands back a wrong-slot actor is also caught.
fn resolve_actor_for(
    resolve_actor: &dyn Fn(&str, SignerSlot) -> Option<ResolvedActor>,
    key_id: &str,
    slot: SignerSlot,
) -> Result<ResolvedActor, HttpProfileError> {
    let actor = resolve_actor(key_id, slot).ok_or(HttpProfileError::UnresolvedKeyId)?;
    if actor.slot != slot {
        return Err(HttpProfileError::ActorSlotMismatch);
    }
    Ok(actor)
}

/// One parsed `Signature-Input` dictionary member.
struct ParsedSignatureInput {
    components: Vec<CoveredComponent>,
    params: SignatureParams,
}

/// Split a Structured Fields dictionary into members at top-level commas
/// (commas inside quoted strings do not split).
fn split_dictionary(value: &str) -> Vec<&str> {
    let mut members = Vec::new();
    let mut start = 0usize;
    let mut in_quotes = false;
    for (i, c) in value.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                members.push(value[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    members.push(value[start..].trim());
    members
}

/// Find the member value for `label` in a `Signature-Input`/`Signature`
/// dictionary header, fail-closed on absence or duplication.
fn member_value<'a>(header_value: &'a str, label: &str) -> Result<&'a str, HttpProfileError> {
    let mut found: Option<&'a str> = None;
    for member in split_dictionary(header_value) {
        if let Some(rest) = member.strip_prefix(label) {
            if let Some(v) = rest.strip_prefix('=') {
                if found.is_some() {
                    return Err(HttpProfileError::MalformedEvidence(
                        "duplicate signature label",
                    ));
                }
                found = Some(v.trim());
            }
        }
    }
    found.ok_or(HttpProfileError::MissingEvidence("signature label"))
}

/// Leak-free integer parse for created/expires.
fn parse_i64(s: &str) -> Result<i64, HttpProfileError> {
    s.parse::<i64>()
        .map_err(|_| HttpProfileError::MalformedEvidence("integer signature parameter"))
}

/// Parse one `("a" "b";req ...);k=v;...` signature-input member value.
fn parse_signature_input(value: &str) -> Result<ParsedSignatureInput, HttpProfileError> {
    let value = value.trim();
    if !value.starts_with('(') {
        return Err(HttpProfileError::MalformedEvidence("inner list"));
    }
    let close = value
        .find(')')
        .ok_or(HttpProfileError::MalformedEvidence("inner list"))?;
    let list = &value[1..close];
    let mut components = Vec::new();
    for item in list.split_whitespace() {
        let (name_part, req) = match item.strip_suffix(";req") {
            Some(p) => (p, true),
            None => (item, false),
        };
        let name = name_part
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .ok_or(HttpProfileError::MalformedEvidence("component identifier"))?;
        // Identifiers are 'static in this profile: admit only the closed set
        // the profile can ever cover; anything else is foreign evidence.
        let known: &'static str = match name {
            "@method" => "@method",
            "@target-uri" => "@target-uri",
            "@authority" => "@authority",
            "@path" => "@path",
            "@status" => "@status",
            "content-digest" => "content-digest",
            "content-type" => "content-type",
            "content-length" => "content-length",
            "authorization" => "authorization",
            "dpop" => "dpop",
            _ => {
                return Err(HttpProfileError::MalformedEvidence(
                    "unknown covered component",
                ))
            }
        };
        components.push(if req {
            CoveredComponent::req(known)
        } else {
            CoveredComponent::new(known)
        });
    }

    let mut params = SignatureParams::default();
    let mut last_param_rank: i32 = -1;
    for p in value[close + 1..].split(';') {
        let p = p.trim();
        if p.is_empty() {
            continue;
        }
        let (k, v) = p
            .split_once('=')
            .ok_or(HttpProfileError::MalformedEvidence("signature parameter"))?;
        let unquote = |v: &str| -> Result<String, HttpProfileError> {
            v.strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .map(str::to_owned)
                .ok_or(HttpProfileError::MalformedEvidence(
                    "quoted signature parameter",
                ))
        };
        // Strict Structured Fields (MCPRE-98): the profile's parameter set is
        // closed AND ordered. The verifier normalizes to a canonical order when
        // rebuilding the base, so a reordered wire form would silently verify;
        // reject it structurally instead. `rank` is the canonical position; a
        // key that is not strictly after the previous one (reordered OR
        // duplicated) fails closed.
        let rank = match k {
            "created" => 0,
            "expires" => 1,
            "nonce" => 2,
            "keyid" => 3,
            "alg" => 4,
            "tag" => 5,
            // Unknown parameters would change the signature base this verifier
            // rebuilds; fail closed rather than sign-what-you-did-not-say.
            _ => {
                return Err(HttpProfileError::MalformedEvidence(
                    "unknown signature parameter",
                ))
            }
        };
        if rank <= last_param_rank {
            return Err(HttpProfileError::MalformedEvidence(
                "signature parameter order",
            ));
        }
        last_param_rank = rank;
        match k {
            "created" => params.created = Some(parse_i64(v)?),
            "expires" => params.expires = Some(parse_i64(v)?),
            "nonce" => params.nonce = Some(unquote(v)?),
            "keyid" => params.keyid = Some(unquote(v)?),
            "alg" => params.alg = Some(unquote(v)?),
            "tag" => params.tag = Some(unquote(v)?),
            _ => unreachable!("rank match above is exhaustive over the closed set"),
        }
    }
    Ok(ParsedSignatureInput { components, params })
}

/// Shared parameter gate: tag, algorithm, freshness window, keyid presence.
fn check_params(
    params: &SignatureParams,
    now: i64,
    require_nonce: bool,
) -> Result<(i64, i64, String, String), HttpProfileError> {
    match params.tag.as_deref() {
        Some(PROFILE_TAG) => {}
        _ => return Err(HttpProfileError::UnknownProfileTag),
    }
    match params.alg.as_deref() {
        Some(ALG_ED25519) => {}
        _ => return Err(HttpProfileError::UnsupportedAlgorithm),
    }
    let created = params.created.ok_or(HttpProfileError::StaleWindow)?;
    let expires = params.expires.ok_or(HttpProfileError::StaleWindow)?;
    if created > now || expires <= now || expires <= created {
        return Err(HttpProfileError::StaleWindow);
    }
    let nonce = match (&params.nonce, require_nonce) {
        (Some(n), _) => n.clone(),
        (None, false) => String::new(),
        (None, true) => return Err(HttpProfileError::MissingEvidence("nonce")),
    };
    let key_id = params
        .keyid
        .clone()
        .ok_or(HttpProfileError::MissingEvidence("keyid"))?;
    Ok((created, expires, nonce, key_id))
}

/// The `Signature` header's byte sequence for `label`, transcoded to the
/// base64url form the core verifier consumes.
fn signature_value_b64url(
    headers: &[(String, String)],
    header_error: &'static str,
    label: &str,
) -> Result<String, HttpProfileError> {
    let signature_header = required_header(headers, "signature")
        .map_err(|_| HttpProfileError::MissingEvidence(header_error))?;
    let member = member_value(signature_header, label)?;
    let b64 = member
        .strip_prefix(':')
        .and_then(|s| s.strip_suffix(':'))
        .ok_or(HttpProfileError::MalformedEvidence(
            "signature byte sequence",
        ))?;
    let bytes = base64_standard_decode(b64)?;
    Ok(mcp_re_core::b64url_encode(&bytes))
}

fn require_components(
    covered: &[CoveredComponent],
    required_plain: &[&'static str],
    required_req: &[&'static str],
) -> Result<(), HttpProfileError> {
    for name in required_plain {
        if !covered.iter().any(|c| !c.req && c.name == *name) {
            return Err(HttpProfileError::MissingCoveredComponent(name));
        }
    }
    for name in required_req {
        if !covered.iter().any(|c| c.req && c.name == *name) {
            return Err(HttpProfileError::MissingCoveredComponent(name));
        }
    }
    Ok(())
}

/// Verify a signed MCP-RE/HTTP request. `resolve_key` is the trust seam: it
/// maps a keyid to a verification key ONLY if local policy trusts that key for
/// this route/audience — a keyid never introduces trust (CONTEXT.md anchor
/// rule; v0.11 grill B.1).
pub fn verify_request(
    request: &HttpRequest,
    resolve_actor: &dyn Fn(&str, SignerSlot) -> Option<ResolvedActor>,
    now: i64,
) -> Result<VerifiedHttpRequestEvidence, HttpProfileError> {
    reject_content_encoding(&request.headers)?;

    // 1. Content binding first: the body must match its digest before any
    //    signature statement about that digest is even considered.
    let digest_header = required_header(&request.headers, "content-digest")?;
    verify_content_digest_sha256(digest_header, &request.body)?;
    let content_digest = digest_header.to_owned();

    // 2. Parse evidence.
    let input_header = required_header(&request.headers, "signature-input")?;
    let parsed = parse_signature_input(member_value(input_header, REQUEST_LABEL)?)?;
    require_components(&parsed.components, &REQUIRED_REQUEST_COMPONENTS, &[])?;
    if parsed.components.iter().any(|c| c.req) {
        return Err(HttpProfileError::MalformedEvidence(
            "req component on a request",
        ));
    }
    // Conditional coverage is mandatory when the header is present.
    if single_header(&request.headers, "authorization")?.is_some()
        && !parsed.components.iter().any(|c| c.name == "authorization")
    {
        return Err(HttpProfileError::MissingCoveredComponent("authorization"));
    }
    if single_header(&request.headers, "dpop")?.is_some()
        && !parsed.components.iter().any(|c| c.name == "dpop")
    {
        return Err(HttpProfileError::MissingCoveredComponent("dpop"));
    }
    let (created, expires, nonce, key_id) = check_params(&parsed.params, now, true)?;

    // 3. Trust resolution for the REQUEST slot: a keyid never introduces trust,
    //    and a key not trusted to sign requests fails actor_binding_failed.
    let resolved_actor = resolve_actor_for(resolve_actor, &key_id, SignerSlot::Request)?;
    // 4. Signature over the reconstructed base.
    let base = signature_base(
        &parsed.components,
        &parsed.params,
        &SourceMessage::Request(request),
    )?;
    let sig = signature_value_b64url(&request.headers, "signature", REQUEST_LABEL)?;
    verify_ed25519_with(
        &base,
        &sig,
        &resolved_actor.verification_key,
        McpReError::InvalidSignature,
    )
    .map_err(|_| HttpProfileError::InvalidSignature)?;

    // 5. Derive the handle from the exact verified base and return the full
    //    verified evidence context.
    Ok(VerifiedHttpRequestEvidence {
        profile_id: PROFILE_TAG.to_owned(),
        signature_label: REQUEST_LABEL.to_owned(),
        resolved_actor,
        evidence: RequestEvidence::from_signature_base(&base),
        content_digest,
        created,
        expires,
        nonce,
        key_id,
        audience: None,
        audience_hash: None,
        request_block: None,
    })
}

/// Full-profile request verification (MCPRE-101): the minimal proof path PLUS
/// the request evidence block (`se.syncom/mcp-re.http.request`). Runs the
/// cryptographic floor first, then parses the block (protected by the covered
/// `content-digest`), enforces the profile tag, the audience tuple, and — strictly
/// — every `artifact_bindings[]` entry.
///
/// `expected_audience` is the verifier's own audience tuple: the block's
/// audience must equal it AND its `target_uri` must match the request
/// `@target-uri`. `artifact_material` supplies the credential bytes for bindings
/// the verifier cannot derive from covered headers (mTLS cert, RAR details,
/// etc.); DPoP is derived from the covered `Authorization` header. A binding with
/// no obtainable credential fails `artifact_binding_failed` — full profile never
/// silently accepts an unverifiable binding.
pub fn verify_request_full(
    request: &HttpRequest,
    expected_audience: &AudienceTuple,
    artifact_material: &dyn Fn(&ArtifactBinding) -> Option<Vec<u8>>,
    resolve_actor: &dyn Fn(&str, SignerSlot) -> Option<ResolvedActor>,
    now: i64,
) -> Result<VerifiedHttpRequestEvidence, HttpProfileError> {
    // 1. Cryptographic floor: content digest, evidence, trust, signature.
    let mut verified = verify_request(request, resolve_actor, now)?;

    // 2. Parse the request evidence block — protected because content-digest is a
    //    covered component of the signature just verified.
    let block: HttpRequestEvidenceBlock =
        extract_meta_block(&request.body, REQUEST_EVIDENCE_BLOCK_KEY, "request evidence block")?;
    block.validate(&verified.profile_id)?;

    // 3. Audience binding: block audience == expected, and the expected tuple's
    //    target URI is consistent with the request @target-uri (guards routed /
    //    reverse-proxied deployments where a label could alias two dispatch
    //    boundaries).
    if block.audience != *expected_audience || expected_audience.target_uri != request.target_uri {
        return Err(HttpProfileError::AudienceMismatch);
    }

    // 4. Strict artifact enforcement: every present binding must verify.
    for binding in &block.artifact_bindings {
        let credential = resolve_artifact_credential(binding, &request.headers, artifact_material)
            .ok_or(HttpProfileError::ArtifactBindingFailed)?;
        verify_artifact_binding(binding, &credential)?;
    }

    verified.audience_hash = Some(block.audience.audience_hash());
    verified.audience = Some(block.audience.clone());
    verified.request_block = Some(block);
    Ok(verified)
}

/// Obtain the credential bytes a binding commits to. DPoP `ath` binds the access
/// token in the covered `Authorization` header (falling back to caller material
/// if the header is absent); every other artifact type is caller-supplied. A
/// `None` here means the credential surface is unavailable — the caller treats
/// that as `artifact_binding_failed`.
fn resolve_artifact_credential(
    binding: &ArtifactBinding,
    headers: &[(String, String)],
    artifact_material: &dyn Fn(&ArtifactBinding) -> Option<Vec<u8>>,
) -> Option<Vec<u8>> {
    match binding.artifact_type {
        ArtifactType::OauthDpop => {
            authorization_bearer_bytes(headers).or_else(|| artifact_material(binding))
        }
        _ => artifact_material(binding),
    }
}

/// Verify a signed MCP-RE/HTTP response against the exact request the caller
/// sent. The `;req` components are resolved from `request`, so a spliced
/// response (signed for a different request) fails the signature.
pub fn verify_response(
    response: &HttpResponse,
    request: &HttpRequest,
    resolve_actor: &dyn Fn(&str, SignerSlot) -> Option<ResolvedActor>,
    now: i64,
) -> Result<VerifiedHttpResponseEvidence, HttpProfileError> {
    reject_content_encoding(&response.headers)?;

    let digest_header = required_header(&response.headers, "content-digest")
        .map_err(|_| HttpProfileError::MissingEvidence("response content-digest"))?;
    verify_content_digest_sha256(digest_header, &response.body)?;

    let input_header = required_header(&response.headers, "signature-input")
        .map_err(|_| HttpProfileError::MissingEvidence("response signature-input"))?;
    let parsed = parse_signature_input(member_value(input_header, RESPONSE_LABEL)?)?;
    require_components(
        &parsed.components,
        &REQUIRED_RESPONSE_COMPONENTS,
        &REQUIRED_RESPONSE_REQ_COMPONENTS,
    )?;
    let (_created, _expires, _nonce, key_id) = check_params(&parsed.params, now, false)?;

    // Trust resolution for the RESPONSE slot: a request-signer key presented on
    // a response fails actor_binding_failed.
    let resolved_server_actor = resolve_actor_for(resolve_actor, &key_id, SignerSlot::Response)?;
    let base = signature_base(
        &parsed.components,
        &parsed.params,
        &SourceMessage::Response { response, request },
    )?;
    let sig = signature_value_b64url(&response.headers, "response signature", RESPONSE_LABEL)?;
    verify_ed25519_with(
        &base,
        &sig,
        &resolved_server_actor.verification_key,
        McpReError::ResponseSigInvalid,
    )
    .map_err(|_| HttpProfileError::ResponseSignatureInvalid)?;
    Ok(VerifiedHttpResponseEvidence {
        resolved_server_actor,
        response_signature_base_digest: RequestEvidence::from_signature_base(&base),
        bound_request_evidence: None,
        body_request_evidence: None,
        server_signer: None,
    })
}

/// Full-profile response verification (MCPRE-101): the `;req`-bound minimal
/// verification PLUS the response evidence block (`se.syncom/mcp-re.http.response`).
/// After the signature verifies, the block is parsed and:
///
/// 1. its `profile` must be the profile tag;
/// 2. its `server_signer.keyid` must match the keyid the response signature was
///    accepted under (a forged `server_signer` is a splice);
/// 3. its `request_evidence` must equal the verified request's evidence handle —
///    explicit MCP semantic defense-in-depth ON TOP of the cryptographic `;req`
///    binding. A mismatch is `request_binding_mismatch`.
///
/// `verified_request` is the [`VerifiedHttpRequestEvidence`] from
/// `verify_request_full`; its `evidence` handle is the recomputed request
/// signature-base digest compared here — no re-parse of the request.
pub fn verify_response_full(
    response: &HttpResponse,
    request: &HttpRequest,
    verified_request: &VerifiedHttpRequestEvidence,
    resolve_actor: &dyn Fn(&str, SignerSlot) -> Option<ResolvedActor>,
    now: i64,
) -> Result<VerifiedHttpResponseEvidence, HttpProfileError> {
    verify_response_bound_full(
        response,
        request,
        &verified_request.evidence,
        resolve_actor,
        now,
    )
}

/// Full-profile response verification bound to a request evidence HANDLE
/// ([`RequestEvidence`]) rather than the whole [`VerifiedHttpRequestEvidence`].
///
/// This is the CLIENT-side entry point: the client that signed the request holds
/// only the [`RequestEvidence`] handle (`SignedRequest::evidence`), not a
/// server-style verified-request context. Semantics are otherwise identical to
/// [`verify_response_full`] — the `;req` cryptographic floor plus the response
/// evidence block's `profile` / `server_signer.keyid` / `request_evidence` checks.
pub fn verify_response_bound_full(
    response: &HttpResponse,
    request: &HttpRequest,
    bound_request_evidence: &RequestEvidence,
    resolve_actor: &dyn Fn(&str, SignerSlot) -> Option<ResolvedActor>,
    now: i64,
) -> Result<VerifiedHttpResponseEvidence, HttpProfileError> {
    // 1. Cryptographic floor incl. the ;req binding to `request`.
    let mut evidence = verify_response(response, request, resolve_actor, now)?;

    // 2. Parse the response evidence block (protected by content-digest).
    let block: HttpResponseEvidenceBlock = extract_meta_block(
        &response.body,
        RESPONSE_EVIDENCE_BLOCK_KEY,
        "response evidence block",
    )?;
    block.validate(PROFILE_TAG)?;

    // 3. server_signer must be the identity that actually signed.
    if block.server_signer.keyid != evidence.resolved_server_actor.identity.keyid {
        return Err(HttpProfileError::ResponseBindingMismatch);
    }

    // 4. Explicit request-evidence comparison: body handle == the request
    //    signature-base digest the caller holds. This is the precise
    //    `request_binding_mismatch` path (the ;req floor already rejects a
    //    cryptographic splice above).
    if block.request_evidence.digest_alg != bound_request_evidence.digest_alg
        || block.request_evidence.digest_value != bound_request_evidence.digest_value
    {
        return Err(HttpProfileError::ResponseBindingMismatch);
    }

    evidence.bound_request_evidence = Some(bound_request_evidence.clone());
    evidence.body_request_evidence = Some(RequestEvidence {
        digest_alg: block.request_evidence.digest_alg.clone(),
        digest_value: block.request_evidence.digest_value.clone(),
    });
    evidence.server_signer = Some(block.server_signer);
    Ok(evidence)
}

/// Deployment policy for verifying a delegated-key-signed response
/// (ADR-MCPRE-052 §3). Supplied by the integration layer from the active profile,
/// the verified request context, and the deployment's epoch/audience policy.
pub struct DelegationExpectations<'a> {
    /// This verifier's own audience identifier(s); the credential's `aud` must
    /// name one (§3 step 5).
    pub verifier_audiences: &'a [&'a str],
    /// The service/audience-scope hash the delegated key must be scoped to
    /// (§3 step 5) — the request's audience hash.
    pub expected_audience_hash: &'a str,
    /// The active accepted trust-epoch set — default `{ current }`, optionally
    /// `{ current, previous }` under a bounded rollout window (§3 step 6).
    pub accepted_epochs: &'a [&'a str],
    /// Clock-skew tolerance for credential freshness (§3 step 4).
    pub max_clock_skew: i64,
}

/// Verify a delegated-key-signed response end-to-end (ADR-MCPRE-052 §3).
///
/// Delegation is **REQUIRED** here (§3 step 1): a response carrying no inline
/// credential — INCLUDING a directly root-signed one — is rejected
/// `delegation_credential_missing`. The credential chain to the root (steps 2–7)
/// is verified via [`verify_delegation_credential`]; the root is resolved through
/// the trust seam for the Response slot, and the delegated key is never enrolled
/// out of band. The RFC 9421 response signature is then verified under `cnf.jwk`
/// with the response `keyid == delegated_kid` (§3 step 8).
///
/// `resolve_actor(issuer_kid, Response)` must resolve the credential's root
/// `issuer_kid`; `is_revoked(kid)` reports revocation at the current epoch.
///
/// `verified_request` is the [`VerifiedHttpRequestEvidence`] from
/// `verify_request_full`; only its `evidence` handle is used. A client that signed
/// the request holds only that [`RequestEvidence`] handle — it uses
/// [`verify_delegated_response_bound_full`] directly (the delegated analogue of
/// [`verify_response_bound_full`]).
#[allow(clippy::too_many_arguments)]
pub fn verify_delegated_response_full(
    response: &HttpResponse,
    request: &HttpRequest,
    verified_request: &VerifiedHttpRequestEvidence,
    resolve_actor: &dyn Fn(&str, SignerSlot) -> Option<ResolvedActor>,
    expect: &DelegationExpectations<'_>,
    is_revoked: &dyn Fn(&str) -> bool,
    now: i64,
) -> Result<VerifiedHttpResponseEvidence, HttpProfileError> {
    verify_delegated_response_bound_full(
        response,
        request,
        &verified_request.evidence,
        resolve_actor,
        expect,
        is_revoked,
        now,
    )
}

/// Delegated-response verification bound to a request evidence HANDLE
/// ([`RequestEvidence`]) rather than the whole [`VerifiedHttpRequestEvidence`] — the
/// CLIENT-side entry point (the delegated analogue of [`verify_response_bound_full`]).
///
/// Semantics are identical to [`verify_delegated_response_full`]: delegation is
/// REQUIRED (a response with no inline credential — including a directly root-signed
/// one — is rejected `delegation_credential_missing`), the credential chain to the
/// root is verified, and the `;req`-bound response signature is verified under
/// `cnf.jwk`. The only difference is that the request-evidence binding is compared
/// against the passed `bound_request_evidence` handle the client kept from signing.
#[allow(clippy::too_many_arguments)]
pub fn verify_delegated_response_bound_full(
    response: &HttpResponse,
    request: &HttpRequest,
    bound_request_evidence: &RequestEvidence,
    resolve_actor: &dyn Fn(&str, SignerSlot) -> Option<ResolvedActor>,
    expect: &DelegationExpectations<'_>,
    is_revoked: &dyn Fn(&str) -> bool,
    now: i64,
) -> Result<VerifiedHttpResponseEvidence, HttpProfileError> {
    // Content-digest floor (same as verify_response).
    reject_content_encoding(&response.headers)?;
    let digest_header = required_header(&response.headers, "content-digest")
        .map_err(|_| HttpProfileError::MissingEvidence("response content-digest"))?;
    verify_content_digest_sha256(digest_header, &response.body)?;

    // Signature-input parse + required components + params gate (keyid).
    let input_header = required_header(&response.headers, "signature-input")
        .map_err(|_| HttpProfileError::MissingEvidence("response signature-input"))?;
    let parsed = parse_signature_input(member_value(input_header, RESPONSE_LABEL)?)?;
    require_components(
        &parsed.components,
        &REQUIRED_RESPONSE_COMPONENTS,
        &REQUIRED_RESPONSE_REQ_COMPONENTS,
    )?;
    let (_created, _expires, _nonce, key_id) = check_params(&parsed.params, now, false)?;

    // Response evidence block (protected by content-digest).
    let block: HttpResponseEvidenceBlock = extract_meta_block(
        &response.body,
        RESPONSE_EVIDENCE_BLOCK_KEY,
        "response evidence block",
    )?;
    block.validate(PROFILE_TAG)?;

    // Step 1 (required mode): a response with no delegation credential — including
    // a directly root-signed one — is rejected.
    let credential = block
        .server_delegation
        .as_deref()
        .ok_or(HttpProfileError::DelegationCredentialMissing)?;

    // Steps 2–7: verify the credential chain to the root. The credential is scoped
    // to the resolved server signer the block declares; a lifted credential fails
    // the scope check (§3 step 5).
    let expected_server_signer = block.server_signer.actor_id();
    let params = DelegationVerifyParams {
        now,
        max_clock_skew: expect.max_clock_skew,
        verifier_audiences: expect.verifier_audiences,
        expected_profile: PROFILE_TAG,
        expected_audience_hash: expect.expected_audience_hash,
        expected_server_signer: &expected_server_signer,
        accepted_epochs: expect.accepted_epochs,
    };
    let verified = verify_delegation_credential(
        credential,
        &params,
        |issuer_kid| resolve_actor(issuer_kid, SignerSlot::Response).map(|a| a.verification_key),
        |kid| is_revoked(kid),
    )?;

    // Step 8: the response keyid is the delegated key, the block names it, and the
    // response signature verifies under cnf.jwk.
    if key_id != verified.delegated_kid || block.server_signer.keyid != verified.delegated_kid {
        return Err(HttpProfileError::DelegationKeyMismatch);
    }
    let base = signature_base(
        &parsed.components,
        &parsed.params,
        &SourceMessage::Response { response, request },
    )?;
    let sig = signature_value_b64url(&response.headers, "response signature", RESPONSE_LABEL)?;
    verify_ed25519_with(
        &base,
        &sig,
        &verified.delegated_key,
        McpReError::ResponseSigInvalid,
    )
    .map_err(|_| HttpProfileError::DelegationKeyMismatch)?;

    // Request-evidence binding (explicit MCP defense-in-depth, as verify_response_full).
    let bound = bound_request_evidence;
    if block.request_evidence.digest_alg != bound.digest_alg
        || block.request_evidence.digest_value != bound.digest_value
    {
        return Err(HttpProfileError::ResponseBindingMismatch);
    }

    // The resolved server actor is authorized by the CREDENTIAL, not the trust
    // map: its verification key is the delegated key, its identity is the block's
    // server_signer, vouched for the Response slot through the credential chain.
    let server_signer = block.server_signer.clone();
    Ok(VerifiedHttpResponseEvidence {
        resolved_server_actor: ResolvedActor {
            identity: server_signer.clone(),
            verification_key: verified.delegated_key,
            slot: SignerSlot::Response,
        },
        response_signature_base_digest: RequestEvidence::from_signature_base(&base),
        bound_request_evidence: Some(bound.clone()),
        body_request_evidence: Some(RequestEvidence {
            digest_alg: block.request_evidence.digest_alg.clone(),
            digest_value: block.request_evidence.digest_value.clone(),
        }),
        server_signer: Some(server_signer),
    })
}

/// Verify a delegated-key-signed response with NO request binding (ADR-MCPRE-052;
/// the preflight-unbound rejection case, MCPRE-122). The credential chain to the
/// root (§3 steps 1–7) and the response signature under `cnf.jwk` (§3 step 8) are
/// verified exactly as in [`verify_delegated_response_full`], but the signature
/// covers only the response components — there is no `;req` binding and no
/// request-evidence comparison, because no trustworthy request context exists.
///
/// The block's `request_evidence` (a digest of the received bytes, if any) is
/// diagnostic and is NOT treated as a binding here. Delegation remains REQUIRED: a
/// response with no inline credential — including a directly root-signed one — is
/// rejected `delegation_credential_missing`.
pub fn verify_delegated_response_unbound(
    response: &HttpResponse,
    resolve_actor: &dyn Fn(&str, SignerSlot) -> Option<ResolvedActor>,
    expect: &DelegationExpectations<'_>,
    is_revoked: &dyn Fn(&str) -> bool,
    now: i64,
) -> Result<VerifiedHttpResponseEvidence, HttpProfileError> {
    // Content-digest floor.
    reject_content_encoding(&response.headers)?;
    let digest_header = required_header(&response.headers, "content-digest")
        .map_err(|_| HttpProfileError::MissingEvidence("response content-digest"))?;
    verify_content_digest_sha256(digest_header, &response.body)?;

    // Response-only signature parse: required response components, and NO `;req`.
    let input_header = required_header(&response.headers, "signature-input")
        .map_err(|_| HttpProfileError::MissingEvidence("response signature-input"))?;
    let parsed = parse_signature_input(member_value(input_header, RESPONSE_LABEL)?)?;
    require_components(&parsed.components, &REQUIRED_RESPONSE_COMPONENTS, &[])?;
    if parsed.components.iter().any(|c| c.req) {
        return Err(HttpProfileError::MalformedEvidence(
            "req component without request context",
        ));
    }
    let (_created, _expires, _nonce, key_id) = check_params(&parsed.params, now, false)?;

    // Response evidence block (protected by content-digest).
    let block: HttpResponseEvidenceBlock = extract_meta_block(
        &response.body,
        RESPONSE_EVIDENCE_BLOCK_KEY,
        "response evidence block",
    )?;
    block.validate(PROFILE_TAG)?;

    // Step 1 (required mode): no inline credential — including a directly
    // root-signed one — is rejected.
    let credential = block
        .server_delegation
        .as_deref()
        .ok_or(HttpProfileError::DelegationCredentialMissing)?;

    // Steps 2–7: verify the credential chain to the root, scoped to the block's
    // declared server signer (a lifted credential fails the scope check).
    let expected_server_signer = block.server_signer.actor_id();
    let params = DelegationVerifyParams {
        now,
        max_clock_skew: expect.max_clock_skew,
        verifier_audiences: expect.verifier_audiences,
        expected_profile: PROFILE_TAG,
        expected_audience_hash: expect.expected_audience_hash,
        expected_server_signer: &expected_server_signer,
        accepted_epochs: expect.accepted_epochs,
    };
    let verified = verify_delegation_credential(
        credential,
        &params,
        |issuer_kid| resolve_actor(issuer_kid, SignerSlot::Response).map(|a| a.verification_key),
        |kid| is_revoked(kid),
    )?;

    // Step 8: the response keyid is the delegated key, the block names it, and the
    // response-only signature verifies under cnf.jwk.
    if key_id != verified.delegated_kid || block.server_signer.keyid != verified.delegated_kid {
        return Err(HttpProfileError::DelegationKeyMismatch);
    }
    let base = signature_base(
        &parsed.components,
        &parsed.params,
        &SourceMessage::ResponseOnly(response),
    )?;
    let sig = signature_value_b64url(&response.headers, "response signature", RESPONSE_LABEL)?;
    verify_ed25519_with(
        &base,
        &sig,
        &verified.delegated_key,
        McpReError::ResponseSigInvalid,
    )
    .map_err(|_| HttpProfileError::DelegationKeyMismatch)?;

    let server_signer = block.server_signer.clone();
    Ok(VerifiedHttpResponseEvidence {
        resolved_server_actor: ResolvedActor {
            identity: server_signer.clone(),
            verification_key: verified.delegated_key,
            slot: SignerSlot::Response,
        },
        response_signature_base_digest: RequestEvidence::from_signature_base(&base),
        bound_request_evidence: None,
        body_request_evidence: None,
        server_signer: Some(server_signer),
    })
}

/// Verify a signed MCP-RE/HTTP response with NO request context (MCPRE-96): a
/// rejection emitted before a request could be parsed. Covers only the response
/// components; any `;req` component is malformed here (there is no request to
/// resolve it against).
pub fn verify_response_unbound(
    response: &HttpResponse,
    resolve_actor: &dyn Fn(&str, SignerSlot) -> Option<ResolvedActor>,
    now: i64,
) -> Result<VerifiedHttpResponseEvidence, HttpProfileError> {
    reject_content_encoding(&response.headers)?;

    let digest_header = required_header(&response.headers, "content-digest")
        .map_err(|_| HttpProfileError::MissingEvidence("response content-digest"))?;
    verify_content_digest_sha256(digest_header, &response.body)?;

    let input_header = required_header(&response.headers, "signature-input")
        .map_err(|_| HttpProfileError::MissingEvidence("response signature-input"))?;
    let parsed = parse_signature_input(member_value(input_header, RESPONSE_LABEL)?)?;
    require_components(&parsed.components, &REQUIRED_RESPONSE_COMPONENTS, &[])?;
    if parsed.components.iter().any(|c| c.req) {
        return Err(HttpProfileError::MalformedEvidence(
            "req component without request context",
        ));
    }
    let (_created, _expires, _nonce, key_id) = check_params(&parsed.params, now, false)?;

    let resolved_server_actor = resolve_actor_for(resolve_actor, &key_id, SignerSlot::Response)?;
    let base = signature_base(
        &parsed.components,
        &parsed.params,
        &SourceMessage::ResponseOnly(response),
    )?;
    let sig = signature_value_b64url(&response.headers, "response signature", RESPONSE_LABEL)?;
    verify_ed25519_with(
        &base,
        &sig,
        &resolved_server_actor.verification_key,
        McpReError::ResponseSigInvalid,
    )
    .map_err(|_| HttpProfileError::ResponseSignatureInvalid)?;
    Ok(VerifiedHttpResponseEvidence {
        resolved_server_actor,
        response_signature_base_digest: RequestEvidence::from_signature_base(&base),
        bound_request_evidence: None,
        body_request_evidence: None,
        server_signer: None,
    })
}
