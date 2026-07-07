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

use crate::block::ResolvedActor;
use crate::block::SignerSlot;
use crate::digest::verify_content_digest_sha256;
use crate::error::HttpProfileError;
use crate::evidence::RequestEvidence;
use crate::ids::ALG_ED25519;
use crate::ids::PROFILE_TAG;
use crate::ids::REQUEST_LABEL;
use crate::ids::REQUIRED_REQUEST_COMPONENTS;
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
    /// The request evidence this response binds to, when the caller supplies it
    /// (MCPRE-101/102). `None` on the seam-only verification path.
    pub bound_request_evidence: Option<RequestEvidence>,
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
    })
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
    })
}
