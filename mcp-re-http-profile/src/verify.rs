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
use mcp_re_core::VerificationKey;

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

/// The verifier's product for a request: the evidence handle (for response
/// binding, MRTR, audit) plus the accepted freshness window.
#[derive(Debug, Clone)]
pub struct VerifiedHttpRequest {
    pub evidence: RequestEvidence,
    pub created: i64,
    pub expires: i64,
    pub nonce: String,
    pub key_id: String,
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
    resolve_key: &dyn Fn(&str) -> Option<VerificationKey>,
    now: i64,
) -> Result<VerifiedHttpRequest, HttpProfileError> {
    reject_content_encoding(&request.headers)?;

    // 1. Content binding first: the body must match its digest before any
    //    signature statement about that digest is even considered.
    let digest_header = required_header(&request.headers, "content-digest")?;
    verify_content_digest_sha256(digest_header, &request.body)?;

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

    // 3. Trust resolution, 4. signature over the reconstructed base.
    let key = resolve_key(&key_id).ok_or(HttpProfileError::UnresolvedKeyId)?;
    let base = signature_base(
        &parsed.components,
        &parsed.params,
        &SourceMessage::Request(request),
    )?;
    let sig = signature_value_b64url(&request.headers, "signature", REQUEST_LABEL)?;
    verify_ed25519_with(&base, &sig, &key, McpReError::InvalidSignature)
        .map_err(|_| HttpProfileError::InvalidSignature)?;

    // 5. Derive the handle from the exact verified base.
    Ok(VerifiedHttpRequest {
        evidence: RequestEvidence::from_signature_base(&base),
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
    resolve_key: &dyn Fn(&str) -> Option<VerificationKey>,
    now: i64,
) -> Result<(), HttpProfileError> {
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

    let key = resolve_key(&key_id).ok_or(HttpProfileError::UnresolvedKeyId)?;
    let base = signature_base(
        &parsed.components,
        &parsed.params,
        &SourceMessage::Response { response, request },
    )?;
    let sig = signature_value_b64url(&response.headers, "response signature", RESPONSE_LABEL)?;
    verify_ed25519_with(&base, &sig, &key, McpReError::ResponseSigInvalid)
        .map_err(|_| HttpProfileError::ResponseSignatureInvalid)?;
    Ok(())
}

/// Verify a signed MCP-RE/HTTP response with NO request context (MCPRE-96): a
/// rejection emitted before a request could be parsed. Covers only the response
/// components; any `;req` component is malformed here (there is no request to
/// resolve it against).
pub fn verify_response_unbound(
    response: &HttpResponse,
    resolve_key: &dyn Fn(&str) -> Option<VerificationKey>,
    now: i64,
) -> Result<(), HttpProfileError> {
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

    let key = resolve_key(&key_id).ok_or(HttpProfileError::UnresolvedKeyId)?;
    let base = signature_base(
        &parsed.components,
        &parsed.params,
        &SourceMessage::ResponseOnly(response),
    )?;
    let sig = signature_value_b64url(&response.headers, "response signature", RESPONSE_LABEL)?;
    verify_ed25519_with(&base, &sig, &key, McpReError::ResponseSigInvalid)
        .map_err(|_| HttpProfileError::ResponseSignatureInvalid)?;
    Ok(())
}
