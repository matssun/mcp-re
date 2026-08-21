// SPDX-License-Identifier: Apache-2.0
//! Verifier side of the proof path. Everything fails closed: missing or
//! duplicated evidence headers, unknown tag, wrong algorithm, stale window,
//! unresolved keyid, digest mismatch, missing covered component, and any
//! cryptographic failure all reject.
//!
//! Verification order (v0.11 grill C.1): content-digest first, then evidence
//! parse, then keyid resolution through the caller's trust seam, then the
//! signature over the reconstructed base, then handle derivation.

// ADR-MCPRE-059 Phase 2. Absent from every production build: the imports are
// feature-gated and each specification rides a `cfg_attr` that expands to nothing
// unless `--features verify` is on.
#[cfg(feature = "verify")]
use verus_builtin_macros::{verus_spec, verus_verify};
#[cfg(feature = "verify")]
#[allow(unused_imports)]
use vstd::prelude::*;

use mcp_re_core::verify_ed25519_with;
use mcp_re_core::McpReError;

use crate::artifact::verify_artifact_binding;
use crate::block::ArtifactBinding;
use crate::block::ArtifactType;
use crate::block::AudienceTuple;
use crate::block::HttpRequestEvidenceBlock;
use crate::block::HttpResponseEvidenceBlock;
use crate::block::ResolvedActor;
use crate::block::ResolverOutcome;
use crate::block::SignerSlot;
use crate::body::authorization_bearer_bytes;
use crate::body::extract_meta_block;
use crate::delegation::verify_delegation_credential;
use crate::delegation::DelegationVerifyParams;
use crate::delegation::VerifiedDelegation;
use crate::digest::verify_content_digest_sha256;
use crate::error::HttpProfileError;
use crate::evidence::RequestEvidence;
use crate::ids::MCP_METHOD_HEADER;
use crate::ids::MCP_NAME_HEADER;
use crate::ids::MCP_PROTOCOL_VERSION_HEADER;
use crate::ids::PROFILE_TAG;
use crate::ids::REQUEST_EVIDENCE_BLOCK_KEY;
use crate::ids::REQUEST_LABEL;
use crate::ids::REQUIRED_REQUEST_COMPONENTS;
use crate::ids::REQUIRED_RESPONSE_COMPONENTS;
use crate::ids::REQUIRED_RESPONSE_REQ_COMPONENTS;
use crate::ids::RESPONSE_EVIDENCE_BLOCK_KEY;
use crate::ids::RESPONSE_LABEL;
use crate::message::reject_content_encoding;
use crate::message::require_json_media_type;
use crate::message::required_header;
use crate::message::single_header;
use crate::message::HttpRequest;
use crate::message::HttpResponse;
use crate::policy::ProfileAlgorithm;
use crate::policy::VerifierPolicy;
use crate::sigbase::signature_base;
use crate::sigbase::CoveredComponent;
use crate::sigbase::SignatureParams;
use crate::sigbase::SourceMessage;
use crate::sign::base64_standard_decode;
use crate::verified_request::CryptographicFloorVerifiedRequest;
use crate::verified_request::VerifiedMcpRequest;
use crate::verified_response::block_agreement;
use crate::verified_response::AcceptedResponseSigner;
use crate::verified_response::BoundResponseSignatureFacts;
use crate::verified_response::CryptographicFloorVerifiedBoundResponse;
use crate::verified_response::CryptographicFloorVerifiedUnboundResponse;
use crate::verified_response::UnboundResponseSignatureFacts;
use crate::verified_response::VerifiedDelegatedMcpResponse;
use crate::verified_response::VerifiedDelegatedUnboundResponse;
use crate::verified_response::VerifiedMcpResponse;

/// Resolve a keyid through the trust seam for a specific signing slot and apply
/// the typed defense-in-depth cross-check (MCPRE-100). The seam is the primary
/// slot-authorization authority: a key not trusted for `slot` resolves to `None`
/// and fails `actor_binding_failed`. The verifier additionally asserts the
/// returned actor is vouched for the slot it asked for — never a role-string
/// comparison — so a resolver that hands back a wrong-slot actor is also caught.
pub(crate) fn resolve_actor_for_slot<R: Into<ResolverOutcome>>(
    resolve_actor: &dyn Fn(&str, SignerSlot) -> R,
    key_id: &str,
    slot: SignerSlot,
) -> Result<ResolvedActor, HttpProfileError> {
    let actor = match resolve_actor(key_id, slot).into() {
        ResolverOutcome::Resolved(actor) => *actor,
        // A definitive negative from a healthy resolver.
        ResolverOutcome::NotTrusted => return Err(HttpProfileError::UnresolvedKeyId),
        // The resolver could not answer. Fail closed, but say WHICH failure it was
        // (C079): during a store outage the previous seam reported "untrusted key",
        // which sends an operator to look at the caller's credentials instead of at
        // their trust store.
        ResolverOutcome::Unavailable => return Err(HttpProfileError::TrustResolverUnavailable),
    };
    if actor.slot != slot {
        return Err(HttpProfileError::ActorSlotMismatch);
    }
    Ok(actor)
}

/// One parsed `Signature-Input` dictionary member.
pub(crate) struct ParsedSignatureInput {
    pub(crate) components: Vec<CoveredComponent>,
    pub(crate) params: SignatureParams,
}

/// Split a Structured Fields dictionary into members at top-level commas
/// (commas inside quoted strings do not split).
///
/// The quote state honours RFC 8941 `\` escapes. Without that, a `\"` inside a
/// member's string value toggled the state and left it odd, so the next top-level
/// comma was swallowed and TWO dictionary members merged into one — and this runs
/// BEFORE any value is validated, so the profile would be reading the merged text
/// as a single member's parameters before anything could reject the value that
/// caused it. Every construction traced from there still failed closed downstream,
/// but "the parser recovers by erroring" is not the same as splitting the
/// dictionary the way every other RFC 8941 implementation does.
fn split_dictionary(value: &str) -> Vec<&str> {
    let mut members = Vec::new();
    let mut start = 0usize;
    let mut in_quotes = false;
    let mut escaped = false;
    for (i, c) in value.char_indices() {
        if escaped {
            // Inside a string, `\` escapes exactly one following character; it never
            // ends the string.
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_quotes => escaped = true,
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

/// Split a signature-input's parameter section at top-level `;` — semicolons inside
/// a quoted string are part of the value, not separators.
///
/// Same reasoning as [`split_dictionary`]: a `;` inside a `nonce` used to cut the
/// value in half and produce a parameter list that was never on the wire. The halves
/// then failed to unquote, so this was fail-closed too, but the parse disagreed with
/// a conforming one before it got there.
fn split_parameters(value: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut in_quotes = false;
    let mut escaped = false;
    for (i, c) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_quotes => escaped = true,
            '"' => in_quotes = !in_quotes,
            ';' if !in_quotes => {
                parts.push(value[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(value[start..].trim());
    parts
}

/// Find the member value for `label` in a `Signature-Input`/`Signature`
/// dictionary header, fail-closed on absence, duplication, or whitespace the
/// dictionary grammar does not permit.
///
/// RFC 8941 §3.2 `dict-member = member-key ( parameters / ( "=" member-value ) )`
/// admits no OWS around the `=`; OWS is permitted only around the member-separating
/// comma, which [`split_dictionary`] trims. Normalizing whitespace after the `=`
/// away — as a `.trim()` here did — made `mcp-re= (...)` and `mcp-re=(...)` rebuild
/// to one signature base and verify under one signature. That is the same
/// wire-spelling collapse [`parse_signature_input`] refuses inside the member, one
/// layer up: an on-path intermediary could rewrite the raw header bytes without
/// invalidating anything, so an audit sink, a retained-evidence blob or a cache key
/// held bytes other than the ones that were signed. This is the sole reader of both
/// the `Signature-Input` and the `Signature` header, so every path inherits it.
fn member_value<'a>(header_value: &'a str, label: &str) -> Result<&'a str, HttpProfileError> {
    let mut found: Option<&'a str> = None;
    for member in split_dictionary(header_value) {
        // RFC 8941 §3.2's `dict-member` cannot be empty, so a leading, trailing or
        // doubled comma is not a spelling of the same dictionary — it is not a
        // dictionary. Skipping it silently, as an unparseable member, is the same
        // wire-spelling collapse the `=` rule above refuses: `mcp-re=(...)` and
        // `,mcp-re=(...),` would rebuild one signature base and verify under one
        // signature, so an intermediary could add or strip a comma in the raw header
        // and every consumer that logs, hashes, caches or diffs it would hold bytes
        // other than the ones that were signed.
        if member.is_empty() {
            return Err(HttpProfileError::MalformedEvidence(
                "empty dictionary member",
            ));
        }
        if let Some(rest) = member.strip_prefix(label) {
            if let Some(v) = rest.strip_prefix('=') {
                if found.is_some() {
                    return Err(HttpProfileError::MalformedEvidence(
                        "duplicate signature label",
                    ));
                }
                if v.trim() != v {
                    return Err(HttpProfileError::MalformedEvidence(
                        "dictionary member spacing",
                    ));
                }
                found = Some(v);
            }
        }
    }
    found.ok_or(HttpProfileError::MissingEvidence("signature label"))
}

/// Leak-free integer parse for created/expires, restricted to the ONE spelling
/// RFC 8941 §3.3.1 allows: optional `-`, then digits with no leading zero (except
/// `0` itself).
///
/// Rust's `i64::from_str` also accepts `+1700000000` and `0017`, which this profile
/// must not: the verifier rebuilds `@signature-params` from the PARSED values and
/// re-serializes them canonically ([`crate::sigbase`]), so every accepted spelling of
/// the same number collapses to one signature base. An intermediary could then
/// rewrite `created=1700000000` to `created=+1700000000` and the signature would
/// still verify, leaving any consumer that reads the raw header looking at bytes
/// other than the ones that were signed. Rejecting the alternate spellings keeps the
/// on-wire form pinned, the same reason parameter reordering is rejected structurally
/// rather than normalized away.
fn parse_i64(s: &str) -> Result<i64, HttpProfileError> {
    let malformed = || HttpProfileError::MalformedEvidence("integer signature parameter");
    let digits = s.strip_prefix('-').unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(malformed());
    }
    // No leading zeros: "0" is fine, "00" / "0017" / "-01" are not.
    if digits.len() > 1 && digits.starts_with('0') {
        return Err(malformed());
    }
    // And no NEGATIVE ZERO. RFC 8941 §3.3.1's sf-integer has no `-0`, and it slipped
    // through the leading-zero rule above (`digits` is "0", length 1): it parsed to 0
    // and re-serialised as "0", so `created=-0` and `created=0` collapsed to one
    // signature base — the exact spelling-collapse this function exists to refuse.
    if s.starts_with('-') && digits == "0" {
        return Err(malformed());
    }
    s.parse::<i64>().map_err(|_| malformed())
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
    // The inner list is EXACTLY single-space separated, with no leading or trailing
    // space — the one form `sigbase` emits. `split_whitespace` accepted any run of
    // spaces and tabs and collapsed them, so `("@method"  "@target-uri")` and
    // `( "@method"\t"@target-uri" )` rebuilt to the same signature base and verified
    // under the same signature. An on-path intermediary could then rewrite the raw
    // `Signature-Input` header without invalidating anything, and every consumer that
    // logs, hashes, caches or diffs the RAW header — an audit sink, a retained-evidence
    // blob, a CDN cache key — saw bytes other than the ones that were signed. No
    // forgery, but the one-to-one correspondence the profile claims for itself did not
    // hold.
    if list.starts_with(' ') || list.ends_with(' ') || list.contains("  ") {
        return Err(HttpProfileError::MalformedEvidence("inner list spacing"));
    }
    if list.bytes().any(|b| b == b'\t') {
        return Err(HttpProfileError::MalformedEvidence("inner list spacing"));
    }
    let mut components = Vec::new();
    for item in list.split(' ').filter(|i| !i.is_empty()) {
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
            // MCP transport headers (§4.1). Coverable so a deployment whose
            // protocol version defines them can bind them; still fail-closed for
            // everything outside this set.
            "mcp-method" => "mcp-method",
            "mcp-name" => "mcp-name",
            "mcp-protocol-version" => "mcp-protocol-version",
            // The delegation-credential header on a delegated bodyless 202
            // (#424): coverable so the credential it carries is protected by the
            // response signature. Only the bodyless-202 path requires it.
            "mcp-re-delegation" => "mcp-re-delegation",
            // The request-evidence header on a bodyless 202 (C019b): coverable so the
            // per-instance coordinate it carries is protected by the response
            // signature. Only the bodyless-202 path requires it.
            "mcp-re-request-evidence" => "mcp-re-request-evidence",
            _ => {
                return Err(HttpProfileError::MalformedEvidence(
                    "unknown covered component",
                ))
            }
        };
        let component = if req {
            CoveredComponent::req(known)
        } else {
            CoveredComponent::new(known)
        };
        // RFC 9421 §2.5 requires an error when an identifier is added to the base
        // twice. Beyond conformance, admitting duplicates would mean one message has
        // many valid signature bases — `signature_base` emits a line per occurrence —
        // and therefore many distinct evidence handles for the same bytes, so the
        // handle would stop being a function of the message. `;req` makes an
        // identifier distinct: "content-digest" and "content-digest";req name
        // different values, so only an exact (name, req) repeat is a duplicate. This
        // is the same exactly-once discipline already applied to duplicated header
        // FIELDS in `sigbase`.
        if components
            .iter()
            .any(|c: &CoveredComponent| c.name == component.name && c.req == component.req)
        {
            return Err(HttpProfileError::MalformedEvidence(
                "duplicate covered component",
            ));
        }
        components.push(component);
    }

    let mut params = SignatureParams::default();
    let mut last_param_rank: i32 = -1;
    // The parameter tail is EXACTLY `;k=v;k=v` — no space around a `;`, no empty
    // slot, no trailing `;`. `(...) ;created=1;` used to parse identically to
    // `(...);created=1`, which is the same wire-spelling collapse the inner-list check
    // above refuses: the base is rebuilt from parsed values, so both spellings verify
    // under one signature and the raw header stops matching the signed bytes.
    let param_tail = &value[close + 1..];
    if !param_tail.is_empty() {
        if !param_tail.starts_with(';') {
            return Err(HttpProfileError::MalformedEvidence(
                "signature parameter spacing",
            ));
        }
        // Only the segment before the FIRST `;` may be empty (there is nothing before
        // it); every other empty segment is a stray or trailing `;`.
        if split_parameters(param_tail)
            .iter()
            .skip(1)
            .any(|seg| seg.is_empty())
        {
            return Err(HttpProfileError::MalformedEvidence(
                "signature parameter spacing",
            ));
        }
        // No space or tab OUTSIDE a quoted value. Inside one it is a legitimate byte of
        // a keyid or nonce (`validate_sf_string` admits printable ASCII); outside, it
        // is a spelling this profile never emits and would normalise away.
        let mut in_quotes = false;
        let mut escaped = false;
        for b in param_tail.bytes() {
            match b {
                _ if escaped => escaped = false,
                b'\\' if in_quotes => escaped = true,
                b'"' => in_quotes = !in_quotes,
                b' ' | b'\t' if !in_quotes => {
                    return Err(HttpProfileError::MalformedEvidence(
                        "signature parameter spacing",
                    ))
                }
                _ => {}
            }
        }
    }
    for p in split_parameters(param_tail) {
        if p.is_empty() {
            continue;
        }
        let (k, v) = p
            .split_once('=')
            .ok_or(HttpProfileError::MalformedEvidence("signature parameter"))?;
        // A quoted string parameter, held to exactly what this profile will EMIT
        // (`sigbase::validate_sf_string`): printable ASCII with no `"` and no `\`.
        //
        // The escape forms RFC 8941 permits are refused rather than decoded. The
        // verifier rebuilds `@signature-params` from these parsed values and
        // re-serializes them canonically, so decoding `\"` would make two wire
        // spellings collapse to one signature base — the same defect the profile
        // already refuses for `created=+1` (see `parse_i64`). Refusing keeps the
        // received bytes and the signed bytes in one-to-one correspondence.
        let unquote = |v: &str| -> Result<String, HttpProfileError> {
            let inner = v
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .ok_or(HttpProfileError::MalformedEvidence(
                    "quoted signature parameter",
                ))?;
            crate::sigbase::validate_sf_string(inner, "quoted signature parameter")?;
            Ok(inner.to_owned())
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
            "nonce" => {
                let nonce = unquote(v)?;
                // A nonce is carried VERBATIM into the node-local replay key and
                // retained for up to `expires + skew`, and that tier bounds entry
                // COUNT, not entry SIZE. Without a length bound an authenticated
                // client could pad each nonce to the header limit and pin ~3 orders of
                // magnitude more memory per admitted request, ending in a self-inflicted
                // `replay_cache_unavailable` for the whole replica. The same bound is
                // applied where the signer SERIALIZES the parameter
                // (`sigbase::validate_nonce_length`), so a value this profile cannot
                // carry is never emitted either.
                crate::sigbase::validate_nonce_length(&nonce)?;
                params.nonce = Some(nonce);
            }
            "keyid" => params.keyid = Some(unquote(v)?),
            "alg" => params.alg = Some(unquote(v)?),
            "tag" => params.tag = Some(unquote(v)?),
            _ => unreachable!("rank match above is exhaustive over the closed set"),
        }
    }
    Ok(ParsedSignatureInput { components, params })
}

/// Shared parameter gate: tag, algorithm, freshness window, keyid presence.
///
/// Algorithm acceptance and clock-skew tolerance are read from `policy`, never
/// from the message (§13.1 / §5.1): the signature parameters state what the
/// signer did, the policy states what this verifier accepts.
// ADR-MCPRE-059 Phase 2 theorem — the live freshness rule (§5.1).
//
// This is the admission decision every served request passes through: if this function
// returns Ok, the message's window contains `now` after widening by the policy's skew in
// both directions, the window is non-degenerate, and it is no wider than the policy
// allows. Nothing is assumed about the skew or the validity bound themselves — the
// theorem holds for whatever a deployment configures, which is the property that matters,
// since the attacker chooses `created`/`expires` and the operator chooses the policy.
//
// The window-width clause carries its saturation explicitly rather than quietly assuming
// `expires - created` fits in an i64: it does not, for a hostile pair, and a theorem that
// pretended otherwise would be false exactly where it is load-bearing.
#[cfg_attr(feature = "verify", verus_spec(out =>
    ensures
        out matches Ok((created, expires, _nonce, _key_id, _algorithm)) ==> {
            &&& created - crate::verus_std_specs::skew_of(policy) <= now
            &&& now < expires + crate::verus_std_specs::skew_of(policy)
            &&& created < expires
            &&& (if expires - created > i64::MAX { i64::MAX as int } else { expires - created })
                    <= crate::verus_std_specs::validity_of(policy)
        },
))]
fn check_params(
    params: &SignatureParams,
    policy: &VerifierPolicy,
    now: i64,
    require_nonce: bool,
) -> Result<(i64, i64, String, String, ProfileAlgorithm), HttpProfileError> {
    match params.tag.as_deref() {
        Some(PROFILE_TAG) => {}
        _ => return Err(HttpProfileError::UnknownProfileTag),
    }
    // Resolve the DECLARED algorithm to one this verifier both accepts and can
    // check. The resolved value is returned, not discarded, so every caller must
    // dispatch on it — "is it allowed" and "what verifies it" are one answer.
    let algorithm = params
        .alg
        .as_deref()
        .and_then(|alg| policy.accepted_algorithm(alg))
        .ok_or(HttpProfileError::UnsupportedAlgorithm)?;
    let created = params.created.ok_or(HttpProfileError::StaleWindow)?;
    let expires = params.expires.ok_or(HttpProfileError::StaleWindow)?;
    // Freshness with a bounded, symmetric skew tolerance (§5.1): a `created`
    // slightly in the future and an `expires` slightly in the past are honest
    // clock disagreement, not evidence of staleness. `expires <= created` is
    // skew-free — a degenerate window is a property of the message itself, and
    // no amount of clock disagreement makes it well-formed.
    let skew = policy.max_clock_skew();
    if created.saturating_sub(skew) > now
        || expires.saturating_add(skew) <= now
        || expires <= created
    {
        return Err(HttpProfileError::StaleWindow);
    }
    // Bound how WIDE the signer may declare its own window (§5.1). Freshness above
    // decides when a window may be used; it says nothing about its width, so without
    // this a client can present `created = now, expires = now + 10y` — fresh, and
    // therefore accepted — and the replay tier then retains that nonce until
    // `expires + skew`. The retention a single client can pin would be client-chosen
    // and unbounded. The window is the message's own property, so like the degenerate
    // `expires <= created` case this is checked skew-free.
    if expires.saturating_sub(created) > policy.max_signature_validity() {
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
    Ok((created, expires, nonce, key_id, algorithm))
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

/// The MCP transport headers this profile can cover (§4.1).
///
/// `mcp-session-id` is deliberately ABSENT. Protocol sessions are a 2025-11-25
/// concept that MCP 2026-07-28 removes, and MCP-RE never adopted them: its
/// serving path is stateless per-request by design (ADR-MCPRE-051), so there is
/// no session for a session id to identify. Covering a header whose referent does
/// not exist would manufacture the appearance of a binding over nothing. If a
/// deployment sends one anyway it is simply not coverable, and the closed
/// allowlist rejects it as an unknown covered component — which is the correct
/// answer, not an oversight.
const MCP_COVERABLE_TRANSPORT_HEADERS: [&str; 3] = [
    MCP_METHOD_HEADER,
    MCP_NAME_HEADER,
    MCP_PROTOCOL_VERSION_HEADER,
];

/// Reject a request whose covered `Mcp-Method` header disagrees with the JSON-RPC
/// `method` in its covered body (§4.1).
///
/// Both values are protected by the signature by the time this runs, so a
/// disagreement is not tampering — it is the signer making two contradictory
/// statements about what it is asking for. The verifier refuses rather than
/// choosing a winner: the whole point of the transport header is that
/// intermediaries may read it, and an intermediary reading `tools/list` while the
/// server executes `tools/call` is precisely the divergence §4.1 closes.
///
/// The body is authoritative wherever this profile acts (ADR-MCPS-025); this does
/// not change that. It ensures the header cannot CLAIM otherwise.
fn reject_mcp_method_divergence(request: &HttpRequest) -> Result<(), HttpProfileError> {
    let Some(header_method) = single_header(&request.headers, MCP_METHOD_HEADER)? else {
        return Ok(());
    };
    let body: serde_json::Value = serde_json::from_slice(&request.body)
        .map_err(|_| HttpProfileError::MalformedEvidence("body json"))?;
    // A body with no `method` gives the header nothing to agree with, so the signed
    // value would be constrained by nothing at all — and an intermediary that routes,
    // rate-limits or audits on `Mcp-Method` (the stated reason §4.1 covers it) would
    // act on an arbitrary signer-chosen string carrying full authenticity. Skipping
    // the check here would make "the header always mirrors the body" true only for
    // the shapes that happen to have a body method. A message that sends this header
    // must therefore carry the `method` it mirrors.
    let Some(body_method) = body.get("method").and_then(|m| m.as_str()) else {
        return Err(HttpProfileError::McpMethodDivergence);
    };
    if header_method.trim() != body_method {
        return Err(HttpProfileError::McpMethodDivergence);
    }
    Ok(())
}

/// Verify `sig` over `base` under the RESOLVED algorithm.
///
/// The match is exhaustive over [`ProfileAlgorithm`], which is the point: a new
/// algorithm variant does not compile until its verifier is wired here. Before
/// this existed, every path called the Ed25519 verifier unconditionally, so a
/// policy that allowlisted an unimplemented algorithm accepted a message
/// declaring it while Ed25519 was what actually ran — algorithm confusion. The
/// policy now makes such a set unconstructible AND this dispatch makes the
/// verifier-per-algorithm coupling explicit rather than assumed.
pub(crate) fn verify_under(
    algorithm: ProfileAlgorithm,
    base: &[u8],
    sig: &str,
    key: &mcp_re_core::VerificationKey,
    on_fail: McpReError,
) -> Result<(), HttpProfileError> {
    let failure = match on_fail {
        McpReError::ResponseSigInvalid => HttpProfileError::ResponseSignatureInvalid,
        _ => HttpProfileError::InvalidSignature,
    };
    match algorithm {
        ProfileAlgorithm::Ed25519 => {
            verify_ed25519_with(base, sig, key, on_fail).map_err(|_| failure)
        }
    }
}

/// Parse the `Signature-Input` member for `label`. Shared with the bodyless
/// component sets (`crate::bodyless`) so both read one grammar: a second parser
/// would be a second place for the closed allowlist to drift.
pub(crate) fn parse_signature_input_for(
    headers: &[(String, String)],
    label: &str,
    what: &'static str,
) -> Result<ParsedSignatureInput, HttpProfileError> {
    let input_header = required_header(headers, "signature-input")
        .map_err(|_| HttpProfileError::MissingEvidence(what))?;
    parse_signature_input(member_value(input_header, label)?)
}

/// Enforce PRESENT ⇒ COVERED for every conditionally-mandatory request header
/// (§4.1): `authorization`, `dpop`, and the MCP transport headers.
///
/// Presence is the condition rather than a configured protocol version, because that
/// is the question the verifier can answer from the message in front of it: if the
/// sender put the header on the wire, the signature covers it or the request is
/// rejected. A deployment whose version does not define these simply never sends them
/// and nothing here fires.
///
/// Shared by the bodied and BODYLESS request paths. The bodyless path (§8.1) had none
/// of these checks, which meant a bodyless request could carry an
/// `Authorization: Bearer <token>` — or an `Mcp-Method` contradicting nothing because
/// there is no body to contradict — entirely outside its signature. An intermediary
/// could then add or swap the presented credential without invalidating anything,
/// which is precisely what covering it prevents on the bodied path. Two copies of a
/// rule this shape is how one of them ends up missing, so there is one copy.
pub(crate) fn require_conditional_coverage(
    headers: &[(String, String)],
    covered: &[CoveredComponent],
) -> Result<(), HttpProfileError> {
    for header in conditionally_covered_request_headers() {
        // `single_header` also fails closed on a duplicated header, so a smuggled
        // second `authorization` cannot slip past by being the uncovered one.
        if single_header(headers, header)?.is_some()
            && !covered.iter().any(|c| !c.req && c.name == header)
        {
            return Err(HttpProfileError::MissingCoveredComponent(header));
        }
    }
    Ok(())
}

/// Every request header that is mandatory-if-present, in one place so the signer and
/// the verifier cannot disagree about the set: `authorization`/`dpop` bind the presented
/// credential surface, and [`MCP_COVERABLE_TRANSPORT_HEADERS`] binds the routing claims
/// made in the clear (whose rationale lives on that constant).
pub(crate) fn conditionally_covered_request_headers() -> impl Iterator<Item = &'static str> {
    ["authorization", "dpop"]
        .into_iter()
        .chain(MCP_COVERABLE_TRANSPORT_HEADERS)
}

pub(crate) fn require_components_for(
    covered: &[CoveredComponent],
    required_plain: &[&'static str],
    required_req: &[&'static str],
) -> Result<(), HttpProfileError> {
    require_components(covered, required_plain, required_req)
}

/// [`check_params`] shared with the bodyless sets: tag, allowlisted algorithm,
/// bounded-skew freshness, keyid.
pub(crate) fn check_params_for(
    params: &SignatureParams,
    policy: &VerifierPolicy,
    now: i64,
    require_nonce: bool,
) -> Result<(i64, i64, String, String, ProfileAlgorithm), HttpProfileError> {
    check_params(params, policy, now, require_nonce)
}

/// The `Signature` byte sequence for `label`, base64url-transcoded.
pub(crate) fn signature_value_for(
    headers: &[(String, String)],
    label: &str,
) -> Result<String, HttpProfileError> {
    signature_value_b64url(headers, "signature", label)
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

/// [`verify_request`] under an explicit verifier-local [`VerifierPolicy`] —
/// the algorithm allowlist (§13.1) and the bounded clock-skew tolerance (§5.1).
/// [`verify_request`] is this function at [`VerifierPolicy::default`].
pub(crate) fn floor_request<R: Into<ResolverOutcome>>(
    request: &HttpRequest,
    resolve_actor: &dyn Fn(&str, SignerSlot) -> R,
    policy: &VerifierPolicy,
    now: i64,
) -> Result<CryptographicFloorVerifiedRequest, HttpProfileError> {
    reject_content_encoding(&request.headers)?;
    // JSON mode (§3.4): a covered exchange carries JSON. Checked before the
    // content binding — there is no point digesting a body the profile could not
    // make an evidence statement about anyway.
    require_json_media_type(&request.headers, "request content-type")?;

    // 1. Content binding first: the body must match its digest before any
    //    signature statement about that digest is even considered. This keeps the
    //    trust store off the path of digest-mismatched traffic — a keyid is never
    //    looked up for a message whose body does not match what it claims.
    //
    //    The ordering is not forced by the profile: the signature base needs only
    //    the Content-Digest HEADER value, never the body. So a peer that clears mTLS
    //    but holds no valid signing key does drive a full SHA-256 pass over a
    //    max-size body before the ~50 µs signature check refuses it.
    //
    //    That asymmetry is bounded work, not unbounded work, and the bound is not
    //    here. Every path into this function passes a read-time ceiling that fails
    //    closed BEFORE the body is allocated — `ServerLimits::max_body_bytes` on the
    //    serving path, `ClientLimits::max_response_bytes` on the client — with the
    //    per-core in-flight permit bounding concurrency on top. A ceiling re-checked
    //    at this point would fire only after the allocation the read-time one
    //    already refuses, so it would narrow nothing and give a deployment two
    //    ceilings to keep in agreement.
    //
    //    The remaining cost is a few milliseconds of SHA-256 over a max-size body,
    //    against a sender that had to put that body on the wire to buy it — link
    //    time alone exceeds the hash by more than an order of magnitude. The ratio
    //    runs against the sender, so this is not an amplification path.
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
    require_conditional_coverage(&request.headers, &parsed.components)?;
    let (created, expires, nonce, key_id, algorithm) =
        check_params(&parsed.params, policy, now, true)?;

    // 3. Trust resolution for the REQUEST slot: a keyid never introduces trust,
    //    and a key not trusted to sign requests fails actor_binding_failed.
    let resolved_actor = resolve_actor_for_slot(resolve_actor, &key_id, SignerSlot::Request)?;
    // 4. Signature over the reconstructed base.
    let base = signature_base(
        &parsed.components,
        &parsed.params,
        &SourceMessage::Request(request),
    )?;
    let sig = signature_value_b64url(&request.headers, "signature", REQUEST_LABEL)?;
    verify_under(
        algorithm,
        &base,
        &sig,
        &resolved_actor.verification_key,
        McpReError::InvalidSignature,
    )?;

    // 5. MCP transport contract (§4.1). Deliberately AFTER the signature: before
    //    it, both sides of every comparison are unauthenticated, and two attacker-
    //    chosen strings agreeing proves nothing. Once the signature verifies, a
    //    present `mcp-*` header is covered (the closed-allowlist gate enforced
    //    present ⇒ covered) and the body is covered via `content-digest`.
    //
    //    The `mcp-method`/body agreement is ALWAYS checked — a covered header must
    //    never lie about the signed body, regardless of policy. Required-header
    //    presence, the supported-version set, and `mcp-name` agreement are the
    //    configurable part, enforced only when the deployment attached a transport
    //    policy.
    reject_mcp_method_divergence(request)?;
    if let Some(transport) = policy.mcp_transport() {
        transport.enforce(request)?;
    }

    // 6. Derive the handle from the exact verified base and return the full
    //    verified evidence context.
    Ok(CryptographicFloorVerifiedRequest {
        profile_id: PROFILE_TAG.to_owned(),
        signature_label: REQUEST_LABEL.to_owned(),
        resolved_actor,
        evidence: RequestEvidence::from_signature_base(&base),
        request_signature_base: base,
        content_digest,
        created,
        expires,
        nonce,
        key_id,
    })
}

/// [`verify_request_full`] under an explicit verifier-local [`VerifierPolicy`].
pub(crate) fn full_request<R: Into<ResolverOutcome>>(
    request: &HttpRequest,
    expected_audience: &AudienceTuple,
    artifact_material: &dyn Fn(&ArtifactBinding) -> Option<Vec<u8>>,
    resolve_actor: &dyn Fn(&str, SignerSlot) -> R,
    policy: &VerifierPolicy,
    now: i64,
) -> Result<VerifiedMcpRequest, HttpProfileError> {
    // 1. Cryptographic floor: content digest, evidence, trust, signature.
    let floor = floor_request(request, resolve_actor, policy, now)?;

    // 2. Parse the request evidence block — protected because content-digest is a
    //    covered component of the signature just verified.
    let block: HttpRequestEvidenceBlock = extract_meta_block(
        &request.body,
        REQUEST_EVIDENCE_BLOCK_KEY,
        "request evidence block",
    )?;
    block.validate(floor.profile_id())?;

    // 3-4. Audience binding and strict artifact enforcement.
    enforce_full_profile_bindings(request, &block, expected_audience, artifact_material)?;

    // 5. The full product is CONSTRUCTED from the floor one, not the floor one relabelled.
    //    There is no path that produces a `VerifiedMcpRequest` without reaching here.
    Ok(VerifiedMcpRequest {
        audience_hash: block.audience.audience_hash(),
        audience: block.audience.clone(),
        request_block: block,
        floor,
    })
}

/// The two full-profile checks that need inputs the request cannot supply for itself:
/// audience-tuple equality and `artifact_bindings[]`.
///
/// Shared with chain reconstruction rather than restated there. Reconstruction's verdict
/// is embedded in a SCITT Signed Statement, so "served" and "accounted for" have to be
/// the same verdict — two copies of this rule would let a record be labelled `Complete`
/// under checks the enforcement boundary had tightened.
///
/// The audience test is equality against the VERIFIER's own tuple plus consistency
/// between that tuple's `target_uri` and the request's `@target-uri`, which guards routed
/// and reverse-proxied deployments where a label could alias two dispatch boundaries.
/// Artifact enforcement is strict: a binding whose credential surface is unavailable
/// fails `artifact_binding_failed` rather than being skipped.
pub(crate) fn enforce_full_profile_bindings(
    request: &HttpRequest,
    block: &HttpRequestEvidenceBlock,
    expected_audience: &AudienceTuple,
    artifact_material: &dyn Fn(&ArtifactBinding) -> Option<Vec<u8>>,
) -> Result<(), HttpProfileError> {
    if block.audience != *expected_audience || expected_audience.target_uri != request.target_uri {
        return Err(HttpProfileError::AudienceMismatch);
    }
    for binding in &block.artifact_bindings {
        let credential = resolve_artifact_credential(binding, &request.headers, artifact_material)
            .ok_or(HttpProfileError::ArtifactBindingFailed)?;
        verify_artifact_binding(binding, &credential)?;
    }
    Ok(())
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

/// [`verify_response`] under an explicit verifier-local [`VerifierPolicy`].
pub(crate) fn floor_bound_response<R: Into<ResolverOutcome>>(
    response: &HttpResponse,
    request: &HttpRequest,
    resolve_actor: &dyn Fn(&str, SignerSlot) -> R,
    policy: &VerifierPolicy,
    now: i64,
) -> Result<CryptographicFloorVerifiedBoundResponse, HttpProfileError> {
    reject_content_encoding(&response.headers)?;
    // JSON mode (§3.4): an SSE response to a covered request is a profile
    // violation, not a streaming opt-in.
    require_json_media_type(&response.headers, "response content-type")?;

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
    let (_created, _expires, _nonce, key_id, algorithm) =
        check_params(&parsed.params, policy, now, false)?;

    // Trust resolution for the RESPONSE slot: a request-signer key presented on
    // a response fails actor_binding_failed.
    let resolved_server_actor =
        resolve_actor_for_slot(resolve_actor, &key_id, SignerSlot::Response)?;
    let base = signature_base(
        &parsed.components,
        &parsed.params,
        &SourceMessage::Response { response, request },
    )?;
    let sig = signature_value_b64url(&response.headers, "response signature", RESPONSE_LABEL)?;
    verify_under(
        algorithm,
        &base,
        &sig,
        &resolved_server_actor.verification_key,
        McpReError::ResponseSigInvalid,
    )?;
    Ok(CryptographicFloorVerifiedBoundResponse {
        resolved_server_actor,
        response_signature_base_digest: RequestEvidence::from_response_signature_base(&base),
    })
}

/// [`verify_response_bound_full`] under an explicit verifier-local [`VerifierPolicy`].
pub(crate) fn full_bound_response<R: Into<ResolverOutcome>>(
    response: &HttpResponse,
    request: &HttpRequest,
    bound_request_evidence: &RequestEvidence,
    resolve_actor: &dyn Fn(&str, SignerSlot) -> R,
    policy: &VerifierPolicy,
    now: i64,
) -> Result<VerifiedMcpResponse, HttpProfileError> {
    // 1. Cryptographic floor incl. the ;req binding to `request`.
    let floor = floor_bound_response(response, request, resolve_actor, policy, now)?;

    // 2. Parse the response evidence block (protected by content-digest).
    let block: HttpResponseEvidenceBlock = extract_meta_block(
        &response.body,
        RESPONSE_EVIDENCE_BLOCK_KEY,
        "response evidence block",
    )?;
    block.validate(PROFILE_TAG)?;

    // 3. server_signer must be the identity that actually signed.
    if block.server_signer.keyid != floor.resolved_server_actor.identity.keyid {
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

    Ok(VerifiedMcpResponse::from_block(
        floor,
        bound_request_evidence.clone(),
        &block,
    ))
}

/// Deployment policy for verifying a delegated-key-signed response
/// (ADR-MCPRE-052 §3). Supplied by the integration layer from the active profile,
/// the verified request context, and the deployment's epoch/audience policy.
/// The response-signature policy is NOT here. It is the verifier's, held once by
/// [`crate::verifier::Verifier`]; this record carries only what is specific to the
/// CREDENTIAL — its own window, its audience scope, and the accepted epoch set.
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

/// Verify the inline delegation credential a response block carries (ADR-MCPRE-052 §3
/// steps 2–7), resolving its ROOT issuer through the SAME trust seam every other path uses.
///
/// One function rather than a copy per delegated operation: the bound and unbound paths
/// differ in what the signature covers, not in how a credential chains to a root, and two
/// copies of a trust-resolution rule are two places for it to drift.
///
/// `verify_delegation_credential`'s resolver returns `Option`, which cannot express the
/// difference between "not trusted" and "the store could not answer" — so resolving inline
/// collapsed a trust-store OUTAGE into `mcp-re.delegation_issuer_untrusted`, sending an
/// operator to look at the caller's credentials instead of at their own store (the exact
/// confusion the C079 fix removed everywhere else), and it dropped the `actor.slot != slot`
/// assertion, so a resolver handing back a Request-slot actor would have had its key
/// accepted as a delegation root. The failure is captured here and re-reported as itself.
fn chain_to_root<R: Into<ResolverOutcome>>(
    credential: &str,
    block: &HttpResponseEvidenceBlock,
    resolve_actor: &dyn Fn(&str, SignerSlot) -> R,
    expect: &DelegationExpectations<'_>,
    is_revoked: &dyn Fn(&str) -> bool,
    now: i64,
) -> Result<VerifiedDelegation, HttpProfileError> {
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
    let resolve_failure: std::cell::RefCell<Option<HttpProfileError>> =
        std::cell::RefCell::new(None);
    let verified = verify_delegation_credential(
        credential,
        &params,
        |issuer_kid| match resolve_actor_for_slot(resolve_actor, issuer_kid, SignerSlot::Response) {
            Ok(actor) => Some(actor.verification_key),
            // A definitive "not trusted" stays the credential layer's own verdict
            // (`mcp-re.delegation_issuer_untrusted`) — that IS the right token for an
            // issuer nobody vouches for. Only an OUTAGE and a wrong-slot actor are
            // propagated, because those are not statements about the credential.
            Err(HttpProfileError::UnresolvedKeyId) => None,
            Err(e) => {
                *resolve_failure.borrow_mut() = Some(e);
                None
            }
        },
        |kid| is_revoked(kid),
    );
    verified.map_err(|e| resolve_failure.into_inner().unwrap_or(e))
}

/// Delegated-response verification bound to a request evidence HANDLE
/// ([`RequestEvidence`]) rather than the whole [`VerifiedMcpRequest`] — the
/// CLIENT-side entry point (the delegated analogue of [`verify_response_bound_full`]).
///
/// Semantics are identical to [`verify_delegated_response_full`]: delegation is
/// REQUIRED (a response with no inline credential — including a directly root-signed
/// one — is rejected `delegation_credential_missing`), the credential chain to the
/// root is verified, and the `;req`-bound response signature is verified under
/// `cnf.jwk`. The only difference is that the request-evidence binding is compared
/// against the passed `bound_request_evidence` handle the client kept from signing.
#[allow(clippy::too_many_arguments)]
pub(crate) fn delegated_bound_response<R: Into<ResolverOutcome>>(
    response: &HttpResponse,
    request: &HttpRequest,
    bound_request_evidence: &RequestEvidence,
    resolve_actor: &dyn Fn(&str, SignerSlot) -> R,
    policy: &VerifierPolicy,
    expect: &DelegationExpectations<'_>,
    is_revoked: &dyn Fn(&str) -> bool,
    now: i64,
) -> Result<VerifiedDelegatedMcpResponse, HttpProfileError> {
    // Content-digest floor (same as verify_response).
    reject_content_encoding(&response.headers)?;
    // JSON mode (§3.4): the delegated path gets the same gate — a credential
    // chain to the root does not make a stream evidenceable.
    require_json_media_type(&response.headers, "response content-type")?;
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
    let (_created, _expires, _nonce, key_id, algorithm) =
        check_params(&parsed.params, policy, now, false)?;

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

    // Steps 2–7: the credential chain to the root, scoped to the block's declared server
    // signer — a lifted credential fails the scope check (§3 step 5).
    let verified = chain_to_root(credential, &block, resolve_actor, expect, is_revoked, now)?;

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
    verify_under(
        algorithm,
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

    // The accepted signer is authorized by the CREDENTIAL, not by the trust map: its key
    // is the delegated key, which no trust store vouches for, and its identity is the
    // block's `server_signer`. That is why this path assembles the SHARED facts rather
    // than a `CryptographicFloorVerifiedBoundResponse`, whose meaning is "the presented
    // keyid was resolved through the trust seam" — false of every value here.
    Ok(VerifiedDelegatedMcpResponse {
        signature_facts: BoundResponseSignatureFacts {
            accepted_signer: AcceptedResponseSigner {
                identity: block.server_signer.clone(),
                verification_key: verified.delegated_key,
            },
            response_signature_base_digest: RequestEvidence::from_response_signature_base(&base),
        },
        request_evidence_agreement: block_agreement(bound.clone(), &block),
        // C004b: the ROOT anchor the credential chained to — the stable coordinate,
        // unlike the ephemeral delegated kid. Not an `Option`: this product is only
        // reachable through a verified chain.
        delegation_issuer_kid: verified.issuer_kid.clone(),
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
pub(crate) fn delegated_unbound_response<R: Into<ResolverOutcome>>(
    response: &HttpResponse,
    resolve_actor: &dyn Fn(&str, SignerSlot) -> R,
    policy: &VerifierPolicy,
    expect: &DelegationExpectations<'_>,
    is_revoked: &dyn Fn(&str) -> bool,
    now: i64,
) -> Result<VerifiedDelegatedUnboundResponse, HttpProfileError> {
    // Content-digest floor.
    reject_content_encoding(&response.headers)?;
    // JSON mode (§3.4): the delegated path gets the same gate — a credential
    // chain to the root does not make a stream evidenceable.
    require_json_media_type(&response.headers, "response content-type")?;
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
    let (_created, _expires, _nonce, key_id, algorithm) =
        check_params(&parsed.params, policy, now, false)?;

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

    // Steps 2–7: the credential chain to the root, scoped to the block's declared server
    // signer — a lifted credential fails the scope check (§3 step 5).
    let verified = chain_to_root(credential, &block, resolve_actor, expect, is_revoked, now)?;

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
    verify_under(
        algorithm,
        &base,
        &sig,
        &verified.delegated_key,
        McpReError::ResponseSigInvalid,
    )
    .map_err(|_| HttpProfileError::DelegationKeyMismatch)?;

    // Credential-authorized, exactly as on the bound path: the shared unbound facts, not
    // a seam-resolved `CryptographicFloorVerifiedUnboundResponse`.
    Ok(VerifiedDelegatedUnboundResponse {
        signature_facts: UnboundResponseSignatureFacts {
            accepted_signer: AcceptedResponseSigner {
                identity: block.server_signer.clone(),
                verification_key: verified.delegated_key,
            },
            response_signature_base_digest: RequestEvidence::from_response_signature_base(&base),
        },
        delegation_issuer_kid: verified.issuer_kid.clone(),
    })
}

/// [`verify_response_unbound`] under an explicit verifier-local [`VerifierPolicy`].
pub(crate) fn floor_unbound_response<R: Into<ResolverOutcome>>(
    response: &HttpResponse,
    resolve_actor: &dyn Fn(&str, SignerSlot) -> R,
    policy: &VerifierPolicy,
    now: i64,
) -> Result<CryptographicFloorVerifiedUnboundResponse, HttpProfileError> {
    reject_content_encoding(&response.headers)?;
    // JSON mode (§3.4): an SSE response to a covered request is a profile
    // violation, not a streaming opt-in.
    require_json_media_type(&response.headers, "response content-type")?;

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
    let (_created, _expires, _nonce, key_id, algorithm) =
        check_params(&parsed.params, policy, now, false)?;

    let resolved_server_actor =
        resolve_actor_for_slot(resolve_actor, &key_id, SignerSlot::Response)?;
    let base = signature_base(
        &parsed.components,
        &parsed.params,
        &SourceMessage::ResponseOnly(response),
    )?;
    let sig = signature_value_b64url(&response.headers, "response signature", RESPONSE_LABEL)?;
    verify_under(
        algorithm,
        &base,
        &sig,
        &resolved_server_actor.verification_key,
        McpReError::ResponseSigInvalid,
    )?;
    Ok(CryptographicFloorVerifiedUnboundResponse {
        resolved_server_actor,
        response_signature_base_digest: RequestEvidence::from_response_signature_base(&base),
    })
}

#[cfg(test)]
mod wire_form_tests {
    use super::*;

    const CANONICAL: &str = r#"("@method" "@target-uri" "content-digest");created=1700000000;expires=1700000300;nonce="n";keyid="k";alg="ed25519""#;

    /// The verifier rebuilds `@signature-params` from PARSED values and re-serialises
    /// canonically, so any wire spelling it silently normalises away verifies under the
    /// same signature as the canonical one. That breaks the one-to-one correspondence
    /// between the received bytes and the signed bytes the profile claims — an
    /// intermediary could rewrite the raw header and nothing would notice.
    #[test]
    fn alternate_signature_input_spellings_are_refused_not_normalised() {
        parse_signature_input(CANONICAL).expect("the canonical form parses");

        let alternates = [
            // Inner-list whitespace.
            r#"("@method"  "@target-uri" "content-digest");created=1700000000;expires=1700000300;nonce="n";keyid="k";alg="ed25519""#,
            "(\"@method\"\t\"@target-uri\" \"content-digest\");created=1700000000;expires=1700000300;nonce=\"n\";keyid=\"k\";alg=\"ed25519\"",
            r#"( "@method" "@target-uri" "content-digest");created=1700000000;expires=1700000300;nonce="n";keyid="k";alg="ed25519""#,
            r#"("@method" "@target-uri" "content-digest" );created=1700000000;expires=1700000300;nonce="n";keyid="k";alg="ed25519""#,
            // Parameter spacing and empty slots.
            r#"("@method" "@target-uri" "content-digest") ;created=1700000000;expires=1700000300;nonce="n";keyid="k";alg="ed25519""#,
            r#"("@method" "@target-uri" "content-digest");created=1700000000;expires=1700000300;nonce="n";keyid="k";alg="ed25519";"#,
            r#"("@method" "@target-uri" "content-digest");created=1700000000;;expires=1700000300;nonce="n";keyid="k";alg="ed25519""#,
            r#"("@method" "@target-uri" "content-digest");created=1700000000; expires=1700000300;nonce="n";keyid="k";alg="ed25519""#,
        ];
        for alternate in alternates {
            assert!(
                parse_signature_input(alternate).is_err(),
                "must be refused rather than normalised: {alternate}"
            );
        }
    }

    /// A space inside a quoted parameter value is a legitimate byte of that value, not
    /// a spelling variant — refusing it would break keyids and nonces the profile
    /// admits.
    #[test]
    fn a_space_inside_a_quoted_parameter_value_is_kept() {
        let with_space = r#"("@method");created=1700000000;expires=1700000300;nonce="n";keyid="key one";alg="ed25519""#;
        let parsed = parse_signature_input(with_space).expect("a quoted space is data");
        assert_eq!(parsed.params.keyid.as_deref(), Some("key one"));
    }

    /// The spelling rules hold at the DICTIONARY MEMBER boundary too, not only inside
    /// the member value. `member_value` is the sole reader of both `Signature-Input`
    /// and `Signature`, so OWS normalised away here would let an intermediary rewrite
    /// either raw header and still verify under the same signature.
    #[test]
    fn dictionary_member_spacing_is_refused_not_normalised() {
        let canonical = format!("mcp-re={CANONICAL}");
        assert_eq!(
            member_value(&canonical, "mcp-re").expect("the canonical member reads"),
            CANONICAL
        );

        for alternate in [
            format!("mcp-re= {CANONICAL}"),
            format!("mcp-re=\t{CANONICAL}"),
            format!("other=(\"@method\"), mcp-re=  {CANONICAL}"),
        ] {
            assert_eq!(
                member_value(&alternate, "mcp-re").unwrap_err(),
                HttpProfileError::MalformedEvidence("dictionary member spacing"),
                "must be refused rather than normalised: {alternate}"
            );
        }

        // The same reader serves the `Signature` header's byte sequence.
        assert_eq!(
            member_value("mcp-re=  :YWJj:", "mcp-re").unwrap_err(),
            HttpProfileError::MalformedEvidence("dictionary member spacing")
        );
        assert_eq!(
            member_value("mcp-re=:YWJj:", "mcp-re").expect("canonical"),
            ":YWJj:"
        );

        // OWS around the member-separating comma stays legal (RFC 8941 §4.2).
        assert_eq!(
            member_value("other=(\"@method\") , mcp-re=:YWJj:", "mcp-re").expect("comma OWS"),
            ":YWJj:"
        );
    }

    /// A comma that delimits nothing is not a spelling variant of the dictionary — RFC
    /// 8941 has no empty `dict-member`. Ignored as "a member I could not parse", it let
    /// an intermediary add or strip commas in the raw `Signature-Input`/`Signature`
    /// header while the signature still verified.
    #[test]
    fn an_empty_dictionary_member_is_refused_not_ignored() {
        for spelling in [
            ",mcp-re=:YWJj:",
            "mcp-re=:YWJj:,",
            "mcp-re=:YWJj:,,other=1",
            " , mcp-re=:YWJj:",
            ",",
            "",
        ] {
            assert_eq!(
                member_value(spelling, "mcp-re").unwrap_err(),
                HttpProfileError::MalformedEvidence("empty dictionary member"),
                "{spelling:?} was read as the canonical dictionary",
            );
        }
        // The canonical spelling, and a legitimate neighbouring member, are unaffected.
        assert_eq!(
            member_value("mcp-re=:YWJj:", "mcp-re").expect("canonical"),
            ":YWJj:"
        );
        assert_eq!(
            member_value("other=1, mcp-re=:YWJj:", "mcp-re").expect("a neighbour is legal"),
            ":YWJj:"
        );
    }

    /// RFC 8941 §3.3.1's sf-integer has no `-0`. It slipped past the leading-zero rule
    /// (the digits are just "0") and re-serialised as "0", so two spellings collapsed
    /// to one signature base.
    #[test]
    fn negative_zero_is_not_an_sf_integer() {
        assert_eq!(parse_i64("0").expect("zero parses"), 0);
        assert!(parse_i64("-0").is_err(), "-0 is not an sf-integer");
        assert!(parse_i64("-00").is_err());
        assert_eq!(parse_i64("-17").expect("negatives parse"), -17);
    }
}
