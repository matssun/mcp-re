// SPDX-License-Identifier: Apache-2.0
//! The request's cryptographic floor (THM-0014).
//!
//! One authority: **this request's body matches its digest, its signature verifies over the
//! reconstructed base under a key the deployment trusts for the Request slot, and its
//! window is current.** Nothing here is about what the request MEANS — that is
//! [`crate::verify::full::request`].
//!
//! The ORDER is the argument, and it is the same one v0.11 grill C.1 fixed: content-digest,
//! then evidence parse, then keyid resolution through the trust seam, then the signature
//! over the reconstructed base, then handle derivation. Each numbered step below states why
//! it sits where it does; the §4.1 transport contract is deliberately last, after the
//! signature, because before it both sides of every comparison are attacker-chosen.

use mcp_re_core::McpReError;

use crate::block::ResolverOutcome;
use crate::block::SignerSlot;
use crate::digest::verify_content_digest_sha256;
use crate::error::HttpProfileError;
use crate::evidence::RequestEvidence;
use crate::ids::PROFILE_TAG;
use crate::ids::REQUEST_LABEL;
use crate::ids::REQUIRED_REQUEST_COMPONENTS;
use crate::message::reject_content_encoding;
use crate::message::require_json_media_type;
use crate::message::required_header;
use crate::message::HttpRequest;
use crate::policy::VerifierPolicy;
use crate::sigbase::signature_base;
use crate::sigbase::SourceMessage;
use crate::verified_request::CryptographicFloorVerifiedRequest;

use super::components::require_components;
use super::components::require_conditional_coverage;
use super::params::check_params;
use super::sf_dictionary::member_value;
use super::signature::signature_value_b64url;
use super::signature::verify_under;
use super::signature_input::parse_signature_input;
use super::transport_headers::reject_mcp_method_divergence;
use super::trust_slot::resolve_actor_for_slot;

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
