// SPDX-License-Identifier: Apache-2.0
//! The request's cryptographic floor (THM-0014).
//!
//! One authority: **this request's body matches its digest, its signature verifies over the
//! reconstructed base under a key the deployment trusts for the Request slot, and its
//! window is current.** Nothing here is about what the request MEANS — that is
//! [`crate::verify::full::request`].
//!
//! Two wire preconditions run first, on unauthenticated headers. `Content-Encoding` must be
//! absent or identity: it is not a coverable component, so its absence is a reception-time
//! property the signature never binds and the product does not carry; checking it can only
//! force a refusal. `Content-Type` must be JSON: it is a required covered component, so its
//! value is later bound by the signature and a rewrite can only force a refusal.
//!
//! From the content-digest step on, the ORDER is the argument: content-digest, then
//! evidence parse, then keyid resolution through the trust seam, then the signature over
//! the reconstructed base, then the §4.1 transport contract, then handle derivation. Each
//! numbered step below states why it sits where it does; the §4.1 transport contract sits
//! after the signature because before it both sides of every comparison are
//! attacker-chosen. The ordering argument is load-bearing only from the content-digest
//! step on.

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
use super::signature::SignedMessage;
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
        SignedMessage::Request,
    )?;

    // 5. MCP transport contract (§4.1). Deliberately AFTER the signature: before
    //    it, both sides of every comparison are unauthenticated, and two attacker-
    //    chosen strings agreeing proves nothing. Once the signature verifies, a
    //    present `mcp-*` header is covered (the closed-allowlist gate enforced
    //    present ⇒ covered) and the body is covered via `content-digest`.
    //
    //    The whole contract is enforced on every request: a covered header never lies
    //    about the signed body, required headers are present, and the version is one
    //    the deployment accepts. The deployment chooses the accepted set, never whether
    //    there is a contract.
    reject_mcp_method_divergence(request)?;
    policy.mcp_transport().enforce(request)?;

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

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use mcp_re_core::SigningKey;

    use super::*;
    use crate::block::ActorIdentity;
    use crate::block::ResolvedActor;
    use crate::sign::sign_request;

    const CREATED: i64 = 1_700_000_000;
    const EXPIRES: i64 = 1_700_000_300;
    const NOW: i64 = 1_700_000_100;
    const KEY_ID: &str = "client-key-1";

    fn key() -> SigningKey {
        SigningKey::from_seed_bytes(&[11u8; 32])
    }

    fn signed(extra_headers: &[(&str, &str)]) -> HttpRequest {
        let mut headers = vec![("Content-Type".to_owned(), "application/json".to_owned())];
        headers.extend(
            extra_headers
                .iter()
                .map(|(n, v)| ((*n).to_owned(), (*v).to_owned())),
        );
        let mut r = HttpRequest {
            method: "POST".into(),
            target_uri: "https://mcp.example.com/mcp".into(),
            headers,
            body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#
                .to_vec(),
        };
        sign_request(&mut r, &key(), KEY_ID, CREATED, EXPIRES, "n-floor")
            .expect("signing succeeds");
        r
    }

    fn resolver<'a>(
        calls: &'a Cell<u32>,
        seen: &'a Cell<Option<SignerSlot>>,
    ) -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> + 'a {
        move |key_id: &str, slot: SignerSlot| {
            calls.set(calls.get() + 1);
            seen.set(Some(slot));
            (key_id == KEY_ID).then(|| ResolvedActor {
                identity: ActorIdentity {
                    role: "client".into(),
                    trust_domain: "example.com".into(),
                    subject: "did:example:client".into(),
                    keyid: key_id.into(),
                },
                verification_key: key().public_key(),
                slot,
            })
        }
    }

    #[test]
    fn a_valid_request_consults_the_trust_seam_once_in_the_request_slot() {
        let (calls, seen) = (Cell::new(0), Cell::new(None));
        let req = signed(&[]);
        let out = floor_request(
            &req,
            &resolver(&calls, &seen),
            &VerifierPolicy::default(),
            NOW,
        );
        assert!(out.is_ok());
        assert_eq!(calls.get(), 1);
        assert_eq!(seen.get(), Some(SignerSlot::Request));
    }

    #[test]
    fn a_body_that_misses_its_digest_never_reaches_the_trust_seam() {
        let (calls, seen) = (Cell::new(0), Cell::new(None));
        let mut req = signed(&[]);
        req.body[0] ^= 0x01;
        let err = floor_request(
            &req,
            &resolver(&calls, &seen),
            &VerifierPolicy::default(),
            NOW,
        )
        .map(|_| ())
        .unwrap_err();
        assert_eq!(err, HttpProfileError::ContentDigestMismatch);
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn a_covered_mcp_method_contradicting_the_body_is_refused() {
        let (calls, seen) = (Cell::new(0), Cell::new(None));
        let req = signed(&[("Mcp-Method", "tools/list")]);
        let policy = VerifierPolicy::default();
        let err = floor_request(&req, &resolver(&calls, &seen), &policy, NOW)
            .map(|_| ())
            .unwrap_err();
        assert_eq!(err, HttpProfileError::McpMethodDivergence);
    }
}
