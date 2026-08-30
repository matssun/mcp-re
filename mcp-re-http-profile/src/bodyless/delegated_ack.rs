// SPDX-License-Identifier: Apache-2.0
//! Verifying a DELEGATED bodyless `202 Accepted` (§3.4/#424, owner ruling 2026-07-17).
//!
//! One claim, and it is narrow: **a delegated key trusted for THIS service accepted this
//! notification.** Nothing about what happened next. A client that reads a 202 as
//! *cancelled* has been misled (#418).
//!
//! Delegation is REQUIRED and self-contained. The `mcp-re-delegation` header carries a
//! compact-JWS credential that chains to a trusted root, and the 202 is signed by the
//! delegated key that credential attests — so the four questions below are asked in an
//! order where each one's inputs are already established:
//!
//! 1. is this the shape of message the profile signs bodyless (envelope);
//! 2. is the credential present exactly once, bounded, and COVERED by the signature;
//! 3. does the credential chain to a root this deployment trusts;
//! 4. does the credential's scope name the key the response actually signed under.
//!
//! Step 4 is the one that would be easy to lose. There is no body-declared `server_signer`
//! to cross-check — there is no body — so the credential's own root-signed
//! `mcp_re_server_signer` is the only value available, and feeding it back in as
//! `expected_server_signer` makes the §3 step-5 scope comparison `x != x`, a check that
//! cannot fail. The SUBSTANTIVE cross-check is against a field the credential does not get
//! to choose freely: the delegated kid the response actually signed under.

use mcp_re_core::McpReError;

use crate::block::ResolverOutcome;
use crate::digest::verify_content_digest_sha256;
use crate::error::HttpProfileError;
use crate::ids::REQUIRED_RESPONSE_REQ_COMPONENTS;
use crate::ids::RESPONSE_LABEL;
use crate::ids::STATUS_ACCEPTED;
use crate::message::reject_content_encoding;
use crate::message::required_header;
use crate::message::HttpRequest;
use crate::message::HttpResponse;
use crate::policy::ProfileAlgorithm;
use crate::policy::VerifierPolicy;
use crate::sigbase::signature_base;
use crate::sigbase::SourceMessage;
use crate::verify::floor::components::require_components;
use crate::verify::floor::params::check_params;
use crate::verify::floor::signature::signature_value_b64url;
use crate::verify::floor::signature::verify_under;
use crate::verify::floor::signature_input::parse_signature_input_for;
use crate::verify::floor::signature_input::ParsedSignatureInput;

use super::delegated_credential::check_scope_names_the_signing_key;
use super::delegated_credential::read_credential;
use super::delegated_credential::verify_credential;

use super::check_request_evidence;
use super::require_bodyless;
use super::AcknowledgedDelegation;

/// The message is the shape a bodyless acknowledgement has, and it acknowledges THIS
/// request.
///
/// The named set is enforced exactly rather than relaxed: a verifier never *notices* a body
/// is absent and drops a requirement, because then "no content-type because there is no
/// content" and "content-type stripped in flight" would be the same observation. The digest
/// of nothing is not ceremony either — it makes *this message has no body* a signed
/// statement rather than an absence.
///
/// C019b: the same instance-level transmission binding as the non-delegated
/// acknowledgement, so an acknowledgement for transmission A does not verify as the
/// acknowledgement for a byte-identical retransmission A′.
fn check_envelope(response: &HttpResponse, request: &HttpRequest) -> Result<(), HttpProfileError> {
    reject_content_encoding(&response.headers)?;
    require_bodyless(&response.headers, &response.body)?;
    if response.status != STATUS_ACCEPTED {
        return Err(HttpProfileError::MalformedEvidence(
            "bodyless acknowledgement status",
        ));
    }
    let digest_header = required_header(&response.headers, "content-digest")
        .map_err(|_| HttpProfileError::MissingEvidence("response content-digest"))?;
    verify_content_digest_sha256(digest_header, &response.body)?;
    check_request_evidence(&response.headers, request)
}

/// The DELEGATED bodyless component set, enforced exactly.
///
/// The credential header MUST be covered: an uncovered credential is one an intermediary
/// could swap, which is the whole reason it is in the set. `content-type` must NOT be —
/// covering it on a bodyless message asserts content the named set says is absent.
fn check_coverage(
    headers: &[(String, String)],
    policy: &VerifierPolicy,
    now: i64,
) -> Result<(ParsedSignatureInput, String, ProfileAlgorithm), HttpProfileError> {
    let parsed = parse_signature_input_for(headers, RESPONSE_LABEL, "response signature-input")?;
    require_components(
        &parsed.components,
        &crate::ids::BODYLESS_DELEGATED_RESPONSE_COMPONENTS,
        &REQUIRED_RESPONSE_REQ_COMPONENTS,
    )?;
    if parsed
        .components
        .iter()
        .any(|c| !c.req && c.name == "content-type")
    {
        return Err(HttpProfileError::MalformedEvidence(
            "content-type covered on a bodyless message",
        ));
    }
    let (_c, _e, _n, key_id, algorithm) = check_params(&parsed.params, policy, now, false)?;
    Ok((parsed, key_id, algorithm))
}

/// Verify a DELEGATED bodyless `202 Accepted`.
///
/// Fail-closed on: the header absent, DUPLICATED, or over
/// [`crate::ids::MAX_DELEGATION_HEADER_LEN`]; the header NOT covered by the response
/// signature; any credential-chain failure (issuer→root, audience-scope, profile, key-use,
/// trust-epoch, expiry, revocation); the response `keyid` ≠ the credential's
/// `delegated_kid`; and the response signature not verifying under the delegated `cnf.jwk`.
///
/// On success the caller learns: a delegated key trusted for THIS service accepted this
/// notification. Nothing about what happened next.
pub fn verify_delegated_accepted_202<R: Into<ResolverOutcome>>(
    response: &HttpResponse,
    request: &HttpRequest,
    verifier: &crate::verifier::Verifier<'_, R>,
    expect: &crate::verify::DelegationExpectations<'_>,
    is_revoked: &dyn Fn(&str) -> bool,
    now: i64,
) -> Result<AcknowledgedDelegation, HttpProfileError> {
    check_envelope(response, request)?;
    let credential = read_credential(&response.headers)?;
    let (parsed, key_id, algorithm) = check_coverage(&response.headers, verifier.policy(), now)?;
    let (verified, server_signer) =
        verify_credential(&credential, verifier, expect, is_revoked, now)?;
    check_scope_names_the_signing_key(&key_id, &server_signer, &verified.delegated_kid)?;
    // The response signature verifies under `cnf.jwk` over the base that COVERS the
    // credential header.
    let base = signature_base(
        &parsed.components,
        &parsed.params,
        &SourceMessage::Response { response, request },
    )?;
    let sig = signature_value_b64url(&response.headers, "signature", RESPONSE_LABEL)?;
    verify_under(
        algorithm,
        &base,
        &sig,
        &verified.delegated_key,
        McpReError::ResponseSigInvalid,
    )
    .map_err(|_| HttpProfileError::DelegationKeyMismatch)?;
    Ok(AcknowledgedDelegation::established(verified))
}
