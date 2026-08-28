// SPDX-License-Identifier: Apache-2.0
//! Delegated verification of a response bound to a request (THM-0019).
//!
//! One authority: **this response is a delegated-signed answer to THIS request.** Binding
//! is what separates it from its unbound sibling, and it is established three ways that do
//! not substitute for one another: the signature covers the request's components through
//! `;req`, the block's `request_evidence` equals the handle the caller holds, and the
//! credential's scope names the block's declared server signer.
//!
//! The product carries the shared [`BoundResponseSignatureFacts`], never a
//! `CryptographicFloorVerifiedBoundResponse` — see [`super`] for why that containment would
//! state something false.

use mcp_re_core::McpReError;

use crate::block::HttpResponseEvidenceBlock;
use crate::block::ResolverOutcome;
use crate::block::SignerSlot;
use crate::body::extract_meta_block;
use crate::digest::verify_content_digest_sha256;
use crate::error::HttpProfileError;
use crate::evidence::RequestEvidence;
use crate::ids::PROFILE_TAG;
use crate::ids::REQUIRED_RESPONSE_COMPONENTS;
use crate::ids::RESPONSE_EVIDENCE_BLOCK_KEY;
use crate::ids::RESPONSE_LABEL;
use crate::message::reject_content_encoding;
use crate::message::require_json_media_type;
use crate::message::required_header;
use crate::message::HttpResponse;
use crate::policy::VerifierPolicy;
use crate::sigbase::signature_base;
use crate::sigbase::SourceMessage;
use crate::verified_response::AcceptedResponseSigner;
use crate::verify::floor::components::require_components;
use crate::verify::floor::params::check_params;
use crate::verify::floor::sf_dictionary::member_value;
use crate::verify::floor::signature::signature_value_b64url;
use crate::verify::floor::signature::verify_under;
use crate::verify::floor::signature_input::parse_signature_input;

use super::credential_chain::chain_to_root;
use super::DelegationExpectations;
use crate::ids::REQUIRED_RESPONSE_REQ_COMPONENTS;
use crate::message::HttpRequest;
use crate::verified_response::block_agreement;
use crate::verified_response::BoundResponseSignatureFacts;
use crate::verified_response::VerifiedDelegatedMcpResponse;

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
