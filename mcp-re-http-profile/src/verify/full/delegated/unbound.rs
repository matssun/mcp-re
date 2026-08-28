// SPDX-License-Identifier: Apache-2.0
//! Delegated verification of a response with NO request binding (THM-0020).
//!
//! One authority: **this response is a delegated-signed statement, and it claims no request
//! binding.** The preflight case: a request that never earned a trustworthy hash still gets
//! a refusal the client can verify.
//!
//! `;req` is REFUSED here rather than ignored. There is no request context to resolve it
//! against, and a covered component that cannot be resolved must not be silently dropped —
//! that would let a receipt claim a binding this path cannot check. The block's
//! `request_evidence` is likewise diagnostic and is NOT treated as a binding; whether a
//! receipt is about a given request is the CLIENT's separate question, and
//! `mcp-re-client-core` asks it.

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
use crate::verified_response::UnboundResponseSignatureFacts;
use crate::verified_response::VerifiedDelegatedUnboundResponse;

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
