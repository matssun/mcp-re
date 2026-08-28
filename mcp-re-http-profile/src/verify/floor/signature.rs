// SPDX-License-Identifier: Apache-2.0
//! Signature verification under the RESOLVED algorithm.
//!
//! One authority: **the algorithm that was allowlisted is the algorithm that runs.** That
//! is a single fact and it is worth a module, because the alternative was the defect: every
//! path called the Ed25519 verifier unconditionally, so a policy allowlisting an
//! unimplemented algorithm accepted a message declaring it while Ed25519 was what actually
//! ran. `ProfileAlgorithm` now makes such a policy unconstructible AND this dispatch makes
//! the verifier-per-algorithm coupling a compile-time obligation.
//!
//! Getting the signature OFF THE WIRE lives here too. It is one step of one fact — the
//! bytes that are about to be checked — and separating "find the signature" from "check the
//! signature" would put a module boundary in the middle of a single act.

use mcp_re_core::verify_ed25519_with;
use mcp_re_core::McpReError;

use crate::error::HttpProfileError;
use crate::message::required_header;
use crate::policy::ProfileAlgorithm;
use crate::sign::base64_standard_decode;

use super::sf_dictionary::member_value;

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

/// The `Signature` header's byte sequence for `label`, transcoded to the
/// base64url form the core verifier consumes.
pub(crate) fn signature_value_b64url(
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
