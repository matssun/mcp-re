// SPDX-License-Identifier: Apache-2.0
//! The request-evidence handle OF a request — #416 rev 2 §7.1, THM-0018 and THM-0019.
//!
//! # Why the handle is not an operand
//!
//! Full bound-response verification used to receive two request-shaped inputs that nothing
//! related: a concrete [`HttpRequest`], against which the response's `;req` components are
//! resolved, and separately a [`RequestEvidence`] handle, against which the response
//! block's `request_evidence` is compared. A caller could supply request A and handle B.
//! Verification then established cryptographic binding to A and semantic equality with B,
//! and NOT that A and B denote the same exchange — so a response could be verified as the
//! answer to a request it was not the answer to, and the theorem could only report that
//! relating them was the caller's job.
//!
//! Both callers did relate them. A server passed the handle of the request it had just
//! verified; a client passed the handle it retained from signing the request it had just
//! sent. That is a convention held at two call sites, and adding a third would not have
//! turned anything red.
//!
//! The handle is a FUNCTION of the request: SHA-256 over the request's RFC 9421
//! signature-base bytes, domain-separated by role. So the boundary derives it rather than
//! accepting it, and the second operand is gone. `request A + handle B` is not refused —
//! it is unconstructible, because there is nowhere to put B.
//!
//! # What this is not
//!
//! This is a DERIVATION, not a verification. It reconstructs the signature base the
//! request's own `Signature-Input` describes and digests it; it checks no signature,
//! resolves no trust, and enforces no required-component set. Those are
//! [`crate::verify::floor_request`]'s authority and are not repeated here, because the
//! handle of a request is a fact about its bytes rather than a fact about its
//! trustworthiness. A response bound to a request whose signature does not verify is
//! refused by the floor, not by this.
//!
//! Both producers of a handle compute it exactly this way — the request floor at
//! `verify/floor/request.rs` and the signer at `crate::sign` — so a derivation here agrees
//! with a retained handle whenever the request is the one that was signed, and differs
//! whenever it is not. That difference is the whole point.

use crate::error::HttpProfileError;
use crate::evidence::RequestEvidence;
use crate::ids::REQUEST_LABEL;
use crate::message::required_header;
use crate::message::HttpRequest;
use crate::sigbase::signature_base;
use crate::sigbase::SourceMessage;
use crate::verify::floor::sf_dictionary::member_value;
use crate::verify::floor::signature_input::parse_signature_input;

/// The REQUEST-role evidence handle of `request`.
///
/// Fails closed when the request carries no `Signature-Input`, no `mcp-re` member in it, a
/// member that does not parse, or a covered-component set the base cannot be built over —
/// in every case because there is no signature base, and therefore no handle, rather than
/// because a check failed.
pub(crate) fn request_evidence_of(
    request: &HttpRequest,
) -> Result<RequestEvidence, HttpProfileError> {
    let input_header = required_header(&request.headers, "signature-input")
        .map_err(|_| HttpProfileError::MissingEvidence("request signature-input"))?;
    let parsed = parse_signature_input(member_value(input_header, REQUEST_LABEL)?)?;
    let base = signature_base(
        &parsed.components,
        &parsed.params,
        &SourceMessage::Request(request),
    )?;
    Ok(RequestEvidence::from_signature_base(&base))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_with_no_signature_input_has_no_handle() {
        let request = HttpRequest {
            method: "POST".to_owned(),
            target_uri: "https://mcp.example.com/mcp".to_owned(),
            headers: Vec::new(),
            body: b"{}".to_vec(),
        };
        assert!(request_evidence_of(&request).is_err());
    }
}
