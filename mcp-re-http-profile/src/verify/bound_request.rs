// SPDX-License-Identifier: Apache-2.0
//! The request-evidence handle OF a request — #416 rev 2 §7.1, THM-0018 and THM-0019.
//!
//! # Why the handle is not an operand
//!
//! Full bound-response verification used to receive two request-shaped inputs that nothing
//! related: a concrete [`HttpRequest`], against which the response's `;req` components are
//! resolved, and separately a [`RequestRoleEvidence`] handle, against which the response
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
//! Both producers of a handle digest the base the same way, but over a covered set of at
//! least `REQUIRED_REQUEST_COMPONENTS` and with no `;req`, while this derivation admits any
//! parseable covered set. A derived handle equals a producer's only when the two bases are
//! byte-identical; because the base's `@signature-params` line names the covered set, a
//! request declaring any other set (including an empty one) derives a handle no producer
//! emits, so the domain difference fails closed at the comparison.

use crate::error::HttpProfileError;
use crate::evidence::RequestRoleEvidence;
use crate::ids::REQUEST_LABEL;
use crate::message::single_header;
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
) -> Result<RequestRoleEvidence, HttpProfileError> {
    let input_header = single_header(&request.headers, "signature-input")?
        .ok_or(HttpProfileError::MissingEvidence("request signature-input"))?;
    let parsed = parse_signature_input(member_value(input_header, REQUEST_LABEL)?)?;
    let base = signature_base(
        &parsed.components,
        &parsed.params,
        &SourceMessage::Request(request),
    )?;
    Ok(RequestRoleEvidence::from_signature_base(&base))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed_request() -> (HttpRequest, RequestRoleEvidence) {
        let mut request = HttpRequest {
            method: "POST".to_owned(),
            target_uri: "https://mcp.example.com/mcp".to_owned(),
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#.to_vec(),
        };
        let evidence = crate::sign::sign_request(
            &mut request,
            &mcp_re_core::SigningKey::from_seed_bytes(&[11u8; 32]),
            "client-key-1",
            1_700_000_000,
            1_700_000_300,
            "n-bound",
        )
        .expect("the fixture request signs");
        (request, evidence)
    }

    #[test]
    fn a_derived_handle_agrees_with_the_signers_handle() {
        let (request, signed) = signed_request();
        assert_eq!(
            request_evidence_of(&request).expect("the signed request has a handle"),
            signed
        );
    }

    #[test]
    fn a_request_differing_in_a_covered_component_derives_a_different_handle() {
        let (request, signed) = signed_request();
        let mut other = request.clone();
        other.target_uri = "https://mcp.example.com/other".to_owned();
        assert_ne!(request_evidence_of(&other).ok(), Some(signed));
    }

    #[test]
    fn a_thin_covered_set_cannot_reproduce_a_signed_handle() {
        let (request, signed) = signed_request();
        let mut thin = request.clone();
        for (name, value) in &mut thin.headers {
            if !name.eq_ignore_ascii_case("signature-input") {
                continue;
            }
            let open = value.find('(').expect("covered set opens");
            let close = value.find(')').expect("covered set closes");
            value.replace_range(open + 1..close, "");
        }
        assert_ne!(request_evidence_of(&thin).ok(), Some(signed));
    }

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
