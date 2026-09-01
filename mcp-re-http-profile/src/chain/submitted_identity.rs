// SPDX-License-Identifier: Apache-2.0
//! What IDENTIFIES a submission — the closed representation a retained hop's commitment is
//! taken over.
//!
//! Its own module because it is its own security fact, and because the fact is defined by
//! what it REFUSES to select. Its sibling [`super`] decides whether a chain verified and
//! what its label is; this one decides only when two retained submissions are the same
//! submission, and it must answer that for hops nothing verified — the unverified tail of an
//! Incomplete record is exactly where the question matters and where no signature check
//! reaches.
//!
//! # A curated field list cannot hold this property
//!
//! An earlier revision folded the request line, the bodies and the `signature` header. That
//! omitted `signature-input` — the header that says WHAT was signed — so two unverified tail
//! hops naming different covered components, a different `created` or a different keyid
//! shared an identity, and the tail substitution the field exists to prevent stayed open
//! through the omission.
//!
//! The recursion is why no list can be trusted here: `signature-input` NAMES covered
//! components, so the values of those components are part of the hop's identity too. Any
//! list that reached them would have to be maintained against a header set it does not
//! control.
//!
//! So the representation is closed: a submitted hop IS its retained request and response,
//! entire. Nothing is selected, because selecting is how an identity comes to omit
//! something.

use mcp_re_core::b64url_encode;
use sha2::Digest;
use sha2::Sha256;

use crate::message::HttpRequest;
use crate::message::HttpResponse;

use super::RetainedHop;

/// Digest the submitted hops — an IDENTITY for the submission, length-delimited so no two
/// distinct submissions can share a preimage.
///
/// # What a submitted hop IS
///
/// Every retained fact about the hop, and the closed representation is the retained hop
/// itself: a request's method, target and headers and body, and a response's status and
/// headers and body. Nothing is selected, because selecting is how an identity comes to
/// omit something.
///
/// A curated field list cannot hold this property. One that folded only `signature` left
/// `signature-input` out — so two unverified tail hops naming different covered components,
/// a different `created`, or a different keyid shared an identity, and the tail substitution
/// this digest exists to prevent stayed open through the header that says what was signed.
/// The recursive part is why a list can never be trusted here: `signature-input` NAMES
/// covered components, so the values of those components are part of the hop's identity
/// too. Folding every retained header reaches them without anyone having to notice they
/// were reachable.
///
/// # Why this cannot silently omit a field again
///
/// The fold DESTRUCTURES each message exhaustively. Adding a field to [`HttpRequest`] or
/// [`HttpResponse`] is a compile error here until the fold accounts for it — the language
/// carries the obligation instead of a reviewer remembering it.
///
/// Every variable-length field is preceded by its length as 8 octets big-endian, and each
/// header contributes both its name and its value the same way. Concatenating raw bytes
/// would let a request ending in one byte and a response beginning with another produce the
/// same stream as a different split, which is exactly the ambiguity an identity must not
/// have. Header ORDER is part of the identity: the retained bytes carry an order, and two
/// submissions whose retained bytes differ are two submissions.
pub(super) fn submitted_commitment(hops: &[RetainedHop]) -> String {
    let mut h = Sha256::new();
    h.update(SUBMITTED_COMMITMENT_DOMAIN.len().to_be_bytes());
    h.update(SUBMITTED_COMMITMENT_DOMAIN);
    h.update((hops.len() as u64).to_be_bytes());
    for hop in hops {
        let RetainedHop { request, response } = hop;
        let HttpRequest {
            method,
            target_uri,
            headers: request_headers,
            body: request_body,
        } = request;
        let HttpResponse {
            status,
            headers: response_headers,
            body: response_body,
        } = response;

        h.update(u64::from(*status).to_be_bytes());
        for part in [
            method.as_bytes(),
            target_uri.as_bytes(),
            request_body.as_slice(),
            response_body.as_slice(),
        ] {
            h.update((part.len() as u64).to_be_bytes());
            h.update(part);
        }
        for headers in [request_headers, response_headers] {
            h.update((headers.len() as u64).to_be_bytes());
            for (name, value) in headers {
                h.update((name.len() as u64).to_be_bytes());
                h.update(name.as_bytes());
                h.update((value.len() as u64).to_be_bytes());
                h.update(value.as_bytes());
            }
        }
    }
    b64url_encode(&h.finalize())
}

/// Domain separator for [`submitted_commitment`], so its digests can never be confused
/// with any other SHA-256 this profile takes over evidence.
const SUBMITTED_COMMITMENT_DOMAIN: &[u8] = b"mcp-re-evidence/v3:submitted-chain";
#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::HttpRequest;
    use crate::message::HttpResponse;

    fn hop(status: u16, body: &str) -> RetainedHop {
        RetainedHop {
            request: HttpRequest {
                method: "POST".into(),
                target_uri: "https://example.test/mcp".into(),
                headers: vec![("signature".into(), "sig1=:AA:".into())],
                body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#.to_vec(),
            },
            response: HttpResponse {
                status,
                headers: vec![("signature".into(), "sig1=:BB:".into())],
                body: body.as_bytes().to_vec(),
            },
        }
    }

    /// The response status is part of the identity.
    #[test]
    fn the_response_status_is_inside_the_submitted_identity() {
        assert_ne!(
            submitted_commitment(&[hop(200, "{}")]),
            submitted_commitment(&[hop(400, "{}")])
        );
    }

    /// Header ORDER is part of the submission identity, and that is a decision rather than
    /// an accident of the fold.
    ///
    /// The earlier curated digest SORTED the `signature` headers, so two retained hops
    /// carrying the same signatures in a different order shared an identity. Under the
    /// closed representation the identity is of the RETAINED BYTES, and two retained
    /// artefacts whose bytes differ are two artefacts.
    ///
    /// This cannot produce a false match. It could in principle produce a false MISMATCH —
    /// an honest record failing to verify because something reordered its headers — except
    /// that both sides of the comparison are computed from the same stored artefact: the
    /// issuer digests what it retained, and the verifier digests what it presents. Nothing
    /// reorders in between.
    #[test]
    fn header_order_is_part_of_the_submission_identity() {
        let mut a = hop(200, "{}");
        a.request.headers = vec![
            ("signature".to_string(), "sig1=:AA:".to_string()),
            ("signature".to_string(), "sig2=:BB:".to_string()),
        ];
        let mut b = hop(200, "{}");
        b.request.headers = vec![
            ("signature".to_string(), "sig2=:BB:".to_string()),
            ("signature".to_string(), "sig1=:AA:".to_string()),
        ];
        assert_ne!(submitted_commitment(&[a]), submitted_commitment(&[b]));
    }

    /// EVERY retained header is inside the submitted identity — the claim this file's
    /// predecessor stated in reverse.
    ///
    /// The old test asserted that a non-`signature` header was OUTSIDE it, which is exactly
    /// the property that left `signature-input` out of the identity. The claim was not
    /// stale; it was wrong, and it is inverted rather than deleted so the reversal stays
    /// visible.
    #[test]
    fn every_retained_header_is_inside_the_submitted_identity() {
        let mut with_extra = hop(200, "{}");
        with_extra
            .request
            .headers
            .push(("x-forwarded-for".to_string(), "10.0.0.1".to_string()));
        assert_ne!(
            submitted_commitment(&[hop(200, "{}")]),
            submitted_commitment(&[with_extra])
        );
    }

    /// An empty chain still has an identity, and it is not the identity of a one-hop chain.
    #[test]
    fn the_empty_submission_has_an_identity_of_its_own() {
        let empty = submitted_commitment(&[]);
        assert!(!empty.is_empty());
        assert_ne!(empty, submitted_commitment(&[hop(200, "{}")]));
    }
}
