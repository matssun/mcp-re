// SPDX-License-Identifier: Apache-2.0
//! Pure HTTP message model for the profile. This crate does no networking; a
//! transport layer (proxy/host) adapts its real messages into these shapes at
//! the boundary, exactly once, before verification.

use crate::error::HttpProfileError;

/// A request as seen by the signer/verifier. `target_uri` is the absolute
/// target URI (RFC 9421 `@target-uri`); header names are matched
/// case-insensitively; `body` is the unencoded content bytes.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub target_uri: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// A response as seen by the signer/verifier.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Look up a header that MUST appear at most once. Returns `Ok(None)` when
/// absent, and fails closed on duplicates (v0.11 grill B.1: an ambiguous
/// `authorization`/`dpop`/digest surface is a protocol error, not a pick-one).
pub fn single_header<'a>(
    headers: &'a [(String, String)],
    name: &'static str,
) -> Result<Option<&'a str>, HttpProfileError> {
    let mut found: Option<&'a str> = None;
    for (k, v) in headers {
        if k.eq_ignore_ascii_case(name) {
            if found.is_some() {
                return Err(HttpProfileError::DuplicateHeader(name));
            }
            found = Some(v.as_str());
        }
    }
    Ok(found)
}

/// Like [`single_header`] but the header is REQUIRED.
pub fn required_header<'a>(
    headers: &'a [(String, String)],
    name: &'static str,
) -> Result<&'a str, HttpProfileError> {
    single_header(headers, name)?.ok_or(HttpProfileError::MissingEvidence(name))
}

/// Fail closed if the message carries any `Content-Encoding` other than
/// `identity`: the profile signs and digests unencoded content bytes only
/// (v0.11 grill B.1; RFC 9530 warns representation metadata must be protected).
pub fn reject_content_encoding(headers: &[(String, String)]) -> Result<(), HttpProfileError> {
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("content-encoding") && !v.trim().eq_ignore_ascii_case("identity")
        {
            return Err(HttpProfileError::ContentEncodingPresent);
        }
    }
    Ok(())
}
