// SPDX-License-Identifier: Apache-2.0
//! WHAT is retained: the record's schema, its encoding, and which headers it keeps.
//!
//! This owner answers one question — what an auditor will find when it asks for an
//! exchange — and it answers it for both directions at once, because a request and a
//! response are retained under the same rules and reconstructed by the same reader.
//!
//! **Which headers are kept is a security decision, not a size one.** The retained set is
//! exactly the covered components the signature base names, plus what a reconstruction
//! needs to rebuild it. Retaining less means the chain cannot be re-verified; retaining
//! more means keeping bytes nothing will ever check.
//!
//! A covered CREDENTIAL header is retained for that reason and no other: the signature base
//! includes it, so a reconstruction that dropped it would fail to verify a hop that was
//! perfectly valid. That is a stated operational consequence of ADR-MCPRE-054, not an
//! oversight — see the module documentation of [`super`].
//!
//! Bodies are base64url rather than byte arrays: a JSON array of 40 000 integers is the
//! same information at eight times the size, and the store holds one of these per served
//! call.

use mcp_re_core::b64url_decode;
use mcp_re_core::b64url_encode;
use mcp_re_http_profile::chain::RetainedHop;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;
use serde::Deserialize;
use serde::Serialize;

use super::covered_set::covered_headers;
use super::RetentionError;

/// The schema token every retained record carries.
///
/// A content-addressed blob has no type of its own — the store returns bytes that hash to the
/// name asked for and nothing more. Without a token in the record, a future change to the
/// encoding would be read by an old reader as a valid record of a different shape, and the
/// chain it reconstructed would be about something else.
///
/// `pub(super)` and declared HERE: the record is the only thing that writes it or checks it,
/// and it was `pub` for a consumer that does not exist anywhere in the tree.
pub(super) const RETAINED_HOP_SCHEMA: &str = "mcp-re-retained-hop/v1";

/// One retained exchange, in the form an auditor reconstructs a chain from.
///
/// Bodies are base64url rather than byte arrays: a JSON array of 40 000 integers is the
/// same information at eight times the size, and this store holds one of these per
/// served call.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RetainedHopRecord {
    schema: String,
    request: RetainedRequest,
    response: RetainedResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RetainedRequest {
    method: String,
    target_uri: String,
    headers: Vec<(String, String)>,
    body_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RetainedResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body_b64: String,
}

/// The headers a retained message keeps: the ones its own signature covers, plus the two
/// that carry the signature itself.
///
/// Everything else is dropped. Reconstruction re-verifies each message, and verification
/// reads exactly the covered components plus `signature`/`signature-input` — so an
/// uncovered header contributes nothing to a chain and is retained for no reason. That
/// distinction matters because of what these records hold: this profile REQUIRES
/// `authorization` and `dpop` to be covered when present, so a retained request contains
/// the live bearer token and DPoP proof of the call it describes. Those cannot be
/// stripped without making the signature base unreproducible — the signature is over
/// them. What CAN be kept out is every other credential the client happened to send
/// (`cookie`, `proxy-authorization`, bespoke API-key headers), none of which any auditor
/// will ever need.
///
impl RetainedHopRecord {
    pub(super) fn of(request: &HttpRequest, response: &HttpResponse) -> Self {
        RetainedHopRecord {
            schema: RETAINED_HOP_SCHEMA.to_owned(),
            request: retained_request(request),
            response: RetainedResponse {
                status: response.status,
                headers: covered_headers(&response.headers, mcp_re_http_profile::RESPONSE_LABEL),
                body_b64: b64url_encode(&response.body),
            },
        }
    }

    pub(super) fn into_hop(self) -> Result<RetainedHop, RetentionError> {
        if self.schema != RETAINED_HOP_SCHEMA {
            return Err(RetentionError::Malformed("unknown retained-hop schema"));
        }
        Ok(RetainedHop {
            request: HttpRequest {
                method: self.request.method,
                target_uri: self.request.target_uri,
                headers: self.request.headers,
                body: b64url_decode(&self.request.body_b64)
                    .map_err(|_| RetentionError::Malformed("request body encoding"))?,
            },
            response: HttpResponse {
                status: self.response.status,
                headers: self.response.headers,
                body: b64url_decode(&self.response.body_b64)
                    .map_err(|_| RetentionError::Malformed("response body encoding"))?,
            },
        })
    }
}

/// The retained-request half of a record, shared by the reservation marker and the hop.
pub(super) fn retained_request(request: &HttpRequest) -> RetainedRequest {
    RetainedRequest {
        method: request.method.clone(),
        target_uri: request.target_uri.clone(),
        headers: covered_headers(&request.headers, mcp_re_http_profile::REQUEST_LABEL),
        body_b64: b64url_encode(&request.body),
    }
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::RetainedHopRecord;
    use super::RETAINED_HOP_SCHEMA;
    use mcp_re_http_profile::HttpRequest;
    use mcp_re_http_profile::HttpResponse;

    fn request() -> HttpRequest {
        HttpRequest {
            method: "POST".to_owned(),
            target_uri: "https://example.test/mcp".to_owned(),
            headers: vec![
                (
                    "signature-input".to_owned(),
                    format!(
                        "{}=(\"@method\" \"content-digest\")",
                        mcp_re_http_profile::REQUEST_LABEL
                    ),
                ),
                ("signature".to_owned(), "abc".to_owned()),
                ("content-digest".to_owned(), "sha-256=:AAAA:".to_owned()),
                ("cookie".to_owned(), "session=secret".to_owned()),
            ],
            body: b"{\"jsonrpc\":\"2.0\"}".to_vec(),
        }
    }

    fn response() -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: vec![
                (
                    "signature-input".to_owned(),
                    format!(
                        "{}=(\"@status\" \"content-digest\")",
                        mcp_re_http_profile::RESPONSE_LABEL
                    ),
                ),
                ("signature".to_owned(), "def".to_owned()),
                ("content-digest".to_owned(), "sha-256=:BBBB:".to_owned()),
                ("set-cookie".to_owned(), "session=secret".to_owned()),
            ],
            body: b"{\"result\":1}".to_vec(),
        }
    }

    /// The whole point of the record: an auditor gets back exactly the bytes the signature
    /// was over. A record that did not round-trip could not re-verify a hop that was
    /// perfectly valid.
    #[test]
    fn a_record_round_trips_the_bytes_a_reconstruction_re_verifies() {
        let hop = RetainedHopRecord::of(&request(), &response())
            .into_hop()
            .expect("a record this implementation wrote reads back");
        assert_eq!(hop.request.method, "POST");
        assert_eq!(hop.request.target_uri, "https://example.test/mcp");
        assert_eq!(hop.request.body, b"{\"jsonrpc\":\"2.0\"}");
        assert_eq!(hop.response.status, 200);
        assert_eq!(hop.response.body, b"{\"result\":1}");
    }

    /// **Retaining more is a credential on disk.** The store has no expiry and holds one
    /// object per served call; an uncovered `cookie` contributes nothing to any
    /// reconstruction and would sit there forever. Both directions, because a `set-cookie`
    /// on the response half is the same exposure.
    #[test]
    fn an_uncovered_credential_header_is_not_retained_in_either_direction() {
        let record = RetainedHopRecord::of(&request(), &response());
        let hop = record.into_hop().expect("reads back");
        let request_names: Vec<&str> = hop
            .request
            .headers
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();
        let response_names: Vec<&str> = hop
            .response
            .headers
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();
        assert!(
            !request_names.contains(&"cookie"),
            "an uncovered request credential was retained: {request_names:?}"
        );
        assert!(
            !response_names.contains(&"set-cookie"),
            "an uncovered response credential was retained: {response_names:?}"
        );
    }

    /// **Retaining less breaks re-verification.** The covered components and the two headers
    /// carrying the signature itself must survive, or a reconstruction fails on a hop that
    /// was valid. This is the direction the control above could be satisfied by deleting
    /// everything.
    #[test]
    fn every_covered_header_and_the_signature_itself_survive() {
        let hop = RetainedHopRecord::of(&request(), &response())
            .into_hop()
            .expect("reads back");
        for (half, headers) in [
            ("request", &hop.request.headers),
            ("response", &hop.response.headers),
        ] {
            let names: Vec<&str> = headers.iter().map(|(name, _)| name.as_str()).collect();
            for required in ["signature", "signature-input", "content-digest"] {
                assert!(
                    names.contains(&required),
                    "the {half} half dropped `{required}`, which its own signature base \
                     names: {names:?}"
                );
            }
        }
    }

    /// A content-addressed blob has no type of its own. Without the schema token a future
    /// encoding would be read by an old reader as a valid record of a different shape, and
    /// the chain it reconstructed would be about something else.
    #[test]
    fn a_record_of_an_unknown_schema_is_refused_rather_than_interpreted() {
        let record = RetainedHopRecord::of(&request(), &response());
        let mut json: serde_json::Value =
            serde_json::to_value(&record).expect("the record serializes");
        json["schema"] = serde_json::Value::String("mcp-re-retained-hop/v2".to_owned());
        let future: RetainedHopRecord =
            serde_json::from_value(json).expect("the shape still parses");
        assert!(
            future.into_hop().is_err(),
            "a record naming an unknown schema must be refused, not read as this one"
        );
    }

    /// The stored form is `deny_unknown_fields`, so a record carrying a field this reader
    /// does not know is refused at parse rather than silently ignored.
    #[test]
    fn an_unknown_field_is_refused_at_parse() {
        let record = RetainedHopRecord::of(&request(), &response());
        let mut json: serde_json::Value = serde_json::to_value(&record).expect("serializes");
        json["extra"] = serde_json::Value::Bool(true);
        assert!(
            serde_json::from_value::<RetainedHopRecord>(json).is_err(),
            "an unknown field must be refused, not ignored"
        );
    }

    /// A body that is not base64url is a malformed record, not a shorter body.
    #[test]
    fn a_body_that_is_not_base64url_is_malformed_not_empty() {
        let record = RetainedHopRecord::of(&request(), &response());
        let mut json: serde_json::Value = serde_json::to_value(&record).expect("serializes");
        json["request"]["body_b64"] = serde_json::Value::String("!!! not base64".to_owned());
        let broken: RetainedHopRecord = serde_json::from_value(json).expect("shape parses");
        assert!(
            broken.into_hop().is_err(),
            "an undecodable body must be refused, never read as an empty one"
        );
    }

    /// The schema token this implementation writes is the one it accepts.
    #[test]
    fn the_written_schema_is_the_accepted_one() {
        let record = RetainedHopRecord::of(&request(), &response());
        let json: serde_json::Value = serde_json::to_value(&record).expect("serializes");
        assert_eq!(json["schema"].as_str(), Some(RETAINED_HOP_SCHEMA));
    }
}
