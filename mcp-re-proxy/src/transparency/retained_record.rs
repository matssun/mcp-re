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
use super::RETAINED_HOP_SCHEMA;

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
