// SPDX-License-Identifier: Apache-2.0
//! WHAT capsule-anchor's registration contract puts on the wire.
//!
//! One fact: **the shape of one registration exchange with this service.** The path, the
//! media type, and the two JSON documents — nothing about what an answer MEANS, which is
//! [`super::fault`]'s, and nothing about whether a receipt is good, which is the
//! verifying layer's.
//!
//! Every constant here is measured against the service's published OpenAPI document, not
//! inferred from a family resemblance to SCRAPI. That is the point of the second leaf: the
//! two protocols agree on nothing this module names.

use serde::Deserialize;
use serde::Serialize;

/// How this leaf names the protocol it speaks, in refusals and in the artifact.
///
/// Not a version pin, deliberately: capsule-anchor publishes an OpenAPI document rather
/// than a versioned protocol, so there is no revision to name. What an operator gets is
/// the SERVICE contract, and the claim it earns says exactly that.
pub(in crate::transparency::auditor::registration::capsule_anchor) const CAPSULE_ANCHOR_CONTRACT:
    &str = "capsule-anchor /transparency";

/// The registration resource, relative to the operator-configured base URL.
pub(super) const REGISTER_STATEMENT_PATH: &str = "/transparency/register-statement";

/// The one media type this exchange uses, in both directions.
///
/// The service's own note on why: base64-in-JSON rather than a raw `application/cose`
/// body, so the same convention round-trips the request AND the response.
pub(super) const JSON_MEDIA_TYPE: &str = "application/json";

/// The registration URL for a service base.
pub(super) fn register_statement_url(base_url: &str) -> String {
    format!("{base_url}{REGISTER_STATEMENT_PATH}")
}

/// What goes up: the Signed Statement's exact octets, base64.
#[derive(Debug, Serialize)]
pub(super) struct RegisterStatementRequest {
    /// Standard base64 (with padding) of the COSE_Sign1 Signed Statement.
    pub(super) signed_statement_b64: String,
}

/// What comes back on a `200`.
///
/// `receipt_b64` is the only field this leaf reads. The rest are the service's own log
/// coordinates, and they are deliberately NOT consumed: the receipt commits to its own
/// `(tree_size, leaf_index)` or it does not, and a leaf that trusted the JSON beside it
/// would be supplying from an unsigned document what the verifier must get from a signed
/// one. `serde` ignores them.
#[derive(Debug, Deserialize)]
pub(super) struct RegisterStatementResponse {
    /// Base64 of the COSE Receipt (COSE_Sign1, CBOR tag 18).
    pub(super) receipt_b64: String,
}
