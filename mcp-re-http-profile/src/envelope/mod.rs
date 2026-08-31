// SPDX-License-Identifier: Apache-2.0
//! The JSON-RPC 2.0 control envelope of an MCP exchange — the vocabulary both directions
//! share, and the two authorities that use it.
//!
//! MCP-RE is an enforcement boundary for a protocol, not a reader of application data, and
//! the two halves inspect exactly as deep as deciding a legal exchange transition requires.
//! They are separate modules because they are separate decisions:
//!
//! * [`request`] — is this inbound body a legal JSON-RPC request this boundary may act on?
//!   Asked before admission, where a refusal costs nothing.
//! * [`response`] — is this backend reply a legal response to the outstanding request?
//!   Asked after the backend has run, where it cannot.
//!
//! What lives here is what neither owns alone: the JSON-RPC version every MCP message must
//! carry, and [`OutstandingId`], which the request half establishes and the response half
//! compares against.

use serde_json::Value;

/// The inbound half: whether a body is a legal JSON-RPC request this boundary may act on.
mod request;

/// The outbound half: whether a backend reply is a legal response to an outstanding request.
mod response;

pub use request::outstanding_id;
pub use request::validate_request_envelope;
pub use response::parse_response_body;
pub use response::validate_response_envelope;
pub use response::ResponseOutcome;
pub use response::ValidatedEnvelope;

/// The JSON-RPC version every MCP message must carry (MCP 2026-07-28: MCP messages MUST
/// follow the JSON-RPC 2.0 specification).
pub const JSON_RPC_VERSION: &str = "2.0";

/// The `id` of the request this exchange is answering.
///
/// A notification has none, which is a different fact from "the id is null": JSON-RPC
/// reserves `null` for a response whose request id could not be determined, and a
/// notification has no response at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutstandingId {
    /// An id-bearing request. The response MUST echo this value.
    Id(Value),
    /// A one-way notification. There is no response to correlate.
    Notification,
}
