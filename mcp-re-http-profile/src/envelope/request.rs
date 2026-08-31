// SPDX-License-Identifier: Apache-2.0
//! The JSON-RPC 2.0 control envelope of a CLIENT REQUEST — what a body must be before
//! this boundary will treat it as an MCP message at all.
//!
//! Its own module because it is its own authority. Its sibling [`super`] decides whether a
//! BACKEND REPLY is a legal response to an outstanding request; this one decides whether an
//! inbound body is a legal request. The two read different members, refuse for different
//! reasons, and are asked at opposite ends of the exchange — and only this one runs where a
//! refusal is still free.
//!
//! **What "legal" includes, and why representability is part of it.** A request this profile
//! cannot carry through its own re-serialization unchanged is not a request it may vouch
//! for: the evidence block is composed by re-serializing the whole body, and that happens
//! before `Content-Digest` and the signature, so anything the round trip alters is what gets
//! signed and delivered as authentic. [`crate::body::reject_unrepresentable_json`] owns the
//! rule; what this module owns is WHEN it is asked. Asking it on the dispatch path, where
//! the forwarded body is composed, would put it after the nonce is burned, the continuation
//! approval retired and the retention marker written — and a document MCP-RE will not carry
//! unchanged is not a document those effects should be spent on. So it belongs with the rest
//! of the request-shape decision, at the same cost: free, and answered before admission.
//!
//! It is asked FIRST, and on the original bytes, because every clause below it reads the
//! body through `serde_json`, which resolves a duplicate member name to one winner and would
//! therefore answer for a document the client did not sign.

use crate::error::HttpProfileError;
use serde_json::Value;

use super::OutstandingId;
use super::JSON_RPC_VERSION;

/// Read the outstanding id from a REQUEST body.
///
/// The serving path calls this on the body it verified, so the parse cannot fail in
/// production; it still fails closed rather than defaulting, because "I could not read the
/// request's id" must never become "any id correlates".
///
/// This reads the id and nothing else. Whether the body is a JSON-RPC message at all is
/// [`validate_request_envelope`]'s question, and the absence of an `id` is only a
/// notification once that has been answered — an object with no `jsonrpc` and no `method`
/// is not a notification, it is not a message.
pub fn outstanding_id(request_body: &[u8]) -> Result<OutstandingId, HttpProfileError> {
    let parsed: Value = serde_json::from_slice(request_body)
        .map_err(|_| HttpProfileError::MalformedEvidence("request body"))?;
    let object = parsed
        .as_object()
        .ok_or(HttpProfileError::MalformedEvidence("request body"))?;
    match object.get("id") {
        None => Ok(OutstandingId::Notification),
        Some(id) => Ok(OutstandingId::Id(id.clone())),
    }
}

/// Validate the JSON-RPC control envelope of a CLIENT REQUEST, returning the outstanding
/// id it establishes.
///
/// MCP requires every MCP message to follow JSON-RPC 2.0, and the requirement is not
/// direction-specific: a body that is not a legal request is not a message this boundary
/// may vouch for. Without this, the only member ever read on the request side was `id`,
/// and its ABSENCE was read as "notification" — so an object carrying nothing but an
/// evidence block was dispatched to the inner server and acknowledged with a signed 202
/// asserting the boundary had accepted an MCP message.
///
/// The checks, in the order a reader would apply them:
///
/// 1. the body is REPRESENTABLE — no duplicate member name, no number the `f64` carrier
///    would alter. Asked first, and on the original bytes, because every check below
///    reads the body through `serde_json`, which resolves a duplicate member to one
///    winner and silently answers for a document that has two;
/// 2. the body is JSON, and is an object;
/// 3. `jsonrpc` is present and exactly `"2.0"`;
/// 4. `method` is present and is a string — the member that makes a request a request,
///    and the one whose absence made "no `id`" mean "notification";
/// 5. neither `result` nor `error` is present, so one document cannot be read as a
///    request by this boundary and as a response by the peer;
/// 6. `params`, when present, is an object or an array (JSON-RPC 2.0 §4.2);
/// 7. `id`, when present, is a string or a number. JSON-RPC also permits `null`, and MCP
///    forbids it; a null-id request is refused rather than folded into a notification,
///    because the two are answered differently — one with a bound signed reply, the other
///    with a bodyless 202.
///
/// **On clause 1.** Representability is a property of the REQUEST DOCUMENT, so it belongs
/// with the rest of the request-shape decision and at the same cost. It used to be decided
/// on the dispatch path, when the forwarded body was composed — after a nonce had been
/// burned, an approval retired and a retention marker written. A document MCP-RE will not
/// carry unchanged is not a document those effects should have been spent on, and moving
/// the clause here is what makes the refusal free rather than making it stricter.
pub fn validate_request_envelope(request_body: &[u8]) -> Result<OutstandingId, HttpProfileError> {
    let malformed = HttpProfileError::MalformedEvidence;

    crate::body::reject_unrepresentable_json(request_body)?;

    let parsed: Value =
        serde_json::from_slice(request_body).map_err(|_| malformed("request body is not JSON"))?;
    let object = parsed
        .as_object()
        .ok_or(malformed("request body is not a JSON object"))?;

    match object.get("jsonrpc") {
        Some(Value::String(v)) if v == JSON_RPC_VERSION => {}
        None => return Err(malformed("request jsonrpc member absent")),
        Some(_) => return Err(malformed("request jsonrpc member is not \"2.0\"")),
    }

    match object.get("method") {
        Some(Value::String(_)) => {}
        None => return Err(malformed("request method member absent")),
        Some(_) => return Err(malformed("request method member is not a string")),
    }

    if object.contains_key("result") || object.contains_key("error") {
        return Err(malformed("request carries a response member"));
    }

    match object.get("params") {
        None | Some(Value::Object(_)) | Some(Value::Array(_)) => {}
        Some(_) => {
            return Err(malformed(
                "request params is neither an object nor an array",
            ))
        }
    }

    match object.get("id") {
        None => Ok(OutstandingId::Notification),
        Some(id @ (Value::String(_) | Value::Number(_))) => Ok(OutstandingId::Id(id.clone())),
        Some(_) => Err(malformed("request id is neither a string nor a number")),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_outstanding_id_is_read_from_the_request() {
        assert_eq!(
            outstanding_id(br#"{"jsonrpc":"2.0","id":7,"method":"tools/call"}"#).unwrap(),
            OutstandingId::Id(json!(7))
        );
        assert_eq!(
            outstanding_id(br#"{"jsonrpc":"2.0","method":"notifications/cancelled"}"#).unwrap(),
            OutstandingId::Notification
        );
        // A null id is an id: JSON-RPC distinguishes "absent" (a notification) from
        // "present and null", and folding them together would make a null-id request
        // answerable by a bodyless 202.
        assert_eq!(
            outstanding_id(br#"{"jsonrpc":"2.0","id":null,"method":"x"}"#).unwrap(),
            OutstandingId::Id(Value::Null)
        );
        assert!(outstanding_id(b"not json").is_err());
    }

    /// The request side of the same rule. Reading only `id` made "no id" mean
    /// "notification", so a body that is not a JSON-RPC message at all was dispatched to
    /// the inner server and acknowledged with a signed 202.
    #[test]
    fn a_request_body_that_is_not_a_json_rpc_message_is_refused() {
        for body in [
            r#"{"_meta":{"se.syncom/mcp-re.http.request":{}},"foo":1}"#,
            r#"{"foo":1}"#,
            r#"{}"#,
            r#"{"jsonrpc":"2.0"}"#,
            r#"{"method":"tools/call","id":1}"#,
            r#"{"jsonrpc":"1.0","method":"tools/call"}"#,
            r#"{"jsonrpc":"2.0","method":7}"#,
            r#"{"jsonrpc":"2.0","method":"x","result":{}}"#,
            r#"{"jsonrpc":"2.0","method":"x","error":{"code":-1,"message":"m"}}"#,
            r#"{"jsonrpc":"2.0","method":"x","params":"nope"}"#,
            r#"{"jsonrpc":"2.0","method":"x","id":null}"#,
            r#"{"jsonrpc":"2.0","method":"x","id":{"a":1}}"#,
            "[]",
            "not json",
        ] {
            assert!(
                validate_request_envelope(body.as_bytes()).is_err(),
                "{body} was accepted as an MCP request"
            );
            // The reader the serving path uses today sees no `id` in most of these and
            // calls them notifications, which is what the validator exists to stop.
            let _ = outstanding_id(body.as_bytes());
        }
    }

    /// An unrepresentable request is refused HERE, where the refusal is free.
    ///
    /// Both bodies below are legal JSON-RPC by every other clause, and `serde_json` reads
    /// each of them without complaint — a duplicate member resolves to one winner, and the
    /// integer arrives as an `f64` that has lost thirteen significant digits. That is the
    /// point: the validator
    /// answers for the document the client signed, not for the one a parser picked out of
    /// it, and the answer has to come before anything is spent.
    #[test]
    fn a_request_this_boundary_cannot_carry_unchanged_is_refused() {
        for body in [
            r#"{"jsonrpc":"2.0","method":"tools/call","id":1,"id":2}"#,
            r#"{"jsonrpc":"2.0","method":"tools/call","params":{"n":123456789012345678901234567890}}"#,
        ] {
            assert!(
                validate_request_envelope(body.as_bytes()).is_err(),
                "{body} was accepted as a representable MCP request"
            );
        }
    }

    /// The mirror: legal requests and legal notifications still pass, and the id they
    /// establish is the same one the correlation check will compare against.
    #[test]
    fn a_legal_request_yields_its_outstanding_id() {
        assert_eq!(
            validate_request_envelope(br#"{"jsonrpc":"2.0","id":7,"method":"tools/call"}"#)
                .expect("a legal request"),
            OutstandingId::Id(json!(7))
        );
        assert_eq!(
            validate_request_envelope(
                br#"{"jsonrpc":"2.0","id":"req-1","method":"tools/call","params":{"name":"t"}}"#
            )
            .expect("a legal request"),
            OutstandingId::Id(json!("req-1"))
        );
        assert_eq!(
            validate_request_envelope(
                br#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}"#
            )
            .expect("a legal notification"),
            OutstandingId::Notification
        );
    }}
