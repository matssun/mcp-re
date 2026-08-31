// SPDX-License-Identifier: Apache-2.0
//! The JSON-RPC 2.0 control envelope of a BACKEND REPLY — validated before anything
//! downstream may treat it as a response at all.
//!
//! Its own module because it is its own authority. Its sibling [`super::request`] decides
//! whether an inbound body is a legal request, where a refusal is still free; this one
//! decides whether a reply is a legal response to an outstanding request, where the backend
//! has already run. The two read different members and refuse for different reasons.
//!
//! # Where the boundary is
//!
//! MCP-RE is an enforcement boundary for a protocol, not a reader of application data. This
//! module inspects exactly as deep as deciding a legal exchange transition requires:
//!
//! ```text
//! IN SCOPE                              OUT OF SCOPE
//! JSON syntax                           tool output semantics
//! `jsonrpc` version                     resource contents
//! `id` correlation                      prompt / model output
//! `result` XOR `error`                  every application field inside `result`
//! the `error` member's shape
//! ```
//!
//! `resultType` and `requestState` are the MCP lifecycle layer above this one and live in
//! [`crate::result_class`]. Everything else inside `result` is opaque payload that MCP-RE
//! carries and signs without reading.
//!
//! # Why the boundary must not be the deployment's choice
//!
//! Until this validation existed, the only unconditional inspection of a backend reply on
//! the serving path was a `resultType` classification that returned "not my business" for a
//! body that was not JSON at all. Every other envelope check lived inside the MRTR open-leg
//! recorder, which returns early when no continuation store is configured. So whether MCP-RE
//! refused a malformed protocol response depended on whether an operator had wired Redis — a
//! capability with no relationship to protocol legality.

use crate::error::HttpProfileError;
use serde_json::Value;

use super::OutstandingId;
use super::JSON_RPC_VERSION;

/// Which of the two mutually exclusive JSON-RPC response members this message carries.
///
/// A JSON-RPC error is a **valid terminal protocol response**, not a transport failure and
/// not a malformed message. Keeping it as a variant here rather than an error return is what
/// stops the three from collapsing: a backend that answers `{"error":{...}}` has spoken the
/// protocol correctly and the exchange ends normally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseOutcome {
    /// A `result` member. Its MCP lifecycle class is decided by [`crate::result_class`].
    Result,
    /// An `error` member — a legal terminal response.
    Error,
}

/// A backend reply whose JSON-RPC control envelope is legal and correlated.
///
/// Borrowed from the parsed body: this type is a VERDICT about bytes someone else owns, and
/// copying the payload out to carry it would invite a reader to act on a copy that no longer
/// matches what gets signed.
#[derive(Debug, Clone, Copy)]
pub struct ValidatedEnvelope<'a> {
    /// Which member the response carries.
    pub outcome: ResponseOutcome,
    /// The `result` member, when there is one. Handed to the MCP lifecycle classifier and
    /// otherwise untouched.
    pub result: Option<&'a Value>,
}

/// Validate the JSON-RPC control envelope of a backend reply against the outstanding
/// request.
///
/// Every failure is [`HttpProfileError::UpstreamResponseInvalid`] carrying the specific
/// clause violated. One error type because they are one fact — the upstream did not produce
/// a legal response to this request — and a specific clause because an operator debugging a
/// backend needs to know which one.
///
/// The checks, in the order a reader would apply them:
///
/// 1. the body is JSON, and is an object;
/// 2. `jsonrpc` is present and exactly `"2.0"`;
/// 3. exactly one of `result` / `error` is present;
/// 4. `error`, when present, is an object with an integer `code` and a string `message`;
/// 5. `result`, when present, is an object (MCP defines every Result as one);
/// 6. the reply carries no `method` member, so it is not simultaneously a legal
///    server-initiated request;
/// 7. `id` is present and equal to the outstanding request's id.
///
/// **On clause 6.** A document carrying `jsonrpc`, `id`, `result` AND `method` satisfies
/// every other clause here while a client whose JSON-RPC union is not strict parses it as
/// a request. Signing it would put the boundary's delegated signature over an
/// authenticated injection channel from the inner backend toward every such client, and
/// the claim this profile makes — that it signs a legal JSON-RPC response — would be
/// false: what it signed is also a legal request.
///
/// **On the null-id allowance.** JSON-RPC permits a `null` id when the responder could not
/// determine the request's id — a parse or invalid-request failure. That excuse is not
/// available here: MCP-RE forwards a body it has already parsed and verified, so a backend
/// that cannot find the id in it has produced a response to a request that does not exist.
/// A null id is refused like any other mismatch.
pub fn validate_response_envelope<'a>(
    parsed: &'a Value,
    outstanding: &OutstandingId,
) -> Result<ValidatedEnvelope<'a>, HttpProfileError> {
    let invalid = HttpProfileError::UpstreamResponseInvalid;

    let object = parsed.as_object().ok_or(invalid("not a JSON object"))?;

    match object.get("jsonrpc") {
        Some(Value::String(v)) if v == JSON_RPC_VERSION => {}
        None => return Err(invalid("jsonrpc member absent")),
        Some(_) => return Err(invalid("jsonrpc member is not \"2.0\"")),
    }

    let result = object.get("result");
    let error = object.get("error");
    let outcome = match (result, error) {
        (Some(_), Some(_)) => return Err(invalid("both result and error present")),
        (None, None) => return Err(invalid("neither result nor error present")),
        (Some(_), None) => ResponseOutcome::Result,
        (None, Some(_)) => ResponseOutcome::Error,
    };

    if let Some(error) = error {
        let error = error.as_object().ok_or(invalid("error is not an object"))?;
        match error.get("code") {
            Some(code) if code.is_i64() => {}
            _ => return Err(invalid("error.code is not an integer")),
        }
        match error.get("message") {
            Some(Value::String(_)) => {}
            _ => return Err(invalid("error.message is not a string")),
        }
    }

    // MCP defines every Result as an object. A non-object `result` also silently classifies
    // as terminal in `result_class` — `get("resultType")` on a string yields `None` — so
    // refusing it here is what keeps that classifier's contract honest.
    if let Some(result) = result {
        if !result.is_object() {
            return Err(invalid("result is not an object"));
        }
    }

    // A response is a response and nothing else. `method` is the member that makes a
    // JSON-RPC document a request, and `params` only ever accompanies one.
    if object.contains_key("method") {
        return Err(invalid("response carries a method member"));
    }
    if object.contains_key("params") {
        return Err(invalid("response carries a params member"));
    }

    // Correlation, last, because it is the check most likely to be read as the only one.
    let expected = match outstanding {
        // A response to a notification is not a correlation failure — it is a response that
        // should not exist. The serving path never asks this question (the notification arm
        // branches before validation), so reaching here means a caller applied the wrong
        // outstanding id, and answering "correlated" would be worse than refusing.
        OutstandingId::Notification => return Err(invalid("a notification has no response")),
        OutstandingId::Id(id) => id,
    };
    match object.get("id") {
        None => return Err(invalid("id member absent")),
        Some(id) if id == expected => {}
        Some(_) => return Err(invalid("id does not match the outstanding request")),
    }

    Ok(ValidatedEnvelope { outcome, result })
}

/// Parse a backend reply body, failing closed with the envelope error.
///
/// Separate from [`validate_response_envelope`] because the caller holds the parsed value
/// afterwards — the lifecycle classifier reads `result` out of it, and re-parsing the same
/// bytes twice is how two readers end up disagreeing about one message.
pub fn parse_response_body(body: &[u8]) -> Result<Value, HttpProfileError> {
    serde_json::from_slice(body).map_err(|_| HttpProfileError::UpstreamResponseInvalid("not JSON"))
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn id(n: i64) -> OutstandingId {
        OutstandingId::Id(json!(n))
    }

    fn validate(body: &str, outstanding: &OutstandingId) -> Result<(), HttpProfileError> {
        let parsed = parse_response_body(body.as_bytes())?;
        validate_response_envelope(&parsed, outstanding).map(|_| ())
    }

    #[test]
    fn an_ordinary_result_response_validates() {
        let v = validate(r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#, &id(1));
        assert!(v.is_ok(), "{v:?}");
    }

    /// A JSON-RPC error is a VALID terminal response. It is not malformed, and it is not a
    /// transport failure — the three were one outcome on the serving path, and this is the
    /// seam that keeps the first of them distinct.
    #[test]
    fn a_json_rpc_error_is_a_valid_response_not_a_malformed_one() {
        let parsed = parse_response_body(
            br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"no"}}"#,
        )
        .expect("parses");
        let envelope = validate_response_envelope(&parsed, &id(1)).expect("a legal response");
        assert_eq!(envelope.outcome, ResponseOutcome::Error);
        assert!(envelope.result.is_none());
    }

    /// The broken implementation: `.ok()?` on the parse, which reads downstream as "not my
    /// business" and lets the bytes through to the signer.
    #[test]
    fn an_unparseable_body_is_refused() {
        for body in [&b"not json"[..], &b""[..], &b"{"[..]] {
            assert_eq!(
                parse_response_body(body).expect_err("unparseable"),
                HttpProfileError::UpstreamResponseInvalid("not JSON")
            );
        }
    }

    #[test]
    fn a_non_object_body_is_refused() {
        for body in ["[]", "\"hello\"", "42", "null"] {
            assert!(
                validate(body, &id(1)).is_err(),
                "{body} was accepted as a response"
            );
        }
    }

    /// MCP requires MCP messages to follow JSON-RPC 2.0. Nothing in the tree checked this
    /// before — on requests or responses.
    #[test]
    fn the_json_rpc_version_must_be_exactly_two_point_zero() {
        for body in [
            r#"{"id":1,"result":{}}"#,
            r#"{"jsonrpc":"1.0","id":1,"result":{}}"#,
            r#"{"jsonrpc":"2.1","id":1,"result":{}}"#,
            r#"{"jsonrpc":2.0,"id":1,"result":{}}"#,
            r#"{"jsonrpc":null,"id":1,"result":{}}"#,
            r#"{"jsonrpc":"2.0 ","id":1,"result":{}}"#,
        ] {
            assert!(validate(body, &id(1)).is_err(), "{body} was accepted");
        }
    }

    /// Both members present is the shape that let a response carry a success and a failure
    /// at once. The classifier reads `result.resultType` and never notices the `error`.
    #[test]
    fn a_response_carrying_both_result_and_error_is_refused() {
        assert_eq!(
            validate(
                r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true},"error":{"code":-1,"message":"x"}}"#,
                &id(1),
            )
            .expect_err("both members"),
            HttpProfileError::UpstreamResponseInvalid("both result and error present")
        );
    }

    /// Neither member present classified as `Complete`, because the lifecycle classifier
    /// reads an absent `result` as "this is an error response" — which is only true when
    /// there IS an error member.
    #[test]
    fn a_response_carrying_neither_result_nor_error_is_refused() {
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","id":1}"#, &id(1)).expect_err("neither member"),
            HttpProfileError::UpstreamResponseInvalid("neither result nor error present")
        );
    }

    #[test]
    fn a_malformed_error_member_is_refused() {
        for body in [
            r#"{"jsonrpc":"2.0","id":1,"error":"boom"}"#,
            r#"{"jsonrpc":"2.0","id":1,"error":{}}"#,
            r#"{"jsonrpc":"2.0","id":1,"error":{"message":"no code"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":"-32000","message":"x"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000}}"#,
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":7}}"#,
        ] {
            assert!(validate(body, &id(1)).is_err(), "{body} was accepted");
        }
    }

    #[test]
    fn a_non_object_result_is_refused() {
        for body in [
            r#"{"jsonrpc":"2.0","id":1,"result":"ok"}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":[]}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":null}"#,
        ] {
            assert!(validate(body, &id(1)).is_err(), "{body} was accepted");
        }
    }

    /// THE correlation control. Nothing in the tree compared these before, so a backend
    /// could answer any outstanding call with any other call's id and have MCP-RE sign it.
    #[test]
    fn a_response_id_that_does_not_match_the_request_is_refused() {
        for (body, outstanding) in [
            (r#"{"jsonrpc":"2.0","id":2,"result":{}}"#, id(1)),
            (r#"{"jsonrpc":"2.0","id":"1","result":{}}"#, id(1)),
            (r#"{"jsonrpc":"2.0","result":{}}"#, id(1)),
            (
                r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
                OutstandingId::Id(json!("req-1")),
            ),
        ] {
            assert!(
                validate(body, &outstanding).is_err(),
                "{body} correlated against {outstanding:?}"
            );
        }
    }

    /// A null id is a mismatch here, and the reason is worth pinning: the excuse JSON-RPC
    /// reserves null for — the responder could not determine the id — cannot arise against
    /// a body MCP-RE has already parsed and verified.
    #[test]
    fn a_null_id_does_not_correlate_to_an_id_bearing_request() {
        assert_eq!(
            validate(
                r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse"}}"#,
                &id(1),
            )
            .expect_err("null id"),
            HttpProfileError::UpstreamResponseInvalid("id does not match the outstanding request")
        );
    }

    /// String and numeric ids both correlate, by value and by type. `1` and `"1"` are
    /// different ids, which is exactly what a lenient comparison would get wrong.
    #[test]
    fn ids_correlate_by_value_and_by_type() {
        assert!(validate(
            r#"{"jsonrpc":"2.0","id":"req-abc","result":{}}"#,
            &OutstandingId::Id(json!("req-abc")),
        )
        .is_ok());
        assert!(validate(
            r#"{"jsonrpc":"2.0","id":0,"result":{}}"#,
            &OutstandingId::Id(json!(0)),
        )
        .is_ok());
    }

    #[test]
    fn a_notification_has_no_correlatable_response() {
        assert!(validate(
            r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
            &OutstandingId::Notification,
        )
        .is_err());
    }

    /// A document that is simultaneously a legal response and a legal request is refused.
    /// Every other clause passes, so nothing else in the validator would have caught it,
    /// and the PEP would have delegated-signed a server-initiated request aimed at the
    /// client.
    #[test]
    fn a_reply_that_is_also_a_request_is_refused() {
        assert_eq!(
            validate(
                r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true},"method":"tools/call"}"#,
                &id(1),
            )
            .expect_err("request-shaped response"),
            HttpProfileError::UpstreamResponseInvalid("response carries a method member")
        );
        assert_eq!(
            validate(
                r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true},"params":{"x":1}}"#,
                &id(1),
            )
            .expect_err("request-shaped response"),
            HttpProfileError::UpstreamResponseInvalid("response carries a params member")
        );
        // The same members INSIDE `result` are application payload and stay opaque.
        assert!(validate(
            r#"{"jsonrpc":"2.0","id":1,"result":{"method":"x","params":{}}}"#,
            &id(1),
        )
        .is_ok());
    }

    /// The envelope validator does NOT read application payload. Whatever is inside
    /// `result` beyond the MCP lifecycle members is carried untouched — the boundary this
    /// module is written to hold.
    #[test]
    fn arbitrary_application_payload_inside_result_is_not_inspected() {
        let body = r#"{"jsonrpc":"2.0","id":1,"result":{
            "content":[{"type":"text","text":"anything at all"}],
            "isError":true,
            "unknown_extension":{"deeply":{"nested":[1,2,3]}}
        }}"#;
        let parsed = parse_response_body(body.as_bytes()).expect("parses");
        let envelope = validate_response_envelope(&parsed, &id(1)).expect("payload is opaque");
        assert_eq!(envelope.outcome, ResponseOutcome::Result);
        // `isError: true` inside the payload is an APPLICATION-level tool failure. It is
        // not a JSON-RPC error and MCP-RE must not reinterpret it as one.
        assert!(envelope.result.unwrap().get("isError").is_some());
    }
}
