// SPDX-License-Identifier: Apache-2.0
//! What the backend's reply IS, before anything signs it.
//!
//! One fact: **the bytes the inner plane produced are read once, by this owner, and every
//! later authority is told what they are rather than re-reading them.** Two questions make
//! that up, and both must be answered before the enforcement boundary puts its signature on
//! the message:
//!
//! 1. is this a legal JSON-RPC control envelope, correlated to the request this exchange
//!    opened? — [`ValidatedReply::of`]
//! 2. which MCP lifecycle transition is it? — [`ValidatedReply::classify`]
//!
//! They are separate questions and the separation is the point: a perfectly well-formed
//! JSON-RPC response can still be one whose MCP meaning this reader cannot determine. Both
//! refuse with 502 and neither refusal is free — reaching here means the backend has
//! already acted.
//!
//! Validation stops at the control envelope. Everything inside `result` beyond the MCP
//! lifecycle members is application data that MCP-RE carries and signs without reading.
//!
//! The parse happens once. `classify` is a method on the validated value rather than a
//! function over bytes, so no second reader can walk the same JSON and reach its own
//! conclusion — which is exactly the disagreement the request side already eliminated by
//! deciding its `OutstandingId` once.

use mcp_re_http_profile::parse_response_body;
use mcp_re_http_profile::result_class::classify_result_type;
use mcp_re_http_profile::result_class::input_required_state_of;
use mcp_re_http_profile::result_class::ResultTypeClass;
use mcp_re_http_profile::validate_response_envelope;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::OutstandingId;

use crate::refusal::Refusal;

/// A reply whose JSON-RPC control envelope is legal and correlated to this exchange.
///
/// Private representation, one producer: holding one means syntax, `jsonrpc`, `id`
/// correlation and `result` XOR `error` all hold. There is no way to name the parsed body
/// without having asked that question, so signing bytes nobody validated is not a step the
/// assembly can forget — it is unconstructible.
pub(super) struct ValidatedReply {
    parsed: serde_json::Value,
}

impl ValidatedReply {
    /// RESPONSE-VALIDATED — the JSON-RPC control envelope must be legal before anything
    /// treats these bytes as a response.
    ///
    /// ```text
    /// ensures   Ok  => syntax, `jsonrpc`, `id` correlation and `result` XOR `error` all hold
    ///           Err => 502, bound
    /// refusal   NOT free — the action already ran
    /// ```
    ///
    /// Unconditional, which is the whole change (ADR-MCPRE-058 ruling D2). This used to
    /// happen only inside the MRTR open-leg recorder, so whether MCP-RE refused a malformed
    /// protocol response depended on whether an operator had wired Redis — a capability with
    /// no relationship to protocol legality. A deployment without it signed unparseable
    /// bodies as opaque payload and the client's own verifier then rejected a message the
    /// enforcement boundary had vouched for.
    pub(super) fn of(
        response: &HttpResponse,
        outstanding: &OutstandingId,
    ) -> Result<Self, Refusal> {
        let parsed = parse_response_body(&response.body).map_err(|e| match e {
            HttpProfileError::UpstreamResponseInvalid(clause) => invalid(clause),
            _ => invalid("response body"),
        })?;
        match validate_response_envelope(&parsed, outstanding) {
            Ok(_) => Ok(ValidatedReply { parsed }),
            Err(HttpProfileError::UpstreamResponseInvalid(clause)) => Err(invalid(clause)),
            Err(e) => Err(Refusal::after_admission(e, 502)),
        }
    }

    /// RESPONSE-CLASSIFIED — which MCP lifecycle transition is this reply?
    ///
    /// ```text
    /// ensures   Ok  => the reply is a terminal answer, or an open leg with usable state
    ///           Err => 502, bound
    /// refusal   NOT free — the action already ran
    /// ```
    ///
    /// MCP 2026-07-28 closes the `resultType` set and requires an unrecognized one be
    /// considered invalid — signing it anyway would produce a verifiable message whose
    /// continuation semantics nobody can read, and a client failing closed on it would be
    /// told the PEP had vouched for it.
    ///
    /// A JSON-RPC error classifies as [`ReplyClass::Terminal`]: it is a legal terminal
    /// protocol response, not a malformed one and not a transport failure.
    pub(super) fn classify(&self) -> Result<ReplyClass, Refusal> {
        let result = self.parsed.get("result");
        match classify_result_type(result) {
            ResultTypeClass::Complete => Ok(ReplyClass::Terminal),
            ResultTypeClass::Unrecognized => Err(Refusal::after_admission(
                HttpProfileError::UnrecognizedResultType,
                502,
            )),
            ResultTypeClass::InputRequired => match input_required_state_of(result) {
                Ok(Some(state)) => Ok(ReplyClass::Open(state)),
                // Classified as non-terminal and then failed to yield its state: the two
                // arms cannot both be right, and the only safe reading is that the message
                // is invalid.
                _ => Err(Refusal::after_admission(
                    HttpProfileError::UpstreamResponseInvalid("input_required requestState"),
                    502,
                )),
            },
        }
    }
}

/// An illegal upstream response, at the one status the whole file refuses under.
///
/// A bad gateway is what every arm here means: the enforcement boundary is intact and the
/// message behind it is not.
fn invalid(clause: &'static str) -> Refusal {
    Refusal::after_admission(HttpProfileError::UpstreamResponseInvalid(clause), 502)
}

/// Which MCP lifecycle transition a validated reply is.
///
/// Carries the `requestState` for an open leg because the classifier is the only place that
/// reads it out of the body, and passing the body along instead would invite a second reader
/// to walk the same JSON and reach its own conclusion.
///
/// A JSON-RPC error is [`Terminal`](ReplyClass::Terminal): a legal terminal protocol
/// response, distinct from a malformed one and from a transport failure.
pub(super) enum ReplyClass {
    /// The exchange ends here — an ordinary result, or a JSON-RPC error.
    Terminal,
    /// An `InputRequiredResult`. The state is the one an answer leg re-presents.
    Open(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(body: &str) -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn a_jsonrpc_error_is_a_terminal_answer_and_not_a_malformed_one() {
        // The distinction the whole enum exists for. An error reply is a legal terminal
        // protocol response: the backend answered, and the exchange ends. Treating it as
        // invalid would refuse a conformant message at 502.
        let validated = ValidatedReply::of(
            &reply(r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"bad params"}}"#),
            &OutstandingId::Id(serde_json::json!(1)),
        )
        .expect("an error reply is a legal envelope");
        assert!(matches!(
            validated.classify().expect("and a legal classification"),
            ReplyClass::Terminal
        ));
    }

    #[test]
    fn an_uncorrelated_reply_is_refused_before_anything_signs_it() {
        // `id` correlation is part of the envelope question, so a reply to some OTHER
        // request never reaches the classifier — let alone the signer.
        assert!(ValidatedReply::of(
            &reply(r#"{"jsonrpc":"2.0","id":99,"result":{}}"#),
            &OutstandingId::Id(serde_json::json!(1)),
        )
        .is_err());
    }

    #[test]
    fn an_open_leg_yields_the_state_its_answer_re_presents() {
        let validated = ValidatedReply::of(
            &reply(
                r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"input_required","requestState":"s-1"}}"#,
            ),
            &OutstandingId::Id(serde_json::json!(1)),
        )
        .expect("a legal envelope");
        match validated.classify().expect("a legal classification") {
            ReplyClass::Open(state) => assert_eq!(state, "s-1"),
            ReplyClass::Terminal => panic!("an input_required reply opens a leg"),
        }
    }

    #[test]
    fn an_unrecognized_result_type_is_never_signed() {
        // MCP 2026-07-28 closes the set. Signing an unreadable transition would hand the
        // client a verifiable message whose continuation semantics nobody can read.
        let validated = ValidatedReply::of(
            &reply(r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"something_new"}}"#),
            &OutstandingId::Id(serde_json::json!(1)),
        )
        .expect("a legal envelope");
        assert!(validated.classify().is_err());
    }
}
