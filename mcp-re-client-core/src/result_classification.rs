// SPDX-License-Identifier: Apache-2.0
//! What an MCP result MEANS — as distinct from whether the message carrying it is genuine.
//!
//! EX-009's disposition. `response.rs` verifies signatures; this answers a different
//! question about the same bytes, and it says nothing about whether anything is signed.
//! The separation matters because the two have different inputs: verification consumes the
//! whole HTTP message and its evidence, while classification consumes a `result` member and
//! nothing else.
//!
//! # One discriminator, in the crate below
//!
//! This is the typed client-side FACE of `mcp_re_http_profile::result_class`, not a second
//! copy of it. The `input_required` string lives in the lower crate every reader shares, so
//! the SEP-2322 drift guard that pins it covers the proxy, chain reconstruction and both
//! SDK bindings at the same time. A rename in the final spec text fails one test rather
//! than leaving five readers silently classifying continuations as terminal.
//!
//! # Two seams, and the reason there are two
//!
//! [`classify_result`] REPORTS what a verified body says, including
//! [`ResultClass::Unrecognized`] — a caller inspecting a record may legitimately want to
//! see it. [`continuation_state`] REFUSES it, because a caller acting on a LIVE exchange
//! must not treat a reply whose meaning it cannot determine as terminal. Each SDK binding
//! used to open-code the JSON walk and collapse the malformed case to `None`, which their
//! transports read as terminal: the open leg's correlation entry was consumed, the
//! input-required callback never fired, no answer leg was signed, and an elicitation
//! reached the application as a completed tool result.

use mcp_re_http_profile::HttpProfileError;
use serde_json::Value;

/// The MCP-RE round-trip classification of a verified response body
/// (ADR-MCPS-047). Read ONLY from the signed, verified body — never from
/// untrusted bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultClass {
    /// An ordinary terminal result.
    Terminal,
    /// An `InputRequiredResult` — a non-terminal leg awaiting client continuation.
    InputRequired,
    /// A `resultType` this client does not recognize. MCP 2026-07-28 requires it
    /// be considered invalid, so it is never resolved to [`Terminal`]: a caller
    /// that acts on the exchange must refuse it.
    ///
    /// [`Terminal`]: ResultClass::Terminal
    Unrecognized,
}

/// Classify a (verified) `result` body through the profile's single discriminator
/// ([`mcp_re_http_profile::result_class`], ADR-MCPS-047). An absent `resultType` is
/// terminal, as MCP 2026-07-28 requires of clients; an unrecognized one is
/// [`ResultClass::Unrecognized`], never terminal.
///
/// This is the typed client-side face of that one classifier, not a second copy of
/// it: the discriminator string lives in the lower crate every reader shares, so
/// the SEP-2322 drift guard that pins this function covers the proxy, chain
/// reconstruction and both SDK bindings too.
pub fn classify_result(result: Option<&Value>) -> ResultClass {
    use mcp_re_http_profile::result_class::ResultTypeClass;
    match mcp_re_http_profile::result_class::classify_result_type(result) {
        ResultTypeClass::InputRequired => ResultClass::InputRequired,
        ResultTypeClass::Complete => ResultClass::Terminal,
        ResultTypeClass::Unrecognized => ResultClass::Unrecognized,
    }
}

/// The continuation state a VERIFIED response carries, for callers that must act
/// on a live exchange rather than reconstruct a record: `Some(state)` for an
/// `InputRequiredResult`, `None` for a terminal reply, and an ERROR for a reply
/// that announces itself non-terminal without a usable `requestState`.
///
/// This is what the SDK bindings call. Each of them used to open-code the JSON walk
/// and collapse the malformed case to `None`, which their transports read as
/// terminal: the open leg's correlation entry was consumed, the input-required
/// callback never fired, no answer leg was ever signed, and an elicitation was
/// handed to the application as a completed tool result. See
/// [`mcp_re_http_profile::result_class::input_required_state`] for the three-way
/// contract.
pub fn continuation_state(body: &[u8]) -> Result<Option<String>, HttpProfileError> {
    mcp_re_http_profile::result_class::input_required_state(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_result_type_is_terminal_as_the_spec_requires_of_clients() {
        assert_eq!(
            classify_result(Some(&serde_json::json!({}))),
            ResultClass::Terminal
        );
        assert_eq!(classify_result(None), ResultClass::Terminal);
    }

    #[test]
    fn an_unrecognized_result_type_is_never_terminal() {
        // The distinction the enum exists for. A newer server's transition is reported as
        // unreadable rather than silently treated as an answer.
        assert_eq!(
            classify_result(Some(&serde_json::json!({"resultType": "something_new"}))),
            ResultClass::Unrecognized
        );
    }

    #[test]
    fn the_live_seam_refuses_what_the_reporting_seam_merely_names() {
        // Two seams, two contracts. A reply that announces itself non-terminal without a
        // usable `requestState` is an ERROR here — collapsing it to `None` is what handed
        // an elicitation to an application as a completed tool result.
        // The discriminator comes from the canonical constant, never a literal: this file
        // must not become the sixth copy the drift guard was written for.
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "resultType": mcp_re_http_profile::result_class::INPUT_REQUIRED_RESULT_TYPE,
            },
        })
        .to_string();
        assert!(continuation_state(body.as_bytes()).is_err());
        let terminal = br#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
        assert_eq!(
            continuation_state(terminal).expect("terminal is legal"),
            None
        );
    }
}
