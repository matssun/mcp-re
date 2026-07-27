// SPDX-License-Identifier: Apache-2.0
//! The SEP-2322 / ADR-MCPS-047 result discriminator — ONE copy.
//!
//! Whether a verified reply is terminal or a non-terminal `InputRequiredResult`
//! decides what happens to the exchange: a terminal reply closes the correlation
//! entry and is handed to the application, while an `InputRequiredResult` must keep
//! that entry open and surface the continuation state its answer leg has to sign
//! over. Getting it wrong in the terminal direction does not fail loudly — it hands
//! an elicitation to the caller as if it were a completed tool result.
//!
//! That is why this lives in the lowest crate every reader shares. The
//! discriminator had been open-coded four times — the client core, chain
//! reconstruction, the proxy's open-leg recorder, and both SDK bindings — and each
//! copy walked the JSON its own way. Only the client-core copy was covered by the
//! SEP-2322 drift guard, so a rename in the final text would have failed the guard
//! while leaving the other readers silently classifying every continuation as
//! terminal: exactly the outcome the guard exists to prevent.
//!
//! Every reader that must not be wrong about this classifies through here.

use crate::error::HttpProfileError;
use serde_json::Value;

/// The `result.resultType` value marking a non-terminal leg (ADR-MCPS-047).
///
/// The drift guard pins this constant, so the guard now covers every reader rather
/// than the one that happened to import the helper.
pub const INPUT_REQUIRED_RESULT_TYPE: &str = "input_required";

/// Whether a (verified) `result` member is an `InputRequiredResult`.
///
/// Anything that is not the discriminator is terminal. That direction is the
/// conservative one for readers that reconstruct a record: mislabeling a terminal
/// answer as non-terminal makes a complete chain look truncated, which is a false
/// alarm, whereas the reverse would let a truncated chain pass as complete.
///
/// Readers that act on a live exchange want more than this — see
/// [`input_required_state`], which refuses the malformed middle ground instead of
/// resolving it to "terminal".
pub fn is_input_required(result: Option<&Value>) -> bool {
    result
        .and_then(|r| r.get("resultType"))
        .and_then(|t| t.as_str())
        == Some(INPUT_REQUIRED_RESULT_TYPE)
}

/// The continuation state a VERIFIED response body carries: `Some(state)` for an
/// `InputRequiredResult`, `None` for a terminal reply — and an error for a body
/// that is neither.
///
/// The three outcomes are kept distinct on purpose. Every open-coded copy of this
/// walk collapsed the error case into `None` via `.ok()?` and `?` on missing
/// members, so a reply that announced itself as `input_required` but carried no
/// usable `requestState` — or a body that would not parse at all — was read as a
/// perfectly ordinary terminal answer. On the client side that consumed the open
/// leg's correlation entry, never fired the input-required callback, never signed
/// an answer leg, and handed an elicitation to the application as a completed tool
/// result. A message that declares itself non-terminal and then withholds the state
/// its continuation needs is malformed, and the only safe reading of it is to say
/// so.
///
/// Call ONLY on bytes whose signature and `content-digest` have already verified:
/// this reads protected content, it does not establish it.
pub fn input_required_state(body: &[u8]) -> Result<Option<String>, HttpProfileError> {
    let parsed: Value = serde_json::from_slice(body)
        .map_err(|_| HttpProfileError::MalformedEvidence("response body"))?;
    let result = parsed.get("result");
    if !is_input_required(result) {
        return Ok(None);
    }
    let state = result
        .and_then(|r| r.get("requestState"))
        .and_then(|s| s.as_str())
        .ok_or(HttpProfileError::MalformedEvidence(
            "input_required requestState",
        ))?;
    Ok(Some(state.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    #[test]
    fn a_terminal_reply_has_no_continuation_state() {
        let b = body(r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#);
        assert_eq!(input_required_state(&b).expect("well-formed"), None);
    }

    #[test]
    fn an_input_required_reply_yields_its_state() {
        let b = body(
            r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"input_required","requestState":"s-1"}}"#,
        );
        assert_eq!(
            input_required_state(&b).expect("well-formed"),
            Some("s-1".to_owned())
        );
    }

    /// THE fail-closed case. Every open-coded copy returned `None` here, which
    /// every caller reads as "terminal" — so a non-terminal leg was silently
    /// completed.
    #[test]
    fn input_required_without_a_usable_state_is_refused_not_read_as_terminal() {
        for missing in [
            r#"{"result":{"resultType":"input_required"}}"#,
            r#"{"result":{"resultType":"input_required","requestState":null}}"#,
            r#"{"result":{"resultType":"input_required","requestState":42}}"#,
            r#"{"result":{"resultType":"input_required","requestState":{"a":1}}}"#,
        ] {
            let err = input_required_state(&body(missing))
                .expect_err("a non-terminal leg with no usable state is malformed");
            assert_eq!(
                err,
                HttpProfileError::MalformedEvidence("input_required requestState"),
                "{missing} must not be reported as a terminal reply"
            );
        }
    }

    #[test]
    fn an_unparseable_body_is_refused_not_read_as_terminal() {
        let err = input_required_state(b"not json").expect_err("unparseable");
        assert_eq!(err, HttpProfileError::MalformedEvidence("response body"));
    }

    #[test]
    fn a_body_with_no_result_member_is_terminal() {
        let b = body(r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000}}"#);
        assert_eq!(input_required_state(&b).expect("well-formed"), None);
    }

    /// A neighbouring `resultType` value is terminal — the discriminator is an
    /// exact match, not a prefix or a substring.
    #[test]
    fn only_the_exact_discriminator_is_non_terminal() {
        for other in [
            r#"{"result":{"resultType":"input_required_extra","requestState":"s"}}"#,
            r#"{"result":{"resultType":"Input_Required","requestState":"s"}}"#,
            r#"{"result":{"resultType":"","requestState":"s"}}"#,
        ] {
            assert_eq!(
                input_required_state(&body(other)).expect("well-formed"),
                None,
                "{other} is not the discriminator"
            );
        }
    }
}
