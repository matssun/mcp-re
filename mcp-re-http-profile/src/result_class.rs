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

/// The `result.resultType` value marking a terminal result (MCP 2026-07-28).
pub const COMPLETE_RESULT_TYPE: &str = "complete";

/// How a VERIFIED `result` member classifies under the MCP 2026-07-28 `resultType`
/// rules.
///
/// The specification names exactly two values, permits extensions to add more
/// *that the client has advertised support for*, and then closes the set: "a
/// `resultType` of any value unrecognized by the client MUST be considered
/// invalid". MCP-RE advertises no extension result types, so its recognized set is
/// the core one.
///
/// [`Unrecognized`](ResultTypeClass::Unrecognized) is a third outcome rather than a
/// flavour of terminal because those are different facts. "This call finished" and
/// "I cannot tell whether this call finished" must not reach a reader as the same
/// answer: an extension's non-terminal result read as terminal ends the exchange,
/// consumes the correlation entry, and hands a continuation up as a completed
/// result — the failure [`input_required_state`] already refuses for a message that
/// withholds its state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultTypeClass {
    /// A terminal result: explicit `complete`, or absent, which the specification
    /// requires clients to read as complete for compatibility with revisions that
    /// predate the field.
    Complete,
    /// An `InputRequiredResult` — a non-terminal leg awaiting continuation.
    InputRequired,
    /// A `resultType` this reader does not recognize. Never resolved to a class;
    /// every reader that acts on it fails closed.
    Unrecognized,
}

/// Classify a (verified) `result` member's `resultType`.
///
/// A response with no `result` member at all is not a result response — a JSON-RPC
/// error carries `error` instead — so it classifies as [`Complete`]: the exchange
/// ends, and nothing continues from it.
///
/// [`Complete`]: ResultTypeClass::Complete
pub fn classify_result_type(result: Option<&Value>) -> ResultTypeClass {
    let Some(result) = result else {
        return ResultTypeClass::Complete;
    };
    match result.get("resultType") {
        None => ResultTypeClass::Complete,
        Some(Value::String(t)) if t == INPUT_REQUIRED_RESULT_TYPE => ResultTypeClass::InputRequired,
        Some(Value::String(t)) if t == COMPLETE_RESULT_TYPE => ResultTypeClass::Complete,
        // A non-string `resultType` is unrecognized rather than malformed: either
        // way this reader cannot classify the message, and the two would be the
        // same refusal.
        Some(_) => ResultTypeClass::Unrecognized,
    }
}

/// Whether a (verified) `result` member is an `InputRequiredResult`.
///
/// A boolean cannot carry the third outcome, so this answers only the question it
/// is named for. Readers that must distinguish "terminal" from "unclassifiable"
/// call [`classify_result_type`]; readers acting on a live exchange call
/// [`input_required_state`], which fails closed on both middle grounds.
pub fn is_input_required(result: Option<&Value>) -> bool {
    classify_result_type(result) == ResultTypeClass::InputRequired
}

/// The continuation state a VERIFIED response body carries: `Some(state)` for an
/// `InputRequiredResult`, `None` for a terminal reply — and an error for anything
/// this reader cannot safely resolve to either.
///
/// The outcomes are kept distinct on purpose. Every open-coded copy of this walk
/// collapsed the error case into `None` via `.ok()?` and `?` on missing members, so
/// a reply that announced itself as `input_required` but carried no usable
/// `requestState` — or a body that would not parse at all — was read as a perfectly
/// ordinary terminal answer. On the client side that consumed the open leg's
/// correlation entry, never fired the input-required callback, never signed an
/// answer leg, and handed an elicitation to the application as a completed tool
/// result.
///
/// Two shapes are refused rather than resolved:
///
/// - a message declaring itself non-terminal while withholding the state its
///   continuation needs — malformed, and the only safe reading is to say so;
/// - a `resultType` this reader does not recognize (MCP 2026-07-28: unrecognized
///   MUST be considered invalid). Reading it as terminal would end the exchange on
///   a message whose continuation semantics are unknown — the same silent
///   completion, arrived at from the other direction.
///
/// Call ONLY on bytes whose signature and `content-digest` have already verified:
/// this reads protected content, it does not establish it.
pub fn input_required_state(body: &[u8]) -> Result<Option<String>, HttpProfileError> {
    let parsed: Value = serde_json::from_slice(body)
        .map_err(|_| HttpProfileError::MalformedEvidence("response body"))?;
    let result = parsed.get("result");
    match classify_result_type(result) {
        ResultTypeClass::Complete => Ok(None),
        ResultTypeClass::Unrecognized => Err(HttpProfileError::UnrecognizedResultType),
        ResultTypeClass::InputRequired => {
            let state = result
                .and_then(|r| r.get("requestState"))
                .and_then(|s| s.as_str())
                .ok_or(HttpProfileError::MalformedEvidence(
                    "input_required requestState",
                ))?;
            Ok(Some(state.to_owned()))
        }
    }
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

    /// A neighbouring `resultType` value is NOT the discriminator — matching is
    /// exact, not a prefix or a substring — and it is not terminal either. It is
    /// unrecognized, and MCP 2026-07-28 requires that be treated as invalid.
    ///
    /// The near-misses matter most here: `Input_Required` differs from the real
    /// discriminator by case alone, and reading it as a completed call is exactly
    /// the silent completion this module exists to prevent.
    #[test]
    fn a_near_miss_discriminator_is_refused_not_read_as_terminal() {
        for other in [
            r#"{"result":{"resultType":"input_required_extra","requestState":"s"}}"#,
            r#"{"result":{"resultType":"Input_Required","requestState":"s"}}"#,
            r#"{"result":{"resultType":"","requestState":"s"}}"#,
            r#"{"result":{"resultType":"inputRequired","requestState":"s"}}"#,
        ] {
            let err = input_required_state(&body(other))
                .expect_err("an unrecognized resultType is invalid, not terminal");
            assert_eq!(
                err,
                HttpProfileError::UnrecognizedResultType,
                "{other} must not be reported as a terminal reply"
            );
        }
    }

    /// The two values the core protocol defines, plus the compatibility rule for
    /// the revisions that predate the field.
    #[test]
    fn the_recognized_set_is_complete_input_required_and_absent() {
        let complete = serde_json::json!({ "resultType": "complete" });
        assert_eq!(
            classify_result_type(Some(&complete)),
            ResultTypeClass::Complete
        );

        let input_required = serde_json::json!({ "resultType": "input_required" });
        assert_eq!(
            classify_result_type(Some(&input_required)),
            ResultTypeClass::InputRequired
        );

        // Absent is complete: MCP 2026-07-28 requires clients to read it that way
        // for compatibility with servers on earlier revisions.
        let absent = serde_json::json!({ "ok": true });
        assert_eq!(
            classify_result_type(Some(&absent)),
            ResultTypeClass::Complete
        );
        assert_eq!(classify_result_type(None), ResultTypeClass::Complete);
    }

    /// An extension result type is unrecognized until this implementation
    /// advertises support for it. The specification permits extensions to add
    /// values, and closes the set to what the client actually supports — so
    /// accepting one we never advertised would be accepting a contract we cannot
    /// honour.
    #[test]
    fn an_unadvertised_extension_result_type_is_unrecognized() {
        for t in ["com.example/deferred", "partial", "streaming"] {
            let v = serde_json::json!({ "resultType": t });
            assert_eq!(
                classify_result_type(Some(&v)),
                ResultTypeClass::Unrecognized,
                "{t} was never advertised, so it cannot be classified"
            );
        }
    }

    /// A non-string `resultType` cannot be classified either, and it must not slip
    /// through the string comparison as "not the discriminator, therefore
    /// terminal".
    #[test]
    fn a_non_string_result_type_is_unrecognized() {
        for v in [
            serde_json::json!({ "resultType": 1 }),
            serde_json::json!({ "resultType": null }),
            serde_json::json!({ "resultType": ["input_required"] }),
            serde_json::json!({ "resultType": { "value": "complete" } }),
        ] {
            assert_eq!(
                classify_result_type(Some(&v)),
                ResultTypeClass::Unrecognized,
                "{v} is not a recognized result type"
            );
        }
    }

    /// The negative control for the whole change: if `Unrecognized` were folded
    /// back into `Complete`, an extension's non-terminal result would reach a
    /// caller as a finished call. `is_input_required` says false for it — which is
    /// true and insufficient — so nothing may infer "terminal" from that alone.
    #[test]
    fn is_input_required_is_false_for_unrecognized_but_that_is_not_terminal() {
        let ext = serde_json::json!({ "resultType": "com.example/needs_more" });
        assert!(!is_input_required(Some(&ext)));
        assert_eq!(
            classify_result_type(Some(&ext)),
            ResultTypeClass::Unrecognized
        );
        assert_eq!(
            input_required_state(br#"{"result":{"resultType":"com.example/needs_more"}}"#)
                .expect_err("a live reader must refuse it"),
            HttpProfileError::UnrecognizedResultType
        );
    }
}
