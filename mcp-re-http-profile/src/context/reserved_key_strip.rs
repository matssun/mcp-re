// SPDX-License-Identifier: Apache-2.0
//! The §10 reserved-field guard: remove the `_meta` keys the PEP owns from caller
//! input, everywhere in the body, and hand the result on as a value the write half
//! can require.
//!
//! **The descent is total.** An earlier form enumerated three positions — the top
//! level, `params._meta`, and `params[i]._meta` — which made the guard's correctness
//! a bet on which positions the deployed inner server reads. The guard now removes
//! the PEP-owned keys from EVERY `_meta` object anywhere in the body, so the bet is
//! gone: there is no position a caller can move a forged block to. Depth is bounded
//! by `serde_json`'s own nesting limit, which the body was parsed under.
//!
//! Two shapes are still refused rather than walked: a body that is not a JSON object
//! (the PEP's own write position does not exist in one) and a `params` that is
//! neither an object nor an array. Both mirror the request-envelope boundary, which
//! refuses them earlier and for free.
//!
//! The guard reports what it did rather than that it succeeded — a
//! [`SeededMetaPositions`] or an `Err`, never a bool that means both "nothing was
//! seeded" and "nothing was inspected".
//!
//! # Fidelity
//!
//! The body handed on is a RE-SERIALIZATION of the parsed body, so the guarantee
//! outside the PEP-owned keys is JSON-VALUE equality, never byte identity. Member
//! order is preserved by `serde_json`'s map, but whitespace, escaping and number
//! formatting are not the caller's. No consumer may build a check on byte
//! preservation this boundary does not provide, and in particular the forwarded
//! bytes are not the bytes the client's `Content-Digest` covered.

use serde_json::Map;
use serde_json::Value;

use crate::error::HttpProfileError;
use crate::ids::REQUEST_EVIDENCE_BLOCK_KEY;
use crate::ids::VERIFIED_CONTEXT_BLOCK_KEY;

use super::seeded_meta_positions::SeededMetaPositions;

/// A body the guard has walked: the PEP-owned keys are gone from every `_meta` in
/// it, and the attempt, if there was one, is named.
///
/// **The representation is private and [`strip_proxy_owned_meta`] is its only
/// producer**, which is what makes it the write half's precondition rather than a
/// sentence in a doc comment. [`super::insert_verified_context`] takes one of these
/// instead of `&[u8]`, so writing the PEP's conclusion into bytes no guard has seen
/// is unconstructible: delete the strip from any composer and the code stops
/// compiling rather than forwarding a body with a caller's block still in it.
#[derive(Debug, Clone)]
pub struct StrippedBody {
    body: Vec<u8>,
    seeded: SeededMetaPositions,
}

impl StrippedBody {
    /// The guarded bytes — what a `Disabled` deployment forwards unchanged.
    pub fn bytes(&self) -> &[u8] {
        &self.body
    }

    /// Which positions the caller had seeded.
    pub fn seeded(&self) -> &SeededMetaPositions {
        &self.seeded
    }

    /// Take the report, consuming the guarded body.
    pub fn into_seeded(self) -> SeededMetaPositions {
        self.seeded
    }
}

/// Strip ONLY the PEP-owned `_meta` keys from caller input (§10), leaving every
/// other entry intact.
///
/// Two keys are proxy-owned: the incoming request-evidence block (the PEP consumed
/// it; the inner server has no use for it) and the reserved verified-context key.
/// Everything else in `_meta` belongs to the application or to MCP itself and is
/// none of the enforcement boundary's business — a PEP that deletes the whole
/// `_meta` is not being careful, it is destroying data it was only asked to pass
/// through.
///
/// Called on EVERY request regardless of policy: a caller-seeded reserved field is
/// an attempted authentication bypass, and a deployment with the carrier disabled
/// must not be one config change away from forwarding it.
///
/// Only the verified-context key is REPORTED. The request-evidence block is a key
/// the caller is required to author — `crate::sign::sign_request_full` writes it
/// into the body it signs — so its presence is the ordinary case and reporting it
/// would name every legitimate request as an attempt.
///
/// # Errors
///
/// [`HttpProfileError::MalformedEvidence`] when the body is not JSON, is not a JSON
/// object, or `params` is present and is neither an object nor an array.
pub fn strip_proxy_owned_meta(body: &[u8]) -> Result<StrippedBody, HttpProfileError> {
    let mut value: Value = serde_json::from_slice(body)
        .map_err(|_| HttpProfileError::MalformedEvidence("request body is not JSON"))?;
    refuse_unwalkable_shape(&value)?;
    let mut found = Vec::new();
    strip_descendant_meta(&mut value, "", &mut found);
    let body = serde_json::to_vec(&value)
        .map_err(|_| HttpProfileError::MalformedEvidence("body reserialize"))?;
    Ok(StrippedBody {
        body,
        seeded: SeededMetaPositions::found(found),
    })
}

/// Refuse the two shapes the guard declines to walk, so neither is ever reported
/// clean.
fn refuse_unwalkable_shape(value: &Value) -> Result<(), HttpProfileError> {
    let object = value
        .as_object()
        .ok_or(HttpProfileError::MalformedEvidence(
            "request body is not a JSON object",
        ))?;
    match object.get("params") {
        None | Some(Value::Object(_)) | Some(Value::Array(_)) => Ok(()),
        Some(_) => Err(HttpProfileError::MalformedEvidence(
            "request params is neither an object nor an array",
        )),
    }
}

/// Walk one value, guarding every `_meta` object at or below it.
fn strip_descendant_meta(value: &mut Value, path: &str, found: &mut Vec<String>) {
    match value {
        Value::Object(map) => strip_object(map, path, found),
        Value::Array(elements) => strip_elements(elements, path, found),
        _ => {}
    }
}

/// Guard this object's own `_meta`, then every member below it.
fn strip_object(map: &mut Map<String, Value>, path: &str, found: &mut Vec<String>) {
    if strip_meta_of(map) {
        found.push(member_path(path, "_meta"));
    }
    for (key, child) in map.iter_mut() {
        strip_descendant_meta(child, &member_path(path, key), found);
    }
}

/// Guard every element of an array, object or not.
fn strip_elements(elements: &mut [Value], path: &str, found: &mut Vec<String>) {
    for (index, child) in elements.iter_mut().enumerate() {
        strip_descendant_meta(child, &format!("{path}[{index}]"), found);
    }
}

fn member_path(parent: &str, key: &str) -> String {
    if parent.is_empty() {
        key.to_owned()
    } else {
        format!("{parent}.{key}")
    }
}

/// Remove the PEP-owned keys from `container["_meta"]`, reporting whether the
/// reserved verified-context key had been seeded there.
///
/// `_meta` is dropped only when THIS call removed a key from it and nothing was
/// left: an `_meta` the caller sent already empty is the caller's data, and a
/// boundary that normalises it away is altering a field it documents as none of its
/// business.
///
/// A `_meta` that is not a JSON object is PROVABLY EMPTY of the reserved key rather
/// than uninspectable — JSON has no member under a name in an array or a scalar — so
/// there is nothing to remove and nothing to refuse. The descent still walks into it,
/// so an object nested beneath one is guarded like any other.
fn strip_meta_of(container: &mut Map<String, Value>) -> bool {
    let Some(meta) = container.get_mut("_meta").and_then(Value::as_object_mut) else {
        return false;
    };
    let removed_evidence = meta.remove(REQUEST_EVIDENCE_BLOCK_KEY).is_some();
    let seeded = meta.remove(VERIFIED_CONTEXT_BLOCK_KEY).is_some();
    if (removed_evidence || seeded) && meta.is_empty() {
        container.remove("_meta");
    }
    seeded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeded_meta() -> String {
        format!(
            r#"{{"{VERIFIED_CONTEXT_BLOCK_KEY}":{{"actor_id":"admin"}},"application.example/trace":"abc"}}"#
        )
    }

    fn strip(text: &str) -> StrippedBody {
        strip_proxy_owned_meta(text.as_bytes()).expect("an object body is guarded")
    }

    fn json_of(stripped: &StrippedBody) -> Value {
        serde_json::from_slice(stripped.bytes()).expect("the guarded body is json")
    }

    fn parse(text: &str) -> Value {
        serde_json::from_str(text).expect("fixture parses")
    }

    #[test]
    fn strip_removes_proxy_keys_and_preserves_application_meta() {
        let stripped = strip(&format!(
            r#"{{"jsonrpc":"2.0","_meta":{{"{VERIFIED_CONTEXT_BLOCK_KEY}":{{"actor_id":"admin"}},"{REQUEST_EVIDENCE_BLOCK_KEY}":{{"profile":"x"}},"application.example/trace":"abc","io.modelcontextprotocol/x":1}}}}"#
        ));
        assert!(stripped.seeded().any(), "the seeding attempt is reported");
        let body = json_of(&stripped);
        assert!(body["_meta"].get(VERIFIED_CONTEXT_BLOCK_KEY).is_none());
        assert!(body["_meta"].get(REQUEST_EVIDENCE_BLOCK_KEY).is_none());
        // Not the PEP's data, not the PEP's business.
        assert_eq!(
            body["_meta"]["application.example/trace"],
            serde_json::json!("abc")
        );
        assert_eq!(
            body["_meta"]["io.modelcontextprotocol/x"],
            serde_json::json!(1)
        );
        let again = strip_proxy_owned_meta(stripped.bytes()).expect("idempotent");
        assert!(!again.seeded().any(), "idempotent; nothing left to report");
    }

    #[test]
    fn a_meta_containing_only_proxy_keys_is_removed_entirely() {
        let stripped = strip(&format!(
            r#"{{"jsonrpc":"2.0","_meta":{{"{REQUEST_EVIDENCE_BLOCK_KEY}":{{"profile":"x"}}}}}}"#
        ));
        assert!(
            json_of(&stripped).get("_meta").is_none(),
            "an emptied _meta is noise the caller never sent"
        );
    }

    #[test]
    fn strip_is_noop_without_meta() {
        assert!(!strip(r#"{"jsonrpc":"2.0"}"#).seeded().any());
    }

    // ----- one negative test per guarded position -----

    #[test]
    fn the_top_level_position_is_guarded() {
        let stripped = strip(&format!(r#"{{"jsonrpc":"2.0","_meta":{}}}"#, seeded_meta()));
        assert!(json_of(&stripped)["_meta"]
            .get(VERIFIED_CONTEXT_BLOCK_KEY)
            .is_none());
        assert!(
            stripped.seeded().top_level(),
            "the position is named, not just counted"
        );
        assert_eq!(stripped.seeded().positions(), vec!["_meta".to_owned()]);
    }

    /// The `params._meta` position — the hole that stripping only the top level left
    /// open. An inner server reading the reserved key from here sees the same thing.
    #[test]
    fn the_params_object_position_is_guarded() {
        let stripped = strip(&format!(
            r#"{{"jsonrpc":"2.0","params":{{"name":"read","_meta":{}}}}}"#,
            seeded_meta()
        ));
        assert!(json_of(&stripped)["params"]["_meta"]
            .get(VERIFIED_CONTEXT_BLOCK_KEY)
            .is_none());
        assert!(stripped.seeded().params_object());
        assert_eq!(
            stripped.seeded().positions(),
            vec!["params._meta".to_owned()]
        );
    }

    /// A POSITIONAL `params` (JSON-RPC 2.0 §4.2) — every object element is guarded,
    /// and the seeded positions are reported by index.
    #[test]
    fn every_positional_params_element_is_guarded() {
        let stripped = strip(&format!(
            r#"{{"jsonrpc":"2.0","params":[{{"_meta":{m}}},"scalar",{{"_meta":{m}}}]}}"#,
            m = seeded_meta()
        ));
        let body = json_of(&stripped);
        for index in [0usize, 2] {
            assert!(
                body["params"][index]["_meta"]
                    .get(VERIFIED_CONTEXT_BLOCK_KEY)
                    .is_none(),
                "element {index} kept a caller-authored verified context"
            );
        }
        assert_eq!(
            stripped.seeded().positions(),
            vec!["params[0]._meta".to_owned(), "params[2]._meta".to_owned()]
        );
    }

    /// The descent is TOTAL: a position below the three an inner server is usually
    /// said to read is guarded too, and named, rather than walked past and reported
    /// clean.
    #[test]
    fn a_nested_position_below_params_is_guarded_and_named() {
        let stripped = strip(&format!(
            r#"{{"jsonrpc":"2.0","params":{{"arguments":{{"_meta":{m}}},"rows":[[{{"_meta":{m}}}]]}}}}"#,
            m = seeded_meta()
        ));
        let body = json_of(&stripped);
        assert!(body["params"]["arguments"]["_meta"]
            .get(VERIFIED_CONTEXT_BLOCK_KEY)
            .is_none());
        assert!(body["params"]["rows"][0][0]["_meta"]
            .get(VERIFIED_CONTEXT_BLOCK_KEY)
            .is_none());
        assert_eq!(
            stripped.seeded().positions(),
            vec![
                "params.arguments._meta".to_owned(),
                "params.rows[0][0]._meta".to_owned()
            ]
        );
    }

    /// All positions at once: the report names each rather than collapsing them into
    /// one bit.
    #[test]
    fn every_seeded_position_is_named_at_once() {
        let stripped = strip(&format!(
            r#"{{"jsonrpc":"2.0","_meta":{m},"params":[{{"_meta":{m}}}]}}"#,
            m = seeded_meta()
        ));
        assert_eq!(stripped.seeded().to_string(), "_meta, params[0]._meta");
    }

    // ----- shapes the guard refuses rather than reporting clean -----

    #[test]
    fn a_body_that_is_not_a_json_object_is_refused() {
        // A JSON-RPC batch is a top-level ARRAY, and the PEP's own write position
        // does not exist in one, so the body is refused rather than walked.
        let batch = format!(r#"[{{"jsonrpc":"2.0","_meta":{}}}]"#, seeded_meta());
        assert!(strip_proxy_owned_meta(batch.as_bytes()).is_err());
        assert!(strip_proxy_owned_meta(b"7").is_err());
        assert!(strip_proxy_owned_meta(br#""text""#).is_err());
        assert!(strip_proxy_owned_meta(b"not json").is_err());
    }

    #[test]
    fn a_params_that_is_neither_an_object_nor_an_array_is_refused() {
        assert!(strip_proxy_owned_meta(br#"{"jsonrpc":"2.0","params":"positional"}"#).is_err());
    }

    // ----- fidelity -----

    /// POSITIVE CONTROL for the drop rule: an `_meta` the CALLER sent empty is the
    /// caller's data and survives, because this call removed nothing from it.
    #[test]
    fn a_callers_own_empty_meta_survives() {
        let stripped = strip(r#"{"jsonrpc":"2.0","_meta":{},"params":{"_meta":{}}}"#);
        assert!(!stripped.seeded().any());
        let body = json_of(&stripped);
        assert!(
            body.get("_meta").is_some(),
            "an empty `_meta` the PEP never touched is not the PEP's to delete"
        );
        assert!(body["params"].get("_meta").is_some());
    }

    /// POSITIVE CONTROL for the shape rules: an ordinary body carrying a legitimate
    /// application `params._meta` entry passes through with its JSON value unchanged.
    #[test]
    fn an_ordinary_application_body_passes_through_untouched() {
        let text = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read","_meta":{"app.trace":"t-1"}}}"#;
        let stripped = strip(text);
        assert!(!stripped.seeded().any());
        assert_eq!(
            json_of(&stripped),
            parse(text),
            "nothing the PEP does not own was touched"
        );
    }

    /// A `_meta` that is not an object cannot hold a member under the reserved NAME.
    #[test]
    fn a_non_object_meta_carries_no_reserved_key_and_is_left_alone() {
        let text = r#"{"jsonrpc":"2.0","_meta":[1,2]}"#;
        let stripped = strip(text);
        assert!(!stripped.seeded().any());
        assert_eq!(json_of(&stripped), parse(text));
    }

    /// The distinction the tolerance rests on: a non-object `_meta` is
    /// PROVABLY EMPTY of the reserved key, not uninspectable — and the descent still
    /// reaches an object nested inside one.
    #[test]
    fn a_non_object_meta_is_provably_empty_not_uninspectable() {
        let stripped = strip(&format!(
            r#"{{"jsonrpc":"2.0","_meta":[{{"_meta":{}}}]}}"#,
            seeded_meta()
        ));
        assert_eq!(
            stripped.seeded().positions(),
            vec!["_meta[0]._meta".to_owned()],
            "a position inside a non-object `_meta` is still walked"
        );
    }

    /// The caller-authored request-evidence block is REMOVED and NOT reported: the
    /// client is required to author it (`sign_request_full` writes it into the body
    /// it signs), so naming it would name every legitimate request as an attempt.
    #[test]
    fn the_consumed_request_evidence_block_is_removed_without_being_reported() {
        let stripped = strip(&format!(
            r#"{{"jsonrpc":"2.0","_meta":{{"{REQUEST_EVIDENCE_BLOCK_KEY}":{{"profile":"x"}},"app.keep":1}}}}"#
        ));
        let body = json_of(&stripped);
        assert!(body["_meta"].get(REQUEST_EVIDENCE_BLOCK_KEY).is_none());
        assert_eq!(body["_meta"]["app.keep"], serde_json::json!(1));
        assert!(
            !stripped.seeded().any(),
            "the evidence block is the ordinary case, not an attempted bypass"
        );
    }
}
