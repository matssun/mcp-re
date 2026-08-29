// SPDX-License-Identifier: Apache-2.0
//! JSON-RPC body carriage for the HTTP-profile evidence blocks (MCPRE-101).
//!
//! No new HTTP header fields are minted (v0.11 grill E-3): the MCP-specific
//! evidence blocks ride in the JSON-RPC body under a top-level `_meta` object,
//! keyed by the block id (`se.syncom/mcp-re.http.request` /
//! `.response`). They are protected because `content-digest` is a covered
//! component of the RFC 9421 signature — the signer composes the block into the
//! body BEFORE digesting, so the transmitted bytes the verifier digests are the
//! exact bytes it parses the block from. No canonicalization is required.

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;

use crate::error::HttpProfileError;

const META_KEY: &str = "_meta";

/// Which JSON this profile can carry through its own re-serialization unchanged.
mod representable;
pub use representable::reject_unrepresentable_json;

/// Insert `block` under top-level `_meta[key]` and return the re-serialized body
/// bytes. The body MUST be a JSON object (a JSON-RPC message); an existing
/// `_meta` object is preserved and extended.
///
/// A body carrying a value the round trip would alter is REFUSED rather than
/// silently rewritten — see [`reject_unrepresentable_json`].
pub fn insert_meta_block<T: Serialize>(
    body: &[u8],
    key: &str,
    block: &T,
) -> Result<Vec<u8>, HttpProfileError> {
    let mut root: Value = serde_json::from_slice(body)
        .map_err(|_| HttpProfileError::MalformedEvidence("body json"))?;
    reject_unrepresentable_json(body)?;
    let obj = root
        .as_object_mut()
        .ok_or(HttpProfileError::MalformedEvidence(
            "body not a json object",
        ))?;
    let meta = obj
        .entry(META_KEY)
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    let meta_obj = meta
        .as_object_mut()
        .ok_or(HttpProfileError::MalformedEvidence("_meta not an object"))?;
    let value = serde_json::to_value(block)
        .map_err(|_| HttpProfileError::MalformedEvidence("block serialize"))?;
    meta_obj.insert(key.to_owned(), value);
    serde_json::to_vec(&root).map_err(|_| HttpProfileError::MalformedEvidence("body reserialize"))
}

/// Extract and strictly deserialize the block at top-level `_meta[key]`. An
/// absent block is [`HttpProfileError::MissingEvidence`] (`what` names it); a
/// present-but-malformed block is [`HttpProfileError::MalformedEvidence`]. The
/// block types use `deny_unknown_fields`, so a foreign field fails closed.
pub fn extract_meta_block<T: DeserializeOwned>(
    body: &[u8],
    key: &str,
    what: &'static str,
) -> Result<T, HttpProfileError> {
    let root: Value = serde_json::from_slice(body)
        .map_err(|_| HttpProfileError::MalformedEvidence("body json"))?;
    let block = root
        .get(META_KEY)
        .and_then(|m| m.get(key))
        .ok_or(HttpProfileError::MissingEvidence(what))?;
    serde_json::from_value(block.clone()).map_err(|_| HttpProfileError::MalformedEvidence(what))
}

/// Read the raw `Authorization: Bearer` token bytes from a request's headers, if
/// present exactly once — the credential source for a DPoP `ath` binding
/// (MCPRE-101, built-in header derivation).
pub fn authorization_bearer_bytes(headers: &[(String, String)]) -> Option<Vec<u8>> {
    let value = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
        .map(|(_, v)| v.as_str())?;
    crate::artifact::bearer_token(value).map(|t| t.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Demo {
        a: u8,
    }

    #[test]
    fn insert_then_extract_roundtrips() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#;
        let composed = insert_meta_block(body, "k.demo", &Demo { a: 7 }).unwrap();
        let got: Demo = extract_meta_block(&composed, "k.demo", "demo").unwrap();
        assert_eq!(got, Demo { a: 7 });
    }

    #[test]
    fn insert_preserves_existing_meta_entries() {
        let body = br#"{"jsonrpc":"2.0","_meta":{"other":"keep"}}"#;
        let composed = insert_meta_block(body, "k.demo", &Demo { a: 1 }).unwrap();
        let root: Value = serde_json::from_slice(&composed).unwrap();
        assert_eq!(root["_meta"]["other"], Value::String("keep".into()));
        assert_eq!(root["_meta"]["k.demo"]["a"], Value::from(1));
    }

    #[test]
    fn absent_block_is_missing_evidence() {
        let body = br#"{"jsonrpc":"2.0"}"#;
        let err = extract_meta_block::<Demo>(body, "k.demo", "demo block").unwrap_err();
        assert_eq!(err, HttpProfileError::MissingEvidence("demo block"));
    }

    #[test]
    fn foreign_field_fails_closed() {
        let body = br#"{"_meta":{"k.demo":{"a":1,"evil":true}}}"#;
        let err = extract_meta_block::<Demo>(body, "k.demo", "demo block").unwrap_err();
        assert_eq!(err, HttpProfileError::MalformedEvidence("demo block"));
    }

    /// The composer re-serializes the whole body before it is digested and signed,
    /// so anything the round trip alters is signed and delivered as authentic. An
    /// integer wider than `i64`/`u64` came back thirteen significant digits short —
    /// a 128-bit id, a nanosecond timestamp or a fixed-point amount rewritten by the
    /// enforcement boundary and verified by the client as correctly bound.
    #[test]
    fn an_integer_the_round_trip_would_alter_is_refused_not_rewritten() {
        let body = br#"{"jsonrpc":"2.0","id":1,"result":{"big":123456789012345678901234567890}}"#;
        assert_eq!(
            insert_meta_block(body, "k.demo", &Demo { a: 1 }).unwrap_err(),
            HttpProfileError::MalformedEvidence(
                "body carries an integer this profile cannot sign without altering it"
            ),
        );
        // The negative control: had it been composed, the payload would have been
        // mutated inside the signed bytes.
        let mutated = serde_json::to_vec(&serde_json::from_slice::<Value>(body).expect("parses"))
            .expect("re-serializes");
        let mutated = String::from_utf8(mutated).unwrap();
        assert!(
            !mutated.contains("123456789012345678901234567890"),
            "the round trip really is lossy — the refusal is not decoration; got {mutated}"
        );
    }

    /// Every integer that fits is carried unchanged, so nothing legitimate was
    /// narrowed away — including the extremes and the negative side.
    #[test]
    fn representable_numbers_still_compose() {
        for value in [
            "0",
            "-1",
            "9223372036854775807",
            "-9223372036854775808",
            "18446744073709551615",
            "1.0",
            "-2.5e-3",
            "1e2",
        ] {
            let body = format!(r#"{{"jsonrpc":"2.0","result":{{"v":{value}}}}}"#);
            let out = insert_meta_block(body.as_bytes(), "k.demo", &Demo { a: 1 })
                .unwrap_or_else(|e| panic!("{value} must still compose: {e:?}"));
            let root: Value = serde_json::from_slice(&out).unwrap();
            assert_eq!(root["_meta"]["k.demo"]["a"], Value::from(1));
        }
    }

    /// A duplicate member name loses every value but the last, inside the signed
    /// bytes. Digits inside a STRING must not be read as a number token, and a
    /// repeated name in two SIBLING objects is not a duplicate.
    #[test]
    fn a_duplicate_member_name_is_refused_and_lookalikes_are_not() {
        assert_eq!(
            insert_meta_block(br#"{"r":{"dup":1,"dup":2}}"#, "k.demo", &Demo { a: 1 }).unwrap_err(),
            HttpProfileError::MalformedEvidence("body object has a duplicate member name"),
        );
        for ok in [
            r#"{"a":{"same":1},"b":{"same":2}}"#,
            r#"{"note":"999999999999999999999999 and \"dup\":1,\"dup\":2","x":1}"#,
            r#"{"list":[{"same":1},{"same":2}]}"#,
        ] {
            insert_meta_block(ok.as_bytes(), "k.demo", &Demo { a: 1 })
                .unwrap_or_else(|e| panic!("{ok} must still compose: {e:?}"));
        }
    }

    /// Two escaping-variant spellings of one member name are ONE member to
    /// `serde_json::Map`, so the earlier value vanishes from the signed bytes exactly as
    /// the plain duplicate would. The refusal is decided on the decoded name.
    #[test]
    fn an_escaped_duplicate_member_name_is_refused_like_a_plain_one() {
        for body in [
            r#"{"result":{"amount":100,"\u0061mount":1}}"#,
            r#"{"result":{"\u0061mount":1,"amount":100}}"#,
            r#"{"result":{"a\u0062":1,"ab":2}}"#,
            r#"{"result":{"\ud83d\ude00":1,"😀":2}}"#,
        ] {
            assert_eq!(
                insert_meta_block(body.as_bytes(), "k.demo", &Demo { a: 1 }).unwrap_err(),
                HttpProfileError::MalformedEvidence("body object has a duplicate member name"),
                "{body} was composed rather than refused",
            );
        }
        // The negative control: composing it really does delete a value.
        let mutated = serde_json::to_vec(
            &serde_json::from_slice::<Value>(br#"{"result":{"amount":100,"\u0061mount":1}}"#)
                .expect("parses"),
        )
        .expect("re-serializes");
        assert!(
            !String::from_utf8(mutated).unwrap().contains("100"),
            "the escaped spelling really does collapse last-wins"
        );
        // An escaped name that is NOT a duplicate still composes.
        insert_meta_block(
            br#"{"result":{"\u0061mount":1,"other":2}}"#,
            "k.demo",
            &Demo { a: 1 },
        )
        .expect("a lone escaped name is not a duplicate");
    }

    /// A decimal wider than the `f64` carrier is rewritten by the round trip just as an
    /// oversized integer is, and is refused on the same ground.
    #[test]
    fn a_decimal_the_round_trip_would_alter_is_refused_not_rewritten() {
        for value in [
            "1234567890123456789.5",
            "0.12345678901234567890123",
            "1.0000000000000000001",
            "1e-400",
            "-1234567890123456789.5",
        ] {
            let body = format!(r#"{{"jsonrpc":"2.0","result":{{"v":{value}}}}}"#);
            let err = insert_meta_block(body.as_bytes(), "k.demo", &Demo { a: 1 })
                .expect_err(&format!("{value} must be refused"));
            assert_eq!(
                err,
                HttpProfileError::MalformedEvidence(
                    "body carries a number this profile cannot sign without altering it"
                ),
                "{value}",
            );
        }
        // An exponent past the carrier's range is refused by the parse itself, one step
        // earlier — still refused, never composed.
        assert!(insert_meta_block(
            br#"{"jsonrpc":"2.0","result":{"v":1e400}}"#,
            "k.demo",
            &Demo { a: 1 }
        )
        .is_err());
    }

    /// The mirror: a decimal the carrier holds exactly composes AND arrives with its
    /// value intact. Asserting composition alone would not have caught the rewrite.
    #[test]
    fn a_representable_decimal_keeps_its_value_through_the_composer() {
        for (value, expect) in [
            ("1.5", 1.5f64),
            ("-2.5e-3", -2.5e-3),
            ("1e2", 100.0),
            ("0.1", 0.1),
            ("123456789012345.0", 123456789012345.0),
            ("0.000", 0.0),
        ] {
            let body = format!(r#"{{"jsonrpc":"2.0","result":{{"v":{value}}}}}"#);
            let out = insert_meta_block(body.as_bytes(), "k.demo", &Demo { a: 1 })
                .unwrap_or_else(|e| panic!("{value} must still compose: {e:?}"));
            let root: Value = serde_json::from_slice(&out).unwrap();
            assert_eq!(
                root["result"]["v"].as_f64().expect("a number"),
                expect,
                "{value} did not survive the composer",
            );
        }
    }

    #[test]
    fn non_object_body_fails_closed() {
        let err = insert_meta_block(b"[1,2,3]", "k", &Demo { a: 1 }).unwrap_err();
        assert_eq!(
            err,
            HttpProfileError::MalformedEvidence("body not a json object")
        );
    }
}
