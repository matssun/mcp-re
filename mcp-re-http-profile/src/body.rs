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

/// Refuse a JSON body whose application payload this composer cannot carry
/// unchanged.
///
/// Composing the evidence block re-serializes the WHOLE body through
/// `serde_json::Value`, and that happens before `Content-Digest` and the signature —
/// so anything the round trip alters is what gets signed and delivered as authentic,
/// with the client verifying the altered value as a correctly bound response. The
/// proxy is a pass-through for application payload, and this is the one place it
/// could stop being one, so the two alterations that change what a reader SEES are
/// refused rather than performed:
///
///   * **An integer outside the i64/u64 range.** Without `arbitrary_precision`,
///     `serde_json` carries it as `f64`:
///     `123456789012345678901234567890` comes back as `1.2345678901234568e29`, having
///     lost thirteen significant digits. A 128-bit identifier, a nanosecond timestamp
///     or a fixed-point monetary value would be silently rewritten.
///   * **A duplicate member name.** The last one wins and the others vanish from the
///     signed bytes.
///
/// Member ORDER is rewritten too, and is not refusable here: every message this
/// profile has ever signed carries the re-serialized order, so the order IS the
/// emitted form. RFC 8259 §4 states object members are unordered, so no reader may
/// depend on it, and unlike the two above it changes no value anyone reads.
///
/// Runs after the body has parsed, so the scan may assume well-formed JSON: it
/// tracks string literals (to avoid reading their contents as structure), object
/// nesting, and member names, and needs no error recovery.
fn reject_unrepresentable_json(body: &[u8]) -> Result<(), HttpProfileError> {
    // One frame per open object; `None` for an array, whose elements have no names.
    let mut frames: Vec<Option<std::collections::HashSet<&[u8]>>> = Vec::new();
    let mut i = 0usize;
    while i < body.len() {
        match body[i] {
            b'"' => {
                let start = i + 1;
                let mut j = start;
                while j < body.len() && body[j] != b'"' {
                    j += if body[j] == b'\\' { 2 } else { 1 };
                }
                let name = &body[start..j.min(body.len())];
                i = j + 1;
                // A string followed by `:` is a member name; nothing else can be.
                let mut k = i;
                while k < body.len() && body[k].is_ascii_whitespace() {
                    k += 1;
                }
                if k < body.len() && body[k] == b':' {
                    if let Some(Some(names)) = frames.last_mut() {
                        if !names.insert(name) {
                            return Err(HttpProfileError::MalformedEvidence(
                                "body object has a duplicate member name",
                            ));
                        }
                    }
                }
            }
            b'{' => {
                frames.push(Some(std::collections::HashSet::new()));
                i += 1;
            }
            b'[' => {
                frames.push(None);
                i += 1;
            }
            b'}' | b']' => {
                frames.pop();
                i += 1;
            }
            b'-' | b'0'..=b'9' => {
                let start = i;
                while i < body.len()
                    && matches!(body[i], b'-' | b'+' | b'.' | b'0'..=b'9' | b'e' | b'E')
                {
                    i += 1;
                }
                let token = &body[start..i];
                // Only INTEGER syntax is checked. A token with a fraction or an
                // exponent is a JSON number whose carrier is `f64` by construction
                // (RFC 8259 §6), and `f64` round-trips through `serde_json` exactly.
                if !token.iter().any(|b| matches!(b, b'.' | b'e' | b'E')) {
                    let text = std::str::from_utf8(token)
                        .map_err(|_| HttpProfileError::MalformedEvidence("body json"))?;
                    if text.parse::<i64>().is_err() && text.parse::<u64>().is_err() {
                        return Err(HttpProfileError::MalformedEvidence(
                            "body carries an integer this profile cannot sign without altering it",
                        ));
                    }
                }
            }
            _ => i += 1,
        }
    }
    Ok(())
}

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

    #[test]
    fn non_object_body_fails_closed() {
        let err = insert_meta_block(b"[1,2,3]", "k", &Demo { a: 1 }).unwrap_err();
        assert_eq!(
            err,
            HttpProfileError::MalformedEvidence("body not a json object")
        );
    }
}
