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

/// Insert `block` under top-level `_meta[key]` and return the re-serialized body
/// bytes. The body MUST be a JSON object (a JSON-RPC message); an existing
/// `_meta` object is preserved and extended.
pub fn insert_meta_block<T: Serialize>(
    body: &[u8],
    key: &str,
    block: &T,
) -> Result<Vec<u8>, HttpProfileError> {
    let mut root: Value =
        serde_json::from_slice(body).map_err(|_| HttpProfileError::MalformedEvidence("body json"))?;
    let obj = root
        .as_object_mut()
        .ok_or(HttpProfileError::MalformedEvidence("body not a json object"))?;
    let meta = obj
        .entry(META_KEY)
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    let meta_obj = meta
        .as_object_mut()
        .ok_or(HttpProfileError::MalformedEvidence("_meta not an object"))?;
    let value =
        serde_json::to_value(block).map_err(|_| HttpProfileError::MalformedEvidence("block serialize"))?;
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
    let root: Value =
        serde_json::from_slice(body).map_err(|_| HttpProfileError::MalformedEvidence("body json"))?;
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

    #[test]
    fn non_object_body_fails_closed() {
        let err = insert_meta_block(b"[1,2,3]", "k", &Demo { a: 1 }).unwrap_err();
        assert_eq!(
            err,
            HttpProfileError::MalformedEvidence("body not a json object")
        );
    }
}
