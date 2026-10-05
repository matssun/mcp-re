// SPDX-License-Identifier: Apache-2.0
//! Which JSON this profile can carry through its own re-serialization unchanged.
//!
//! One authority, and it is the proxy's pass-through promise made checkable. Composing the
//! evidence block re-serializes the WHOLE body through `serde_json::Value`, and that happens
//! BEFORE `Content-Digest` and the signature — so anything the round trip alters is what
//! gets signed and delivered as authentic, with the client verifying the altered value as a
//! correctly bound response.
//!
//! The proxy is a pass-through for application payload, and this is the one place it could
//! stop being one. Every alteration that changes what a reader SEES is therefore refused
//! rather than performed. Member ORDER is the one exception, and it is not refusable: every
//! message this profile has ever signed carries the re-serialized order, so the order IS the
//! emitted form. RFC 8259 §4 states object members are unordered, so no reader may depend on
//! it, and unlike the refusals here it changes no value anyone reads.
//!
//! The scan is total over arbitrary bytes and may NOT assume well-formed JSON: it is called
//! both after the body has parsed (`insert_meta_block`, `extract_meta_block`) and before it
//! (`validate_request_envelope`, which must answer for the bytes the client signed rather
//! than the document serde picks out of them). It tracks string literals (to avoid reading
//! their contents as structure), object nesting, and member names, never panics or reads
//! past the slice on any input, and does no error recovery: on bytes that are not JSON its
//! verdict is not a JSON verdict, and the caller's own parse is what refuses them. The
//! control for that totality is `the_representability_scan_never_reads_past_the_body`.
//!
//! ## Bounds and cursor arithmetic
//!
//! Every read of `body` goes through `get`, so the walk stops where the slice stops —
//! including where an escape at the very end carries the cursor one position past it. What
//! remains is cursor arithmetic over slice indices, bounded by `isize::MAX`
//! (`docs/dev/partial-operations.md`, class C).

use std::collections::HashSet;

use crate::error::HttpProfileError;

use super::carried_number::scan_number;

/// One frame per open composite: the member names seen so far in an object, or `None` for
/// an array, whose elements have no names.
type Frames = Vec<Option<HashSet<String>>>;

/// Scan one string literal, and — when it turns out to be a member NAME — record it in the
/// enclosing object's frame.
///
/// Returns the index just past the closing quote. A string followed by `:` is a member name;
/// nothing else can be. Duplication is decided on the DECODED name, because
/// `serde_json::Map` is keyed on the decoded string: `"x"` and `"\u0078"` are one member
/// name however differently they are spelled on the wire — and the last one would win,
/// making the others vanish from the signed bytes.
// Class C: `start`, `j`, `k`, `after` are positions in `body` or just past it. Every
// READ is a `get`.
#[allow(clippy::arithmetic_side_effects)]
fn scan_string(body: &[u8], at: usize, frames: &mut Frames) -> Result<usize, HttpProfileError> {
    let start = at + 1;
    let mut j = start;
    while let Some(byte) = body.get(j) {
        if *byte == b'"' {
            break;
        }
        // An escape skips its escaped byte, so a body ending in a backslash leaves `j`
        // one PAST the end. `get` above decides every access, so the walk simply stops.
        j += if *byte == b'\\' { 2 } else { 1 };
    }
    let end = j.min(body.len());
    let Some(raw) = body.get(start..end) else {
        // `start <= end` for every index the walk produces; this fails only if `at` did
        // not point at a byte of `body`. The posture for anything unaccounted for is
        // refusal, not a default that would scan as an empty member name.
        return Err(HttpProfileError::MalformedEvidence("body json"));
    };
    let after = j + 1;
    let mut k = after;
    while body.get(k).is_some_and(u8::is_ascii_whitespace) {
        k += 1;
    }
    if body.get(k) == Some(&b':') {
        let name = decoded_member_name(raw)?;
        if let Some(Some(names)) = frames.last_mut() {
            if !names.insert(name) {
                return Err(HttpProfileError::MalformedEvidence(
                    "body object has a duplicate member name",
                ));
            }
        }
    }
    Ok(after)
}

/// Refuse a JSON body whose application payload this composer cannot carry unchanged.
///
/// The module documentation states what is refused and why. This is the walk: strings and
/// numbers are the only tokens that can carry a loss, and the brackets are tracked only so
/// that a member name is attributed to the object it belongs to.
// Class C: each arm advances `i` past the byte `get` just returned, so it stays within one
// position of `body`'s length. The scanners return their own cursors, bounded the same way.
#[allow(clippy::arithmetic_side_effects)]
pub fn reject_unrepresentable_json(body: &[u8]) -> Result<(), HttpProfileError> {
    let mut frames: Frames = Vec::new();
    let mut i = 0usize;
    while let Some(byte) = body.get(i) {
        i = match *byte {
            b'"' => scan_string(body, i, &mut frames)?,
            b'-' | b'0'..=b'9' => scan_number(body, i)?,
            b'{' => {
                frames.push(Some(HashSet::new()));
                i + 1
            }
            b'[' => {
                frames.push(None);
                i + 1
            }
            b'}' | b']' => {
                frames.pop();
                i + 1
            }
            _ => i + 1,
        };
    }
    Ok(())
}

/// The member name as `serde_json` keys it: the raw bytes between the quotes with JSON
/// escapes decoded.
///
/// Duplication must be decided on this form. `serde_json::Map` is keyed on the decoded
/// string, so `"x"` and `"x"` are ONE member there and the earlier value is
/// dropped on the way into the signed bytes; keyed on the raw slice they are two
/// distinct names and the refusal never fires.
fn decoded_member_name(raw: &[u8]) -> Result<String, HttpProfileError> {
    let malformed = || HttpProfileError::MalformedEvidence("body json");
    if !raw.contains(&b'\\') {
        return std::str::from_utf8(raw)
            .map(str::to_owned)
            .map_err(|_| malformed());
    }
    // Class C: `raw` is a subslice of the body, so the two quote bytes fit.
    #[allow(clippy::arithmetic_side_effects)]
    let capacity = raw.len() + 2;
    let mut quoted = Vec::with_capacity(capacity);
    quoted.push(b'"');
    quoted.extend_from_slice(raw);
    quoted.push(b'"');
    serde_json::from_slice::<String>(&quoted).map_err(|_| malformed())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const DUPLICATE: HttpProfileError =
        HttpProfileError::MalformedEvidence("body object has a duplicate member name");

    /// A duplicate member name loses every value but the last, inside the signed bytes.
    /// Digits inside a STRING must not be read as a number token, and a repeated name in
    /// two SIBLING objects is not a duplicate.
    #[test]
    fn a_duplicate_member_name_is_refused_and_lookalikes_are_not() {
        assert_eq!(reject_unrepresentable_json(br#"{"r":{"dup":1,"dup":2}}"#), Err(DUPLICATE));
        for ok in [
            r#"{"a":{"same":1},"b":{"same":2}}"#,
            r#"{"note":"999999999999999999999999 and \"dup\":1,\"dup\":2","x":1}"#,
            r#"{"list":[{"same":1},{"same":2}]}"#,
        ] {
            assert_eq!(reject_unrepresentable_json(ok.as_bytes()), Ok(()), "{ok}");
        }
    }

    /// Two escaping-variant spellings of one member name are ONE member to
    /// `serde_json::Map`, so the earlier value vanishes from the signed bytes exactly as the
    /// plain duplicate would. The refusal is decided on the decoded name.
    #[test]
    fn an_escaped_duplicate_member_name_is_refused_like_a_plain_one() {
        for body in [
            r#"{"result":{"amount":100,"\u0061mount":1}}"#,
            r#"{"result":{"\u0061mount":1,"amount":100}}"#,
            r#"{"result":{"a\u0062":1,"ab":2}}"#,
            r#"{"result":{"\ud83d\ude00":1,"😀":2}}"#,
        ] {
            assert_eq!(
                reject_unrepresentable_json(body.as_bytes()),
                Err(DUPLICATE),
                "{body} was carried rather than refused",
            );
        }
        // The negative control: carrying it really does delete a value.
        let carried = serde_json::to_vec(
            &serde_json::from_slice::<Value>(br#"{"result":{"amount":100,"\u0061mount":1}}"#)
                .expect("parses"),
        )
        .expect("re-serializes");
        assert!(
            !String::from_utf8(carried).expect("utf-8").contains("100"),
            "the escaped spelling really does collapse last-wins"
        );
        // An escaped name that is NOT a duplicate is carried.
        assert_eq!(
            reject_unrepresentable_json(br#"{"result":{"\u0061mount":1,"other":2}}"#),
            Ok(())
        );
    }

    /// The representability scan is TOTAL: it never reads past the body it was handed.
    ///
    /// Every cursor in that scanner is derived from bytes the caller supplied, and one of
    /// them — the escape skip — deliberately steps TWO positions, so it can leave the body
    /// entirely when a string's last byte is a backslash. The walk is bounded by `get`
    /// rather than by that arithmetic staying in range, and this is what measures it:
    /// truncations of a body at every byte offset, which is exactly the family that puts a
    /// cursor one past the end, plus the degenerate and non-JSON inputs.
    ///
    /// It asserts a verdict for none of them. Whether a given truncation is refused is the
    /// job of the tests above; the property here is that answering at all does not panic.
    #[test]
    fn the_representability_scan_never_reads_past_the_body() {
        let seeds: &[&[u8]] = &[
            br#"{"a":"b\"c","n":1.5e10,"m":[1,2,{"k":"v"}]}"#,
            br#"{"escape":"trailing\\"}"#,
            br#"{"a":"\"#,
            b"\\",
            b"\"",
            b"",
            b"{",
            b"[[[[",
            b"}]}]",
            b"-",
            b"1e",
            b"\xff\xfe\x00\x80",
        ];
        for seed in seeds {
            for cut in 0..=seed.len() {
                let _ = reject_unrepresentable_json(&seed[..cut]);
            }
        }
    }
}
