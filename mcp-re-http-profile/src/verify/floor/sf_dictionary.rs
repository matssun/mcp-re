// SPDX-License-Identifier: Apache-2.0
//! RFC 8941 dictionary reading, for the two headers that carry evidence.
//!
//! One authority: **a dictionary header has exactly one spelling, and exactly one value
//! under a label.** This is the generic Structured-Fields layer; what a member's VALUE
//! means is [`super::signature_input`]'s, and the two are separate because they are
//! separate specifications with separate closed sets.
//!
//! # Why alternate spellings are refused rather than normalised
//!
//! The verifier rebuilds `@signature-params` from PARSED values and re-serialises them
//! canonically ([`crate::sigbase`]). Any spelling difference normalised away here therefore
//! collapses into the canonical signature base and verifies under the same signature — so
//! an on-path intermediary could rewrite the raw header bytes without invalidating
//! anything, and every consumer that logs, hashes, caches or diffs the RAW header would
//! hold bytes other than the ones that were signed. No forgery; the one-to-one
//! correspondence the profile claims for itself simply stops holding.
//!
//! This module is the SOLE reader of both `Signature-Input` and `Signature`, so every path
//! inherits the rule rather than each remembering it.

use crate::error::HttpProfileError;

/// Split a Structured Fields dictionary into members at top-level commas
/// (commas inside quoted strings do not split).
///
/// The quote state honours RFC 8941 `\` escapes. Without that, a `\"` inside a
/// member's string value toggled the state and left it odd, so the next top-level
/// comma was swallowed and TWO dictionary members merged into one — and this runs
/// BEFORE any value is validated, so the profile would be reading the merged text
/// as a single member's parameters before anything could reject the value that
/// caused it. Every construction traced from there still failed closed downstream,
/// but "the parser recovers by erroring" is not the same as splitting the
/// dictionary the way every other RFC 8941 implementation does.
pub(super) fn split_dictionary(value: &str) -> Vec<&str> {
    let mut members = Vec::new();
    let mut start = 0usize;
    let mut in_quotes = false;
    let mut escaped = false;
    for (i, c) in value.char_indices() {
        if escaped {
            // Inside a string, `\` escapes exactly one following character; it never
            // ends the string.
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_quotes => escaped = true,
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                members.push(value[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    members.push(value[start..].trim());
    members
}
/// Split a signature-input's parameter section at top-level `;` — semicolons inside
/// a quoted string are part of the value, not separators.
///
/// Same reasoning as [`split_dictionary`]: a `;` inside a `nonce` used to cut the
/// value in half and produce a parameter list that was never on the wire. The halves
/// then failed to unquote, so this was fail-closed too, but the parse disagreed with
/// a conforming one before it got there.
pub(super) fn split_parameters(value: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut in_quotes = false;
    let mut escaped = false;
    for (i, c) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_quotes => escaped = true,
            '"' => in_quotes = !in_quotes,
            ';' if !in_quotes => {
                parts.push(value[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(value[start..].trim());
    parts
}
/// Find the member value for `label` in a `Signature-Input`/`Signature`
/// dictionary header, fail-closed on absence, duplication, or whitespace the
/// dictionary grammar does not permit.
///
/// RFC 8941 §3.2 `dict-member = member-key ( parameters / ( "=" member-value ) )`
/// admits no OWS around the `=`; OWS is permitted only around the member-separating
/// comma, which [`split_dictionary`] trims. Normalizing whitespace after the `=`
/// away — as a `.trim()` here did — made `mcp-re= (...)` and `mcp-re=(...)` rebuild
/// to one signature base and verify under one signature. That is the same
/// wire-spelling collapse [`parse_signature_input`] refuses inside the member, one
/// layer up: an on-path intermediary could rewrite the raw header bytes without
/// invalidating anything, so an audit sink, a retained-evidence blob or a cache key
/// held bytes other than the ones that were signed. This is the sole reader of both
/// the `Signature-Input` and the `Signature` header, so every path inherits it.
pub(crate) fn member_value<'a>(
    header_value: &'a str,
    label: &str,
) -> Result<&'a str, HttpProfileError> {
    let mut found: Option<&'a str> = None;
    for member in split_dictionary(header_value) {
        // RFC 8941 §3.2's `dict-member` cannot be empty, so a leading, trailing or
        // doubled comma is not a spelling of the same dictionary — it is not a
        // dictionary. Skipping it silently, as an unparseable member, is the same
        // wire-spelling collapse the `=` rule above refuses: `mcp-re=(...)` and
        // `,mcp-re=(...),` would rebuild one signature base and verify under one
        // signature, so an intermediary could add or strip a comma in the raw header
        // and every consumer that logs, hashes, caches or diffs it would hold bytes
        // other than the ones that were signed.
        if member.is_empty() {
            return Err(HttpProfileError::MalformedEvidence(
                "empty dictionary member",
            ));
        }
        if let Some(rest) = member.strip_prefix(label) {
            if let Some(v) = rest.strip_prefix('=') {
                if found.is_some() {
                    return Err(HttpProfileError::MalformedEvidence(
                        "duplicate signature label",
                    ));
                }
                if v.trim() != v {
                    return Err(HttpProfileError::MalformedEvidence(
                        "dictionary member spacing",
                    ));
                }
                found = Some(v);
            }
        }
    }
    found.ok_or(HttpProfileError::MissingEvidence("signature label"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANONICAL: &str = r#"("@method" "@target-uri" "content-digest");created=1700000000;expires=1700000300;nonce="n";keyid="k";alg="ed25519""#;

    /// The spelling rules hold at the DICTIONARY MEMBER boundary too, not only inside
    /// the member value. `member_value` is the sole reader of both `Signature-Input`
    /// and `Signature`, so OWS normalised away here would let an intermediary rewrite
    /// either raw header and still verify under the same signature.
    #[test]
    fn dictionary_member_spacing_is_refused_not_normalised() {
        let canonical = format!("mcp-re={CANONICAL}");
        assert_eq!(
            member_value(&canonical, "mcp-re").expect("the canonical member reads"),
            CANONICAL
        );

        for alternate in [
            format!("mcp-re= {CANONICAL}"),
            format!("mcp-re=\t{CANONICAL}"),
            format!("other=(\"@method\"), mcp-re=  {CANONICAL}"),
        ] {
            assert_eq!(
                member_value(&alternate, "mcp-re").unwrap_err(),
                HttpProfileError::MalformedEvidence("dictionary member spacing"),
                "must be refused rather than normalised: {alternate}"
            );
        }

        // The same reader serves the `Signature` header's byte sequence.
        assert_eq!(
            member_value("mcp-re=  :YWJj:", "mcp-re").unwrap_err(),
            HttpProfileError::MalformedEvidence("dictionary member spacing")
        );
        assert_eq!(
            member_value("mcp-re=:YWJj:", "mcp-re").expect("canonical"),
            ":YWJj:"
        );

        // OWS around the member-separating comma stays legal (RFC 8941 §4.2).
        assert_eq!(
            member_value("other=(\"@method\") , mcp-re=:YWJj:", "mcp-re").expect("comma OWS"),
            ":YWJj:"
        );
    }

    /// A comma that delimits nothing is not a spelling variant of the dictionary — RFC
    /// 8941 has no empty `dict-member`. Ignored as "a member I could not parse", it let
    /// an intermediary add or strip commas in the raw `Signature-Input`/`Signature`
    /// header while the signature still verified.
    #[test]
    fn an_empty_dictionary_member_is_refused_not_ignored() {
        for spelling in [
            ",mcp-re=:YWJj:",
            "mcp-re=:YWJj:,",
            "mcp-re=:YWJj:,,other=1",
            " , mcp-re=:YWJj:",
            ",",
            "",
        ] {
            assert_eq!(
                member_value(spelling, "mcp-re").unwrap_err(),
                HttpProfileError::MalformedEvidence("empty dictionary member"),
                "{spelling:?} was read as the canonical dictionary",
            );
        }
        // The canonical spelling, and a legitimate neighbouring member, are unaffected.
        assert_eq!(
            member_value("mcp-re=:YWJj:", "mcp-re").expect("canonical"),
            ":YWJj:"
        );
        assert_eq!(
            member_value("other=1, mcp-re=:YWJj:", "mcp-re").expect("a neighbour is legal"),
            ":YWJj:"
        );
    }
}
