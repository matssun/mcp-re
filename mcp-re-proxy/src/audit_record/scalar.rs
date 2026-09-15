// SPDX-License-Identifier: Apache-2.0
//! An injective escape for one audit scalar, and its inverse.
//!
//! The proposition, which mentions no record and no field:
//!
//! > `escape_scalar` is injective, and its image contains no SPACE, no `=`, no C0 control,
//! > no DEL, no C1 control, no Unicode line separator, no bidi or format control, and never
//! > the bare token `-`.
//!
//! [`super::text`] is what turns that into a record property. The two are separable because
//! this one can be stated, and refuted, with nothing in scope but a string: which codepoints
//! are hazards and how each is spelled here; whether two distinct inputs can produce one
//! output there.
//!
//! Injectivity is established by an explicit left inverse rather than by reading the
//! forward function: [`unescape_scalar`] is written as one and the round trip is a test, so
//! the claim is checkable rather than argued.

/// Whether a token or a field name can be rendered verbatim without breaking the grammar.
///
/// The record's other half: escaping values is worth nothing if a NAME can carry a space.
pub(crate) fn is_separator_free(text: &str) -> bool {
    !text.is_empty()
        && !text
            .chars()
            .any(|c| c == ' ' || c == '=' || c == '\\' || is_hazard(c))
}

/// The scalar escape.
///
/// Backslash escaping over a closed hazard set, applied unconditionally. The backslash's own
/// escape is emitted first, so no literal backslash survives unescaped and no escape output
/// can be re-read as a literal — which is what keeps `"read\nx"` (three characters) and
/// `"read"` + LF + `"x"` distinguishable.
///
/// Every value in the field today renders byte-identically: tool names, methods, base64url
/// digests, wire codes and actor ids carry no backslash, space, `=`, control or leading `-`.
/// That is the reason to escape rather than to quote — a `grep 'actor=did:example:agent-1'`
/// keeps working, and the bytes move only where a hazard is actually present.
pub(crate) fn escape_scalar(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for (index, c) in value.char_indices() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ' ' => out.push_str("\\s"),
            '=' => out.push_str("\\e"),
            // The reserved `Absent` token, and only where it would be that whole token.
            '-' if index == 0 => out.push_str("\\x2d"),
            c if (c as u32) < 0x20 || c as u32 == 0x7F => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c if is_hazard(c) => out.push_str(&format!("\\u{{{:x}}}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Codepoints that must never reach an operator's line verbatim, beyond the grammar's own
/// separators and the C0/DEL range `escape_scalar` handles by arithmetic.
///
/// Two families, for two different reasons. The C1 controls (NEL U+0085 among them) and the
/// Unicode line separators end a record for a Unicode-aware reader even though they are not
/// U+000A. The bidi and format controls do not end anything — they make
/// a line DISPLAY as something other than what it says, so a value carrying U+202E can make
/// a real field read as a different one.
fn is_hazard(c: char) -> bool {
    matches!(c as u32,
        0x80..=0x9F | 0x2028 | 0x2029 | 0x061C | 0x200E | 0x200F
        | 0x202A..=0x202E | 0x2066..=0x2069 | 0xFEFF)
}

/// The left inverse of [`escape_scalar`].
///
/// `unescape_scalar(&escape_scalar(s)) == Some(s.to_owned())` for every `s`. This function
/// is what makes injectivity a CHECKABLE claim rather than an assertion about
/// `escape_scalar`'s source text: the round trip is a test, not a reading.
///
/// `None` for input that is not an image of `escape_scalar` — a truncated escape, an unknown
/// escape body, or a codepoint that would have been escaped appearing verbatim.
///
/// `#[cfg(test)]` because no serving path reads a record back: the inverse is how the
/// injectivity claim is STATED, not an operation this proxy performs. Compiling it into the
/// library would ship an unused decoder and name no consumer for it.
#[cfg(test)]
pub(crate) fn unescape_scalar(rendered: &str) -> Option<String> {
    let mut out = String::with_capacity(rendered.len());
    let mut chars = rendered.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            // A byte that `escape_scalar` would have escaped cannot appear literally in an
            // image of it, so admitting one here would make the inverse accept strings the
            // forward direction never produces — and the round trip would stop being a
            // statement about injectivity.
            if c == ' ' || c == '=' || (c as u32) < 0x20 || c as u32 == 0x7F || is_hazard(c) {
                return None;
            }
            out.push(c);
            continue;
        }
        match chars.next()? {
            '\\' => out.push('\\'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            's' => out.push(' '),
            'e' => out.push('='),
            'x' => {
                let hex: String = [chars.next()?, chars.next()?].iter().collect();
                out.push(decode_codepoint(&hex)?);
            }
            'u' => {
                if chars.next()? != '{' {
                    return None;
                }
                let mut hex = String::new();
                loop {
                    match chars.next()? {
                        '}' => break,
                        h => hex.push(h),
                    }
                }
                out.push(decode_codepoint(&hex)?);
            }
            _ => return None,
        }
    }
    Some(out)
}

/// One hexadecimal escape body as the character it names.
#[cfg(test)]
fn decode_codepoint(hex: &str) -> Option<char> {
    char::from_u32(u32::from_str_radix(hex, 16).ok()?)
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::*;

    /// THE anti-collision control: an escaped value and a literal one are different bytes.
    ///
    /// This is the test that fails if `\` is escaped last instead of first.
    #[test]
    fn an_escaped_value_and_a_literal_one_do_not_collide() {
        let with_newline = "read\nx";
        let with_backslash = "read\\nx";
        assert_ne!(escape_scalar(with_newline), escape_scalar(with_backslash));
        assert_eq!(
            unescape_scalar(&escape_scalar(with_newline)).as_deref(),
            Some(with_newline)
        );
        assert_eq!(
            unescape_scalar(&escape_scalar(with_backslash)).as_deref(),
            Some(with_backslash)
        );
    }

    /// Every scalar round-trips, over a corpus chosen to contain each escape family.
    #[test]
    fn every_scalar_round_trips() {
        let mut corpus: Vec<String> = vec![
            String::new(),
            "-".to_owned(),
            "--".to_owned(),
            "a-b".to_owned(),
            "\\".to_owned(),
            "=".to_owned(),
            " ".to_owned(),
            "\"".to_owned(),
            "read\\nx".to_owned(),
            "tools/call".to_owned(),
            "client:example.com:did%3Aexample%3Aa:kid-1".to_owned(),
            "\u{1F600}".to_owned(),
            "\u{85}".to_owned(),
            "\u{2028}".to_owned(),
            "\u{2029}".to_owned(),
            "\u{061C}".to_owned(),
            "\u{200E}".to_owned(),
            "\u{202E}".to_owned(),
            "\u{2066}".to_owned(),
            "\u{FEFF}".to_owned(),
        ];
        for code in (0..=0x1Fu32)
            .chain(std::iter::once(0x7F))
            .chain(0x80..=0x9F)
        {
            corpus.push(char::from_u32(code).expect("scalar value").to_string());
        }
        // Each of the above at the start, in the middle and at the end, because the leading
        // `-` rule is positional and an off-by-one there would otherwise pass.
        let seeds = corpus.clone();
        for seed in &seeds {
            corpus.push(format!("{seed}tail"));
            corpus.push(format!("head{seed}"));
            corpus.push(format!("head{seed}tail"));
        }
        for s in &corpus {
            let escaped = escape_scalar(s);
            assert_eq!(
                unescape_scalar(&escaped).as_ref(),
                Some(s),
                "round trip failed for {s:?} -> {escaped:?}"
            );
            assert!(
                escaped.chars().all(|c| c != ' '
                    && c != '='
                    && (c as u32) >= 0x20
                    && c as u32 != 0x7F
                    && !is_hazard(c)),
                "the image carries a hazard: {s:?} -> {escaped:?}"
            );
        }
    }

    /// The inverse refuses what the forward direction never produces.
    #[test]
    fn the_inverse_refuses_text_that_is_no_image_of_the_escape() {
        assert_eq!(unescape_scalar("a b"), None, "a literal separator");
        assert_eq!(unescape_scalar("a=b"), None, "a literal key separator");
        assert_eq!(unescape_scalar("a\nb"), None, "a literal line break");
        assert_eq!(unescape_scalar("a\\"), None, "a truncated escape");
        assert_eq!(unescape_scalar("a\\q"), None, "an unknown escape body");
        assert_eq!(unescape_scalar("a\\x2"), None, "a truncated hex escape");
        assert_eq!(
            unescape_scalar("a\\u{202e"),
            None,
            "an unterminated brace escape"
        );
    }

    /// The reserved absent marker is not in the image of the escape.
    ///
    /// The record grammar spells *the owner resolved nothing* as a bare `-`. That stays a
    /// distinct fact only while no scalar can produce the same bytes, which is a property
    /// of THIS function and is therefore stated here.
    #[test]
    fn no_scalar_escapes_to_the_bare_absent_marker() {
        assert_ne!(escape_scalar("-"), "-");
        assert_eq!(unescape_scalar(&escape_scalar("-")).as_deref(), Some("-"));
        assert_eq!(
            escape_scalar("a-b"),
            "a-b",
            "only a LEADING dash is reserved"
        );
    }

    /// A name or token rendered verbatim must not be able to break the grammar.
    #[test]
    fn a_separator_free_string_is_exactly_one_that_renders_verbatim() {
        assert!(is_separator_free("authz_policy_reason"));
        assert!(is_separator_free("mcp-re.request.accepted"));
        assert!(!is_separator_free(""));
        assert!(!is_separator_free("a b"));
        assert!(!is_separator_free("a=b"));
        assert!(!is_separator_free("a\\b"));
        assert!(!is_separator_free("a\u{202E}b"));
    }
}
