// SPDX-License-Identifier: Apache-2.0
//! An injective escape for one audit scalar, and its inverse.
//!
//! The proposition, which mentions no record and no field:
//!
//! > `escape_scalar` is injective, and its image contains no SPACE, no `=`, no C0 control,
//! > no DEL, no C1 control, no Unicode whitespace, no Unicode line separator, no bidi or
//! > format control, and never the bare token `-`.
//!
//! [`super::text`] is what turns that into a record property. The two are separable because
//! this one can be stated, and refuted, with nothing in scope but a string: which codepoints
//! are hazards and how each is spelled here; whether two distinct inputs can produce one
//! output there.
//!
//! Injectivity is established by an explicit left inverse rather than by reading the
//! forward function: [`unescape_scalar`] is written as one and the round trip is a test, so
//! the claim is checkable rather than argued.

/// Whether a token or a field name is already its own rendering.
///
/// The record's other half: escaping values is worth nothing if a NAME can carry a space.
///
/// True of exactly the non-empty strings [`escape_scalar`] maps to themselves — the
/// escape's fixed point, which is what makes "rendered verbatim" and "recoverable by
/// [`unescape_scalar`]" the same set. Derived from the escape's own hazard set rather than
/// restated as a second list, because a second list is a list that can disagree: a
/// codepoint the escape spells and this predicate admits is one the record escapes inside a
/// value and emits verbatim in a name.
pub(crate) fn is_separator_free(text: &str) -> bool {
    !text.is_empty() && !text.starts_with('-') && !text.chars().any(is_escaped_char)
}

/// Whether [`escape_scalar`] spells `c` as something other than itself, apart from the
/// positional leading-`-` rule its caller applies separately.
fn is_escaped_char(c: char) -> bool {
    c == '\\' || c == ' ' || c == '=' || is_render_hazard(c)
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
            c if is_render_hazard(c) => out.push_str(&format!("\\u{{{:x}}}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Codepoints that must never reach an operator's line verbatim, beyond U+0020, which the
/// record grammar escapes by name.
///
/// Three families, for three reasons:
///
/// - **Controls** (Cc: C0, DEL, C1 with NEL U+0085) and the Unicode line separators end a
///   record for a reader that is not looking for U+000A alone.
/// - **Whitespace other than U+0020** (U+00A0, U+1680, U+2000–U+200A, U+202F, U+205F,
///   U+3000, …) SEPARATES tokens for a reader that splits on Unicode whitespace — Python's
///   `str.split()`, Go's `strings.Fields`, or any pipeline that normalises spaces — so a value
///   carrying one would read there as two fields, and the second could shadow a real one.
/// - **Every format control** (General_Category `Cf`: [`FORMAT_CONTROLS`]) does not end or
///   split anything; it makes a line DISPLAY as something other than what it says. The bidi
///   embeddings, overrides and isolates, the zero-width characters, the byte order mark, the
///   tag characters and the script-specific format characters are all `Cf`.
///
/// One statement of the set, shared with
/// [`crate::communication_assurance::peer_identity_value`]: a peer identity is refused for
/// carrying exactly the codepoints the audit record would have to escape, because both
/// rules exist so that what an operator reads is what the value is.
pub(crate) fn is_render_hazard(c: char) -> bool {
    c.is_control()
        || (c.is_whitespace() && c != ' ')
        || FORMAT_CONTROLS
            .iter()
            .any(|&(first, last)| (first..=last).contains(&(c as u32)))
}

/// Unicode 16.0.0 General_Category `Cf` as inclusive `(first, last)` codepoint ranges.
/// `scripts/format_control_table_gate.py` regenerates the table from `unicodedata` and fails
/// when this one differs.
const FORMAT_CONTROLS: &[(u32, u32)] = &[
    (0x00AD, 0x00AD),
    (0x0600, 0x0605),
    (0x061C, 0x061C),
    (0x06DD, 0x06DD),
    (0x070F, 0x070F),
    (0x0890, 0x0891),
    (0x08E2, 0x08E2),
    (0x180E, 0x180E),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x2064),
    (0x2066, 0x206F),
    (0xFEFF, 0xFEFF),
    (0xFFF9, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0001, 0xE0001),
    (0xE0020, 0xE007F),
];

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
            if c == ' ' || c == '=' || is_render_hazard(c) {
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
            "\u{00A0}".to_owned(),
            "\u{2000}".to_owned(),
            "\u{3000}".to_owned(),
            "\u{200B}".to_owned(),
            "\u{E0041}".to_owned(),
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
        // Two escapes with nothing between them. The seeds above are each isolated by
        // ordinary text, so they say nothing about an escape whose neighbour is another
        // escape — and the backslash's escape is the one whose correctness depends on that
        // neighbour. The cross product is over ONE representative of each family
        // (backslash, the named escapes, the positional `-`, `\xNN`, `\u{...}`) rather than
        // over every seed, which bounds it at 121 members and keeps it readable.
        let families = [
            "\\", "\n", "\r", "\t", " ", "=", "-", "\u{0}", "\u{7F}", "\u{202E}", "\u{2028}",
        ];
        for left in families {
            for right in families {
                corpus.push(format!("{left}{right}"));
            }
        }
        // Values that are ALREADY images of the escape: a backslash followed by an escape
        // body, written literally. Each must come back as the characters it is made of and
        // never as the character that body names — `\x41` is four characters, not `A`.
        for already_an_image in ["\\x41", "\\u{202e}", "\\n", "\\\\n", "\\e", "\\s", "-\\n"] {
            corpus.push(already_an_image.to_owned());
        }
        let mut images: std::collections::HashMap<String, &String> =
            std::collections::HashMap::new();
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
                    && !is_render_hazard(c)),
                "the image carries a hazard: {s:?} -> {escaped:?}"
            );
            // Injectivity, stated rather than inferred: the word the proposition uses is
            // the one the corpus is evidence for. A repeated corpus member is not a
            // collision, so the comparison is between the preimages, not the images.
            let collision = images.insert(escaped.clone(), s);
            assert!(
                !matches!(collision, Some(previous) if previous != s),
                "{collision:?} and {s:?} share the image {escaped:?}"
            );
        }
    }

    /// Every Unicode whitespace codepoint other than U+0020 (which the grammar escapes by
    /// name), and every invisible or bidi format control, leaves the escape spelled out —
    /// never verbatim — and comes back from the inverse.
    #[test]
    fn unicode_whitespace_and_format_controls_are_escaped() {
        let whitespace = [
            0x0085u32, 0x00A0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006,
            0x2007, 0x2008, 0x2009, 0x200A, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000,
        ];
        let format = [
            0x00ADu32, 0x061C, 0x180E, 0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x202A, 0x202B,
            0x202C, 0x202D, 0x202E, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0x2066, 0x2067, 0x2068,
            0x2069, 0x206A, 0x206F, 0xFEFF, 0xFFF9, 0xFFFA, 0xFFFB, 0xE0001, 0xE0020, 0xE007F,
        ];
        for code in whitespace.into_iter().chain(format) {
            let c = char::from_u32(code).expect("scalar value");
            let value = format!("a{c}b");
            let escaped = escape_scalar(&value);
            assert_eq!(
                escaped,
                format!("a\\u{{{code:x}}}b"),
                "U+{code:04X} must be spelled out, not emitted verbatim"
            );
            assert!(
                !is_separator_free(&value),
                "U+{code:04X} cannot render verbatim"
            );
            assert_eq!(unescape_scalar(&escaped).as_deref(), Some(value.as_str()));
        }
    }

    /// A value an enrolled client chooses cannot become a second field for a reader that
    /// splits on Unicode whitespace: the rendered value is ONE token under `split_whitespace`,
    /// which is the splitting rule of Python's `str.split()` and Go's `strings.Fields`, and
    /// not only under the grammar's own `split(' ')`.
    #[test]
    fn a_value_cannot_forge_a_field_for_a_unicode_whitespace_reader() {
        for separator in ['\u{2000}', '\u{00A0}', '\u{3000}', '\u{205F}', '\u{1680}'] {
            let forged = format!("tools/call{separator}authz=refused");
            let rendered = format!("authz_operation={}", escape_scalar(&forged));
            assert_eq!(
                rendered.split_whitespace().count(),
                1,
                "{rendered:?} splits into a second field for a Unicode-whitespace reader"
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

    /// The predicate is the escape's fixed point, not a second opinion about hazards.
    ///
    /// This is the tie that keeps the two from drifting: a hazard added to `escape_scalar`
    /// and not to `is_separator_free` makes some string of the corpus escape to something
    /// other than itself while the predicate still calls it verbatim, and the equality
    /// below fails. The corpus is this test's own, because the question needs members on
    /// BOTH sides of the predicate — ordinary names and tokens that must be fixed points,
    /// which the round-trip corpus has no reason to carry — and one member of every escape
    /// family, which must not be.
    #[test]
    fn is_separator_free_is_exactly_the_escapes_fixed_point() {
        let mut corpus: Vec<String> = vec![
            String::new(),
            "-".to_owned(),
            "-leading".to_owned(),
            "a-b".to_owned(),
            "event".to_owned(),
            "authz_policy_reason".to_owned(),
            "mcp-re.request.accepted".to_owned(),
            "\\".to_owned(),
            "=".to_owned(),
            " ".to_owned(),
            "\n".to_owned(),
            "\r".to_owned(),
            "\t".to_owned(),
            "\u{7F}".to_owned(),
            "\u{85}".to_owned(),
            "\u{2028}".to_owned(),
            "\u{202E}".to_owned(),
            "\u{FEFF}".to_owned(),
        ];
        for code in (0..=0x1Fu32)
            .chain(std::iter::once(0x7F))
            .chain(0x80..=0x9F)
        {
            corpus.push(char::from_u32(code).expect("scalar value").to_string());
        }
        let seeds = corpus.clone();
        for seed in &seeds {
            corpus.push(format!("{seed}tail"));
            corpus.push(format!("head{seed}"));
            corpus.push(format!("head{seed}tail"));
        }
        for s in &corpus {
            assert_eq!(
                is_separator_free(s),
                !s.is_empty() && escape_scalar(s) == *s,
                "the predicate and the escape disagree about {s:?}"
            );
        }
    }

    /// The format controls the earlier hand-picked set missed — Arabic number signs, the
    /// Syriac abbreviation mark, Egyptian hieroglyph format controls, shorthand format
    /// controls and musical symbol format controls — are refused and spelled out, and
    /// ordinary non-format text is left verbatim.
    #[test]
    fn every_format_control_is_a_hazard_and_ordinary_text_is_not() {
        for code in [
            0x0600u32, 0x0605, 0x06DD, 0x070F, 0x0890, 0x0891, 0x08E2, 0x110BD, 0x110CD, 0x13430,
            0x1343F, 0x1BCA0, 0x1BCA3, 0x1D173, 0x1D17A, 0x200B,
        ] {
            let c = char::from_u32(code).expect("scalar value");
            assert!(is_render_hazard(c), "U+{code:04X} is a format control");
            assert_eq!(
                escape_scalar(&format!("a{c}b")),
                format!("a\\u{{{code:x}}}b")
            );
        }
        for c in [
            '\u{00E9}',
            '\u{4E2D}',
            '\u{1F600}',
            '\u{0301}',
            '\u{2010}',
            '\u{2070}',
        ] {
            assert!(!is_render_hazard(c), "{c:?} must be left verbatim");
            assert_eq!(escape_scalar(&c.to_string()), c.to_string());
        }
    }

    /// Both ends of every range in the table are hazards, and the codepoint just outside
    /// each end is a hazard only for a reason other than the table.
    #[test]
    fn the_format_control_table_is_exact_at_every_range_edge() {
        let otherwise = |c: char| c.is_control() || (c.is_whitespace() && c != ' ');
        for &(first, last) in FORMAT_CONTROLS {
            for edge in [first, last] {
                let c = char::from_u32(edge).expect("scalar value");
                assert!(is_render_hazard(c), "U+{edge:04X} ends a format range");
            }
            for outside in [first.checked_sub(1), last.checked_add(1)]
                .into_iter()
                .flatten()
            {
                if let Some(c) = char::from_u32(outside) {
                    if !FORMAT_CONTROLS
                        .iter()
                        .any(|&(a, b)| (a..=b).contains(&outside))
                    {
                        assert_eq!(is_render_hazard(c), otherwise(c), "U+{outside:04X}");
                    }
                }
            }
        }
    }
}
