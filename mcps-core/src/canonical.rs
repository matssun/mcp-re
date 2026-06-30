//! In-house RFC 8785 (JCS) canonicalization with a fail-closed JCS-safe value
//! domain (MCPS_SPEC §4 / ADR-MCPS-005).
//!
//! This is the most security-critical unit in MCP-S: the entire signature
//! scheme depends on a byte-identical preimage. We therefore do NOT depend on an
//! external JCS crate — RFC 8785 canonicalization is implemented here so the
//! preimage is fully auditable, and pinned by committed vectors.
//!
//! # JCS-safe domain (every violation => [`McpsError::CanonicalizationFailed`])
//! 1. **Duplicate object member names** within any object are rejected. We parse
//!    the raw bytes with our own value model that surfaces duplicates — we do NOT
//!    rely on `serde_json::Value`/`Map`, which silently keeps the last duplicate.
//! 2. **Invalid UTF-8** in the input is rejected before parsing; **unpaired
//!    surrogates** expressed via `\uXXXX` escapes are rejected during string
//!    parsing.
//! 3. **Numbers are integers only**, within ±(2^53 − 1) inclusive. Any fraction
//!    (`1.5`), exponent (`1e3`), or out-of-range integer is rejected.
//! 4. **No Unicode normalization / no parser repair** — code points pass through
//!    unchanged.
//!
//! # Canonical output (RFC 8785)
//! - Object members sorted by member name using UTF-16 code-unit ordering.
//! - Integers in shortest decimal form, no leading zeros, no `+`, `-0` => `0`.
//! - Strings escape only `"`, `\`, and control chars U+0000–U+001F (short forms
//!   `\b \t \n \f \r` where applicable, else `\u00xx` lowercase hex). All other
//!   code points are emitted as literal UTF-8 bytes — never `\u`-escaped.
//! - Arrays in order; no insignificant whitespace anywhere; `true`/`false`/`null`
//!   as literals.

use crate::error::McpsError;

/// The maximum safe integer magnitude, ±(2^53 − 1), per the JCS-safe domain.
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991; // 2^53 - 1

/// Maximum container-nesting depth accepted by either recursive parse path
/// (MCPS-073). Matches `serde_json`'s default `recursion_limit` so the raw-bytes
/// parser and the serde-backed verify path reject at the same depth, preserving
/// the raw-path/value-path agreement invariant. Exceeding it fails closed via
/// [`McpsError::CanonicalizationFailed`] rather than overflowing the stack.
const MAX_PARSE_DEPTH: usize = 128;

/// A validated, JCS-safe JSON value. Constructed only by [`parse`], which
/// enforces the JCS-safe domain, so any `JcsValue` is guaranteed canonicalizable.
///
/// Object members retain insertion order here (a `Vec` of pairs); the canonical
/// serializer sorts them by UTF-16 code-unit order at emit time.
#[derive(Debug, Clone, PartialEq)]
pub enum JcsValue {
    /// JSON `null`.
    Null,
    /// JSON `true` / `false`.
    Bool(bool),
    /// A safe integer in ±(2^53 − 1).
    Integer(i64),
    /// A JSON string (already validated UTF-8, surrogate-paired).
    String(String),
    /// A JSON array.
    Array(Vec<JcsValue>),
    /// A JSON object. Keys are unique (duplicates rejected at parse time).
    Object(Vec<(String, JcsValue)>),
}

/// Parse raw JSON bytes, validate against the JCS-safe domain, and emit RFC 8785
/// canonical UTF-8 bytes.
///
/// On any domain violation (duplicate keys, invalid UTF-8, unpaired surrogate,
/// non-integer / out-of-range number, malformed JSON) returns
/// [`McpsError::CanonicalizationFailed`].
pub fn canonicalize(input: &[u8]) -> Result<Vec<u8>, McpsError> {
    let value = parse(input)?;
    canonicalize_value(&value)
}

/// Parse raw JSON bytes into a validated [`JcsValue`] tree, enforcing the full
/// JCS-safe domain (including duplicate-key detection, which MUST happen on this
/// raw-bytes path — `serde_json::Value` cannot represent duplicate keys).
pub fn parse(input: &[u8]) -> Result<JcsValue, McpsError> {
    // (2) Reject invalid UTF-8 up front.
    let text = std::str::from_utf8(input).map_err(|_| McpsError::CanonicalizationFailed)?;
    let mut parser = Parser::new(text);
    parser.skip_ws();
    let value = parser.parse_value()?;
    parser.skip_ws();
    if !parser.at_end() {
        // Trailing non-whitespace content.
        return Err(McpsError::CanonicalizationFailed);
    }
    Ok(value)
}

/// Emit RFC 8785 canonical UTF-8 bytes for an already-validated value tree.
///
/// `JcsValue` is a PUBLIC, hand-constructible enum (its container variants are
/// re-exported at the crate root), so an external caller can build a value tree
/// nested far deeper than any [`parse`]-produced tree (which is already bounded
/// by [`MAX_PARSE_DEPTH`]). The serializer therefore enforces the SAME depth
/// bound itself and fails closed via [`McpsError::CanonicalizationFailed`]
/// rather than overflowing the stack (MCPS-092). In-crate callers always pass a
/// value at depth ≤ [`MAX_PARSE_DEPTH`], so this only ever rejects adversarial
/// externally-constructed trees.
pub fn canonicalize_value(value: &JcsValue) -> Result<Vec<u8>, McpsError> {
    let mut out = String::new();
    write_value(value, 0, &mut out)?;
    Ok(out.into_bytes())
}

/// Canonicalize an already-parsed [`serde_json::Value`] for the later signing
/// layer (MCPS-005) and pipeline (MCPS-008), e.g. after removing
/// `signature.value` from the JSON-RPC object.
///
/// NOTE: `serde_json::Value` cannot represent duplicate object keys (its `Map`
/// silently keeps the last), so this path CANNOT detect duplicate members. The
/// duplicate-key check is therefore the responsibility of the raw-bytes
/// [`parse`]/[`canonicalize`] path, which MUST be run on the original wire bytes
/// before any `serde_json::Value` is derived. This helper still enforces the
/// rest of the JCS-safe domain (integers-only/in-range, valid strings).
pub fn canonicalize_json_value(value: &serde_json::Value) -> Result<Vec<u8>, McpsError> {
    let jcs = from_serde_value(value)?;
    canonicalize_value(&jcs)
}

/// Convert a `serde_json::Value` into a validated [`JcsValue`], enforcing the
/// integer-only/in-range number rule. Cannot detect duplicate keys (see
/// [`canonicalize_json_value`]).
fn from_serde_value(value: &serde_json::Value) -> Result<JcsValue, McpsError> {
    // Bound recursion identically to the raw-bytes path (MCPS-073). depth counts
    // container nesting; the public entry starts at 0.
    from_serde_value_at(value, 0)
}

/// Depth-bounded core of [`from_serde_value`]. `depth` is the container-nesting
/// level of `value`; recursing into a container's children passes `depth + 1`.
fn from_serde_value_at(value: &serde_json::Value, depth: usize) -> Result<JcsValue, McpsError> {
    match value {
        serde_json::Value::Null => Ok(JcsValue::Null),
        serde_json::Value::Bool(b) => Ok(JcsValue::Bool(*b)),
        serde_json::Value::Number(n) => {
            // Reject any non-integer (serde_json without arbitrary_precision
            // models numbers as i64/u64/f64). A float that is not integral, or
            // an integer outside the safe range, is rejected.
            if let Some(i) = n.as_i64() {
                check_safe_integer(i)?;
                Ok(JcsValue::Integer(i))
            } else if let Some(u) = n.as_u64() {
                if u > MAX_SAFE_INTEGER as u64 {
                    return Err(McpsError::CanonicalizationFailed);
                }
                Ok(JcsValue::Integer(u as i64))
            } else {
                // f64 (fractional or exponent or out-of-i64/u64-range) => reject.
                Err(McpsError::CanonicalizationFailed)
            }
        }
        serde_json::Value::String(s) => Ok(JcsValue::String(s.clone())),
        serde_json::Value::Array(items) => {
            if depth >= MAX_PARSE_DEPTH {
                return Err(McpsError::CanonicalizationFailed);
            }
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(from_serde_value_at(item, depth + 1)?);
            }
            Ok(JcsValue::Array(out))
        }
        serde_json::Value::Object(map) => {
            if depth >= MAX_PARSE_DEPTH {
                return Err(McpsError::CanonicalizationFailed);
            }
            let mut out = Vec::with_capacity(map.len());
            for (k, v) in map {
                out.push((k.clone(), from_serde_value_at(v, depth + 1)?));
            }
            Ok(JcsValue::Object(out))
        }
    }
}

fn check_safe_integer(i: i64) -> Result<(), McpsError> {
    if (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&i) {
        Ok(())
    } else {
        Err(McpsError::CanonicalizationFailed)
    }
}

// ---------------------------------------------------------------------------
// Canonical serialization (RFC 8785 output rules).
// ---------------------------------------------------------------------------

/// Recursively emit canonical bytes for `value`. `depth` is the container-nesting
/// level of `value`; recursing into a container's children passes `depth + 1`.
///
/// The bound mirrors the two parse paths ([`Parser::parse_value`] and
/// [`from_serde_value_at`]): a container at or beyond [`MAX_PARSE_DEPTH`] fails
/// closed via [`McpsError::CanonicalizationFailed`] instead of overflowing the
/// stack. This guards the PUBLIC, hand-constructible [`JcsValue`] surface
/// (MCPS-092) — only Array/Object add depth, so non-container leaves never trip
/// it.
fn write_value(value: &JcsValue, depth: usize, out: &mut String) -> Result<(), McpsError> {
    match value {
        JcsValue::Null => out.push_str("null"),
        JcsValue::Bool(true) => out.push_str("true"),
        JcsValue::Bool(false) => out.push_str("false"),
        JcsValue::Integer(i) => write_integer(*i, out),
        JcsValue::String(s) => write_string(s, out),
        JcsValue::Array(items) => {
            if depth >= MAX_PARSE_DEPTH {
                return Err(McpsError::CanonicalizationFailed);
            }
            out.push('[');
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_value(item, depth + 1, out)?;
            }
            out.push(']');
        }
        JcsValue::Object(members) => {
            if depth >= MAX_PARSE_DEPTH {
                return Err(McpsError::CanonicalizationFailed);
            }
            // Sort members by member name using UTF-16 code-unit ordering.
            let mut sorted: Vec<&(String, JcsValue)> = members.iter().collect();
            sorted.sort_by(|a, b| cmp_utf16(&a.0, &b.0));
            // Re-enforce the JCS no-duplicate-key invariant on the PUBLIC,
            // hand-constructible `JcsValue` surface, mirroring the depth-bound
            // treatment above (MCPS-092). `parse()`/`from_serde_value` cannot
            // produce duplicates, but a caller hand-building
            // `JcsValue::Object(vec![("a", _), ("a", _)])` otherwise emits the
            // key twice instead of failing closed. Sorting by key (stability is
            // immaterial here) puts equal keys adjacent, so a single adjacent-pair
            // scan detects them.
            if sorted.windows(2).any(|pair| pair[0].0 == pair[1].0) {
                return Err(McpsError::CanonicalizationFailed);
            }
            out.push('{');
            for (idx, (key, val)) in sorted.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_value(val, depth + 1, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Shortest decimal form: no leading zeros, no `+`, `-0` normalized to `0`.
/// Rust's integer `Display` already yields this for `i64` (and `0` for `-0`,
/// which cannot exist as a distinct `i64`).
fn write_integer(i: i64, out: &mut String) {
    use std::fmt::Write;
    let _ = write!(out, "{i}");
}

/// Escape per RFC 8785: only `"`, `\`, and control chars U+0000–U+001F; short
/// forms where applicable, else `\u00xx` lowercase hex. Everything else literal.
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{0009}' => out.push_str("\\t"),
            '\u{000A}' => out.push_str("\\n"),
            '\u{000C}' => out.push_str("\\f"),
            '\u{000D}' => out.push_str("\\r"),
            c if (c as u32) <= 0x1F => {
                use std::fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Compare two strings by their UTF-16 code-unit sequences (RFC 8785 ordering).
fn cmp_utf16(a: &str, b: &str) -> std::cmp::Ordering {
    let mut ai = a.encode_utf16();
    let mut bi = b.encode_utf16();
    loop {
        match (ai.next(), bi.next()) {
            (Some(x), Some(y)) => match x.cmp(&y) {
                std::cmp::Ordering::Equal => continue,
                other => return other,
            },
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (None, None) => return std::cmp::Ordering::Equal,
        }
    }
}

// ---------------------------------------------------------------------------
// Minimal, fail-closed JSON parser over a validated UTF-8 &str.
// ---------------------------------------------------------------------------

/// A character-level JSON parser. Operates over chars (the input is already
/// validated UTF-8) and enforces the JCS-safe domain during parsing.
struct Parser<'a> {
    chars: Vec<char>,
    pos: usize,
    /// Current container-nesting depth (only objects/arrays add depth). Bounded
    /// by [`MAX_PARSE_DEPTH`] so untrusted deep nesting fails closed instead of
    /// overflowing the stack (MCPS-073).
    depth: usize,
    _marker: std::marker::PhantomData<&'a str>,
}

impl<'a> Parser<'a> {
    fn new(text: &'a str) -> Self {
        Parser {
            chars: text.chars().collect(),
            pos: 0,
            depth: 0,
            _marker: std::marker::PhantomData,
        }
    }

    fn at_end(&self) -> bool {
        self.pos >= self.chars.len()
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.chars.get(self.pos).copied();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }

    fn skip_ws(&mut self) {
        // RFC 8259 insignificant whitespace: space, tab, LF, CR.
        while let Some(c) = self.peek() {
            if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn expect(&mut self, expected: char) -> Result<(), McpsError> {
        match self.bump() {
            Some(c) if c == expected => Ok(()),
            _ => Err(McpsError::CanonicalizationFailed),
        }
    }

    fn parse_value(&mut self) -> Result<JcsValue, McpsError> {
        match self.peek() {
            // Containers add nesting depth; bound it so deeply-nested untrusted
            // input fails closed rather than overflowing the stack (MCPS-073).
            Some('{') | Some('[') => {
                if self.depth >= MAX_PARSE_DEPTH {
                    return Err(McpsError::CanonicalizationFailed);
                }
                self.depth += 1;
                let result = if self.peek() == Some('{') {
                    self.parse_object()
                } else {
                    self.parse_array()
                };
                self.depth -= 1;
                result
            }
            Some('"') => Ok(JcsValue::String(self.parse_string()?)),
            Some('t') | Some('f') => self.parse_bool(),
            Some('n') => self.parse_null(),
            Some(c) if c == '-' || c.is_ascii_digit() => self.parse_number(),
            _ => Err(McpsError::CanonicalizationFailed),
        }
    }

    fn parse_literal(&mut self, literal: &str) -> Result<(), McpsError> {
        for expected in literal.chars() {
            self.expect(expected)?;
        }
        Ok(())
    }

    fn parse_bool(&mut self) -> Result<JcsValue, McpsError> {
        match self.peek() {
            Some('t') => {
                self.parse_literal("true")?;
                Ok(JcsValue::Bool(true))
            }
            Some('f') => {
                self.parse_literal("false")?;
                Ok(JcsValue::Bool(false))
            }
            _ => Err(McpsError::CanonicalizationFailed),
        }
    }

    fn parse_null(&mut self) -> Result<JcsValue, McpsError> {
        self.parse_literal("null")?;
        Ok(JcsValue::Null)
    }

    fn parse_object(&mut self) -> Result<JcsValue, McpsError> {
        self.expect('{')?;
        self.skip_ws();
        let mut members: Vec<(String, JcsValue)> = Vec::new();
        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        if self.peek() == Some('}') {
            self.bump();
            return Ok(JcsValue::Object(members));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some('"') {
                return Err(McpsError::CanonicalizationFailed);
            }
            let key = self.parse_string()?;
            // (1) Duplicate member name within this object => reject.
            if !seen.insert(key.clone()) {
                return Err(McpsError::CanonicalizationFailed);
            }
            self.skip_ws();
            self.expect(':')?;
            self.skip_ws();
            let value = self.parse_value()?;
            members.push((key, value));
            self.skip_ws();
            match self.bump() {
                Some(',') => continue,
                Some('}') => break,
                _ => return Err(McpsError::CanonicalizationFailed),
            }
        }
        Ok(JcsValue::Object(members))
    }

    fn parse_array(&mut self) -> Result<JcsValue, McpsError> {
        self.expect('[')?;
        self.skip_ws();
        let mut items = Vec::new();
        if self.peek() == Some(']') {
            self.bump();
            return Ok(JcsValue::Array(items));
        }
        loop {
            self.skip_ws();
            let value = self.parse_value()?;
            items.push(value);
            self.skip_ws();
            match self.bump() {
                Some(',') => continue,
                Some(']') => break,
                _ => return Err(McpsError::CanonicalizationFailed),
            }
        }
        Ok(JcsValue::Array(items))
    }

    fn parse_string(&mut self) -> Result<String, McpsError> {
        self.expect('"')?;
        let mut out = String::new();
        loop {
            match self.bump() {
                None => return Err(McpsError::CanonicalizationFailed),
                Some('"') => break,
                Some('\\') => {
                    let esc = self.bump().ok_or(McpsError::CanonicalizationFailed)?;
                    match esc {
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        '/' => out.push('/'),
                        'b' => out.push('\u{0008}'),
                        'f' => out.push('\u{000C}'),
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        'u' => {
                            let cp = self.parse_unicode_escape()?;
                            out.push(cp);
                        }
                        _ => return Err(McpsError::CanonicalizationFailed),
                    }
                }
                Some(c) => {
                    // Reject raw control characters U+0000–U+001F in strings
                    // (must be escaped in valid JSON).
                    if (c as u32) <= 0x1F {
                        return Err(McpsError::CanonicalizationFailed);
                    }
                    out.push(c);
                }
            }
        }
        Ok(out)
    }

    /// Parse a `\uXXXX` escape (the `\u` already consumed), handling surrogate
    /// pairs and rejecting unpaired surrogates.
    fn parse_unicode_escape(&mut self) -> Result<char, McpsError> {
        let first = self.read_hex4()?;
        if (0xD800..=0xDBFF).contains(&first) {
            // High surrogate: a low surrogate MUST follow via `\uXXXX`.
            if self.bump() != Some('\\') {
                return Err(McpsError::CanonicalizationFailed);
            }
            if self.bump() != Some('u') {
                return Err(McpsError::CanonicalizationFailed);
            }
            let second = self.read_hex4()?;
            if !(0xDC00..=0xDFFF).contains(&second) {
                return Err(McpsError::CanonicalizationFailed);
            }
            let combined =
                0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00);
            char::from_u32(combined).ok_or(McpsError::CanonicalizationFailed)
        } else if (0xDC00..=0xDFFF).contains(&first) {
            // Lone low surrogate => unpaired => reject.
            Err(McpsError::CanonicalizationFailed)
        } else {
            char::from_u32(first).ok_or(McpsError::CanonicalizationFailed)
        }
    }

    fn read_hex4(&mut self) -> Result<u32, McpsError> {
        let mut value = 0u32;
        for _ in 0..4 {
            let c = self.bump().ok_or(McpsError::CanonicalizationFailed)?;
            let digit = c.to_digit(16).ok_or(McpsError::CanonicalizationFailed)?;
            value = value * 16 + digit;
        }
        Ok(value)
    }

    /// Parse a JSON number, enforcing the integers-only / in-range rule. Any
    /// fraction or exponent is rejected.
    fn parse_number(&mut self) -> Result<JcsValue, McpsError> {
        let start = self.pos;
        if self.peek() == Some('-') {
            self.bump();
        }
        // Integer part: a single 0, or [1-9][0-9]* (no leading zeros).
        match self.peek() {
            Some('0') => {
                self.bump();
            }
            Some(c) if ('1'..='9').contains(&c) => {
                self.bump();
                while let Some(d) = self.peek() {
                    if d.is_ascii_digit() {
                        self.bump();
                    } else {
                        break;
                    }
                }
            }
            _ => return Err(McpsError::CanonicalizationFailed),
        }
        // Reject fraction or exponent => non-integer number.
        if matches!(self.peek(), Some('.') | Some('e') | Some('E')) {
            return Err(McpsError::CanonicalizationFailed);
        }
        let token: String = self.chars[start..self.pos].iter().collect();
        let parsed: i64 = token
            .parse()
            .map_err(|_| McpsError::CanonicalizationFailed)?;
        check_safe_integer(parsed)?;
        Ok(JcsValue::Integer(parsed))
    }
}

#[cfg(test)]
mod tests {
    use super::canonicalize;
    use super::canonicalize_json_value;
    use super::canonicalize_value;
    use super::JcsValue;
    use super::MAX_PARSE_DEPTH;
    use crate::error::McpsError;

    fn canon_str(input: &str) -> Result<String, McpsError> {
        canonicalize(input.as_bytes()).map(|b| String::from_utf8(b).expect("utf8"))
    }

    // ---- JCS-01..08 from MCPS_SPEC §10 ----

    #[test]
    fn jcs_01_duplicate_key_rejected() {
        let err = canonicalize(br#"{"a":1,"a":2}"#).unwrap_err();
        assert_eq!(err, McpsError::CanonicalizationFailed);
    }

    #[test]
    fn jcs_01_nested_duplicate_key_rejected() {
        let err = canonicalize(br#"{"outer":{"a":1,"a":2}}"#).unwrap_err();
        assert_eq!(err, McpsError::CanonicalizationFailed);
    }

    #[test]
    fn jcs_02_unsafe_integer_value_rejected() {
        let err = canonicalize(b"9007199254740993").unwrap_err();
        assert_eq!(err, McpsError::CanonicalizationFailed);
    }

    #[test]
    fn jcs_02_unsafe_integer_in_object_rejected() {
        let err = canonicalize(br#"{"id":9007199254740993}"#).unwrap_err();
        assert_eq!(err, McpsError::CanonicalizationFailed);
    }

    #[test]
    fn jcs_03_unsafe_integer_nested_in_array_rejected() {
        let err = canonicalize(br#"{"args":[1,2,9007199254740993]}"#).unwrap_err();
        assert_eq!(err, McpsError::CanonicalizationFailed);
    }

    #[test]
    fn safe_integer_boundary_accepted() {
        // 2^53 - 1 is the inclusive max.
        assert_eq!(canon_str("9007199254740991").unwrap(), "9007199254740991");
        assert_eq!(canon_str("-9007199254740991").unwrap(), "-9007199254740991");
    }

    #[test]
    fn jcs_04_non_integer_number_rejected() {
        let err = canonicalize(b"1.5").unwrap_err();
        assert_eq!(err, McpsError::CanonicalizationFailed);
    }

    /// ADR-MCPS-037 / decision B.1 — the int53 scheme (`mcps-jcs-int53-json-v1`)
    /// does NOT protect signed payloads containing common MCP fractional numbers.
    /// These exact examples (a temperature, a price) fail closed; the limitation
    /// is machine-checked here, not merely documented.
    #[test]
    fn int53_documented_float_limitation_rejects_common_mcp_floats() {
        for float in ["0.7", "19.99", "-0.0", "55.7047", "0.1"] {
            assert_eq!(
                canonicalize(float.as_bytes()).unwrap_err(),
                McpsError::CanonicalizationFailed,
                "{float} must fail closed under the int53 domain"
            );
        }
        // …and inside a realistic signed-payload arguments object.
        assert_eq!(
            canonicalize(br#"{"temperature":0.7,"price":19.99}"#).unwrap_err(),
            McpsError::CanonicalizationFailed
        );
    }

    #[test]
    fn jcs_05_exponent_number_rejected() {
        assert_eq!(canonicalize(b"1e3").unwrap_err(), McpsError::CanonicalizationFailed);
        assert_eq!(canonicalize(b"1E3").unwrap_err(), McpsError::CanonicalizationFailed);
    }

    #[test]
    fn jcs_06_unpaired_high_surrogate_rejected() {
        let err = canonicalize(br#""\uD800""#).unwrap_err();
        assert_eq!(err, McpsError::CanonicalizationFailed);
    }

    #[test]
    fn jcs_06_unpaired_low_surrogate_rejected() {
        let err = canonicalize(br#""\uDC00""#).unwrap_err();
        assert_eq!(err, McpsError::CanonicalizationFailed);
    }

    #[test]
    fn valid_surrogate_pair_accepted() {
        // 😀 = U+1F600 GRINNING FACE; must decode and emit literal UTF-8.
        let out = canon_str(r#""😀""#).unwrap();
        assert_eq!(out, "\"\u{1F600}\"");
    }

    #[test]
    fn jcs_07_invalid_utf8_rejected() {
        // 0xFF is never valid UTF-8.
        let err = canonicalize(&[0x22, 0xFF, 0x22]).unwrap_err();
        assert_eq!(err, McpsError::CanonicalizationFailed);
    }

    #[test]
    fn jcs_08_large_id_as_string_ok() {
        let out = canon_str(r#"{"id":"9007199254740993"}"#).unwrap();
        assert_eq!(out, r#"{"id":"9007199254740993"}"#);
    }

    // ---- Golden canonicalization vectors ----

    #[test]
    fn golden_object_keys_sorted() {
        assert_eq!(canon_str(r#"{"b":1,"a":2}"#).unwrap(), r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn golden_nested_object_keys_sorted() {
        let input = r#"{"z":{"y":1,"x":2},"a":3}"#;
        assert_eq!(canon_str(input).unwrap(), r#"{"a":3,"z":{"x":2,"y":1}}"#);
    }

    #[test]
    fn golden_non_ascii_char_stays_literal() {
        // "é" (U+00E9) must NOT be \u-escaped; emitted as literal UTF-8.
        let out = canonicalize(r#"{"name":"é"}"#.as_bytes()).unwrap();
        assert_eq!(out, r#"{"name":"é"}"#.as_bytes());
        // Must contain the raw 2-byte UTF-8 for é (0xC3 0xA9), and no "\\u".
        assert!(out.windows(2).any(|w| w == [0xC3, 0xA9]));
        assert!(!String::from_utf8(out).unwrap().contains("\\u"));
    }

    #[test]
    fn golden_control_char_tab_becomes_short_escape() {
        // A tab escaped in the input as \t canonicalizes to the short form \t.
        let out = canon_str(r#"{"k":"a\tb"}"#).unwrap();
        assert_eq!(out, r#"{"k":"a\tb"}"#);
    }

    #[test]
    fn raw_control_char_in_string_rejected() {
        // A literal (unescaped) tab byte inside a JSON string is invalid JSON.
        let err = canonicalize(b"\"a\tb\"").unwrap_err();
        assert_eq!(err, McpsError::CanonicalizationFailed);
    }

    #[test]
    fn golden_other_control_char_lowercase_hex() {
        // U+0001 has no short form; input carries it as the JSON escape
        // backslash-u-0001 and canonicalizes to lowercase-hex \u0001.
        // Bytes are built explicitly so no raw control byte is present.
        let bs = b'\\';
        let q = b'"';
        let input = [q, bs, b'u', b'0', b'0', b'0', b'1', q];
        let out = canonicalize(&input).unwrap();
        assert_eq!(out, &[q, bs, b'u', b'0', b'0', b'0', b'1', q]);
    }

    #[test]
    fn golden_escaped_quote_and_backslash() {
        let out = canon_str(r#""a\"b\\c""#).unwrap();
        assert_eq!(out, r#""a\"b\\c""#);
    }

    #[test]
    fn golden_negative_zero_normalized() {
        assert_eq!(canon_str("-0").unwrap(), "0");
        assert_eq!(canon_str(r#"{"v":-0}"#).unwrap(), r#"{"v":0}"#);
    }

    #[test]
    fn golden_literals_and_array_no_whitespace() {
        let input = r#"  [ true , false , null , 1 , "x" ]  "#;
        assert_eq!(canon_str(input).unwrap(), r#"[true,false,null,1,"x"]"#);
    }

    #[test]
    fn golden_empty_object_and_array() {
        assert_eq!(canon_str("{}").unwrap(), "{}");
        assert_eq!(canon_str("[]").unwrap(), "[]");
    }

    #[test]
    fn golden_whitespace_insignificant() {
        let input = "{\n  \"b\" : 2 ,\n  \"a\" : 1\n}";
        assert_eq!(canon_str(input).unwrap(), r#"{"a":1,"b":2}"#);
    }

    #[test]
    fn leading_zero_integer_rejected() {
        let err = canonicalize(b"01").unwrap_err();
        assert_eq!(err, McpsError::CanonicalizationFailed);
    }

    #[test]
    fn plus_sign_rejected() {
        let err = canonicalize(b"+1").unwrap_err();
        assert_eq!(err, McpsError::CanonicalizationFailed);
    }

    #[test]
    fn trailing_garbage_rejected() {
        let err = canonicalize(br#"{"a":1} extra"#).unwrap_err();
        assert_eq!(err, McpsError::CanonicalizationFailed);
    }

    #[test]
    fn trailing_comma_rejected() {
        assert_eq!(canonicalize(br#"{"a":1,}"#).unwrap_err(), McpsError::CanonicalizationFailed);
        assert_eq!(canonicalize(br#"[1,2,]"#).unwrap_err(), McpsError::CanonicalizationFailed);
    }

    // ---- Determinism ----

    #[test]
    fn determinism_canonicalize_is_idempotent() {
        let input = r#"{"b":[3,2,1],"a":{"d":1,"c":"é\t"},"id":"123"}"#;
        let once = canonicalize(input.as_bytes()).unwrap();
        let twice = canonicalize(&once).unwrap();
        assert_eq!(once, twice);
    }

    // ---- serde_json::Value helper (for MCPS-005/008) ----

    #[test]
    fn json_value_helper_canonicalizes_and_sorts() {
        let v: serde_json::Value = serde_json::from_str(r#"{"b":1,"a":2}"#).unwrap();
        let out = canonicalize_json_value(&v).unwrap();
        assert_eq!(out, br#"{"a":2,"b":1}"#);
    }

    #[test]
    fn json_value_helper_rejects_non_integer() {
        let v: serde_json::Value = serde_json::from_str("1.5").unwrap();
        assert_eq!(canonicalize_json_value(&v).unwrap_err(), McpsError::CanonicalizationFailed);
    }

    #[test]
    fn json_value_helper_rejects_unsafe_integer() {
        let v: serde_json::Value = serde_json::from_str(r#"{"id":9007199254740993}"#).unwrap();
        assert_eq!(canonicalize_json_value(&v).unwrap_err(), McpsError::CanonicalizationFailed);
    }

    #[test]
    fn json_value_helper_matches_raw_path_for_valid_input() {
        let input = r#"{"z":1,"a":{"y":"é","x":2},"id":"9007199254740993"}"#;
        let raw = canonicalize(input.as_bytes()).unwrap();
        let v: serde_json::Value = serde_json::from_str(input).unwrap();
        let via_value = canonicalize_json_value(&v).unwrap();
        assert_eq!(raw, via_value);
    }

    // ---- Recursion-depth bound (MCPS-073) ----
    //
    // Deeply-nested untrusted JSON must fail closed via CanonicalizationFailed
    // rather than overflow the stack. The bound matches serde_json's default
    // recursion_limit (128) so the raw-bytes parser and the serde-backed verify
    // path reject at the same depth, preserving raw-path/value-path agreement.

    #[test]
    fn parse_depth_limit_rejects_over_max() {
        // MAX_PARSE_DEPTH + 1 = 129 nested arrays must be rejected.
        let s = "[".repeat(MAX_PARSE_DEPTH + 1) + &"]".repeat(MAX_PARSE_DEPTH + 1);
        assert_eq!(
            canonicalize(s.as_bytes()).unwrap_err(),
            McpsError::CanonicalizationFailed
        );
    }

    #[test]
    fn parse_depth_limit_allows_exactly_max() {
        // Exactly MAX_PARSE_DEPTH = 128 nested arrays is the inclusive boundary.
        let s = "[".repeat(MAX_PARSE_DEPTH) + &"]".repeat(MAX_PARSE_DEPTH);
        canon_str(&s).expect("depth at the inclusive boundary must canonicalize");
    }

    #[test]
    fn parse_depth_limit_rejects_nested_objects() {
        // MAX_PARSE_DEPTH + 1 = 129 nested single-member objects must be rejected
        // on the object path. The input is well-formed JSON
        // (`{"a":{"a":...{"a":1}...}}`); its ONLY problem is nesting depth, so the
        // rejection genuinely exercises the object recursion-depth bound rather
        // than tripping on a malformed token.
        let n = MAX_PARSE_DEPTH + 1;
        let s = "{\"a\":".repeat(n) + "1" + &"}".repeat(n);
        assert_eq!(
            canonicalize(s.as_bytes()).unwrap_err(),
            McpsError::CanonicalizationFailed
        );
    }

    #[test]
    fn parse_depth_limit_allows_exactly_max_objects() {
        // Exactly MAX_PARSE_DEPTH = 128 nested single-member objects is the
        // inclusive boundary: well-formed JSON within the bound must canonicalize.
        // Paired with `parse_depth_limit_rejects_nested_objects`, this proves the
        // rejection above is due to depth, not malformedness.
        let n = MAX_PARSE_DEPTH;
        let s = "{\"a\":".repeat(n) + "1" + &"}".repeat(n);
        canon_str(&s).expect("object depth at the inclusive boundary must canonicalize");
    }

    #[test]
    fn canonicalize_json_value_rejects_over_max_depth() {
        // Build a 129-deep serde_json::Value programmatically (no parsing).
        let mut v = serde_json::Value::Array(vec![]);
        for _ in 0..MAX_PARSE_DEPTH {
            v = serde_json::Value::Array(vec![v]);
        }
        assert_eq!(
            canonicalize_json_value(&v).unwrap_err(),
            McpsError::CanonicalizationFailed
        );
    }

    #[test]
    fn parse_depth_pathological_input_fails_clean() {
        // Without the depth bound this would recurse 100_000 deep and abort the
        // process (SIGABRT) via stack overflow. With the bound it must return a
        // clean CanonicalizationFailed long before exhausting the stack.
        let n = 100_000;
        let s = "[".repeat(n) + &"]".repeat(n);
        assert_eq!(
            canonicalize(s.as_bytes()).unwrap_err(),
            McpsError::CanonicalizationFailed
        );
    }

    // ---- Serializer recursion bound on the PUBLIC JcsValue surface (MCPS-092) ----
    //
    // `JcsValue`'s container variants are public and re-exported at the crate
    // root, so an external caller can hand-construct a value tree FAR deeper than
    // any parse path can produce (parse is already capped at MAX_PARSE_DEPTH).
    // The serializer `write_value` must enforce the same bound and fail closed,
    // not overflow the stack. These tests drive that bound directly via the
    // public `canonicalize_value`.

    /// Build a value tree of exactly `n` nested `JcsValue::Array` containers
    /// around an `Integer(0)` leaf, BOTTOM-UP and iteratively (heap, no stack
    /// recursion) so neither construction nor this test overflows. The outermost
    /// array is the one handed to `canonicalize_value` (serializer depth 0); the
    /// innermost is reached at serializer depth `n - 1`, matching the parser's
    /// depth accounting where `n` brackets reach depth `n - 1`.
    fn nested_array(n: usize) -> JcsValue {
        let mut v = JcsValue::Integer(0);
        for _ in 0..n {
            v = JcsValue::Array(vec![v]);
        }
        v
    }

    #[test]
    fn write_value_depth_limit_rejects_deep_public_jcs_value() {
        // A hand-built JcsValue far deeper than MAX_PARSE_DEPTH (128). WITHOUT
        // the serializer bound, `write_value` would recurse to this depth and
        // overflow the stack (SIGABRT, aborting the whole process). WITH the
        // bound, it returns CanonicalizationFailed after ~128 frames — long
        // before any real stack pressure — so the asserting test runs clean.
        //
        // Depth is 5_000 (≫ 128), not 100_000: `JcsValue`'s derived `Drop` is
        // itself recursive, so a 100_000-deep tree overflows the stack on test
        // TEARDOWN (observed: SIGABRT in Drop, not in write_value). 5_000 proves
        // the bound trips (it fires at 128) while dropping safely. The depth is
        // ~39× the bound, so the bound is the only thing preventing overflow.
        let deep = nested_array(5_000);
        assert_eq!(
            canonicalize_value(&deep).unwrap_err(),
            McpsError::CanonicalizationFailed
        );
    }

    #[test]
    fn write_value_depth_limit_rejects_just_over_max() {
        // MAX_PARSE_DEPTH + 1 nested arrays: the smallest tree that must be
        // rejected. Pairs with the exactly-max test below to prove the bound
        // trips on depth, at exactly the parse-path boundary.
        let just_over = nested_array(MAX_PARSE_DEPTH + 1);
        assert_eq!(
            canonicalize_value(&just_over).unwrap_err(),
            McpsError::CanonicalizationFailed
        );
    }

    #[test]
    fn write_value_depth_limit_allows_exactly_max() {
        // MAX_PARSE_DEPTH nested arrays is the inclusive boundary and must
        // serialize, matching the parse path's exactly-max acceptance. This
        // proves the rejection above is due to depth, not a blanket failure.
        let at_max = nested_array(MAX_PARSE_DEPTH);
        canonicalize_value(&at_max)
            .expect("serializer depth at the inclusive boundary must canonicalize");
    }

    #[test]
    fn write_value_rejects_hand_built_object_with_duplicate_keys() {
        // The PUBLIC `JcsValue` surface is hand-constructible, so a caller can
        // build an Object that violates the JCS no-duplicate-key invariant that
        // `parse()`/`from_serde_value` would otherwise guarantee. The serializer
        // must re-enforce it (MCPS-092), mirroring the depth-bound treatment,
        // rather than emitting the duplicated key twice.
        let dup = JcsValue::Object(vec![
            ("a".to_string(), JcsValue::Integer(1)),
            ("a".to_string(), JcsValue::Integer(2)),
        ]);
        assert_eq!(
            canonicalize_value(&dup).unwrap_err(),
            McpsError::CanonicalizationFailed
        );
    }

    #[test]
    fn write_value_accepts_hand_built_object_with_distinct_keys() {
        // Pairs with the duplicate-key rejection above: an Object with distinct
        // keys must still canonicalize, proving the rejection is keyed on
        // duplication, not a blanket Object failure.
        let ok = JcsValue::Object(vec![
            ("a".to_string(), JcsValue::Integer(1)),
            ("b".to_string(), JcsValue::Integer(2)),
        ]);
        canonicalize_value(&ok).expect("distinct-keyed object must canonicalize");
    }
}
