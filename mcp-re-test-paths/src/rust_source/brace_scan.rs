// SPDX-License-Identifier: Apache-2.0
//! Which characters of a Rust source are CODE.
//!
//! One fact, and it is lexical: a `{` inside a string, a raw string, a character literal or
//! a comment is not a brace. Separate from [`super`], which owns a different fact — where a
//! test region begins and ends. The region model asks this scanner a question; it does not
//! reimplement the answer, and this scanner knows nothing about `#[cfg(test)]`.
//!
//! The split is the invalidation boundary. A new literal form is a change here and cannot
//! alter the region rule; a change to which attributes open a region cannot alter what
//! counts as a brace.
//!
//! Mirrors `scripts/module_size_gate.py::_BraceScan`, which is the same definition on the
//! Python side. The two decide the same fact for different gates and must not drift.

/// Where a brace-counting scan currently is, carried ACROSS lines.
///
/// Per-line state was the second defect in this file, and it is the same class as the
/// truncation the module docs describe: a scanner that forgets at every newline reports
/// braces that are inside a literal. A raw byte string holding JSON —
/// `br#"{"error":{"data":{...}}}"#`, which `execution_contract.rs` writes over five lines —
/// closed a `#[cfg(test)]` region three lines early, and twenty-seven lines of test code
/// were then measured as production by every guard built on this primitive.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Ordinary code.
    Code,
    /// Inside `"…"`. A `\\` escapes the next character; a newline does not end it.
    Str,
    /// Inside `r"…"` / `r#"…"#` / `b`-prefixed, carrying the hash count that closes it.
    /// There are no escapes here at all, which is exactly why the ordinary scanner
    /// mis-read one.
    Raw(usize),
    /// Inside `/* … */`, carrying the nesting depth Rust permits.
    Block(usize),
}

/// A brace-counting scan over a sequence of lines.
///
/// It emits only the code characters, so `{` and `}` inside a literal or a comment never
/// reach the caller's count.
pub(super) struct BraceScan {
    mode: Mode,
}

impl BraceScan {
    pub(super) fn new() -> Self {
        BraceScan { mode: Mode::Code }
    }

    /// `line` with literals and comments blanked, continuing whatever `line` began inside.
    pub(super) fn feed(&mut self, line: &str) -> String {
        let chars: Vec<char> = line.chars().collect();
        let mut out = String::with_capacity(line.len());
        let mut i = 0usize;
        while i < chars.len() {
            i = match self.mode {
                Mode::Code => self.step_code(&chars, i, &mut out),
                Mode::Str => self.step_str(&chars, i),
                Mode::Raw(hashes) => self.step_raw(&chars, i, hashes),
                Mode::Block(depth) => self.step_block(&chars, i, depth),
            };
        }
        out
    }

    /// One step in code. Returns the next index; a line comment consumes the rest.
    fn step_code(&mut self, chars: &[char], i: usize, out: &mut String) -> usize {
        let c = at(chars, i);
        if c == '/' && at(chars, i.saturating_add(1)) == '/' {
            return chars.len();
        }
        if c == '/' && at(chars, i.saturating_add(1)) == '*' {
            self.mode = Mode::Block(1);
            return i.saturating_add(2);
        }
        if let Some(next) = self.open_raw(chars, i) {
            return next;
        }
        if c == '"' {
            self.mode = Mode::Str;
            return i.saturating_add(1);
        }
        if c == '\'' {
            return skip_char_literal(chars, i, out);
        }
        out.push(c);
        i.saturating_add(1)
    }

    /// If a raw-string opener starts at `i`, enter it and return the index past the quote.
    ///
    /// The prefix is `r` or `br`, and it must not be the tail of an identifier — `for` and
    /// `char` end in those letters, and treating one as an opener would swallow the file.
    fn open_raw(&mut self, chars: &[char], i: usize) -> Option<usize> {
        if i > 0 && is_ident(at(chars, i.saturating_sub(1))) {
            return None;
        }
        let mut j = i;
        if at(chars, j) == 'b' {
            j = j.saturating_add(1);
        }
        if at(chars, j) != 'r' {
            return None;
        }
        j = j.saturating_add(1);
        let start_hashes = j;
        while at(chars, j) == '#' {
            j = j.saturating_add(1);
        }
        if at(chars, j) != '"' {
            return None;
        }
        self.mode = Mode::Raw(j.saturating_sub(start_hashes));
        Some(j.saturating_add(1))
    }

    /// One step inside `"…"`.
    fn step_str(&mut self, chars: &[char], i: usize) -> usize {
        match at(chars, i) {
            '\\' => i.saturating_add(2),
            '"' => {
                self.mode = Mode::Code;
                i.saturating_add(1)
            }
            _ => i.saturating_add(1),
        }
    }

    /// One step inside a raw string: only `"` followed by exactly `hashes` `#` closes it.
    fn step_raw(&mut self, chars: &[char], i: usize, hashes: usize) -> usize {
        if at(chars, i) != '"' {
            return i.saturating_add(1);
        }
        let mut seen = 0usize;
        while seen < hashes && at(chars, i.saturating_add(1).saturating_add(seen)) == '#' {
            seen = seen.saturating_add(1);
        }
        if seen < hashes {
            return i.saturating_add(1);
        }
        self.mode = Mode::Code;
        i.saturating_add(1).saturating_add(hashes)
    }

    /// One step inside `/* … */`, which nests in Rust.
    fn step_block(&mut self, chars: &[char], i: usize, depth: usize) -> usize {
        let (c, n) = (at(chars, i), at(chars, i.saturating_add(1)));
        if c == '/' && n == '*' {
            self.mode = Mode::Block(depth.saturating_add(1));
            return i.saturating_add(2);
        }
        if c == '*' && n == '/' {
            self.mode = closing_block(depth);
            return i.saturating_add(2);
        }
        i.saturating_add(1)
    }
}

/// The mode a `*/` leaves behind at nesting `depth`: the outermost close returns to code.
fn closing_block(depth: usize) -> Mode {
    if depth <= 1 {
        Mode::Code
    } else {
        Mode::Block(depth.saturating_sub(1))
    }
}

/// The character at `i`, or `\0` past the end. Keeps every lookahead total.
fn at(chars: &[char], i: usize) -> char {
    chars.get(i).copied().unwrap_or('\0')
}

/// Whether `c` may appear inside an identifier — used to tell `r"…"` from the `r` of `for`.
fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Skip a character literal at `i`, or emit the `\'` as a lifetime tick and move on.
///
/// `'{'` is a brace this scan must not count; `'a` is a lifetime carrying nothing.
fn skip_char_literal(chars: &[char], i: usize, out: &mut String) -> usize {
    let body = i.saturating_add(1);
    if at(chars, body) == '\\' {
        // An escape of unknown width: scan to the closing tick.
        let mut j = body.saturating_add(2);
        while j < chars.len() && at(chars, j) != '\'' {
            j = j.saturating_add(1);
        }
        return j.saturating_add(1);
    }
    if at(chars, body.saturating_add(1)) == '\'' {
        return body.saturating_add(2);
    }
    out.push('\'');
    i.saturating_add(1)
}

#[cfg(test)]
mod tests {
    use super::BraceScan;

    /// Braces inside every literal form are invisible to the count; braces in code are not.
    #[test]
    fn only_code_braces_survive() {
        let mut scan = BraceScan::new();
        assert_eq!(
            scan.feed(r#"fn f() { let s = "{{{"; }"#),
            "fn f() { let s = ; }"
        );
    }

    /// A raw string spans lines and has no escapes; the scan must carry that across.
    #[test]
    fn a_raw_string_is_carried_across_lines() {
        let mut scan = BraceScan::new();
        assert_eq!(scan.feed(r##"let b = br#"{{{"##), "let b = ");
        assert_eq!(scan.feed(r##"still inside } {"##), "");
        assert_eq!(scan.feed(r##""#; let x = {"##), "; let x = {");
    }

    /// A block comment nests and spans lines.
    #[test]
    fn a_nested_block_comment_is_carried_across_lines() {
        let mut scan = BraceScan::new();
        assert_eq!(scan.feed("a /* } /* }"), "a ");
        assert_eq!(scan.feed("} */ } */ b {"), " b {");
    }

    /// An escaped quote does not end an ordinary string.
    #[test]
    fn an_escaped_quote_does_not_end_a_string() {
        let mut scan = BraceScan::new();
        assert_eq!(scan.feed(r#"let s = "a\"{"; {"#), "let s = ; {");
    }

    /// A lifetime tick is not a character literal, and a braced character literal is.
    #[test]
    fn a_lifetime_is_not_a_char_literal() {
        let mut scan = BraceScan::new();
        assert_eq!(
            scan.feed("fn f<'a>(c: char) { let _ = ('{', c); }"),
            "fn f<'a>(c: char) { let _ = (, c); }"
        );
    }

    /// `for` ends in `r`, and `char` in `r`-adjacent letters; neither opens a raw string.
    #[test]
    fn an_identifier_tail_does_not_open_a_raw_string() {
        let mut scan = BraceScan::new();
        assert_eq!(scan.feed(r#"for x in y {"#), "for x in y {");
    }
}
