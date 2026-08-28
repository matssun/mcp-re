// SPDX-License-Identifier: Apache-2.0
//! The production half of a Rust source, for the gates that scan source text.
//!
//! Several architectural guards in this workspace assert a property over *production* code
//! by reading a `.rs` file and looking for forbidden spellings. Every one of them needs the
//! same primitive — the source with its test-only regions removed — and every one of them
//! got it wrong in the same way: truncating at the first `#[cfg(test)]`.
//!
//! # Why truncation is unsound for these guards
//!
//! Truncation states "test code begins at the first test attribute and never ends". Rust
//! says otherwise on two counts:
//!
//! - a `#[cfg(test)]` attribute may sit on an inline helper hundreds of lines above the
//!   real test module — `trust_plane.rs:78`, `signing_plane.rs:62`, `tls_plane.rs:137` and
//!   `ocsp.rs:248` all do this;
//! - production items may legally appear *after* a `#[cfg(test)] mod tests { … }` region,
//!   and nothing in this repository forbids it.
//!
//! Under either shape a truncating guard stops scanning early and reports a clean pass over
//! code it never read. That is the failure mode ADR-MCPRE-061 names: a green that measured
//! nothing. `scripts/module_size_gate.py` already measures the same way for the same
//! reason; this is that definition on the Rust side, so the two cannot drift.
//!
//! # The definition
//!
//! A **test region** opens at an attribute matching `^#[cfg(test` or `^#[cfg(all(test`
//! and closes with the item that attribute introduces — a braced item at its matching
//! close, a `;`-terminated item at that semicolon. Counting resumes immediately after.
//! Everything outside every region is production.

/// Whether `line` opens a test region.
///
/// Both `#[cfg(test)]` and the `#[cfg(all(test, unix))]` family open one. Matching only the
/// narrow spelling is what let `#[cfg(all(test, unix))]` modules be measured as production
/// during an earlier census.
fn opens_test_region(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("#[cfg(test") || t.starts_with("#[cfg(all(test")
}

/// `line` with string literals and line comments blanked, so their braces do not count.
fn brace_significant(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    let mut in_string = false;
    while let Some(c) = chars.next() {
        if in_string {
            in_string = still_in_string(c, &mut chars);
            continue;
        }
        match c {
            '"' => in_string = true,
            '/' if chars.peek() == Some(&'/') => break,
            _ => out.push(c),
        }
    }
    out
}

/// Whether the scan is still inside a string literal after consuming `c`.
///
/// A backslash escapes exactly one following character and never ends the string, so the
/// escaped character is consumed here rather than examined by the caller.
fn still_in_string(c: char, chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> bool {
    match c {
        '\\' => {
            chars.next();
            true
        }
        '"' => false,
        _ => true,
    }
}

/// The lines of `source`, 1-indexed, that lie outside every test region.
///
/// The line numbers are kept because a guard that reports a violation has to be able to
/// name where it is, and a filtered copy of the text cannot.
#[must_use]
pub fn production_lines(source: &str) -> Vec<(usize, &str)> {
    let lines: Vec<&str> = source.lines().collect();
    let mut kept: Vec<(usize, &str)> = Vec::new();
    let mut i = 0usize;
    while i < lines.len() {
        let Some(line) = lines.get(i) else { break };
        if !opens_test_region(line) {
            // `saturating_add`, not `+`: the line NUMBER is 1-indexed and `i` is bounded by
            // `lines.len()`, so overflow is unreachable — but "unreachable" is the sort of
            // claim ADR-MCPRE-061 §6.4 asks to be written down rather than assumed, and
            // saturating is the honest algebra for a display index.
            kept.push((i.saturating_add(1), line));
            i = i.saturating_add(1);
            continue;
        }
        i = end_of_region(&lines, i);
    }
    kept
}

/// The index just past the region opened at `start`.
///
/// Scans forward for the item's opening brace. An attributed item with no brace before a
/// `;` — `#[cfg(test)] use super::*;` — is a single-line region and ends at that semicolon.
fn end_of_region(lines: &[&str], start: usize) -> usize {
    let mut depth: i64 = 0;
    let mut opened = false;
    let mut i = start;
    while i < lines.len() {
        let Some(raw) = lines.get(i) else { break };
        let code = brace_significant(raw);
        let opens = i64::try_from(code.matches('{').count()).unwrap_or(i64::MAX);
        let closes = i64::try_from(code.matches('}').count()).unwrap_or(i64::MAX);
        depth = depth.saturating_add(opens).saturating_sub(closes);
        if code.contains('{') {
            opened = true;
        }
        i = i.saturating_add(1);
        if opened && depth <= 0 {
            return i;
        }
        if !opened && code.trim_end().ends_with(';') {
            return i;
        }
    }
    i
}

/// `source` with every test region removed, blank lines standing in for the elided ones.
///
/// Blanks rather than deletion so that a `contains` check over the result cannot join two
/// production lines that were never adjacent, and so line counts stay comparable.
#[must_use]
pub fn production_half(source: &str) -> String {
    let kept: std::collections::BTreeMap<usize, &str> =
        production_lines(source).into_iter().collect();
    let total = source.lines().count();
    let mut out = String::with_capacity(source.len());
    for number in 1..=total {
        if let Some(line) = kept.get(&number) {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_trailing_test_module_does_not_end_the_scan() {
        let source = "fn a() {}\n#[cfg(test)]\nmod tests {\n    fn t() {}\n}\nfn b() {}\n";
        let half = production_half(source);
        assert!(half.contains("fn a()"));
        assert!(
            half.contains("fn b()"),
            "production below the tests was dropped"
        );
        assert!(!half.contains("fn t()"));
    }

    #[test]
    fn the_wide_attribute_opens_a_region_too() {
        let source =
            "fn a() {}\n#[cfg(all(test, unix))]\nmod tests {\n    fn t() {}\n}\nfn b() {}\n";
        let half = production_half(source);
        assert!(!half.contains("fn t()"));
        assert!(half.contains("fn b()"));
    }

    #[test]
    fn several_regions_are_each_closed() {
        let source = "fn a() {}\n#[cfg(test)]\nmod t1 {\n}\nfn b() {}\n#[cfg(test)]\nmod t2 {\n    fn u() {}\n}\nfn c() {}\n";
        let half = production_half(source);
        for kept in ["fn a()", "fn b()", "fn c()"] {
            assert!(half.contains(kept), "{kept} was dropped");
        }
        assert!(!half.contains("fn u()"));
    }

    #[test]
    fn an_attributed_semicolon_item_is_a_one_line_region() {
        let source = "fn a() {}\n#[cfg(test)]\nuse super::*;\nfn b() {}\n";
        let half = production_half(source);
        assert!(!half.contains("use super::*"));
        assert!(half.contains("fn b()"));
    }

    #[test]
    fn a_brace_in_a_string_or_comment_does_not_close_a_region() {
        let source =
            "#[cfg(test)]\nmod tests {\n    let s = \"}\"; // }\n    fn t() {}\n}\nfn b() {}\n";
        let half = production_half(source);
        assert!(!half.contains("fn t()"), "the region closed early");
        assert!(half.contains("fn b()"));
    }

    #[test]
    fn nested_braces_do_not_close_a_region_early() {
        let source = "#[cfg(test)]\nmod tests {\n    fn t() { if x { y(); } }\n    fn u() {}\n}\nfn b() {}\n";
        let half = production_half(source);
        assert!(!half.contains("fn u()"));
        assert!(half.contains("fn b()"));
    }

    #[test]
    fn line_numbers_survive_the_elision() {
        let source = "fn a() {}\n#[cfg(test)]\nmod tests {\n}\nfn b() {}\n";
        let kept = production_lines(source);
        assert_eq!(kept.first().map(|(n, _)| *n), Some(1));
        assert_eq!(kept.last().map(|(n, _)| *n), Some(5));
    }

    #[test]
    fn a_file_with_no_tests_is_wholly_production() {
        let source = "fn a() {}\nfn b() {}\n";
        assert_eq!(production_lines(source).len(), 2);
    }
}
