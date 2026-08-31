// SPDX-License-Identifier: Apache-2.0
//! What a request IS, decided once (THM-0083).
//!
//! Before anything reads the body for meaning, the serving path asks whether the body is a
//! legal JSON-RPC 2.0 request at all, and what its outstanding id is. Everything below
//! depends on that answer: the continuation stage reads `params.requestState`, the forwarded
//! body strips `_meta`, and the TERMINAL — a signed reply, or an acknowledgement that says
//! only that the boundary accepted the message — is chosen by whether an `id` is present.
//!
//! Two readers of one document can disagree, and the disagreement that matters here is a
//! body DISPATCHED AS A REQUEST and ACKNOWLEDGED AS A NOTIFICATION: the tool ran, and the
//! caller was told nothing about it under a receipt that claims nothing ran.
//!
//! > The outstanding id is decided once, by envelope validation, ahead of every stage that
//! > reads the body for meaning; and no production serving code reads it again.
//!
//! # Why a source scan and not a type
//!
//! `outstanding_id` is a published API with its own battery — the client side and the
//! response-envelope validator legitimately call it — so it cannot be deleted to make a
//! second read unavailable. What can be held is that the SERVING PATH does not take it
//! twice. Evidence, never unconstructibility.

use std::path::Path;
use std::path::PathBuf;

/// The one decision, and where the serving path makes it.
const DECISION: &str = "validate_envelope";

/// The published reader the serving path must NOT reach: asking the body again is what makes
/// two answers possible.
const SECOND_READ: &str = "outstanding_id(";

/// The value every downstream reader is given instead.
const CARRIED: &str = "admitted.outstanding";

fn collect_rust_files(dir: &Path, into: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read dir {dir:?}: {e}"));
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rust_files(&path, into);
        } else if path.extension().is_some_and(|e| e == "rs") {
            into.push(path);
        }
    }
}

/// The serving subtree's production half, whole.
fn serving_source() -> String {
    let anchor = mcp_re_test_paths::resolve_runfile("MCP_RE_HTTP_PROFILE_SERVE_SRC");
    let root = anchor
        .parent()
        .unwrap_or_else(|| panic!("{anchor:?} has no parent directory"))
        .to_path_buf();
    let mut files = Vec::new();
    collect_rust_files(&root, &mut files);
    files.sort();
    assert!(
        files.len() > 1,
        "the serving path is one file at {root:?} — the walk found no regions"
    );
    files
        .into_iter()
        .map(|path| {
            let text =
                std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
            mcp_re_test_paths::rust_source::production_half(&text)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// How many times `name` is CALLED, ignoring its definition and whole-line comments.
fn calls(text: &str, name: &str) -> usize {
    let code: String = text
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let needle = if name.ends_with('(') {
        name.to_string()
    } else {
        format!("{name}(")
    };
    code.matches(&needle)
        .count()
        .saturating_sub(code.matches(&format!("fn {needle}")).count())
}

/// The serving path decides what the request is exactly once.
#[test]
fn the_serving_path_decides_the_outstanding_id_exactly_once() {
    let source = serving_source();
    assert_eq!(
        calls(&source, DECISION),
        1,
        "the serving path calls `{DECISION}` {} time(s). None means the terminal is chosen \
         from something this test cannot see; more than one means two answers to \"what is \
         this request\", and nothing decides which one the reply is served under.",
        calls(&source, DECISION)
    );
}

/// And never reads the body for that answer again.
#[test]
fn no_production_serving_code_reads_the_outstanding_id_a_second_time() {
    let source = serving_source();
    assert_eq!(
        calls(&source, SECOND_READ),
        0,
        "the serving path reaches `{SECOND_READ}`. A second read of the same document can \
         disagree with the first, and the disagreement that matters is a body dispatched as \
         a request and acknowledged as a notification — the tool ran, and the caller was \
         told nothing ran."
    );
    assert!(
        source.contains(CARRIED),
        "the serving path no longer carries `{CARRIED}` to its terminal. The decided value \
         being PASSED is what makes the single decision load-bearing rather than merely \
         first."
    );
}

/// The rules detect what they claim to.
#[test]
fn the_rules_would_catch_each_regression() {
    assert_eq!(calls("let o = validate_envelope(r)?;", DECISION), 1);
    assert_eq!(
        calls(
            "fn validate_envelope(x: u8) {}\nlet o = validate_envelope(r);",
            DECISION
        ),
        1,
        "the definition must not be counted as a call"
    );
    assert_eq!(calls("// validate_envelope(r);", DECISION), 0);
    assert_eq!(calls("fn f() {}", DECISION), 0);
    assert_eq!(
        calls("let id = outstanding_id(&body)?;", SECOND_READ),
        1,
        "a second read must be seen"
    );

    // Test regions are out of scope, and production below one is still production.
    let half = mcp_re_test_paths::rust_source::production_half(
        "#[cfg(test)]\nmod tests {\n    outstanding_id(&b);\n}\nfn late() { validate_envelope(r); }\n",
    );
    assert_eq!(calls(&half, SECOND_READ), 0);
    assert_eq!(calls(&half, DECISION), 1);
}
