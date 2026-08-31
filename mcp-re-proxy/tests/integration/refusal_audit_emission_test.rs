// SPDX-License-Identifier: Apache-2.0
//! Every exchange-owned refusal reaches the audit boundary, typed, before it is answered
//! (THM-0085).
//!
//! THM-0081 establishes that every refusal SITE is inside the exchange lifecycle. THM-0046
//! establishes that a refusal CARRIES which authority reached it. THM-0069 establishes what a
//! record may say in each authority's coordinate. None of them says the record is EMITTED —
//! a refusal could be correctly typed, correctly sited, and simply never recorded, and every
//! one of those claims would still hold.
//!
//! This is that joint, and it is measured at the one boundary rather than reason by reason:
//!
//! > `ResponseSigning::refuse` is the single funnel every exchange-owned refusal passes
//! > through; it dispatches to exactly two emitters; each emitter takes the TYPED cause and
//! > asks it for its projections; and each records BEFORE the refusal response is minted.
//!
//! The ordering is the part that is easy to lose. Recording after the mint would leave a
//! window in which a refusal has been served and no record of it exists, and a panic or a
//! process death inside that window is exactly the case an auditor cannot reconstruct.
//!
//! # Scope
//!
//! Exchange-owned refusals only. The four pre-exchange transport replies are outside — no
//! exchange exists, so there is no exchange record to emit — and THM-0081 is what enumerates
//! them. This says nothing about DELIVERY once the record reaches the sink, which is
//! THM-0070 and carries its own durability boundary.

use std::path::Path;
use std::path::PathBuf;

/// The one funnel, and the two emitters it dispatches to. The serving subtree has two
/// functions called `refuse`; this claim is about the response owner's, which is selected by
/// what its body contains rather than by declaration order.
const FUNNEL: &str = "refuse";
const EMITTERS: &[&str] = &["rejection", "response_rejection"];

/// What an emitter must reach: the record boundary, and the typed projections it feeds it.
const RECORD: &str = "record_to(";
const CORE_PROJECTION: &str = "cause.core_verdict()";
const AUTHORIZATION_PROJECTION: &str = "cause.authorization_facet()";

/// What must come AFTER the record, never before.
const MINT: &str = "self.signed_rejection(";

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

/// Every body of `fn <name>` in `source`, by brace depth, over code lines only.
///
/// Plural because the serving subtree has TWO `fn refuse`, and they are different
/// authorities: the assembly's, which asks the response owner to serve a refusal, and the
/// response owner's, which is the emission funnel this claim is about. A helper taking the
/// first would have silently measured the wrong one — and did.
fn bodies_of(source: &str, name: &str) -> Vec<String> {
    let code: String = source
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let needle = format!("fn {name}");
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = code[from..].find(&needle) {
        let at = from + rel;
        let Some(brace) = code[at..].find('{') else {
            break;
        };
        let open = at + brace;
        let chars: Vec<char> = code[open..].chars().collect();
        let mut depth = 0i64;
        for (offset, c) in chars.iter().enumerate() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        out.push(chars[..=offset].iter().collect::<String>());
                        break;
                    }
                }
                _ => {}
            }
        }
        from = open + 1;
    }
    out
}

/// The single body of `fn <name>` that contains `marker`.
///
/// Naming the marker is how an ambiguous name is resolved without depending on declaration
/// order: zero matches and two matches are both failures, and both say which.
fn body_of_with(source: &str, name: &str, marker: &str) -> String {
    let matching: Vec<String> = bodies_of(source, name)
        .into_iter()
        .filter(|b| b.contains(marker))
        .collect();
    assert_eq!(
        matching.len(),
        1,
        "expected exactly one `fn {name}` containing {marker:?}, found {}",
        matching.len()
    );
    matching.into_iter().next().expect("checked above")
}

/// The single body of `fn <name>`, where the name is unambiguous.
fn body_of(source: &str, name: &str) -> String {
    let bodies = bodies_of(source, name);
    assert_eq!(
        bodies.len(),
        1,
        "expected exactly one `fn {name}` in scope, found {}",
        bodies.len()
    );
    bodies.into_iter().next().expect("checked above")
}

/// How many times `name` is CALLED, ignoring its definition and whole-line comments.
fn calls(source: &str, name: &str) -> usize {
    let code: String = source
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    code.matches(&format!("{name}("))
        .count()
        .saturating_sub(code.matches(&format!("fn {name}(")).count())
}

/// One funnel, dispatching to exactly the two emitters.
#[test]
fn every_exchange_owned_refusal_passes_through_one_funnel() {
    let source = serving_source();
    // The RESPONSE OWNER's `refuse`, not the assembly's — named by what it contains rather
    // than by which comes first in the walk.
    let funnel = body_of_with(&source, FUNNEL, "self.rejection(");
    for emitter in EMITTERS {
        assert!(
            funnel.contains(&format!("self.{emitter}(")),
            "`{FUNNEL}` no longer dispatches to `{emitter}`. A refusal reaching a third \
             emitter is a refusal whose record nothing here measures."
        );
    }
    // Every production call of either emitter is the funnel's own. More means a refusal
    // route that bypasses the funnel, and the funnel is what this claim is about.
    for emitter in EMITTERS {
        assert_eq!(
            calls(&source, &format!("self.{emitter}")),
            1,
            "`self.{emitter}` is called {} time(s) in the serving subtree. Exactly one — the \
             funnel's — is what makes the funnel a funnel.",
            calls(&source, &format!("self.{emitter}"))
        );
    }
}

/// Each emitter records, and records the TYPED projections rather than a rendering.
#[test]
fn each_emitter_records_the_typed_projections() {
    let source = serving_source();
    for emitter in EMITTERS {
        let body = body_of(&source, emitter);
        assert!(
            body.contains(RECORD),
            "`{emitter}` no longer reaches `{RECORD}`. A refusal served with no record is a \
             refusal an auditor cannot see happened."
        );
        assert!(
            body.contains(CORE_PROJECTION),
            "`{emitter}` no longer asks the cause for its Core verdict. Anything else is this \
             boundary choosing a token rather than recording the one an authority reached."
        );
    }
    assert!(
        body_of(&source, "rejection").contains(AUTHORIZATION_PROJECTION),
        "the request-side emitter no longer asks the cause for its authorization facet. That \
         coordinate is what keeps a policy denial from being recorded as a Core verdict."
    );
}

/// The record precedes the answer.
#[test]
fn the_record_is_emitted_before_the_refusal_is_minted() {
    let source = serving_source();
    for emitter in EMITTERS {
        let body = body_of(&source, emitter);
        let recorded = body
            .find(RECORD)
            .unwrap_or_else(|| panic!("`{emitter}` does not record at all"));
        let minted = body
            .find(MINT)
            .unwrap_or_else(|| panic!("`{emitter}` no longer mints a signed refusal"));
        assert!(
            recorded < minted,
            "`{emitter}` mints the refusal before recording it. That leaves a window in which \
             a refusal has been served and no record of it exists — the one case an auditor \
             cannot reconstruct afterwards."
        );
    }
}

/// The rules detect what they claim to.
#[test]
fn the_emission_rules_would_catch_each_regression() {
    let reordered = "fn rejection(&self) -> R {\n    let r = self.signed_rejection(x);\n    \
                     record_to(a, b);\n    r\n}";
    let body = body_of(reordered, "rejection");
    assert!(
        body.find(MINT).unwrap() < body.find(RECORD).unwrap(),
        "a mint-before-record ordering must be visible to the comparison"
    );

    let untyped = "fn rejection(&self) -> R {\n    record_to(a, cause.wire_code());\n    \
                   self.signed_rejection(x)\n}";
    assert!(
        !body_of(untyped, "rejection").contains(CORE_PROJECTION),
        "an emitter that renders instead of projecting must be seen"
    );

    assert_eq!(calls("let a = self.rejection(x);", "self.rejection"), 1);
    assert_eq!(calls("// self.rejection(x);", "self.rejection"), 0);
    assert_eq!(
        calls(
            "fn rejection(&self) {}\nself.rejection(x);",
            "self.rejection"
        ),
        1,
        "the definition must not be counted as a call"
    );

    // Test regions are out of scope; production below one is still production.
    let half = mcp_re_test_paths::rust_source::production_half(
        "#[cfg(test)]\nmod t {\n    self.rejection(x);\n}\nfn late() { self.rejection(y); }\n",
    );
    assert_eq!(calls(&half, "self.rejection"), 1);
}
