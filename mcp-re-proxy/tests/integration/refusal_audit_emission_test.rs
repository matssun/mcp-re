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
const AUTHORIZATION_PROJECTION: &str = "cause.authorization_facet(authorization)";

/// What must come AFTER the record, never before.
const MINT: &str = "self.signed_rejection(";

/// The signed-refusal constructor's call and its declared visibility: private to the
/// receipt module, whose two emitters are its only callers.
const MINT_CALL: &str = "self.signed_rejection(";
const MINT_VISIBILITY: &str = "pub(super) fn signed_rejection(";

/// The production sites that call an emitter, by method name whatever the receiver: the
/// response owner's funnel (two), pre-admission, the accepted-reply assembly and the
/// notification path.
const EMITTER_ROUTES: usize = 5;

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

/// How many times the method `name` is CALLED through any receiver (`.name(`), ignoring
/// its definition and whole-line comments.
fn method_calls(source: &str, name: &str) -> usize {
    let code: String = source
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    code.matches(&format!(".{name}(")).count()
}

/// Every exchange-owned refusal is minted by one of exactly two emitters.
///
/// The structural fact is the mint's confinement, not a funnel: the signed-refusal
/// constructor is private to the receipt module, and the two emitters are its only callers.
/// Whatever route reaches a refusal — the response owner's `refuse`, a pre-admission stage, a
/// notification — reaches it through an emitter, and the tests below hold each emitter to
/// recording before it mints.
#[test]
fn every_exchange_owned_refusal_is_minted_by_one_of_two_emitters() {
    let source = serving_source();
    assert!(
        source.contains(MINT_VISIBILITY),
        "the signed-refusal constructor is no longer `{MINT_VISIBILITY}`. Wider visibility lets \
         a route outside the receipt module mint a refusal no emitter recorded."
    );
    let in_emitters: usize = EMITTERS
        .iter()
        .map(|emitter| body_of(&source, emitter).matches(MINT_CALL).count())
        .sum();
    assert_eq!(
        in_emitters,
        EMITTERS.len(),
        "each emitter mints exactly once"
    );
    assert_eq!(
        calls(&source, MINT_CALL.trim_end_matches('(')),
        in_emitters,
        "`{MINT_CALL}` is called outside the two emitters — a refusal minted there is one \
         nothing records"
    );
    // The response owner's `refuse` still dispatches to both emitters.
    let funnel = body_of_with(&source, FUNNEL, "self.rejection(");
    for emitter in EMITTERS {
        assert!(
            funnel.contains(&format!("self.{emitter}(")),
            "`{FUNNEL}` no longer dispatches to `{emitter}`."
        );
    }
    // Every call of an emitter, whatever its receiver — `self.rejection(` and
    // `self.responses.rejection(` alike. The count is pinned so a new refusal route is a
    // reviewed change rather than an unseen one.
    let routes: usize = EMITTERS
        .iter()
        .map(|emitter| method_calls(&source, emitter))
        .sum();
    assert_eq!(
        routes, EMITTER_ROUTES,
        "the serving subtree calls an emitter from {routes} site(s), not {EMITTER_ROUTES}. A new \
         refusal route must be adjudicated against THM-0085 and this pin moved with it."
    );
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
        "the request-side emitter no longer asks the cause for its authorization facet, given \
         what the exchange reached. That coordinate is what keeps a policy denial from being \
         recorded as a Core verdict — and the argument is what keeps a refusal AFTER a permit \
         from being recorded as one before any policy ran."
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
    assert_eq!(
        method_calls(
            "a(self.rejection(x)); b(self.responses.rejection(y));",
            "rejection"
        ),
        2,
        "an emitter called through a field receiver must be counted"
    );
    assert_eq!(
        method_calls("fn rejection(&self) {}\n// self.rejection(x);", "rejection"),
        0,
        "neither the definition nor a comment is a call"
    );
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
