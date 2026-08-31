// SPDX-License-Identifier: Apache-2.0
//! Every production refusal is inside the exchange lifecycle (THM-0081).
//!
//! `refusal/cause.rs` establishes what a refusal IS and which authority reached it, and
//! `exchange_state.rs` establishes that the machine decides a retry consequence for every
//! state it can be in. Neither says that every SITE that answers a client is inside that
//! machine — and an exit that answers from source position satisfies both while stating a
//! retry contract the machine never derived. That is not hypothetical: it is the defect
//! ADR-MCPRE-058 §10 ruling D1 recorded, where a refusal reached after a human's approval
//! had already been spent came back as HTTP 503, the status clients retry, so the tool ran
//! twice.
//!
//! So the decidable property is the SITE SET, in four parts:
//!
//! > (a) the serving subtree mints no answer of its own — the sole construction of a
//! >     `ServedHttpResponse` under it is inside `served`, which wraps a response the
//! >     receipt owner built from a `Refusal`;
//! > (b) `handle` answers only through its stages — every `Err` arm returns the binding its
//! >     stage produced, and none builds a response at the exit;
//! > (c) the answers given outside the exchange are exactly the transport frame's four —
//! >     the channel/routing refusal, the malformed message, the oversized body and the
//! >     shed — every one of them minted in the frame's own three files and reached ahead
//! >     of the handler, before an exchange exists to place a refusal in; and the single
//! >     exit that answers after the exchange has decided, `served_to_hyper`'s framing
//! >     fallback, advertises no retry;
//! > (d) the retry contract every refusal carries is DERIVED: `disposition` reads
//! >     `retry_semantics()` and has no wildcard arm, so a new machine consequence is a
//! >     compile error rather than a silently inherited contract.
//!
//! # Why a source scan and not a type
//!
//! `ServedHttpResponse` is the crate's own public transport frame and has public fields, as
//! a wire frame must: the async fleet, the harness and external embedders all construct one.
//! Privacy would buy nothing — a constructor taking the same three fields is the same
//! absence of checking — so this is EVIDENCE for the site set, never unconstructibility, and
//! deleting it leaves an out-of-lifecycle exit compiling. `scripts/refusal_provenance_gate.py`
//! clause 12 measures the same four facts, and widens (c) to the whole workspace.

use std::collections::BTreeSet;
use std::path::Path;
use std::path::PathBuf;

/// The wrapper the serving subtree is allowed to mint through, and the only one.
const WRAPPER: &str = "served";

/// The mint outside the exchange. Named rather than described, because a bounded site set is
/// only reassuring if the sites are also the RIGHT ones.
const TRANSPORT_MINT: &str = "ServedHttpResponse::json";

/// The transport frame's own fail-closed reply, and the three named replies built on it.
/// Every answer the async fleet gives that did not come from the exchange goes through one
/// of these, so enumerating them IS the "no third kind" half of the claim.
const FRAME_MINT: &str = "empty_response(";
const FRAME_REPLIES: &[&str] = &[
    "malformed_header_response",
    "fail_closed_response",
    "overloaded_response",
];

/// Everything in the frame that can answer, as it is named where the handler is called.
/// Each must appear BEFORE `handler(`: that ordering is what makes "reached before an
/// exchange exists" a measured fact rather than a reading of the code.
const PRE_HANDLER_STAGES: &[&str] = &[
    "overloaded_response",
    "request_view(",
    "read_body(",
    TRANSPORT_MINT,
];

/// Where that mint is DEFINED, and where its one production caller lives. A definition is
/// not a refusal site; the caller is.
const MINT_OWNER: &str = "async_serve/mod.rs";
const DECLARED_TRANSPORT_SITE: &str = "async_serve/request.rs";

/// Every file allowed to mint an answer outside the exchange: the transport frame, and
/// nothing else. `mod.rs` defines the frame replies, `request.rs` sheds and refuses the
/// channel, `inbound.rs` refuses a malformed or oversized message.
const FRAME_FILES: &[&str] = &[
    "async_serve/mod.rs",
    "async_serve/request.rs",
    "async_serve/inbound.rs",
];

fn production_half(source: &str) -> String {
    mcp_re_test_paths::rust_source::production_half(source)
}

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

/// The crate's `src/` root, reached through a file inside it rather than by a relative path
/// from the test: under Bazel the sources are a runfiles copy, and the anchor is what the
/// target's `glob` populates.
fn crate_src_root() -> PathBuf {
    let anchor = mcp_re_test_paths::resolve_runfile("MCP_RE_APP_SRC");
    anchor
        .parent()
        .unwrap_or_else(|| panic!("{anchor:?} has no parent directory"))
        .to_path_buf()
}

/// Every production line of the crate, as `(repo-ish suffix, text)` pairs.
///
/// Per file rather than concatenated, because (c) has to NAME the offending file, and
/// because one file's unterminated test region would otherwise swallow the next file's
/// production code.
fn crate_production() -> Vec<(String, String)> {
    let root = crate_src_root();
    let mut files = Vec::new();
    collect_rust_files(&root, &mut files);
    files.sort();
    assert!(
        files.len() > 10,
        "the crate source walk found {} file(s) under {root:?} — the scope has moved, and \
         every assertion below would be about almost nothing",
        files.len()
    );
    files
        .into_iter()
        .map(|path| {
            let rel = path
                .strip_prefix(&root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            let text =
                std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
            (rel, production_half(&text))
        })
        .collect()
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
    let mut whole = String::new();
    for path in files {
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
        whole.push_str(&production_half(&text));
        whole.push('\n');
    }
    whole
}

/// The body of `fn <name>`, by brace depth from its opening brace.
fn body_of(text: &str, name: &str) -> Option<String> {
    let needle = format!("fn {name}");
    let at = text.find(&needle)?;
    let open = at + text[at..].find('{')?;
    let chars: Vec<char> = text[open..].chars().collect();
    let mut depth = 0i64;
    for (offset, c) in chars.iter().enumerate() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(chars[..=offset].iter().collect());
                }
            }
            _ => {}
        }
    }
    None
}

/// Lines that CONSTRUCT a `ServedHttpResponse` — the struct literal or the json mint —
/// excluding the ones that merely name the type in a signature.
fn minting_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("//"))
        .filter(|line| !line.contains("->"))
        .filter(|line| {
            line.contains(TRANSPORT_MINT)
                || (line.contains("ServedHttpResponse") && line.contains('{'))
        })
        .map(str::to_string)
        .collect()
}

/// (a) The serving subtree mints no answer of its own.
#[test]
fn the_serving_subtree_answers_only_through_its_one_wrapper() {
    let source = serving_source();
    let wrapper = body_of(&source, WRAPPER).unwrap_or_else(|| {
        panic!(
            "`fn {WRAPPER}` is not in the serving subtree — the one wrapper this rule exempts \
             is gone, so the scope has moved rather than the property changed"
        )
    });
    let outside = source.replacen(&wrapper, "", 1);
    let minted = minting_lines(&outside);
    assert!(
        minted.is_empty(),
        "the serving path mints a response outside `{WRAPPER}`: {minted:?}. A refusal built \
         at the exit is not inside the exchange lifecycle, so nothing derived its retry \
         contract from the machine."
    );
}

/// (b) `handle` answers only through its stages.
#[test]
fn every_error_arm_of_handle_returns_what_its_stage_produced() {
    let source = serving_source();
    let handle = body_of(&source, "handle").expect("`fn handle` must be in the serving subtree");
    let arms: Vec<(String, String)> = handle
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("Err("))
        .map(|line| {
            let bound = line
                .trim_start_matches("Err(")
                .split(')')
                .next()
                .unwrap_or_default()
                .trim()
                .to_string();
            let returned = line
                .split("=>")
                .nth(1)
                .unwrap_or_default()
                .trim()
                .trim_start_matches("return ")
                .trim_end_matches(',')
                .trim()
                .to_string();
            (bound, returned)
        })
        .collect();
    assert!(
        !arms.is_empty(),
        "`handle` has no `Err` arm — the matcher has stopped matching, and this assertion \
         would pass on any source at all"
    );
    for (bound, returned) in &arms {
        assert_eq!(
            bound, returned,
            "`handle` answers an `Err({bound})` arm with `{returned}` rather than the \
             rejection its stage produced. An exit that builds its own answer is outside the \
             lifecycle."
        );
    }
}

/// (c) The answers given outside the exchange are exactly the transport frame's, and each
/// is reached before the handler.
///
/// Five exits, at two types, and the enumeration is the point: `ServedHttpResponse::json`
/// for the channel/routing refusal, and `empty_response` for the malformed message, the
/// oversized body and the shed. All four are pre-handler. The fifth is `served_to_hyper`'s
/// framing fallback, which is post-handler and is treated below.
#[test]
fn the_answers_outside_the_exchange_are_exactly_the_transport_frames() {
    let crate_src = crate_production();
    let mints_an_answer = |text: &str| {
        text.contains(TRANSPORT_MINT)
            || text.contains(FRAME_MINT)
            || FRAME_REPLIES
                .iter()
                .any(|reply| text.contains(&format!("{reply}()")))
    };
    let minting: BTreeSet<String> = crate_src
        .iter()
        .filter(|(rel, text)| rel != MINT_OWNER && mints_an_answer(text))
        .map(|(rel, _)| rel.clone())
        .collect();
    let declared: BTreeSet<String> = FRAME_FILES
        .iter()
        .filter(|rel| **rel != MINT_OWNER)
        .map(|rel| (*rel).to_string())
        .collect();
    assert_eq!(
        minting, declared,
        "answers outside the exchange are minted in {minting:?}, declared {declared:?}. A          file outside the transport frame that mints one is a refusal reached with no          exchange to place it in — and nothing derived its retry contract."
    );

    let frame = crate_src
        .iter()
        .find(|(rel, _)| rel == DECLARED_TRANSPORT_SITE)
        .map(|(_, text)| text.clone())
        .unwrap_or_else(|| panic!("{DECLARED_TRANSPORT_SITE} is not in the crate"));
    let handler_at = frame
        .find("handler(")
        .unwrap_or_else(|| panic!("{DECLARED_TRANSPORT_SITE} no longer calls the handler"));
    let mint_at = frame
        .find(TRANSPORT_MINT)
        .unwrap_or_else(|| panic!("{DECLARED_TRANSPORT_SITE} no longer mints a refusal"));
    assert!(
        mint_at < handler_at,
        "the channel/routing refusal no longer sits ahead of the handler, so it is not          established that it is reached BEFORE an exchange exists — which is the whole          reason it is allowed to answer outside the lifecycle."
    );
    for stage in PRE_HANDLER_STAGES {
        let at = frame
            .find(*stage)
            .unwrap_or_else(|| panic!("{DECLARED_TRANSPORT_SITE} no longer reaches {stage}"));
        assert!(
            at < handler_at,
            "{stage} is reached after the handler in {DECLARED_TRANSPORT_SITE}. A frame reply \
             taken once an exchange exists would discard a decided answer rather than refuse \
             before one existed."
        );
    }
}

/// The one exit that answers AFTER the exchange has decided, named rather than hidden.
///
/// `served_to_hyper` cannot fail for any value the receipt owner produces — the status is a
/// u16 the exchange chose and the headers are ones it wrote — but the hyper builder is
/// fallible, so the fallback exists. It is recorded here because it is the single place an
/// exchange's derived answer can be replaced, and because its status matters: an empty 500
/// asserts nothing about retry, where the 503 the shed uses is the status clients DO retry.
/// A frame fallback that answered 503 would resurrect ADR-MCPRE-058 §10 ruling D1 at the one
/// site the exchange machine cannot see.
#[test]
fn the_one_post_exchange_frame_exit_advertises_no_retry() {
    let owner = crate_production()
        .into_iter()
        .find(|(rel, _)| rel == MINT_OWNER)
        .map(|(_, text)| text)
        .unwrap_or_else(|| panic!("{MINT_OWNER} is not in the crate"));
    let framing = body_of(&owner, "served_to_hyper")
        .unwrap_or_else(|| panic!("`fn served_to_hyper` is not in {MINT_OWNER}"));
    assert!(
        framing.contains("INTERNAL_SERVER_ERROR"),
        "the framing fallback no longer answers 500. Any status that advertises a retry          would let an unframeable post-dispatch answer be retried, which is the defect the          exchange machine exists to remove."
    );
    for retryable in ["SERVICE_UNAVAILABLE", "TOO_MANY_REQUESTS"] {
        assert!(
            !framing.contains(retryable),
            "the framing fallback answers {retryable} — a retry contract stated at the one              exit the exchange machine cannot reach."
        );
    }
}

/// (d) The retry contract is derived from the machine, not chosen at the exit.
#[test]
fn the_retry_contract_is_derived_from_the_exchange_machine() {
    let source = serving_source();
    let disposition =
        body_of(&source, "disposition").expect("`fn disposition` must be in the serving subtree");
    assert!(
        disposition.contains("retry_semantics()"),
        "`disposition` does not read `retry_semantics()`. A refusal's retry contract would \
         then be chosen at the exit rather than derived from the exchange, which is exactly \
         how a post-dispatch failure came to advertise an ordinary retry."
    );
    assert!(
        !disposition
            .lines()
            .any(|line| line.trim().starts_with("_ =>")),
        "`disposition` has a wildcard arm. A new machine consequence would inherit a retry \
         contract instead of naming one — and the inherited one is whichever the wildcard \
         happens to sit on."
    );
}

/// The rules detect what they claim to.
///
/// Without this a matcher that never matches leaves all four assertions vacuously true, and
/// a green run would mean nothing at all.
#[test]
fn the_rules_would_catch_each_regression() {
    // (a) a mint outside the wrapper is seen; a signature naming the type is not.
    assert_eq!(
        minting_lines("fn f() -> ServedHttpResponse {").len(),
        0,
        "a return type is not a mint"
    );
    assert_eq!(
        minting_lines("    ServedHttpResponse { status: 500 }").len(),
        1,
        "a struct literal is a mint"
    );
    assert_eq!(
        minting_lines("    ServedHttpResponse::json(403, body)").len(),
        1,
        "the json mint is a mint"
    );
    assert_eq!(
        minting_lines("// ServedHttpResponse { status: 500 }").len(),
        0,
        "a comment is not a mint"
    );

    // (a) the wrapper's own literal is excised rather than exempted by name.
    let src = "fn served(r: HttpResponse) -> ServedHttpResponse {\n    ServedHttpResponse { \
               status: r.status }\n}\nfn oops() -> ServedHttpResponse {\n    \
               ServedHttpResponse { status: 500 }\n}\n";
    let wrapper = body_of(src, WRAPPER).expect("the helper must find the wrapper body");
    assert_eq!(
        minting_lines(&src.replacen(&wrapper, "", 1)).len(),
        1,
        "excising the wrapper must leave the second mint visible"
    );

    // (b) an arm that returns something other than its binding is seen.
    let handle = "fn handle() {\n    match a() {\n        Ok(v) => v,\n        \
                  Err(rejection) => return rejection,\n    }\n}";
    let body = body_of(handle, "handle").expect("the helper must find the handle body");
    assert!(body.contains("Err(rejection) => return rejection,"));

    // (d) a wildcard and a missing derivation are both seen.
    let bad =
        "fn disposition(p: &P) -> D {\n    match p.thing() {\n        _ => D::None,\n    }\n}";
    let body = body_of(bad, "disposition").expect("the helper must find the disposition body");
    assert!(
        !body.contains("retry_semantics()"),
        "a lost derivation is seen"
    );
    assert!(
        body.lines().any(|line| line.trim().starts_with("_ =>")),
        "a wildcard arm is seen"
    );

    // Test regions are out of scope, and production below one is still production.
    assert_eq!(
        minting_lines(&production_half(
            "#[cfg(test)]\nmod tests {\n    ServedHttpResponse { status: 1 };\n}\n"
        ))
        .len(),
        0,
        "a mint inside a test region is not a production mint"
    );
    assert_eq!(
        minting_lines(&production_half(
            "#[cfg(test)]\nmod tests {\n}\nfn late() { ServedHttpResponse { status: 1 }; }\n"
        ))
        .len(),
        1,
        "a mint below a test module must still be seen"
    );
}
