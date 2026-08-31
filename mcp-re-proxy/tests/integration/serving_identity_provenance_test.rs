// SPDX-License-Identifier: Apache-2.0
//! Serving derives peer identity only from the credential the mechanism accepted (THM-0080).
//!
//! The composition ADR-MCPRE-064 Slice 2 forbids is an acceptance from relationship A paired
//! with an identity derived from credential B. It is invisible to every behavioural control,
//! because each one still measures a true thing about a correctly-composed value: the
//! identity really is the one in the certificate it was read from, the acceptance really did
//! happen, and nothing checks that they are about the same relationship.
//!
//! So the decidable property is the ROUTE:
//!
//! > Each direct-TLS serving path asks its authority exactly once, through a resolver whose
//! > signature admits its predecessor and the options and nothing else, and neither path
//! > names any step of the certificate-representation route.
//!
//! The fourth of those is the one that matters. The enforcement mechanism is the ABSENCE OF
//! A PARAMETER through which a second credential could enter, which is a property of a
//! signature — and a signature is exactly what a future edit widens first. "Just pass the
//! leaf too, we already have it" reintroduces the defect without touching a single check.
//!
//! # Why a source scan and not a type
//!
//! The historical extractor is a published API with its own X.509 conformance suite over
//! real DER, so it cannot be deleted to make the wrong call unavailable. What can be held is
//! that the SERVING PATHS do not take it — a call-site fact, and a call-site fact needs a
//! call-site check. Evidence, never unconstructibility.
//!
//! `scripts/serving_identity_provenance_gate.py` measures the same route with two clauses
//! this battery does not carry: the historical facade's exemption, and the `online_ocsp`
//! residue's feature gate.

use std::path::Path;
use std::path::PathBuf;

/// The two direct-TLS serving paths, as path suffixes under `src/`. Directories, because
/// the async listener is one module per region: a scan of one file would report a clean pass
/// over the regions that hold the derivation.
const SERVING_PATHS: &[&str] = &["async_serve/", "blocking_mtls_harness/"];

/// The one function each path calls about its relationship.
const RESOLVER: &str = "served_channel_peer";

/// Where its signature lives.
const DISPATCH_MODULE: &str = "tls.rs";

/// The route this migration removed from production serving: certificate representation in,
/// identity or a currency verdict out. Each name is one step of it.
const RAW_ROUTE: &[&str] = &[
    "extract_identity",
    "interpret_identity",
    "from_leaf_der",
    "resolve_identity_from_leaf",
    "cert_lifetime_rejection_for_chain",
    "connection_rejection_for_chain",
    "leaf_facts",
    "chain_issuers_",
];

/// A parameter naming certificate representation or a rival identity product. The check is
/// on the parameter LIST: a local of any of these names is untouched, and what is forbidden
/// is a CALLER being able to supply one.
const FORBIDDEN_PARAM: &[&str] = &["leaf", "der", "chain", "certificate", "identity"];

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

fn crate_production() -> Vec<(String, String)> {
    let anchor = mcp_re_test_paths::resolve_runfile("MCP_RE_APP_SRC");
    let root = anchor
        .parent()
        .unwrap_or_else(|| panic!("{anchor:?} has no parent directory"))
        .to_path_buf();
    let mut files = Vec::new();
    collect_rust_files(&root, &mut files);
    files.sort();
    assert!(files.len() > 10, "the crate source walk found too little");
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
            (rel, mcp_re_test_paths::rust_source::production_half(&text))
        })
        .collect()
}

/// One serving path's production source, whole.
fn serving_path(prefix: &str) -> String {
    let joined: String = crate_production()
        .into_iter()
        .filter(|(rel, _)| rel.starts_with(prefix))
        .map(|(_, text)| text)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !joined.is_empty(),
        "the serving path {prefix:?} holds no production source — the scope has moved, and \
         every assertion about it would pass on nothing"
    );
    joined
}

/// How many times `name` is CALLED — `name(` occurrences that are not its definition, and
/// not in a whole-line comment.
fn calls(text: &str, name: &str) -> usize {
    let code: String = text
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    code.matches(&format!("{name}("))
        .count()
        .saturating_sub(code.matches(&format!("fn {name}(")).count())
}

/// The parenthesised parameter list of `fn <name>`.
fn signature_of(text: &str, name: &str) -> Option<String> {
    let at = text.find(&format!("fn {name}"))?;
    let open = at + text[at..].find('(')?;
    let chars: Vec<char> = text[open..].chars().collect();
    let mut depth = 0i64;
    for (offset, c) in chars.iter().enumerate() {
        match c {
            '(' => depth += 1,
            ')' => {
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

/// Each serving path asks its authority exactly once.
#[test]
fn each_serving_path_asks_its_authority_exactly_once() {
    for prefix in SERVING_PATHS {
        let source = serving_path(prefix);
        assert_eq!(
            calls(&source, RESOLVER),
            1,
            "{prefix} calls `{RESOLVER}` {} time(s). None means it answers the identity \
             question somewhere this test cannot see; more than one means two derivations \
             that agree today and are two places to change.",
            calls(&source, RESOLVER)
        );
    }
}

/// Neither serving path names any step of the certificate-representation route.
#[test]
fn neither_serving_path_reconstructs_identity_from_representation() {
    for prefix in SERVING_PATHS {
        let source = serving_path(prefix);
        for step in RAW_ROUTE {
            assert_eq!(
                calls(&source, step),
                0,
                "{prefix} reaches `{step}`. That is the route from certificate \
                 representation to an identity or a currency verdict, and a serving path \
                 that takes it can pair an acceptance from one relationship with an \
                 identity derived from another credential."
            );
        }
    }
}

/// The resolver admits its predecessor and the options, and nothing else.
#[test]
fn the_resolver_admits_no_second_credential() {
    let dispatch = crate_production()
        .into_iter()
        .find(|(rel, _)| rel == DISPATCH_MODULE)
        .map(|(_, text)| text)
        .unwrap_or_else(|| panic!("{DISPATCH_MODULE} is not in the crate"));
    let signature = signature_of(&dispatch, RESOLVER)
        .unwrap_or_else(|| panic!("`fn {RESOLVER}` is not in {DISPATCH_MODULE}"));
    let lowered = signature.to_lowercase();
    for forbidden in FORBIDDEN_PARAM {
        assert!(
            !lowered.contains(forbidden),
            "`{RESOLVER}` takes a parameter mentioning {forbidden:?}. The enforcement \
             mechanism for ADR-MCPRE-064 Slice 2 is the ABSENCE of a parameter through \
             which a second credential could enter, so widening the signature reintroduces \
             the defect without touching a single check: {signature}"
        );
    }
}

/// The rules detect what they claim to.
#[test]
fn the_rules_would_catch_each_regression() {
    assert_eq!(calls("let p = served_channel_peer(a, b);", RESOLVER), 1);
    assert_eq!(
        calls(
            "fn served_channel_peer(a: u8) {}\nlet p = served_channel_peer(a);",
            RESOLVER
        ),
        1,
        "the definition must not be counted as a call"
    );
    assert_eq!(calls("// served_channel_peer(a);", RESOLVER), 0);
    assert_eq!(calls("fn f() {}", RESOLVER), 0);

    let widened = "fn served_channel_peer(accepted: &A, options: &O, leaf: &[u8]) -> R {";
    let signature = signature_of(widened, RESOLVER).expect("the helper must find a signature");
    assert!(
        signature.to_lowercase().contains("leaf"),
        "a widened signature must be seen"
    );

    // Test regions are out of scope, and production below one is still production.
    let half = mcp_re_test_paths::rust_source::production_half(
        "#[cfg(test)]\nmod tests {\n    extract_identity(x);\n}\nfn late() { served_channel_peer(a); }\n",
    );
    assert_eq!(calls(&half, "extract_identity"), 0);
    assert_eq!(calls(&half, RESOLVER), 1);
}
