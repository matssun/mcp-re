// SPDX-License-Identifier: Apache-2.0
//! The composition root installs exactly the continuation capability the seam established.
//!
//! `serving_capabilities::continuation` decides what a plan yields, and its own controls
//! measure that. What they cannot see is the step AFTER: `app.rs` calls `into_parts`,
//! separating the artifact from the posture, and then chooses whether to attach the store
//! and which seam state to declare. A defect there falsifies D1b′ while every
//! `Established<T>` control stays green — the type couples the two locally, and the
//! coupling ends at the split.
//!
//! # Why a source inventory rather than a startup
//!
//! No HERMETIC configuration reaches the posture phase: it sits after the replay tier is
//! established, and every tier validation accepts needs a live Redis or etcd. So a test
//! that starts the proxy measures nothing in `cargo test --workspace` or
//! `bazel test //...`. The installation step is three lines of straight-line code in one
//! function, and what a reader checks by eye is exactly what is pinned here.
//!
//! # The property this exists to defend
//!
//! A deployment that selected no continuation capability installs NO correlation store —
//! not a node-local one, not a test double, nothing. `InMemoryContinuationStore` exists
//! for tests and is a `pub` item of this crate, so nothing but placement stops a future
//! composition root from reaching for it the next time OFF looks inconvenient. That is the
//! substitution the owner ruling of 2026-09-03 forbids, and it is the negative control
//! below.

use std::path::{Path, PathBuf};

use mcp_re_test_paths::rust_source::production_half;

/// The crate's `src/` root, reached through a file inside it rather than by a relative
/// path: under Bazel the sources are a runfiles copy, and the anchor is what the target's
/// `glob` populates.
fn crate_src_root() -> PathBuf {
    let anchor = mcp_re_test_paths::resolve_runfile("MCP_RE_APP_SRC");
    anchor
        .parent()
        .unwrap_or_else(|| panic!("{anchor:?} has no parent directory"))
        .to_path_buf()
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

/// Every production line of the crate, per file, so a finding can name its file.
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

fn app_production() -> String {
    let path = mcp_re_test_paths::resolve_runfile("MCP_RE_APP_SRC");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    production_half(&text)
}

/// The store is attached ONLY from what the seam established, and only when it established
/// one.
///
/// Two facts, and the second is the one that carries the claim. `with_continuation_store`
/// is called once, and its guard is the `Option` that came out of `into_parts` — so the
/// artifact installed is the seam's artifact, and an OFF posture cannot coexist with an
/// installed store.
#[test]
fn the_root_installs_only_the_store_the_seam_established() {
    let app = app_production();

    assert_eq!(
        app.matches("with_continuation_store(").count(),
        1,
        "app.rs attaches the continuation store from more than one site: a second site is \
         a second authority over what this deployment holds, and the posture line declared \
         below describes only one of them"
    );

    let at = app
        .find("with_continuation_store(")
        .expect("the composition root must attach the established store");
    let before = app.get(..at).unwrap_or_default();
    let guard = before
        .rfind("if let Some(store) = continuation_store")
        .expect(
            "the attachment is not guarded by the Option that came out of `into_parts`. \
             That Option IS the seam's answer; attaching on any other condition installs a \
             store the posture does not describe",
        );
    assert!(
        before.get(guard..).unwrap_or_default().matches('{').count() == 1,
        "the guard and the attachment are no longer one block: the attachment has moved \
         out from under the seam's answer"
    );

    assert_eq!(
        app.matches("mrtr_continuation_store(").count(),
        1,
        "the capability is established from more than one site in app.rs"
    );
    assert_eq!(
        app.matches("Seam::MrtrContinuationStore").count(),
        1,
        "the seam is declared other than exactly once in app.rs — `assert_complete` \
         refuses that at runtime, and no hermetic lane reaches it"
    );
}

/// THE NEGATIVE CONTROL — no production path installs a node-local continuation tier.
///
/// A deployment that selected nothing must hold nothing. `InMemoryContinuationStore` is
/// the only substitute the crate contains, and the honest answer to "why can't a future
/// composition root reach for it" is placement, not the type system — so placement is
/// what is checked. Its own module is excluded because it is the definition.
#[test]
fn no_production_path_installs_a_node_local_continuation_tier() {
    let offenders: Vec<String> = crate_production()
        .into_iter()
        .filter(|(file, text)| {
            file != "continuation_store/in_memory.rs"
                && file != "continuation_store/mod.rs"
                && text.contains("InMemoryContinuationStore")
        })
        .map(|(file, _)| file)
        .collect();
    assert!(
        offenders.is_empty(),
        "{offenders:?} reach the in-memory continuation tier in production code. A \
         deployment that selected no correlation capability must install NO store — a \
         node-local tier is a different capability with a different scope, and the OFF \
         posture line does not describe it"
    );
}

/// The rules above would catch the regressions they exist for.
///
/// Without this the two tests are satisfied by a search that finds nothing: a renamed
/// guard, a renamed type, or a `production_half` that returned the empty string would all
/// read as a pass.
#[test]
fn the_rules_would_catch_each_regression() {
    let app = app_production();
    assert!(
        app.len() > 5_000,
        "app.rs production half is {} bytes — the rules above are searching almost nothing",
        app.len()
    );

    // The definition is still where the exclusion says it is, so the negative control is
    // excluding a definition rather than silently exempting a live consumer.
    let defined: Vec<String> = crate_production()
        .into_iter()
        .filter(|(_, text)| text.contains("pub struct InMemoryContinuationStore"))
        .map(|(file, _)| file)
        .collect();
    assert_eq!(
        defined,
        vec!["continuation_store/in_memory.rs".to_owned()],
        "the in-memory tier is not defined in exactly the one file the negative control \
         excludes, so that exclusion may now be exempting a live consumer"
    );

    // A store attached outside the seam's guard is what the first rule catches; prove the
    // rule can see such a line rather than trusting that it would.
    let tampered = app.replace(
        "if let Some(store) = continuation_store",
        "if true /* always */",
    );
    assert!(
        !tampered.contains("if let Some(store) = continuation_store"),
        "the guard the first rule anchors on is no longer spelled this way, so that rule \
         now passes vacuously"
    );
}
