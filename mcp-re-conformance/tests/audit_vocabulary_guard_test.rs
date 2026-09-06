//! ADR-MCPS-035 — audit-evidence vocabulary drift guard.
//!
//! The MCP-RE audit-evidence vocabulary (`mcp-re-core/src/audit.rs`) derives its
//! rejection reasons from the FROZEN `McpReError::wire_code()` taxonomy
//! (`mcp-re-core/src/error.rs` is the sole authority) and adds ONLY the two
//! success events the error enum cannot express, plus the three delegated-key
//! lifecycle events authorized by ADR-MCPRE-052 §7. This guard FAILS on any drift
//! between the two files:
//!
//!   1. a rejection `reason` the audit layer can emit is NOT a member of
//!      `McpReError::wire_code()` (a minted parallel token);
//!   2. the success-event set is not EXACTLY the two-item allowlist
//!      (`mcp-re.request.accepted`, `mcp-re.response.signed`);
//!   3. the key-lifecycle set is not EXACTLY the three-item allowlist
//!      (`mcp-re.delegated_key.{issued,rotated,retired}`, ADR-MCPRE-052 §7);
//!   4. an audit `event_type` collides with a frozen `wire_code()` token (a
//!      rejection sub-name masquerading as an event type);
//!   5. an `authorization_hash_mismatch` notion reappears as an audit reason
//!      (Core binds, never interprets — ADR-MCPS-013);
//!   6. any producer OUTSIDE `mcp-re-core/src/error.rs` mints an `mcp-re.*` token of its
//!      own instead of naming a Core verdict and deriving the token from it
//!      (ADR-MCPRE-066 Slice 2).
//!
//! Both source files are delivered through Bazel `data` runfiles and read from
//! DISK at test time (resolved via `$(rlocationpath)` against
//! `TEST_SRCDIR`/`RUNFILES_DIR`, the SAME scheme as the conformance drift_guard
//! and the method-name drift guard), with the `mcp-re-test-paths` cargo fallback —
//! so adding an `McpReError` variant (a new frozen wire_code) or editing the audit
//! vocabulary is re-read from reality, never trusted as written. The guard does
//! not hardcode any absolute path.
//!
//! std only (no new crates).

use std::collections::BTreeSet;
use std::path::PathBuf;

/// The exact, exhaustive success/lifecycle allowlist (ADR-MCPS-035 §3). These are
/// the ONLY audit events the frozen error taxonomy cannot express; the audit
/// module's `SUCCESS_EVENT_TYPES` must equal this set, and nothing else may be
/// minted without an ADR.
const EXPECTED_SUCCESS_EVENTS: &[&str] = &["mcp-re.request.accepted", "mcp-re.response.signed"];

/// The two rejection `event_type`s. Each carries a frozen `wire_code()` token in
/// `reason`; neither is itself a `wire_code()` token.
const EXPECTED_REJECTION_EVENTS: &[&str] = &["mcp-re.request.rejected", "mcp-re.response.rejected"];

/// The three delegated-key lifecycle `event_type`s — the third audit category,
/// authorized by ADR-MCPRE-052 §7. Not verdicts (no `reason`); emitted by the
/// custody layer. Nothing else may join this set without an ADR.
const EXPECTED_KEY_LIFECYCLE_EVENTS: &[&str] = &[
    "mcp-re.delegated_key.issued",
    "mcp-re.delegated_key.rotated",
    "mcp-re.delegated_key.retired",
];

// --- runfiles resolution (same scheme as the drift guards) -------------------

fn locate(env_key: &str) -> PathBuf {
    mcp_re_test_paths::resolve_runfile(env_key)
}

fn read(env_key: &str) -> String {
    let path = locate(env_key);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"))
}

// --- on-disk derivation ------------------------------------------------------

/// Every `mcp-re.*` wire token the frozen taxonomy renders, parsed from the
/// `wire_code()` match arms in `error.rs`. We scan the `=> "mcp-re...."` string
/// literals so a newly added `McpReError` variant (with its new wire_code) is
/// picked up automatically — exactly the frozen-taxonomy process ADR-MCPS-035
/// relies on. We start the scan at the `fn wire_code` token so the enum
/// `#[error("...")]` attributes are not double-counted (they carry the same
/// strings, so the set would be identical, but scoping to `wire_code` keeps the
/// guard reading the authority it claims to read).
fn frozen_wire_codes(error_rs: &str) -> BTreeSet<String> {
    let body = error_rs
        .split_once("fn wire_code")
        .map(|(_, after)| after)
        .unwrap_or_else(|| panic!("error.rs has no `fn wire_code` — frozen taxonomy moved?"));
    mcp_re_string_literals(body)
}

/// Every `mcp-re.*` token mentioned anywhere in `audit.rs` (event_type constants,
/// allowlists, doc examples). The audit vocabulary is small; we partition these
/// into the success/rejection event types and confirm no other `mcp-re.*` token is
/// minted as a reason that is not a frozen wire_code.
fn audit_mcp_re_tokens(audit_rs: &str) -> BTreeSet<String> {
    // Scan only the production region, so the unit-test fixtures (which deliberately
    // mention bogus tokens like the bare "authorization_hash_mismatch" they assert must
    // NOT appear) do not pollute the vocabulary set. The region is every line outside a
    // `#[cfg(test)]` item, not everything above the first one: a token minted below the
    // test module is still minted.
    let production = mcp_re_test_paths::rust_source::production_half(audit_rs);
    mcp_re_string_literals(&production)
}

/// The body of a `pub const <NAME>: &[&str] = &[ ... ];` slice declared in
/// `audit.rs`, i.e. everything between the value opener `= &[` and its closing
/// `]`. Anchoring on `= &[` skips the `&[&str]` TYPE annotation's brackets.
fn slice_value_body(audit_rs: &str, const_name: &str) -> String {
    let after_name = audit_rs
        .split_once(&format!("pub const {const_name}"))
        .map(|(_, a)| a)
        .unwrap_or_else(|| panic!("audit.rs declares `pub const {const_name}`"));
    // Collapse whitespace so a value split across lines (`=\n    &[...`) still
    // matches the `= &[` anchor; the `&[&str]` TYPE annotation precedes the `=`.
    let collapsed: String = after_name.split_whitespace().collect::<Vec<_>>().join(" ");
    let after_eq = collapsed
        .split_once("= &[")
        .map(|(_, a)| a.to_string())
        .unwrap_or_else(|| panic!("`{const_name}` is not in the `= &[ ... ]` form"));
    after_eq
        .split_once(']')
        .map(|(b, _)| b.to_string())
        .unwrap_or_else(|| panic!("`{const_name}` slice has no closing `]`"))
}

/// The `event_type` module's `pub const NAME: &str = "mcp-re...."` map, parsed from
/// `audit.rs`. Lets the guard resolve a const reference (e.g. the
/// `SUCCESS_EVENT_TYPES` slice lists `event_type::REQUEST_ACCEPTED`) back to its
/// `mcp-re.*` string value without depending on literal duplication.
fn event_type_consts(audit_rs: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in audit_rs.lines() {
        let line = line.trim();
        // `pub const REQUEST_ACCEPTED: &str = "mcp-re.request.accepted";`
        if let Some(rest) = line.strip_prefix("pub const ") {
            if let Some((name, after)) = rest.split_once(':') {
                if let Some(q1) = after.find('"') {
                    if let Some(q2_rel) = after[q1 + 1..].find('"') {
                        let value = &after[q1 + 1..q1 + 1 + q2_rel];
                        if value.starts_with("mcp-re.") {
                            out.push((name.trim().to_string(), value.to_string()));
                        }
                    }
                }
            }
        }
    }
    out
}

/// Resolve the `mcp-re.*` values referenced inside a `&[ ... ]` slice body, where
/// each element is either a bare `mcp-re.*` string literal OR an `event_type::NAME`
/// reference resolved through [`event_type_consts`].
fn resolve_slice_tokens(slice_body: &str, consts: &[(String, String)]) -> BTreeSet<String> {
    let mut out = mcp_re_string_literals(slice_body);
    for (name, value) in consts {
        if slice_body.contains(&format!("event_type::{name}")) {
            out.insert(value.clone());
        }
    }
    out
}

/// Extract every double-quoted string literal beginning with `mcp-re.` from `text`.
fn mcp_re_string_literals(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            // Find the closing quote (no escaped quotes occur in these tokens).
            if let Some(rel) = text[i + 1..].find('"') {
                let lit = &text[i + 1..i + 1 + rel];
                if lit.starts_with("mcp-re.") {
                    out.insert(lit.to_string());
                }
                i = i + 1 + rel + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

// --- drift conditions --------------------------------------------------------

/// Condition (1): every `mcp-re.*` token the audit vocabulary uses is EITHER a
/// frozen `wire_code()` rejection token OR one of the four fixed `event_type`
/// tokens. No third category — i.e. the audit layer cannot mint a rejection
/// reason outside `wire_code()`.
#[test]
fn every_audit_token_is_a_wire_code_or_a_fixed_event_type() {
    let codes = frozen_wire_codes(&read("MCP_RE_CORE_SRC_ERROR"));
    let tokens = audit_mcp_re_tokens(&read("MCP_RE_CORE_SRC_AUDIT"));

    let allowed_event_types: BTreeSet<String> = EXPECTED_SUCCESS_EVENTS
        .iter()
        .chain(EXPECTED_REJECTION_EVENTS.iter())
        .chain(EXPECTED_KEY_LIFECYCLE_EVENTS.iter())
        .map(|s| s.to_string())
        .collect();

    let mut foreign: Vec<String> = Vec::new();
    for token in &tokens {
        if !codes.contains(token) && !allowed_event_types.contains(token) {
            foreign.push(token.clone());
        }
    }
    assert!(
        foreign.is_empty(),
        "audit.rs mentions mcp-re.* token(s) that are neither a frozen McpReError::wire_code() nor \
         one of the fixed audit event_types (four verdict + three ADR-MCPRE-052 key-lifecycle) — a \
         minted rejection reason outside the frozen taxonomy is forbidden (ADR-MCPS-035): {foreign:?}"
    );
}

/// Condition (2): the audit module's success allowlist is EXACTLY the two
/// expected success events — derived from the `SUCCESS_EVENT_TYPES` slice
/// declared in `audit.rs`, parsed from disk.
#[test]
fn success_event_set_is_exactly_the_two_item_allowlist() {
    let audit = read("MCP_RE_CORE_SRC_AUDIT");
    let declared = resolve_slice_tokens(
        &slice_value_body(&audit, "SUCCESS_EVENT_TYPES"),
        &event_type_consts(&audit),
    );

    let expected: BTreeSet<String> = EXPECTED_SUCCESS_EVENTS
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(
        declared, expected,
        "audit.rs SUCCESS_EVENT_TYPES must be EXACTLY the two-item allowlist \
         (mcp-re.request.accepted, mcp-re.response.signed) — no third success event without an ADR \
         (ADR-MCPS-035 §3)"
    );
}

/// Condition (2b): the delegated-key lifecycle allowlist is EXACTLY the three
/// expected events — derived from the `KEY_LIFECYCLE_EVENT_TYPES` slice declared
/// in `audit.rs`, parsed from disk (ADR-MCPRE-052 §7). No fourth lifecycle event
/// without an ADR.
#[test]
fn key_lifecycle_event_set_is_exactly_the_three_item_allowlist() {
    let audit = read("MCP_RE_CORE_SRC_AUDIT");
    let declared = resolve_slice_tokens(
        &slice_value_body(&audit, "KEY_LIFECYCLE_EVENT_TYPES"),
        &event_type_consts(&audit),
    );

    let expected: BTreeSet<String> = EXPECTED_KEY_LIFECYCLE_EVENTS
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(
        declared, expected,
        "audit.rs KEY_LIFECYCLE_EVENT_TYPES must be EXACTLY the three-item allowlist \
         (mcp-re.delegated_key.issued/rotated/retired) — no fourth lifecycle event without an ADR \
         (ADR-MCPRE-052 §7)"
    );
}

/// Condition (3): no audit `event_type` is itself a frozen `wire_code()` token.
/// A rejection sub-name like `mcp-re.request.rejected.bad_signature` would either
/// shadow a wire_code or duplicate it; the fixed event_types must stay disjoint
/// from the taxonomy.
#[test]
fn event_types_do_not_collide_with_frozen_wire_codes() {
    let codes = frozen_wire_codes(&read("MCP_RE_CORE_SRC_ERROR"));
    for ev in EXPECTED_SUCCESS_EVENTS
        .iter()
        .chain(EXPECTED_REJECTION_EVENTS.iter())
        .chain(EXPECTED_KEY_LIFECYCLE_EVENTS.iter())
    {
        assert!(
            !codes.contains(*ev),
            "audit event_type {ev:?} collides with a frozen McpReError::wire_code() token — \
             event_types and rejection reasons must stay disjoint (ADR-MCPS-035)"
        );
    }
}

/// Condition (4): no `authorization_hash_mismatch` notion is an audit reason.
/// Core binds `authorization_hash` but never interprets the artifact, so it can
/// never emit a "mismatch" (ADR-MCPS-013). The frozen taxonomy has no such code,
/// and the audit vocabulary must not introduce one.
#[test]
fn no_authorization_hash_mismatch_audit_reason() {
    let codes = frozen_wire_codes(&read("MCP_RE_CORE_SRC_ERROR"));
    assert!(
        !codes.contains("mcp-re.authorization_hash_mismatch"),
        "the frozen Core taxonomy must NOT contain authorization_hash_mismatch (Core binds, \
         never interprets — ADR-MCPS-013)"
    );
    // And the audit production region must not mention it as a token at all.
    let tokens = audit_mcp_re_tokens(&read("MCP_RE_CORE_SRC_AUDIT"));
    assert!(
        !tokens.contains("mcp-re.authorization_hash_mismatch"),
        "audit.rs must not introduce an authorization_hash_mismatch reason (Core binds, never \
         interprets — ADR-MCPS-013)"
    );
}

/// ADR-MCPRE-066 Slice 2 — **no producer outside Core mints a wire token.**
///
/// This test used to check set CONTAINMENT: it parsed the `mcp-re.*` string literals out of
/// each producer's own `wire_code` table and asserted they were a subset of the frozen
/// taxonomy's. That was the right check while the sink took a string, and it had the defect
/// its own subject describes — its scope was a hand-maintained list of files, so it
/// described yesterday's producer set on exactly the day a producer moved (ADR-MCPRE-066
/// §2.1). #637 found a fourth producer it had never been told about.
///
/// Slice 2 removed the string-taking constructors, so the containment is now a type
/// property and the interesting claim changed with it: not *are the carriers' strings a
/// subset*, but **do the carriers have strings at all**. A producer that mints one has
/// re-created the parallel namespace, whether or not the token happens to be a frozen
/// member today, because a string is what let one authority's verdict pass for another's.
///
/// So: exactly one file in the workspace decides what an `mcp-re.*` token says, and it is
/// `mcp-re-core/src/error.rs`. Every carrier states which Core verdict it IS, with an
/// exhaustive `From<&_> for McpReError`, and derives its token from that.
#[test]
fn no_producer_outside_core_mints_a_wire_token() {
    for (env_key, who) in [
        ("MCP_RE_PROFILE_SRC_ERROR", "HttpProfileError"),
        (
            "MCP_RE_PROFILE_SRC_PROJECTION",
            "the HttpProfileError projection",
        ),
        ("MCP_RE_PROXY_SRC_DISPATCH", "ProxyDispatchError"),
        (
            "MCP_RE_PROXY_SRC_DISPATCH_PROJECTION",
            "the ProxyDispatchError projection",
        ),
        (
            "MCP_RE_CLIENT_CORE_SRC_BINDING_REFUSAL",
            "BindingSpecRefusal",
        ),
        (
            "MCP_RE_CLIENT_CORE_SRC_PROJECTION",
            "the BindingSpecRefusal projection",
        ),
    ] {
        let src = read(env_key);
        let production = mcp_re_test_paths::rust_source::production_half(&src);
        let minted = mcp_re_string_literals(&production);
        assert!(
            minted.is_empty(),
            "{who} mints its own mcp-re.* token(s) {minted:?} instead of naming a Core              verdict and deriving the token from it. Exactly one file decides what these              strings say (mcp-re-core/src/error.rs); a second table is the parallel              namespace ADR-MCPRE-066 Slice 2 removed."
        );
    }

    // Positive control on the parser and the runfiles wiring: the ONE file that is
    // supposed to mint them still does, so an empty result above means "no tokens here"
    // rather than "this test reads nothing".
    let frozen = frozen_wire_codes(&read("MCP_RE_CORE_SRC_ERROR"));
    assert!(
        frozen.len() >= 15,
        "the sole minting authority parsed {} tokens — the runfiles wiring is broken, and          every assertion above is then vacuous",
        frozen.len()
    );

    // And each projection really is where that producer's verdicts are decided, so the
    // files scanned above are the ones that replaced a table rather than empty stubs.
    for (env_key, signature, who) in [
        (
            "MCP_RE_PROFILE_SRC_PROJECTION",
            "impl From<&HttpProfileError> for McpReError",
            "the carrier",
        ),
        (
            "MCP_RE_CLIENT_CORE_SRC_PROJECTION",
            "impl From<&BindingSpecRefusal> for McpReError",
            "the client seam",
        ),
    ] {
        let projection = read(env_key);
        assert!(
            projection.contains(signature),
            "{who}'s Core projection is not where this guard is looking"
        );
        assert!(
            !projection.contains("_ =>"),
            "{who}'s Core projection has a wildcard arm — a new failure would inherit a              verdict instead of naming one"
        );
    }
}

/// ADR-MCPRE-066 §2.1, closed — **which files decide what an `mcp-re.*` verdict token says
/// is MEASURED, not listed.**
///
/// `no_producer_outside_core_mints_a_wire_token` scans a hand-maintained set of producer
/// files, and the ADR names that shape's defect in its own words: such a list describes
/// yesterday's producer set on exactly the day a producer moves. #637 found a producer it
/// had never been told about, and the v0.17 policy-authority slice found a fifth —
/// `BindingSpecRefusal`, rendered by both published SDKs from a table of two string
/// literals.
///
/// So this control does not read a list of producers. It walks EVERY workspace crate's
/// source tree, takes each file's production half, and asserts that the set of files
/// holding a verdict-token literal is exactly the two frozen vocabularies:
///
/// ```text
/// mcp-re-core/src/error.rs      McpReError    — the Core verification taxonomy (ADR-MCPS-035)
/// mcp-re-policy/src/error.rs    PolicyError   — the authorization taxonomy (ADR-MCPS-013)
/// ```
///
/// A **verdict token** is `mcp-re.<name>` with no further dot. The dotted spellings are
/// audit EVENT types (`mcp-re.request.accepted`, `mcp-re.delegated_key.issued`), a separate
/// vocabulary the three allowlist tests above pin exactly.
///
/// The crate list is itself derived rather than remembered: it comes from the workspace
/// `Cargo.toml` at compile time, and a member with no registered source tree fails here
/// instead of going unscanned. Its scope is therefore exactly the Cargo/Bazel workspace —
/// see [`CRATE_SOURCE_TREES`] for the two source trees outside it and why the structural
/// producer check covers them instead.
#[test]
fn exactly_two_files_decide_what_a_verdict_token_says() {
    let expected: BTreeSet<String> = SOLE_MINTING_FILES.iter().map(|s| s.to_string()).collect();

    let mut found: BTreeSet<String> = BTreeSet::new();
    let mut files_scanned = 0usize;
    for (crate_dir, env_key) in CRATE_SOURCE_TREES {
        // The sentinel is `<crate>/src/lib.rs`; its parent is the tree to walk.
        let sentinel = locate(env_key);
        let src_root = sentinel
            .parent()
            .unwrap_or_else(|| panic!("{env_key} resolved to a path with no parent"))
            .to_path_buf();
        for file in rust_sources_under(&src_root) {
            files_scanned += 1;
            let text =
                std::fs::read_to_string(&file).unwrap_or_else(|e| panic!("read {file:?}: {e}"));
            let production = mcp_re_test_paths::rust_source::production_half(&text);
            if !verdict_tokens(&production).is_empty() {
                let rel = file
                    .strip_prefix(&src_root)
                    .unwrap_or(&file)
                    .to_string_lossy()
                    .replace('\\', "/");
                found.insert(format!("{crate_dir}/src/{rel}"));
            }
        }
    }

    // Positive control on the walk and the runfiles wiring: an empty or tiny scan would
    // make the equality below hold vacuously.
    assert!(
        files_scanned >= 200,
        "the workspace walk read only {files_scanned} source files — the runfiles wiring is          broken, and this control measures nothing"
    );
    assert_eq!(
        found, expected,
        "the set of files deciding what an mcp-re.* VERDICT token says is not the two frozen          vocabularies. A file that appears here and is not one of them has re-created the          parallel namespace ADR-MCPRE-066 Slice 2 removed: state which verdict the failure IS          (an exhaustive `From<&_> for McpReError` or a `PolicyError`) and derive the token from          that. A file that DISAPPEARS from here has moved a frozen vocabulary, which is an ADR."
    );
}

/// Every workspace crate that has a source tree, and the sentinel naming it. Derived
/// against the workspace `Cargo.toml` by [`the_scanned_crate_set_is_the_workspace`], so a
/// new member cannot be scanned by nobody.
///
/// # What is NOT here, and why
///
/// `sdk/python` and `sdk/typescript` are separate Cargo workspaces with their own lockfiles
/// and no Bazel target, so they cannot be delivered as runfiles and a cargo-only scan would
/// make this lane measure two different things in its two lanes. They are thin PyO3/napi
/// wrappers over `mcp_re_client_core::build_authorization`, and the refusal they render is
/// `BindingSpecRefusal` — which, since the v0.17 policy-authority slice, derives its token
/// from the client seam's Core projection rather than from a table. That is the property
/// [`no_producer_outside_core_mints_a_wire_token`] checks directly, on the file the SDKs
/// render THROUGH.
const CRATE_SOURCE_TREES: &[(&str, &str)] = &[
    ("mcp-re-core", "MCP_RE_SRC_TREE_CORE"),
    ("mcp-re-proxy", "MCP_RE_SRC_TREE_PROXY"),
    ("mcp-re-host", "MCP_RE_SRC_TREE_HOST"),
    ("mcp-re-client-core", "MCP_RE_SRC_TREE_CLIENT_CORE"),
    ("mcp-re-client", "MCP_RE_SRC_TREE_CLIENT"),
    ("mcp-re-client-proxy", "MCP_RE_SRC_TREE_CLIENT_PROXY"),
    ("mcp-re-transport", "MCP_RE_SRC_TREE_TRANSPORT"),
    ("mcp-re-policy", "MCP_RE_SRC_TREE_POLICY"),
    ("mcp-re-http-profile", "MCP_RE_SRC_TREE_HTTP_PROFILE"),
    ("mcp-re-demo", "MCP_RE_SRC_TREE_DEMO"),
    ("mcp-re-test-paths", "MCP_RE_SRC_TREE_TEST_PATHS"),
];

/// Workspace members with no `src/` tree at all. Named rather than inferred: a crate that
/// acquires one must be added to [`CRATE_SOURCE_TREES`], and listing it here is the
/// deliberate act that says it has none.
const MEMBERS_WITHOUT_A_SOURCE_TREE: &[&str] = &["mcp-re-conformance"];

/// The two files that may hold a verdict-token literal, and the only two.
const SOLE_MINTING_FILES: &[&str] = &["mcp-re-core/src/error.rs", "mcp-re-policy/src/error.rs"];

/// The scanned set is the workspace, so nothing is scanned by nobody.
///
/// Read from the root `Cargo.toml` at COMPILE time, which is the one input a new crate
/// cannot be added to the workspace without touching.
#[test]
fn the_scanned_crate_set_is_the_workspace() {
    let members = workspace_members(include_str!("../../Cargo.toml"));
    assert!(
        members.len() >= 10,
        "parsed {} workspace members — the manifest parser is broken and every membership          assertion below is vacuous",
        members.len()
    );
    let accounted: BTreeSet<String> = CRATE_SOURCE_TREES
        .iter()
        .map(|(dir, _)| (*dir).to_string())
        .chain(
            MEMBERS_WITHOUT_A_SOURCE_TREE
                .iter()
                .map(|d| (*d).to_string()),
        )
        .collect();
    let unscanned: Vec<&String> = members.iter().filter(|m| !accounted.contains(*m)).collect();
    assert!(
        unscanned.is_empty(),
        "workspace member(s) {unscanned:?} are scanned by no source-tree sentinel. Add one to          CRATE_SOURCE_TREES (with its runfiles wiring), or to MEMBERS_WITHOUT_A_SOURCE_TREE if          the crate genuinely has no src/."
    );
}

/// The `members = [...]` entries of the workspace manifest, comments stripped.
fn workspace_members(manifest: &str) -> BTreeSet<String> {
    let after = manifest
        .split_once("members = [")
        .map(|(_, rest)| rest)
        .unwrap_or_else(|| panic!("the workspace manifest has no `members = [` list"));
    let body = after
        .split_once(']')
        .map(|(inside, _)| inside)
        .unwrap_or_else(|| panic!("the workspace `members` list is unterminated"));
    body.lines()
        .map(|line| line.split('#').next().unwrap_or(""))
        .filter_map(|line| {
            let start = line.find('"')?;
            let rest = &line[start + 1..];
            let end = rest.find('"')?;
            Some(rest[..end].to_string())
        })
        .collect()
}

/// Every `.rs` file under `root`, recursively. std only.
fn rust_sources_under(root: &std::path::Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) => panic!("read_dir {dir:?}: {e}"),
        };
        for entry in entries {
            let path = entry
                .unwrap_or_else(|e| panic!("dir entry under {dir:?}: {e}"))
                .path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    out
}

/// The VERDICT tokens in `text`: `mcp-re.<name>` with no further dot.
///
/// The dotted spellings are audit event types, a separate vocabulary with its own exact
/// allowlists above. Conflating the two would report `audit.rs` as a third minting
/// authority, which it is not — it names events, never verdicts.
fn verdict_tokens(text: &str) -> BTreeSet<String> {
    mcp_re_string_literals(text)
        .into_iter()
        .filter(|token| !token.trim_start_matches("mcp-re.").contains('.'))
        .collect()
}

#[test]
fn guard_inputs_are_non_empty() {
    let codes = frozen_wire_codes(&read("MCP_RE_CORE_SRC_ERROR"));
    assert!(
        codes.len() >= 15,
        "parsed too few frozen wire_code tokens from error.rs ({}) — runfiles wiring is broken",
        codes.len()
    );
    // A representative frozen token is present (positive control on the parser).
    assert!(
        codes.contains("mcp-re.invalid_signature"),
        "expected mcp-re.invalid_signature among the parsed frozen wire_codes"
    );
    let tokens = audit_mcp_re_tokens(&read("MCP_RE_CORE_SRC_AUDIT"));
    for ev in EXPECTED_SUCCESS_EVENTS
        .iter()
        .chain(EXPECTED_REJECTION_EVENTS.iter())
    {
        assert!(
            tokens.contains(*ev),
            "expected audit event_type {ev:?} to appear in audit.rs production region — wiring broken"
        );
    }
}
