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
//!   2b. the key-lifecycle set is not EXACTLY the three-item allowlist
//!      (`mcp-re.delegated_key.{issued,rotated,retired}`, ADR-MCPRE-052 §7);
//!   3. an audit `event_type` collides with a frozen `wire_code()` token (a
//!      rejection sub-name masquerading as an event type);
//!   4. an `authorization_hash_mismatch` notion reappears as an audit reason
//!      (Core binds, never interprets — ADR-MCPS-013).
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
    // Scan only the production region (above the first `#[cfg(test)]`), so the
    // unit-test fixtures (which deliberately mention bogus tokens like the bare
    // "authorization_hash_mismatch" they assert must NOT appear) do not pollute
    // the vocabulary set.
    let production = match audit_rs.find("#[cfg(test)]") {
        Some(idx) => &audit_rs[..idx],
        None => audit_rs,
    };
    mcp_re_string_literals(production)
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

/// Sanity: the guard actually parsed real content from both files, so a silent
/// empty-set false-pass (e.g. a renamed env var resolving to an empty file)
/// cannot masquerade as "no drift". The frozen taxonomy has 20 variants today,
/// so we expect a healthy lower bound; the audit module mentions at least the
/// four event_types.
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
