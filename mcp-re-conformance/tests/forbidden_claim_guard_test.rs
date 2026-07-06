//! ADR-MCPS-036 (gate component, item 4) — forbidden-claim CI guard.
//!
//! The v0.5 proposal-readiness gate forbids a set of over-claims from appearing
//! as an ASSERTED (live) release claim in the proposal-facing docs. This guard
//! scans that doc set from DISK and FAILS if any forbidden phrase appears as a
//! live claim.
//!
//! ## Forbidden phrases (case-insensitive substring)
//!
//! The list below is co-located with — and must be maintained alongside — the
//! **Forbidden claim** column of §A in `docs/spec/v0.5-claim-matrix.md`
//! (per ADR-MCPS-036 "the forbidden-wording list must be maintained alongside
//! §A's forbidden column"). It mirrors the example wording enumerated in
//! ADR-MCPS-036 §Decision item 4.
//!
//! ## Scanned set — proposal-facing docs ONLY
//!
//! `docs/spec/security-boundary.md`, `docs/spec/v0.5-claim-matrix.md`,
//! `docs/spec/threat-coverage-matrix.md`, `docs/spec/composability.md`,
//! `docs/spec/proposal-scope.md`. The guard deliberately does NOT scan
//! historical ADRs, the `v0.3-…` files, the grilling seed, or test fixtures —
//! a forbidden phrase is legitimate THERE (it is named to be repudiated).
//!
//! ## Live claim vs. legitimate mention
//!
//! The claim matrix and the boundary doc must be ABLE to NAME each forbidden
//! phrase in order to repudiate it — inside a markdown table's **Forbidden
//! claim** column, or in an explicitly negated / non-existence sentence
//! ("Core **never** … provides RBAC", "**No** `authorization_hash_mismatch`",
//! "if an `authorization_hash_mismatch` notion **reappears**"). Those are NOT
//! live claims. A line trips the guard only when the phrase appears OUTSIDE a
//! forbidden-claim table cell AND without a negation/non-existence marker on the
//! same line — i.e. asserted as a capability MCP-RE has. This is exactly the
//! "does not appear as an asserted claim" wording of ADR-MCPS-036 / 033 / 032.
//!
//! ## Wiring (same scheme as the conformance drift_guard / method-name guard)
//!
//! Each doc is delivered through Bazel `data` runfiles and read from DISK at
//! test time (resolved via `$(rlocationpath)` against `TEST_SRCDIR`/
//! `RUNFILES_DIR`), with the `mcp-re-test-paths` cargo fallback — so the guard
//! re-reads reality and a hardcoded absolute path is never used.
//!
//! std only (no new crates).

use std::path::PathBuf;

/// Forbidden over-claim phrases (case-insensitive substring match). Co-located
/// with §A's **Forbidden claim** column in `docs/spec/v0.5-claim-matrix.md`
/// (ADR-MCPS-036 §Decision item 4) — keep the two in sync.
const FORBIDDEN_PHRASES: &[&str] = &[
    "prevents tool poisoning",
    "provides RBAC",
    "proves a signer is a safe agent",
    "proves on_behalf_of delegation is legitimate",
    "authorization_hash_mismatch",
    "unconditional multi-node replay",
    "secures all MCP",
    "validates tool descriptors",
];

/// Negation / non-existence markers. If one of these appears on the same line as
/// a forbidden phrase, the phrase is being repudiated (a non-goal), not asserted
/// — exactly how the claim matrix and boundary doc name the forbidden wording in
/// prose. Lower-cased before comparison.
const NEGATION_MARKERS: &[&str] = &[
    "no ",
    "not ",
    "never",
    "forbidden",
    "does not",
    "do not",
    "cannot",
    "outside core",
    "reappears",
    "policy-layer",
    "no such",
    "non-goal",
    "by design", // "Tool safety is `none` by design" framing
];

/// The proposal-facing docs scanned by this guard, paired with the runfile env
/// key that delivers each. Proposal-facing ONLY — no ADRs, no v0.3 files, no
/// fixtures.
const SCANNED_DOCS: &[(&str, &str)] = &[
    (
        "docs/spec/security-boundary.md",
        "MCP_RE_DOC_SECURITY_BOUNDARY",
    ),
    ("docs/spec/v0.5-claim-matrix.md", "MCP_RE_DOC_CLAIM_MATRIX"),
    (
        "docs/spec/threat-coverage-matrix.md",
        "MCP_RE_DOC_THREAT_COVERAGE",
    ),
    ("docs/spec/composability.md", "MCP_RE_DOC_COMPOSABILITY"),
    ("docs/spec/proposal-scope.md", "MCP_RE_DOC_PROPOSAL_SCOPE"),
];

fn locate(env_key: &str) -> PathBuf {
    mcp_re_test_paths::resolve_runfile(env_key)
}

fn read(env_key: &str) -> String {
    let path = locate(env_key);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"))
}

/// `true` iff this `|`-delimited markdown table row carries the forbidden phrase
/// inside a column whose header is "Forbidden claim". `header` is the table's
/// header row (the most recent `| … |` line that names "Forbidden claim").
fn phrase_is_in_forbidden_column(row: &str, header: &str, phrase_lc: &str) -> bool {
    if !row.trim_start().starts_with('|') {
        return false;
    }
    let header_lc = header.to_lowercase();
    // Index of the "forbidden claim" cell in the header (split on '|').
    let forbidden_col = header_lc
        .split('|')
        .position(|cell| cell.trim() == "forbidden claim");
    let Some(col) = forbidden_col else {
        return false;
    };
    let row_lc = row.to_lowercase();
    row_lc
        .split('|')
        .nth(col)
        .map(|cell| cell.contains(phrase_lc))
        .unwrap_or(false)
}

/// `true` iff a negation/non-existence marker appears on this (lower-cased) line.
fn line_has_negation(line_lc: &str) -> bool {
    for &m in NEGATION_MARKERS {
        if m == "never" {
            // Avoid substring false-positives like "whenever" matching "never".
            if line_lc
                .split(|c: char| !c.is_ascii_alphabetic())
                .any(|w| w == "never")
            {
                return true;
            }
            continue;
        }
        if line_lc.contains(m) {
            return true;
        }
    }
    false
}

/// Scan one doc; return every (1-based line number, phrase) pair that is a LIVE
/// (asserted) occurrence of a forbidden phrase — i.e. not inside a forbidden
/// table column and not negated.
fn live_claim_hits(text: &str) -> Vec<(usize, &'static str)> {
    let mut hits = Vec::new();
    // Track the most recent markdown table header that contains "forbidden claim".
    let mut current_forbidden_header: Option<String> = None;
    for (idx, line) in text.lines().enumerate() {
        // The forbidden-claim table context only applies while we're inside that table.
        if current_forbidden_header.is_some() && !line.trim_start().starts_with('|') {
            current_forbidden_header = None;
        }
        let line_lc = line.to_lowercase();
        if line_lc.contains("forbidden claim") && line.trim_start().starts_with('|') {
            current_forbidden_header = Some(line.to_string());
        }
        for &phrase in FORBIDDEN_PHRASES {
            let phrase_lc = phrase.to_lowercase();
            if !line_lc.contains(&phrase_lc) {
                continue;
            }
            // Legitimate: inside the "Forbidden claim" column of the current table.
            if let Some(header) = &current_forbidden_header {
                if phrase_is_in_forbidden_column(line, header, &phrase_lc) {
                    continue;
                }
            }
            // Legitimate: an explicitly negated / non-existence sentence.
            if line_has_negation(&line_lc) {
                continue;
            }
            hits.push((idx + 1, phrase));
        }
    }
    hits
}

// --- the guard ---------------------------------------------------------------

/// No forbidden phrase appears as a LIVE (asserted) claim in any proposal-facing
/// doc. If this fails, FIX the doc wording to the compliant form (CONTEXT.md),
/// never weaken the guard.
#[test]
fn no_forbidden_phrase_is_an_asserted_claim() {
    let mut violations: Vec<String> = Vec::new();
    for (doc, env_key) in SCANNED_DOCS {
        let text = read(env_key);
        for (line_no, phrase) in live_claim_hits(&text) {
            violations.push(format!(
                "{doc}:{line_no}: asserted forbidden claim {phrase:?}"
            ));
        }
    }
    assert!(
        violations.is_empty(),
        "forbidden over-claim wording asserted as a live claim in proposal-facing \
         docs (fix the doc wording to the compliant form per CONTEXT.md / §A's \
         forbidden column — do NOT weaken this guard):\n  {}",
        violations.join("\n  ")
    );
}

/// Optional add-on (ADR-MCPS-032 §Compliance): `docs/SECURITY_BOUNDARY.md` is a
/// redirect stub with no live claim — it points at the canonical
/// `docs/spec/security-boundary.md` and carries no forbidden over-claim.
#[test]
fn legacy_security_boundary_is_a_stub_with_no_live_claim() {
    let text = read("MCP_RE_DOC_SECURITY_BOUNDARY_STUB");
    // It must redirect to the canonical doc.
    assert!(
        text.to_lowercase().contains("spec/security-boundary.md"),
        "docs/SECURITY_BOUNDARY.md must redirect to docs/spec/security-boundary.md"
    );
    // And it must carry no asserted forbidden claim.
    let hits = live_claim_hits(&text);
    assert!(
        hits.is_empty(),
        "docs/SECURITY_BOUNDARY.md must be a stub with no live claim, but found: {hits:?}"
    );
    // A stub, not a competing claim doc: keep it short (defensive ceiling).
    assert!(
        text.lines().count() <= 20,
        "docs/SECURITY_BOUNDARY.md grew beyond a redirect stub ({} lines) — it must \
         never become a competing claim doc (ADR-MCPS-032)",
        text.lines().count()
    );
}

/// Sanity: the guard actually read every scanned doc (non-empty), so a broken
/// runfiles wiring resolving to an empty file cannot masquerade as "no
/// forbidden claims".
#[test]
fn guard_inputs_are_non_empty() {
    for (doc, env_key) in SCANNED_DOCS {
        assert!(
            !read(env_key).trim().is_empty(),
            "scanned zero bytes for {doc} — runfiles wiring is broken"
        );
    }
    assert!(
        !read("MCP_RE_DOC_SECURITY_BOUNDARY_STUB").trim().is_empty(),
        "scanned zero bytes for docs/SECURITY_BOUNDARY.md — runfiles wiring is broken"
    );
}

/// Self-check of the detector (the "would fail on drift" demonstration kept
/// green without mutating any committed doc): an ASSERTED forbidden phrase is
/// caught, while the same phrase inside a forbidden-claim table column or a
/// negated sentence is allowed. Proves the negative path without weakening the
/// real assertion.
#[test]
fn detector_catches_asserted_claim_but_allows_repudiation() {
    // Asserted as a live capability -> a hit.
    let asserted = "MCP-RE provides RBAC for every tool call.";
    assert_eq!(
        live_claim_hits(asserted).len(),
        1,
        "an asserted forbidden phrase must be caught"
    );

    // Inside the Forbidden-claim column of a table -> allowed.
    let table = "| Cap | Allowed claim | Forbidden claim |\n\
                 | Authz | Core binds | Core provides RBAC; unconditional multi-node replay safety |";
    assert!(
        live_claim_hits(table).is_empty(),
        "a phrase in the Forbidden-claim column must NOT be a hit"
    );

    // A negated / non-existence sentence -> allowed.
    let negated = "Core never validates artifact contents, provides RBAC, or emits a mismatch.";
    assert!(
        live_claim_hits(negated).is_empty(),
        "a negated forbidden phrase must NOT be a hit"
    );
    let no_token = "No `authorization_hash_mismatch`. Core binds the hash.";
    assert!(
        live_claim_hits(no_token).is_empty(),
        "a 'No <token>' non-existence statement must NOT be a hit"
    );
}
