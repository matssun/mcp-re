// SPDX-License-Identifier: Apache-2.0
//! A stage's transition is the stage's. The assembly may not state one.
//!
//! ADR-MCPRE-057 §4 puts the exchange lifecycle in a value, and
//! `ExchangeProgress::advance` owns transition LEGALITY: `(state, event)` is checked on
//! every advance of every build, and a refused step latches an anomaly that degrades the
//! exchange's retry claim to full strength. That is not the whole invariant.
//!
//! What it does not own is the correspondence between *the work happened* and *the event
//! was emitted*. `handle` used to run a stage and then state its event on the next line —
//! twenty such statements, in the one function where every refusal's retry contract is
//! decided. Apply the R-SEAL operational test: delete one and the machine is silently
//! behind the code until some later advance happens to be illegal. A check that can be
//! deleted is a check being remembered, not owned.
//!
//! `Established<T>` closes it. A stage that succeeds returns the event it justifies, and
//! `ExchangeProgress::establish` is the only way to open one — so the assembly cannot reach
//! a stage's value without the machine learning the stage ran, and there is no `advance`
//! call left at the call site to forget.
//!
//! # What this test pins, and why it is a source scan
//!
//! The seal itself is the type, and the compiler enforces it. What the compiler cannot say
//! is that nobody has ADDED an `advance` back alongside a stage — which is the form the
//! regression takes, because it compiles and the relation accepts it (the event is legal
//! from that state; it was just already emitted).
//!
//! So the decidable property is disjointness:
//!
//! > No event established by a stage is also named by an `advance` in the serving path.
//!
//! and, so the list stays a measurement rather than a memory, the assembly's own events are
//! inventoried with the reason each one is the ASSEMBLY's fact and not some stage's.

use std::collections::BTreeSet;

/// The transitions the assembly states itself, and why each is the assembly's fact.
///
/// A stage establishes what its own work justifies. These six are not any stage's: they
/// are established by the shape of the pipeline around the stages, so there is no function
/// whose success could carry them. "The assembly" is `handle` together with its region
/// functions — the code that COMPOSES stages rather than performing one.
const ASSEMBLY_OWNED: &[(&str, &str)] = &[
    (
        "ContinuationRetired",
        "decided by the answering-commitment region from a `Retirement`, not by the \
         outcomes do not proceed, and which of them spends a human's approval is a fact \
         about the exchange rather than about the call",
    ),
    (
        "BackendDispatched",
        "emitted at the handoff and BEFORE the await, so a cancelled or panicking dispatch \
         cannot leave the exchange claiming nothing happened. A value returned by the \
         dispatch could only be built after it returned, which is the wrong side of the \
         threshold",
    ),
    (
        "ContinuationNotRequired",
        "the absence of an obligation. No work establishes it — it is what the classifier \
         NOT having opened a leg means, and the arm that states it calls nothing",
    ),
    (
        "EvidenceRetained",
        "`retain_accepted` answers with the refusal or with nothing, because it is shared \
         with the notification terminal, which reaches it from a different state",
    ),
    (
        "TerminalResponseServed",
        "the exchange is served on the next line; nothing runs between the fact and the \
         claim, so there is no work to carry it",
    ),
    (
        "OpenLegResponseServed",
        "the other terminal, chosen from the same reply class. Both are the assembly \
         which claim this reply makes, not a step either of them performs",
    ),
];

/// Every `ExchangeEvent::` variant named inside the balanced argument list of each `call`.
///
/// Paren-matched rather than line-matched: rustfmt splits both forms across lines
/// (`Established::new(\n    value,\n    ExchangeEvent::X,\n)`), and a line matcher would
/// see neither the multi-line establishes nor the `advance(match class { .. })` terminal.
fn events_named_in(source: &str, call: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for (index, _) in source.match_indices(call) {
        let after = &source[index + call.len()..];
        let mut depth = 1usize;
        let mut end = after.len();
        for (offset, ch) in after.char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = offset;
                        break;
                    }
                }
                _ => {}
            }
        }
        for (at, _) in after[..end].match_indices("ExchangeEvent::") {
            let rest = &after[at + "ExchangeEvent::".len()..];
            let variant: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !variant.is_empty() {
                found.insert(variant);
            }
        }
    }
    found
}

/// The serving path's production half. A fixture in a test module must not be able to make
/// this gate pass or fail — and production below a test module must still be measured, so
/// the region definition is [`mcp_re_test_paths::rust_source`]'s rather than a truncation.
fn production_half(source: &str) -> String {
    mcp_re_test_paths::rust_source::production_half(source)
}

/// Every production line of the serving path — the assembly and every region under it.
///
/// The property is about THE SERVING PATH, not about one file of it. When the pipeline
/// became one module per region, a scan of `mod.rs` alone would have reported a clean pass
/// over an assembly that no longer contains most of the pipeline, and a region that kept an
/// `advance` beside a stage would simply have been out of scope. A gate's scope is part of
/// its measurement.
///
/// The scope is the DIRECTORY the anchor file sits in, walked, rather than a list of region
/// files: a list would have to learn about the next region, and the failure mode of a stale
/// list is a clean pass over unmeasured code. Under Bazel the directory is the runfiles
/// copy, which the target's `glob` populates; under cargo it is the source tree.
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
        "the serving path is one file at {root:?} — the walk found no regions, and every \
         assertion below would then be about the assembly alone"
    );
    let mut whole = String::new();
    for path in files {
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
        // Each file's production half separately: concatenating first would let one file's
        // unterminated test region swallow the next file's production code.
        whole.push_str(&production_half(&text));
        whole.push('\n');
    }
    whole
}

fn collect_rust_files(dir: &std::path::Path, into: &mut Vec<std::path::PathBuf>) {
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

/// A stage's event is never also stated by the assembly.
#[test]
fn no_transition_a_stage_establishes_is_also_advanced_by_the_serving_path() {
    let production = serving_source();
    let production = production.as_str();
    let by_stages = events_named_in(production, "Established::new(");
    let by_assembly = events_named_in(production, ".advance(");

    assert!(
        !by_stages.is_empty(),
        "no stage declares an event — the matcher has stopped matching, and the assertion \
         below would pass on any source at all"
    );

    let both: Vec<&String> = by_stages.intersection(&by_assembly).collect();
    assert!(
        both.is_empty(),
        "{both:?} is established by a stage AND advanced by the serving path. The stage \
         already tells the machine it ran; the extra advance is the remembered statement \
         `Established` exists to remove. Delete the advance, not the stage's event."
    );
}

/// The assembly states exactly the six transitions that are its own.
#[test]
fn the_serving_path_states_only_the_assembly_s_own_transitions() {
    let declared: BTreeSet<String> = ASSEMBLY_OWNED.iter().map(|(e, _)| e.to_string()).collect();
    let actual = events_named_in(&serving_source(), ".advance(");

    let undeclared: Vec<&String> = actual.difference(&declared).collect();
    assert!(
        undeclared.is_empty(),
        "the serving path advances {undeclared:?} itself. Before adding to ASSEMBLY_OWNED, \
         ask which function's SUCCESS establishes this fact — if one does, the event \
         belongs in its `Established`, where it cannot be forgotten."
    );

    let stale: Vec<&String> = declared.difference(&actual).collect();
    assert!(
        stale.is_empty(),
        "ASSEMBLY_OWNED names {stale:?}, which the serving path no longer advances. An event \
         that found a stage should leave this list, so the list stays a measurement."
    );
}

/// The rule detects what it claims to.
///
/// Without this, a matcher that never matches leaves both assertions above vacuously true,
/// and a green run would mean nothing at all.
#[test]
fn the_rule_would_catch_a_reintroduced_advance() {
    let regressed = "fn f() { let v = Established::new(x, ExchangeEvent::ReplayAdmitted); \
                     progress.advance(ExchangeEvent::ReplayAdmitted); }";
    let by_stages = events_named_in(regressed, "Established::new(");
    let by_assembly = events_named_in(regressed, ".advance(");
    assert!(
        by_stages.contains("ReplayAdmitted") && by_assembly.contains("ReplayAdmitted"),
        "the matcher must see both halves of the regression"
    );

    let split = "fn f() {\n    progress.advance(match class {\n        A => \
                 ExchangeEvent::TerminalResponseServed,\n        B => \
                 ExchangeEvent::OpenLegResponseServed,\n    });\n}";
    let both = events_named_in(split, ".advance(");
    assert!(
        both.contains("TerminalResponseServed") && both.contains("OpenLegResponseServed"),
        "a multi-line advance names both of its events; a line matcher would see neither"
    );

    assert!(
        events_named_in(
            &production_half("fn f() {}\n#[cfg(test)]\nmod tests { progress.advance(ExchangeEvent::ReplayAdmitted); }"),
            ".advance(",
        )
        .is_empty(),
        "test code is out of scope, so a fixture cannot make the gate fail or pass"
    );
    // And the other direction: an advance reintroduced BELOW the test module is production
    // and must be seen. A truncating split reported a clean pass over every line after the
    // first `#[cfg(test)]`, which in this file is not the test module at all.
    assert!(
        events_named_in(
            &production_half("#[cfg(test)]\nmod tests {\n}\nfn late() { progress.advance(ExchangeEvent::ReplayAdmitted); }\n"),
            ".advance(",
        )
        .contains("ReplayAdmitted"),
        "an advance below the test module must still be seen"
    );
}

/// The inventory is not a bare list: every entry states why the transition is the
/// assembly's rather than some stage's.
#[test]
fn every_assembly_owned_transition_states_why_no_stage_carries_it() {
    for (event, reason) in ASSEMBLY_OWNED {
        assert!(
            reason.len() > 40,
            "{event} has no real justification: {reason:?}"
        );
    }
}
