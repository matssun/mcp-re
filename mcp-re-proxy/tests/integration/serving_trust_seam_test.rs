// SPDX-License-Identifier: Apache-2.0
//! The serving trust seam is built ONCE, from the authority materialization produced.
//!
//! `revocation_serving_wiring_test` pins what the seam does: whatever the tier decides, the
//! Request slot obeys, and every non-active outcome yields no actor. It takes the seam as
//! given. What it cannot say is that the seam the serving path actually runs was built from
//! the deployment's materialized trust authority rather than from something frozen beside it
//! — which is the exact defect ADR-MCPS-021 recorded: the resolver chain was constructed,
//! its guarantee printed, and then dropped, while the PEP resolved from a `HashMap` frozen at
//! process start.
//!
//! That defect is invisible to every behavioural control, because each still measures a true
//! thing about a correctly-composed seam. So the decidable property is composition:
//!
//! > The composition root calls `build_actor_resolver` exactly once, passing the reloading
//! > signer snapshot and the tier resolver, and the seam consults the tier on every Request
//! > slot resolution rather than a map it captured.
//!
//! # Why a source scan and not a type
//!
//! `ActorResolver` is `Box<dyn Fn(&str, SignerSlot) -> ResolverOutcome + Send + Sync>` — a
//! closure seam. Anything that can produce that signature is an inhabitant, so privacy buys
//! nothing here: if the value is wrong, it is the composition root's bug, and the root is
//! entitled to build one (`docs/dev/sealed-owners.md`). A scan is EVIDENCE for the
//! composition, never unconstructibility, and deleting it leaves the old defect compiling.

/// The seam's builder, and the two operands that make it the MATERIALIZED authority rather
/// than a snapshot beside it.
///
/// `signers()` is the reloading directory's projection — read through the snapshot so a kid
/// removed from the trust file leaves the request-signer set at the same instant it stops
/// resolving. `resolver` is the ADR-MCPS-021 revocation tier. Passing either as a captured
/// value would re-freeze trust at process start, which is the defect this pins.
const BUILDER: &str = "build_actor_resolver";
const MATERIALIZED_OPERANDS: &[&str] = &["signers()", "Arc::clone(&resolver)"];

/// What the seam must reach on the Request slot: the tier, per call.
const PER_REQUEST_TIER: &str = "request_trust.resolve(";

/// What it must NOT hold: a map captured at build time. The historical defect by name.
const FROZEN_CAPTURE: &str = "HashMap";

fn app_source() -> String {
    let path = mcp_re_test_paths::resolve_runfile("MCP_RE_APP_SRC");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"))
}

/// Everything outside a `#[cfg(test)]`-family region, by brace depth from the attribute.
///
/// The same definition `scripts/module_size_gate.py` uses, and for the same reason: a
/// fixture that builds a resolver from a literal map is evidence, not a production route,
/// and counting resumes after the region so production below a test module is still read.
fn production(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let mut kept = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim_start().starts_with("#[cfg(test)]")
            || lines[i].trim_start().starts_with("#[cfg(all(test")
        {
            let mut depth: i64 = 0;
            let mut opened = false;
            while i < lines.len() {
                depth += lines[i].matches('{').count() as i64;
                depth -= lines[i].matches('}').count() as i64;
                if lines[i].contains('{') {
                    opened = true;
                }
                i += 1;
                if opened && depth <= 0 {
                    break;
                }
            }
            continue;
        }
        kept.push(lines[i]);
        i += 1;
    }
    kept.join("\n")
}

/// The body of `fn <name>`, by brace depth from its opening brace.
fn body_of(text: &str, name: &str) -> Option<String> {
    let needle = format!("fn {name}");
    let at = text.find(&needle)?;
    let open = at + text[at..].find('{')?;
    let bytes: Vec<char> = text[open..].chars().collect();
    let mut depth = 0i64;
    for (offset, c) in bytes.iter().enumerate() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(bytes[..=offset].iter().collect());
                }
            }
            _ => {}
        }
    }
    None
}

/// How many times `name` is CALLED — occurrences of `name(` that are not the definition.
fn calls(text: &str, name: &str) -> usize {
    text.matches(&format!("{name}("))
        .count()
        .saturating_sub(text.matches(&format!("fn {name}(")).count())
}

/// The composition root builds the seam once, from the materialized authority.
#[test]
fn the_serving_trust_seam_is_built_once_from_the_materialized_authority() {
    let source = production(&app_source());
    assert_eq!(
        calls(&source, BUILDER),
        1,
        "the composition root must call `{BUILDER}` exactly once. None is a serving path \
         whose seam came from somewhere this test cannot see; more is two seams that happen \
         to agree today."
    );
    for operand in MATERIALIZED_OPERANDS {
        assert!(
            source.contains(operand),
            "the composition root no longer passes `{operand}` to the seam. Both operands \
             ARE the materialization: the reloading snapshot and the revocation tier. A \
             value captured beside them re-freezes trust at process start, which is the \
             ADR-MCPS-021 defect."
        );
    }
}

/// The seam consults the tier per request, and holds no map of its own.
#[test]
fn the_seam_resolves_through_the_tier_rather_than_a_frozen_map() {
    let source = production(&app_source());
    let seam = body_of(&source, BUILDER).expect("the seam builder must be defined in app.rs");
    assert!(
        seam.contains(PER_REQUEST_TIER),
        "the seam no longer reaches `{PER_REQUEST_TIER}`. Resolving from anything else means \
         a key revoked in the trust store keeps verifying until restart, on every tier."
    );
    assert!(
        !seam.contains(FROZEN_CAPTURE),
        "the seam captures a `{FROZEN_CAPTURE}`. That is the defect by name: trust frozen at \
         process start, behind a resolver chain whose guarantee is printed and dropped."
    );
}

/// The rules detect what they claim to.
///
/// Without this, a matcher that never matches leaves both assertions vacuously true, and a
/// green run would mean nothing at all.
#[test]
fn the_rules_would_catch_each_regression() {
    let one = "fn run() { let r = build_actor_resolver(signers(), Arc::clone(&resolver)); }";
    assert_eq!(calls(one, BUILDER), 1, "one call must count as one");
    assert_eq!(
        calls(&format!("pub fn {BUILDER}(a: u8) {{}}\n{one}"), BUILDER),
        1,
        "the definition must not be counted as a call"
    );
    assert_eq!(
        calls("fn run() {}", BUILDER),
        0,
        "a missing call must be seen"
    );

    let seam = format!("fn {BUILDER}() {{ let m = HashMap::new(); }}");
    let body = body_of(&seam, BUILDER).expect("the helper must find a body");
    assert!(body.contains(FROZEN_CAPTURE), "a captured map must be seen");
    assert!(
        !body.contains(PER_REQUEST_TIER),
        "a seam that never reaches the tier must be seen"
    );

    // Test code is out of scope, so a fixture cannot make either rule pass or fail.
    assert_eq!(
        calls(
            &production("#[cfg(test)]\nmod tests {\n    build_actor_resolver();\n}\n"),
            BUILDER
        ),
        0,
        "a call inside a test region is not a production call"
    );
    // Production below a test module is still production.
    assert_eq!(
        calls(
            &production("#[cfg(test)]\nmod tests {\n}\nfn late() { build_actor_resolver(); }\n"),
            BUILDER
        ),
        1,
        "a call below the test module must still be seen"
    );
}
