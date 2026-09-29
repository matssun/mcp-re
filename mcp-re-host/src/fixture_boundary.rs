// SPDX-License-Identifier: Apache-2.0
//! Why the deterministic fixtures cannot reach a production build.
//!
//! One fact, and it is not `nonce.rs`'s or `clock.rs`'s: those two own what their production
//! implementations DO, and this owns the boundary that keeps their test doubles off the
//! surface a downstream crate compiles.
//!
//! Audit #81 made that boundary ENFORCED rather than documented, and it has three parts that
//! fail independently:
//!
//! ```text
//! the #[cfg] on each item          a fixture item without it compiles into every build
//! the production target            `crate_features = ["test-fixtures"]` on `:mcp_re_host`
//!   compiles no fixture feature    satisfies every #[cfg] with no source line changing
//! the fixture flavor is testonly   without it, a production target may depend on the
//!                                  flavor and link the fixtures
//! ```
//!
//! All three are read from the files that are actually built — `include_str!`, at compile
//! time — so a control here cannot pass over a copy of the source or a stale BUILD file.
//! `testonly` is Bazel's to enforce: analysis refuses a target that is not test-only
//! depending on one that is. `scripts/fixture_feature_gate.py` states the same boundary over
//! every target in the graph.
//!
//! There is no production item in this module. It exists because the fact it measures has no
//! other home: it is a property of the crate's build configuration, and neither of the two
//! modules whose types it protects can state it about the other.

#[cfg(test)]
mod tests {
    /// The gate on each fixture item, read from the source that is built.
    ///
    /// `SeededNonceSource` has NO real entropy and `FixedClock` has no clock behind it. A
    /// production binary that could construct either could be given predictable nonces or
    /// pinned to a frozen `created`/`expires` — in both cases by configuration alone, with
    /// every request still well-formed and correctly signed.
    #[test]
    fn every_fixture_item_is_compiled_only_under_test_or_the_explicit_feature() {
        const GATE: &str = "#[cfg(any(test, feature = \"test-fixtures\"))]";
        for (name, source, production_marker) in [
            (
                "SeededNonceSource",
                include_str!("nonce.rs"),
                "pub struct SystemNonceSource;",
            ),
            (
                "FixedClock",
                include_str!("clock.rs"),
                "pub struct SystemClock;",
            ),
        ] {
            let gated = source.matches(GATE).count();
            assert_eq!(
                gated, 3,
                "{name}: expected the gate on the struct, its inherent impl and its trait \
                 impl; found {gated}. A fixture reachable from a production build is a \
                 predictable value a deployment can be given."
            );
            // Positive control on the scan: the PRODUCTION type in the same file is not
            // gated, so a source that matched everything would fail here.
            assert!(
                source.contains(production_marker),
                "the scan is not reading the file it names for {name}"
            );
        }
    }

    /// The target block `name` declares in this crate's BUILD file.
    fn target_block<'a>(build: &'a str, name: &str) -> &'a str {
        let marker = format!("    name = \"{name}\",\n");
        let at = build
            .find(&marker)
            .unwrap_or_else(|| panic!("BUILD.bazel declares no target `{name}`"));
        let open = build[..at]
            .rfind("(\n")
            .expect("the target opens a rule call");
        let close = build[at..].find("\n)\n").expect("the rule call closes");
        &build[open..at + close]
    }

    /// The production half. A `crate_features` entry on `:mcp_re_host` would satisfy every
    /// `#[cfg]` above with no source line changing, and put both fixtures on every
    /// downstream production surface.
    #[test]
    fn the_production_library_compiles_no_fixture_feature() {
        let library = target_block(include_str!("../BUILD.bazel"), "mcp_re_host");
        assert!(
            library.contains("crate_name = \"mcp_re_host\""),
            "the scan is not reading the production library"
        );
        assert!(
            !library.contains("crate_features") && !library.contains("test-fixtures"),
            "`:mcp_re_host` compiles a feature: `test-fixtures` must stay off the production \
             library, because it compiles a nonce source with no entropy and a frozen clock"
        );
    }

    /// And the consumer half. The flavor that turns the feature on is `testonly`, so Bazel
    /// refuses any production target that depends on it; without that, one dependency edge
    /// links the fixtures into a deployable binary.
    #[test]
    fn the_fixture_flavor_is_testonly() {
        let flavor = target_block(include_str!("../BUILD.bazel"), "mcp_re_host_test_fixtures");
        assert!(
            flavor.contains("crate_features = [\"test-fixtures\"]"),
            "the fixture flavor is not where this control reads it"
        );
        assert!(
            flavor.contains("testonly = True"),
            "`:mcp_re_host_test_fixtures` is not testonly, so a production target may depend \
             on it and link the entropy-free nonce source and the frozen clock"
        );
    }
}
