// SPDX-License-Identifier: Apache-2.0
//! Why the deterministic fixtures cannot reach a production build.
//!
//! One fact, and it is not `nonce.rs`'s or `clock.rs`'s: those two own what their production
//! implementations DO, and this owns the boundary that keeps their test doubles off the
//! surface a downstream crate compiles.
//!
//! Audit #81 made that boundary ENFORCED rather than documented, and it has two halves that
//! fail independently:
//!
//! ```text
//! the #[cfg] on each item      a fixture item without it compiles into every build
//! the feature not defaulted    `default = ["test-fixtures"]` satisfies every #[cfg] in
//!                              the crate with no source line changing
//! ```
//!
//! Both are read from the files that are actually built — `include_str!`, at compile time —
//! so a control here cannot pass over a copy of the source or a stale manifest.
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

    /// The other half. `default = ["test-fixtures"]` would satisfy every `#[cfg]` above with
    /// no source line changing, and put both fixtures on every downstream production surface.
    #[test]
    fn the_fixture_feature_is_not_a_default_feature() {
        let manifest = include_str!("../Cargo.toml");
        let features = manifest
            .split_once("[features]")
            .map(|(_, rest)| rest)
            .expect("the manifest declares a [features] table");
        let default_line = features
            .lines()
            .map(str::trim)
            .find(|line| line.starts_with("default"))
            .expect("the [features] table declares `default`");
        assert_eq!(
            default_line, "default = []",
            "`test-fixtures` must stay off by default: it compiles a nonce source with no \
             entropy and a frozen clock"
        );
        assert!(
            features.contains("test-fixtures = []"),
            "the fixture feature is not declared where this control reads it"
        );
    }

    /// And the third way in. The self-dependency that turns the feature on for THIS crate's
    /// own tests is scoped to `[dev-dependencies]`; moving it to `[dependencies]` would
    /// enable it for every downstream consumer, which is the same failure as defaulting it.
    #[test]
    fn the_fixture_feature_is_enabled_only_as_a_dev_dependency() {
        let manifest = include_str!("../Cargo.toml");
        let (before_dev, dev) = manifest
            .split_once("[dev-dependencies]")
            .expect("the manifest declares [dev-dependencies]");
        assert!(
            dev.contains("features = [\"test-fixtures\"]"),
            "the self dev-dependency enabling the fixtures is not where this control reads it"
        );
        assert!(
            !before_dev.contains("features = [\"test-fixtures\"]"),
            "a non-dev dependency enables `test-fixtures`, which puts the entropy-free nonce \
             source and the frozen clock on every downstream production surface"
        );
    }
}
