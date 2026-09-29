// SPDX-License-Identifier: Apache-2.0
//! The guard's report — which `_meta` positions a caller had seeded with the
//! reserved verified-context key.

/// Every `_meta` position from which the guard removed a caller-authored
/// verified-context block, named by the path an inner server would have read it
/// from: `_meta`, `params._meta`, `params[0]._meta`, `params.arguments._meta`.
///
/// The value was removed from every one of them; this is the record of the attempt,
/// and the position is the interesting fact about the method.
///
/// **There is no `Default`.** An inhabitant reading "a guard inspected this body and
/// found nothing" is producible only by a guard that inspected a body — the whole
/// reason the strip returns a `Result` rather than a bool is that "nothing was
/// seeded" and "nothing was inspected" must not be the same value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeededMetaPositions {
    paths: Vec<String>,
}

impl SeededMetaPositions {
    /// The guard's own constructor, private to this module tree: possession of a
    /// report means a descent produced it.
    pub(super) fn found(paths: Vec<String>) -> Self {
        SeededMetaPositions { paths }
    }

    /// Whether the caller seeded the reserved key anywhere in the body.
    pub fn any(&self) -> bool {
        !self.paths.is_empty()
    }

    /// Whether the body's top-level `_meta` carried the reserved key.
    pub fn top_level(&self) -> bool {
        self.names(&["_meta"])
    }

    /// Whether `params._meta` carried it, for a `params` that is an object.
    pub fn params_object(&self) -> bool {
        self.names(&["params._meta"])
    }

    /// The seeded positions, each named by the path an inner server would have read
    /// it from, in document order.
    pub fn positions(&self) -> Vec<String> {
        self.paths.clone()
    }

    fn names(&self, wanted: &[&str]) -> bool {
        self.paths
            .iter()
            .any(|path| wanted.contains(&path.as_str()))
    }
}

impl std::fmt::Display for SeededMetaPositions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let named = self.paths.join(", ");
        f.write_str(if named.is_empty() {
            "none"
        } else {
            named.as_str()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_report_names_the_positions_it_was_built_from() {
        let seeded =
            SeededMetaPositions::found(vec!["_meta".to_owned(), "params[0]._meta".to_owned()]);
        assert!(seeded.any());
        assert!(seeded.top_level());
        assert!(!seeded.params_object());
        assert_eq!(seeded.to_string(), "_meta, params[0]._meta");
    }

    #[test]
    fn an_empty_report_names_nothing() {
        let seeded = SeededMetaPositions::found(Vec::new());
        assert!(!seeded.any());
        assert!(!seeded.top_level());
        assert_eq!(seeded.to_string(), "none");
    }
}
