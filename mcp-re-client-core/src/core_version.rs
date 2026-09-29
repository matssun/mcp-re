// SPDX-License-Identifier: Apache-2.0
//! Which audited core a binding is reporting when it is asked.
//!
//! One fact: **the version a consumer is told is the version of the code that was
//! audited.**
//!
//! # The defect this exists to remove
//!
//! Both published SDK bindings exposed `core_version()` / `coreVersion()` returning their
//! OWN `env!("CARGO_PKG_VERSION")` — the pyo3 shim's `0.1.0`, the N-API shim's `0.1.1` —
//! while the code an audit actually looked at is this crate, at the workspace version. A
//! consumer calling a function named `core_version` is asking which audited core they
//! have; they were told the version of the wrapper in front of it, and the two move
//! independently (r12 R12-1474).
//!
//! The wrapper's own version is not secret and not useless — it is just the answer to a
//! different question, and nothing in either binding asked that one.

/// The audited client core's version.
///
/// `env!` is evaluated where it is WRITTEN, so this constant is the value only because it
/// lives in this crate. That is the whole mechanism: moving this line into a binding would
/// silently make it the binding's version again, which is the defect it replaced.
pub const CORE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::CORE_VERSION;

    /// LOAD-BEARING: the value is THIS crate's, not a caller's. `0.1.x` is what both
    /// binding crates are versioned at, and reporting one of those is the defect.
    #[test]
    fn the_reported_version_is_the_audited_cores_and_not_a_bindings() {
        assert_eq!(CORE_VERSION, env!("CARGO_PKG_VERSION"));
        let (major, minor) = CORE_VERSION.split_once('.').expect("a dotted version");
        let minor: u32 = minor
            .split_once('.')
            .map_or(minor, |(m, _)| m)
            .parse()
            .expect("a numeric minor");
        let major: u32 = major.parse().expect("a numeric major");
        assert!(
            major > 0 || minor >= 17,
            "{CORE_VERSION} looks like a binding crate's version, not the core's"
        );
    }
}
