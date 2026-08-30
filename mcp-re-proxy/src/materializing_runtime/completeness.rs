// SPDX-License-Identifier: Apache-2.0
//! WHAT a materialization must have before it may be called materialized, and what each
//! missing thing is called.
//!
//! One authority, and the reason it is one: a `Materialized` lifecycle over an incomplete
//! resource graph is exactly the equivalence [`super::MaterializingRuntime`] exists to
//! prevent, so the set of required resources and the refusals naming them must not be
//! restated anywhere else. Every refusal below is an INTERNAL error — none of these
//! conditions is reachable from configuration, a peer, or a clock — but each is reported
//! rather than asserted, because the composition root already returns this error type and a
//! refusal to serve is strictly better than a panic on the startup path.
//!
//! The read-back accessors live here for the same reason as the assembly precondition:
//! "this resource is not installed" is one fact, and the three projections a composition
//! root reads between installs are the other place it can be observed.

use super::MaterializingRuntime;
use super::SigningPlane;
use super::TlsPlane;
use super::TrustPlane;

/// What a required resource is called, for the refusals below. A `&'static str` rather than
/// an enum because its only use is the message.
const REQUIRED: [&str; 4] = ["trust plane", "signing plane", "TLS plane", "proxy"];

/// The first required resource `present` reports absent, in declaration order.
///
/// The array is positional and its order is [`REQUIRED`]'s: the caller builds it from the
/// four fields in the same sequence, which is what lets one name stand for one slot.
pub(super) fn first_missing(present: [bool; REQUIRED.len()]) -> Option<&'static str> {
    REQUIRED
        .iter()
        .zip(present)
        .find(|(_, ok)| !ok)
        .map(|(name, _)| *name)
}

/// Why a composition root could not read back a resource it has not installed.
pub(super) fn absent(what: &str) -> String {
    format!("internal error: the {what} was read before it was installed")
}

/// Why an assembly may not proceed: the graph is missing `what`.
pub(super) fn incomplete(what: &str) -> String {
    format!(
        "internal error: materialization finished without the {what}; the runtime would \
         report Materialized over an incomplete resource graph"
    )
}

/// Why an assembly may not proceed even though the check above passed.
///
/// Unreachable while `finish` consumes `self` and nothing between the two lines takes a
/// resource. It exists so that guarantee is carried by a value rather than by those lines
/// staying adjacent — the same reason the take is one destructuring and not four
/// assertions.
pub(super) fn vanished() -> String {
    "internal error: a required resource was taken between the completeness check and the \
     assembly"
        .to_owned()
}

impl MaterializingRuntime {
    /// The three resources a composition root reads back after installing them.
    ///
    /// Each REPORTS an absent plane rather than asserting one: the guarantee otherwise
    /// lives in the adjacency of two statements in another module, and the composition
    /// root already returns this error type for a materialization it cannot complete.
    pub(crate) fn trust(&self) -> Result<&TrustPlane, String> {
        self.trust.as_ref().ok_or_else(|| absent("trust plane"))
    }

    pub(crate) fn tls(&self) -> Result<&TlsPlane, String> {
        self.tls.as_ref().ok_or_else(|| absent("TLS plane"))
    }

    pub(crate) fn signing(&self) -> Result<&SigningPlane, String> {
        self.signing.as_ref().ok_or_else(|| absent("signing plane"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every slot is named, and the FIRST absence is the one reported — so a graph missing
    /// several does not report an arbitrary one.
    #[test]
    fn the_first_missing_resource_is_the_one_named() {
        assert_eq!(first_missing([true; 4]), None);
        for (index, name) in REQUIRED.iter().enumerate() {
            let mut present = [true; 4];
            #[allow(clippy::indexing_slicing)] // `index` comes from `REQUIRED`'s own enumerate
            {
                present[index] = false;
            }
            assert_eq!(first_missing(present), Some(*name));
        }
        assert_eq!(first_missing([false; 4]), Some(REQUIRED[0]));
    }
}
