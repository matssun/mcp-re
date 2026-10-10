// SPDX-License-Identifier: Apache-2.0
//! The policy's two freshness bounds, read — and, under `verify`, the specifications those
//! reads are proved against.
//!
//! Each specification is CLOSED: its body is visible only in this module, where the getter is
//! proved to return the field it names. A proof anywhere else, the freshness theorem among
//! them, learns nothing about a bound beyond its being this policy's, so the theorem still
//! holds for whatever skew and validity window a deployment configures.

use super::VerifierPolicy;
#[cfg(feature = "verify")]
use verus_builtin_macros::{verus, verus_spec, verus_verify};
#[cfg(feature = "verify")]
#[allow(unused_imports)]
use vstd::prelude::*;

impl VerifierPolicy {
    /// The validated skew tolerance, in seconds.
    #[cfg_attr(feature = "verify", verus_verify)]
    #[cfg_attr(feature = "verify", verus_spec(out =>
        ensures out == crate::verus_std_specs::skew_of(self),
    ))]
    pub fn max_clock_skew(&self) -> i64 {
        self.max_clock_skew
    }

    /// The widest accepted `expires - created`, in seconds.
    #[cfg_attr(feature = "verify", verus_verify)]
    #[cfg_attr(feature = "verify", verus_spec(out =>
        ensures out == crate::verus_std_specs::validity_of(self),
    ))]
    pub fn max_signature_validity(&self) -> i64 {
        self.max_signature_validity
    }
}

#[cfg(feature = "verify")]
verus! {
impl VerifierPolicy {
    pub closed spec fn spec_max_clock_skew(&self) -> i64 {
        self.max_clock_skew
    }

    pub closed spec fn spec_max_signature_validity(&self) -> i64 {
        self.max_signature_validity
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_bound_reads_the_value_the_policy_was_built_with() {
        let policy = VerifierPolicy::new(&["ed25519"], 12)
            .expect("a legal policy")
            .with_max_signature_validity(90)
            .expect("a legal window");
        assert_eq!(policy.max_clock_skew(), 12);
        assert_eq!(policy.max_signature_validity(), 90);
    }
}
