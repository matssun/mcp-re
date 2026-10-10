// SPDX-License-Identifier: Apache-2.0
//! The binding's tags and digest, read — and, under `verify`, the specifications those reads
//! are proved against.
//!
//! Each specification is CLOSED: its body is visible only in this module, where the reads are
//! proved to return the fields they name. No proof elsewhere reads the representation the
//! owner keeps private, so the typed-verifier theorem still holds for whatever tags a binding
//! carries, and the digest comparison is proved against the binding's own digest.

use super::ArtifactBinding;
use super::ArtifactType;
use super::BindingType;
#[cfg(feature = "verify")]
use verus_builtin_macros::{verus, verus_spec, verus_verify};
#[cfg(feature = "verify")]
#[allow(unused_imports)]
use vstd::prelude::*;

impl ArtifactBinding {
    /// What the artifact is.
    #[cfg_attr(feature = "verify", verus_verify)]
    #[cfg_attr(feature = "verify", verus_spec(out =>
        ensures out == crate::verus_std_specs::artifact_type_of(self),
    ))]
    pub fn artifact_type(&self) -> ArtifactType {
        self.artifact_type
    }

    /// How the artifact is bound.
    #[cfg_attr(feature = "verify", verus_verify)]
    #[cfg_attr(feature = "verify", verus_spec(out =>
        ensures out == crate::verus_std_specs::binding_type_of(self),
    ))]
    pub fn binding_type(&self) -> BindingType {
        self.binding_type
    }

    /// Whether `candidate` is this binding's digest, byte for byte. `pub(crate)`: the
    /// verifier's digest comparison is the one consumer, and it is proved through this.
    #[cfg_attr(feature = "verify", verus_verify)]
    #[cfg_attr(feature = "verify", verus_spec(result =>
        ensures result == (candidate@ == self.spec_digest_value()),
    ))]
    pub(crate) fn digest_is(&self, candidate: &String) -> bool {
        candidate.eq(&self.digest_value)
    }
}

#[cfg(feature = "verify")]
verus! {
impl ArtifactBinding {
    pub closed spec fn spec_artifact_type(&self) -> ArtifactType {
        self.artifact_type
    }

    pub closed spec fn spec_binding_type(&self) -> BindingType {
        self.binding_type
    }

    pub closed spec fn spec_digest_value(&self) -> Seq<char> {
        self.digest_value@
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reads_return_what_the_binding_was_built_with() {
        let digest = mcp_re_core::b64url_encode(&[7u8; 32]);
        let binding = ArtifactBinding::opaque_from_digest(ArtifactType::OauthMtls, &digest)
            .expect("a legal binding");
        assert_eq!(binding.artifact_type(), ArtifactType::OauthMtls);
        assert_eq!(binding.binding_type(), BindingType::OpaqueDigest);
        assert!(binding.digest_is(&digest));
        assert!(!binding.digest_is(&mcp_re_core::b64url_encode(&[8u8; 32])));
    }
}
