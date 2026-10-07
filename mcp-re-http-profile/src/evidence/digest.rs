// SPDX-License-Identifier: Apache-2.0
//! The split-form handle as it appears on the wire: a CLAIM about some role's digest,
//! read from a peer or written into a block, never itself evidence of which role it is.

use serde::Deserialize;
use serde::Serialize;

use super::role::labeled_digest_value;
use super::role::EvidenceRole;
use crate::ids::EVIDENCE_DIGEST_ALG;
#[cfg(feature = "verify")]
use verus_builtin_macros::{verus_spec, verus_verify};
#[cfg(feature = "verify")]
#[allow(unused_imports)]
use vstd::prelude::*;

/// A split-form digest handle (`digest_alg`/`digest_value`) as carried in the HTTP
/// profile's body evidence.
///
/// Public fields, deliberately: this is the wire form, deserialized from unauthenticated
/// bodies, so any value is constructible and holding one proves nothing. The role-typed
/// derivations are [`super::RequestRoleEvidence`] and [`super::ResponseRoleEvidence`]; a
/// claim is checked against one of them, or against a role with
/// [`matches_labeled`](Self::matches_labeled).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestEvidenceDigest {
    pub digest_alg: String,
    pub digest_value: String,
}

/// Characters in an unpadded base64url SHA-256 digest.
const DIGEST_VALUE_LEN: usize = 43;

impl RequestEvidenceDigest {
    /// Derive the handle over the mandated input under `role`'s label (#416 rev 2
    /// §7.1/§7.3): `base64url-no-pad(SHA-256(label || 0x00 || bytes))`.
    pub fn over_labeled(role: EvidenceRole, bytes: &[u8]) -> Self {
        RequestEvidenceDigest {
            digest_alg: EVIDENCE_DIGEST_ALG.to_owned(),
            digest_value: labeled_digest_value(role, bytes),
        }
    }

    /// Whether this claim has the shape a derived handle has: the profile's algorithm and
    /// an unpadded base64url SHA-256 value. Says nothing about which bytes or role.
    pub fn is_well_formed(&self) -> bool {
        self.digest_alg == EVIDENCE_DIGEST_ALG
            && self.digest_value.len() == DIGEST_VALUE_LEN
            && crate::block::is_b64url_no_pad(&self.digest_value)
    }

    /// Whether this handle IS `other`: the same algorithm and the same value.
    // Proved: a true answer is exactly the two fields comparing equal. The digest itself
    // stays uninterpreted, so no cryptographic property is claimed here.
    #[cfg_attr(feature = "verify", verus_verify)]
    #[cfg_attr(feature = "verify", verus_spec(result =>
        ensures
            result == (self.digest_alg@ == other.digest_alg@
                && self.digest_value@ == other.digest_value@),
    ))]
    pub fn same_handle(&self, other: &RequestEvidenceDigest) -> bool {
        self.digest_alg.eq(&other.digest_alg) && self.digest_value.eq(&other.digest_value)
    }

    /// Constant-shape check that this handle commits to `bytes` IN `role`. A handle that
    /// commits to the same bytes in a different role does not match.
    // ADR-MCPRE-059 ASM-0023: trusted at exactly the strength the role-separation contract
    // needs — a true answer means this handle's value IS the labeled digest of these bytes
    // under that role's label. The digest itself stays uninterpreted.
    #[cfg_attr(feature = "verify", verus_verify(external_body))]
    #[cfg_attr(feature = "verify", verus_spec(result =>
        ensures
            result ==> self.digest_value@ == crate::verus_std_specs::labeled_digest(
                crate::evidence::prover_model::role_label(role), bytes@),
    ))]
    pub fn matches_labeled(&self, role: EvidenceRole, bytes: &[u8]) -> bool {
        self.digest_alg == EVIDENCE_DIGEST_ALG
            && self.digest_value == labeled_digest_value(role, bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_derived_handle_is_well_formed_and_matches_only_its_role() {
        let h = RequestEvidenceDigest::over_labeled(EvidenceRole::RequestState, b"state");
        assert!(h.is_well_formed());
        assert!(h.matches_labeled(EvidenceRole::RequestState, b"state"));
        assert!(!h.matches_labeled(EvidenceRole::Request, b"state"));
        assert!(!h.matches_labeled(EvidenceRole::RequestState, b"other"));
    }

    #[test]
    fn a_claim_of_another_shape_is_not_well_formed() {
        let derived = RequestEvidenceDigest::over_labeled(EvidenceRole::Request, b"b");
        for bad in [
            RequestEvidenceDigest {
                digest_alg: "sha-256".into(),
                ..derived.clone()
            },
            RequestEvidenceDigest {
                digest_value: format!("{}=", derived.digest_value),
                ..derived.clone()
            },
            RequestEvidenceDigest {
                digest_value: derived.digest_value.replace(|_: char| true, "+"),
                ..derived.clone()
            },
            RequestEvidenceDigest {
                digest_value: String::new(),
                ..derived.clone()
            },
        ] {
            assert!(!bad.is_well_formed(), "{bad:?}");
        }
    }

    #[test]
    fn same_handle_compares_algorithm_and_value() {
        let a = RequestEvidenceDigest::over_labeled(EvidenceRole::Request, b"x");
        assert!(a.same_handle(&a.clone()));
        let other_alg = RequestEvidenceDigest {
            digest_alg: "sha-256".into(),
            ..a.clone()
        };
        assert!(!a.same_handle(&other_alg));
    }
}
