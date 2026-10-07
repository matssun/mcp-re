// SPDX-License-Identifier: Apache-2.0
//! The artifact verifiers' non-vacuity probe (r12 Ruling 38 §7).
//!
//! `thumbprint_of` is built from two uninterpreted functions, and an uninterpreted symbol can
//! make a postcondition read as a guarantee while constraining nothing. These three functions
//! show it constrains: the positive control must verify, and the two negatives must FAIL — one
//! claims the relation without establishing it, the other contradicts it with a different
//! credential. `verify-verus` builds this module only in the `verus_nonvacuity_probe` target
//! and refuses the lane unless exactly the two negatives fail.
//!
//! Never compiled into a library build: the module needs both the `verify` and the
//! `verus_nonvacuity_probe` cfgs, and only the probe target sets the second.

use super::{expect_type, verify_artifact_binding};
use crate::block::{ArtifactBinding, ArtifactType};
use crate::error::HttpProfileError;
use verus_builtin_macros::{verus_spec, verus_verify};
#[allow(unused_imports)]
use vstd::prelude::*;

/// Positive control: the public verifier's contract carries the relation.
#[verus_verify]
#[verus_spec(out =>
    ensures out matches Ok(()) ==> binding.spec_digest_value()
        == super::thumbprint::thumbprint_of(credential@),
)]
pub fn probe_the_contract_carries_the_relation(
    binding: &ArtifactBinding,
    credential: &[u8],
) -> Result<(), HttpProfileError> {
    verify_artifact_binding(binding, credential)
}

/// Must FAIL: the relation is claimed without the comparison that establishes it.
#[verus_verify]
#[verus_spec(out =>
    ensures out matches Ok(()) ==> binding.spec_digest_value()
        == super::thumbprint::thumbprint_of(credential@),
)]
pub fn probe_negative_relation_removed(
    binding: &ArtifactBinding,
    credential: &[u8],
) -> Result<(), HttpProfileError> {
    expect_type(binding, ArtifactType::OauthDpop)
}

/// Must FAIL: a verified binding is claimed to commit to a credential it was not checked
/// against.
#[verus_verify]
#[verus_spec(out =>
    ensures out matches Ok(()) ==> binding.spec_digest_value()
        == super::thumbprint::thumbprint_of(other@),
)]
pub fn probe_negative_relation_contradicted(
    binding: &ArtifactBinding,
    credential: &[u8],
    other: &[u8],
) -> Result<(), HttpProfileError> {
    verify_artifact_binding(binding, credential)
}
