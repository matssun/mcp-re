// SPDX-License-Identifier: Apache-2.0
//! What the prover sees of the evidence handles. Present only under the `verify` feature,
//! like `verus_std_specs.rs`, and kept beside the types it declares.

use verus_builtin_macros::verus;
use vstd::prelude::*;

verus! {

/// OPAQUE (ASM-0046): the representation is private so that holding one means it was
/// derived. No theorem reads it; the prover names it only because the verified request
/// products carry one.
#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExRequestRoleEvidence(super::RequestRoleEvidence);

/// TRANSPARENT (ASM-0045): [`role_label`] is defined by cases over it.
#[verifier::external_type_specification]
pub struct ExEvidenceRole(super::EvidenceRole);

/// The label a role derives under: the three constants `EvidenceRole::label` returns. A
/// definition, not an assumption — it lets a contract stated over a role reduce to the
/// labeled digest under that role's constant.
pub open spec fn role_label(role: super::EvidenceRole) -> Seq<char> {
    match role {
        super::EvidenceRole::Request => crate::ids::EVIDENCE_LABEL_REQUEST@,
        super::EvidenceRole::Response => crate::ids::EVIDENCE_LABEL_RESPONSE@,
        super::EvidenceRole::RequestState => crate::ids::EVIDENCE_LABEL_REQUEST_STATE@,
    }
}

}
