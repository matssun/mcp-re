// SPDX-License-Identifier: Apache-2.0
//! The COSE/CWT wire vocabulary this profile writes and reads.
//!
//! One fact: **which header labels and domain-separated bytes the MCP-RE SCITT profile
//! uses.** It is a vocabulary rather than an authority, and it is a module rather than
//! constants scattered through the owners because a label that means one thing to the
//! issuer and another to the verifier is the failure this centralization prevents.
//!
//! [`position_commitment`] lives here for the same reason: it is a byte layout, and both
//! the issuer that computes it and the verifier that recomputes it must agree on it
//! exactly.

use sha2::Digest;
use sha2::Sha256;

use serde::Deserialize;
use serde::Serialize;

/// COSE header label for the CWT claims of a Signed Statement (RFC 9597).
///
/// RFC 9943 puts the issuer and subject in CWT claims inside the PROTECTED header,
/// not in the payload, so they are covered by the signature and readable without
/// decoding the payload.
pub(super) const HEADER_CWT_CLAIMS: i64 = 15;

/// CWT claim keys (RFC 8392 §3.1) used in the protected header.
pub(super) const CWT_ISS: i64 = 1;
pub(super) const CWT_SUB: i64 = 2;
pub(super) const CWT_IAT: i64 = 6;

/// `vds`: COSE header label for the verifiable-data-structure a Receipt proves
/// inclusion in (RFC 9942 §5.2.1, Figure 4), in the PROTECTED header. It is covered
/// by the signature because it tells the verifier how to READ the proof — a verifier
/// that took the structure identifier from unprotected data could be steered into
/// walking a proof with the wrong algorithm.
pub(super) const HEADER_VDS: i64 = 395;

/// `vdp`: COSE header label for the Verifiable Data Structure Proofs of a Receipt
/// (RFC 9942 §5.2.1, Figure 5), in the UNPROTECTED header — a proof is not signed by
/// the tree head it proves against.
pub(super) const HEADER_VDP: i64 = 396;

/// `inclusion-proof`: the proof-type key inside the `vdp` map (RFC 9942 §5.2.1). The
/// map is keyed by proof type because one Receipt may carry inclusion AND consistency
/// proofs; the label selects which, and its value is an array of proofs.
pub(super) const PROOF_INCLUSION: i64 = -1;

/// `RFC9162_SHA256`: the RFC 9162 binary Merkle tree, SHA-256 (RFC 9942 §5).
pub(super) const VDS_RFC9162_SHA256: i64 = 1;

/// The MCP-RE evidence profile these receipts and statements are issued under.
///
/// It is part of the position commitment's preimage, so a commitment computed under one
/// profile can never be read as valid under another. Bumping it is how a future contract
/// change becomes visible rather than silent.
pub const EVIDENCE_PROFILE: &str = "mcp-re-evidence/v2";

/// Protected header parameter carrying the position commitment (C080).
///
/// A text label, not an integer: this is an MCP-RE profile extension, and a tstr cannot
/// collide with a future IANA assignment in the COSE header registry the way a guessed
/// integer can.
pub(super) const HEADER_POSITION_COMMITMENT: &str = "mcp-re-position";

/// Domain separator for the position commitment preimage.
pub(super) const POSITION_COMMITMENT_DOMAIN: &[u8] = b"mcp-re-scitt-position";

/// The position commitment: `H(domain ‖ profile ‖ log_identity ‖ vds ‖ tree_size ‖
/// leaf_index ‖ root_hash)`, every field length-delimited.
///
/// This is what closes C080. `tree_size` and `leaf_index` ride in the UNSIGNED `vdp`
/// header and the `RFC9162_SHA256` receipt payload is the bare Merkle Tree Hash, so the
/// service's signature covers the root and nothing else — and the root does not
/// determine the position. Placing this digest in the PROTECTED header brings the whole
/// tuple under that signature: restating a receipt at a different position changes the
/// recomputed digest and the protected one no longer matches.
///
/// The tuple is bound EXPLICITLY rather than relying on an authenticated `tree_size`
/// making the index derivable. That derivation does hold today — no ambiguity class
/// contains two members sharing a tree size, which
/// `the_tree_size_determines_the_leaf_index_within_every_ambiguity_class` pins — but it
/// is a property of the current verification algorithm, not of the evidence. A contract
/// that depends on a test continuing to pass is weaker than one that states the fact.
///
/// Every component is preceded by its length as 8 octets big-endian, and the integers
/// are fixed-width big-endian. Raw concatenation would let a longer log identity absorb
/// the leading octets of the next field and produce one preimage for two different
/// positions, which is the exact ambiguity this exists to remove.
pub(super) fn position_commitment(
    log_identity: &str,
    vds: i64,
    tree_size: u64,
    leaf_index: u64,
    root: &[u8],
) -> Vec<u8> {
    let mut h = Sha256::new();
    for part in [
        POSITION_COMMITMENT_DOMAIN,
        EVIDENCE_PROFILE.as_bytes(),
        log_identity.as_bytes(),
        &vds.to_be_bytes()[..],
        &tree_size.to_be_bytes()[..],
        &leaf_index.to_be_bytes()[..],
        root,
    ] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    h.finalize().to_vec()
}

/// Whether a pinned transparency service issues position-bound receipts.
///
/// The old profile authenticates inclusion in the signed root but NOT the exposed
/// position tuple; the new one authenticates the tuple as well. Which applies is a
/// property of the service, so it comes from the pinned artifact an operator wrote down
/// — never from the receipt being checked, which is the value under attack.
///
/// The reverse direction is enforced by the `crit` header rather than by this field: a
/// v2 receipt marks the position parameter critical, so an implementation that does not
/// understand it must refuse rather than verify the receipt while ignoring the
/// commitment. [`Receipt::from_cose`] refuses every critical label it does not know.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReceiptPositionProfile {
    /// Receipts carry no position commitment. `tree_size` and `leaf_index` remain
    /// unauthenticated transport hints, and a relayer may restate them.
    #[default]
    Unbound,
    /// Receipts MUST carry a valid position commitment. A receipt without one is refused
    /// rather than verified under the weaker contract — otherwise pinning the stronger
    /// profile would buy nothing, since an attacker would simply strip the parameter.
    Bound,
}
