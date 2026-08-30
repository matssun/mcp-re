// SPDX-License-Identifier: Apache-2.0
//! The RFC 9162 fold — authority D.
//!
//! One fact: **this inclusion path folds this leaf to this root at this position.**
//!
//! # The independent cross-check, and why it must not be "deduplicated"
//!
//! [`super::prototype`] BUILDS a tree; this module VERIFIES a path. They are deliberately
//! two implementations of RFC 6962 §2.1, and the vector corpus is what keeps them honest:
//! a bug in one is caught by the other, and consolidating them would make a bug in the only
//! implementation invisible to the corpus that exists to see it. #657 ruling 3 says this,
//! and any later consolidation must first put an equally independent oracle in place.
//!
//! `StatementLeafProfile` lives here because it decides WHICH BYTES the leaf hash is over,
//! which is the first step of the fold and not a property of the statement.

use sha2::Digest;
use sha2::Sha256;

use serde::Deserialize;
use serde::Serialize;

use crate::error::HttpProfileError;

use super::statement::SignedStatement;

/// The leaf hash of a signed statement (RFC 6962 leaf prefix `0x00`), over the
/// statement's COSE bytes — the exact octets that were registered.
pub(super) fn leaf_hash(statement: &SignedStatement, profile: StatementLeafProfile) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    match profile {
        StatementLeafProfile::StatementBytes => h.update(statement.to_cose()),
        StatementLeafProfile::StatementDigest => h.update(Sha256::digest(statement.to_cose())),
    }
    h.finalize().into()
}

/// WHICH bytes a transparency service logs as the Merkle entry for a Signed Statement.
///
/// RFC 9162 §2.1 defines the leaf hash as `SHA-256(0x00 ‖ d(i))` over the i-th ENTRY, and
/// RFC 9943 says the service registers the Signed Statement — but neither document says
/// whether the entry is the statement's octets or a digest of them. That gap is real, and
/// two conforming services have been observed on opposite sides of it, so a verifier
/// cannot deduce the answer from the receipt.
///
/// **Exactly one profile applies to any verification.** Trying both and accepting either
/// would be strictly worse than picking wrong: it hands an attacker two chances at the
/// fold, and it destroys the property the proof is for — that the receipt pins WHICH
/// entry was logged. So the profile comes from the pinned service artifact, which an
/// operator wrote down and reviewed, and never from the receipt being checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StatementLeafProfile {
    /// The entry is the Signed Statement's own COSE octets: `SHA-256(0x00 ‖ statement)`.
    ///
    /// The default, and the more direct reading of RFC 9162 §2.1 composed with RFC 9943:
    /// what the service registers is the statement, so the statement is the entry. The
    /// RFC 9942 editor's own implementation (`@transmute/cose`) hashes this way.
    #[default]
    StatementBytes,
    /// The entry is a digest of the statement: `SHA-256(0x00 ‖ SHA-256(statement))`.
    ///
    /// Used by services that log digests rather than documents — `capsule-anchor` does,
    /// and its source calls it a deliberate exception to its own leaf rule. Verifiable,
    /// but only if a verifier is told; it cannot be inferred.
    StatementDigest,
}
/// An interior Merkle node hash (RFC 6962 node prefix `0x01`).
pub(super) fn node_hash(left: &[u8], right: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// The RFC 9162 §2.1.3.2 inclusion-proof verification algorithm, verbatim.
///
/// Returns the Merkle Tree Hash the proof re-derives, or an error if the proof does
/// not fit `(leaf_index, tree_size)`.
///
/// **Why the whole algorithm and not an index-bit fold.** An `index & 1` walk that
/// shifts the index right once per sibling is right only when the tree size is a
/// power of two. Two things break otherwise:
///
///   * **Wrong answer.** In a non-power-of-two tree the right-hand subtree is short,
///     so a node on the right edge is PROMOTED past levels rather than paired. RFC
///     9162's `fn`/`sn` pair is what tracks that: `sn` is the last index at the
///     current level, and `fn == sn` means "right edge, combine as the right child
///     and keep climbing". Without it a conforming receipt for a 3-leaf log folds
///     its operands in the wrong order and is rejected.
///   * **Most restatements are refused.** With only the low bits of `leaf_index`
///     consulted and `tree_size` unused, the trailing bits of the index and the size
///     itself are wholly unconstrained. The terminal `sn == 0` requirement plus the
///     per-step `sn != 0` check makes the PATH LENGTH load-bearing, so `(21, 32)`,
///     `(3, 4)`, `(7, 8)` and `(1, 4)` no longer fold a one-sibling proof to a root.
///
/// **What this function cannot bind, and why.** It does not make `leaf_index` and
/// `tree_size` authentic, and no fold can. In the `RFC9162_SHA256` profile the
/// receipt payload is the bare Merkle Tree Hash (RFC 9942 §5) — unlike an RFC 9162
/// signed tree head, it never covers `tree_size` — and both values ride in the
/// UNSIGNED `vdp` header.
///
/// The scope is not a special family, it is nearly everything. What the verifier
/// computes is fixed by the SEQUENCE of combine directions this loop takes, so any
/// two `(leaf_index, tree_size)` pairs producing the same sequence accept the same
/// path and the same root. Enumerated over every pair with `tree_size <= 1024`,
/// **98.4% lie in a class with at least one other pair**, spread over 251 distinct
/// classes — not one right-edge family. `(1,2)`, `(2,3)`, `(4,5)`, `(8,9)` share the
/// single-sibling class, but so do `(3,4)`, `(5,6)`, `(6,7)` at length 2, and only
/// four pairs in that whole range are unique. Refusing the ambiguous ones is
/// therefore not an available defence: it would refuse essentially every receipt.
///
/// **How it is closed.** Not inside this function — no fold can separate positions that
/// direct it identically. [`position_commitment`] puts the whole tuple in the receipt's
/// PROTECTED header, so the service's signature covers `(profile, log identity, vds,
/// tree_size, leaf_index, root)` and a restatement no longer matches.
///
/// An authenticated `tree_size` ALONE would also suffice: within every class no two
/// members share one, so the size determines the index —
/// `the_tree_size_determines_the_leaf_index_within_every_ambiguity_class` pins that.
/// It is deliberately not what the profile relies on. That sufficiency is a property of
/// this algorithm rather than of the evidence, and a security contract resting on a test
/// continuing to pass is weaker than one that states the fact outright.
///
/// Where a pinned service issues no commitment ([`ReceiptPositionProfile::Unbound`]),
/// the pre-revision contract still applies and both accessors remain transport hints.
///
/// An EMPTY path is admitted only for `tree_size == 1`, which is the one case RFC
/// 9162 defines it for (`PATH(0, D[1]) = {}`); for any larger tree `sn` is non-zero
/// with no siblings left to consume, and the proof is refused.
pub(super) fn rfc9162_root_from_inclusion_proof(
    leaf: &[u8; 32],
    leaf_index: u64,
    tree_size: u64,
    path: &[Vec<u8>],
) -> Result<[u8; 32], HttpProfileError> {
    if leaf_index >= tree_size {
        return Err(HttpProfileError::ReceiptInclusionInvalid);
    }
    let mut fnode = leaf_index;
    // `tree_size` arrives inside a receipt, so its predecessor is taken checked rather
    // than argued from the `leaf_index >= tree_size` refusal above. The refusal does
    // establish `tree_size >= 1`; stating the bound where it is used costs one `ok_or`
    // and does not depend on that line staying where it is.
    let Some(mut snode) = tree_size.checked_sub(1) else {
        return Err(HttpProfileError::ReceiptInclusionInvalid);
    };
    let mut r = *leaf;
    for sibling in path {
        if snode == 0 {
            // More siblings than the tree has levels for this leaf.
            return Err(HttpProfileError::ReceiptInclusionInvalid);
        }
        if !fnode.is_multiple_of(2) || fnode == snode {
            r = node_hash(sibling, &r);
            while fnode != 0 && fnode.is_multiple_of(2) {
                fnode /= 2;
                snode /= 2;
            }
        } else {
            r = node_hash(&r, sibling);
        }
        fnode /= 2;
        snode /= 2;
    }
    if snode != 0 {
        // Fewer siblings than the tree requires: the proof does not reach the root.
        return Err(HttpProfileError::ReceiptInclusionInvalid);
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::ChainLabel;
    use crate::scitt::commitment::EvidenceCommitment;
    use crate::scitt::fixtures::*;
    use crate::scitt::offline::verify_receipt_offline;
    use crate::scitt::prototype::tree::mth_and_path;
    use crate::scitt::prototype::PrototypeTransparencyService;

    /// The combine-direction sequence `rfc9162_root_from_inclusion_proof` takes for a
    /// position. Two positions with the same sequence run the same computation, so one
    /// path and one root verify for both — this is what "restatement" means here.
    fn combine_sequence(leaf_index: u64, tree_size: u64) -> Option<Vec<bool>> {
        if leaf_index >= tree_size {
            return None;
        }
        let (mut fnode, mut snode) = (leaf_index, tree_size - 1);
        let mut out = Vec::new();
        while out.len() <= 64 {
            if snode == 0 {
                return Some(out);
            }
            if !fnode.is_multiple_of(2) || fnode == snode {
                out.push(true);
                while fnode != 0 && fnode.is_multiple_of(2) {
                    fnode /= 2;
                    snode /= 2;
                }
            } else {
                out.push(false);
            }
            fnode /= 2;
            snode /= 2;
        }
        None
    }

    /// The property that makes "the service signs the tree size" a COMPLETE fix rather
    /// than a mitigation: within any set of positions that verify interchangeably, no
    /// two share a `tree_size`. An authenticated size therefore pins the index outright.
    ///
    /// If this ever stops holding, signing the size stops being sufficient and the
    /// remedy has to change — which is why it is asserted rather than described.
    #[test]
    fn the_tree_size_determines_the_leaf_index_within_every_ambiguity_class() {
        let mut classes: std::collections::HashMap<Vec<bool>, Vec<(u64, u64)>> =
            std::collections::HashMap::new();
        for tree_size in 1..=256u64 {
            for leaf_index in 0..tree_size {
                if let Some(seq) = combine_sequence(leaf_index, tree_size) {
                    classes
                        .entry(seq)
                        .or_default()
                        .push((leaf_index, tree_size));
                }
            }
        }

        for (seq, members) in &classes {
            let mut sizes: Vec<u64> = members.iter().map(|(_, n)| *n).collect();
            sizes.sort_unstable();
            let before = sizes.len();
            sizes.dedup();
            assert_eq!(
                sizes.len(),
                before,
                "two positions with combine sequence {seq:?} share a tree_size, so \
                 authenticating the size would NOT pin the index: {members:?}"
            );
        }

        // And the exposure itself: ambiguity is the overwhelming norm, so refusing the
        // ambiguous positions is not an available defence. Stated as a floor so the
        // test pins the shape of the problem without pinning an exact census.
        let total: usize = classes.values().map(Vec::len).sum();
        let ambiguous: usize = classes.values().filter(|m| m.len() > 1).map(Vec::len).sum();
        assert!(
            ambiguous * 10 > total * 9,
            "expected the great majority of positions to be restatable ({ambiguous} of \
             {total}); if this dropped, re-derive whether refusal became viable"
        );
    }

    /// The RFC 9162 §2.1.1 known answer for a NON-power-of-two tree.
    ///
    /// `MTH(D[3]) = HASH(0x01 ‖ MTH(D[0:2]) ‖ MTH(D[2:3]))` — the split is at the
    /// largest power of two BELOW 3, i.e. 2, and the last leaf is never duplicated.
    /// The duplicate-last-node construction this replaced computed
    /// `node(node(a,b), node(c,c))` instead, which is a different root for every size
    /// that is not a power of two.
    #[test]
    fn the_tree_hash_is_the_rfc_9162_split_not_a_duplicated_last_node() {
        let leaves: Vec<[u8; 32]> = (0u8..3).map(|i| [i; 32]).collect();
        let mut path = Vec::new();
        let root = mth_and_path(&leaves, None, &mut path);

        let expected = node_hash(&node_hash(&leaves[0], &leaves[1]), &leaves[2]);
        assert_eq!(root, expected, "MTH(D[3]) per RFC 9162 §2.1.1");

        let duplicated = node_hash(
            &node_hash(&leaves[0], &leaves[1]),
            &node_hash(&leaves[2], &leaves[2]),
        );
        assert_ne!(
            root, duplicated,
            "the two constructions must be visibly different, or this test proves nothing"
        );
    }

    /// EVERY leaf of a non-power-of-two log verifies. Leaf 2 of a 3-leaf tree sits on
    /// the short right edge, and the old index-bit fold combined its operands in the
    /// wrong order — so a conforming receipt from any real log whose size is not a
    /// power of two was rejected.
    #[test]
    fn every_leaf_of_a_three_leaf_log_verifies() {
        let mut svc = PrototypeTransparencyService::new(TS_KID);
        let mut issued = Vec::new();
        for hops in 1..=3 {
            let st = statement(EvidenceCommitment::from_reconstruction(
                &recon(ChainLabel::Complete, hops),
                None,
                None,
            ));
            let receipt = register(&mut svc, &st);
            issued.push((st, receipt));
        }
        // The last receipt is over the 3-leaf tree; re-register nothing, just check it.
        let (st, receipt) = issued.last().expect("three registered");
        assert_eq!(receipt.tree_size(), 3);
        assert_eq!(receipt.leaf_index(), 2, "the right-edge leaf");
        verify_receipt_offline(st, receipt, ir(), tr())
            .expect("a right-edge leaf of a 3-leaf tree verifies");
    }

    /// `tree_size` and `leaf_index` ride in the UNSIGNED `vdp` header. The RFC 9162
    /// walk's terminal `sn == 0` requirement makes the PATH LENGTH load-bearing, so a
    /// position whose proof would need a different number of siblings is refused.
    #[test]
    fn restating_the_log_position_at_a_different_path_length_does_not_verify() {
        let leaf = [7u8; 32];
        let sibling = vec![9u8; 32];
        // The honest proof: leaf 1 of a 2-leaf tree, one sibling.
        let root = rfc9162_root_from_inclusion_proof(&leaf, 1, 2, std::slice::from_ref(&sibling))
            .expect("the honest position verifies");
        assert_eq!(root, node_hash(&sibling, &leaf));

        for (index, size) in [(3u64, 4u64), (7, 8), (21, 32), (1, 4)] {
            assert!(
                rfc9162_root_from_inclusion_proof(
                    &leaf,
                    index,
                    size,
                    std::slice::from_ref(&sibling)
                )
                .is_err(),
                "leaf_index {index} of a {size}-leaf tree needs a different path length"
            );
        }
    }

    /// The limit of the above, pinned so nobody reads the accessors as authenticated.
    ///
    /// A right-edge leaf is PROMOTED past every level, so leaf `2^k` of a `2^k + 1`-leaf
    /// log consumes exactly one sibling and folds to the same `H(0x01 ‖ sibling ‖ leaf)`
    /// as leaf 1 of a 2-leaf log. The `RFC9162_SHA256` receipt payload is the bare
    /// Merkle Tree Hash, which — unlike an RFC 9162 signed tree head — never covers
    /// `tree_size`, so there is nothing in the signed material that distinguishes these
    /// positions and no fold can refuse them. This test states the residual explicitly:
    /// [`Receipt::tree_size`] and [`Receipt::leaf_index`] are unauthenticated hints,
    /// and any consumer building ordering, anchoring or log-maturity reasoning on them
    /// is reading a relayer-chosen value.
    #[test]
    fn a_right_edge_restatement_is_indistinguishable_and_still_verifies() {
        let leaf = [7u8; 32];
        let sibling = vec![9u8; 32];
        let honest = rfc9162_root_from_inclusion_proof(&leaf, 1, 2, std::slice::from_ref(&sibling))
            .expect("the honest position verifies");

        for k in 1u32..8 {
            let (index, size) = (1u64 << k, (1u64 << k) + 1);
            let restated = rfc9162_root_from_inclusion_proof(
                &leaf,
                index,
                size,
                std::slice::from_ref(&sibling),
            )
            .expect("a right-edge position of the same path length is not distinguishable");
            assert_eq!(
                restated, honest,
                "leaf {index} of a {size}-leaf log folds to the honest 2-leaf root"
            );
        }
    }

    /// An EMPTY inclusion path is admitted only for the single-leaf tree RFC 9162
    /// defines it for. For any larger tree it proves nothing — the fold would collapse
    /// to `root == leaf hash`, so any signature a service made over an ENTRY hash
    /// rather than a tree head would read as a receipt carrying an arbitrary,
    /// unauthenticated size and index.
    #[test]
    fn an_empty_inclusion_path_is_only_valid_for_a_single_leaf_tree() {
        let leaf = [3u8; 32];
        assert_eq!(
            rfc9162_root_from_inclusion_proof(&leaf, 0, 1, &[]).expect("PATH(0, D[1]) = {}"),
            leaf,
            "a one-leaf tree's root IS its leaf hash"
        );
        for size in [2u64, 3, 8] {
            assert!(
                rfc9162_root_from_inclusion_proof(&leaf, 0, size, &[]).is_err(),
                "an empty path cannot reach the root of a {size}-leaf tree"
            );
        }
    }
}
