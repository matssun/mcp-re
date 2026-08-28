// SPDX-License-Identifier: Apache-2.0
//! The RFC 6962 §2.1 tree, BUILT.
//!
//! One fact: **the Merkle tree hash of a leaf list, and the audit path to one of them.**
//!
//! This is the BUILD side of the pair #657 ruling 3 protects. [`crate::scitt::merkle`] is
//! the verify side: it folds a path back to a root without ever building a tree. They are
//! deliberately two implementations of one specification, and the vector corpus is what
//! keeps them honest — a bug in one is caught by the other, and a single shared
//! implementation would make a bug in the only implementation invisible to the corpus that
//! exists to see it.
//!
//! Its own module so that the independence has a name, rather than being a fact about where
//! two functions happen to sit.

use sha2::Digest;
use sha2::Sha256;

use crate::scitt::merkle::node_hash;

/// `MTH(D[n])` (RFC 9162 §2.1.1), accumulating `PATH(target, D[n])` (§2.1.3.1) into
/// `path` when `target` is `Some`.
///
/// The two are computed together because they are the same recursion: the audit path
/// is exactly the sequence of sibling subtree roots skipped while descending to the
/// target leaf. `None` means "this subtree contains no target" — it contributes its
/// root and nothing to the path.
///
/// Entries are pushed LEAF-TO-ROOT: the targeted half recurses first, so everything
/// it contributes is already in `path` before this level's sibling is appended.
pub(crate) fn mth_and_path(
    leaves: &[[u8; 32]],
    target: Option<usize>,
    path: &mut Vec<[u8; 32]>,
) -> [u8; 32] {
    match leaves.len() {
        // `MTH({}) = SHA-256()`. Unreachable from the log (a receipt is only issued
        // for a registered leaf), but defined so the recursion is total.
        0 => Sha256::new().finalize().into(),
        1 => leaves[0],
        n => {
            // k = the largest power of two STRICTLY less than n.
            let k = 1usize << (usize::BITS - 1 - (n - 1).leading_zeros());
            let (left_leaves, right_leaves) = leaves.split_at(k);
            match target {
                Some(t) if t < k => {
                    let left = mth_and_path(left_leaves, Some(t), path);
                    let right = mth_and_path(right_leaves, None, path);
                    path.push(right);
                    node_hash(&left, &right)
                }
                Some(t) => {
                    let left = mth_and_path(left_leaves, None, path);
                    let right = mth_and_path(right_leaves, Some(t - k), path);
                    path.push(left);
                    node_hash(&left, &right)
                }
                None => {
                    let left = mth_and_path(left_leaves, None, path);
                    let right = mth_and_path(right_leaves, None, path);
                    node_hash(&left, &right)
                }
            }
        }
    }
}
