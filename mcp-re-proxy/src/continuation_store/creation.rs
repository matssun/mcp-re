// SPDX-License-Identifier: Apache-2.0
//! What establishing a continuation entry found — the answer of
//! [`super::AsyncContinuationStore::create`].

/// What establishing a continuation entry found.
///
/// Named outcomes and not a `bool`: at this boundary a boolean reads as "did it work",
/// which both arms answer yes to. Deliberately not a [`super::ContinuationStoreError`] variant
/// either — a collision is the store answering correctly, and folding it into the error arm
/// would make it indistinguishable from an outage at the one site that must tell them
/// apart: an outage may be retried, a taken key never will be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Creation {
    /// No live entry existed; this call established one.
    Stored,
    /// A live entry already exists under this key. It was NOT replaced.
    Collision,
    /// The store already holds its [`super::ContinuationCapacity`] of live entries. Nothing was
    /// recorded; capacity returns as entries are answered or expire.
    AtCapacity,
}
