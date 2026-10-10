// SPDX-License-Identifier: Apache-2.0
//! What removing a continuation entry found, when the store answered.

/// What [`consume`](super::AsyncContinuationStore::consume) found, when the store answered.
///
/// Two values, because a store that answered can say two things and a caller acts on them
/// differently: one hands this caller the one-shot spend, the other says there is nothing
/// for it to spend. Not a `bool`, which reads as "did it work" at a boundary where an
/// outage and an absence must not be confused; and not an error variant, because an
/// absence is the store answering correctly. The `Err` arm of `consume` is the third
/// case, the one in which the entry's fate is unknown.
///
/// Already consumed, never opened, expired, and another actor's key are ONE value. No
/// store can tell them apart — a removal leaves nothing behind, and a key derived from
/// another actor names no entry — and the caller owes each the same response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consumption {
    /// A live entry existed and THIS call removed it: the approval is spent, by this caller.
    Consumed,
    /// The store answered and held no live entry under the key; this call spent nothing.
    NoLiveEntry,
}
