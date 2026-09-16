// SPDX-License-Identifier: Apache-2.0
//! The two answers about one dispatch, on opposite sides of the execution threshold.
//!
//! [`DispatchedOutcome`] is what the plane DID once the dispatch was committed; every one
//! of its cases is compatible with the action having executed. [`NotAdmitted`] is why a
//! dispatch could not begin, decided without transmitting anything. Their own file because
//! the distinction between them IS the threshold, and a reader who has to find it among a
//! seam's other concerns is the reader who collapses the two.

/// What the inner plane did once the dispatch was committed.
///
/// Three facts, and every one of them is compatible with the action having executed. The
/// fourth case a reader might expect — *nothing was transmitted* — is deliberately absent:
/// it is decided before commitment, by [`AsyncInnerServer::prepare`], and reported as
/// [`NotAdmitted`]. A post-commitment value that could say it would let a caller walk an
/// exchange's consequence back after the threshold, which is the one direction the
/// exchange machine may never move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchedOutcome {
    /// The backend answered with a 2xx JSON body. Whether that body is a LEGAL response is
    /// a separate question, decided by the envelope validator — this says only that the
    /// bytes are the backend's own.
    Replied(Vec<u8>),
    /// The request was transmitted and the transport then failed — timeout, reset,
    /// truncation. **Whether the action executed is unknown**, and the honest answer is to
    /// say so rather than to pick the flattering reading.
    Indeterminate(&'static str),
    /// The backend answered, and its answer cannot be used: a non-2xx status, a
    /// non-JSON media type (an SSE stream, an HTML error page), an unreadable or
    /// over-cap body.
    ///
    /// Separate from [`Indeterminate`](Self::Indeterminate) because the backend DID act,
    /// and separate from [`Replied`](Self::Replied) because there is nothing here to
    /// classify as an MCP response.
    InvalidUpstream(&'static str),
}

/// Why a dispatch cannot begin, decided WITHOUT transmitting anything.
///
/// Returned by [`AsyncInnerServer::prepare`] so the serving path can refuse on the
/// retry-safe side of the execution threshold. That is the entire point: local saturation
/// is a fact about this proxy, and answering it after the threshold turns a
/// definitely-not-executed outage into an exchange that must claim `possibly_executed`
/// forever after.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotAdmitted(pub &'static str);
