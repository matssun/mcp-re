//! A single outstanding (pending) request awaiting its signed response
//! (MCPS-034, ADR-MCPS-015).
//!
//! [`HostSession`](crate::session::HostSession) keeps one [`PendingRequest`] per
//! in-flight JSON-RPC id. It records exactly what response correlation and
//! cleanup need:
//!
//! - the Core-computed `request_hash` the response must bind to (verify against
//!   the STORED hash, never a caller-supplied value); and
//! - the request's `expires_at` as Unix seconds, so
//!   [`HostSession::expire_pending`](crate::session::HostSession::expire_pending)
//!   can drop stale entries deterministically under the injected clock.
//!
//! No networking/async — this is plain owned state, keeping `mcps-host`
//! transport-free.

/// One outstanding request: the stored `request_hash` to bind a response to, and
/// the request's expiry (Unix seconds, UTC) used by pending cleanup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRequest {
    request_hash: String,
    expires_at_unix: i64,
}

impl PendingRequest {
    /// Record a pending request from its Core-computed `request_hash` and the
    /// `expires_at` instant (Unix seconds) it was signed with.
    pub fn new(request_hash: String, expires_at_unix: i64) -> Self {
        PendingRequest {
            request_hash,
            expires_at_unix,
        }
    }

    /// The Core-computed `request_hash` a response must bind to.
    pub fn request_hash(&self) -> &str {
        &self.request_hash
    }

    /// Whether this entry is expired at `now_unix` (Unix seconds, UTC).
    ///
    /// Expiry is inclusive of the `expires_at` instant: an entry whose
    /// `expires_at_unix == now_unix` is treated as expired (the freshness window
    /// has closed), matching fail-closed cleanup semantics.
    pub fn is_expired_at(&self, now_unix: i64) -> bool {
        now_unix >= self.expires_at_unix
    }
}
