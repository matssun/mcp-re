// SPDX-License-Identifier: Apache-2.0
//! A bounded set of INTERCHANGEABLE logged-in sessions, for the delegated-TLS path.
//!
//! A different shape of load from [`super::amortized_session`], not a second copy of it.
//! `C_Sign` is blocking and occupies its worker for the whole call, so one shared session
//! makes every handshake on every core queue behind one token operation, and a slow token
//! stalls all of them. PKCS#11 permits many sessions per slot — they all ride the one
//! `C_Login`, which is per-token-per-application — so the handshake path gets several.
//!
//! Interchangeable is what makes this a POOL and not a cache: a handshake signature needs
//! *a* logged-in session, not a particular one.
//!
//! The size is deliberately not scaled by core count. It matches the number of blocking
//! handshake-signing workers a core runs, so a core''s workers do not queue on each other,
//! and the ceiling that binds beyond that is the token''s own session limit and internal
//! concurrency rather than the host''s.

use crate::key_source::KeyError;

use super::amortized_session::AmortizedSession;
use super::LoginSessionFactory;
use super::SessionOpError;

/// is the token's own session limit and its internal concurrency, not the host's.
pub(crate) const TLS_SESSION_POOL_SIZE: usize = 4;

/// A fixed set of interchangeable logged-in sessions for the delegated-TLS path.
///
/// Interchangeable is what makes this a pool and not a cache: a handshake signature
/// needs *a* logged-in session, not a particular one, so callers are spread across the
/// set by a rotating cursor and each blocks only on the one it was handed.
pub(crate) struct SessionPool<S> {
    sessions: Vec<AmortizedSession<S>>,
    next: std::sync::atomic::AtomicUsize,
}

impl<S> SessionPool<S> {
    pub(crate) fn new(size: usize) -> Self {
        SessionPool {
            sessions: (0..size.max(1)).map(|_| AmortizedSession::new()).collect(),
            next: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Run `op` on one of the pool's logged-in sessions.
    ///
    /// The cursor is advanced with `Relaxed` ordering: it selects which session to try
    /// and orders nothing, and the session's own mutex is what makes the operation
    /// exclusive.
    pub(crate) fn with_session<F, T, Op>(&self, factory: &F, op: Op) -> Result<T, KeyError>
    where
        F: LoginSessionFactory<Session = S>,
        Op: Fn(&S) -> Result<T, SessionOpError>,
    {
        let index =
            self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % self.sessions.len();
        self.sessions[index].with_session(factory, op)
    }
}
