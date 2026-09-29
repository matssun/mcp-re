// SPDX-License-Identifier: Apache-2.0
//! ONE logged-in session, reused across operations.
//!
//! PKCS#11 `C_Login` is per-token-per-application and it is expensive. A fresh session and
//! a `C_Login` on EVERY signed response makes signing latency and availability hostage to
//! the token''s login throughput — a boundary DoS amplification, since a peer that can make
//! the proxy sign can make it log in.
//!
//! The distinction that keeps fail-closed intact is [`super::SessionOpError`]: a TRANSIENT
//! session fault — the handle went invalid, the token was re-inserted, the login lapsed — is
//! re-opened and retried exactly ONCE, while a genuine sign or lookup failure is propagated
//! immediately and never retried. A reconnect-and-retry loop that did not draw that line
//! would mask real failures. If the re-open itself fails, that error is surfaced: no
//! in-process fallback, no fabricated signature.

use std::sync::Mutex;

use crate::key_source::KeyError;

use super::LoginSessionFactory;
use super::SessionOpError;

/// Amortizes the PKCS#11 LOGIN across operations (audit M16): instead of opening a
/// fresh session and performing a `C_Login` on EVERY signed response — which makes
/// signing latency/availability hostage to token login throughput and is a
/// boundary DoS amplification — this holds ONE logged-in session behind a `Mutex`
/// and reuses it. A fresh login happens only on first use or when the cached
/// session has gone invalid (handle closed / token re-inserted / login lapsed), so
/// N sequential signs perform far fewer than N logins.
///
/// Fail-closed is preserved: a *fatal* [`SessionOpError::Fatal`] (a real sign /
/// lookup failure) is propagated immediately and never retried; only a
/// [`SessionOpError::SessionInvalid`] triggers a single re-open-and-retry. If the
/// re-open itself fails, that error is surfaced (no in-process fallback, no
/// fabricated signature).
pub(crate) struct AmortizedSession<S> {
    /// The cached logged-in session, lazily opened on first use and re-opened on a
    /// transient session fault. `None` until the first successful login.
    cached: Mutex<Option<S>>,
}

impl<S> AmortizedSession<S> {
    /// Start with no cached session; the first [`Self::with_session`] call opens
    /// and logs one in.
    pub(crate) fn new() -> Self {
        AmortizedSession {
            cached: Mutex::new(None),
        }
    }

    /// Run `op` against a logged-in session, reusing the cached one when possible.
    ///
    /// 1. Ensure a cached session exists (open + login once if absent).
    /// 2. Run `op` on it. On success, return — NO new login.
    /// 3. On [`SessionOpError::SessionInvalid`], drop the dead session, open a
    ///    fresh logged-in one, and run `op` ONE more time. A second transient
    ///    failure (or a re-open failure) is surfaced — no unbounded retry loop.
    /// 4. On [`SessionOpError::Fatal`], propagate immediately (fail closed).
    pub(crate) fn with_session<F, T, Op>(&self, factory: &F, op: Op) -> Result<T, KeyError>
    where
        F: LoginSessionFactory<Session = S>,
        Op: Fn(&S) -> Result<T, SessionOpError>,
    {
        let mut guard = self
            .cached
            .lock()
            .map_err(|e| KeyError::NotFound(format!("pkcs11: session mutex poisoned: {e}")))?;

        // Ensure a session is cached (first use, or after a prior invalidation
        // cleared it).
        if guard.is_none() {
            *guard = Some(factory.open_logged_in()?);
        }

        // First attempt on the (reused) cached session.
        let first = {
            let session = guard
                .as_ref()
                .ok_or_else(|| KeyError::NotFound("pkcs11: session cache empty".to_string()))?;
            op(session)
        };
        match first {
            Ok(value) => Ok(value),
            Err(SessionOpError::Fatal(e)) => Err(e),
            Err(SessionOpError::SessionInvalid(_)) => {
                // Transient: the cached session is dead. Drop it, open exactly ONE
                // fresh logged-in session, and retry the op once. Re-open failure
                // (or a second transient failure) fails closed.
                *guard = None;
                let session = factory.open_logged_in()?;
                // Cache the fresh session ONLY if the retried op SUCCEEDS (issue
                // #25). A session whose op returned Fatal or SessionInvalid must
                // NOT be cached — leaving the cache empty so the next call re-opens
                // a clean session — otherwise a dead/invalid handle would be reused
                // and every subsequent op would fail until eviction.
                match op(&session) {
                    Ok(value) => {
                        *guard = Some(session);
                        Ok(value)
                    }
                    Err(SessionOpError::Fatal(e)) | Err(SessionOpError::SessionInvalid(e)) => {
                        // `guard` stays None; `session` is dropped (closed) here.
                        Err(e)
                    }
                }
            }
        }
    }
}
