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
//!
//! Logins are bounded per unit time, not per request: after a login fails, or a freshly
//! opened session is invalid again, no caller re-opens a session until the cool-off has
//! elapsed, so a peer that keeps a broken token busy cannot turn each request into a login.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::key_source::KeyError;

use super::LoginSessionFactory;
use super::SessionOpError;

/// How long no caller re-opens a session after a failed login or a freshly opened
/// session that was invalid again; bounds `C_Login` attempts per unit time.
const REOPEN_COOL_OFF: Duration = Duration::from_secs(1);

/// The cached session and the monotonic instant of the last failed (re-)open.
struct Slot<S> {
    /// `None` until the first successful login, and after any invalidation.
    session: Option<S>,
    /// Set by a failed login or an invalid fresh session; cleared when a session is cached.
    cooling_since: Option<Instant>,
}

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
/// fabricated signature). After a failed login, or a fresh session that is invalid
/// again, every open is refused until the cool-off elapses.
pub(crate) struct AmortizedSession<S> {
    /// The cached logged-in session, lazily opened on first use and re-opened on a
    /// transient session fault, with the cool-off stamp.
    cached: Mutex<Slot<S>>,
    /// Minimum time between a failed open and the next login attempt.
    cool_off: Duration,
}

impl<S> AmortizedSession<S> {
    /// Start with no cached session; the first [`Self::with_session`] call opens
    /// and logs one in.
    pub(crate) fn new() -> Self {
        Self::with_cool_off(REOPEN_COOL_OFF)
    }

    fn with_cool_off(cool_off: Duration) -> Self {
        AmortizedSession {
            cached: Mutex::new(Slot {
                session: None,
                cooling_since: None,
            }),
            cool_off,
        }
    }

    /// Open a logged-in session unless the slot is cooling off; a failed login starts
    /// the cool-off.
    fn open<F>(&self, slot: &mut Slot<S>, factory: &F) -> Result<S, KeyError>
    where
        F: LoginSessionFactory<Session = S>,
    {
        if slot
            .cooling_since
            .is_some_and(|since| since.elapsed() < self.cool_off)
        {
            return Err(KeyError::NotFound(
                "pkcs11: session re-open cooling off after a failed login".to_string(),
            ));
        }
        factory.open_logged_in().inspect_err(|_| {
            slot.cooling_since = Some(Instant::now());
        })
    }

    /// Run `op` against a logged-in session, reusing the cached one when possible.
    ///
    /// 1. Ensure a cached session exists (open + login once if absent and not cooling off).
    /// 2. Run `op` on it. On success, return — NO new login.
    /// 3. On [`SessionOpError::SessionInvalid`], drop the dead session, open a
    ///    fresh logged-in one, and run `op` ONE more time. A second transient
    ///    failure (or a re-open failure) is surfaced and starts the cool-off — no
    ///    unbounded retry loop.
    /// 4. On [`SessionOpError::Fatal`], propagate immediately (fail closed).
    ///
    /// A lock poisoned by a panicking `op` retires its session: `None` is always a legal
    /// slot state, so the handle left in an unknown state is dropped and re-opened.
    pub(crate) fn with_session<F, T, Op>(&self, factory: &F, op: Op) -> Result<T, KeyError>
    where
        F: LoginSessionFactory<Session = S>,
        Op: Fn(&S) -> Result<T, SessionOpError>,
    {
        let mut guard = match self.cached.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                // A panicking op left its session in an unknown state; `None` (no cached
                // session) is always a legal slot state, so dropping the handle and
                // re-opening restores the invariant. `cooling_since` is preserved.
                let mut guard = poisoned.into_inner();
                guard.session = None;
                self.cached.clear_poison();
                guard
            }
        };

        // Ensure a session is cached (first use, or after a prior invalidation
        // cleared it).
        if guard.session.is_none() {
            let session = self.open(&mut guard, factory)?;
            guard.session = Some(session);
            guard.cooling_since = None;
        }

        // First attempt on the (reused) cached session.
        let first = {
            let session = guard
                .session
                .as_ref()
                .ok_or_else(|| KeyError::NotFound("pkcs11: session cache empty".to_string()))?;
            op(session)
        };
        match first {
            Ok(value) => Ok(value),
            Err(SessionOpError::Fatal(e)) => Err(e),
            Err(SessionOpError::SessionInvalid(_)) => {
                self.retry_on_fresh_session(&mut guard, factory, &op)
            }
        }
    }

    /// The one retry after a transient failure: drop the dead session, open exactly ONE
    /// fresh logged-in session, and run `op` once more. A re-open failure (or a second
    /// transient failure) fails closed.
    ///
    /// The fresh session is cached ONLY if the retried op SUCCEEDS (issue #25): a session
    /// whose op returned Fatal or SessionInvalid is dropped (closed) and the cache stays
    /// empty, so the next call re-opens a clean session instead of reusing a dead handle.
    fn retry_on_fresh_session<F, T, Op>(
        &self,
        slot: &mut Slot<S>,
        factory: &F,
        op: &Op,
    ) -> Result<T, KeyError>
    where
        F: LoginSessionFactory<Session = S>,
        Op: Fn(&S) -> Result<T, SessionOpError>,
    {
        slot.session = None;
        let session = self.open(slot, factory)?;
        match op(&session) {
            Ok(value) => {
                slot.session = Some(session);
                slot.cooling_since = None;
                Ok(value)
            }
            Err(SessionOpError::SessionInvalid(e)) => {
                // The next open waits out the cool-off.
                slot.cooling_since = Some(Instant::now());
                Err(e)
            }
            Err(SessionOpError::Fatal(e)) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    struct Fake {
        opens: Cell<u32>,
        fail_open: bool,
    }

    struct Handle {
        generation: u32,
    }

    impl LoginSessionFactory for Fake {
        type Session = Handle;
        fn open_logged_in(&self) -> Result<Handle, KeyError> {
            self.opens.set(self.opens.get() + 1);
            if self.fail_open {
                return Err(KeyError::NotFound("login refused".to_string()));
            }
            Ok(Handle {
                generation: self.opens.get(),
            })
        }
    }

    fn fake(fail_open: bool) -> Fake {
        Fake {
            opens: Cell::new(0),
            fail_open,
        }
    }

    fn invalid(_: &Handle) -> Result<(), SessionOpError> {
        Err(SessionOpError::SessionInvalid(KeyError::NotFound(
            "invalid".to_string(),
        )))
    }

    #[test]
    fn a_persistently_invalid_session_logs_in_twice_per_cool_off_not_per_request() {
        let amortized = AmortizedSession::with_cool_off(Duration::from_secs(3600));
        let factory = fake(false);
        for _ in 0..10 {
            assert!(amortized.with_session(&factory, invalid).is_err());
        }
        assert_eq!(factory.opens.get(), 2);
    }

    #[test]
    fn a_failed_login_is_not_retried_within_the_cool_off() {
        let amortized = AmortizedSession::with_cool_off(Duration::from_secs(3600));
        let factory = fake(true);
        for _ in 0..10 {
            assert!(amortized.with_session(&factory, invalid).is_err());
        }
        assert_eq!(factory.opens.get(), 1);
    }

    #[test]
    fn the_cool_off_expires() {
        let amortized = AmortizedSession::with_cool_off(Duration::ZERO);
        let factory = fake(false);
        for _ in 0..3 {
            assert!(amortized.with_session(&factory, invalid).is_err());
        }
        assert_eq!(factory.opens.get(), 6);
    }

    #[test]
    fn a_poisoned_session_is_retired_and_reopened() {
        let amortized = AmortizedSession::with_cool_off(Duration::from_secs(3600));
        let factory = fake(false);
        assert!(amortized.with_session(&factory, |_s| Ok(())).is_ok());
        assert_eq!(factory.opens.get(), 1);
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            amortized.with_session(&factory, |_s| -> Result<(), SessionOpError> {
                panic!("op panicked")
            })
        }));
        assert!(panicked.is_err());
        let generation = amortized
            .with_session(&factory, |s| Ok(s.generation))
            .expect("a poisoned slot re-opens");
        assert_eq!(generation, 2);
        assert_eq!(factory.opens.get(), 2);
    }
}
