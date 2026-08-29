// SPDX-License-Identifier: Apache-2.0
//! One logged-in session, reused — and the bounded set of them the TLS path needs.
//!
//! PKCS#11 `C_Login` is per-token-per-application, and it is expensive. Opening a fresh
//! session and logging in on EVERY signed response makes signing latency and availability
//! hostage to the token's login throughput, which is a boundary DoS amplification: a peer
//! that can make the proxy sign can make it log in.
//!
//! So a session is held and reused. The distinction that keeps fail-closed intact is
//! [`SessionOpError`]: a TRANSIENT session fault — the handle went invalid, the token was
//! re-inserted, the login lapsed — is re-opened and retried exactly ONCE, while a genuine
//! sign or lookup failure is propagated immediately and never retried. A reconnect loop that
//! did not draw that line would mask real failures behind a retry.
//!
//! The pool is the same idea for a different shape of load. `C_Sign` is blocking and
//! occupies its worker for the whole call, so with a single TLS session every handshake on
//! every core queues behind one token operation. Sessions are INTERCHANGEABLE — a handshake
//! needs *a* logged-in session, not a particular one — which is what makes a pool the right
//! structure rather than a second cache. It is sized to the per-core handshake workers and
//! deliberately NOT scaled by core count: the ceiling that binds is the token's own session
//! limit, not the host's.

use cryptoki_sys::CKR_DEVICE_ERROR;
use cryptoki_sys::CKR_DEVICE_REMOVED;
use cryptoki_sys::CKR_SESSION_CLOSED;
use cryptoki_sys::CKR_SESSION_COUNT;
use cryptoki_sys::CKR_SESSION_HANDLE_INVALID;
use cryptoki_sys::CKR_USER_NOT_LOGGED_IN;
use cryptoki_sys::CK_SESSION_HANDLE;

use crate::key_source::KeyError;
use crate::pkcs11_native::Pkcs11Error;
use crate::pkcs11_native::SessionCloser;

/// Outcome of running an operation on a (possibly stale) cached session.
///
/// The amortization layer ([`AmortizedSession`]) distinguishes a *transient*
/// session fault (the cached session went invalid/closed or login lapsed —
/// re-open ONCE and retry) from a *fatal* error (a genuine
/// [`KeyError`] that re-opening would not fix — propagate, fail closed). This is
/// what keeps the fail-closed posture intact while still amortizing logins: a real
/// signing/lookup failure is NEVER masked by a reconnect-and-retry loop.
pub(crate) enum SessionOpError {
    /// The cached session is no longer usable (handle invalid / closed / not
    /// logged in / device hiccup). Re-open a fresh logged-in session and retry the
    /// operation exactly once.
    SessionInvalid(KeyError),
    /// A genuine failure that a fresh session would not cure — propagate as-is.
    Fatal(KeyError),
}

/// Open a fresh logged-in session of type `S`. Implemented for the real
/// [`Pkcs11KeySource`] (opens a Cryptoki R/W session + `C_Login`) and, in tests,
/// by a counting fake — so the amortization decision is provable WITHOUT a live
/// token (no PKCS#11 provider dependency for the unit proof).
pub(crate) trait LoginSessionFactory {
    /// The session handle type this factory produces.
    type Session;
    /// Open a NEW session and authenticate it (one `C_Login`). Every call here is
    /// one login — the whole point of [`AmortizedSession`] is to make this run far
    /// fewer than once per signed response.
    fn open_logged_in(&self) -> Result<Self::Session, KeyError>;
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
/// drop is the backstop for the one currently-cached handle.
/// A cached, logged-in PKCS#11 session reduced to its raw `CK_SESSION_HANDLE`.
///
/// This is the lifetime-free `S` that [`AmortizedSession`] caches for the real
/// source. The wrapper's [`crate::pkcs11_native::Session`] carries a phantom
/// lifetime tying it to its [`Pkcs11Context`], which makes it impossible to store
/// alongside that same context in one struct (self-referential). Because a session
/// is really just a `Copy` handle, we amortize on the HANDLE: open+login once,
/// keep the handle here, and run each op through a non-owning
/// [`SessionRef`](crate::pkcs11_native::SessionRef) against the live context.
///
/// The handle is closed explicitly when this holder is retired (on a transient
/// invalidation, via [`Pkcs11Context::close_session`]); `C_Finalize` on context
pub(crate) struct LoggedInSession {
    /// The raw open+logged-in session handle (owned: closed on retirement).
    pub(crate) handle: CK_SESSION_HANDLE,
    /// Lifetime-free closer for `handle`'s parent context; closes the handle on
    /// drop (retirement by [`AmortizedSession`], or when the source is dropped).
    pub(crate) closer: SessionCloser,
}

impl Drop for LoggedInSession {
    fn drop(&mut self) {
        // Retire the cached handle. A close error on teardown has nowhere
        // meaningful to go (and `C_Finalize` on the context is the backstop), so it
        // is intentionally ignored — but we never call a null pointer (the closer
        // guards that) and we never leak silently while the context lives.
        let _ = self.closer.close(self.handle);
    }
}

/// Classify a wrapper [`Pkcs11Error`]: `true` when re-opening a fresh logged-in
/// session could plausibly cure it (the current session handle is invalid/closed,
/// the login lapsed, or the device had a transient fault). A `false` here means the
/// error is intrinsic to the operation (bad mechanism, malformed object, …) and a
/// reconnect would not help — fail closed (a real sign/lookup error is NOT retried).
pub(super) fn is_session_invalid(error: &Pkcs11Error) -> bool {
    match error {
        Pkcs11Error::Ck { rv, .. } => matches!(
            *rv,
            CKR_SESSION_HANDLE_INVALID
                | CKR_SESSION_CLOSED
                | CKR_SESSION_COUNT
                | CKR_USER_NOT_LOGGED_IN
                | CKR_DEVICE_ERROR
                | CKR_DEVICE_REMOVED
        ),
        // Load / missing-function / protocol shape errors are not transient session
        // faults — re-opening would not cure them. Fail closed.
        Pkcs11Error::Load(_) | Pkcs11Error::MissingFunction(_) | Pkcs11Error::Protocol(_) => false,
    }
}

/// Map a wrapper [`Pkcs11Error`] from a token op into a [`SessionOpError`]: a
/// session-fault CK_RV becomes [`SessionOpError::SessionInvalid`] (retry once),
/// everything else [`SessionOpError::Fatal`] (propagate, fail closed). `make_fatal`
/// builds the contextual [`KeyError`] for the fatal/propagated case (matching the
/// pre-amortization error text exactly).
pub(super) fn classify_op_error(
    error: Pkcs11Error,
    make_fatal: impl FnOnce(&Pkcs11Error) -> KeyError,
) -> SessionOpError {
    if is_session_invalid(&error) {
        // Retryable: surface a NotFound carrying the transient cause; the retry
        // path discards the message, so the text is diagnostic only.
        SessionOpError::SessionInvalid(KeyError::NotFound(format!(
            "pkcs11: transient session fault: {error}"
        )))
    } else {
        SessionOpError::Fatal(make_fatal(&error))
    }
}
