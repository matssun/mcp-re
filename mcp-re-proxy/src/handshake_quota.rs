// SPDX-License-Identifier: Apache-2.0
//! The handshake path's share of a remote signer's quota (ADR-MCPS-028 §G).
//!
//! # The failure this exists to stop
//!
//! A TLS server using a KMS-custodied key signs one `CertificateVerify` per handshake —
//! one remote `Sign` — BEFORE it has seen a client certificate, and with session
//! resumption refused every connection is a full handshake. So the handshake path is the
//! one an unauthenticated peer can drive, and it shares an account or project quota with
//! the delegated-credential issuance that keeps the replica able to sign responses at all.
//!
//! Left alone, a connection flood spends the quota; the cold-path rotor's `Sign` for the
//! next delegated credential fails with it; and the replica fails closed on
//! `delegated_signing_unavailable` once the current credential's TTL runs out. **A
//! handshake flood becomes a signing outage.**
//!
//! The mitigation is to treat a throttle as a signal about the SHARED quota rather than as
//! one request's bad luck: for a window afterwards the handshake path refuses locally
//! without calling the signer, leaving the quota to the issuance path. Refusing handshakes
//! is the cheap failure — a peer retries a connection; a replica that has lost response
//! signing does not recover until a credential can be minted.
//!
//! # Why it is one owner and not one per provider
//!
//! It was one per provider. `aws_kms_keysource` and `gcp_kms_keysource` held
//! character-identical copies of the window, the probe, the straggler rule and the poison
//! recovery, plus seven near-identical behaviour tests each, reached through a fake HTTP
//! transport, a backend construction and an SPKI parse — none of which the property is
//! about. Two copies of a concurrency rule is two chances to fix half of it.
//!
//! What genuinely differs between providers is two things, and they are the two parameters:
//! the sentence a refusal states, and which failures mean *the quota is gone* rather than
//! *that request was bad*.
//!
//! # The window length is derived, not configured
//!
//! [`HandshakeQuotaWindow::for_network_timeout`] takes the caller's per-request network
//! timeout and makes the window equal to it. A window SHORTER than the timeout can be
//! installed already elapsed — the reaction happens after a call that may have taken a
//! whole timeout — and it would degenerate to no throttle at all in exactly the regime it
//! exists for: an overloaded signer answering slowly.
//!
//! Both providers used to state the relation as a constant defined against their own
//! timeout, with a test asserting the two had not drifted apart. Deriving it is what
//! deletes the test: there is one value, so there is nothing to drift.

use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

use crate::key_source::KeyError;

/// What a signer-backend failure says about the shared quota.
///
/// Two values, because the question is not how the call failed but whether the ACCOUNT
/// or PROJECT is out of budget: a malformed request and an expired credential are this
/// caller's problem, and throttling every later handshake over them would turn a
/// configuration error into a self-inflicted outage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuotaVerdict {
    /// The signer said the shared quota is exhausted. The window opens.
    Exhausted,
    /// Anything else. The failure is reported and the window is left alone.
    Unrelated,
}

/// One backend's handshake-path throttle window.
///
/// Holds no signer and performs no call: [`guard`](Self::guard) is handed the signing
/// operation, so the window can be driven against a closure and an explicit clock rather
/// than against a fake HTTP transport.
pub(crate) struct HandshakeQuotaWindow {
    /// When the handshake path may call the signer again. `None` outside a window, which
    /// is the steady state and the state a successful probe leaves behind.
    until: Mutex<Option<Instant>>,
    /// How long a window lasts. Equal to the caller's network timeout — see the module
    /// docs for why it may not be shorter.
    cooldown: Duration,
    /// What a locally-refused handshake says. Provider-specific because the operator
    /// reading it needs to know which quota to look at.
    refusal: &'static str,
}

impl HandshakeQuotaWindow {
    /// A window for a backend whose calls time out after `network_timeout`.
    pub(crate) fn for_network_timeout(network_timeout: Duration, refusal: &'static str) -> Self {
        Self {
            until: Mutex::new(None),
            cooldown: network_timeout,
            refusal,
        }
    }

    /// Open a window ending [`Self::cooldown`] after `now`, never SHORTENING one already
    /// in force.
    ///
    /// `now` MUST be a clock reading taken AFTER the call being reacted to. That is what
    /// keeps the window from being installed stale: it was previously the handshake's ENTRY
    /// instant, so a signer call slower than the cooldown opened a window that had already
    /// elapsed — no throttle at all, precisely when the signer was slow enough to need one.
    ///
    /// `max` is a narrower guarantee than it looks, and the two are easy to confuse: it
    /// stops a thread REPLACING a longer window with a shorter one, which is what plain
    /// assignment did when two threads reported failures out of order. It does NOT sanitise
    /// a stale reading — on the `None` branch, whatever `until` it is handed is installed
    /// outright. Freshness comes from the caller reading the clock here, not from `max`.
    fn arm(&self, now: Instant) {
        let mut window = self.until.lock().unwrap_or_else(|p| p.into_inner());
        let until = now + self.cooldown;
        *window = Some(window.map_or(until, |current| current.max(until)));
    }

    /// Run one handshake signature under the window.
    ///
    /// Inside a window this refuses WITHOUT calling `sign`. `clock` is read TWICE and the
    /// distinction is load-bearing: once at the gate, to decide whether this handshake may
    /// reach the signer, and again AFTER the call, to open a window that reacts to when the
    /// call finished rather than to when the handshake arrived.
    ///
    /// `verdict` classifies a failure. It is the provider's, because the codes are.
    pub(crate) fn guard(
        &self,
        clock: &dyn Fn() -> Instant,
        sign: impl FnOnce() -> Result<Vec<u8>, KeyError>,
        verdict: impl Fn(&KeyError) -> QuotaVerdict,
    ) -> Result<Vec<u8>, KeyError> {
        let now = clock();
        // Whether THIS thread is the one probing a lapsed window. Only the thread that
        // observes the lapse takes the probe: it re-arms the window before releasing the
        // lock, so the rest of a concurrent handshake cohort at the boundary is still
        // refused instead of all calling the signer at once — which is the flood the window
        // exists to stop, arriving one cooldown late.
        let probing = {
            // Poison recovery, not propagation: the state is one whole-value swap, and a
            // sticky lock error here would refuse every later handshake signature for the
            // process lifetime — a far worse failure than the throttle it guards against.
            let mut window = self.until.lock().unwrap_or_else(|p| p.into_inner());
            match *window {
                Some(until) if now < until => {
                    return Err(KeyError::NotFound(self.refusal.to_string()))
                }
                Some(_) => {
                    *window = Some(now + self.cooldown);
                    true
                }
                None => false,
            }
        };
        let signed = sign();
        match &signed {
            Ok(_) if probing => {
                // The probe went through: the quota is available again, so reopen the path
                // rather than leaving the window this thread armed to run its course.
                *self.until.lock().unwrap_or_else(|p| p.into_inner()) = None;
            }
            // Armed from a reading taken NOW, after the call — not from the entry instant.
            Err(error) if verdict(error) == QuotaVerdict::Exhausted => self.arm(clock()),
            _ => {}
        }
        signed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    const TIMEOUT: Duration = Duration::from_secs(5);
    const REFUSAL: &str = "test-kms: the shared quota is exhausted";

    fn window() -> HandshakeQuotaWindow {
        HandshakeQuotaWindow::for_network_timeout(TIMEOUT, REFUSAL)
    }

    fn throttled() -> KeyError {
        KeyError::NotFound("ThrottlingException".to_string())
    }

    fn malformed() -> KeyError {
        KeyError::Malformed("one bad request".to_string())
    }

    /// Every failure that is not a quota failure.
    fn only_throttling(error: &KeyError) -> QuotaVerdict {
        if format!("{error:?}").contains("ThrottlingException") {
            QuotaVerdict::Exhausted
        } else {
            QuotaVerdict::Unrelated
        }
    }

    /// The whole point: after a throttle, the signer is not called again for the window.
    #[test]
    fn a_throttled_signature_stops_calling_the_signer_for_the_cooldown() {
        let w = window();
        let calls = AtomicUsize::new(0);
        let sign = || {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(throttled())
        };
        let start = Instant::now();
        assert!(w.guard(&|| start, sign, only_throttling).is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Inside the window: refused locally, and the signer is NOT reached.
        let inside = start + TIMEOUT - Duration::from_millis(1);
        let err = w
            .guard(
                &|| inside,
                || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(vec![7u8; 64])
                },
                only_throttling,
            )
            .unwrap_err();
        assert!(
            format!("{err}").contains("shared quota is exhausted"),
            "{err}"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the signer was called inside the window"
        );
    }

    /// A call SLOWER than the cooldown still leaves a live window behind it.
    ///
    /// The regression this pins: the window used to be armed from the handshake's ENTRY
    /// instant, so a call that took a whole timeout installed one that had already elapsed
    /// — no throttle at all, in exactly the regime the throttle exists for.
    #[test]
    fn a_slow_throttled_call_still_opens_a_live_window() {
        let w = window();
        let start = Instant::now();
        let slow = TIMEOUT + Duration::from_millis(20);
        // Entry reads `start`; the post-call reading is a whole slow call later.
        let readings = AtomicUsize::new(0);
        let clock = || {
            if readings.fetch_add(1, Ordering::SeqCst) == 0 {
                start
            } else {
                start + slow
            }
        };
        assert!(w
            .guard(&clock, || Err(throttled()), only_throttling)
            .is_err());

        let just_after_the_call = start + slow + Duration::from_millis(1);
        let calls = AtomicUsize::new(0);
        assert!(
            w.guard(
                &|| just_after_the_call,
                || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(vec![])
                },
                only_throttling,
            )
            .is_err(),
            "the window must still be live one millisecond after the slow call returned"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    /// At the boundary exactly ONE handshake probes; the rest of the cohort is refused.
    ///
    /// Without the re-arm inside the lock, every thread waiting at the boundary observes
    /// the lapse and calls the signer at once — the flood the window exists to stop,
    /// arriving one cooldown late.
    #[test]
    fn only_one_handshake_probes_at_the_cooldown_boundary() {
        let w = window();
        let start = Instant::now();
        assert!(w
            .guard(&|| start, || Err(throttled()), only_throttling)
            .is_err());

        let boundary = start + TIMEOUT;
        let calls = AtomicUsize::new(0);
        let mut probes = 0;
        for _ in 0..5 {
            let outcome = w.guard(
                &|| boundary,
                || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Err(throttled())
                },
                only_throttling,
            );
            assert!(outcome.is_err());
            probes = calls.load(Ordering::SeqCst);
        }
        assert_eq!(probes, 1, "the cohort at the boundary must not all probe");
    }

    /// A straggler reporting an OLD failure cannot shorten a window already in force.
    #[test]
    fn a_straggler_cannot_shorten_the_window() {
        let w = window();
        let start = Instant::now();
        // A late thread arms from a much later reading: the long window.
        let later = start + Duration::from_secs(60);
        w.arm(later);
        // The straggler's reading is older, so `max` keeps the longer window.
        w.arm(start);

        let between = later - Duration::from_secs(1);
        let calls = AtomicUsize::new(0);
        assert!(
            w.guard(
                &|| between,
                || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(vec![])
                },
                only_throttling,
            )
            .is_err(),
            "the longer window must survive a straggler's older reading"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    /// A probe that SUCCEEDS reopens the path at once, rather than serving out the window
    /// the probing thread itself armed.
    #[test]
    fn a_successful_probe_reopens_the_path_at_once() {
        let w = window();
        let start = Instant::now();
        assert!(w
            .guard(&|| start, || Err(throttled()), only_throttling)
            .is_err());

        let boundary = start + TIMEOUT;
        assert!(w
            .guard(&|| boundary, || Ok(vec![1u8; 64]), only_throttling)
            .is_ok());
        // The very next handshake, at the same instant, is served — the probing thread's
        // re-armed window was cleared by its own success.
        assert!(w
            .guard(&|| boundary, || Ok(vec![2u8; 64]), only_throttling)
            .is_ok());
    }

    /// Only quota failures open a window. A malformed request is this caller's problem,
    /// and throttling every later handshake over it is a self-inflicted outage.
    #[test]
    fn only_quota_failures_open_the_window() {
        let w = window();
        let start = Instant::now();
        assert!(w
            .guard(&|| start, || Err(malformed()), only_throttling)
            .is_err());

        let calls = AtomicUsize::new(0);
        assert!(w
            .guard(
                &|| start + Duration::from_millis(1),
                || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(vec![3u8; 64])
                },
                only_throttling,
            )
            .is_ok());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "no window should have opened"
        );
    }

    /// A poisoned lock still signs.
    ///
    /// A sticky lock error would refuse every later handshake signature for the process
    /// lifetime — a far worse failure than the throttle it guards against.
    #[test]
    fn a_poisoned_window_lock_still_signs() {
        let w = window();
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = w.until.lock().unwrap();
            panic!("poison the window lock");
        }));
        assert!(poisoned.is_err());
        assert!(w.until.is_poisoned());

        let now = Instant::now();
        assert!(w
            .guard(&|| now, || Ok(vec![9u8; 64]), only_throttling)
            .is_ok());
    }

    /// The window can never be shorter than the call it reacts to.
    ///
    /// Not an assertion about two constants agreeing — there is only one value now, and
    /// this pins that the constructor keeps it that way rather than scaling it down.
    #[test]
    fn the_window_is_never_shorter_than_the_network_timeout() {
        let w = HandshakeQuotaWindow::for_network_timeout(TIMEOUT, REFUSAL);
        assert!(w.cooldown >= TIMEOUT);
    }
}
