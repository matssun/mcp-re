// SPDX-License-Identifier: Apache-2.0
//! The root issuer, asked under a bound (ADR-MCPRE-052 §6/§7).
//!
//! One fact: **a root-issuer call that does not answer is a failed issuance, not a stopped
//! rotation worker.**
//!
//! The rotation worker is the only thing that mints successors and the only thing that
//! polls the shared trust epoch, and the root issuer is a KMS, an HSM or a file. A KMS
//! adapter bounds its own HTTP exchanges; a PKCS#11 `C_Sign` bounds nothing. Called on the
//! worker's own thread, a root call that never returns stops rotation AND the operator's
//! epoch kill switch, while `consecutive_failures` — written only when an issuance returns
//! — reads 0. So each call runs on its own thread and is waited for at most
//! [`ROOT_ISSUER_CALL_BOUND`]; a call that outlives the bound is reported as a failure, which
//! the custody treats as a fail-closed issuance: the current key serves to its `exp`, the
//! failure is counted, and the worker returns to its loop and its epoch poll.
//!
//! SINGLE-FLIGHT. A thread cannot be cancelled, so a call that outlived the bound keeps
//! running. While it does, every further call is refused at once rather than started
//! beside it: one stuck root call holds one thread, never one per retry.

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use crate::key_source::ResponseSigner;

/// How long one root-issuer call may take before it is a failed issuance.
///
/// The slowest live root is a cloud KMS whose credential must be refreshed first: a token
/// exchange and a sign exchange, and one retry of both after a credential refusal — four
/// exchanges, each bounded by the remote-signer `NETWORK_TIMEOUT` of 5s. A root slower than
/// that is not answering, and the epoch poll is stalled for at most this long per attempt.
pub(crate) const ROOT_ISSUER_CALL_BOUND: Duration = Duration::from_secs(20);

/// Why a bounded root-issuer call produced no signature.
#[derive(Debug)]
pub(crate) enum RootCallError {
    /// A previous call has outlived the bound and is still running.
    Outstanding,
    /// The root did not answer within the bound.
    TimedOut(Duration),
    /// The root answered with a refusal, or the call could not be made.
    Unavailable(String),
}

impl std::fmt::Display for RootCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RootCallError::Outstanding => f.write_str(
                "root issuer unavailable: a previous call has not returned, so no second one is started",
            ),
            RootCallError::TimedOut(bound) => {
                write!(f, "root issuer unavailable: no answer within {bound:?}")
            }
            RootCallError::Unavailable(why) => write!(f, "root issuer unavailable: {why}"),
        }
    }
}

/// A root issuer every call to which is bounded and single-flight.
pub(crate) struct BoundedRootIssuer<S> {
    root: Arc<Mutex<S>>,
    in_flight: Arc<AtomicBool>,
    bound: Duration,
}

/// Clears the in-flight flag when the call's thread ends, however it ends — a root that
/// panics must not leave every later call refused as outstanding.
struct InFlight(Arc<AtomicBool>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl<S: ResponseSigner + Send + 'static> BoundedRootIssuer<S> {
    /// An issuer under `bound`; production passes [`ROOT_ISSUER_CALL_BOUND`].
    pub(crate) fn with_bound(root: S, bound: Duration) -> Self {
        BoundedRootIssuer {
            root: Arc::new(Mutex::new(root)),
            in_flight: Arc::new(AtomicBool::new(false)),
            bound,
        }
    }

    /// The root's signature over `input`, or why there is none within the bound.
    pub(crate) fn sign(&self, input: &[u8]) -> Result<String, RootCallError> {
        if self.in_flight.swap(true, Ordering::SeqCst) {
            return Err(RootCallError::Outstanding);
        }
        let guard = InFlight(Arc::clone(&self.in_flight));
        let root = Arc::clone(&self.root);
        let input = input.to_vec();
        let (reply, answer) = mpsc::sync_channel(1);
        let spawned = std::thread::Builder::new()
            .name("delegated root issuer call".to_string())
            .spawn(move || {
                let _guard = guard;
                let signed = match root.lock() {
                    Ok(root) => root.sign_response(&input).map_err(|e| e.to_string()),
                    Err(_) => Err("a previous root call panicked".to_string()),
                };
                // The caller may have stopped waiting; its answer is then nobody's.
                let _ = reply.send(signed);
            });
        if let Err(e) = spawned {
            // The closure, and the guard it owns, were dropped with the failed spawn.
            return Err(RootCallError::Unavailable(format!(
                "no thread for the call: {e}"
            )));
        }
        match answer.recv_timeout(self.bound) {
            Ok(signed) => signed.map_err(RootCallError::Unavailable),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(RootCallError::TimedOut(self.bound)),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(RootCallError::Unavailable(
                "the root call ended without answering".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_source::KeyError;
    use mcp_re_core::SigningKey;
    use mcp_re_core::VerificationKey;
    use std::sync::atomic::AtomicUsize;
    use std::time::Instant;

    const BOUND: Duration = Duration::from_millis(100);

    /// A root that blocks every call until the test releases it, counting the calls it saw.
    struct HangingRoot {
        release: Mutex<mpsc::Receiver<()>>,
        calls: Arc<AtomicUsize>,
        key: SigningKey,
    }

    impl ResponseSigner for HangingRoot {
        fn sign_response(&self, preimage: &[u8]) -> Result<String, KeyError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let _ = self.release.lock().expect("release lock").recv();
            Ok(self.key.sign(preimage))
        }
        fn response_public_key(&self) -> Result<VerificationKey, KeyError> {
            Ok(self.key.public_key())
        }
    }

    fn hanging() -> (HangingRoot, mpsc::Sender<()>, Arc<AtomicUsize>) {
        let (release, wait) = mpsc::channel();
        let calls = Arc::new(AtomicUsize::new(0));
        let root = HangingRoot {
            release: Mutex::new(wait),
            calls: Arc::clone(&calls),
            key: SigningKey::from_seed_bytes(&[7u8; 32]),
        };
        (root, release, calls)
    }

    #[test]
    fn an_answering_root_signs() {
        let key = SigningKey::from_seed_bytes(&[5u8; 32]);
        let expected = key.sign(b"input");
        let issuer = BoundedRootIssuer::with_bound(key, BOUND);
        assert_eq!(issuer.sign(b"input").expect("signed"), expected);
    }

    #[test]
    fn a_root_that_does_not_answer_is_a_failure_within_the_bound() {
        let (root, release, _calls) = hanging();
        let issuer = BoundedRootIssuer::with_bound(root, BOUND);
        let started = Instant::now();
        let refused = issuer.sign(b"input");
        assert!(matches!(refused, Err(RootCallError::TimedOut(b)) if b == BOUND));
        assert!(
            started.elapsed() < BOUND * 20,
            "the caller must get its answer at the bound, not when the root returns"
        );
        drop(release);
    }

    #[test]
    fn a_call_outliving_the_bound_refuses_the_next_without_starting_it() {
        let (root, release, calls) = hanging();
        let issuer = BoundedRootIssuer::with_bound(root, BOUND);
        assert!(matches!(issuer.sign(b"a"), Err(RootCallError::TimedOut(_))));
        assert!(matches!(issuer.sign(b"b"), Err(RootCallError::Outstanding)));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "one stuck call holds one thread, never one per retry"
        );
        drop(release);
    }

    #[test]
    fn once_the_stuck_call_returns_the_next_call_is_served() {
        let (root, release, calls) = hanging();
        let issuer = BoundedRootIssuer::with_bound(root, BOUND);
        assert!(matches!(issuer.sign(b"a"), Err(RootCallError::TimedOut(_))));
        release.send(()).expect("release the stuck call");
        let deadline = Instant::now() + BOUND * 50;
        while issuer.in_flight.load(Ordering::SeqCst) {
            assert!(Instant::now() < deadline, "the stuck call never cleared");
            std::thread::sleep(Duration::from_millis(5));
        }
        release.send(()).expect("release the next call");
        assert!(issuer.sign(b"b").is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    struct PanickingRoot;

    impl ResponseSigner for PanickingRoot {
        fn sign_response(&self, _preimage: &[u8]) -> Result<String, KeyError> {
            panic!("root backend panicked");
        }
        fn response_public_key(&self) -> Result<VerificationKey, KeyError> {
            Ok(SigningKey::from_seed_bytes(&[1u8; 32]).public_key())
        }
    }

    #[test]
    fn a_root_that_panics_fails_each_call_without_wedging_the_issuer() {
        let issuer = BoundedRootIssuer::with_bound(PanickingRoot, BOUND);
        assert!(matches!(
            issuer.sign(b"a"),
            Err(RootCallError::Unavailable(_))
        ));
        let deadline = Instant::now() + BOUND * 50;
        while issuer.in_flight.load(Ordering::SeqCst) {
            assert!(
                Instant::now() < deadline,
                "a panicked call left the issuer in flight"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            matches!(issuer.sign(b"b"), Err(RootCallError::Unavailable(_))),
            "a later call fails as unavailable, not as outstanding"
        );
    }
}
