//! What an AWS KMS refusal of the session credential costs, and what it discards.
//!
//! A cached session credential can stop being honoured by KMS before the expiry it was cached
//! under, and nothing else evicts it. This module owns the one answer: KMS refusing the
//! credential as expired or unrecognized discards exactly the credential that was presented
//! and re-signs ONCE with a fresh one. `AccessDeniedException`, throttling and every other
//! name discard nothing and cost one call, because a fresh credential cannot fix them and
//! evicting on them is a per-handshake STS exchange drivable by a peer. A refusal a fresh
//! credential does not fix suspends the retry for [`CREDENTIAL_REFUSAL_RETRY_COOLDOWN`].

use crate::aws_sigv4::AwsCredentials;
use crate::aws_sts::AwsCredentialSource;
use crate::key_source::KeyError;
use crate::remote_signer_call::RemoteSignerFailure;
use crate::remote_signer_call::NETWORK_TIMEOUT;
use std::sync::atomic::Ordering;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

/// The `__type` names with which KMS says it will not read the credential itself.
const SESSION_CREDENTIAL_REFUSALS: &[&str] =
    &["ExpiredTokenException", "UnrecognizedClientException"];

/// How long a refusal that a FRESH credential did not fix suspends the retry.
const CREDENTIAL_REFUSAL_RETRY_COOLDOWN: Duration = NETWORK_TIMEOUT;

/// Did KMS refuse the session credential itself? Reads only the `__type` of the body: the
/// suffix after the last `#` and before any `:`.
fn refused_the_session_credential(failure: &RemoteSignerFailure) -> bool {
    let Some(body) = failure.body() else {
        return false;
    };
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    let Some(kind) = parsed.get("__type").and_then(serde_json::Value::as_str) else {
        return false;
    };
    let name = kind.rsplit('#').next().unwrap_or(kind);
    let name = name.split(':').next().unwrap_or(name);
    SESSION_CREDENTIAL_REFUSALS.contains(&name)
}

/// The refused-credential retry and its suspension.
pub(super) struct RefusalRecovery {
    /// When the last refusal that a fresh credential did not fix was observed. `None` in the
    /// steady state. Held as a start rather than an end so no `Instant` arithmetic can overflow.
    suspended_since: Mutex<Option<Instant>>,
}

impl RefusalRecovery {
    pub(super) fn new() -> Self {
        Self {
            suspended_since: Mutex::new(None),
        }
    }

    /// Return `first`, or when KMS refused the credential `presented`, discard it and call
    /// `resend` once with a fresh one.
    pub(super) fn recover(
        &self,
        source: &dyn AwsCredentialSource,
        presented: Option<String>,
        operation: &str,
        first: Result<Vec<u8>, RemoteSignerFailure>,
        resend: impl FnOnce(AwsCredentials) -> Result<Vec<u8>, RemoteSignerFailure>,
    ) -> Result<Vec<u8>, RemoteSignerFailure> {
        self.recover_at(Instant::now(), source, presented, operation, first, resend)
    }

    fn recover_at(
        &self,
        now: Instant,
        source: &dyn AwsCredentialSource,
        presented: Option<String>,
        operation: &str,
        first: Result<Vec<u8>, RemoteSignerFailure>,
        resend: impl FnOnce(AwsCredentials) -> Result<Vec<u8>, RemoteSignerFailure>,
    ) -> Result<Vec<u8>, RemoteSignerFailure> {
        let refused = match first {
            Ok(body) => return Ok(body),
            Err(error) => error,
        };
        let Some(presented) = presented else {
            return Err(refused);
        };
        if !refused_the_session_credential(&refused)
            || self.suspended_at(now)
            || !source.invalidate(&presented)
        {
            return Err(refused);
        }
        let fresh = match source.credentials() {
            Ok(fresh) => fresh,
            Err(error) => {
                self.suspend(now);
                return Err(RemoteSignerFailure::rendered(KeyError::NotFound(format!(
                    "credential re-acquisition failed: {error}; after {}",
                    refused.into_key_error("aws-kms", operation)
                ))));
            }
        };
        let resent = resend(fresh);
        match &resent {
            Ok(_) => *self.since() = None,
            Err(error) if refused_the_session_credential(error) => self.suspend(now),
            Err(_) => {}
        }
        resent
    }

    fn since(&self) -> std::sync::MutexGuard<'_, Option<Instant>> {
        self.suspended_since
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    /// Is the retry suspended at `now`? Clears a lapsed suspension.
    fn suspended_at(&self, now: Instant) -> bool {
        let mut since = self.since();
        match *since {
            Some(start)
                if now.saturating_duration_since(start) < CREDENTIAL_REFUSAL_RETRY_COOLDOWN =>
            {
                true
            }
            Some(_) => {
                *since = None;
                false
            }
            None => false,
        }
    }

    /// Never shortens: a straggler holding an older `now` leaves a later start in place.
    fn suspend(&self, now: Instant) {
        let mut since = self.since();
        *since = Some(since.map_or(now, |current| current.max(now)));
    }
}

impl super::UreqKmsClient {
    /// Refresh before signing; a failed refresh keeps the last-good credentials and is reported
    /// once per failing episode. Poison is recovered: the guarded value is a whole-value swap.
    /// Returns the access key id installed.
    pub(super) fn refresh(&self) -> Option<String> {
        match self.credential_source.credentials() {
            Ok(refreshed) => {
                let presented = refreshed.access_key_id.clone();
                let mut signer = self.signer.write().unwrap_or_else(|p| p.into_inner());
                signer.set_credentials(refreshed);
                self.refresh_failing.store(false, Ordering::Relaxed);
                Some(presented)
            }
            Err(e) if !self.refresh_failing.swap(true, Ordering::Relaxed) => {
                eprintln!("mcp-re-proxy: aws-kms credential refresh failed; signing continues on the last-good credentials: {e}");
                None
            }
            Err(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    #[derive(Default)]
    struct CountingSource {
        credentials: AtomicUsize,
        invalidations: AtomicUsize,
        replaced: bool,
        fails: bool,
    }

    impl AwsCredentialSource for CountingSource {
        fn credentials(&self) -> Result<AwsCredentials, KeyError> {
            self.credentials.fetch_add(1, Ordering::SeqCst);
            if self.fails {
                return Err(KeyError::NotFound("sts down".to_string()));
            }
            Ok(AwsCredentials {
                access_key_id: "AKIDFRESH".to_string(),
                secret_access_key: zeroize::Zeroizing::new("secret".to_string()),
                session_token: None,
            })
        }
        fn invalidate(&self, _refused: &str) -> bool {
            self.invalidations.fetch_add(1, Ordering::SeqCst);
            !self.replaced
        }
        fn describe(&self) -> String {
            "counting".to_string()
        }
    }

    fn refusal(kind: &str) -> RemoteSignerFailure {
        RemoteSignerFailure::status_body(400, format!("{{\"__type\":\"{kind}\"}}"))
    }

    fn recover(
        recovery: &RefusalRecovery,
        now: Instant,
        source: &CountingSource,
        first: RemoteSignerFailure,
        resent: &AtomicUsize,
    ) -> Result<Vec<u8>, RemoteSignerFailure> {
        recovery.recover_at(
            now,
            source,
            Some("AKIDOLD".to_string()),
            "Sign",
            Err(first),
            |_| {
                resent.fetch_add(1, Ordering::SeqCst);
                Ok(b"{}".to_vec())
            },
        )
    }

    #[test]
    fn only_an_expired_or_unrecognized_session_credential_is_a_refusal_of_the_credential() {
        assert!(refused_the_session_credential(&refusal(
            "ExpiredTokenException"
        )));
        assert!(refused_the_session_credential(&refusal(
            "UnrecognizedClientException"
        )));
        assert!(refused_the_session_credential(&refusal(
            "com.amazonaws.kms#ExpiredTokenException"
        )));
        for other in [
            "AccessDeniedException",
            "ThrottlingException",
            "InvalidSignatureException",
        ] {
            assert!(!refused_the_session_credential(&refusal(other)), "{other}");
        }
        for body in ["{}", "not json"] {
            let failure = RemoteSignerFailure::status_body(400, body.to_string());
            assert!(!refused_the_session_credential(&failure), "{body}");
        }
        assert!(!refused_the_session_credential(
            &RemoteSignerFailure::transport("down".to_string())
        ));
    }

    #[test]
    fn a_refused_session_credential_is_discarded_and_the_call_retried_once() {
        let (recovery, source, resent) = (
            RefusalRecovery::new(),
            CountingSource::default(),
            AtomicUsize::new(0),
        );
        let out = recover(
            &recovery,
            Instant::now(),
            &source,
            refusal("ExpiredTokenException"),
            &resent,
        );
        assert!(out.is_ok());
        assert_eq!(source.invalidations.load(Ordering::SeqCst), 1);
        assert_eq!(source.credentials.load(Ordering::SeqCst), 1);
        assert_eq!(resent.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn an_access_denied_refusal_discards_nothing_and_costs_one_call() {
        let (recovery, source, resent) = (
            RefusalRecovery::new(),
            CountingSource::default(),
            AtomicUsize::new(0),
        );
        let out = recover(
            &recovery,
            Instant::now(),
            &source,
            refusal("AccessDeniedException"),
            &resent,
        );
        assert!(out.is_err());
        assert_eq!(source.invalidations.load(Ordering::SeqCst), 0);
        assert_eq!(source.credentials.load(Ordering::SeqCst), 0);
        assert_eq!(resent.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_refusal_about_a_credential_already_replaced_costs_no_second_call() {
        let source = CountingSource {
            replaced: true,
            ..CountingSource::default()
        };
        let (recovery, resent) = (RefusalRecovery::new(), AtomicUsize::new(0));
        let out = recover(
            &recovery,
            Instant::now(),
            &source,
            refusal("ExpiredTokenException"),
            &resent,
        );
        assert!(out.is_err());
        assert_eq!(source.invalidations.load(Ordering::SeqCst), 1);
        assert_eq!(resent.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_refusal_a_fresh_credential_does_not_fix_suspends_the_retry_for_the_cool_off() {
        let (recovery, source, resent) = (
            RefusalRecovery::new(),
            CountingSource::default(),
            AtomicUsize::new(0),
        );
        let now = Instant::now();
        let again = |at: Instant| {
            let first = refusal("ExpiredTokenException");
            recovery.recover_at(
                at,
                &source,
                Some("AKIDOLD".to_string()),
                "Sign",
                Err(first),
                |_| {
                    resent.fetch_add(1, Ordering::SeqCst);
                    Err(refusal("ExpiredTokenException"))
                },
            )
        };
        assert!(again(now).is_err());
        assert_eq!(resent.load(Ordering::SeqCst), 1);
        assert!(again(now).is_err());
        assert_eq!(
            source.invalidations.load(Ordering::SeqCst),
            1,
            "suspended: no invalidate"
        );
        assert_eq!(resent.load(Ordering::SeqCst), 1, "suspended: no resend");
        assert!(again(now + CREDENTIAL_REFUSAL_RETRY_COOLDOWN).is_err());
        assert_eq!(resent.load(Ordering::SeqCst), 2, "the cool-off lapsed");
    }
}
