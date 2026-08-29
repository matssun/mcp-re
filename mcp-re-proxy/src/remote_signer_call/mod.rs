// SPDX-License-Identifier: Apache-2.0
//! One call to a remote signer, as it failed (ADR-MCPS-028 §B/§C).
//!
//! # The fact this exists to keep
//!
//! Both KMS backends have to answer a question about a failed call that nothing in the
//! failure's TEXT is a reliable carrier for: *does this say the account or project is out
//! of quota, or that this one request was bad?* The answer arms the handshake-path throttle
//! window ([`crate::handshake_quota`]), and getting it wrong in either direction is a live
//! failure — a missed throttle is a handshake flood against an already-throttled signer, and
//! a spurious one refuses handshakes on a healthy signer.
//!
//! The fact is known, typed, at the transport: an HTTP status, and a documented error field
//! in the body. It was then destroyed. `KeyError` has two variants and both carry a
//! `String`, so every transport rendered the status and the body into prose, and the
//! classifier parsed them back out with `format!("{error:?}")` and `contains`. A rewording
//! upstream silently stopped arming the window; an unrelated failure carrying one of the
//! tokens armed it.
//!
//! This type is the fact kept instead. It is what the transports return, and it renders to
//! a `KeyError` at the outward boundary — the direction that was always fine.
//!
//! # Why one type for both providers
//!
//! The shape is identical because the situation is: a status-carrying answer, a call that
//! got no answer, and a failure that never reached the wire. GCP had exactly this type
//! privately (`KmsCallError`) and used its typed status for the bearer-token retry, while
//! AWS had none and matched text for the same class of question. What differs is the
//! VOCABULARY inside the body, and that stays with each provider.
//!
//! Two members are `#[cfg(feature = "gcp_kms_keysource")]` — the chained cause and its
//! rendering. They serve the refused-bearer-token retry, which Cloud KMS has and AWS SigV4
//! does not, so a build carrying only the AWS backend must not carry them. `clippy
//! --features <one feature> -- -D warnings` is what says so, and it is a CI lane of its
//! own.

mod quota_signals;

pub(crate) use quota_signals::{quota_verdict, QuotaSignals};

mod wire_limits;

pub(crate) use wire_limits::read_error_body;
pub(crate) use wire_limits::NETWORK_TIMEOUT;

use crate::key_source::KeyError;

/// Why a remote signer call did not produce a usable response body.
#[derive(Debug)]
pub(crate) enum CallOutcome {
    /// The call never reached the wire, and the reason already carries its own rendered
    /// diagnosis — no credential could be produced, a response body could not be read.
    /// Passed through unchanged; there is no status to keep.
    Rendered(KeyError),
    /// The service ANSWERED, with this HTTP status and this body. The pair is the whole
    /// point of the type: both halves are needed to classify, and both used to be prose.
    Status(u16, String),
    /// The call was made and got no answer — connect refused, TLS failure, timeout.
    Transport(String),
}

/// A remote signer call that failed, and the failure that made it be retried.
///
/// # Why the preceding cause is a separate field
///
/// A bearer token refused with 401 is retried once with a fresh one, and when the SECOND
/// call fails an operator needs both: the 401 is the cause and the second failure is the
/// symptom, and rendering only the symptom leaves a metadata-server error with nothing to
/// say why a token was being fetched at all.
///
/// The obvious way to keep both is to append the cause to the body. That would put prose
/// into the field a classifier reads as wire data — the exact confusion this module exists
/// to remove — and a `__type` or `error.status` lookup would start failing on a body that
/// really does state one. So the cause travels alongside, and [`Self::body`] returns the
/// service's answer untouched.
#[derive(Debug)]
pub(crate) struct RemoteSignerFailure {
    outcome: CallOutcome,
    /// A failure that PRECEDED this one and explains why the call was made again.
    after: Option<String>,
}

impl RemoteSignerFailure {
    /// The service answered with this status and body.
    pub(crate) fn status_body(code: u16, body: String) -> Self {
        Self::of(CallOutcome::Status(code, body))
    }

    /// The call was made and got no answer.
    pub(crate) fn transport(message: String) -> Self {
        Self::of(CallOutcome::Transport(message))
    }

    /// A failure carrying its own rendered diagnosis, with no status to keep.
    pub(crate) fn rendered(error: KeyError) -> Self {
        Self::of(CallOutcome::Rendered(error))
    }

    /// A failure that never reached the wire and is malformed input rather than a service
    /// answer.
    pub(crate) fn malformed(message: String) -> Self {
        Self::rendered(KeyError::Malformed(message))
    }

    fn of(outcome: CallOutcome) -> Self {
        Self {
            outcome,
            after: None,
        }
    }

    /// Record the failure that made this call happen. Does not touch [`Self::body`].
    ///
    /// Cloud KMS's, because the credential retry is: AWS SigV4 re-signs per call and has no
    /// refused-token round to chain a cause from. Gated so a build with only the AWS
    /// backend does not carry a method nothing there can reach.
    #[cfg(feature = "gcp_kms_keysource")]
    pub(crate) fn after(mut self, cause: String) -> Self {
        self.after = Some(cause);
        self
    }

    /// Render for the outward surface. `provider` is the short tag an operator greps for
    /// (`aws-kms`, `gcp-kms`); `operation` names the call.
    pub(crate) fn into_key_error(self, provider: &str, operation: &str) -> KeyError {
        let cause = self.after;
        let rendered = match self.outcome {
            CallOutcome::Rendered(error) if cause.is_none() => return error,
            CallOutcome::Rendered(error) => format!("{provider}: {error}"),
            CallOutcome::Status(code, body) => {
                format!("{provider}: {operation} HTTP {code}: {body}")
            }
            CallOutcome::Transport(error) => format!("{provider}: {operation}: {error}"),
        };
        match cause {
            None => KeyError::NotFound(rendered),
            Some(cause) => KeyError::NotFound(format!(
                "{rendered} (after the signer refused the cached credential with: \
                 {provider}: {cause})"
            )),
        }
    }

    /// The rendered text, for chaining this failure onto a retry's. Cloud KMS's, for the
    /// same reason [`Self::after`] is.
    #[cfg(feature = "gcp_kms_keysource")]
    pub(crate) fn describe(&self, operation: &str) -> String {
        match &self.outcome {
            CallOutcome::Rendered(error) => format!("{error}"),
            CallOutcome::Status(code, body) => format!("{operation} HTTP {code}: {body}"),
            CallOutcome::Transport(error) => format!("{operation}: {error}"),
        }
    }

    /// The HTTP status the service answered with, when it answered at all.
    pub(crate) fn status(&self) -> Option<u16> {
        match &self.outcome {
            CallOutcome::Status(code, _) => Some(*code),
            CallOutcome::Rendered(_) | CallOutcome::Transport(_) => None,
        }
    }

    /// The service's answer, untouched by any chained diagnosis.
    pub(crate) fn body(&self) -> Option<&str> {
        match &self.outcome {
            CallOutcome::Status(_, body) => Some(body),
            CallOutcome::Rendered(_) | CallOutcome::Transport(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_status_failure_keeps_both_halves_and_renders_with_them() {
        let failure =
            RemoteSignerFailure::status_body(429, "{\"__type\":\"Throttling\"}".to_string());
        assert_eq!(failure.status(), Some(429));
        assert_eq!(failure.body(), Some("{\"__type\":\"Throttling\"}"));
        let rendered = failure.into_key_error("aws-kms", "TrentService.Sign");
        assert!(
            format!("{rendered}").contains("HTTP 429"),
            "the outward surface is unchanged: {rendered}"
        );
    }

    #[test]
    fn a_rendered_failure_passes_its_own_diagnosis_through_unchanged() {
        let failure = RemoteSignerFailure::malformed("no bearer token".to_string());
        let rendered = failure.into_key_error("gcp-kms", "asymmetricSign");
        assert!(matches!(rendered, KeyError::Malformed(ref m) if m == "no bearer token"));
    }

    #[cfg(feature = "gcp_kms_keysource")]
    #[test]
    fn a_chained_cause_renders_but_never_enters_the_body() {
        let failure = RemoteSignerFailure::status_body(
            503,
            "{\"error\":{\"status\":\"UNAVAILABLE\"}}".to_string(),
        )
        .after("asymmetricSign HTTP 401: ".to_string());

        assert_eq!(
            failure.body(),
            Some("{\"error\":{\"status\":\"UNAVAILABLE\"}}"),
            "the classifier must still see the service's own answer"
        );
        assert_eq!(
            quota_signals::json_string_field(failure.body().unwrap(), &["error", "status"])
                .as_deref(),
            Some("UNAVAILABLE"),
            "and must still be able to read the field out of it"
        );
        assert_eq!(failure.status(), Some(503));

        let rendered = format!("{}", failure.into_key_error("gcp-kms", "asymmetricSign"));
        assert!(rendered.contains("HTTP 503"), "{rendered}");
        assert!(
            rendered.contains("HTTP 401"),
            "the cause must survive: {rendered}"
        );
    }
}
