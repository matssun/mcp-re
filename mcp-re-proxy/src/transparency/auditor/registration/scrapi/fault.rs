// SPDX-License-Identifier: Apache-2.0
//! WHAT can go wrong in this protocol, and HOW CERTAIN each one is.
//!
//! One fact: **whether a failed registration definitely did not happen, or may have.**
//!
//! Its own owner because it is the one decision in this subtree that a caller cannot
//! recover from a message. Reporting *not registered* for a statement a service may hold
//! sends an operator to re-submit a record already in a log; reporting the reverse loses
//! the record. So the protocol's faults are typed here, and [`fault_to_error`] is the
//! single place any of them becomes a semantic refusal.
//!
//! The rule it applies is short and it is the whole of the authority: **only an answer the
//! service gave BEFORE accepting anything is a definitive negative.** Everything that can
//! go wrong after the bytes went out leaves the outcome unknown.

use std::time::Duration;

use super::super::capability::RegistrationError;
use super::wire::SCRAPI_REVISION;

/// WHICH half of the protocol an answer came from.
///
/// Carried because it is what a reader needs to act: "the transport failed while
/// submitting" and "the transport failed while polling" describe different states of the
/// world, even though both leave the outcome unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Phase {
    /// Submitting the statement.
    Submitting,
    /// Polling the receipt resource named by a `202`.
    Polling,
}

impl Phase {
    fn as_str(self) -> &'static str {
        match self {
            Phase::Submitting => "while submitting the statement",
            Phase::Polling => "while polling the receipt resource",
        }
    }
}

/// A protocol fault, typed. Every one of these is a thing the draft's own contract can go
/// wrong in, named rather than flattened into a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Scrapi11Fault {
    /// The exchange did not complete.
    Transport { phase: Phase, detail: String },
    /// An answer this reader cannot use — an empty body where one is required.
    MalformedResponse { phase: Phase, detail: &'static str },
    /// A body arrived under a media type this profile does not accept.
    UnsupportedMediaType { phase: Phase, media_type: String },
    /// A `202` carried no `Location`, so there is nothing to poll.
    MissingLocation,
    /// A `Location` naming an authority outside the configured service.
    LocationOutsideService { location: String },
    /// A status the protocol does not define for this exchange.
    ProtocolError { phase: Phase, status: u16 },
    /// The service read the submission and said no.
    Refused { status: u16 },
    /// The service's rate limiter rejected the submission.
    RateLimited { status: u16 },
    /// A `503` answered the submission.
    ///
    /// Separate from [`RateLimited`](Self::RateLimited) because the two are not equally
    /// knowable. A `429` is a rate limiter declining a request before it is handled. A
    /// `503` can be that too — and it can equally be a reverse proxy answering after the
    /// origin accepted the statement and then took too long, which is a registration that
    /// happened. Nothing in the response tells the two apart, so this does not claim one.
    Unavailable { status: u16 },
    /// The budget ran out with the receipt still not ready.
    TimedOut { after: Duration },
}

/// The ONE place a protocol fault becomes a semantic one — and therefore the one place
/// certainty is decided.
///
/// Only an explicit refusal status and an explicit rate limit are definitive negatives:
/// in both the service read the submission and declined it. Everything else happened
/// after the bytes went out, so the service may hold the statement, and reporting those
/// as failures to register would send an operator to re-submit a record already in a log.
pub(super) fn fault_to_error(fault: Scrapi11Fault) -> RegistrationError {
    match fault {
        Scrapi11Fault::Refused { status } => RegistrationError::Refused(format!(
            "{SCRAPI_REVISION}: the service answered {status} to the submission",
        )),
        Scrapi11Fault::RateLimited { status } => RegistrationError::Throttled(format!(
            "{SCRAPI_REVISION}: the service's rate limiter answered {status} to the \
             submission",
        )),
        Scrapi11Fault::Unavailable { status } => RegistrationError::Indeterminate(format!(
            "{SCRAPI_REVISION}: the submission was answered {status}. That is most likely \
             an unavailable service and therefore no registration, but a reverse proxy \
             answers the same way over an origin that accepted, so it is not shown",
        )),
        Scrapi11Fault::Transport { phase, detail } => RegistrationError::Indeterminate(format!(
            "{SCRAPI_REVISION}: the exchange did not complete {} ({detail})",
            phase.as_str(),
        )),
        Scrapi11Fault::MalformedResponse { phase, detail } => RegistrationError::Indeterminate(
            format!("{SCRAPI_REVISION}: {detail} {}", phase.as_str()),
        ),
        Scrapi11Fault::UnsupportedMediaType { phase, media_type } => {
            RegistrationError::Indeterminate(format!(
                "{SCRAPI_REVISION}: a body arrived as {media_type:?} {}, and this profile \
                 reads only application/cose",
                phase.as_str(),
            ))
        }
        Scrapi11Fault::MissingLocation => RegistrationError::Indeterminate(format!(
            "{SCRAPI_REVISION}: the submission was accepted with no Location, so there is \
             nothing to poll",
        )),
        Scrapi11Fault::LocationOutsideService { location } => {
            RegistrationError::Indeterminate(format!(
                "{SCRAPI_REVISION}: the submission was accepted and named {location:?}, \
                 which is outside the configured service",
            ))
        }
        Scrapi11Fault::ProtocolError { phase, status } => {
            RegistrationError::Indeterminate(format!(
                "{SCRAPI_REVISION}: unexpected status {status} {}",
                phase.as_str()
            ))
        }
        Scrapi11Fault::TimedOut { after } => RegistrationError::Indeterminate(format!(
            "{SCRAPI_REVISION}: the receipt was still not ready after {after:?}",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The certainty rule, stated over every variant. This is the test that has to be
    /// read to know what the auditor will tell an operator.
    #[test]
    fn only_a_pre_acceptance_answer_is_a_definitive_negative() {
        let definite: Vec<(Scrapi11Fault, &str)> = vec![
            (Scrapi11Fault::Refused { status: 400 }, "refused"),
            (Scrapi11Fault::RateLimited { status: 429 }, "throttled"),
        ];
        for (fault, kind) in definite {
            let error = fault_to_error(fault);
            let matched = match kind {
                "refused" => matches!(error, RegistrationError::Refused(_)),
                _ => matches!(error, RegistrationError::Throttled(_)),
            };
            assert!(matched, "{kind}: {error:?}");
        }

        let unknown = [
            Scrapi11Fault::Transport {
                phase: Phase::Submitting,
                detail: "connection reset".to_owned(),
            },
            Scrapi11Fault::Transport {
                phase: Phase::Polling,
                detail: "connection reset".to_owned(),
            },
            Scrapi11Fault::MalformedResponse {
                phase: Phase::Submitting,
                detail: "empty body",
            },
            Scrapi11Fault::UnsupportedMediaType {
                phase: Phase::Submitting,
                media_type: "application/json".to_owned(),
            },
            Scrapi11Fault::MissingLocation,
            Scrapi11Fault::LocationOutsideService {
                location: "http://169.254.169.254/".to_owned(),
            },
            Scrapi11Fault::ProtocolError {
                phase: Phase::Submitting,
                status: 500,
            },
            Scrapi11Fault::ProtocolError {
                phase: Phase::Polling,
                status: 404,
            },
            Scrapi11Fault::TimedOut {
                after: Duration::from_secs(300),
            },
            // A `503` is NOT grouped with the rate limit: a reverse proxy answers the same
            // way over an origin that accepted, and nothing in the response separates them.
            Scrapi11Fault::Unavailable { status: 503 },
        ];
        for fault in unknown {
            let error = fault_to_error(fault.clone());
            assert!(
                matches!(error, RegistrationError::Indeterminate(_)),
                "{fault:?} happened after the bytes went out: {error:?}",
            );
        }
    }

    /// Every refusal names the revision it was performed under. "SCITT" alone does not
    /// identify a protocol anyone can reproduce, and a draft is a moving target.
    #[test]
    fn every_refusal_names_the_draft_revision() {
        for fault in [
            Scrapi11Fault::Refused { status: 403 },
            Scrapi11Fault::RateLimited { status: 503 },
            Scrapi11Fault::MissingLocation,
            Scrapi11Fault::TimedOut {
                after: Duration::from_secs(1),
            },
        ] {
            let message = fault_to_error(fault).to_string();
            assert!(message.contains(SCRAPI_REVISION), "{message}");
        }
    }

    /// The phase reaches the operator's message. "The transport failed while submitting"
    /// and "while polling" describe different states of the world.
    #[test]
    fn the_phase_reaches_the_message() {
        let submitting = fault_to_error(Scrapi11Fault::Transport {
            phase: Phase::Submitting,
            detail: "reset".to_owned(),
        })
        .to_string();
        let polling = fault_to_error(Scrapi11Fault::Transport {
            phase: Phase::Polling,
            detail: "reset".to_owned(),
        })
        .to_string();
        assert!(submitting.contains("while submitting"), "{submitting}");
        assert!(polling.contains("while polling"), "{polling}");
    }
}
