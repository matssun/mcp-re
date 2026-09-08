// SPDX-License-Identifier: Apache-2.0
//! WHAT can go wrong against capsule-anchor, and HOW CERTAIN each one is.
//!
//! One fact: **whether a failed registration definitely did not happen, or may have.**
//!
//! Its own owner for the reason the SCRAPI leaf's is: this is the one decision in the
//! subtree a caller cannot recover from a message. The rule is the same rule, because it
//! is a property of submitting bytes to somebody rather than of a protocol — **only an
//! answer the service gave BEFORE accepting anything is a definitive negative** — but the
//! statuses it applies to are this service's, and reading them off the other leaf is what
//! a shared implementation would have made easy to get wrong.
//!
//! The `200`-with-an-unreadable-body case is the one worth stating: the service accepted
//! and logged the statement, and this process cannot show it. That is INDETERMINATE, and
//! calling it a failure would send an operator to re-register a record already in the log.

use super::super::capability::RegistrationError;
use super::wire::CAPSULE_ANCHOR_CONTRACT;

/// A fault against this service's contract, typed rather than flattened into a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum CapsuleAnchorFault {
    /// The exchange did not complete.
    Transport { detail: String },
    /// The service read the submission and said no.
    Refused { status: u16 },
    /// The service's rate limiter declined it.
    RateLimited { status: u16 },
    /// A `5xx`.
    ///
    /// Not a definitive negative, for the reason a `503` is not one anywhere: a reverse
    /// proxy answers the same way over an origin that accepted the statement and then took
    /// too long, and nothing in the response tells the two apart.
    Unavailable { status: u16 },
    /// A status this contract does not define for this exchange.
    UnexpectedStatus { status: u16 },
    /// A `200` whose body this reader cannot use.
    ///
    /// The statement is registered — the service said so — and the receipt is lost. Both
    /// halves matter to an operator, and the message says both.
    UnreadableAnswer { detail: &'static str },
}

/// The ONE place a fault of this contract becomes a semantic refusal.
pub(super) fn fault_to_error(fault: CapsuleAnchorFault) -> RegistrationError {
    match fault {
        CapsuleAnchorFault::Refused { status } => RegistrationError::Refused(format!(
            "{CAPSULE_ANCHOR_CONTRACT}: the service answered {status} to the submission",
        )),
        CapsuleAnchorFault::RateLimited { status } => RegistrationError::Throttled(format!(
            "{CAPSULE_ANCHOR_CONTRACT}: the service's rate limiter answered {status} to \
             the submission",
        )),
        CapsuleAnchorFault::Unavailable { status } => RegistrationError::Indeterminate(format!(
            "{CAPSULE_ANCHOR_CONTRACT}: the submission was answered {status}. That is most \
             likely an unavailable service and therefore no registration, but a reverse \
             proxy answers the same way over an origin that accepted, so it is not shown",
        )),
        CapsuleAnchorFault::Transport { detail } => RegistrationError::Indeterminate(format!(
            "{CAPSULE_ANCHOR_CONTRACT}: the exchange did not complete while submitting the \
             statement ({detail})",
        )),
        CapsuleAnchorFault::UnexpectedStatus { status } => {
            RegistrationError::Indeterminate(format!(
                "{CAPSULE_ANCHOR_CONTRACT}: the submission was answered {status}, which \
                 this contract does not define for it",
            ))
        }
        CapsuleAnchorFault::UnreadableAnswer { detail } => {
            RegistrationError::Indeterminate(format!(
                "{CAPSULE_ANCHOR_CONTRACT}: the service ACCEPTED the statement and its \
                 answer cannot be read ({detail}), so the statement is registered and this \
                 run does not hold the receipt",
            ))
        }
    }
}

/// The status an answer carries, read as a fault. `200` is not a fault and is not here.
pub(super) fn fault_for_status(status: u16) -> CapsuleAnchorFault {
    match status {
        429 => CapsuleAnchorFault::RateLimited { status },
        400..=499 => CapsuleAnchorFault::Refused { status },
        500..=599 => CapsuleAnchorFault::Unavailable { status },
        _ => CapsuleAnchorFault::UnexpectedStatus { status },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only a status the service answered BEFORE accepting anything is definitive.
    #[test]
    fn only_a_pre_acceptance_answer_is_a_definitive_negative() {
        for status in [400, 403, 404, 422] {
            assert!(
                matches!(
                    fault_to_error(fault_for_status(status)),
                    RegistrationError::Refused(_)
                ),
                "{status}",
            );
        }
        assert!(matches!(
            fault_to_error(fault_for_status(429)),
            RegistrationError::Throttled(_)
        ));
        for status in [500, 502, 503, 504] {
            assert!(
                matches!(
                    fault_to_error(fault_for_status(status)),
                    RegistrationError::Indeterminate(_)
                ),
                "{status}: a 5xx may sit over an origin that accepted",
            );
        }
    }

    /// A `200` this reader cannot parse means REGISTERED and no receipt — never "failed".
    #[test]
    fn an_accepted_submission_with_an_unreadable_answer_is_indeterminate_and_says_so() {
        let error = fault_to_error(CapsuleAnchorFault::UnreadableAnswer {
            detail: "the answer is not the JSON this contract defines",
        });
        assert!(matches!(error, RegistrationError::Indeterminate(_)));
        let text = error.to_string();
        assert!(text.contains("ACCEPTED"), "{text}");
        assert!(text.contains("may be registered"), "{text}");
    }

    /// A transport failure while submitting leaves the outcome unknown.
    #[test]
    fn a_transport_failure_is_not_a_failure_to_register() {
        let error = fault_to_error(CapsuleAnchorFault::Transport {
            detail: "connection reset".to_owned(),
        });
        assert!(matches!(error, RegistrationError::Indeterminate(_)));
    }

    /// A status outside every defined band is unknown, not a refusal.
    #[test]
    fn an_undefined_status_is_unknown_rather_than_a_refusal() {
        for status in [100, 201, 202, 204, 302, 600] {
            assert!(
                matches!(
                    fault_to_error(fault_for_status(status)),
                    RegistrationError::Indeterminate(_)
                ),
                "{status}",
            );
        }
    }
}
