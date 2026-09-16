// SPDX-License-Identifier: Apache-2.0
//! Which half of an exchange an audit event describes.
//!
//! A PROJECTION of the frozen vocabulary, and not a new audit token. Core already owns the
//! fact — it is spread across [`SUCCESS_EVENT_TYPES`](super::SUCCESS_EVENT_TYPES),
//! [`REJECTION_EVENT_TYPES`](super::REJECTION_EVENT_TYPES) and
//! [`KEY_LIFECYCLE_EVENT_TYPES`](super::KEY_LIFECYCLE_EVENT_TYPES) — and answering the
//! question here is what stops a consumer re-deriving it from a second list of its own.
//!
//! The consumer this exists for is `mcp-re-proxy`'s audit record, whose `Request` arm
//! carries an authorization facet and whose `Response` arm does not. That arm and the
//! event's own half were two representations of one fact, and they could disagree: a
//! request-shaped subject built around a response-half event was a legal inhabitant.
//! Nothing in the proxy may restate this mapping — see ADR-MCPS-035 and R11-161.

use super::event_type;
use super::AuditEvent;

/// Which half of one exchange an event describes, or neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditHalf {
    /// About the REQUEST: it was accepted, or it was rejected.
    Request,
    /// About the RESPONSE: it was signed, or it was rejected.
    Response,
    /// About no exchange at all.
    ///
    /// The delegated-key lifecycle events are emitted by the custody layer at issuance,
    /// rotation and retirement rather than by a verification outcome, so they describe
    /// neither half. The variant exists because that category exists; if ADR-MCPRE-052 §7
    /// ever withdraws it, this goes with it rather than staying as a resting place for
    /// whatever is unmapped.
    NonExchange,
}

impl AuditEvent {
    /// Which half of the exchange this event describes.
    ///
    /// Derived from the `event_type` the frozen allowlists pin, so a consumer asks Core
    /// rather than keeping its own copy of the mapping.
    ///
    /// **The catch-all is safe only because a control makes it so.** `event_type` is a
    /// `&'static str`, so the compiler cannot check this match for exhaustiveness and a
    /// newly minted event would fall silently into `NonExchange`. That is the failure mode
    /// this is designed against, not one it accepts:
    /// `every_pinned_event_type_is_given_a_half` walks all three allowlists and fails the
    /// battery if any member lands in the catch-all.
    #[must_use]
    pub fn half(&self) -> AuditHalf {
        match self.event_type {
            event_type::REQUEST_ACCEPTED | event_type::REQUEST_REJECTED => AuditHalf::Request,
            event_type::RESPONSE_SIGNED | event_type::RESPONSE_REJECTED => AuditHalf::Response,
            _ => AuditHalf::NonExchange,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::McpReError;

    fn of(event_type: &'static str) -> AuditEvent {
        AuditEvent {
            event_type,
            decision: super::super::Decision::Accepted,
            reason: None,
            reason_label: None,
        }
    }

    /// **The control the catch-all rests on.** Every event type the drift guard pins is
    /// given a half deliberately, and the key-lifecycle set is the ONLY one that may reach
    /// `NonExchange`.
    ///
    /// Without this, adding a fifth exchange event to an allowlist and forgetting this file
    /// would make it `NonExchange` — silently, and in the direction that reads as "this is
    /// about no exchange" rather than as an error. The failure mode of a stale mapping is a
    /// clean pass over a wrong answer.
    #[test]
    fn every_pinned_event_type_is_given_a_half() {
        for t in super::super::SUCCESS_EVENT_TYPES
            .iter()
            .chain(super::super::REJECTION_EVENT_TYPES)
        {
            assert_ne!(
                of(t).half(),
                AuditHalf::NonExchange,
                "{t} is an exchange event and must name the half it describes"
            );
        }
        for t in super::super::KEY_LIFECYCLE_EVENT_TYPES {
            assert_eq!(
                of(t).half(),
                AuditHalf::NonExchange,
                "{t} is emitted by the custody layer and describes neither half"
            );
        }
    }

    /// The halves are read off the real constructors, not off hand-written strings — a
    /// constructor that started emitting another `event_type` must move this control.
    #[test]
    fn the_constructors_land_on_the_half_their_names_claim() {
        assert_eq!(AuditEvent::request_accepted().half(), AuditHalf::Request);
        assert_eq!(
            AuditEvent::request_rejected(&McpReError::ReplayDetected).half(),
            AuditHalf::Request
        );
        assert_eq!(AuditEvent::response_signed().half(), AuditHalf::Response);
        assert_eq!(
            AuditEvent::response_rejected(&McpReError::ReplayDetected).half(),
            AuditHalf::Response
        );
    }

    /// The three halves are three values. A derive that made two compare equal would let a
    /// consumer reach the wrong arm without the compiler or this battery noticing.
    #[test]
    fn the_three_halves_are_distinguishable() {
        let all = [
            AuditHalf::Request,
            AuditHalf::Response,
            AuditHalf::NonExchange,
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                assert_eq!(i == j, a == b, "{a:?} vs {b:?}");
            }
        }
    }
}
