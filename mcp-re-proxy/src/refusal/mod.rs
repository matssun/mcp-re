// SPDX-License-Identifier: Apache-2.0
//! What a stage decided when it refused, and **which authority decided it**.
//!
//! Split from the serving path because they are different facts: the serving path owns the
//! order the stages run in, and this module owns what a refusal *is*. The split is also what
//! ADR-MCPRE-066 Slice 0 needs — the cause has to outlive the stage that produced it, and a
//! type that lives inside the pipeline file tends to be shaped by the pipeline's convenience.
//!
//! ## The defect this module exists to remove
//!
//! `Refusal` used to hold `wire_code: &'static str`. Every stage rendered its typed verdict to
//! a string at the stage boundary, so by the time the serving/audit boundary saw one, which
//! authority had refused was unrecoverable — a Core verification verdict and an authorization
//! policy refusal arrived as the same type, carrying the same kind of value.
//!
//! That single move caused two symptoms ADR-MCPRE-066 measured separately: a foreign taxonomy
//! could reach `AuditEvent.reason` with nothing able to notice, and the authorization facet
//! the ADR needs could not be built at all, because `BeforePolicy` and `ByPolicy` had already
//! been flattened into one string.
//!
//! ## Closed over owners, deliberately
//!
//! [`RefusalCause`] does not hold "the error". It holds *whose* error, and the distinction is
//! the point. Replacing the string with a bare [`McpReError`] would have moved the collapse one
//! level earlier rather than removed it: every stage would then agree on a Core verdict,
//! including the stages that never consulted Core.
//!
//! [`HttpProfileError`] projects into Core because that relationship is a ratified invariant
//! — the conformance guard asserts every one of its `wire_code()` tokens is a frozen Core
//! token. **`PolicyError` has no such projection and may never acquire one**: an
//! authorization refusal must arrive at the audit boundary still recognizably authorization
//! provenance.
//!
//! ## Three projections, three questions
//!
//! * [`RefusalCause::wire_code`] — the public code, at the one presentation boundary.
//! * `RefusalCause::authorization_facet` — what the AUTHORIZATION authority says about this
//!   refusal, the question the pre-rendered string made unanswerable.
//! * `RefusalCause::core_verdict` — which CORE verdict the audit record is written under,
//!   and `None` where Core reached none.
//!
//! The third is what closes ADR-MCPRE-066 invariants 8 and 9. The audit boundary takes an
//! `McpReError`, so a policy denial cannot be written into Core's `reason` by any route: it
//! has nothing of that type to offer, and Core records the rejection with no reason of its
//! own while the authorization coordinate says who refused. The producer graph stopped
//! being something a scanner discovers and became something the compiler decides.

mod cause;

pub(crate) use cause::RefusalCause;

/// How a refusal must be signed and recorded.
///
/// Not a detail of presentation: each posture is a different claim. Preflight says no
/// trustworthy request hash exists; the other two say one does, and differ on whether the
/// request had already been ADMITTED — which decides whether the fault is attributed to the
/// caller or to the response side (ADR-MCPS-035 §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefusalPosture {
    /// The request never verified. Signed response-only, no actor to attribute it to.
    Preflight,
    /// The request verified but was not yet admitted. Bound via `;req`, recorded as
    /// `mcp-re.request.rejected`.
    BeforeAdmission,
    /// The request was admitted, so the fault is on the response side. Bound, recorded as
    /// `mcp-re.response.rejected` — a `request.rejected` here would contradict the
    /// `accepted` record already emitted for the same request.
    AfterAdmission,
}

/// What a stage DECIDED, before anything is signed.
///
/// A stage names its refusal; it does not produce one. Two reasons, and the second is the
/// load-bearing one:
///
/// * signing is authority, and the eleven stages have no business exercising it;
/// * a refusal that is a VALUE can be asserted on directly, so a stage's contract can be
///   tested without standing up a signer, a credential, or a clock.
///
/// Note what is absent: the retry contract. A stage cannot state it, because it is a fact
/// about the whole exchange rather than about the step that failed. It is derived once, from
/// the exchange machine, where `HttpProfileProxy::refuse` signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Refusal {
    /// Which authority refused, in its own vocabulary. Not a rendered token.
    pub(crate) cause: RefusalCause,
    pub(crate) status: u16,
    pub(crate) posture: RefusalPosture,
}

impl Refusal {
    /// The request never verified.
    pub(crate) fn preflight(cause: impl Into<RefusalCause>, status: u16) -> Self {
        Refusal {
            cause: cause.into(),
            status,
            posture: RefusalPosture::Preflight,
        }
    }

    /// The request verified but had not been admitted.
    pub(crate) fn before_admission(cause: impl Into<RefusalCause>, status: u16) -> Self {
        Refusal {
            cause: cause.into(),
            status,
            posture: RefusalPosture::BeforeAdmission,
        }
    }

    /// The request was admitted; the fault is on the response side.
    pub(crate) fn after_admission(cause: impl Into<RefusalCause>, status: u16) -> Self {
        Refusal {
            cause: cause.into(),
            status,
            posture: RefusalPosture::AfterAdmission,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_re_core::McpReError;

    #[test]
    fn the_posture_is_independent_of_the_cause() {
        let a = Refusal::preflight(McpReError::MissingEnvelope, 400);
        let b = Refusal::after_admission(McpReError::MissingEnvelope, 500);
        assert_eq!(a.cause, b.cause);
        assert_ne!(a.posture, b.posture);
    }

    #[test]
    fn a_refusal_renders_only_at_the_presentation_boundary() {
        // The refusal itself holds no token and no longer offers one: the serving path
        // asks the CAUSE, at the one point that presents a public code. A convenience
        // delegation here would be a second place a token appears to come from.
        let r = Refusal::before_admission(McpReError::ReplayDetected, 409);
        assert_eq!(r.cause.wire_code(), "mcp-re.replay_detected");
    }
}
