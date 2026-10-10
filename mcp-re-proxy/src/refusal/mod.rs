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
//! ## Placement, ruled (MCPRE-151, ADR-MCPRE-061 §8 authority C)
//!
//! The refusal vocabulary is a **neutral semantic product owned here**, and it stays here.
//! It was a live question whether it should move under the response-signing receipt
//! authority, which is its largest consumer; the answer is no, and the reason is a
//! separation the receipt owner itself depends on.
//!
//! `receipt::ResponseSigning` consumes a refusal and decides how it is REPRESENTED and
//! SIGNED — which credential, which audit event. It does not own the
//! semantic fact that some other authority refused, and it is not the only consumer:
//! admission, authorization, transport binding, the continuation plane, the inner plane and
//! the retention obligation all name refusals, and none of them signs one. Forcing refusal
//! construction through the signer would make every one of those authorities depend on the
//! response-signing credential in order to say *no*.
//!
//! What DID change is width: constructors and visibility are as narrow as the real producer
//! set permits. That is the part of authority C worth acting on.
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
//! * [`RefusalCause::wire_code`] — the public code, at the final presentation boundary.
//!   Composition, never ownership: `PolicyError` owns the authorization-token mapping and
//!   `McpReError` owns Core's, and neither is reproduced here.
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

use mcp_re_http_profile::rejection::ExecutionDisposition;

mod cause;

pub(crate) use cause::RefusalCause;

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
    /// What the REFUSING OWNER established about effects that the exchange machine has no
    /// representation for.
    ///
    /// `None` is the ordinary case, and the machine's own derivation stands. The one
    /// producer is the retained-evidence store's unresolvable pre-dispatch state: the
    /// backend provably did not act, and the store may still hold an artefact that reads
    /// as a crossed execution threshold — a conjunction no state of the machine encodes,
    /// because the machine does not model the store's withdrawal.
    ///
    /// It REFINES, and can only refine downward in safety: the composition applies it only
    /// where the machine says an ordinary retry would have been correct, so a floor the
    /// machine has already raised is never walked back (`HttpProfileProxy::disposition`).
    pub(crate) execution_refinement: Option<ExecutionDisposition>,
}

impl Refusal {
    /// A stage's decision: WHAT was refused. Which record it becomes is decided by the entry
    /// it is served from (`receipt::RefusalPoint`), never by the stage.
    pub(crate) fn new(cause: impl Into<RefusalCause>, status: u16) -> Self {
        Refusal {
            cause: cause.into(),
            status,
            execution_refinement: None,
        }
    }

    /// The same refusal, carrying what the refusing owner established about effects.
    ///
    /// For an owner that knows something the machine cannot represent. Everything else
    /// leaves it unset and the machine's derivation is the whole answer.
    pub(crate) fn refining(mut self, execution: ExecutionDisposition) -> Self {
        self.execution_refinement = Some(execution);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_re_core::McpReError;

    #[test]
    fn a_refusal_renders_only_at_the_presentation_boundary() {
        // The refusal itself holds no token and no longer offers one: the serving path
        // asks the CAUSE, at the one point that presents a public code. A convenience
        // delegation here would be a second place a token appears to come from.
        let r = Refusal::new(McpReError::ReplayDetected, 409);
        assert_eq!(r.cause.wire_code(), "mcp-re.replay_detected");
    }
}
