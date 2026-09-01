// SPDX-License-Identifier: Apache-2.0
//! WHAT THE BOUNDARY KNOWS about a refused exchange's effects, and the contract it projects.
//!
//! A different authority from [`super::rejection`], which owns how a rejection body is
//! assembled, signed and verified. This one owns a smaller and sharper fact: given what the
//! request machine established and which frozen token was minted, what may a client safely
//! do next. The split is the invalidation boundary — changing how a body is framed cannot
//! change what a refusal claims about execution, and adding a consequence the machine can
//! derive cannot change a byte of the envelope.
//!
//! There is exactly ONE projection and it lives here, because the unsigned last-resort
//! receipt is built in another crate and must state the same thing. A second projection
//! over the same two inputs is a second authority, and the two drifted before: the copy
//! took only the disposition, so it could not express the wire-code-dependent retention
//! case at all.

use serde_json::json;
use serde_json::Value;

/// What the enforcement boundary knows about the refused exchange's effects.
///
/// The wire code alone cannot answer this. `evidence_retention_unavailable` at the
/// pre-dispatch reservation is retry-safe when the exchange carries no continuation, and is
/// NOT retry-safe when it already retired one — same code, same status, opposite advice.
/// The difference lives in the request machine's cross-machine state
/// (ADR-MCPRE-057 §4), so it is supplied here rather than guessed from the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExecutionDisposition {
    /// Nothing is asserted beyond what the wire code itself implies. The historical
    /// behaviour, and what every caller that has no request machine to consult supplies.
    #[default]
    Unstated,
    /// The backend never acted and no approval was spent. An ordinary retry is correct.
    NothingExecuted,
    /// The backend never acted, but the approval authorizing it was already consumed.
    /// A retry passes replay admission on a fresh nonce and then fails as
    /// already-answered — the action needs a new human elicitation, not a retry.
    ApprovalSpentNothingExecuted,
    /// The exchange crossed the execution threshold: the backend may have acted, and
    /// whatever failed afterwards cannot unmake that (ADR-MCPRE-058 §10, ruling D1).
    ///
    /// The GENERIC post-dispatch statement, and it is generic on purpose. Before it, only
    /// two post-dispatch failures said anything at all: `evidence_retention_indeterminate`,
    /// which `retry_semantics` special-cased by name, and the approval case above, which is
    /// a PRE-dispatch fact. Everything else — an illegal upstream response, a signing
    /// failure, a continuation-record failure at **HTTP 503**, a 202 that could not be
    /// signed — returned a bare status after the tool had already run, and 503 is the status
    /// clients retry.
    ///
    /// Not a reuse of [`ApprovalSpentNothingExecuted`](Self::ApprovalSpentNothingExecuted):
    /// that token means an approval was destroyed and a NEW elicitation is required, which
    /// is a different remedy and, in the ordinary case, simply false here.
    PossiblyExecuted,
    /// The backend never acted — and the deployment's own record of the attempt could
    /// neither be established nor withdrawn (#741, R9-C099).
    ///
    /// A pre-dispatch fact, like [`ApprovalSpentNothingExecuted`](Self::ApprovalSpentNothingExecuted),
    /// and it exists for the same reason that one does: the wire code and the status are
    /// the ordinary retention-unavailable pair, and the advice is the opposite. The
    /// difference lives in what the retained-evidence store established about its own
    /// withdrawal, which no token carries.
    ///
    /// Not rounded to either neighbour. [`PossiblyExecuted`](Self::PossiblyExecuted) would
    /// collapse *did not run* into *unknown whether it ran*, inventing an indeterminacy
    /// that provably did not occur; [`NothingExecuted`](Self::NothingExecuted) would send a
    /// client into a free retry while the deployment holds an artefact that reads as a
    /// crossed execution threshold and cannot account for it.
    NothingExecutedRetentionUnresolved,
}

/// Explicit machine-readable execution/retry state, for the cases where the safe action is
/// not inferable from the HTTP status.
///
/// Two sources, and both are needed. The wire code carries the post-execution case, where
/// the code alone is decisive. The disposition carries the pre-execution case, where it is
/// not: the SAME code at the SAME status is retry-safe or not depending on whether the
/// exchange had already spent a continuation, and only the request machine knows that.
///
/// A disposition of [`ExecutionDisposition::Unstated`] adds nothing, so every caller
/// without a request machine — and every frozen conformance vector — produces exactly the
/// bytes it produced before.
///
/// **The canonical projection, and the only one.** It is public because the unsigned
/// last-resort receipt is built in another crate and must state the same thing: a second
/// projection over the same two inputs is a second authority, and the two drifted before —
/// the copy took only the disposition, so it could not express the wire-code-dependent
/// retention case at all. Adding a wrapper to keep this private would recreate exactly that.
pub fn retry_semantics(wire_code: &str, execution: ExecutionDisposition) -> Option<Value> {
    if execution == ExecutionDisposition::ApprovalSpentNothingExecuted {
        // The action did NOT run, so this is not the indeterminate case — but the human
        // approval that authorized it is gone, and an ordinary retry cannot recover it.
        // Saying only "503, try again" sends the client into a retry that passes replay
        // admission on a fresh nonce and then fails as already-answered, with the approval
        // already destroyed.
        return Some(json!({
            "execution_status": "not_executed",
            "continuation_status": "consumed",
            "retry_safety": "unsafe_without_new_elicitation",
        }));
    }
    if execution == ExecutionDisposition::NothingExecutedRetentionUnresolved {
        // Both halves stated, neither rounded to the other. The action did not run, and
        // the store may still hold something that reads as a crossed execution threshold
        // for this exchange — so the hazard is named without lying about execution.
        return Some(json!({
            "execution_status": "not_executed",
            "retention_status": "unresolved",
            "retry_safety": "unsafe_without_reconciliation",
        }));
    }
    if wire_code == mcp_re_core::McpReError::EvidenceRetentionIndeterminate.wire_code() {
        // The backend ran; only the evidence write failed. A client that treats this
        // as an ordinary outage and retries re-executes the action, and the retry's
        // fresh nonce passes replay admission — so the state is stated rather than
        // left to be guessed from a status code.
        //
        // Kept ahead of the generic arm because it says one thing more: WHICH obligation
        // failed. The extra field is the difference between "reconcile" and "reconcile,
        // and know the evidence store has no record of this call".
        return Some(json!({
            "execution_status": "possibly_executed",
            "retention_status": "failed",
            "retry_safety": "unsafe_without_reconciliation",
        }));
    }
    if execution == ExecutionDisposition::PossiblyExecuted {
        // Every other failure below the execution threshold. Derived from the exchange
        // machine, not from an allowlist of wire codes: an allowlist is a thing a NEW
        // post-dispatch exit silently fails to be on, which is exactly how the
        // continuation-record failure ended up returning a bare 503 after the tool ran.
        return Some(json!({
            "execution_status": "possibly_executed",
            "retry_safety": "unsafe_without_reconciliation",
        }));
    }
    None
}
