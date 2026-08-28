// SPDX-License-Identifier: Apache-2.0
//! What a verified rejection receipt says about whether the work ran, and what the client
//! may safely do next (ADR-MCPRE-058 §10).
//!
//! One fact: **a refusal is not an answer to "did anything happen"** — the receipt states
//! that separately, and the client must be able to tell *the server said no* from *the
//! server said nothing*.
//!
//! Every distinction here exists to stop a caller collapsing one into another at the one
//! place it decides whether to retry:
//!
//! * [`ExecutionStatus::Unstated`] is not [`ExecutionStatus::NotExecuted`]. A receipt that
//!   says nothing leaves the question open; reading silence as "it did not run" is how a
//!   side effect gets repeated.
//! * a spent approval is not a failed one. Retrying an exchange whose elicitation was
//!   consumed passes replay admission on a fresh nonce and then fails with nothing left to
//!   answer — a new elicitation is the remedy, and only the contract can say so.
//! * a failed retention obligation means the audit store has no record of a call that may
//!   have run. That is a statement about the DEPLOYMENT, and it survives beside whatever
//!   the execution status says.
//!
//! The wire code and the contract are read in ONE parse, by [`rejection_receipt`], because
//! they are one object: a caller must never see the code without the disposition beside it.
//! Both are read only AFTER verification — the content-digest covered these bytes, so what
//! comes back is what the server signed.

use serde_json::Value;

/// Whether the refused work had already reached the backend, as the server states it
/// in the verified rejection body (ADR-MCPRE-058 §10 `execution_status`).
///
/// [`Unstated`](ExecutionStatus::Unstated) is NOT
/// [`NotExecuted`](ExecutionStatus::NotExecuted). A receipt that says nothing leaves
/// the question open, and collapsing the two here would turn "unknown whether it ran"
/// into "it did not run" at the one place a caller decides whether to retry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionStatus {
    /// The receipt carries no `execution_status`. Nothing is known from it.
    Unstated,
    /// The server states the work did not reach the backend.
    NotExecuted,
    /// The server states the work may already have run.
    PossiblyExecuted,
    /// A token this client does not recognize. Never resolved to either of the two
    /// known states: an unknown disposition is not evidence that nothing ran.
    Unrecognized(String),
}

/// What a retry of the refused request would cost, as the server states it
/// (ADR-MCPRE-058 §10 `retry_safety`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetrySafety {
    /// The receipt carries no `retry_safety`. The server made no statement; a caller
    /// that needs one must not read this as permission to retry.
    Unstated,
    /// The work may already have run. A blind retry re-executes it — the caller must
    /// reconcile against the backend first.
    UnsafeWithoutReconciliation,
    /// The work did not run, but the human approval that authorized it is gone. A
    /// retry cannot recover it; a new elicitation is required.
    UnsafeWithoutNewElicitation,
    /// A token this client does not recognize. Treated as a statement that was made
    /// and not understood — never as its absence, and never as "safe".
    Unrecognized(String),
}

/// The execution / retry contract a server derives from its exchange machine and signs
/// into every rejection body (ADR-MCPRE-058 §10, SL-10), read back on the client.
///
/// The raw tokens are kept verbatim so a caller can log exactly what the peer said; the
/// accessors classify them without ever inventing a state the receipt did not carry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecutionContract {
    /// `error.data.mcp_re_error.execution_status`, verbatim.
    pub execution_status: Option<String>,
    /// `error.data.mcp_re_error.retry_safety`, verbatim.
    pub retry_safety: Option<String>,
    /// `error.data.mcp_re_error.continuation_status`, verbatim.
    pub continuation_status: Option<String>,
    /// `error.data.mcp_re_error.retention_status`, verbatim.
    pub retention_status: Option<String>,
}

impl ExecutionContract {
    /// Whether the receipt stated any part of the contract at all.
    pub fn is_stated(&self) -> bool {
        self.execution_status.is_some()
            || self.retry_safety.is_some()
            || self.continuation_status.is_some()
            || self.retention_status.is_some()
    }

    /// The classified `execution_status`.
    pub fn execution(&self) -> ExecutionStatus {
        match self.execution_status.as_deref() {
            None => ExecutionStatus::Unstated,
            Some("not_executed") => ExecutionStatus::NotExecuted,
            Some("possibly_executed") => ExecutionStatus::PossiblyExecuted,
            Some(other) => ExecutionStatus::Unrecognized(other.to_owned()),
        }
    }

    /// The classified `retry_safety`.
    pub fn retry(&self) -> RetrySafety {
        match self.retry_safety.as_deref() {
            None => RetrySafety::Unstated,
            Some("unsafe_without_reconciliation") => RetrySafety::UnsafeWithoutReconciliation,
            Some("unsafe_without_new_elicitation") => RetrySafety::UnsafeWithoutNewElicitation,
            Some(other) => RetrySafety::Unrecognized(other.to_owned()),
        }
    }

    /// Whether a blind retry is refused by this receipt: the server stated a retry
    /// hazard, or stated the work may already have run.
    ///
    /// A receipt that states NOTHING returns `false` — this reports what the server
    /// said, and a caller that needs the difference between "stated safe" and "said
    /// nothing" reads [`is_stated`](Self::is_stated) alongside it. There is no token
    /// for "safe to retry": the contract only ever names hazards.
    pub fn retry_is_refused(&self) -> bool {
        !matches!(self.retry(), RetrySafety::Unstated)
            || matches!(self.execution(), ExecutionStatus::PossiblyExecuted)
    }

    /// Whether the exchange consumed a continuation (a human approval) that a retry
    /// cannot recover.
    pub fn continuation_consumed(&self) -> bool {
        self.continuation_status.as_deref() == Some("consumed")
    }

    /// Whether the server states its evidence-retention obligation failed for this
    /// exchange — the audit store has no record of a call that may have run.
    pub fn retention_failed(&self) -> bool {
        self.retention_status.as_deref() == Some("failed")
    }
}

/// The server's frozen wire code and its ADR-MCPRE-058 §10 execution/retry contract,
/// from a (verified) rejection-receipt body's `error.data.mcp_re_error`.
///
/// Read ONLY after verification: the content-digest covered these bytes, so what comes
/// back is what the server signed. One parse for both, because they are one object and
/// a caller must never see the wire code without the disposition beside it.
pub(crate) fn rejection_receipt(body: &[u8]) -> (Option<String>, ExecutionContract) {
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return (None, ExecutionContract::default());
    };
    let Some(error) = value.pointer("/error/data/mcp_re_error") else {
        return (None, ExecutionContract::default());
    };
    let field = |name: &str| error.get(name).and_then(Value::as_str).map(str::to_owned);
    (
        field("wire_code"),
        ExecutionContract {
            execution_status: field("execution_status"),
            retry_safety: field("retry_safety"),
            continuation_status: field("continuation_status"),
            retention_status: field("retention_status"),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_receipt_that_says_nothing_is_not_a_receipt_that_says_it_did_not_run() {
        // The distinction the whole module exists to hold. A caller reading silence as
        // "it did not run" retries a side effect that may already have happened, at the
        // one place it decides whether to retry.
        let silent = ExecutionContract::default();
        assert_eq!(silent.execution(), ExecutionStatus::Unstated);
        assert_ne!(silent.execution(), ExecutionStatus::NotExecuted);
        assert!(!silent.is_stated());
    }

    #[test]
    fn an_unrecognized_value_is_carried_and_never_read_as_a_known_one() {
        // A server on a newer vocabulary must not have its statement silently downgraded
        // to the most convenient known value. `Unrecognized` keeps the string so a caller
        // fails closed on something it can name.
        let future = ExecutionContract {
            execution_status: Some("quantum_superposition".to_owned()),
            ..ExecutionContract::default()
        };
        assert_eq!(
            future.execution(),
            ExecutionStatus::Unrecognized("quantum_superposition".to_owned())
        );
        assert!(future.is_stated(), "the server did state something");
    }

    #[test]
    fn the_wire_code_and_its_disposition_are_read_in_one_parse() {
        // One object, one parse: a caller must never see the code without the disposition
        // beside it, because the code alone does not say whether the work ran.
        let body = br#"{"error":{"data":{"mcp_re_error":{
            "wire_code":"mcp-re.evidence_retention_indeterminate",
            "execution_status":"possibly_executed",
            "retry_safety":"unsafe_without_reconciliation",
            "retention_status":"failed"}}}}"#;
        let (wire_code, contract) = rejection_receipt(body);
        assert_eq!(
            wire_code.as_deref(),
            Some("mcp-re.evidence_retention_indeterminate")
        );
        assert_eq!(contract.execution(), ExecutionStatus::PossiblyExecuted);
        assert_eq!(contract.retry(), RetrySafety::UnsafeWithoutReconciliation);
        assert!(
            contract.retention_failed(),
            "the audit store has no record of a call that may have run — a statement about \
             the DEPLOYMENT, and it survives beside the execution status"
        );
    }

    #[test]
    fn a_body_carrying_no_contract_yields_the_silent_one_rather_than_a_guess() {
        // An unparseable or contract-free body is not evidence that nothing ran.
        assert_eq!(
            rejection_receipt(b"not json").1,
            ExecutionContract::default()
        );
        assert_eq!(
            rejection_receipt(br#"{"error":{}}"#).1,
            ExecutionContract::default()
        );
    }
}
