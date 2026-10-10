// SPDX-License-Identifier: Apache-2.0
//! Which refusal a failed pre-dispatch retention step earns.

use mcp_re_core::McpReError;
use mcp_re_http_profile::rejection::ExecutionDisposition;

use super::fault_report;
use super::fault_report::Fault;
use crate::refusal::Refusal;
use crate::transparency::RetentionError;

/// What a PRE-DISPATCH retention fault is answered with.
///
/// One place, because it is one decision: could a retry succeed, and is the store's record
/// of this exchange statable? 503 says keep trying and is right for a full queue — the permit
/// scheme's whole argument is that refusing at the ceiling is free and retry-safe. It is
/// wrong for the other two, and for different reasons: a retired writer accepts nothing again
/// until this replica restarts, and an unresolved crossing leaves something on disk that may
/// read as a threshold an exchange never crossed (R9-C099), so it carries the disposition
/// that says so.
pub(super) fn pre_dispatch(error: &RetentionError, attempted: &str) -> Refusal {
    let unavailable = |status| Refusal::new(McpReError::EvidenceRetentionUnavailable, status);
    let (fault, refusal) = match error {
        RetentionError::Unresolved(_) => (
            Fault::Unresolved,
            unavailable(500).refining(ExecutionDisposition::NothingExecutedRetentionUnresolved),
        ),
        RetentionError::StoreRetired(_) => (Fault::Retired, unavailable(500)),
        RetentionError::Store(_) => (Fault::Backpressure, unavailable(503)),
        RetentionError::Malformed(_) | RetentionError::AlreadyCompleted => {
            (Fault::Unusable, unavailable(500))
        }
    };
    fault_report::report(fault, attempted, error);
    refusal
}

#[cfg(test)]
mod tests {
    use super::*;

    fn io(kind: std::io::ErrorKind) -> std::io::Error {
        std::io::Error::new(kind, "fixture")
    }

    /// The three pre-dispatch faults are three answers, and the module's whole argument is
    /// that they are not one.
    ///
    /// Before this the file had exactly ONE control — the negative, that a deployment
    /// retaining nothing owes nothing — so every failing branch of the refusal was
    /// unmeasured. A `503` for all three would have satisfied the battery while telling a
    /// client to keep retrying a replica that will never accept another write, and while
    /// dropping the disposition that says an unresolved crossing may be on disk.
    #[test]
    fn each_pre_dispatch_fault_earns_its_own_answer() {
        // Backpressure: retry, and the permit scheme's argument is that refusing here is
        // free.
        let full = pre_dispatch(
            &RetentionError::Store(io(std::io::ErrorKind::WouldBlock)),
            "accept the exchange",
        );
        assert_eq!(full.status, 503);
        assert!(full.execution_refinement.is_none());

        // A retired writer accepts nothing again until this replica restarts, so 503 —
        // the status clients retry — is the wrong thing to say.
        let retired = pre_dispatch(
            &RetentionError::StoreRetired(io(std::io::ErrorKind::BrokenPipe)),
            "accept the exchange",
        );
        assert_eq!(retired.status, 500);
        assert!(retired.execution_refinement.is_none());

        // An unresolved crossing leaves something on disk that may read as a threshold the
        // exchange never crossed (R9-C099), and the refusal has to CARRY that.
        let unresolved = pre_dispatch(
            &RetentionError::Unresolved(io(std::io::ErrorKind::Other)),
            "record the crossing",
        );
        assert_eq!(unresolved.status, 500);
        assert_eq!(
            unresolved.execution_refinement,
            Some(ExecutionDisposition::NothingExecutedRetentionUnresolved)
        );

        // A record this exchange cannot form will not form on retry, and a completion
        // already taken is not a pre-dispatch state: both fail closed.
        for unusable in [
            RetentionError::Malformed("fixture"),
            RetentionError::AlreadyCompleted,
        ] {
            let refusal = pre_dispatch(&unusable, "accept the exchange");
            assert_eq!(refusal.status, 500);
            assert!(refusal.execution_refinement.is_none());
        }
    }

    /// Every pre-dispatch refusal is free, whichever fault produced it.
    ///
    /// All three are served past the accepted record, so they record
    /// `mcp-re.response.rejected`; the backend has NOT run in any of them and a
    /// `request.rejected` would contradict the accepted record for the same request.
    #[test]
    fn no_pre_dispatch_fault_claims_the_backend_ran() {
        for error in [
            RetentionError::Store(io(std::io::ErrorKind::WouldBlock)),
            RetentionError::StoreRetired(io(std::io::ErrorKind::BrokenPipe)),
            RetentionError::Unresolved(io(std::io::ErrorKind::Other)),
            RetentionError::Malformed("fixture"),
            RetentionError::AlreadyCompleted,
        ] {
            let refusal = pre_dispatch(&error, "accept the exchange");
            assert_eq!(
                refusal.cause,
                crate::refusal::RefusalCause::from(McpReError::EvidenceRetentionUnavailable),
                "a pre-dispatch retention fault is UNAVAILABLE, never INDETERMINATE: the \
                 indeterminate code is what `complete` uses once the call has executed"
            );
        }
    }
}
