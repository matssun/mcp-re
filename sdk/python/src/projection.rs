// SPDX-License-Identifier: Apache-2.0
//! The binding's verdict projection.
//!
//! `verify_response` hands the core's verified outcome to the Python layer field for field.
//! The execution contract travels as the receipt stated it: a member the receipt did not
//! state stays absent, because collapsing silence into "not executed" is the read that
//! makes a post-dispatch refusal look retry-safe.

use mcp_re_client_core::DelegatedOutcome;
use mcp_re_client_core::ExecutionContract;

use crate::PyVerifyResult;

/// The result a caller sees for one verified delegated response.
///
/// `evidence_bound` is whether a rejection receipt is bound to the request this client sent;
/// a success is bound by construction. `request_state` and the evidence digest are read from
/// the verified response by the caller of this function.
pub(crate) fn project_verdict(
    server_keyid: &str,
    outcome: &DelegatedOutcome,
    evidence_bound: bool,
    resp_evidence_digest_alg: &str,
    resp_evidence_digest_value: &str,
    request_state: Option<String>,
) -> PyVerifyResult {
    let (outcome, wire_code, bound, execution) = match outcome {
        DelegatedOutcome::Success => (
            "success".to_owned(),
            None,
            true,
            ExecutionContract::default(),
        ),
        DelegatedOutcome::Rejection {
            wire_code,
            execution,
        } => (
            "rejection".to_owned(),
            wire_code.clone(),
            evidence_bound,
            execution.clone(),
        ),
    };
    PyVerifyResult {
        ok: true,
        server_keyid: server_keyid.to_owned(),
        outcome,
        wire_code,
        bound,
        execution_status: execution.execution_status,
        retry_safety: execution.retry_safety,
        continuation_status: execution.continuation_status,
        retention_status: execution.retention_status,
        resp_evidence_digest_alg: resp_evidence_digest_alg.to_owned(),
        resp_evidence_digest_value: resp_evidence_digest_value.to_owned(),
        request_state,
    }
}

#[cfg(test)]
mod tests {
    use super::project_verdict;
    use mcp_re_client_core::DelegatedOutcome;
    use mcp_re_client_core::ExecutionContract;

    fn rejection(execution: ExecutionContract) -> DelegatedOutcome {
        DelegatedOutcome::Rejection {
            wire_code: Some("mcp-re.replay_detected".to_owned()),
            execution,
        }
    }

    #[test]
    fn an_absent_execution_member_stays_absent_in_the_projection() {
        let stated = ExecutionContract {
            execution_status: Some("executed".to_owned()),
            retry_safety: None,
            continuation_status: None,
            retention_status: Some("failed".to_owned()),
        };
        let out = project_verdict("k", &rejection(stated), true, "sha256", "d", None);
        assert_eq!(out.execution_status.as_deref(), Some("executed"));
        assert_eq!(out.retention_status.as_deref(), Some("failed"));
        assert_eq!(out.retry_safety, None);
        assert_eq!(out.continuation_status, None);
        let silent = project_verdict(
            "k",
            &rejection(ExecutionContract::default()),
            true,
            "sha256",
            "d",
            None,
        );
        assert_eq!(silent.execution_status, None);
        assert_eq!(silent.retry_safety, None);
        assert_eq!(silent.continuation_status, None);
        assert_eq!(silent.retention_status, None);
    }

    #[test]
    fn a_rejection_is_not_reported_as_a_success() {
        let out = project_verdict(
            "k",
            &rejection(ExecutionContract::default()),
            false,
            "sha256",
            "d",
            None,
        );
        assert_eq!(out.outcome, "rejection");
        assert_eq!(out.wire_code.as_deref(), Some("mcp-re.replay_detected"));
        assert!(!out.bound, "an unbound rejection is reported unbound");
        let success = project_verdict(
            "k",
            &DelegatedOutcome::Success,
            false,
            "sha256",
            "d",
            Some("s".to_owned()),
        );
        assert_eq!(success.outcome, "success");
        assert_eq!(success.wire_code, None);
        assert!(success.bound);
        assert_eq!(success.request_state.as_deref(), Some("s"));
        assert_eq!(success.resp_evidence_digest_alg, "sha256");
        assert_eq!(success.resp_evidence_digest_value, "d");
        assert_eq!(success.server_keyid, "k");
    }
}
