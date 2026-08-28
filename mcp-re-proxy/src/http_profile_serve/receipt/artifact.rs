// SPDX-License-Identifier: Apache-2.0
//! How a refusal receipt is built.
//!
//! Signed under the delegated credential when one is available, and never advertising
//! validity past it — [`SigningWindow`] carries that bound. When even the signed receipt
//! cannot be built, the last-resort body still states what the exchange knows about
//! effects, because that claim is the one thing a client cannot infer from what is left.

use std::sync::Arc;

use mcp_re_http_profile::build_delegated_rejection;
use mcp_re_http_profile::build_delegated_rejection_preflight;
use mcp_re_http_profile::ExecutionDisposition;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::RejectionReason;
use mcp_re_http_profile::RequestEvidence;

use super::super::served;
use super::super::signing_window::SigningWindow;
use super::super::ServedHttpResponse;
use super::ResponseSigning;

impl ResponseSigning {
    /// Build a signed rejection receipt bound to `request` (or preflight-unbound),
    /// with the injected `now` for the signature window (fail-closed freshness).
    ///
    /// Signs the rejection with the active delegated key and the inline credential
    /// (ADR-MCPRE-052) — request-bound when `bound` is `Some` (the request verified),
    /// preflight-unbound when `None` (the request never earned a trustworthy hash).
    /// Never root-signed. If no valid delegated key exists, a last-resort UNSIGNED
    /// error is emitted rather than a bogus signature.
    ///
    /// `snapshot` is the key the exchange took at ANSWERABLE, when it had got that far. It
    /// is preferred over re-asking the signer, and that preference is the whole reason it
    /// is threaded here: `current` returns `None` for a retired signer, so a drain or a
    /// failed rotation between ANSWERABLE and a post-dispatch refusal turned the one
    /// receipt that must state "the backend may have acted" into an unsigned body a client
    /// cannot tell from an on-path forgery. The same snapshot signs the successful reply,
    /// so no refusal claims a validity the reply would not have had.
    ///
    /// Carries no audit emission of its own: the two callers above choose the frozen
    /// event type, because which one is correct depends on whether the request had
    /// already been admitted.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn signed_rejection(
        &self,
        request: &HttpRequest,
        wire_code: &'static str,
        status: u16,
        now: i64,
        bound: Option<&RequestEvidence>,
        execution: ExecutionDisposition,
        snapshot: Option<Arc<mcp_re_http_profile::ActiveDelegatedKey>>,
    ) -> ServedHttpResponse {
        let reason = RejectionReason::new(
            wire_code,
            format!("mcp-re http-profile proxy rejected: {wire_code}"),
        )
        .with_execution(execution);
        // The exchange's own snapshot when it reached one, so a refusal signs with the key
        // the reply itself would have used rather than re-asking a signer that may have been
        // retired in between. Either way the window is derived once, by its owner.
        let resp = match snapshot
            .map(|a| SigningWindow::over(a, now, self.sig_ttl_secs))
            .or_else(|| SigningWindow::open(&self.signer, now, self.sig_ttl_secs))
        {
            Some(w) => {
                let (a, expires) = (w.key(), w.expires());
                let built = match bound {
                    Some(ev) => build_delegated_rejection(
                        request,
                        ev,
                        &reason,
                        status,
                        &a.server_signer,
                        &a.credential,
                        a.key.as_ref(),
                        &a.delegated_kid,
                        now,
                        expires,
                    ),
                    None => build_delegated_rejection_preflight(
                        Some(request),
                        &reason,
                        status,
                        &a.server_signer,
                        &a.credential,
                        a.key.as_ref(),
                        &a.delegated_kid,
                        now,
                        expires,
                    ),
                };
                built.unwrap_or_else(|_| unsigned_error(status, wire_code, execution))
            }
            None => unsigned_error(status, wire_code, execution),
        };
        served(resp)
    }
}

/// A last-resort unsigned error body when even the signed rejection cannot be built
/// (a server-key failure). Never a silent allow — an explicit error status.
///
/// It still states what the exchange knows about effects. That claim is the one thing a
/// client cannot infer from what is left: an unsigned 504 with an empty error object reads
/// as an ordinary transport failure, i.e. as did-not-run, on the exits where the proxy
/// knows the backend was dispatched.
fn unsigned_error(status: u16, wire_code: &str, execution: ExecutionDisposition) -> HttpResponse {
    let mut mcp_re_error = serde_json::json!({ "wire_code": wire_code });
    // The SAME projection the signed rejection uses. Both inputs are handed over, so this
    // receipt can state the wire-code-dependent cases — a retention failure the client must
    // reconcile against a store that has no record of the call — and not merely what the
    // disposition alone knows.
    if let Some(claim) = mcp_re_http_profile::retry_semantics(wire_code, execution) {
        if let (Some(target), Some(extra)) = (mcp_re_error.as_object_mut(), claim.as_object()) {
            for (k, v) in extra {
                target.insert(k.clone(), v.clone());
            }
        }
    }
    HttpResponse {
        status,
        headers: vec![("content-type".into(), "application/json".into())],
        body: serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "error": {
                "code": mcp_re_core::MCP_RE_JSON_RPC_ERROR_CODE,
                "message": wire_code,
                "data": { "mcp_re_error": mcp_re_error },
            },
            "id": serde_json::Value::Null,
        }))
        .unwrap_or_default(),
    }
}
/// The last-resort unsigned receipt states what the signed one would have stated.
///
/// This is the exit where a client has least to go on: no signature, no binding, and an
/// error object it would otherwise read as an ordinary transport failure. What it must
/// still carry is the execution claim — and the claim is a function of the wire code as
/// well as the disposition, which is why this receipt consumes the canonical projection
/// rather than a local copy of it.
#[cfg(test)]
mod last_resort_receipt_tests {
    use super::*;

    /// Read the `mcp_re_error` object out of an unsigned last-resort body.
    fn claim(status: u16, wire_code: &str, execution: ExecutionDisposition) -> serde_json::Value {
        let resp = unsigned_error(status, wire_code, execution);
        let body: serde_json::Value =
            serde_json::from_slice(&resp.body).expect("the last-resort body is JSON");
        body["error"]["data"]["mcp_re_error"].clone()
    }

    /// The negative control for the duplicated-authority defect.
    ///
    /// A local projection taking only the disposition CANNOT produce `retention_status`,
    /// because that case is selected by the wire code. Before the duplicate was deleted
    /// this assertion failed on the missing field while every other field passed — the
    /// client was told to reconcile without being told the evidence store has no record of
    /// the call it must reconcile.
    #[test]
    fn a_retention_indeterminate_last_resort_receipt_still_names_the_failed_obligation() {
        let e = claim(
            500,
            mcp_re_core::McpReError::EvidenceRetentionIndeterminate.wire_code(),
            ExecutionDisposition::PossiblyExecuted,
        );
        assert_eq!(e["execution_status"], "possibly_executed");
        assert_eq!(
            e["retention_status"], "failed",
            "the unsigned receipt must state WHICH obligation failed: {e}"
        );
        assert_eq!(e["retry_safety"], "unsafe_without_reconciliation");
    }

    /// The field is selected by the wire code, not added to every possibly-executed exit.
    #[test]
    fn an_ordinary_post_dispatch_failure_claims_no_retention_status() {
        let e = claim(
            502,
            mcp_re_core::McpReError::TrustResolverUnavailable.wire_code(),
            ExecutionDisposition::PossiblyExecuted,
        );
        assert_eq!(e["execution_status"], "possibly_executed");
        assert!(
            e.get("retention_status").is_none(),
            "no retention obligation failed here: {e}"
        );
    }

    /// The spent-approval case is disposition-selected and survives the same path.
    #[test]
    fn a_spent_approval_last_resort_receipt_names_the_consumed_continuation() {
        let e = claim(
            503,
            mcp_re_core::McpReError::ReplayCacheUnavailable.wire_code(),
            ExecutionDisposition::ApprovalSpentNothingExecuted,
        );
        assert_eq!(e["execution_status"], "not_executed");
        assert_eq!(e["continuation_status"], "consumed");
        assert_eq!(e["retry_safety"], "unsafe_without_new_elicitation");
    }

    /// An exchange that states nothing adds nothing: the frozen vectors keep their bytes.
    #[test]
    fn an_unstated_disposition_adds_no_claim() {
        let e = claim(
            400,
            mcp_re_core::McpReError::MalformedEnvelope.wire_code(),
            ExecutionDisposition::Unstated,
        );
        assert_eq!(
            e.as_object().expect("an object").len(),
            1,
            "only the wire code: {e}"
        );
    }
}
