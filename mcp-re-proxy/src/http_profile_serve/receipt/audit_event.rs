// SPDX-License-Identifier: Apache-2.0
//! Which security record a refusal is.
//!
//! ADR-MCPS-035 §9 freezes the taxonomy, and the split it draws is not cosmetic: a
//! `request.rejected` for an exchange that already emitted `accepted` would contradict the
//! earlier record and attribute a backend fault to the caller. The choice therefore belongs
//! to one owner, decided from the refusal's posture rather than from which branch of the
//! assembly happened to be taken.

use std::sync::Arc;

use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::RequestEvidence;

use crate::audit_sink::MaybeAuditSink;
use crate::refusal::RefusalCause;
use mcp_re_http_profile::ExecutionDisposition;

use super::super::ServedHttpResponse;
use super::ResponseSigning;

impl ResponseSigning {
    /// A PRE-ACCEPTANCE rejection — recorded as `mcp-re.request.rejected`.
    ///
    /// Used by every exit that runs BEFORE the `mcp-re.request.accepted` record is
    /// emitted, so `accepted` and `request.rejected` stay mutually exclusive per
    /// request (ADR-MCPS-035). `wire_code` is already the frozen token; the record
    /// carries it verbatim, never a parallel sub-name.
    ///
    /// `actor_id` is the VERIFIER-RESOLVED actor when one was established before this
    /// exit, and `None` when the request was refused before resolution — the
    /// distinction `AuditRecord` documents, and the reason a denial that carries
    /// attribution must not discard it.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn rejection(
        &self,
        audit: &MaybeAuditSink,
        request: &HttpRequest,
        cause: &RefusalCause,
        status: u16,
        now: i64,
        bound: Option<&RequestEvidence>,
        actor_id: Option<String>,
        execution: ExecutionDisposition,
        snapshot: Option<Arc<mcp_re_http_profile::ActiveDelegatedKey>>,
    ) -> ServedHttpResponse {
        crate::audit_record::record_to(
            audit,
            crate::audit_record::AuditSubject::request(
                match cause.core_verdict() {
                    Some(e) => mcp_re_core::audit::AuditEvent::request_rejected(&e),
                    // Core reached no verdict: a policy did. Its token belongs in the
                    // authorization coordinate below, never in Core's `reason`.
                    None => mcp_re_core::audit::AuditEvent::request_rejected_elsewhere(),
                },
                cause.authorization_facet(),
            ),
            actor_id,
            status,
            now,
        );
        self.signed_rejection(
            request,
            cause.wire_code(),
            status,
            now,
            bound,
            execution,
            snapshot,
        )
    }
    /// A POST-ACCEPTANCE rejection — recorded as `mcp-re.response.rejected`.
    ///
    /// The request was admitted (an `accepted` record already names it) and the fault
    /// is on the RESPONSE side: the forwarded body, the backend's reply class, the
    /// response signature, or recording the continuation that makes the reply
    /// answerable. Emitting `request.rejected` here would contradict the `accepted`
    /// record for the same request and attribute a backend fault to the caller;
    /// `mcp-re.response.rejected` is the frozen token the §9 taxonomy splits out for
    /// exactly this.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn response_rejection(
        &self,
        audit: &MaybeAuditSink,
        request: &HttpRequest,
        cause: &RefusalCause,
        status: u16,
        now: i64,
        bound: Option<&RequestEvidence>,
        actor_id: Option<String>,
        execution: ExecutionDisposition,
        snapshot: Option<Arc<mcp_re_http_profile::ActiveDelegatedKey>>,
    ) -> ServedHttpResponse {
        crate::audit_record::record_to(
            audit,
            crate::audit_record::AuditSubject::response(match cause.core_verdict() {
                Some(e) => mcp_re_core::audit::AuditEvent::response_rejected(&e),
                None => mcp_re_core::audit::AuditEvent::response_rejected_elsewhere(),
            }),
            actor_id,
            status,
            now,
        );
        self.signed_rejection(
            request,
            cause.wire_code(),
            status,
            now,
            bound,
            execution,
            snapshot,
        )
    }
}
