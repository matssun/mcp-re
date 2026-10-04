// SPDX-License-Identifier: Apache-2.0
//! Which security record a refusal is.
//!
//! ADR-MCPS-035 §9 freezes the taxonomy, and the split it draws is not cosmetic: a
//! `request.rejected` for an exchange that already emitted `accepted` would contradict the
//! earlier record and attribute a backend fault to the caller. The choice therefore belongs
//! to one owner, decided by the entry the refusal is served from
//! ([`super::RefusalPoint`]) rather than from which branch of the assembly happened to be
//! taken. Only [`Accepted::record`] mints the response-side entry.

use std::sync::Arc;

use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::RequestEvidence;

use crate::admission_enforcer::AdmissionFacet;
use crate::audit_sink::MaybeAuditSink;
use crate::refusal::RefusalCause;
use mcp_re_http_profile::ExecutionDisposition;

use super::super::pre_admission::AdmittedRequest;
use super::super::Answerable;
use super::super::Exchange;
use super::super::ServedHttpResponse;
use super::ResponseSigning;

/// An exchange whose `mcp-re.request.accepted` record has been emitted; every refusal
/// served through one is `mcp-re.response.rejected` by type.
///
/// The field is private to this module, so [`Accepted::record`] — which emits the record —
/// is the only way to hold one.
pub(in crate::http_profile_serve) struct Accepted<'a> {
    ans: Answerable<'a>,
}

impl<'a> Accepted<'a> {
    /// ADR-MCPS-035: the request is now ADMITTED, and this is the record that says so.
    ///
    /// Emitted here rather than at signature verification so `accepted` and `rejected` are
    /// MUTUALLY EXCLUSIVE per request: a signature-valid request that then loses replay
    /// admission is a rejection, and a record claiming both would make the surface useless
    /// for attribution.
    ///
    /// Every exit AFTER this records `mcp-re.response.rejected` instead — the request was
    /// admitted, so a `request.rejected` record would contradict this one, and the fault is
    /// on the response side anyway.
    pub(in crate::http_profile_serve) fn record(
        audit: &MaybeAuditSink,
        admitted: &AdmittedRequest<'_>,
        ans: Answerable<'a>,
    ) -> Self {
        crate::audit_record::record_to(
            audit,
            // The live product, asked for its own projection. Nothing here reconstructs an
            // authorization fact, and an unconfigured deployment says so rather than reading
            // as an allow (ADR-MCPRE-066 §1.1, invariant 5).
            crate::audit_record::AuditSubject::request_accepted(
                &admitted.authorized,
                // Read back from the exchange, never re-derived from the fact that nothing
                // refused. `None` cannot occur on this path — an accepted request reached
                // the gate — and `NotReached` is the honest reading if it ever did.
                ans.ex
                    .verdicts
                    .admission()
                    .unwrap_or(AdmissionFacet::NotReached),
            ),
            Some(ans.ex.actor_id.to_owned()),
            200,
            ans.ex.now,
        );
        Accepted { ans }
    }

    /// The exchange, lent shared only.
    pub(in crate::http_profile_serve) fn exchange(&self) -> &Exchange<'a> {
        &self.ans.ex
    }

    /// The delegated key snapshotted at ANSWERABLE.
    pub(in crate::http_profile_serve) fn key(
        &self,
    ) -> &Arc<mcp_re_http_profile::ActiveDelegatedKey> {
        &self.ans.key
    }
}

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
        authorization: Option<&crate::authorization::AuthorizationFacet>,
        admission: crate::admission_enforcer::AdmissionFacet,
        admission_refusal: Option<crate::admission_enforcer::AdmissionRefusalClass>,
    ) -> ServedHttpResponse {
        // `None` means Core reached no verdict: a policy did. Its token belongs in the
        // authorization coordinate, never in Core's `reason`.
        let core_verdict = cause.core_verdict();
        let authorization = cause.authorization_facet(authorization);
        let subject = match admission_refusal {
            // The §7 gate refused, and says why: its own coordinate beside the facet.
            Some(class) => crate::audit_record::AuditSubject::request_refused_at_admission(
                core_verdict.as_ref(),
                authorization,
                class,
            ),
            None => crate::audit_record::AuditSubject::request_rejected(
                core_verdict.as_ref(),
                authorization,
                admission,
            ),
        };
        crate::audit_record::record_to(audit, subject, actor_id, status, now);
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
            crate::audit_record::AuditSubject::response_rejected(cause.core_verdict().as_ref()),
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

#[cfg(test)]
mod tests {
    use super::super::RefusalPoint;
    use super::*;
    use crate::authorization::AuthorizationPosture;
    use crate::http_profile_serve::request_admission::tests::validated;
    use crate::refusal::Refusal;
    use mcp_re_core::McpReError;

    fn verified() -> mcp_re_http_profile::VerifiedMcpRequest {
        let audience = mcp_re_http_profile::AudienceTuple {
            audience_id: "aud".into(),
            target_uri: "https://example.test/mcp".into(),
            route: None,
        };
        mcp_re_http_profile::VerifiedMcpRequest {
            floor: mcp_re_http_profile::CryptographicFloorVerifiedRequest {
                profile_id: "p".into(),
                signature_label: "mcpre".into(),
                resolved_actor: mcp_re_http_profile::ResolvedActor {
                    identity: mcp_re_http_profile::ActorIdentity {
                        role: "client".into(),
                        trust_domain: "example.com".into(),
                        subject: "did:example:host-a".into(),
                        keyid: "key-1".into(),
                    },
                    verification_key: mcp_re_core::SigningKey::from_seed_bytes(&[7u8; 32])
                        .public_key(),
                    slot: mcp_re_http_profile::SignerSlot::Request,
                },
                evidence: mcp_re_http_profile::RequestEvidence::from_signature_base(b"base"),
                request_signature_base: b"base".to_vec(),
                content_digest: mcp_re_http_profile::content_digest_sha256(b"{}"),
                created: 1,
                expires: 2,
                nonce: "n".into(),
                key_id: "key-1".into(),
            },
            audience: audience.clone(),
            audience_hash: audience.audience_hash(),
            request_block: mcp_re_http_profile::HttpRequestEvidenceBlock {
                profile: "p".into(),
                audience,
                artifact_bindings: Vec::new(),
                continuation: None,
                admission: None,
                admission_assertion: None,
                authorization_decision: None,
            },
        }
    }

    fn event_names(sink: &crate::audit_sink::CollectingAuditSink) -> Vec<String> {
        sink.records()
            .iter()
            .map(|r| r.event().event_type().to_owned())
            .collect()
    }

    /// The record follows the entry, not the cause, and an accepted exchange can only be
    /// refused on the response side.
    #[test]
    fn the_posture_is_independent_of_the_cause() {
        let signing = ResponseSigning::new(
            &Arc::new(crate::delegated_server_signer::DelegatedServerSigner::new()),
            60,
        );
        let verified = verified();
        let actor_id = verified.resolved_actor().actor_id();
        let http_req = crate::http_profile_serve::HttpRequest {
            method: "POST".into(),
            target_uri: "https://example.test/mcp".into(),
            headers: Vec::new(),
            body: b"{}".to_vec(),
        };
        let exchange = || Exchange {
            http_req: &http_req,
            verified: &verified,
            actor_id: &actor_id,
            now: 1,
            verdicts: Default::default(),
        };

        let sink = Arc::new(crate::audit_sink::CollectingAuditSink::new());
        let audit: MaybeAuditSink = Some(sink.clone());
        let mut ex = exchange();
        signing.refuse(
            &audit,
            RefusalPoint::Request(&mut ex, None),
            Refusal::new(McpReError::MissingEnvelope, 400),
            ExecutionDisposition::NothingExecuted,
        );
        assert_eq!(event_names(&sink), ["mcp-re.request.rejected"]);

        let sink = Arc::new(crate::audit_sink::CollectingAuditSink::new());
        let audit: MaybeAuditSink = Some(sink.clone());
        let ans = Answerable {
            ex: exchange(),
            key: Arc::new(crate::delegated_wiring::test_support::issued_expiring_at(
                100, 7,
            )),
        };
        let notification = crate::http_profile_serve::HttpRequest {
            method: "POST".into(),
            target_uri: "https://example.test/mcp".into(),
            headers: Vec::new(),
            body: br#"{"jsonrpc":"2.0","method":"ping"}"#.to_vec(),
        };
        let admitted = AdmittedRequest {
            envelope: validated(&notification),
            authorized: AuthorizationPosture::NoPolicyConfigured,
        };
        let acc = Accepted::record(&audit, &admitted, ans);
        signing.refuse(
            &audit,
            RefusalPoint::Response(&acc),
            Refusal::new(McpReError::MissingEnvelope, 500),
            ExecutionDisposition::PossiblyExecuted,
        );
        assert_eq!(
            event_names(&sink),
            ["mcp-re.request.accepted", "mcp-re.response.rejected"]
        );
    }
}
