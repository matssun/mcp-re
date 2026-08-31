// SPDX-License-Identifier: Apache-2.0
//! What makes an inbound message a request this deployment will read at all.
//!
//! One fact: **a message is attributable to an actor and legal as MCP before anything reads
//! it for meaning.** Three inputs decide it and they only mean anything together —
//!
//! * the trust seam, which turns a presented keyid FOR a signing slot into an actor;
//! * the expected audience tuple, which is what "this message was addressed to us" means;
//! * the verifier-local acceptance policy — algorithm registry, bounded skew, and the
//!   optional MCP transport/version contract.
//!
//! Held apart, a deployment could attach a stricter policy to one call and not to the
//! next, and the audience the verifier enforced would be one value while the audience the
//! continuation store keyed under was another. Held together, there is one answer to *whose
//! message is this, and is it addressed to us*, and every consumer takes a named projection
//! of it.
//!
//! Both questions here refuse for free: nothing has happened on the request's behalf.

use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::OutstandingId;
use mcp_re_http_profile::VerifiedMcpRequest;
use mcp_re_http_profile::Verifier;
use mcp_re_http_profile::VerifierPolicy;

use crate::exchange_state::Established;
use crate::exchange_state::ExchangeEvent;
use crate::refusal::Refusal;

use super::ActorResolver;

/// The deployment's request-admission authority: who may speak, to whom, and under what
/// acceptance policy.
///
/// Private representation. The trust seam is never handed out, and the audience leaves only
/// as [`audience_id`](Self::audience_id) — the coordinate the correlation store keys under,
/// which is therefore provably the same one the verifier enforced.
pub(super) struct RequestAdmission {
    /// Trust resolution for request (client) and response (server) signing slots.
    resolve_actor: ActorResolver,
    /// The verifier's expected audience tuple (audience id + `@target-uri` + route);
    /// `target_uri` must equal the request `@target-uri` (enforced in verify).
    expected_audience: AudienceTuple,
    /// The verifier-local acceptance policy: algorithm registry, bounded skew, and the
    /// optional MCP transport/version contract (§4.1, §5.1, §13.1). Default is
    /// `VerifierPolicy::default()` — Ed25519, 30 s skew, no transport contract.
    policy: VerifierPolicy,
}

impl RequestAdmission {
    /// The authority a deployment starts with: its trust seam and its audience, under the
    /// default acceptance policy.
    pub(super) fn new(resolve_actor: ActorResolver, expected_audience: AudienceTuple) -> Self {
        RequestAdmission {
            resolve_actor,
            expected_audience,
            policy: VerifierPolicy::default(),
        }
    }

    /// Attach a stricter verifier-local acceptance policy.
    pub(super) fn under(&mut self, policy: VerifierPolicy) {
        self.policy = policy;
    }

    /// The audience coordinate this deployment answers as.
    ///
    /// The one projection of the tuple, and it exists so the correlation store keys under
    /// the value the verifier enforced rather than under a second copy that can drift.
    pub(super) fn audience_id(&self) -> &str {
        &self.expected_audience.audience_id
    }

    /// VERIFIED — RFC 9421 + RFC 9530 + the evidence block.
    ///
    /// ```text
    /// ensures   Ok  => the signature verified and an actor is resolved
    ///           Err => 403, signed UNBOUND (no trustworthy request hash exists yet)
    /// forbids   any effect on the request's behalf
    /// refusal   free — nothing has happened
    /// ```
    ///
    /// DPoP artifact bindings derive their credential from the covered Authorization
    /// header, so no external material is supplied; a binding lacking one fails closed.
    pub(super) fn verify(
        &self,
        http_req: &HttpRequest,
        now: i64,
    ) -> Result<Established<VerifiedMcpRequest>, Refusal> {
        let no_material = |_b: &ArtifactBinding| None;
        // Scoped so the timer covers the verification and nothing after it.
        let verify_result = {
            let _t = crate::stage_timers::Timed::start(crate::stage_timers::Stage::Verify);
            Verifier::new(&self.policy, self.resolve_actor.as_ref()).verify_request(
                http_req,
                &self.expected_audience,
                &no_material,
                now,
            )
        };
        // The request never verified, so there is no trustworthy request hash to bind to
        // and no resolved actor to attribute the denial to.
        verify_result
            .map(|v| Established::new(v, ExchangeEvent::SignatureVerified))
            .map_err(|e| Refusal::preflight(e, 403))
    }

    /// REQUEST-ENVELOPE-VALIDATED — is this body a legal JSON-RPC request at all?
    ///
    /// ```text
    /// ensures   Ok  => the body is a legal JSON-RPC 2.0 request, and the outstanding id
    ///                  it establishes is decided ONCE, here
    ///           Err => 400, bound to the request via `;req`
    /// forbids   any effect on the request's behalf
    /// refusal   free — nothing has happened
    /// ```
    ///
    /// Asked before anything reads the body for meaning, because everything below does: the
    /// continuation stage reads `params.requestState`, the forwarded body strips `_meta`,
    /// and the terminal arm is chosen by the presence of `id`. Deciding the shape after
    /// admission would burn a nonce, spend an approval and write a durable retention marker
    /// on behalf of a document that is not an MCP message.
    ///
    /// REPRESENTABILITY is part of that shape, and for the same reason. A body carrying a
    /// duplicate member name or a number the `f64` carrier rewrites is one the profile
    /// cannot forward and sign unchanged, and every reader below — this validator included
    /// — goes through `serde_json`, which answers for one winner rather than for the
    /// document the client signed.
    ///
    /// The returned [`OutstandingId`] is the exchange's single answer to "what is this
    /// request": the notification arm and the response envelope validator are both given
    /// this value rather than re-reading the body. Two readers of one document can disagree,
    /// and the disagreement that mattered here is a body dispatched as a request and
    /// acknowledged as a notification.
    pub(super) fn validate_envelope(
        &self,
        http_req: &HttpRequest,
    ) -> Result<OutstandingId, Refusal> {
        mcp_re_http_profile::validate_request_envelope(&http_req.body)
            .map_err(|e| Refusal::before_admission(e, 400))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_re_http_profile::ResolverOutcome;

    fn admission() -> RequestAdmission {
        RequestAdmission::new(
            Box::new(|_kid, _slot| ResolverOutcome::NotTrusted),
            AudienceTuple {
                audience_id: "aud-1".into(),
                target_uri: "https://example.test/mcp".into(),
                route: Some("/mcp".to_owned()),
            },
        )
    }

    fn request(body: &str) -> HttpRequest {
        HttpRequest {
            method: "POST".into(),
            target_uri: "https://example.test/mcp".into(),
            headers: vec![],
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn the_audience_the_store_keys_under_is_the_one_the_verifier_enforces() {
        // The reason the tuple is not a separate field. One value, one projection: a
        // correlation key derived from a second copy could name a continuation this
        // deployment never admitted anything for.
        assert_eq!(admission().audience_id(), "aud-1");
    }

    #[test]
    fn a_document_that_is_not_an_mcp_message_is_refused_at_400() {
        // Free, and asked before anything reads the body for meaning. Deciding the shape
        // after admission would burn a nonce and write a durable retention marker on behalf
        // of a document that is not a request.
        let Err(refusal) = admission().validate_envelope(&request(r#"{"not":"jsonrpc"}"#)) else {
            panic!("a non-JSON-RPC body is not a legal request");
        };
        assert_eq!(refusal.status, 400);
    }

    #[test]
    fn a_body_the_profile_cannot_carry_unchanged_is_refused_before_anything_is_spent() {
        // Free, and 400 rather than 500. The scan used to run when the forwarded body was
        // composed, which is after the nonce is burned, the approval retired and the
        // retention marker written — so a document MCP-RE will not carry was refused at
        // the cost of a document it would have.
        for body in [
            r#"{"jsonrpc":"2.0","method":"tools/call","id":1,"id":2}"#,
            r#"{"jsonrpc":"2.0","method":"tools/call","params":{"n":123456789012345678901234567890}}"#,
        ] {
            let Err(refusal) = admission().validate_envelope(&request(body)) else {
                panic!("{body} was accepted as a representable request");
            };
            assert_eq!(refusal.status, 400);
        }
    }

    #[test]
    fn a_notification_and_a_request_are_told_apart_once() {
        // The single answer to "what is this request". Both the notification terminal and
        // the response-envelope validator are handed THIS value rather than re-reading the
        // body, because two readers of one document can disagree.
        let admission = admission();
        assert!(matches!(
            admission.validate_envelope(&request(r#"{"jsonrpc":"2.0","method":"ping"}"#)),
            Ok(OutstandingId::Notification)
        ));
        assert!(matches!(
            admission.validate_envelope(&request(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#)),
            Ok(OutstandingId::Id(_))
        ));
    }
}
