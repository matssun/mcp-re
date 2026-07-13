// SPDX-License-Identifier: Apache-2.0
//! RFC 9421 signed-response verification on the client side (ADR-MCPRE-050,
//! MCPRE-101). The return leg of [`crate::request`].
//!
//! Given the received [`HttpResponse`] and the request context the client kept
//! from signing (`SignedRequest`: the sent [`HttpRequest`] and its
//! [`RequestEvidence`] handle), it confirms the response is genuine RFC 9421 +
//! RFC 9530 evidence bound to THIS request:
//! [`mcp_re_http_profile::verify_response_bound_full`] performs the
//! `Content-Digest` check, the RFC 9421 signature verification over the `;req`-bound
//! signature base (a spliced response fails), server-signer trust resolution through
//! the injected actor resolver, and the response-block `request_evidence` binding.
//!
//! The response evidence is an RFC 9421 signature over the `;req`-bound base plus the
//! RFC 9530 Content-Digest, not a JSON-RPC `_meta` block. Trust resolution stays
//! behind the actor-resolver seam, so the proxy/SDK
//! injects the live-trust / OCSP-backed resolver and this pure module never reaches
//! the network.

use mcp_re_http_profile::verify_delegated_response_bound_full;
use mcp_re_http_profile::verify_delegated_response_unbound;
use mcp_re_http_profile::verify_response_bound_full;
use mcp_re_http_profile::DelegationExpectations;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::RequestEvidence;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::VerifiedHttpResponseEvidence;
use serde_json::Value;

/// The MCP-RE round-trip classification of a verified response body
/// (ADR-MCPS-047). Read ONLY from the signed, verified body — never from
/// untrusted bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultClass {
    /// An ordinary terminal result.
    Terminal,
    /// An `InputRequiredResult` — a non-terminal leg awaiting client continuation.
    InputRequired,
}

/// What the client expects of the bound response for one outstanding request: the
/// exact request it sent (for the `;req` binding), the [`RequestEvidence`] handle
/// the response must bind, and an optional pinned server signer.
#[derive(Debug, Clone)]
pub struct ResponseExpectation {
    /// The exact [`HttpRequest`] the client signed and sent.
    pub request: HttpRequest,
    /// The [`RequestEvidence`] handle the response's `request_evidence` must equal.
    pub request_evidence: RequestEvidence,
    /// The server signer policy expects for this route/audience, if pinned. When
    /// `Some`, the verified server signer keyid MUST equal it (unexpected → fail
    /// closed) even if some other signer would independently resolve.
    pub expected_server_signer_keyid: Option<String>,
}

impl ResponseExpectation {
    /// Build an expectation from the sent request and its evidence handle, with no
    /// pinned signer (resolver scope governs).
    pub fn new(request: HttpRequest, request_evidence: RequestEvidence) -> Self {
        ResponseExpectation {
            request,
            request_evidence,
            expected_server_signer_keyid: None,
        }
    }

    /// Pin the expected server signer keyid. A verified-but-unexpected signer then
    /// fails closed.
    pub fn with_expected_server_signer(mut self, keyid: impl Into<String>) -> Self {
        self.expected_server_signer_keyid = Some(keyid.into());
        self
    }
}

/// Verify a signed RFC 9421 response and confirm it binds the expected request.
///
/// `resolve_actor` is the client's trust seam (injected by the proxy/SDK; live
/// trust + OCSP live behind it, so this pure module performs no I/O). On success
/// returns the [`VerifiedHttpResponseEvidence`]; on any failure the precise frozen
/// [`HttpProfileError`], fail-closed.
pub fn verify_signed_response(
    response: &HttpResponse,
    resolve_actor: &dyn Fn(&str, SignerSlot) -> Option<ResolvedActor>,
    expectation: &ResponseExpectation,
    now: i64,
) -> Result<VerifiedHttpResponseEvidence, HttpProfileError> {
    let verified = verify_response_bound_full(
        response,
        &expectation.request,
        &expectation.request_evidence,
        resolve_actor,
        now,
    )?;

    // Unexpected-signer guard (client policy): a signer that verifies but is not
    // the one policy bound to this route/audience fails closed.
    if let Some(expected) = &expectation.expected_server_signer_keyid {
        let signed_keyid = &verified.resolved_server_actor.identity.keyid;
        if signed_keyid != expected {
            return Err(HttpProfileError::ResponseBindingMismatch);
        }
    }

    Ok(verified)
}

/// A verified response plus its multi-round-trip classification (ADR-MCPS-047),
/// read from the signed, verified body.
#[derive(Debug, Clone)]
pub struct ClassifiedResponse {
    /// The verification verdict.
    pub verified: VerifiedHttpResponseEvidence,
    /// Terminal vs `InputRequiredResult`.
    pub class: ResultClass,
}

/// Verify a signed RFC 9421 response AND classify its result body for the
/// multi-round-trip flow. Classification runs ONLY after verification succeeds, so
/// the class is never trusted from unverified bytes.
pub fn verify_and_classify_response(
    response: &HttpResponse,
    resolve_actor: &dyn Fn(&str, SignerSlot) -> Option<ResolvedActor>,
    expectation: &ResponseExpectation,
    now: i64,
) -> Result<ClassifiedResponse, HttpProfileError> {
    let verified = verify_signed_response(response, resolve_actor, expectation, now)?;
    let body: Value =
        serde_json::from_slice(&response.body).map_err(|_| HttpProfileError::MalformedEvidence("response body"))?;
    let class = classify_result(body.get("result"));
    Ok(ClassifiedResponse { verified, class })
}

/// Classify a (verified) `result` body as terminal or `InputRequiredResult`. The
/// `InputRequiredResult` marker is the `resultType == "input_required"` discriminator
/// (ADR-MCPS-047). Absent/other results are terminal.
pub fn classify_result(result: Option<&Value>) -> ResultClass {
    match result.and_then(|r| r.get("resultType")).and_then(|t| t.as_str()) {
        Some("input_required") => ResultClass::InputRequired,
        _ => ResultClass::Terminal,
    }
}

// ---- ADR-MCPRE-052 delegated-required client verification (MCPRE-122) --------

/// The deployment policy the client applies when verifying a DELEGATED-key-signed
/// response (ADR-MCPRE-052 §3) — the owned, client-side mirror of
/// [`mcp_re_http_profile::DelegationExpectations`]. The trusted ROOT issuer is
/// injected through the actor resolver (the credential's `issuer_kid` resolved for
/// the `Response` slot); this carries the audience-scope, epoch, and skew policy the
/// credential must satisfy.
#[derive(Debug, Clone)]
pub struct DelegationPolicy {
    /// This client's accepted verifier audience identifier(s); the credential's
    /// `aud` must name one.
    pub verifier_audiences: Vec<String>,
    /// The audience-scope hash the delegated key must be scoped to (the request's
    /// audience hash the deployment coordinates).
    pub expected_audience_hash: String,
    /// The accepted trust-epoch set (default `{ current }`, optionally
    /// `{ current, previous }` in a bounded rollout window).
    pub accepted_epochs: Vec<String>,
    /// Clock-skew tolerance for credential freshness, seconds.
    pub max_clock_skew: i64,
}

impl DelegationPolicy {
    /// Build a delegation policy.
    pub fn new(
        verifier_audiences: Vec<String>,
        expected_audience_hash: impl Into<String>,
        accepted_epochs: Vec<String>,
        max_clock_skew: i64,
    ) -> Self {
        DelegationPolicy {
            verifier_audiences,
            expected_audience_hash: expected_audience_hash.into(),
            accepted_epochs,
            max_clock_skew,
        }
    }
}

/// The verified-response outcome the client hands its caller (ADR-MCPRE-052): a
/// success, or a delegated REJECTION receipt (request-bound or preflight-unbound)
/// carrying the server's frozen wire code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegatedOutcome {
    /// A delegated-signed, request-bound SUCCESS response.
    Success,
    /// A delegated-signed REJECTION receipt. `bound` distinguishes a request-bound
    /// receipt (the server verified the request before a later fail-closed step)
    /// from a preflight-unbound one (the request never earned a trustworthy hash).
    /// `wire_code` is the server's frozen `mcp-re.*` reason from the verified body.
    Rejection { bound: bool, wire_code: Option<String> },
}

/// A verified delegated response: the verification evidence plus the outcome.
#[derive(Debug, Clone)]
pub struct VerifiedDelegatedResponse {
    /// The verified response evidence (server signer, bound request evidence, …).
    pub verified: VerifiedHttpResponseEvidence,
    /// Success vs delegated rejection receipt (bound / preflight).
    pub outcome: DelegatedOutcome,
}

/// Verify a DELEGATED-required response on the client (ADR-MCPRE-052 §3, MCPRE-122).
///
/// Delegation is REQUIRED and there is NO downgrade: a response with no inline
/// credential — INCLUDING a directly root-signed one — fails closed
/// (`delegation_credential_missing`); an unsigned response fails closed (no signature
/// to verify); there is no object/`_meta` evidence path.
///
/// A SUCCESS (2xx) MUST be request-bound — verified with
/// [`mcp_re_http_profile::verify_delegated_response_bound_full`] against the request
/// the client signed (a stripped-`;req` "success" cannot produce a valid delegated
/// signature). A non-2xx REJECTION receipt is verified request-bound first (a request
/// the server verified before a later fail-closed step) and, failing that, as a
/// preflight-unbound receipt — NEVER accepting an unbound receipt as a bound success.
/// On total failure the (more specific) bound error is surfaced, fail-closed.
///
/// `resolve_actor` is the client's trust seam; `is_revoked(kid)` reports delegated- or
/// root-key revocation at the current epoch (pass a never-revoked predicate if the
/// deployment relies on short delegated-key TTLs alone).
pub fn verify_delegated_response(
    response: &HttpResponse,
    resolve_actor: &dyn Fn(&str, SignerSlot) -> Option<ResolvedActor>,
    expectation: &ResponseExpectation,
    policy: &DelegationPolicy,
    is_revoked: &dyn Fn(&str) -> bool,
    now: i64,
) -> Result<VerifiedDelegatedResponse, HttpProfileError> {
    let audiences: Vec<&str> = policy.verifier_audiences.iter().map(String::as_str).collect();
    let epochs: Vec<&str> = policy.accepted_epochs.iter().map(String::as_str).collect();
    let expect = DelegationExpectations {
        verifier_audiences: &audiences,
        expected_audience_hash: policy.expected_audience_hash.as_str(),
        accepted_epochs: &epochs,
        max_clock_skew: policy.max_clock_skew,
    };

    // A SUCCESS must be request-bound. The server only ever signs success responses
    // with the `;req` binding, and a stripped-`;req` "success" changes the signature
    // base so no valid delegated signature can cover it — so this is a hard floor.
    if (200..300).contains(&response.status) {
        let verified = verify_delegated_response_bound_full(
            response,
            &expectation.request,
            &expectation.request_evidence,
            resolve_actor,
            &expect,
            is_revoked,
            now,
        )?;
        return Ok(VerifiedDelegatedResponse {
            verified,
            outcome: DelegatedOutcome::Success,
        });
    }

    // A REJECTION receipt: verify request-bound first, then preflight-unbound. Both
    // require the inline credential + a valid delegated signature, so an unsigned or
    // direct-root rejection fails closed here (no downgrade, no unsigned acceptance).
    match verify_delegated_response_bound_full(
        response,
        &expectation.request,
        &expectation.request_evidence,
        resolve_actor,
        &expect,
        is_revoked,
        now,
    ) {
        Ok(verified) => Ok(VerifiedDelegatedResponse {
            verified,
            outcome: DelegatedOutcome::Rejection {
                bound: true,
                wire_code: rejection_wire_code(&response.body),
            },
        }),
        Err(bound_err) => match verify_delegated_response_unbound(
            response,
            resolve_actor,
            &expect,
            is_revoked,
            now,
        ) {
            Ok(verified) => Ok(VerifiedDelegatedResponse {
                verified,
                outcome: DelegatedOutcome::Rejection {
                    bound: false,
                    wire_code: rejection_wire_code(&response.body),
                },
            }),
            // Neither path verified — fail closed. Surface the bound error (the more
            // specific of the two for a receipt claiming to be about this request).
            Err(_unbound_err) => Err(bound_err),
        },
    }
}

/// The server's frozen wire code from a (verified) rejection-receipt body
/// (`error.data.mcp_re_error.wire_code`), if present. Read ONLY after verification.
fn rejection_wire_code(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<Value>(body).ok().and_then(|v| {
        v.pointer("/error/data/mcp_re_error/wire_code")
            .and_then(|w| w.as_str())
            .map(str::to_owned)
    })
}

#[cfg(test)]
mod delegated_tests {
    use super::*;
    use crate::build_signed_request;
    use crate::RequestSigningInputs;
    use mcp_re_core::SigningKey;
    use mcp_re_http_profile::build_delegated_rejection;
    use mcp_re_http_profile::build_delegated_rejection_preflight;
    use mcp_re_http_profile::sign_response_full;
    use mcp_re_http_profile::ActorIdentity;
    use mcp_re_http_profile::AudienceTuple;
    use mcp_re_http_profile::CustodyConfig;
    use mcp_re_http_profile::DelegatedSigningCustody;
    use mcp_re_http_profile::DelegationClaims;
    use mcp_re_http_profile::DelegationHeader;
    use mcp_re_http_profile::RejectionReason;
    use mcp_re_http_profile::PROFILE_TAG;
    use serde_json::json;
    use serde_json::Map;

    const ROOT_SEED: [u8; 32] = [33u8; 32];
    const CLIENT_SEED: [u8; 32] = [11u8; 32];
    const CLIENT_KEY_ID: &str = "client-key-1";
    const ROOT_KID: &str = "root-kid";
    const AUD: &str = "verifier-1";
    const AUD_SCOPE: &str = "aud-scope-1";
    const EPOCH: &str = "epoch-1";
    const TARGET: &str = "https://mcp.example.com/mcp?route=a";
    const NOW: i64 = 1_700_000_100;
    const CREATED: i64 = 1_700_000_000;
    const EXPIRES: i64 = 1_700_000_300;

    fn root_key() -> SigningKey {
        SigningKey::from_seed_bytes(&ROOT_SEED)
    }
    fn client_key() -> SigningKey {
        SigningKey::from_seed_bytes(&CLIENT_SEED)
    }
    fn audience() -> AudienceTuple {
        AudienceTuple {
            audience_id: AUD.into(),
            target_uri: TARGET.into(),
            route: Some("a".into()),
        }
    }
    /// The client's trust seam: the ROOT issuer key (by its issuer kid) for the
    /// Response slot. The delegated key is authorized by the credential alone.
    fn resolver() -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> {
        move |key_id: &str, slot: SignerSlot| match (key_id, slot) {
            (ROOT_KID, SignerSlot::Response) => Some(ResolvedActor {
                identity: ActorIdentity {
                    role: "server".into(),
                    trust_domain: "example.com".into(),
                    subject: "did:example:server".into(),
                    keyid: ROOT_KID.into(),
                },
                verification_key: root_key().public_key(),
                slot,
            }),
            _ => None,
        }
    }
    fn policy() -> DelegationPolicy {
        DelegationPolicy::new(vec![AUD.to_string()], AUD_SCOPE, vec![EPOCH.to_string()], 60)
    }
    fn custody_cfg() -> CustodyConfig {
        CustodyConfig {
            issuer_kid: ROOT_KID.into(),
            iss: "did:example:server".into(),
            profile: PROFILE_TAG.into(),
            aud: AUD.into(),
            audience_hash: AUD_SCOPE.into(),
            trust_epoch: EPOCH.into(),
            server_role: "server".into(),
            server_trust_domain: "example.com".into(),
            server_subject: "did:example:server".into(),
            ttl: 300,
            overlap: 60,
        }
    }
    fn custody() -> DelegatedSigningCustody<
        impl FnMut(&DelegationHeader, &DelegationClaims) -> Option<String>,
        impl FnMut() -> SigningKey,
    > {
        let root = root_key();
        let issue = move |h: &DelegationHeader, c: &DelegationClaims| {
            Some(mcp_re_http_profile::issue_delegation_credential(&root, h, c))
        };
        let mut n = 100u8;
        let factory = move || {
            n = n.wrapping_add(1);
            SigningKey::from_seed_bytes(&[n; 32])
        };
        DelegatedSigningCustody::new(custody_cfg(), issue, factory)
    }
    fn signed() -> crate::SignedRequest {
        let inputs = RequestSigningInputs::new(
            CLIENT_KEY_ID.to_string(),
            audience(),
            Vec::new(),
            "nonce-1",
            CREATED,
            EXPIRES,
        );
        let params: Map<String, Value> =
            json!({ "name": "read" }).as_object().cloned().unwrap();
        build_signed_request(&json!(1), "tools/call", params, TARGET, &inputs, &client_key())
            .expect("client signs request")
    }
    fn expectation(signed: &crate::SignedRequest) -> ResponseExpectation {
        ResponseExpectation::new(signed.request().clone(), signed.evidence().clone())
    }
    fn success_body() -> Vec<u8> {
        br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec()
    }

    #[test]
    fn delegated_success_is_verified_and_classified() {
        let signed = signed();
        let mut custody = custody();
        let mut resp = HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: success_body(),
        };
        custody
            .sign_response(NOW, &mut resp, signed.request(), signed.evidence())
            .expect("server delegated-signs the success response");
        let out = verify_delegated_response(
            &resp,
            &resolver(),
            &expectation(&signed),
            &policy(),
            &|_| false,
            NOW,
        )
        .expect("client verifies delegated success");
        assert_eq!(out.outcome, DelegatedOutcome::Success);
        assert_eq!(
            out.verified.server_signer.as_ref().unwrap().keyid,
            format!("{ROOT_KID}/delegated/1")
        );
    }

    #[test]
    fn delegated_bound_rejection_is_verified_and_classified() {
        let signed = signed();
        let mut custody = custody();
        custody.ensure_active(NOW).expect("issue");
        let snap = custody.active_snapshot().unwrap();
        let reason = RejectionReason {
            wire_code: "mcp-re.replay_detected",
            message: "replayed".into(),
        };
        let resp = build_delegated_rejection(
            signed.request(),
            signed.evidence(),
            &reason,
            409,
            &snap.server_signer,
            &snap.credential,
            snap.key.as_ref(),
            &snap.delegated_kid,
            NOW,
            NOW + 300,
        )
        .expect("server builds bound delegated rejection");
        let out = verify_delegated_response(
            &resp,
            &resolver(),
            &expectation(&signed),
            &policy(),
            &|_| false,
            NOW,
        )
        .expect("client verifies bound rejection");
        assert_eq!(
            out.outcome,
            DelegatedOutcome::Rejection {
                bound: true,
                wire_code: Some("mcp-re.replay_detected".into())
            }
        );
    }

    #[test]
    fn delegated_preflight_rejection_is_verified_unbound() {
        let signed = signed();
        let mut custody = custody();
        custody.ensure_active(NOW).expect("issue");
        let snap = custody.active_snapshot().unwrap();
        let reason = RejectionReason {
            wire_code: "mcp-re.request_signature_invalid",
            message: "bad request".into(),
        };
        let resp = build_delegated_rejection_preflight(
            Some(signed.request()),
            &reason,
            403,
            &snap.server_signer,
            &snap.credential,
            snap.key.as_ref(),
            &snap.delegated_kid,
            NOW,
            NOW + 300,
        )
        .expect("server builds preflight delegated rejection");
        let out = verify_delegated_response(
            &resp,
            &resolver(),
            &expectation(&signed),
            &policy(),
            &|_| false,
            NOW,
        )
        .expect("client verifies preflight rejection unbound");
        assert_eq!(
            out.outcome,
            DelegatedOutcome::Rejection {
                bound: false,
                wire_code: Some("mcp-re.request_signature_invalid".into())
            }
        );
    }

    #[test]
    fn direct_root_success_is_rejected_no_credential() {
        // A pre-052 directly-root-signed 200 has no inline credential — the delegated
        // verifier fails closed (no direct-root fallback).
        let signed = signed();
        let server_identity = ActorIdentity {
            role: "server".into(),
            trust_domain: "example.com".into(),
            subject: "did:example:server".into(),
            keyid: ROOT_KID.into(),
        };
        let mut resp = HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: success_body(),
        };
        sign_response_full(
            &mut resp,
            signed.request(),
            signed.evidence(),
            &server_identity,
            &root_key(),
            ROOT_KID,
            NOW,
            NOW + 300,
        )
        .expect("server directly root-signs");
        let err = verify_delegated_response(
            &resp,
            &resolver(),
            &expectation(&signed),
            &policy(),
            &|_| false,
            NOW,
        )
        .unwrap_err();
        assert_eq!(err, HttpProfileError::DelegationCredentialMissing);
    }

    #[test]
    fn unsigned_response_is_rejected() {
        // The server's last-resort unsigned error (no RFC 9421 signature) must never
        // be accepted in delegated-required mode.
        let signed = signed();
        let resp = HttpResponse {
            status: 503,
            headers: vec![("content-type".into(), "application/json".into())],
            body: json!({
                "jsonrpc": "2.0",
                "error": { "code": -32001, "message": "mcp-re.delegated_signing_unavailable" },
                "id": Value::Null,
            })
            .to_string()
            .into_bytes(),
        };
        assert!(verify_delegated_response(
            &resp,
            &resolver(),
            &expectation(&signed),
            &policy(),
            &|_| false,
            NOW,
        )
        .is_err());
    }

    #[test]
    fn unbound_signature_is_not_accepted_as_success() {
        // An unbound (response-only) signature presented with a 2xx status must be
        // rejected: a success MUST carry the `;req` request binding.
        let signed = signed();
        let mut custody = custody();
        custody.ensure_active(NOW).expect("issue");
        let snap = custody.active_snapshot().unwrap();
        let reason = RejectionReason {
            wire_code: "mcp-re.request_signature_invalid",
            message: "x".into(),
        };
        // Build an UNBOUND signature but stamp a success status onto it.
        let mut resp = build_delegated_rejection_preflight(
            Some(signed.request()),
            &reason,
            200,
            &snap.server_signer,
            &snap.credential,
            snap.key.as_ref(),
            &snap.delegated_kid,
            NOW,
            NOW + 300,
        )
        .expect("build unbound response");
        resp.status = 200;
        assert!(verify_delegated_response(
            &resp,
            &resolver(),
            &expectation(&signed),
            &policy(),
            &|_| false,
            NOW,
        )
        .is_err());
    }
}
