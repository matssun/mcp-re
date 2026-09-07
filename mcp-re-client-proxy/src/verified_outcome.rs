// SPDX-License-Identifier: Apache-2.0
//! What a VERIFIED outcome MEANS to a plain MCP client.
//!
//! A verified signature says the server said this. It does not say the exchange is
//! finished, and it does not say the call succeeded — so the reply is CLASSIFIED before it
//! is handed over, and two classes never resolve to success:
//!
//! * an `InputRequiredResult` carrying no usable `requestState` is MALFORMED rather than
//!   terminal. An answer leg could never be honoured, so failing closed is the only honest
//!   outcome;
//! * MCP 2026-07-28 closes the `resultType` set, so an unrecognized one MUST be considered
//!   invalid. It is never resolved to terminal.
//!
//! A verified REJECTION receipt is not an error here. The request was provably denied, and
//! that is an answer: it becomes a plain JSON-RPC error carrying its classification, never a
//! success result.
//!
//! Nothing in this module decides anything about TRUST. It reads a verdict the verifier has
//! already reached — which is why it is a free function over that verdict rather than a
//! method on the proxy that holds the keys.

use mcp_re_client_core::continuation_state_of;
use mcp_re_client_core::DelegatedOutcome;
use mcp_re_client_core::HttpResponse;
use serde_json::Value;

use crate::proxy::plain_error_from_rejection;
use crate::proxy::plain_response_from_verified;
use crate::proxy::ProxyResponse;
use crate::proxy::ResponseKind;
use crate::transport::ProxyError;

/// What a VERIFIED outcome means to a plain MCP client.
///
/// A verified signature says the server said this; it does not say the exchange is
/// finished. So the reply is CLASSIFIED before it is handed over, and two classes never
/// resolve to success: an `InputRequiredResult` carrying no usable `requestState` is
/// malformed rather than terminal — an answer leg could never be honoured — and MCP
/// 2026-07-28 closes the `resultType` set, so an unrecognized one MUST be considered
/// invalid.
///
/// A verified REJECTION receipt is not an error here: the request was provably denied, and
/// that is an answer. It becomes a plain JSON-RPC error carrying its classification, never
/// a success result.
pub(crate) fn read_outcome(
    verified: mcp_re_client_core::VerifiedDelegatedResponse,
    response: &HttpResponse,
    request_id: Value,
) -> Result<ProxyResponse, ProxyError> {
    match verified.outcome {
        DelegatedOutcome::Success => {
            let plain = plain_response_from_verified(&response.body, &request_id)?;
            // Classify BEFORE handing the reply over. A verified signature says
            // the server said this; it does not say the exchange is finished.
            let result = plain.get("result");
            // `plain_response_from_verified` has already refused a reply carrying
            // neither member or both, so an `error` here means there is no
            // `result` to classify — and classifying an absent `result` yields
            // Terminal, which is the success label.
            if let Some(code) = plain
                .get("error")
                .map(|e| e.get("code").and_then(Value::as_i64))
            {
                return Ok(ProxyResponse {
                    plain_response: plain,
                    kind: ResponseKind::CallFailed { code },
                });
            }
            // ONE classification, over the `result` already parsed out of the
            // verified bytes. The three-way contract refuses both middle grounds
            // here rather than reporting them: a reply that announces itself
            // non-terminal and then carries no usable `requestState` is MALFORMED,
            // not terminal — an answer leg could never be honoured — and MCP
            // 2026-07-28 closes the `resultType` set, so an unrecognized one is
            // invalid and never resolves to a class. Asking over `response.body`
            // instead would parse and classify this message a second time, which is
            // how two readers of one message come to disagree about what it says.
            let kind = match continuation_state_of(result)? {
                None => ResponseKind::Success,
                Some(request_state) => ResponseKind::InputRequired { request_state },
            };
            Ok(ProxyResponse {
                plain_response: plain,
                kind,
            })
        }
        // A VERIFIED rejection receipt: the request was provably denied. Convert the
        // signed receipt to a plain JSON-RPC error for the local client and report
        // the classification (fail closed — never returned as a success result).
        DelegatedOutcome::Rejection {
            wire_code,
            execution,
        } => Ok(ProxyResponse {
            plain_response: plain_error_from_rejection(
                &request_id,
                wire_code.as_deref(),
                &execution,
            ),
            kind: ResponseKind::VerifiedRejection {
                wire_code,
                bound: verified.verified.is_bound(),
                execution,
            },
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_re_client_core::build_signed_request;
    use mcp_re_client_core::verify_delegated_response;
    use mcp_re_client_core::ArtifactBinding;
    use mcp_re_client_core::ArtifactType;
    use mcp_re_client_core::AudienceTuple;
    use mcp_re_client_core::CompositeResponseTrust;
    use mcp_re_client_core::DelegationPolicy;
    use mcp_re_client_core::HttpProfileError;
    use mcp_re_client_core::RequestSigningInputs;
    use mcp_re_client_core::ResolvedActor;
    use mcp_re_client_core::ResponseExpectation;
    use mcp_re_client_core::SignedRequest;
    use mcp_re_client_core::SignerSlot;
    use mcp_re_client_core::StaticRevocationList;
    use mcp_re_core::SigningKey;
    use mcp_re_http_profile::ActorIdentity;
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

    /// The client's trust seam: the ROOT issuer key for the Response slot. One
    /// [`CompositeResponseTrust`] over it plus an empty delegated-key revocation set,
    /// because the verifier takes ONE trust authority and the pairing is not the
    /// question these controls ask.
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
        DelegationPolicy::new(
            vec![AUD.to_string()],
            AUD_SCOPE,
            vec![EPOCH.to_string()],
            60,
        )
    }

    fn custody() -> DelegatedSigningCustody<
        impl FnMut(&DelegationHeader, &DelegationClaims) -> Option<String>,
        impl FnMut() -> SigningKey,
    > {
        let root = root_key();
        let issue = move |h: &DelegationHeader, c: &DelegationClaims| {
            Some(mcp_re_http_profile::issue_delegation_credential(
                &root, h, c,
            ))
        };
        let mut n = 100u8;
        let factory = move || {
            n = n.wrapping_add(1);
            SigningKey::from_seed_bytes(&[n; 32])
        };
        DelegatedSigningCustody::new(
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
            },
            issue,
            factory,
        )
    }

    fn signed() -> SignedRequest {
        let inputs = RequestSigningInputs::new(
            CLIENT_KEY_ID.to_string(),
            AudienceTuple {
                audience_id: AUD.into(),
                target_uri: TARGET.into(),
                route: Some("a".into()),
            },
            vec![ArtifactBinding::opaque_digest(
                ArtifactType::OauthDpop,
                b"access-token-under-test",
            )],
            "nonce-1-padded-to-the-128-bit-floor",
            CREATED,
            EXPIRES,
        );
        let params: Map<String, Value> = json!({ "name": "read" })
            .as_object()
            .cloned()
            .expect("an object");
        build_signed_request(
            &json!(1),
            "tools/call",
            params,
            TARGET,
            &inputs,
            &SigningKey::from_seed_bytes(&CLIENT_SEED),
        )
        .expect("client signs request")
    }

    /// A GENUINELY verified delegated reply carrying `body`, handed to [`read_outcome`]
    /// exactly as the proxy hands it over.
    ///
    /// The round trip is real on both halves: the server delegated-signs the bytes under a
    /// credential issued by the root, and the client verifies them through the shipped
    /// verifier. Nothing here constructs a `VerifiedDelegatedResponse` — the type is only
    /// obtainable from a verification that succeeded, which is what makes these controls
    /// statements about the deployed path rather than about a hand-built value.
    fn outcome_of(body: &[u8]) -> Result<ProxyResponse, ProxyError> {
        let signed = signed();
        let mut custody = custody();
        let mut response = HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: body.to_vec(),
        };
        custody
            .sign_response(NOW, &mut response, signed.request(), signed.evidence())
            .expect("server delegated-signs the reply");
        let revoked = StaticRevocationList::new();
        let resolve = resolver();
        let resolve_now = |kid: &str, slot: SignerSlot, _now: i64| resolve(kid, slot).into();
        let trust = CompositeResponseTrust::new(&resolve_now, &revoked);
        let verified = verify_delegated_response(
            &response,
            &trust,
            &ResponseExpectation::for_signed(&signed),
            &policy(),
            NOW,
        )
        .expect("the client verifies the delegated reply");
        read_outcome(verified, &response, json!(1))
    }

    /// An ordinary terminal reply is a SUCCESS, and the plain body reaches the caller.
    #[test]
    fn a_verified_terminal_reply_is_success() {
        let out = outcome_of(br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#)
            .expect("a terminal reply is an outcome");
        assert_eq!(out.kind, ResponseKind::Success);
        assert_eq!(out.plain_response["result"]["ok"], json!(true));
    }

    /// An `InputRequiredResult` WITH a usable `requestState` surfaces that state rather
    /// than closing the exchange — the other half of the three-way contract, without which
    /// "fails closed" could be satisfied by refusing every non-terminal leg.
    #[test]
    fn a_verified_input_required_reply_surfaces_its_continuation_state() {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "resultType": mcp_re_http_profile::result_class::INPUT_REQUIRED_RESULT_TYPE,
                "requestState": "state-1",
            },
        })
        .to_string();
        let out = outcome_of(body.as_bytes()).expect("a well-formed continuation is an outcome");
        assert_eq!(
            out.kind,
            ResponseKind::InputRequired {
                request_state: "state-1".to_owned(),
            }
        );
    }

    /// THE fail-closed case, over a reply whose signature is GENUINE. A verified message
    /// that announces itself non-terminal and then withholds the state its answer leg would
    /// have to sign over is MALFORMED, and reading it as terminal is what hands an
    /// elicitation to an application as a completed tool result.
    #[test]
    fn a_verified_input_required_reply_with_no_usable_state_fails_closed() {
        for withheld in [
            json!({"resultType": mcp_re_http_profile::result_class::INPUT_REQUIRED_RESULT_TYPE}),
            json!({
                "resultType": mcp_re_http_profile::result_class::INPUT_REQUIRED_RESULT_TYPE,
                "requestState": null,
            }),
            json!({
                "resultType": mcp_re_http_profile::result_class::INPUT_REQUIRED_RESULT_TYPE,
                "requestState": 42,
            }),
        ] {
            let body = json!({"jsonrpc": "2.0", "id": 1, "result": withheld}).to_string();
            let err = outcome_of(body.as_bytes())
                .expect_err("a non-terminal leg with no usable state is not an outcome");
            assert_eq!(
                err,
                ProxyError::FailedClosed(HttpProfileError::MalformedEvidence(
                    "input_required requestState"
                )),
                "{body} must not resolve to a terminal outcome"
            );
        }
    }

    /// MCP 2026-07-28 closes the `resultType` set. A verified reply carrying one this
    /// client does not recognize is INVALID — never `Success`, and never any other
    /// terminal outcome. A genuine signature over an unreadable classification is
    /// precisely the case where "the server said this" must not become "the call
    /// finished".
    #[test]
    fn a_verified_unrecognized_result_type_never_becomes_terminal() {
        for unrecognized in [json!("something_new"), json!(7), json!({"a": 1})] {
            let body = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"resultType": unrecognized},
            })
            .to_string();
            let err = outcome_of(body.as_bytes())
                .expect_err("an unrecognized resultType is not an outcome");
            assert_eq!(
                err,
                ProxyError::FailedClosed(HttpProfileError::UnrecognizedResultType),
                "{body} must not resolve to a terminal outcome"
            );
        }
    }

    /// A verified REJECTION receipt is an ANSWER, not a transport failure — and not a
    /// success. It reaches the local client as a plain JSON-RPC error carrying the frozen
    /// wire code the boundary signed.
    #[test]
    fn a_verified_rejection_receipt_is_an_answer_and_never_a_success() {
        let signed = signed();
        let mut custody = custody();
        custody.ensure_active(NOW).expect("a credential is issued");
        let snapshot = custody.active_snapshot().expect("a key is active");
        let reason = RejectionReason::new("mcp-re.replay_detected", "replayed");
        let response = mcp_re_http_profile::build_delegated_rejection(
            signed.request(),
            signed.evidence(),
            &reason,
            409,
            &snapshot.server_signer,
            &snapshot.credential,
            snapshot.key.as_ref(),
            &snapshot.delegated_kid,
            NOW,
            NOW + 300,
        )
        .expect("the boundary builds a bound delegated rejection");
        let revoked = StaticRevocationList::new();
        let resolve = resolver();
        let resolve_now = |kid: &str, slot: SignerSlot, _now: i64| resolve(kid, slot).into();
        let trust = CompositeResponseTrust::new(&resolve_now, &revoked);
        let verified = verify_delegated_response(
            &response,
            &trust,
            &ResponseExpectation::for_signed(&signed),
            &policy(),
            NOW,
        )
        .expect("the client verifies the receipt");
        let out = read_outcome(verified, &response, json!(1)).expect("a receipt is an answer");
        match out.kind {
            ResponseKind::VerifiedRejection { wire_code, .. } => {
                assert_eq!(wire_code.as_deref(), Some("mcp-re.replay_detected"));
            }
            other => panic!("a verified rejection must not read as {other:?}"),
        }
        assert!(
            out.plain_response.get("error").is_some(),
            "a provable denial reaches the local client as a JSON-RPC error"
        );
        assert!(out.plain_response.get("result").is_none());
    }
}
