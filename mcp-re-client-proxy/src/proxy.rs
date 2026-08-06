// SPDX-License-Identifier: Apache-2.0
//! The local client-side MCP-RE proxy pipeline (MCPS-49, #196), on the RFC 9421
//! carrier (ADR-MCPRE-050).
//!
//! The local client speaks PLAIN MCP to this proxy; the proxy signs the outbound
//! request as RFC 9421 + RFC 9530 via `mcp-re-client-core`, forwards it to the
//! remote MCP-RE endpoint, verifies the signed response bound to that request, and
//! returns PLAIN MCP. The local client never emits, parses, or negotiates any
//! MCP-RE field; the signature rides in the RFC 9421 HTTP headers, not a JSON-RPC
//! `_meta` block.
//!
//! ## PURGE 2026-07-11 — lean RFC 9421 pipeline
//! The object-era enforcement-mode engine, in-flight correlation store, MRT
//! continuation retention, and authorization-binding providers are **deferred**
//! (rebuilt on RFC 9421 later); this is the signing/verification adapter core.

use mcp_re_client_core::build_signed_notification;
use mcp_re_client_core::build_signed_request;
use mcp_re_client_core::classify_result;
use mcp_re_client_core::continuation_state;
use mcp_re_client_core::response::verify_delegated_accepted_202_anchored_pinned;
use mcp_re_client_core::response::verify_delegated_accepted_202_pinned;
use mcp_re_client_core::verify_delegated_response;
use mcp_re_client_core::verify_delegated_response_anchored;
use mcp_re_client_core::DelegatedOutcome;
use mcp_re_client_core::HttpProfileError;
use mcp_re_client_core::HttpResponse;
use mcp_re_client_core::RequestSigningInputs;
use mcp_re_client_core::ResponseExpectation;
use mcp_re_client_core::ResultClass;
use mcp_re_core::SigningKey;
use serde_json::json;
use serde_json::Map;
use serde_json::Value;

use crate::route::ClientVerification;
use crate::route::RouteRegistry;
use crate::transport::ProxyError;
use crate::transport::RemoteTransport;

/// Per-call parameters the mode-specific layer supplies (RFC 9421 freshness + the
/// verification clock). The binary fills these from its nonce source and clock.
#[derive(Debug, Clone)]
pub struct CallParams {
    /// A fresh anti-replay nonce (RFC 9421 `nonce`).
    pub nonce: String,
    /// Signature creation time, Unix seconds (RFC 9421 `created`).
    pub created: i64,
    /// Signature expiry time, Unix seconds (RFC 9421 `expires`).
    pub expires: i64,
    /// Current time (Unix seconds) for response verification.
    pub now_unix: i64,
}

/// The proxy's response to the local client: plain MCP, plus the verified kind so
/// the embedding layer can distinguish a genuine success from a provably-denied
/// request (a verified rejection receipt) without re-parsing.
#[derive(Debug, Clone)]
pub struct ProxyResponse {
    /// The plain MCP JSON-RPC response to return to the local client — a `result`
    /// on success, or a JSON-RPC `error` when the server provably rejected.
    pub plain_response: Value,
    /// Whether the verified response was a success or a delegated rejection receipt.
    pub kind: ResponseKind,
}

/// The verified outcome the proxy hands its embedding layer. A verified REJECTION is
/// NOT a proxy failure — the server provably denied the request; the proxy converts
/// the signed receipt to a plain JSON-RPC error and reports the classification. An
/// UNVERIFIABLE response (unsigned / direct-root in delegated mode / bad signature)
/// is a `ProxyError` instead — the channel is compromised or misconfigured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseKind {
    /// A verified TERMINAL success response — the call completed.
    Success,
    /// A verified NON-TERMINAL `InputRequiredResult`: the server is awaiting a signed
    /// answer leg, carrying `request_state` to present on it.
    ///
    /// Distinct from [`Success`](ResponseKind::Success) because the two are different
    /// events and the difference is not recoverable from the plain body once it has
    /// been handed over. Reporting this as a success is how an elicitation — a
    /// human-approval round trip — gets delivered to an application as a finished
    /// tool result: the application then acts on an approval nobody gave, and no
    /// answer leg is ever signed.
    InputRequired {
        /// The opaque MRTR state the answer leg must re-present.
        request_state: String,
    },
    /// A verified signed bodyless 202 for a one-way NOTIFICATION: the enforcement
    /// boundary authenticated and accepted the message. It does NOT say any action
    /// completed.
    AcceptedNotification,
    /// A verified TERMINAL reply carrying a JSON-RPC `error` member: the exchange
    /// completed and the call did not succeed.
    ///
    /// Distinct from [`Success`](ResponseKind::Success) because `classify_result`
    /// reads the `result` member, and an error reply has none — so an absent `result`
    /// classifies as terminal and the failure would be announced to the local client
    /// as a completed call. The signature is equally valid either way; what differs is
    /// what the server said, and that difference is not recoverable once the header
    /// has been written.
    ///
    /// Distinct from [`VerifiedRejection`](ResponseKind::VerifiedRejection), which is
    /// the enforcement boundary refusing the request. This is the *inner tool* failing
    /// a request that was admitted.
    CallFailed {
        /// The JSON-RPC error code the server reported, when it is an integer.
        code: Option<i64>,
    },
    /// A verified delegated rejection receipt, converted to plain JSON-RPC error.
    /// `wire_code` is the server's frozen `mcp-re.*` reason; `bound` distinguishes a
    /// request-bound receipt from a preflight-unbound one.
    VerifiedRejection {
        wire_code: Option<String>,
        bound: bool,
    },
}

/// The local client-side MCP-RE proxy. Holds the static route registry, the client
/// signing key + keyid, and the remote transport.
pub struct ClientProxy {
    registry: RouteRegistry,
    signing_key: SigningKey,
    key_id: String,
    transport: Box<dyn RemoteTransport>,
}

impl ClientProxy {
    /// Construct a proxy from its wired pieces.
    pub fn new(
        registry: RouteRegistry,
        signing_key: SigningKey,
        key_id: impl Into<String>,
        transport: Box<dyn RemoteTransport>,
    ) -> Self {
        ClientProxy {
            registry,
            signing_key,
            key_id: key_id.into(),
            transport,
        }
    }

    /// Handle one plain-MCP request on `route_id`: sign (RFC 9421) → forward →
    /// verify the bound signed response → return plain MCP. Fails closed on any
    /// verification failure.
    pub fn handle(
        &self,
        route_id: &str,
        plain_request: &Value,
        params: &CallParams,
    ) -> Result<ProxyResponse, ProxyError> {
        let route = self
            .registry
            .get(route_id)
            .ok_or_else(|| ProxyError::UnknownRoute(route_id.to_string()))?;

        // Parse the ordinary MCP request (transparency: it carries no MCP-RE fields).
        //
        // ABSENT `id` is what makes a JSON-RPC message a NOTIFICATION (§4.1), and both
        // the signer and the serving path classify on exactly that key's absence.
        // `null` is not the same thing: it is a PRESENT id, so defaulting to it turned
        // every one-way notification into a request that the server dispatched to the
        // backend and answered with a bodied reply nothing was awaiting.
        let id = plain_request.get("id").cloned();
        let method = plain_request
            .get("method")
            .and_then(Value::as_str)
            .ok_or(ProxyError::MalformedRequest)?
            .to_string();
        let req_params: Map<String, Value> = plain_request
            .get("params")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();

        // Sign the RFC 9421 request through the client-core seam.
        let inputs = RequestSigningInputs::new(
            self.key_id.clone(),
            route.audience.clone(),
            route.artifact_bindings.clone(),
            &params.nonce,
            params.created,
            params.expires,
        )
        .with_headers(route.extra_headers.clone());
        let signed = match &id {
            Some(id) => build_signed_request(
                id,
                &method,
                req_params,
                &route.target_uri,
                &inputs,
                &self.signing_key,
            )?,
            None => build_signed_notification(
                &method,
                req_params,
                &route.target_uri,
                &inputs,
                &self.signing_key,
            )?,
        };

        // Forward to the remote MCP-RE endpoint.
        let response = self
            .transport
            .round_trip(signed.request())
            .map_err(ProxyError::Transport)?;

        // Verify the signed response bound to THIS request under the route's required
        // profile (configured profile = required profile). Fail closed on any failure;
        // no cross-profile fallback.
        //
        // ADR-MCPRE-052 delegated-signing (the only mode): a delegated-signed success OR
        // rejection receipt carrying the inline credential. No direct-root / unsigned /
        // object downgrade is accepted (both verify functions fail closed). The two
        // variants differ ONLY in where the trust anchors come from; the outcome
        // handling below is shared, so neither can drift into a laxer mapping.
        let mut expectation =
            ResponseExpectation::new(signed.request().clone(), signed.evidence().clone());
        // The route's PINNED server signer, if it configured one. Without this the
        // field was route bookkeeping that decided nothing: any server whose delegated
        // credential chains to a trusted root and is scoped to this audience could
        // answer for this route, which is precisely what the pin exists to refuse.
        if let Some(keyid) = &route.expected_server_keyid {
            expectation = expectation.with_expected_server_signer(keyid.clone());
        }
        // A NOTIFICATION is answered with a signed bodyless 202, not a bodied reply,
        // so it takes its own verification path. Nothing below it applies: there is no
        // result to classify and no body to rebuild. It carries no `ResponseExpectation`
        // because a bodyless 202 has no response block to bind one to; the pin it does
        // share is passed to it directly.
        if id.is_none() {
            return self.verify_notification_ack(route, &signed, &response, params);
        }
        let verified = match &route.verification {
            // The route's REQUIRED revocation source (§3 step 7). Consulted with the
            // credential's delegated_kid / issuer_kid / jti; an empty static list is
            // the explicit TTL-only posture, never a silent default.
            ClientVerification::DelegatedRequired(policy, resolve_actor, revocation) => {
                verify_delegated_response(
                    &response,
                    resolve_actor.as_ref(),
                    &expectation,
                    policy,
                    revocation.as_ref(),
                    params.now_unix,
                )?
            }
            // Trust-anchor lifecycle: the set is BOTH the root resolver and the
            // revocation source, evaluated at THIS request's `now` so a retiring root's
            // overlap window closes on time rather than at route-construction time.
            ClientVerification::DelegatedAnchored(policy, anchors) => {
                // Read the CURRENT set, so a refreshed manifest that revoked a root
                // takes effect on the next request rather than the next restart.
                verify_delegated_response_anchored(
                    &response,
                    &expectation,
                    policy,
                    &anchors.load(),
                    params.now_unix,
                )?
            }
        };

        // The request id the PROXY signed, not the one the server echoed. The plain
        // reply is addressed to the local client's outstanding call, and taking the id
        // from the response body would let the server redirect the answer.
        let request_id = id.clone().unwrap_or(Value::Null);

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
                let kind = match classify_result(result) {
                    ResultClass::Terminal => ResponseKind::Success,
                    ResultClass::InputRequired => {
                        // Three-way contract: a reply that announces itself
                        // non-terminal and then carries no usable `requestState` is
                        // MALFORMED, not terminal — an answer leg could never be
                        // honoured, so failing closed is the only honest outcome.
                        let state = continuation_state(&response.body)?.ok_or(
                            ProxyError::FailedClosed(HttpProfileError::MalformedEvidence(
                                "input-required reply carries no requestState",
                            )),
                        )?;
                        ResponseKind::InputRequired {
                            request_state: state,
                        }
                    }
                    // MCP 2026-07-28 closes the `resultType` set: unrecognized MUST be
                    // considered invalid. Never resolved to Terminal.
                    ResultClass::Unrecognized => {
                        return Err(ProxyError::FailedClosed(
                            HttpProfileError::UnrecognizedResultType,
                        ))
                    }
                };
                Ok(ProxyResponse {
                    plain_response: plain,
                    kind,
                })
            }
            // A VERIFIED rejection receipt: the request was provably denied. Convert the
            // signed receipt to a plain JSON-RPC error for the local client and report
            // the classification (fail closed — never returned as a success result).
            DelegatedOutcome::Rejection { bound, wire_code } => Ok(ProxyResponse {
                plain_response: plain_error_from_rejection(&request_id),
                kind: ResponseKind::VerifiedRejection { wire_code, bound },
            }),
        }
    }

    /// Verify the signed bodyless 202 that acknowledges a one-way NOTIFICATION.
    ///
    /// The 202 states that the enforcement boundary authenticated and ACCEPTED the
    /// message — not that any action completed. A notification is not delivered until
    /// this verifies, so an unverifiable ack is a `ProxyError`, never a silent success.
    ///
    /// The route's PINNED root issuer is enforced here on the same coordinate the
    /// bodied path pins. A pin that governs replies and not one-way notifications is a
    /// control an operator configured and the proxy did not run: on a route in an
    /// org-wide anchor set, any sibling holding a non-revoked delegated key under any
    /// listed root could otherwise acknowledge this route's `notifications/cancelled`.
    fn verify_notification_ack(
        &self,
        route: &crate::route::Route,
        signed: &mcp_re_client_core::SignedRequest,
        response: &HttpResponse,
        params: &CallParams,
    ) -> Result<ProxyResponse, ProxyError> {
        let pin = route.expected_server_keyid.as_deref();
        match &route.verification {
            ClientVerification::DelegatedRequired(policy, resolve_actor, revocation) => {
                verify_delegated_accepted_202_pinned(
                    response,
                    signed.request(),
                    resolve_actor.as_ref(),
                    policy,
                    revocation.as_ref(),
                    pin,
                    params.now_unix,
                )?;
            }
            // The trust-anchor set is read at THIS message's `now`, exactly as the
            // bodied path reads it, so a manifest that revoked a root refuses the next
            // acknowledgement rather than the next restart.
            ClientVerification::DelegatedAnchored(policy, anchors) => {
                verify_delegated_accepted_202_anchored_pinned(
                    response,
                    signed.request(),
                    policy,
                    &anchors.load(),
                    pin,
                    params.now_unix,
                )?;
            }
        }
        Ok(ProxyResponse {
            // A notification has no reply. The plain JSON-RPC surface is empty rather
            // than a synthesized result the local client never asked for.
            plain_response: Value::Null,
            kind: ResponseKind::AcceptedNotification,
        })
    }
}

/// Convert a VERIFIED delegated rejection receipt to a PLAIN JSON-RPC error for the
/// local client (transparency: the client sees ordinary JSON-RPC, not an MCP-RE
/// field — the `mcp-re.*` classification is surfaced to the embedding layer via
/// [`ResponseKind::VerifiedRejection`], not to the client). The proxy has already
/// verified the receipt's signature, so this is a provable denial, not a guess.
fn plain_error_from_rejection(id: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": mcp_re_core::MCP_RE_JSON_RPC_ERROR_CODE,
            "message": "request rejected by the MCP-RE server",
        },
    })
}

/// Rebuild a PLAIN MCP response from a verified signed response: strip the
/// proxy-owned top-level `_meta` (the RFC 9421 response evidence block) from the
/// body, returning ordinary JSON-RPC.
/// The `id` is the one the PROXY signed, not the one the server echoed back: the reply
/// belongs to the local client's outstanding call, and reading it from the response
/// body would let a server address its answer to a different one.
///
/// A JSON-RPC `error` member is carried through. The serving path signs every bodied
/// backend reply with HTTP 200 — a JSON-RPC error from an MCP backend rides in that
/// 200 body — so rebuilding the reply from `result` alone reported a failed call as a
/// successful one returning `null`, dropped the reason, and emitted a message that was
/// neither a valid JSON-RPC result nor a valid error.
///
/// A body that is not a single JSON-RPC response object carrying EXACTLY ONE of
/// `result` / `error` fails closed. A signed reply is proof the server said this; it is
/// not proof the server said anything a client can act on, and every other shape — a
/// top-level array, a bare scalar, an empty `{"jsonrpc":"2.0","id":1}` envelope, both
/// members at once — has no reading under which "the call completed with result `null`"
/// is true. Defaulting them to a null result is the same defect as flattening an error
/// reply: a truthful-looking success the server never sent.
fn plain_response_from_verified(
    response_body: &[u8],
    request_id: &Value,
) -> Result<Value, ProxyError> {
    let mut object: Value =
        serde_json::from_slice(response_body).map_err(|_| ProxyError::MalformedRequest)?;
    if let Some(result) = object.get_mut("result").and_then(Value::as_object_mut) {
        result.remove("_meta");
    }
    let Some(top) = object.as_object_mut() else {
        return Err(ProxyError::FailedClosed(
            HttpProfileError::MalformedEvidence("verified reply is not a JSON-RPC object"),
        ));
    };
    top.remove("_meta");
    match (top.get("result"), top.get("error")) {
        (Some(_), Some(_)) => Err(ProxyError::FailedClosed(
            HttpProfileError::MalformedEvidence(
                "verified reply carries both a result and an error",
            ),
        )),
        (None, None) => Err(ProxyError::FailedClosed(
            HttpProfileError::MalformedEvidence(
                "verified reply carries neither a result nor an error",
            ),
        )),
        (None, Some(error)) => Ok(json!({
            "jsonrpc": "2.0",
            "id": request_id,
            "error": error.clone(),
        })),
        (Some(result), None) => Ok(json!({
            "jsonrpc": "2.0",
            "id": request_id,
            "result": result.clone(),
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A JSON-RPC error rides in the same HTTP 200 body an ordinary result does, so
    /// rebuilding the plain reply from `result` alone reported a failed call as a
    /// success returning null and dropped the reason with it.
    #[test]
    fn a_json_rpc_error_reply_is_carried_through_not_flattened_to_a_null_result() {
        let body = br#"{"jsonrpc":"2.0","id":"srv-1","error":{"code":-32601,"message":"method not found"}}"#;
        let plain = plain_response_from_verified(body, &json!("req-1")).expect("rebuild");

        assert_eq!(plain["error"]["code"], -32601);
        assert_eq!(plain["error"]["message"], "method not found");
        assert!(
            plain.get("result").is_none(),
            "an error reply must not also carry a result member"
        );
    }

    /// Carrying the error through is only half of it: the classification the local
    /// client reads must say the call failed. `classify_result` inspects `result`, and
    /// an error reply has none — an absent `result` classifies as Terminal, which is
    /// the success label. The signature verifies either way, so nothing downstream can
    /// recover the difference once the header has been written.
    #[test]
    fn a_verified_error_reply_is_classified_as_a_failed_call_not_a_success() {
        let body = br#"{"jsonrpc":"2.0","id":"srv-1","error":{"code":-32601,"message":"method not found"}}"#;
        let plain = plain_response_from_verified(body, &json!("req-1")).expect("rebuild");

        // The selection the serving path makes, on the reply it actually holds.
        let kind = match plain
            .get("error")
            .map(|e| e.get("code").and_then(Value::as_i64))
        {
            Some(code) => ResponseKind::CallFailed { code },
            None => match classify_result(plain.get("result")) {
                ResultClass::Terminal => ResponseKind::Success,
                _ => unreachable!("this fixture carries an error member"),
            },
        };

        assert!(
            matches!(kind, ResponseKind::CallFailed { code: Some(-32601) }),
            "an error reply must classify as CallFailed carrying the server's code, got {kind:?}"
        );
        assert!(
            !matches!(kind, ResponseKind::Success),
            "a failed call must never be announced to the local client as a success"
        );
    }

    /// The id belongs to the local client's outstanding call. Taking it from the
    /// response body would let a server address its answer to a different one.
    #[test]
    fn the_reply_carries_the_id_the_proxy_signed_not_the_one_the_server_echoed() {
        let body = br#"{"jsonrpc":"2.0","id":"server-chosen","result":{"ok":true}}"#;
        let plain = plain_response_from_verified(body, &json!("req-7")).expect("rebuild");
        assert_eq!(plain["id"], "req-7");
        assert_eq!(plain["result"]["ok"], true);
    }

    /// The proxy-owned response evidence block is stripped from both positions.
    #[test]
    fn the_proxy_owned_meta_is_stripped_from_the_plain_reply() {
        let body =
            br#"{"jsonrpc":"2.0","id":"s","_meta":{"a":1},"result":{"_meta":{"b":2},"ok":true}}"#;
        let plain = plain_response_from_verified(body, &json!(1)).expect("rebuild");
        assert!(plain.get("_meta").is_none());
        assert!(plain["result"].get("_meta").is_none());
        assert_eq!(plain["result"]["ok"], true);
    }

    /// The classification the success arm makes before handing a reply over. A
    /// non-terminal elicitation reported as `Success` is how an approval nobody gave
    /// reaches an application as a finished tool result.
    #[test]
    fn an_input_required_reply_does_not_classify_as_terminal() {
        // The discriminator VALUE comes from the profile's own constant, never a
        // literal: an open-coded copy is one more thing to drift, and the gate that
        // enforces that is exactly why this reads the way it does.
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":"s","result":{{"resultType":"{}","requestState":"st-1"}}}}"#,
            mcp_re_client_core::INPUT_REQUIRED_RESULT_TYPE
        );
        let body = body.as_bytes();
        let plain = plain_response_from_verified(body, &json!("req-1")).expect("rebuild");
        assert_eq!(
            classify_result(plain.get("result")),
            ResultClass::InputRequired
        );
        assert_eq!(
            continuation_state(body).expect("state"),
            Some("st-1".to_owned())
        );

        let terminal = br#"{"jsonrpc":"2.0","id":"s","result":{"ok":true}}"#;
        let plain = plain_response_from_verified(terminal, &json!("req-1")).expect("rebuild");
        assert_eq!(classify_result(plain.get("result")), ResultClass::Terminal);
    }

    /// The shapes next to the JSON-RPC-error one. Each used to fall through to
    /// `result: null` and classify Terminal, so a signed reply that is not a JSON-RPC
    /// response at all reached the local client as a completed tool call — the same
    /// defect as flattening an error reply, on its neighbours.
    #[test]
    fn a_reply_that_is_not_a_json_rpc_response_fails_closed() {
        for body in [
            // An envelope with neither member.
            br#"{"jsonrpc":"2.0","id":1}"#.as_slice(),
            // A batch array, a bare scalar, a bare string.
            br#"[{"jsonrpc":"2.0","id":1,"result":{}}]"#.as_slice(),
            br#"7"#.as_slice(),
            br#""ok""#.as_slice(),
            // Both members at once: no reading of this says the call completed.
            br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true},"error":{"code":-1}}"#.as_slice(),
        ] {
            let outcome = plain_response_from_verified(body, &json!("req-1"));
            assert!(
                matches!(outcome, Err(ProxyError::FailedClosed(_))),
                "{} must not be delivered as a success",
                String::from_utf8_lossy(body),
            );
        }
    }

    /// And the shape that IS a response still rebuilds, `_meta` stripped — the guard
    /// above refuses malformed evidence, not an ordinary empty result.
    #[test]
    fn an_ordinary_result_still_rebuilds() {
        let body = br#"{"jsonrpc":"2.0","id":"s","result":{}}"#;
        let plain = plain_response_from_verified(body, &json!(2)).expect("rebuild");
        assert_eq!(plain["id"], 2);
        assert_eq!(plain["result"], json!({}));
    }

    /// MCP 2026-07-28 closes the `resultType` set; an unknown one is never resolved
    /// to terminal, and the success arm turns it into a fail-closed error.
    #[test]
    fn an_unrecognized_result_type_is_never_terminal() {
        let body = br#"{"jsonrpc":"2.0","id":"s","result":{"resultType":"something_new"}}"#;
        let plain = plain_response_from_verified(body, &json!("req-1")).expect("rebuild");
        assert_eq!(
            classify_result(plain.get("result")),
            ResultClass::Unrecognized
        );
    }
}
