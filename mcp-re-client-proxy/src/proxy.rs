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
use mcp_re_client_core::response::verify_delegated_accepted_202_pinned;
use mcp_re_client_core::verify_delegated_response;
use mcp_re_client_core::CompositeResponseTrust;
use mcp_re_client_core::ExecutionContract;
use mcp_re_client_core::HttpProfileError;
use mcp_re_client_core::HttpResponse;
use mcp_re_client_core::RequestSigningInputs;
use mcp_re_client_core::ResponseExpectation;
use mcp_re_client_core::SignerSlot;
use mcp_re_core::SigningKey;
use serde_json::json;
use serde_json::Map;
use serde_json::Value;

use crate::verified_outcome::read_outcome;

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
    ///
    /// `execution` is the ADR-MCPRE-058 §10 contract the receipt carried. It is a
    /// field of this variant rather than something the embedder re-derives from the
    /// status, because the difference it names — a refusal that ran nothing versus one
    /// whose side effect a retry would perform a second time — is not recoverable from
    /// a status code, and 503 is the status clients retry.
    VerifiedRejection {
        wire_code: Option<String>,
        bound: bool,
        execution: ExecutionContract,
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

        // ABSENT `id` is what makes a JSON-RPC message a NOTIFICATION (§4.1), and both the
        // signer and the serving path classify on exactly that key's absence. `null` is not
        // the same thing: it is a PRESENT id, so defaulting to it turned every one-way
        // notification into a request the server dispatched to the backend and answered with
        // a bodied reply nothing was awaiting.
        let id = plain_request.get("id").cloned();
        let signed = self.sign_request(route, plain_request, params, id.as_ref())?;

        // Forward to the remote MCP-RE endpoint.
        let response = self
            .transport
            .round_trip(signed.request())
            .map_err(ProxyError::Transport)?;

        // A NOTIFICATION is answered with a signed bodyless 202, not a bodied reply, so it
        // takes its own verification path. Nothing below applies: there is no result to
        // classify and no body to rebuild. It carries no `ResponseExpectation` either —
        // a bodyless 202 has no response block to bind one to — so the route's pin is
        // passed to it directly.
        if id.is_none() {
            return self.verify_notification_ack(route, &signed, &response, params);
        }
        let verified = self.verify_reply(route, &signed, &response, params)?;

        // The request id the PROXY signed, not the one the server echoed. The plain
        // reply is addressed to the local client's outstanding call, and taking the id
        // from the response body would let the server redirect the answer.
        let request_id = id.unwrap_or(Value::Null);
        read_outcome(verified, &response, request_id)
    }

    /// Build the RFC 9421 signed request (or notification) this route sends.
    ///
    /// The shape follows the ID: a message with none is a NOTIFICATION and is signed as one,
    /// because both the signer and the serving path classify on exactly that key's absence.
    fn sign_request(
        &self,
        route: &crate::route::Route,
        plain_request: &Value,
        params: &CallParams,
        id: Option<&Value>,
    ) -> Result<mcp_re_client_core::SignedRequest, ProxyError> {
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
        let signed = match id {
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
        Ok(signed)
    }

    /// Verify the bound signed response under the route's REQUIRED profile.
    ///
    /// Configured profile = required profile: there is no cross-profile fallback, and both
    /// arms fail closed. ADR-MCPRE-052 delegated-signing is the only mode, so a
    /// delegated-signed success OR rejection receipt carrying the inline credential is what
    /// verifies; no direct-root, unsigned or object downgrade is accepted.
    ///
    /// The two variants differ ONLY in where the trust anchors come from, and the outcome
    /// handling is shared, so neither can drift into a laxer mapping.
    fn verify_reply(
        &self,
        route: &crate::route::Route,
        signed: &mcp_re_client_core::SignedRequest,
        response: &HttpResponse,
        params: &CallParams,
    ) -> Result<mcp_re_client_core::VerifiedDelegatedResponse, ProxyError> {
        // Verify the signed response bound to THIS request under the route's required
        // profile (configured profile = required profile). Fail closed on any failure;
        // no cross-profile fallback.
        //
        // ADR-MCPRE-052 delegated-signing (the only mode): a delegated-signed success OR
        // rejection receipt carrying the inline credential. No direct-root / unsigned /
        // object downgrade is accepted (both verify functions fail closed). The two
        // variants differ ONLY in where the trust anchors come from; the outcome
        // handling below is shared, so neither can drift into a laxer mapping.
        let mut expectation = ResponseExpectation::for_signed(signed);
        // The route's PINNED credential ISSUER, if it configured one: without it any
        // server whose delegated credential chains to a trusted root and is scoped to
        // this audience may answer for this route. The pin is the ISSUER and not the
        // response-signing kid, which rotates every TTL; `route.expected_server_keyid`
        // keeps its published name.
        if let Some(keyid) = &route.expected_server_keyid {
            expectation = expectation.with_expected_issuer_kid(keyid.clone());
        }
        let verified = match &route.verification {
            // The route's REQUIRED revocation source (§3 step 7). Consulted with the
            // credential's delegated_kid / issuer_kid / jti; an empty static list is
            // the explicit TTL-only posture, never a silent default.
            ClientVerification::DelegatedRequired(policy, resolve_actor, revocation) => {
                // Two genuinely different systems, composed into ONE trust authority
                // before the verifier sees them (MCPRE-172). The route's resolver takes
                // no `now` — that is the documented limitation of this variant, and why
                // an overlap window needs `DelegatedAnchored`.
                let resolve = |kid: &str, slot: SignerSlot, _now: i64| resolve_actor(kid, slot);
                let trust = CompositeResponseTrust::new(&resolve, revocation.as_ref());
                verify_delegated_response(response, &trust, &expectation, policy, params.now_unix)?
            }
            // Trust-anchor lifecycle: the set is BOTH the root resolver and the
            // revocation source, evaluated at THIS request's `now` so a retiring root's
            // overlap window closes on time rather than at route-construction time.
            ClientVerification::DelegatedAnchored(policy, anchors) => {
                // Read the CURRENT set, so a refreshed manifest that revoked a root
                // takes effect on the next request rather than the next restart.
                verify_delegated_response(
                    response,
                    &*anchors.load(),
                    &expectation,
                    policy,
                    params.now_unix,
                )?
            }
        };
        Ok(verified)
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
                let resolve = |kid: &str, slot: SignerSlot, _now: i64| resolve_actor(kid, slot);
                let trust = CompositeResponseTrust::new(&resolve, revocation.as_ref());
                verify_delegated_accepted_202_pinned(
                    response,
                    signed.request(),
                    &trust,
                    policy,
                    pin,
                    params.now_unix,
                )?;
            }
            // The trust-anchor set is read at THIS message's `now`, exactly as the
            // bodied path reads it, so a manifest that revoked a root refuses the next
            // acknowledgement rather than the next restart.
            ClientVerification::DelegatedAnchored(policy, anchors) => {
                verify_delegated_accepted_202_pinned(
                    response,
                    signed.request(),
                    &*anchors.load(),
                    policy,
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
/// local client. The proxy has already verified the receipt's signature, so this is a
/// provable denial, not a guess.
///
/// Transparency is about the CARRIER, not about withholding what the server said: the
/// local client still speaks ordinary JSON-RPC and never emits, parses or negotiates an
/// RFC 9421 field. The server's frozen wire code and its ADR-MCPRE-058 §10 execution /
/// retry contract ride in the ordinary `error.data` member, because the party that
/// decides whether to retry is the local agent and nothing else it can see distinguishes
/// a refusal that ran nothing from a post-dispatch failure whose side effect a retry
/// performs twice. A fixed generic error told it neither, so it re-invoked.
///
/// Only members the receipt actually carried are emitted. An absent `execution_status`
/// is a receipt that said nothing, and inventing `not_executed` for it would collapse
/// "unknown whether it ran" into "it did not run" at the one place that matters.
pub(crate) fn plain_error_from_rejection(
    id: &Value,
    wire_code: Option<&str>,
    execution: &ExecutionContract,
) -> Value {
    let mut mcp_re_error = serde_json::Map::new();
    if let Some(wire_code) = wire_code {
        mcp_re_error.insert("wire_code".into(), json!(wire_code));
    }
    for (name, value) in [
        ("execution_status", &execution.execution_status),
        ("retry_safety", &execution.retry_safety),
        ("continuation_status", &execution.continuation_status),
        ("retention_status", &execution.retention_status),
    ] {
        if let Some(value) = value {
            mcp_re_error.insert(name.into(), json!(value));
        }
    }
    // Class B: assembled as a map. Writing back through `error["data"]` panics unless
    // `error` is an object, which is a fact about a literal rather than anything the
    // assignment establishes.
    let mut error = serde_json::Map::new();
    error.insert(
        "code".to_owned(),
        json!(mcp_re_core::MCP_RE_JSON_RPC_ERROR_CODE),
    );
    error.insert(
        "message".to_owned(),
        json!("request rejected by the MCP-RE server"),
    );
    if !mcp_re_error.is_empty() {
        error.insert(
            "data".to_owned(),
            json!({ "mcp_re_error": Value::Object(mcp_re_error) }),
        );
    }
    let error = Value::Object(error);
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": error,
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
///
/// Bytes that are not JSON at all fail the same way, and for the same reason: the bytes
/// that failed to parse are the RESPONSE to an exchange the remote server has already
/// executed. Reporting that as a malformed REQUEST hands the caller a 4xx implying its
/// own message was bad and nothing ran, and a caller that "fixes" its request and
/// retries re-runs a side effect the server already performed.
pub(crate) fn plain_response_from_verified(
    response_body: &[u8],
    request_id: &Value,
) -> Result<Value, ProxyError> {
    let mut object: Value = serde_json::from_slice(response_body).map_err(|_| {
        ProxyError::FailedClosed(HttpProfileError::MalformedEvidence(
            "verified reply is not JSON",
        ))
    })?;
    if let Some(result) = object.get_mut("result").and_then(Value::as_object_mut) {
        result.remove("_meta");
    }
    let Some(top) = object.as_object_mut() else {
        return Err(ProxyError::FailedClosed(
            HttpProfileError::MalformedEvidence("verified reply is not a JSON-RPC object"),
        ));
    };
    top.remove("_meta");
    // A JSON-RPC response has no `method`. Its presence is what makes a permissive
    // union parser pick the REQUEST arm, so a reply carrying both a legal `result` and a
    // `method` becomes a server->client request the client's session dispatches —
    // sampling, elicitation, roots — over a channel MCP-RE profiles no carrier for, and
    // the call whose id was consumed never resolves. Refused rather than dropped, so all
    // three clients say the same thing about the same bytes.
    if top.contains_key("method") {
        return Err(ProxyError::FailedClosed(
            HttpProfileError::MalformedEvidence(
                "verified reply carries a top-level method; a JSON-RPC response has none",
            ),
        ));
    }
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
    use mcp_re_client_core::classify_result;
    use mcp_re_client_core::continuation_state;
    use mcp_re_client_core::ResultClass;

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
            // A legal `result` plus a top-level `method`. A permissive union parser —
            // which is what both SDKs hand this to — reads it as a server->client
            // REQUEST and dispatches sampling / elicitation / roots on the peer's
            // params, while the call whose id it consumed never resolves.
            br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true},"method":"sampling/createMessage","params":{"x":1}}"#.as_slice(),
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

    /// Bytes that are not JSON at all are a RESPONSE failure, not a caller error.
    ///
    /// Mapping them to `MalformedRequest` renders as HTTP 400 at the ambassador, whose
    /// own comment justifies that status with "raised entirely locally, before anything
    /// is signed or sent" — untrue here: the remote server has already executed the
    /// exchange. A caller that "fixes" its request and retries a 400 re-runs the side
    /// effect.
    #[test]
    fn an_unparseable_verified_reply_is_a_verification_failure_not_a_bad_request() {
        let outcome = plain_response_from_verified(b"not json at all", &json!("req-1"));
        assert!(
            matches!(outcome, Err(ProxyError::FailedClosed(_))),
            "an unreadable RESPONSE must not be reported as a malformed REQUEST, got {outcome:?}",
        );
        assert!(
            !matches!(outcome, Err(ProxyError::MalformedRequest)),
            "400 implies the request was never executed",
        );
    }

    /// The ADR-MCPRE-058 §10 contract must reach the party that decides whether to
    /// retry. A fixed generic error told the local agent nothing, so a post-dispatch
    /// 503 read as an ordinary outage and the retry re-executed the tool call.
    #[test]
    fn a_verified_rejection_carries_its_execution_contract_to_the_local_client() {
        let execution = ExecutionContract {
            execution_status: Some("possibly_executed".into()),
            retry_safety: Some("unsafe_without_reconciliation".into()),
            continuation_status: Some("consumed".into()),
            retention_status: None,
        };
        let plain = plain_error_from_rejection(
            &json!("req-1"),
            Some("mcp-re.upstream_unavailable"),
            &execution,
        );
        let data = &plain["error"]["data"]["mcp_re_error"];
        assert_eq!(data["wire_code"], "mcp-re.upstream_unavailable");
        assert_eq!(data["execution_status"], "possibly_executed");
        assert_eq!(data["retry_safety"], "unsafe_without_reconciliation");
        assert_eq!(data["continuation_status"], "consumed");
        assert!(
            data.get("retention_status").is_none(),
            "a member the receipt did not carry must not be invented"
        );
        // The plain reply is still ordinary JSON-RPC: the local client parses an error,
        // not an MCP-RE carrier field.
        assert_eq!(plain["jsonrpc"], "2.0");
        assert_eq!(plain["id"], "req-1");
        assert_eq!(
            plain["error"]["code"],
            mcp_re_core::MCP_RE_JSON_RPC_ERROR_CODE
        );
    }

    /// A receipt that stated nothing must not grow a disposition on the way through.
    /// Emitting `not_executed` for an absent `execution_status` would turn "unknown
    /// whether it ran" into "it did not run" at the one place that decides.
    #[test]
    fn an_unstated_contract_produces_no_invented_disposition() {
        let plain = plain_error_from_rejection(
            &json!(1),
            Some("mcp-re.request_signature_invalid"),
            &ExecutionContract::default(),
        );
        let data = &plain["error"]["data"]["mcp_re_error"];
        assert_eq!(data["wire_code"], "mcp-re.request_signature_invalid");
        assert!(data.get("execution_status").is_none());
        assert!(data.get("retry_safety").is_none());

        // And a receipt with no wire code either emits no `data` at all rather than an
        // empty object that reads as a statement.
        let bare = plain_error_from_rejection(&json!(1), None, &ExecutionContract::default());
        assert!(bare["error"].get("data").is_none());
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
