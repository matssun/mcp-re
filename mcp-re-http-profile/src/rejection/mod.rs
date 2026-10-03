// SPDX-License-Identifier: Apache-2.0
//! Signed rejection receipts (ADR-MCPRE-050 §Threat Model + §Resolved-owner
//! ruling 2/6, MCPRE-96). The FIRST signed-rejection implementation anywhere in
//! MCP-RE.
//!
//! A rejection is an ordinary signed HTTP response carrying a JSON-RPC error
//! body. Its trust properties:
//!
//! - the STABLE machine signal is the wire code at
//!   `error.data.mcp_re_error.wire_code` — a frozen `mcp-re.*` token;
//! - `error.message` is human-readable and is NEVER trusted or parsed;
//! - the body is protected by RFC 9530 `Content-Digest`, covered by an RFC 9421
//!   response `Signature` (label `mcp-re-response`);
//! - when request context exists the response binds the request via `;req`
//!   (a rejection spliced onto a different request fails); a rejection emitted
//!   before a request could be parsed is signed response-only;
//! - HTTP status is a signed routing hint only; the wire code is authoritative.
//!
//! Under `require_mcp_re` a client MUST treat an unsigned or unverifiable rejection as
//! untrusted. A client verifies a rejection through
//! `Verifier::verify_delegated_bound_response` (request context exists) or
//! `Verifier::verify_delegated_unbound_response` (it does not); a failure maps to its
//! client-local `mcp-re.rejection_unsigned` posture.

use serde_json::json;

/// What the boundary KNOWS about a refused exchange's effects, and the contract it
/// projects. A separate authority from how a body is framed and signed.
pub mod retry_contract;

/// The pre-ADR-MCPRE-052 direct-root emitters, kept only so the refusal of that mode
/// can be exercised. Absent from a product build; see the module's own documentation.
#[cfg(any(test, feature = "pre_052_fixtures"))]
pub mod pre_052_direct_root;

/// The cryptographic-floor verifier for those direct-root rejections, a negative-test
/// fixture on the same gate.
#[cfg(any(test, feature = "pre_052_fixtures"))]
pub mod pre_052_direct_root_verifier;

pub use retry_contract::retry_semantics;
pub use retry_contract::ExecutionDisposition;
use serde_json::Value;

use mcp_re_core::SigningKey;

use crate::block::ActorIdentity;
use crate::digest::content_digest_sha256;
use crate::error::HttpProfileError;
use crate::evidence::RequestEvidence;
use crate::message::HttpRequest;
use crate::message::HttpResponse;
use crate::sign::sign_delegated_response_full_with_owned_key;
use crate::sign::sign_delegated_response_unbound_with_owned_key;

/// The JSON-RPC error code MCP-RE rejections carry. The wire code in `data`,
/// not this integer, is the stable signal.
///
/// Allocated outside JSON-RPC's reserved band (`-32768..=-32000`), which MCP
/// 2026-07-28 §Error Codes partitions entirely between a legacy sub-range no new
/// implementation may draw from and a sub-range reserved for the MCP
/// specification itself. Mirrors [`mcp_re_core::wire::MCP_RE_JSON_RPC_ERROR_CODE`].
pub const JSON_RPC_ERROR_CODE: i64 = -31000;

/// A rejection reason: the stable frozen wire code plus a human-readable,
/// NON-authoritative message.
#[derive(Debug, Clone)]
pub struct RejectionReason {
    /// A frozen `mcp-re.*` wire code (typically `HttpProfileError::wire_code()`
    /// or `McpReError::wire_code()`).
    pub wire_code: &'static str,
    /// Human-readable diagnostic. NEVER trusted or parsed by clients.
    pub message: String,
    /// What is known about the exchange's effects, from the request machine.
    pub execution: ExecutionDisposition,
}

impl RejectionReason {
    /// A reason stating nothing beyond its wire code.
    pub fn new(wire_code: &'static str, message: impl Into<String>) -> Self {
        Self {
            wire_code,
            message: message.into(),
            execution: ExecutionDisposition::Unstated,
        }
    }

    /// The same reason, carrying what the request machine established about effects.
    pub fn with_execution(mut self, execution: ExecutionDisposition) -> Self {
        self.execution = execution;
        self
    }
}

/// Build the JSON-RPC error body bytes for a rejection. `id` echoes the
/// rejected request's id when known (else JSON `null`).
fn rejection_body(id: Value, reason: &RejectionReason) -> Vec<u8> {
    let mut mcp_re_error = json!({ "wire_code": reason.wire_code });
    // The retry contract is DERIVED — from the frozen token and the request machine's own
    // disposition — never assembled field by field at a call site. Independently-set
    // values can disagree, and the disagreement that matters here is an outcome the
    // client cannot recover from labelled retry-safe.
    if let Some(extra) = retry_semantics(reason.wire_code, reason.execution) {
        if let (Some(target), Some(extra)) = (mcp_re_error.as_object_mut(), extra.as_object()) {
            for (k, v) in extra {
                target.insert(k.clone(), v.clone());
            }
        }
    }
    let body = json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": JSON_RPC_ERROR_CODE,
            "message": reason.message,
            "data": { "mcp_re_error": mcp_re_error }
        }
    });
    // `Display` renders the same compact JSON as `to_vec`, and cannot fail.
    body.to_string().into_bytes()
}

/// Best-effort extraction of the JSON-RPC `id` from a request body (echoed into
/// the rejection). The body is UNVERIFIED, so only a JSON-RPC-legal id (string or
/// number) is echoed; a body that does not parse, or carries any other id, yields
/// `null` — the rejection is still valid, just uncorrelated.
fn request_id(request: &HttpRequest) -> Value {
    serde_json::from_slice::<Value>(&request.body)
        .ok()
        .and_then(|v| {
            v.get("id")
                .filter(|id| id.is_string() || id.is_number())
                .cloned()
        })
        .unwrap_or(Value::Null)
}

/// Build a **request-bound delegated** rejection (ADR-MCPRE-052 required mode,
/// MCPRE-122): the rejection is signed by the active DELEGATED key, carries the
/// inline delegation credential, and is bound via `;req` to `request` — used when
/// the request verified far enough to trust its hash but failed a later gate
/// (replay / revocation / policy / transport binding). It verifies through the
/// delegated chain (`Verifier::verify_delegated_bound_response`), never as a directly
/// root-signed response.
#[allow(clippy::too_many_arguments)]
pub fn build_delegated_rejection_with_owned_key(
    request: &HttpRequest,
    request_evidence: &RequestEvidence,
    reason: &RejectionReason,
    status: u16,
    server_signer: &ActorIdentity,
    server_delegation: &str,
    delegated_key: &SigningKey,
    delegated_kid: &str,
    created: i64,
    expires: i64,
) -> Result<HttpResponse, HttpProfileError> {
    let mut response = HttpResponse {
        status,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: rejection_body(request_id(request), reason),
    };
    sign_delegated_response_full_with_owned_key(
        &mut response,
        request,
        request_evidence,
        server_signer,
        server_delegation,
        delegated_key,
        delegated_kid,
        created,
        expires,
    )?;
    Ok(response)
}

/// Build a **preflight (unbound) delegated** rejection (ADR-MCPRE-052 required
/// mode, MCPRE-122): the request was malformed, invalidly signed, of the wrong
/// audience, or otherwise unverifiable, so no trustworthy request hash exists. The
/// rejection is still signed by the active DELEGATED key and carries the inline
/// credential — its signer chain is fully verifiable
/// (`verify_delegated_response_unbound`) — but it is response-only signed and does
/// NOT pretend to be bound to a valid request. When `received` is present its bytes
/// are recorded as a diagnostic digest (never a binding) and its id is echoed.
#[allow(clippy::too_many_arguments)]
pub fn build_delegated_rejection_preflight_with_owned_key(
    received: Option<&HttpRequest>,
    reason: &RejectionReason,
    status: u16,
    server_signer: &ActorIdentity,
    server_delegation: &str,
    delegated_key: &SigningKey,
    delegated_kid: &str,
    created: i64,
    expires: i64,
) -> Result<HttpResponse, HttpProfileError> {
    let id = received.map(request_id).unwrap_or(Value::Null);
    // Diagnostic ONLY: a digest of the received bytes so an operator can correlate,
    // explicitly not a trusted request binding (the response is signed unbound).
    let diagnostic = match received {
        Some(req) => RequestEvidence {
            digest_alg: "sha-256-received".into(),
            digest_value: content_digest_sha256(&req.body),
        },
        None => RequestEvidence {
            digest_alg: "none".into(),
            digest_value: String::new(),
        },
    };
    let mut response = HttpResponse {
        status,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: rejection_body(id, reason),
    };
    sign_delegated_response_unbound_with_owned_key(
        &mut response,
        server_signer,
        server_delegation,
        &diagnostic,
        delegated_key,
        delegated_kid,
        created,
        expires,
    )?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::pre_052_direct_root_verifier::verify_pre_052_direct_root_rejection_for_negative_test as verify_rejection;
    use crate::block::SignerSlot;
    use crate::policy::VerifierPolicy;
    use crate::verifier::Verifier;

    /// The indeterminate token must carry its retry contract explicitly.
    ///
    /// A client that reads only the HTTP status cannot tell "nothing happened" from
    /// "it may have happened"; retrying the second re-executes the action, and the
    /// retry's fresh nonce passes replay admission.
    #[test]
    fn the_indeterminate_rejection_states_that_a_retry_is_unsafe() {
        let reason = RejectionReason::new(
            mcp_re_core::McpReError::EvidenceRetentionIndeterminate.wire_code(),
            "retention failed after execution".to_owned(),
        );
        let body = rejection_body(serde_json::json!(1), &reason);
        let v: Value = serde_json::from_slice(&body).expect("body parses");
        let e = &v["error"]["data"]["mcp_re_error"];
        assert_eq!(e["wire_code"], "mcp-re.evidence_retention_indeterminate");
        assert_eq!(e["execution_status"], "possibly_executed");
        assert_eq!(e["retention_status"], "failed");
        assert_eq!(e["retry_safety"], "unsafe_without_reconciliation");
    }

    /// Every OTHER code keeps the exact body shape frozen vectors pin.
    #[test]
    fn an_ordinary_rejection_body_gains_no_new_fields() {
        let reason = RejectionReason::new("mcp-re.invalid_audience", "no".to_owned());
        let body = rejection_body(serde_json::json!(1), &reason);
        let v: Value = serde_json::from_slice(&body).expect("body parses");
        let e = v["error"]["data"]["mcp_re_error"]
            .as_object()
            .expect("object");
        assert_eq!(e.len(), 1, "only wire_code: {e:?}");
    }
    use super::*;

    pub(super) const CLIENT_SEED: [u8; 32] = [11u8; 32];
    pub(super) const SERVER_SEED: [u8; 32] = [22u8; 32];
    pub(super) const NOW: i64 = 1_700_000_100;
    pub(super) const CREATED: i64 = 1_700_000_000;
    pub(super) const EXPIRES: i64 = 1_700_000_300;

    pub(super) fn server_key() -> SigningKey {
        SigningKey::from_seed_bytes(&SERVER_SEED)
    }
    pub(super) fn client_key() -> SigningKey {
        SigningKey::from_seed_bytes(&CLIENT_SEED)
    }

    /// Slot-aware trust seam: the server key is trusted only for the Response
    /// slot, the client key only for the Request slot (MCPRE-100).
    pub(super) fn resolver() -> impl Fn(&str, SignerSlot) -> Option<crate::block::ResolvedActor> {
        move |key_id: &str, slot: SignerSlot| {
            let (role, key) = match (key_id, slot) {
                ("server-key-1", SignerSlot::Response) => ("server", server_key()),
                ("client-key-1", SignerSlot::Request) => ("client", client_key()),
                _ => return None,
            };
            Some(crate::block::ResolvedActor {
                identity: crate::block::ActorIdentity {
                    role: role.into(),
                    trust_domain: "example.com".into(),
                    subject: format!("did:example:{role}"),
                    keyid: key_id.into(),
                },
                verification_key: key.public_key(),
                slot,
            })
        }
    }

    pub(super) fn request() -> HttpRequest {
        // A received MCP-RE HTTP request always carries Content-Digest (it is a
        // required covered component), so a rejection can bind it via `;req`.
        let body = br#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{}}"#.to_vec();
        HttpRequest {
            method: "POST".into(),
            target_uri: "https://mcp.example.com/mcp".into(),
            headers: vec![
                ("Content-Type".into(), "application/json".into()),
                (
                    "Content-Digest".into(),
                    crate::digest::content_digest_sha256(&body),
                ),
            ],
            body,
        }
    }

    pub(super) fn reason() -> RejectionReason {
        RejectionReason::new(
            "mcp-re.invalid_audience",
            "audience did not match this verifier (do not trust this text)",
        )
    }

    #[test]
    fn unsigned_rejection_is_untrusted() {
        // A bare JSON-RPC error with no signature must not verify.
        let unsigned = HttpResponse {
            status: 403,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: rejection_body(serde_json::json!(7), &reason()),
        };
        assert!(verify_rejection(
            &unsigned,
            Some(&request()),
            &Verifier::new(&VerifierPolicy::default(), &resolver()),
            NOW
        )
        .is_err());
    }

    /// The id echoed into a signed response comes from an unverified body: only a string
    /// or a number survives, anything else is `null`.
    #[test]
    fn a_non_scalar_request_id_is_echoed_as_null() {
        let with_id = |id: &str| HttpRequest {
            method: "POST".into(),
            target_uri: "https://mcp.example.com/mcp".into(),
            headers: Vec::new(),
            body: format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"x"}}"#).into_bytes(),
        };
        assert_eq!(request_id(&with_id(r#"{"a":1}"#)), Value::Null);
        assert_eq!(request_id(&with_id("[1,2]")), Value::Null);
        assert_eq!(request_id(&with_id(r#""abc""#)), json!("abc"));
        assert_eq!(request_id(&with_id("7")), json!(7));
    }
}
