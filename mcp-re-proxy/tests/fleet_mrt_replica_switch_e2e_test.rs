//! MCPS-82 (#273) — ADR-MCPS-049 W1, proof (c): an MRT/elicitation continuation
//! SURVIVES a mid-continuation replica switch.
//!
//! ADR-MCPS-047 makes multi-round-trip continuation evidence STATELESS: the two
//! legs are ordinary signed draft-02 requests plus a cryptographic linkage carried
//! INSIDE the signed request preimage (the `continuation` binding). The serving
//! proxy holds no continuation state, so a continuation leg verifies on ANY
//! replica. The ADR-049 node-local-state audit records this as a confirmed
//! non-hazard; this test is the CI-gated proof that makes it executable rather than
//! merely argued (the third ceiling-lifting proof — one of the three gates on
//! MCPS-91).
//!
//! Topology — a two-replica fleet of INDEPENDENT serving `mcp-re-proxy` instances
//! (`replica_a`, `replica_b`), each its own `Proxy` over its own inner MCP server,
//! sharing NOTHING at the continuation layer. The client speaks the real
//! `mcp-re-client-core` draft-02 seam:
//!
//!   leg 1 (no continuation) -> REPLICA A  -> signed `InputRequiredResult`
//!   client verifies A's response, binds it into a signed continuation
//!   leg 2 (continuation)    -> REPLICA B  -> signed terminal result
//!
//! Replica B never saw leg 1, yet the continuation verifies and completes — because
//! the binding rides the signed preimage, not any server-side session. This proves
//! the MCP-S layer is replica-independent; inner-server D5 `requestState` affinity
//! is out of scope (MCPS-83 / ADR-049 clause 2).
//!
//! Unlike the replay (MCPS-81) and revocation (MCPS-86) proofs, replica-
//! independence of the continuation needs no shared cross-node store, so this runs
//! on every `bazel test //...` with no live infra (the fleet's Redis lane carries
//! only the first two proofs).

use mcp_re_client_core::build_signed_request_with_signer;
use mcp_re_client_core::verify_signed_response;
use mcp_re_client_core::Environment;
use mcp_re_client_core::RequestSigningInputs;
use mcp_re_client_core::ResponseExpectation;
use mcp_re_client_core::SignerPolicy;
use mcp_re_client_core::SoftwareSigner;
use mcp_re_core::build_mcp_mrt_continuation;
use mcp_re_core::classify_result;
use mcp_re_core::response_hash;
use mcp_re_core::AuthorizationBinding;
use mcp_re_core::InMemoryTrustResolver;
use mcp_re_core::ResultClass;
use mcp_re_core::SigningKey;
use mcp_re_core::CANONICALIZATION_ID_INT53_V1;
use mcp_re_core::REQUEST_META_KEY;
use serde_json::json;
use serde_json::Map;
use serde_json::Value;

const CLIENT_SIGNER: &str = "did:example:agent-1";
const CLIENT_KEY_ID: &str = "key-1";
const SERVER: &str = "did:example:server-1";
const SERVER_KEY_ID: &str = "server-key-1";
const AUDIENCE: &str = "did:example:server-1";
const ON_BEHALF_OF: &str = "did:example:user-1";
const ISSUED_AT: &str = "2026-05-28T20:00:00Z";
const EXPIRES_AT: &str = "2026-05-28T20:05:00Z";
// Distinct, equal-length base64url nonces — one fresh nonce per leg (a continuation
// leg MUST carry a fresh nonce; it buys no replay exemption).
const NONCE_LEG_1: &str = "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA";
const NONCE_LEG_2: &str = "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MB";
// A valid 32-byte b64url digest for the opaque-bytes authorization binding.
const DIGEST: &str = "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";
// The opaque SEP-2322 resume payload echoed by the elicitation — untrusted app data.
const REQUEST_STATE: &str = "eyJzdGVwIjoxfQ";
const SKEW: i64 = 300;

fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[1u8; 32])
}
fn server_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[2u8; 32])
}
fn now() -> i64 {
    mcp_re_core::parse_rfc3339_utc(ISSUED_AT).expect("parse issued_at") + 60
}

/// The inbound resolver every replica shares — maps the client SIGNER to its public
/// key. Sharing the resolver is the point: any replica admits the same client
/// signature, a prerequisite for a continuation to verify on a sibling.
fn inbound_resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(CLIENT_SIGNER, CLIENT_KEY_ID, client_key().public_key());
    r
}
/// The client's outbound resolver — maps the shared SERVER identity to its response-
/// signing key. Every replica signs responses as the SAME server identity (a fleet
/// serves one logical server), so one entry verifies both legs.
fn server_resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SERVER, SERVER_KEY_ID, server_key().public_key());
    r
}

/// One serving replica. Its inner MCP server branches on the ELICITATION-ANSWER app
/// field, not on any MCP-RE binding: the proxy scrubs `REQUEST_META_KEY` (which
/// carries the `continuation`) before forwarding, so — exactly like a real MCP
/// server — the inner sees only `arguments.inputResponses`. No answer yet ->
/// elicit; answer present -> complete. The branch is on request content, so every
/// replica runs identical, stateless server code.
fn replica() -> mcp_re_proxy::Proxy {
    let inner = |request: &[u8]| -> Vec<u8> {
        let value: Value = serde_json::from_slice(request).expect("inner parses forwarded request");
        let id = value.get("id").cloned().unwrap_or(Value::Null);
        let answered = !value["params"]["arguments"]["inputResponses"].is_null();
        let result = if answered {
            // Terminal: the elicitation was answered, complete the exchange.
            json!({ "content": [ { "type": "text", "text": "deleted 3 files" } ] })
        } else {
            // Non-terminal `InputRequiredResult` (SEP-2322), carrying the opaque
            // requestState the client echoes back on the answer leg.
            json!({
                "resultType": "inputRequired",
                "inputRequests": { "confirm": { "type": "elicitation", "message": "Delete 3 files?" } },
                "requestState": REQUEST_STATE
            })
        };
        serde_json::to_vec(&json!({ "jsonrpc": "2.0", "id": id, "result": result }))
            .expect("serialize inner response")
    };
    mcp_re_proxy::Proxy::new(
        server_key(),
        SERVER,
        SERVER_KEY_ID,
        Box::new(inbound_resolver()),
        AUDIENCE,
        SKEW,
        Box::new(inner),
    )
}

/// Sign a draft-02 `tools/call` via the real client-core seam, optionally binding a
/// continuation (the answer leg). Returns the wire bytes plus the `request_hash`
/// (which binds the response, and is the `previous_request_hash` a later
/// continuation commits to).
fn sign_call(
    id: &str,
    tool: &str,
    arguments: Value,
    nonce: &str,
    continuation: Option<mcp_re_core::Continuation>,
) -> mcp_re_client_core::SignedRequest {
    let signer = SoftwareSigner::new(client_key(), CLIENT_SIGNER, CLIENT_KEY_ID);
    let policy = SignerPolicy::new(CLIENT_SIGNER, Environment::Production, true);
    let binding = AuthorizationBinding::OpaqueBytes {
        digest_alg: "sha256".to_string(),
        digest_value: DIGEST.to_string(),
    };
    let mut inputs = RequestSigningInputs::with_default_canonicalization(
        CLIENT_SIGNER,
        CLIENT_KEY_ID,
        ON_BEHALF_OF,
        AUDIENCE,
        binding,
        nonce,
        ISSUED_AT,
        EXPIRES_AT,
    );
    if let Some(c) = continuation {
        inputs = inputs.with_continuation(c);
    }
    let mut params = Map::new();
    params.insert("name".to_string(), json!(tool));
    params.insert("arguments".to_string(), arguments);
    build_signed_request_with_signer(&json!(id), "tools/call", params, &inputs, &signer, &policy)
        .expect("client-core signs draft-02")
}

fn is_error(bytes: &[u8]) -> bool {
    serde_json::from_slice::<Value>(bytes)
        .ok()
        .and_then(|v| v.get("error").cloned())
        .is_some()
}

/// Proof (c): a continuation begun on replica A completes on a FRESH replica B.
#[test]
fn continuation_begun_on_replica_a_completes_on_replica_b() {
    // Two INDEPENDENT replicas — separate `Proxy` instances, own inner servers, no
    // shared continuation state. `replica_b` is constructed knowing nothing of A.
    let replica_a = replica();
    let replica_b = replica();

    // Leg 1 -> replica A: an ordinary first-round call (no continuation).
    let leg1 = sign_call(
        "req-1",
        "delete_files",
        json!({ "paths": ["a", "b", "c"] }),
        NONCE_LEG_1,
        None,
    );
    let resp1 = replica_a.handle(leg1.wire_bytes(), now());
    assert!(
        !is_error(&resp1),
        "replica A must serve the first-round call, got: {}",
        String::from_utf8_lossy(&resp1)
    );

    // The client verifies A's signed response and binds to its request hash — the
    // real `InputRequiredResult` it will answer.
    let expectation =
        ResponseExpectation::new(leg1.request_hash(), CANONICALIZATION_ID_INT53_V1)
            .with_expected_server_signer(SERVER);
    verify_signed_response(&resp1, &server_resolver(), &expectation)
        .expect("replica A's InputRequiredResult verifies and binds to leg 1");

    let resp1_obj: Value = serde_json::from_slice(&resp1).expect("parse leg-1 response");
    assert_eq!(
        classify_result(&resp1_obj["result"]),
        ResultClass::InputRequired,
        "leg 1 must yield a non-terminal InputRequiredResult"
    );
    // The proxy relays the inner's requestState through the signed envelope.
    assert_eq!(resp1_obj["result"]["requestState"], REQUEST_STATE);

    // The two hashes the client holds after verifying the InputRequiredResult
    // (ADR-MCPS-047 / D4): the request that produced it, and the response itself.
    let previous_request_hash = leg1.request_hash().to_string();
    let input_required_response_hash =
        response_hash(&resp1_obj).expect("hash the verified InputRequiredResult");

    // Leg 2 -> replica B: the signed continuation, carrying the elicitation answer
    // and the binding INSIDE the signed preimage. Fresh nonce; B has never seen A.
    let leg2 = sign_call(
        "req-2",
        "delete_files",
        json!({ "paths": ["a", "b", "c"], "inputResponses": { "confirm": true }, "requestState": REQUEST_STATE }),
        NONCE_LEG_2,
        Some(build_mcp_mrt_continuation(
            &previous_request_hash,
            &input_required_response_hash,
        )),
    );
    let resp2 = replica_b.handle(leg2.wire_bytes(), now());
    assert!(
        !is_error(&resp2),
        "replica B (which never saw leg 1) must complete the continuation, got: {}",
        String::from_utf8_lossy(&resp2)
    );

    // B's terminal response verifies and binds to leg 2 — the continuation survived
    // the replica switch.
    let expectation2 =
        ResponseExpectation::new(leg2.request_hash(), CANONICALIZATION_ID_INT53_V1)
            .with_expected_server_signer(SERVER);
    verify_signed_response(&resp2, &server_resolver(), &expectation2)
        .expect("replica B's terminal response verifies and binds to leg 2");

    let resp2_obj: Value = serde_json::from_slice(&resp2).expect("parse leg-2 response");
    assert_eq!(
        classify_result(&resp2_obj["result"]),
        ResultClass::Terminal,
        "leg 2 on replica B must complete the exchange"
    );
    assert_eq!(resp2_obj["result"]["content"][0]["text"], "deleted 3 files");
}

/// Negative: a continuation whose binding is TAMPERED after signing is rejected by
/// the sibling replica. The binding rides the signed preimage, so mutating a hash
/// breaks the signature — B fails closed with no bespoke continuation-state check.
/// (Replica B does not rely on server-local continuation state carried over from
/// replica A; it verifies the signed continuation evidence present on the request.
/// Semantic validation of the application-level pending elicitation remains a
/// server/policy concern, out of scope for this MCP-S-layer proof — tampering with
/// the signed evidence is what the signature stops here.)
#[test]
fn tampered_continuation_is_rejected_on_the_sibling_replica() {
    let replica_a = replica();
    let replica_b = replica();

    let leg1 = sign_call("req-1", "delete_files", json!({}), NONCE_LEG_1, None);
    let resp1 = replica_a.handle(leg1.wire_bytes(), now());
    assert!(!is_error(&resp1), "replica A serves leg 1");
    let resp1_obj: Value = serde_json::from_slice(&resp1).expect("parse leg-1 response");
    let previous_request_hash = leg1.request_hash().to_string();
    let input_required_response_hash =
        response_hash(&resp1_obj).expect("hash the InputRequiredResult");

    let leg2 = sign_call(
        "req-2",
        "delete_files",
        json!({ "inputResponses": { "confirm": true }, "requestState": REQUEST_STATE }),
        NONCE_LEG_2,
        Some(build_mcp_mrt_continuation(
            &previous_request_hash,
            &input_required_response_hash,
        )),
    );

    // Swap the response-hash binding AFTER signing to a different well-formed hash:
    // the structure still validates but the signed preimage no longer matches.
    let mut object = leg2.object().clone();
    object["params"]["_meta"][REQUEST_META_KEY]["continuation"]["input_required_response_hash"] =
        json!(previous_request_hash);
    let tampered = serde_json::to_vec(&object).expect("serialize tampered continuation");

    let resp2 = replica_b.handle(&tampered, now());
    assert!(
        is_error(&resp2),
        "replica B must reject a tampered continuation, got: {}",
        String::from_utf8_lossy(&resp2)
    );
}
