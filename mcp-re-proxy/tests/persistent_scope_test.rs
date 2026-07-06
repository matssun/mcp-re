//! MCPS-065 (MCP-RE-EPIC-P6.6B) — Phase-5 authorization over the LONG-LIVED
//! `mcp-re-demo-server`'s three scoped tools, through a real [`Proxy`] fronting a
//! single [`PersistentSubprocessInner`].
//!
//! The demo server (#3956) is MCP-RE-UNAWARE: it publishes each tool's intended
//! scope as inert `annotations.net.mcp-re.intendedScope` metadata and enforces
//! NOTHING. Scope enforcement is the PROXY + Phase-5 policy's job (ADR-MCPS-013):
//! the reference profile binds a grant to a tool NAME (one `GrantedOperation`
//! per tool), and the evaluator denies — BEFORE dispatch — any `tools/call`
//! whose tool the presented grant does not cover.
//!
//! ## The three scopes, realized as reference grants
//!   * `echo`        — **public**:    a minimal baseline grant covering `echo`.
//!   * `list_items`  — **protected**: a grant covering `list_items`.
//!   * `reset_items` — **admin**:     NO grant is ever minted for it, so every
//!                                    call is denied (`authorization_scope_denied`).
//! "Public needs no [special] grant" is the baseline `echo` scope; presenting it
//! for `list_items` exceeds that scope, so it is denied. The reference profile
//! always requires a presented, hash-bound artifact (the evaluator denies a bare
//! call with `authorization_block_missing`), so the public scope is the smallest
//! grant, not the absence of one.
//!
//! ## Why denial is proven via zero `inner_request_forwarded`
//! The inner is PERSISTENT: it is spawned + initialized ONCE at construction, so
//! `inner_spawned` has already fired before any tool call and is NOT the
//! deny-before-dispatch signal. The proxy emits `inner_request_forwarded` from
//! inside `dispatch_and_sign` — the path a denial short-circuits. So a denied
//! request adds ZERO `inner_request_forwarded`, while the count rises by exactly
//! one per ALLOWED call. The single session stays alive across a denial: a
//! subsequent authorized call on the SAME proxy/inner still succeeds.
//!
//! The demo binary is delivered via Bazel runfiles (`data` dep) and resolved via
//! the `$(rlocationpath ...)` env var — no hardcoded path, no cargo.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;

use mcp_re_core::b64url_encode;
use mcp_re_core::request_hash;
use mcp_re_core::verify_response;
use mcp_re_core::InMemoryTrustResolver;
use mcp_re_core::SigningKey;
use mcp_re_host::HostSigner;
use mcp_re_policy::mint_reference_grant;
use mcp_re_policy::AuthorizationProfile;
use mcp_re_policy::GrantedOperation;
use mcp_re_policy::InMemoryRevocationSource;
use mcp_re_policy::PolicyEvaluator;
use mcp_re_policy::ReferenceGrantSpec;
use mcp_re_policy::ReferenceProfile;
use mcp_re_policy::AUTHORIZATION_META_KEY;
use mcp_re_policy::REFERENCE_PROFILE_ID;
use mcp_re_proxy::InnerLaunchConfig;
use mcp_re_proxy::InnerLogEvent;
use mcp_re_proxy::InnerLogSink;
use mcp_re_proxy::InnerServer;
use mcp_re_proxy::PersistentSubprocessInner;
use mcp_re_proxy::Proxy;
use serde_json::json;
use serde_json::Map;
use serde_json::Value;

const SIGNER: &str = "did:example:agent-1";
const SIGNER_KEY_ID: &str = "key-1";
const SERVER: &str = "did:example:server-1";
const SERVER_KEY_ID: &str = "server-key-1";
const ISSUER: &str = "did:example:authority-1";
const ISSUER_KEY_ID: &str = "authority-key-1";
const AUDIENCE: &str = "did:example:server-1";
const ON_BEHALF_OF: &str = "did:example:user-1";

// Request envelope freshness window.
const ISSUED_AT: &str = "2026-05-28T20:00:00Z";
const EXPIRES_AT: &str = "2026-05-28T20:05:00Z";
// Grant validity window (comfortably brackets `now()`).
const GRANT_NOT_BEFORE: &str = "2026-05-28T20:00:00Z";
const GRANT_EXPIRES_AT: &str = "2026-05-28T21:00:00Z";
const SKEW: i64 = 300;

const METHOD: &str = "tools/call";
const TOOL_ECHO: &str = "echo";
const TOOL_LIST_ITEMS: &str = "list_items";
const TOOL_RESET_ITEMS: &str = "reset_items";

fn signer_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[1u8; 32])
}
fn server_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[2u8; 32])
}
fn issuer_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[42u8; 32])
}
fn now() -> i64 {
    mcp_re_core::parse_rfc3339_utc(ISSUED_AT).expect("parse") + 60
}

/// A resolver holding BOTH the request-signer key (Core verification) and the
/// grant-issuer key (policy signature check) — the proxy reuses one resolver.
fn inbound_resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SIGNER, SIGNER_KEY_ID, signer_key().public_key());
    r.insert(ISSUER, ISSUER_KEY_ID, issuer_key().public_key());
    r
}
fn server_resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SERVER, SERVER_KEY_ID, server_key().public_key());
    r
}
fn host() -> HostSigner {
    HostSigner::new(signer_key(), SIGNER, SIGNER_KEY_ID)
}

/// The canonical signed bytes of a reference grant covering exactly `tools`
/// (one [`GrantedOperation`] per tool name, no argument constraint). This is the
/// per-scope artifact: an `echo`-only grant is the public baseline; a
/// `list_items` grant is the protected scope.
fn grant_artifact(tools: &[&str], revocation_id: &str) -> Vec<u8> {
    let operations = tools
        .iter()
        .map(|tool| GrantedOperation {
            method: METHOD.to_string(),
            tool: (*tool).to_string(),
            arguments: None,
        })
        .collect();
    let spec = ReferenceGrantSpec {
        issuer: ISSUER.to_string(),
        grantee: SIGNER.to_string(),
        subject: ON_BEHALF_OF.to_string(),
        audience: AUDIENCE.to_string(),
        operations,
        not_before: GRANT_NOT_BEFORE.to_string(),
        expires_at: GRANT_EXPIRES_AT.to_string(),
        revocation_id: revocation_id.to_string(),
    };
    mint_reference_grant(&spec, &issuer_key(), ISSUER_KEY_ID).expect("mint reference grant")
}

/// The `authorization_hash` binding a request to `artifact`
/// (`sha256(canonical artifact bytes)`).
fn authorization_hash(artifact: &[u8]) -> String {
    ReferenceProfile::new()
        .expected_authorization_hash(artifact)
        .expect("authorization_hash")
}

/// Sign a `tools/call` for `tool` carrying `arguments`, attaching `artifact` as
/// the `.authorization` block and binding the request to its hash.
fn signed_call(nonce: &str, tool: &str, arguments: Value, artifact: &[u8]) -> Vec<u8> {
    let mut params = Map::new();
    params.insert("name".to_string(), json!(tool));
    params.insert("arguments".to_string(), arguments);
    let mut meta = Map::new();
    meta.insert(
        AUTHORIZATION_META_KEY.to_string(),
        json!({
            "profile": REFERENCE_PROFILE_ID,
            "artifact": b64url_encode(artifact),
        }),
    );
    params.insert("_meta".to_string(), Value::Object(meta));

    host()
        .sign_request(
            &Value::String(format!("req-{nonce}")),
            METHOD,
            params,
            ON_BEHALF_OF,
            AUDIENCE,
            &authorization_hash(artifact),
            nonce,
            ISSUED_AT,
            EXPIRES_AT,
        )
        .expect("host signs tools/call")
}

/// Resolve a runfiles-relative path delivered via `$(rlocationpath ...)`.
fn resolve_runfile(env_key: &str) -> PathBuf {
    mcp_re_test_paths::resolve_runfile(env_key)
}

fn demo_server_command() -> Vec<String> {
    vec![resolve_runfile("DEMO_SERVER_BIN").to_string_lossy().into_owned()]
}

/// A capturing lifecycle sink shared by the inner (spawn/exit/stderr) and the
/// proxy (request_forwarded/response_signed): one counter sees the whole
/// lifecycle, so `inner_request_forwarded` is the deny-before-dispatch probe.
#[derive(Default)]
struct RecordingSink {
    tags: Mutex<Vec<String>>,
}
impl InnerLogSink for RecordingSink {
    fn log(&self, _inner_identity: &str, event: &InnerLogEvent) {
        self.tags.lock().expect("lock").push(event.tag().to_string());
    }
    fn log_stderr(&self, _inner_identity: &str, _captured: &[u8]) {}
}
impl RecordingSink {
    fn count(&self, tag: &str) -> usize {
        self.tags.lock().expect("lock").iter().filter(|t| *t == tag).count()
    }
}

/// A transparent decorator over an [`InnerServer`] that records every forwarded
/// request frame (post strip/inject) before delegating verbatim. Observation
/// seam only: it adds no behavior, so the wrapped persistent inner is driven
/// exactly as in production.
struct RecordingInner {
    delegate: Box<dyn InnerServer>,
    forwarded: Arc<Mutex<Vec<Vec<u8>>>>,
}
impl InnerServer for RecordingInner {
    fn dispatch(&self, request: &[u8]) -> Vec<u8> {
        self.forwarded.lock().expect("lock").push(request.to_vec());
        self.delegate.dispatch(request)
    }
}

fn error_message(bytes: &[u8]) -> String {
    let value: Value = serde_json::from_slice(bytes).expect("parse");
    value["error"]["message"].as_str().unwrap_or_default().to_string()
}

/// Assert `response` is a successful, request-hash-bound signed result and
/// return its parsed value for further inspection.
fn assert_signed_success(request: &[u8], response: &[u8]) -> Value {
    let expected_hash =
        request_hash(&serde_json::from_slice::<Value>(request).expect("req json")).expect("hash");
    let parsed: Value = serde_json::from_slice(response).expect("parse response");
    assert!(parsed.get("error").is_none(), "unexpected error: {parsed}");
    verify_response(response, &server_resolver(), &expected_hash)
        .expect("authorized response verifies + binds to request_hash");
    parsed
}

/// The MCPS-065 proof: ALL FOUR scope cases over ONE long-lived inner session,
/// with the deny-before-dispatch property proven by `inner_request_forwarded`
/// counts and the session surviving every denial.
#[test]
fn phase5_scopes_over_one_persistent_session() {
    let sink = Arc::new(RecordingSink::default());
    let inner = PersistentSubprocessInner::with_log_sink(
        &demo_server_command(),
        InnerLaunchConfig::new(),
        Arc::clone(&sink) as _,
    )
    .expect("spawn + initialize the persistent inner ONCE");

    // The persistent inner is already spawned + initialized: `inner_spawned`
    // fired at construction, so it is NOT the deny-before-dispatch signal.
    assert_eq!(sink.count("inner_spawned"), 1, "one persistent process at startup");
    assert_eq!(
        sink.count("inner_request_forwarded"),
        0,
        "no tool call has been dispatched yet",
    );

    let forwarded = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let recording = RecordingInner {
        delegate: Box::new(inner),
        forwarded: Arc::clone(&forwarded),
    };

    let mut evaluator = PolicyEvaluator::new();
    evaluator.register(Box::new(ReferenceProfile::new()));

    let proxy = Proxy::new(
        server_key(),
        SERVER,
        SERVER_KEY_ID,
        Box::new(inbound_resolver()),
        AUDIENCE,
        SKEW,
        Box::new(recording),
    )
    .with_log_sink(Arc::clone(&sink) as _)
    .with_policy_enforcement(evaluator, Box::new(InMemoryRevocationSource::new()));

    // Per-scope grants. The admin tool (`reset_items`) is covered by NONE.
    let public_grant = grant_artifact(&[TOOL_ECHO], "rev-public");
    let protected_grant = grant_artifact(&[TOOL_LIST_ITEMS], "rev-protected");

    // ---- Case 1: PUBLIC `echo` succeeds with the baseline (echo) grant. ----
    let req = signed_call("public-echo", TOOL_ECHO, json!({ "message": "hello" }), &public_grant);
    let response = proxy.handle(&req, now());
    let parsed = assert_signed_success(&req, &response);
    assert_eq!(
        parsed["result"]["content"][0]["text"].as_str(),
        Some("hello"),
        "echo must round-trip its message",
    );
    assert_eq!(sink.count("inner_request_forwarded"), 1, "echo reached the inner");

    // ---- Case 2: PROTECTED `list_items` succeeds WITH its matching grant. ----
    let req = signed_call("protected-ok", TOOL_LIST_ITEMS, json!({}), &protected_grant);
    let response = proxy.handle(&req, now());
    let parsed = assert_signed_success(&req, &response);
    assert!(
        parsed["result"]["structuredContent"]["items"].is_array(),
        "list_items returns the in-memory item set: {parsed}",
    );
    assert_eq!(sink.count("inner_request_forwarded"), 2, "list_items reached the inner");

    // ---- Case 3: PROTECTED `list_items` DENIED without a matching grant. ----
    // Presenting only the public (echo) grant: list_items exceeds that scope. The
    // denial is rendered BEFORE dispatch — `inner_request_forwarded` does NOT
    // rise — and never tears down the session.
    let before = sink.count("inner_request_forwarded");
    let req = signed_call("protected-deny", TOOL_LIST_ITEMS, json!({}), &public_grant);
    let response = proxy.handle(&req, now());
    assert_eq!(
        error_message(&response),
        "mcp-re.authorization_scope_denied",
        "list_items with only the public grant must be scope-denied",
    );
    assert_eq!(
        sink.count("inner_request_forwarded"),
        before,
        "a denied request must NOT be forwarded to the inner",
    );

    // ---- Case 4: ADMIN `reset_items` DENIED (no grant covers it). ----
    let before = sink.count("inner_request_forwarded");
    let req = signed_call("admin-deny", TOOL_RESET_ITEMS, json!({}), &protected_grant);
    let response = proxy.handle(&req, now());
    assert_eq!(
        error_message(&response),
        "mcp-re.authorization_scope_denied",
        "reset_items is covered by no grant and must be scope-denied",
    );
    assert_eq!(
        sink.count("inner_request_forwarded"),
        before,
        "the admin denial must NOT be forwarded to the inner",
    );

    // ---- Session survives the denials: a fresh authorized call still works. ----
    // If a denial had torn down the persistent inner, this dispatch would
    // fail-closed instead of returning the echoed message.
    let req = signed_call("public-echo-2", TOOL_ECHO, json!({ "message": "still-alive" }), &public_grant);
    let response = proxy.handle(&req, now());
    let parsed = assert_signed_success(&req, &response);
    assert_eq!(
        parsed["result"]["content"][0]["text"].as_str(),
        Some("still-alive"),
        "the persistent session survives denials: a later authorized call succeeds",
    );

    // Exactly three ALLOWED calls were forwarded; the two denials added nothing.
    assert_eq!(
        sink.count("inner_request_forwarded"),
        3,
        "only the three authorized calls were forwarded over the one session",
    );
    assert_eq!(sink.count("inner_response_signed"), 3, "three signed responses");
    // Still ONE persistent process — the denials never spawned or killed anything.
    assert_eq!(sink.count("inner_spawned"), 1, "still the single persistent process");
    assert_eq!(sink.count("inner_exited"), 0, "session alive (not yet torn down)");

    // Every forwarded frame corresponds to an ALLOWED call (3 total); no denied
    // request ever reached the observation seam.
    assert_eq!(
        forwarded.lock().expect("lock").len(),
        3,
        "the inner observed exactly the three authorized frames",
    );

    // Clean teardown: dropping the proxy drops the inner, tearing the single
    // session down exactly once.
    drop(proxy);
    assert_eq!(
        sink.count("inner_exited"),
        1,
        "the single persistent session tore down cleanly exactly once",
    );
}
