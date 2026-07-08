//! Integration test for the demo delegated-authorization layer (MCPS-048,
//! MCP-RE-EPIC-P6 Child Issue 4).
//!
//! These tests drive the EXISTING `mcp-re-proxy` serving path with Phase 5
//! (ADR-MCPS-013) policy enforcement turned on, while the proxy launches the REAL
//! `mcp-re-demo-fileserver` binary as its inner stdio subprocess. They prove the
//! allow-vs-deny decision is rendered BEFORE the inner server is reached:
//!
//!   1. a validly signed AND authorized `list_files` on the ONE allowed path →
//!      succeeds end-to-end (signed, request-hash-bound response);
//!   2. a validly signed but UNAUTHORIZED request (a different / demo-root-
//!      escaping `path`) → `mcp-re.authorization_scope_denied`, and the inner
//!      fileserver is never spawned;
//!   3. an `authorization_hash` that does not bind the attached artifact →
//!      `mcp-re.authorization_hash_mismatch`, inner never spawned;
//!   4. an EXPIRED grant (`now` past its `expires_at`) → `mcp-re.authorization_expired`,
//!      inner never spawned.
//!
//! "Denied never reaches the inner" is proven through the proxy's own lifecycle
//! signals: the capturing [`InnerLogSink`] records `inner_spawned` only when the
//! subprocess is actually launched (inside `dispatch_and_sign`, which a denial
//! short-circuits). A denied request therefore yields ZERO `inner_*` events.
//!
//! The inner binary + the `demo_root/` fixture are delivered via Bazel runfiles
//! (BUILD `data` deps); nothing here hardcodes an absolute path or uses cargo.

use std::path::PathBuf;
use std::sync::Arc;

use mcp_re_core::request_hash;
use mcp_re_core::verify_response;
use mcp_re_core::InMemoryTrustResolver;
use mcp_re_core::SigningKey;
use mcp_re_demo::build_demo_proxy_with_policy;
use mcp_re_demo::demo_bridge_binary;
use mcp_re_demo::demo_policy_evaluator;
use mcp_re_demo::demo_revocation_source;
use mcp_re_demo::mint_demo_grant;
use mcp_re_demo::BridgeInnerMode;
use mcp_re_demo::BridgeProcess;
use mcp_re_demo::DemoGrant;
use mcp_re_demo::DemoGrantSpec;
use mcp_re_demo::DemoProxyConfig;
use mcp_re_host::HostSigner;
use mcp_re_proxy::test_support::block_on_handle;
use mcp_re_proxy::InnerLogSink;
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
// Grant validity window.
const GRANT_NOT_BEFORE: &str = "2026-05-28T20:00:00Z";
const GRANT_EXPIRES_AT: &str = "2026-05-28T21:00:00Z";
const SKEW: i64 = 300;

/// The one path the demo grant authorizes.
const ALLOWED_PATH: &str = "reports";

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

/// The demo grant authorizing `list_files` on exactly `ALLOWED_PATH`.
fn demo_grant() -> DemoGrant {
    let spec = DemoGrantSpec {
        issuer: ISSUER.to_string(),
        grantee: SIGNER.to_string(),
        subject: ON_BEHALF_OF.to_string(),
        audience: AUDIENCE.to_string(),
        allowed_path: ALLOWED_PATH.to_string(),
        not_before: GRANT_NOT_BEFORE.to_string(),
        expires_at: GRANT_EXPIRES_AT.to_string(),
        revocation_id: "demo-rev-1".to_string(),
    };
    mint_demo_grant(&spec, &issuer_key(), ISSUER_KEY_ID).expect("mint demo grant")
}

/// Sign a `list_files` request for `path`, attaching the grant's `.authorization`
/// block and binding the request to `authorization_hash`. When `bind_hash` is
/// false the request is bound to a DIFFERENT (wrong) hash so the evaluator's
/// hash-binding check fails.
fn signed_list_files(nonce: &str, path: &str, grant: &DemoGrant, bind_hash: bool) -> Vec<u8> {
    let authorization_hash = if bind_hash {
        grant.authorization_hash().expect("authorization_hash")
    } else {
        // A syntactically valid but non-binding hash id.
        "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()
    };

    let mut params = Map::new();
    params.insert("name".to_string(), json!("list_files"));
    params.insert("arguments".to_string(), json!({ "path": path }));
    let mut meta = Map::new();
    meta.insert(DemoGrant::meta_key().to_string(), grant.authorization_block());
    params.insert("_meta".to_string(), Value::Object(meta));

    host()
        .sign_request(
            &Value::String(format!("req-{nonce}")),
            "tools/call",
            params,
            ON_BEHALF_OF,
            AUDIENCE,
            &authorization_hash,
            nonce,
            ISSUED_AT,
            EXPIRES_AT,
        )
        .expect("host signs list_files")
}

/// Resolve a runfiles-relative path delivered via an `$(rlocationpath ...)` env
/// var against the runfiles roots, returning the first that exists.
fn resolve_runfile(env_key: &str) -> PathBuf {
    mcp_re_test_paths::resolve_runfile(env_key)
}

fn inner_binary() -> String {
    resolve_runfile("INNER_FILESERVER_BIN")
        .to_string_lossy()
        .into_owned()
}

fn demo_root() -> String {
    resolve_runfile("DEMO_ROOT_README")
        .parent()
        .expect("readme.txt has a parent")
        .to_string_lossy()
        .into_owned()
}

/// A capturing lifecycle sink: the `inner_*` event tags it records are the proof
/// that (or that NOT) the inner subprocess was reached.
#[derive(Default)]
struct CapturingSink {
    events: std::sync::Mutex<Vec<String>>,
}

impl InnerLogSink for CapturingSink {
    fn log(&self, _inner_identity: &str, event: &mcp_re_proxy::InnerLogEvent) {
        self.events.lock().expect("lock").push(event.tag().to_string());
    }
    fn log_stderr(&self, _inner_identity: &str, _captured: &[u8]) {}
}

impl CapturingSink {
    fn event_tags(&self) -> Vec<String> {
        self.events.lock().expect("lock").clone()
    }
    /// True iff the inner subprocess was launched at all (any `inner_*` event).
    fn inner_was_reached(&self) -> bool {
        self.event_tags().iter().any(|t| t.starts_with("inner_"))
    }
}

/// Spawn the out-of-TCB bridge fronting the real fileserver (over the fixture
/// `demo_root`) and build the policy-enabled demo proxy pointed at it. The
/// returned `BridgeProcess` MUST be kept alive for the proxy's lifetime.
fn build_proxy(sink: Arc<CapturingSink>) -> (mcp_re_proxy::Proxy, BridgeProcess) {
    let root = demo_root();
    let bridge = BridgeProcess::spawn(
        &demo_bridge_binary().expect("resolve mcp-re-stdio-bridge"),
        BridgeInnerMode::OneShot,
        Some(&root),
        &[inner_binary(), "--demo-root".to_string(), root.clone()],
    )
    .expect("spawn stdio bridge fronting the demo fileserver");
    let proxy = build_demo_proxy_with_policy(
        DemoProxyConfig {
            inner_http_url: bridge.url().to_string(),
            server_signing_key: server_key(),
            server_signer: SERVER.to_string(),
            server_key_id: SERVER_KEY_ID.to_string(),
            audience: AUDIENCE.to_string(),
            max_clock_skew_secs: SKEW,
        },
        Box::new(inbound_resolver()),
        sink,
        demo_policy_evaluator(),
        Box::new(demo_revocation_source()),
    )
    .expect("policy-enabled demo proxy builds against the bridge URL");
    (proxy, bridge)
}

fn error_message(bytes: &[u8]) -> String {
    let value: Value = serde_json::from_slice(bytes).expect("parse");
    value["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

#[test]
fn authorized_list_files_on_allowed_path_succeeds_end_to_end() {
    let sink = Arc::new(CapturingSink::default());
    let (proxy, _bridge) = build_proxy(Arc::clone(&sink));
    let grant = demo_grant();

    let request = signed_list_files("nonce-authz-allow-1", ALLOWED_PATH, &grant, true);
    let expected_hash =
        request_hash(&serde_json::from_slice::<Value>(&request).unwrap()).expect("request_hash");

    let response = block_on_handle(&proxy, &request, now());

    // The authorized request reached the inner fileserver and returned a real,
    // signed, request-hash-bound listing of the allowed path.
    assert!(
        sink.inner_was_reached(),
        "authorized request must reach the inner: {:?}",
        sink.event_tags()
    );
    let parsed: Value = serde_json::from_slice(&response).expect("parse response");
    assert!(parsed.get("error").is_none(), "response: {parsed}");
    verify_response(&response, &server_resolver(), &expected_hash)
        .expect("authorized response verifies + binds to request_hash");
    let entries = parsed["result"]["structuredContent"]["entries"]
        .as_array()
        .expect("entries array");
    let names: Vec<&str> = entries
        .iter()
        .map(|e| e["name"].as_str().expect("entry name"))
        .collect();
    assert_eq!(names, vec!["q1.txt", "q2.txt"]);
}

#[test]
fn signed_but_unauthorized_path_is_denied_before_dispatch() {
    let sink = Arc::new(CapturingSink::default());
    let (proxy, _bridge) = build_proxy(Arc::clone(&sink));
    let grant = demo_grant();

    // Validly signed, but the grant authorizes only `reports`; ask for `.`.
    let request = signed_list_files("nonce-authz-deny-1", ".", &grant, true);
    let response = block_on_handle(&proxy, &request, now());

    assert_eq!(error_message(&response), "mcp-re.authorization_scope_denied");
    assert!(
        !sink.inner_was_reached(),
        "denied request must NOT reach the inner: {:?}",
        sink.event_tags()
    );
}

#[test]
fn signed_but_demo_root_escaping_path_is_denied_before_dispatch() {
    let sink = Arc::new(CapturingSink::default());
    let (proxy, _bridge) = build_proxy(Arc::clone(&sink));
    let grant = demo_grant();

    // A demo-root-escaping path is not the granted path → denied by scope, and
    // the inner fileserver (which would itself refuse the escape) is never even
    // launched: authorization fails closed first.
    let request = signed_list_files("nonce-authz-escape-1", "../../etc", &grant, true);
    let response = block_on_handle(&proxy, &request, now());

    assert_eq!(error_message(&response), "mcp-re.authorization_scope_denied");
    assert!(
        !sink.inner_was_reached(),
        "escaping-path request must NOT reach the inner: {:?}",
        sink.event_tags()
    );
}

#[test]
fn authorization_hash_mismatch_is_denied_before_dispatch() {
    let sink = Arc::new(CapturingSink::default());
    let (proxy, _bridge) = build_proxy(Arc::clone(&sink));
    let grant = demo_grant();

    // Authorized path + attached grant, but the request binds a DIFFERENT hash:
    // the evaluator's hash-binding check fails before any artifact claim is read.
    let request = signed_list_files("nonce-authz-hashmm-1", ALLOWED_PATH, &grant, false);
    let response = block_on_handle(&proxy, &request, now());

    assert_eq!(error_message(&response), "mcp-re.authorization_hash_mismatch");
    assert!(
        !sink.inner_was_reached(),
        "hash-mismatch request must NOT reach the inner: {:?}",
        sink.event_tags()
    );
}

#[test]
fn expired_grant_is_denied_before_dispatch() {
    let sink = Arc::new(CapturingSink::default());
    let (proxy, _bridge) = build_proxy(Arc::clone(&sink));

    // A grant whose validity window has already closed before `now()`.
    let spec = DemoGrantSpec {
        issuer: ISSUER.to_string(),
        grantee: SIGNER.to_string(),
        subject: ON_BEHALF_OF.to_string(),
        audience: AUDIENCE.to_string(),
        allowed_path: ALLOWED_PATH.to_string(),
        not_before: "2026-05-28T19:00:00Z".to_string(),
        expires_at: "2026-05-28T19:30:00Z".to_string(),
        revocation_id: "demo-rev-expired".to_string(),
    };
    let grant = mint_demo_grant(&spec, &issuer_key(), ISSUER_KEY_ID).expect("mint expired grant");

    // Request freshness still inside the request window; only the GRANT expired.
    let request = signed_list_files("nonce-authz-expired-1", ALLOWED_PATH, &grant, true);
    let response = block_on_handle(&proxy, &request, now());

    assert_eq!(error_message(&response), "mcp-re.authorization_expired");
    assert!(
        !sink.inner_was_reached(),
        "expired-grant request must NOT reach the inner: {:?}",
        sink.event_tags()
    );
}
