//! MCPS-080 (audit §11 G-7) — NEGATIVE secret-in-logs test.
//!
//! The audit confirms the POSITIVE property (denial logs carry a stable reason
//! code). This is the missing NEGATIVE: drive a known sentinel secret through
//! every proxy error / denial / log path and assert the sentinel NEVER appears
//! in (a) the captured proxy log/stderr output or (b) the returned JSON-RPC
//! error object — and, for the request-forwarding path, that the stripped
//! authorization artifact never reaches the inner server's input bytes.
//!
//! Three distinct, grep-unique sentinels are used so a leak names its own class:
//!   * SEED     — the signing seed (its raw bytes AND its Base64URL form). The
//!                proxy must NEVER log or echo the signing seed anywhere.
//!   * ARTIFACT — a marker embedded in the authorization artifact's `revocation_id`.
//!                The authorization block is stripped before forwarding, so it must
//!                be absent in logs, in returned errors, AND in forwarded bytes.
//!   * ARG      — a marker in the request params. The proxy must not echo request
//!                payload in error objects (asserted on the three error paths).
//!
//! This is a TEST-ONLY change: it asserts existing production behavior. If any
//! assertion fails, that is a real leak — the test must NOT be weakened.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::Mutex;

use mcp_re_core::b64url_encode;
use mcp_re_core::canonicalize;
use mcp_re_core::sha256_hash_id;
use mcp_re_core::InMemoryTrustResolver;
use mcp_re_core::SigningKey;
use mcp_re_host::HostSigner;
use mcp_re_policy::mint_reference_grant;
use mcp_re_policy::GrantedOperation;
use mcp_re_policy::InMemoryRevocationSource;
use mcp_re_policy::PolicyEvaluator;
use mcp_re_policy::ReferenceGrantSpec;
use mcp_re_policy::ReferenceProfile;
use mcp_re_policy::AUTHORIZATION_META_KEY;
use mcp_re_policy::REFERENCE_PROFILE_ID;
use mcp_re_proxy::InnerLogEvent;
use mcp_re_proxy::InnerLogSink;
use mcp_re_proxy::Proxy;
use serde_json::json;
use serde_json::Map;
use serde_json::Value;

// --- Identities (mirror proxy_policy_test.rs) ----------------------------------

const SIGNER: &str = "did:example:agent-1";
const SIGNER_KEY_ID: &str = "key-1";
const SERVER: &str = "did:example:server-1";
const SERVER_KEY_ID: &str = "server-key-1";
const ISSUER: &str = "did:example:authority-1";
const ISSUER_KEY_ID: &str = "authority-key-1";
const AUDIENCE: &str = "did:example:server-1";
const ON_BEHALF_OF: &str = "did:example:user-1";
const ISSUED_AT: &str = "2026-05-28T20:00:00Z";
const EXPIRES_AT: &str = "2026-05-28T20:05:00Z";
const GRANT_NOT_BEFORE: &str = "2026-05-28T20:00:00Z";
const GRANT_EXPIRES_AT: &str = "2026-05-28T21:00:00Z";
const SKEW: i64 = 300;

// --- Sentinels -----------------------------------------------------------------

/// The signing seed. Its raw bytes are the private key material; the realistic
/// leak vector in a text log is its Base64URL encoding (see [`seed_b64url`]).
/// Both forms are asserted absent on every path.
const SEED_BYTES: [u8; 32] = [0xA7u8; 32];

/// A marker embedded INSIDE the authorization artifact (the grant's
/// `revocation_id`). This field lives ONLY in the signed artifact bytes — it is
/// NOT one of the fields the proxy legitimately propagates into the forwarded
/// verified-context block (unlike `on_behalf_of`/`audience`, which the inner is
/// meant to receive). So if it ever surfaces in logs, returned errors, or the
/// forwarded bytes, the artifact itself leaked.
const ARTIFACT_SENTINEL: &str = "SENTINEL_ARTIFACT_g7";

/// A marker carried in the request params (`arguments.secret`).
const ARG_SENTINEL: &str = "SENTINEL_ARG_g7";

fn seed_b64url() -> String {
    b64url_encode(&SEED_BYTES)
}

// --- Keys ----------------------------------------------------------------------

/// The signer key is built from the SENTINEL SEED — so anything that logs or
/// echoes the seed leaks a grep-unique value.
fn signer_key() -> SigningKey {
    SigningKey::from_seed_bytes(&SEED_BYTES)
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

fn resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SIGNER, SIGNER_KEY_ID, signer_key().public_key());
    r.insert(ISSUER, ISSUER_KEY_ID, issuer_key().public_key());
    r
}

fn host() -> HostSigner {
    HostSigner::new(signer_key(), SIGNER, SIGNER_KEY_ID)
}

// --- Recording log sink (the capture seam) -------------------------------------

/// Records EVERYTHING the proxy emits to its diagnostic channel: every `log`
/// event (its `Debug` rendering + its stable `tag()`) and every `log_stderr`
/// buffer. Whatever a real `StderrLogSink` would print to the proxy's stderr is
/// captured here verbatim, so the negative assertion is exact and deterministic.
#[derive(Clone, Default)]
struct RecordingSink {
    lines: Arc<Mutex<Vec<String>>>,
    stderr: Arc<Mutex<Vec<u8>>>,
}

impl InnerLogSink for RecordingSink {
    fn log(&self, inner_identity: &str, event: &InnerLogEvent) {
        // Mirror StderrLogSink::log exactly (tag + Debug + identity).
        self.lines.lock().unwrap().push(format!(
            "mcp-re-proxy: inner-event {} inner={inner_identity} {:?}",
            event.tag(),
            event
        ));
    }
    fn log_stderr(&self, inner_identity: &str, captured: &[u8]) {
        // Mirror the default log_stderr (lossy text) AND keep raw bytes.
        self.lines.lock().unwrap().push(format!(
            "mcp-re-proxy: inner-stderr inner={inner_identity} {:?}",
            String::from_utf8_lossy(captured)
        ));
        self.stderr.lock().unwrap().extend_from_slice(captured);
    }
}

impl RecordingSink {
    /// Every captured byte the proxy emitted to its diagnostic channel, as a
    /// single haystack: the joined log lines plus every raw stderr buffer.
    fn captured_bytes(&self) -> Vec<u8> {
        let mut out = self.lines.lock().unwrap().join("\n").into_bytes();
        out.push(b'\n');
        out.extend_from_slice(&self.stderr.lock().unwrap());
        out
    }
}

// --- Helpers -------------------------------------------------------------------

fn spec(tool: &str) -> ReferenceGrantSpec {
    ReferenceGrantSpec {
        issuer: ISSUER.to_string(),
        grantee: SIGNER.to_string(),
        // subject MUST equal the request on_behalf_of for the reference profile
        // to accept it (subject-match rule); it is therefore a field the verified
        // context legitimately forwards, so it does NOT carry a sentinel.
        subject: ON_BEHALF_OF.to_string(),
        audience: AUDIENCE.to_string(),
        operations: vec![GrantedOperation {
            method: "tools/call".to_string(),
            tool: tool.to_string(),
            arguments: None,
        }],
        not_before: GRANT_NOT_BEFORE.to_string(),
        expires_at: GRANT_EXPIRES_AT.to_string(),
        // The ARTIFACT sentinel rides INSIDE the signed artifact, in a field the
        // proxy never forwards into the verified-context block.
        revocation_id: ARTIFACT_SENTINEL.to_string(),
    }
}

/// Sign a tools/call request for `request_tool`, carrying a grant for
/// `grant_tool` (when `with_block`). The request `arguments` carry the ARG
/// sentinel. The grant's `revocation_id` carries the ARTIFACT sentinel.
fn signed_request(nonce: &str, request_tool: &str, grant_tool: &str, with_block: bool) -> Vec<u8> {
    let artifact = mint_reference_grant(&spec(grant_tool), &issuer_key(), ISSUER_KEY_ID).unwrap();
    let authorization_hash = sha256_hash_id(&canonicalize(&artifact).unwrap());

    let mut params = Map::new();
    params.insert("name".to_string(), json!(request_tool));
    params.insert(
        "arguments".to_string(),
        json!({ "text": "hello", "secret": ARG_SENTINEL }),
    );
    if with_block {
        let mut meta = Map::new();
        meta.insert(
            AUTHORIZATION_META_KEY.to_string(),
            json!({ "profile": REFERENCE_PROFILE_ID, "artifact": mcp_re_core::b64url_encode(&artifact) }),
        );
        params.insert("_meta".to_string(), Value::Object(meta));
    }
    host()
        .sign_request(
            &Value::String("req-1".to_string()),
            "tools/call",
            params,
            ON_BEHALF_OF,
            AUDIENCE,
            &authorization_hash,
            nonce,
            ISSUED_AT,
            EXPIRES_AT,
        )
        .expect("host signs")
}

/// The single assertion primitive: `needle` must be ABSENT from `haystack`.
fn assert_absent(haystack: &[u8], needle: &str, ctx: &str) {
    let found = haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes());
    assert!(
        !found,
        "SECRET LEAK: sentinel {needle:?} found in {ctx} — \
         haystack(lossy)={:?}",
        String::from_utf8_lossy(haystack)
    );
}

/// Assert all three classes of secret absent from a captured-output buffer.
fn assert_no_seed_artifact_arg(haystack: &[u8], ctx: &str) {
    assert_absent(haystack, &seed_b64url(), &format!("{ctx} [SEED b64url]"));
    assert_absent(haystack, ARTIFACT_SENTINEL, &format!("{ctx} [ARTIFACT]"));
    assert_absent(haystack, ARG_SENTINEL, &format!("{ctx} [ARG]"));
    // The raw seed bytes must not appear either.
    let raw_found = haystack
        .windows(SEED_BYTES.len())
        .any(|window| window == SEED_BYTES);
    assert!(!raw_found, "SECRET LEAK: raw seed bytes found in {ctx}");
}

/// A proxy whose inner records the EXACT bytes it is handed (so we can inspect
/// what the proxy forwards), with a recording log sink attached. The inner
/// returns `inner_response` (allowing the response-verify failure path).
fn proxy_recording(
    enforce: bool,
    inner_response: Vec<u8>,
) -> (Proxy, Rc<RefCell<Vec<Vec<u8>>>>, RecordingSink) {
    let forwarded: Rc<RefCell<Vec<Vec<u8>>>> = Rc::new(RefCell::new(Vec::new()));
    let forwarded_for_inner = Rc::clone(&forwarded);
    let inner = move |request: &[u8]| -> Vec<u8> {
        forwarded_for_inner.borrow_mut().push(request.to_vec());
        inner_response.clone()
    };
    let sink = RecordingSink::default();
    let mut proxy = Proxy::new(
        server_key(),
        SERVER,
        SERVER_KEY_ID,
        Box::new(resolver()),
        AUDIENCE,
        SKEW,
        Box::new(inner),
    )
    .with_log_sink(Arc::new(sink.clone()));
    if enforce {
        let mut evaluator = PolicyEvaluator::new();
        evaluator.register(Box::new(ReferenceProfile::new()));
        proxy = proxy.with_policy_enforcement(evaluator, Box::new(InMemoryRevocationSource::new()));
    }
    (proxy, forwarded, sink)
}

fn ok_inner_response() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "jsonrpc": "2.0", "id": "req-1",
        "result": { "content": [ { "type": "text", "text": "hi" } ] }
    }))
    .unwrap()
}

// --- Path 1: request-verify failure --------------------------------------------

#[test]
fn request_verify_failure_leaks_no_secret() {
    let (proxy, forwarded, sink) = proxy_recording(true, ok_inner_response());
    // Tamper the signed request so signature verification fails closed.
    let mut request = signed_request("nonce-rv-01", "echo", "echo", true);
    let last = request.len() - 2;
    request[last] ^= 0xFF; // corrupt a content byte → InvalidSignature

    let response = proxy.handle(&request, now());

    assert_eq!(forwarded.borrow().len(), 0, "tampered request must NOT reach the inner");
    // SEED + ARTIFACT + ARG all absent in the returned error object.
    assert_no_seed_artifact_arg(&response, "request-verify returned error object");
    // SEED + ARTIFACT + ARG all absent in the captured log/stderr buffer.
    assert_no_seed_artifact_arg(&sink.captured_bytes(), "request-verify captured logs");
}

// --- Path 2: authz denial ------------------------------------------------------

#[test]
fn authz_denial_leaks_no_secret() {
    let (proxy, forwarded, sink) = proxy_recording(true, ok_inner_response());
    // Grant only `echo` but call `delete_everything` → scope denied before dispatch.
    let request = signed_request("nonce-az-01", "delete_everything", "echo", true);

    let response = proxy.handle(&request, now());

    assert_eq!(forwarded.borrow().len(), 0, "denied request must NOT reach the inner");
    let value: Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(
        value["error"]["message"].as_str(),
        Some("mcp-re.authorization_scope_denied"),
        "the denial still carries its stable reason code (positive property)"
    );
    assert_no_seed_artifact_arg(&response, "authz-denial returned error object");
    assert_no_seed_artifact_arg(&sink.captured_bytes(), "authz-denial captured logs");
}

// --- Path 3: response-verify / response-signing failure ------------------------

#[test]
fn response_failure_leaks_no_secret() {
    // The inner returns a malformed (non-JSON) response carrying the ARG
    // sentinel — exactly what a buggy/hostile inner could emit. The proxy fails
    // closed on the response path (CanonicalizationFailed) and must surface only
    // the frozen wire token, never the inner's bytes.
    let mut garbage = b"not-json ".to_vec();
    garbage.extend_from_slice(ARG_SENTINEL.as_bytes());
    let (proxy, forwarded, sink) = proxy_recording(true, garbage);
    let request = signed_request("nonce-rs-01", "echo", "echo", true);

    let response = proxy.handle(&request, now());

    // The request IS forwarded (it is in-scope) — the failure is on the way back.
    assert_eq!(forwarded.borrow().len(), 1, "in-scope request reaches the inner once");
    let value: Value = serde_json::from_slice(&response).expect("error object is valid JSON");
    assert!(value.get("error").is_some(), "response-path failure yields an error object");
    assert_no_seed_artifact_arg(&response, "response-failure returned error object");
    assert_no_seed_artifact_arg(&sink.captured_bytes(), "response-failure captured logs");
}

// --- Path 4: inner-stderr / forwarded-to-inner capture -------------------------

#[test]
fn forwarded_to_inner_strips_seed_and_artifact() {
    // Model a request-echoing inner: capture the EXACT bytes the proxy forwards.
    // This is what a hostile/buggy inner could dump to its own stderr. The
    // authorization block (and the external request envelope) are stripped before
    // forwarding, so neither the SEED nor the ARTIFACT can surface at the inner.
    let (proxy, forwarded, sink) = proxy_recording(true, ok_inner_response());
    let request = signed_request("nonce-fwd-01", "echo", "echo", true);

    let response = proxy.handle(&request, now());

    assert_eq!(forwarded.borrow().len(), 1, "in-scope request reaches the inner once");
    let inner_bytes = forwarded.borrow()[0].clone();

    // The forwarded request legitimately carries the request ARG (the inner needs
    // its params), so ARG is NOT asserted absent here. SEED and ARTIFACT MUST be
    // absent: the signing seed is never echoed, and the authorization block (which
    // carries the artifact + its subject sentinel) is stripped before forwarding.
    assert_absent(&inner_bytes, &seed_b64url(), "forwarded-to-inner [SEED b64url]");
    let raw_found = inner_bytes
        .windows(SEED_BYTES.len())
        .any(|window| window == SEED_BYTES);
    assert!(!raw_found, "SECRET LEAK: raw seed bytes found in forwarded-to-inner bytes");
    assert_absent(&inner_bytes, ARTIFACT_SENTINEL, "forwarded-to-inner [ARTIFACT]");

    // Sanity: the authorization meta key itself is gone from the forwarded bytes.
    let forwarded_value: Value = serde_json::from_slice(&inner_bytes).expect("forwarded is JSON");
    assert!(
        forwarded_value["params"]["_meta"]
            .get(AUTHORIZATION_META_KEY)
            .is_none(),
        "authorization block must be stripped before forwarding"
    );

    // The successful response is signed; SEED + ARTIFACT must be absent from the
    // returned bytes and from the captured logs (ARG legitimately appears nowhere
    // in the response either, but is allowed at the inner, so we only check the
    // two key-class sentinels on the returned bytes).
    assert_absent(&response, &seed_b64url(), "forward-path returned response [SEED b64url]");
    assert_absent(&response, ARTIFACT_SENTINEL, "forward-path returned response [ARTIFACT]");
    // Captured logs (RequestForwarded + ResponseSigned events) must be clean of
    // all three classes.
    assert_no_seed_artifact_arg(&sink.captured_bytes(), "forward-path captured logs");
}
