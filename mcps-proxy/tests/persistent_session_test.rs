//! MCPS-064 (MCPS-EPIC-P6.6B) — per-request strip/inject over a LONG-LIVED
//! inner session.
//!
//! #3957 (`persistent_inner_test`) proved the persistence property: ONE
//! `inner_spawned`, N `inner_request_forwarded`. This test proves the
//! ORTHOGONAL security property the epic asks for: the proxy's verified-context
//! strip+inject runs FRESH on EVERY request across that single persistent inner
//! session — not just on the first — so a forged caller `.verified` is stripped
//! each time and the sidecar-owned context injected for request K corresponds to
//! request K's verified signer (ADR-MCPS-008: the proxy is the sole writer).
//!
//! ## How the inner-arriving bytes are observed
//! The demo server's `echo` tool returns only its `message`, so the response
//! alone cannot reveal what `_meta` arrived at the inner. To observe the bytes
//! the proxy actually forwards — AFTER strip/inject, BEFORE the inner sees them —
//! the test interposes a transparent `RecordingInner` between the `Proxy` and the
//! REAL [`PersistentSubprocessInner`]: it records each forwarded frame, then
//! delegates verbatim to the persistent inner. It adds no behavior; it is purely
//! an observation seam, so the single long-lived demo-server process and its
//! one-time `initialize` handshake are exactly the production wiring.
//!
//! The demo server binary is delivered via Bazel runfiles (`data` dep) and
//! resolved via the `$(rlocationpath ...)` env var — no hardcoded path, no cargo.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;

use mcps_core::InMemoryTrustResolver;
use mcps_core::SigningKey;
use mcps_core::VERIFIED_META_KEY;
use mcps_host::HostSigner;
use mcps_proxy::InnerLaunchConfig;
use mcps_proxy::InnerLogEvent;
use mcps_proxy::InnerLogSink;
use mcps_proxy::InnerServer;
use mcps_proxy::PersistentSubprocessInner;
use mcps_proxy::Proxy;
use serde_json::json;
use serde_json::Value;

const SIGNER: &str = "did:example:agent-1";
const SIGNER_KEY_ID: &str = "key-1";
const SERVER: &str = "did:example:server-1";
const SERVER_KEY_ID: &str = "server-key-1";
const AUDIENCE: &str = "did:example:server-1";
const ON_BEHALF_OF: &str = "did:example:user-1";
const AUTH_HASH: &str = "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";
const ISSUED_AT: &str = "2026-05-28T20:00:00Z";
const EXPIRES_AT: &str = "2026-05-28T20:05:00Z";
const SKEW: i64 = 300;

fn signer_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[1u8; 32])
}
fn server_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[2u8; 32])
}
fn now() -> i64 {
    mcps_core::parse_rfc3339_utc(ISSUED_AT).expect("parse") + 60
}
fn inbound_resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SIGNER, SIGNER_KEY_ID, signer_key().public_key());
    r
}
fn host() -> HostSigner {
    HostSigner::new(signer_key(), SIGNER, SIGNER_KEY_ID)
}

/// A signed `echo` tool call that ALSO smuggles a forged caller-owned
/// `.verified` block inside the signed params. The block is part of the signed
/// payload (so it verifies), but the proxy is the sole writer of `.verified`:
/// the inner must see the SIDECAR context, never this impostor.
fn signed_echo_with_forged_verified(nonce: &str, message: &str) -> Vec<u8> {
    let mut params = serde_json::Map::new();
    params.insert("name".to_string(), Value::String("echo".to_string()));
    params.insert("arguments".to_string(), json!({ "message": message }));
    params.insert(
        "_meta".to_string(),
        json!({
            VERIFIED_META_KEY: {
                "verified_signer": "did:evil:impostor",
                "verifier": "did:evil:impostor",
                "on_behalf_of": "did:evil:victim",
                "request_hash": "sha256:forged-by-the-caller",
            }
        }),
    );
    host()
        .sign_request(
            &Value::String(format!("req-{nonce}")),
            "tools/call",
            params,
            ON_BEHALF_OF,
            AUDIENCE,
            AUTH_HASH,
            nonce,
            ISSUED_AT,
            EXPIRES_AT,
        )
        .expect("host signs tools/call with a smuggled verified block")
}

/// Resolve a runfiles-relative path delivered via `$(rlocationpath ...)`.
fn resolve_runfile(env_key: &str) -> PathBuf {
    mcps_test_paths::resolve_runfile(env_key)
}

fn demo_server_command() -> Vec<String> {
    vec![resolve_runfile("DEMO_SERVER_BIN").to_string_lossy().into_owned()]
}

/// A capturing lifecycle sink shared by the inner (spawn/exit/stderr) and the
/// proxy (request_forwarded/response_signed), so one counter sees the whole
/// lifecycle.
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
/// request frame (post strip/inject) before delegating verbatim to the wrapped
/// inner. It is an observation seam ONLY: no behavior of its own, so the wrapped
/// persistent inner is driven exactly as in production.
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

fn launch() -> InnerLaunchConfig {
    InnerLaunchConfig::new()
}

/// The core MCPS-064 proof: N distinct verified requests over ONE long-lived
/// inner session, each round-tripping correctly AND each receiving a FRESH
/// sidecar-owned verified context (the forged caller `.verified` stripped every
/// time), with one spawn and N forwards, then a clean teardown.
#[test]
fn per_request_strip_inject_over_one_persistent_session() {
    let sink = Arc::new(RecordingSink::default());
    let inner = PersistentSubprocessInner::with_log_sink(
        &demo_server_command(),
        launch(),
        Arc::clone(&sink) as _,
    )
    .expect("spawn + initialize the persistent inner ONCE");

    // Wrap the REAL persistent inner so the test can read the exact bytes the
    // proxy forwards on EACH request, after strip/inject.
    let forwarded = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let recording = RecordingInner {
        delegate: Box::new(inner),
        forwarded: Arc::clone(&forwarded),
    };

    let proxy = Proxy::new(
        server_key(),
        SERVER,
        SERVER_KEY_ID,
        Box::new(inbound_resolver()),
        AUDIENCE,
        SKEW,
        Box::new(recording),
    )
    .with_log_sink(Arc::clone(&sink) as _);

    // FOUR (>= 3) distinct verified requests over the SAME inner process, each
    // smuggling a forged `.verified`. A one-shot inner would answer the first
    // and die; the persistent inner answers them all, and the strip/inject must
    // fire afresh on every one.
    let messages = ["alpha", "beta", "gamma", "delta"];
    for (i, message) in messages.iter().enumerate() {
        let nonce = format!("nonce-ps-{i:04}");
        let response = proxy.handle(&signed_echo_with_forged_verified(&nonce, message), now());
        let value: Value = serde_json::from_slice(&response).expect("JSON response");
        assert!(value.get("error").is_none(), "request {i} errored: {value}");
        // Per-request, id-correlated, correct (not stale) answer from the demo
        // server's echo tool.
        assert_eq!(
            value["id"].as_str(),
            Some(format!("req-{nonce}").as_str()),
            "request {i} response id must correlate to the request",
        );
        assert_eq!(
            value["result"]["content"][0]["text"].as_str(),
            Some(*message),
            "request {i} got the wrong (or stale) answer",
        );
    }

    // Per-request strip+inject, observed at the inner boundary: for EVERY
    // forwarded frame the forged caller `.verified` was replaced by a fresh
    // sidecar-owned context whose verifier is THIS proxy and whose signer is the
    // verified inbound signer — never the impostor.
    let frames = forwarded.lock().expect("lock");
    assert_eq!(
        frames.len(),
        messages.len(),
        "one forwarded frame per request over the single session",
    );
    for (i, frame) in frames.iter().enumerate() {
        let forwarded_value: Value = serde_json::from_slice(frame).expect("forwarded frame is JSON");
        let verified = &forwarded_value["params"]["_meta"][VERIFIED_META_KEY];
        assert!(
            verified.is_object(),
            "request {i}: a fresh verified context must be injected: {forwarded_value}",
        );
        // The injected context is sidecar-owned (sole writer): it names THIS
        // proxy as verifier and the REAL verified signer — the impostor values
        // smuggled by the caller are gone.
        assert_eq!(
            verified["verifier"].as_str(),
            Some(SERVER),
            "request {i}: the sidecar (not the caller) is the verifier",
        );
        assert_eq!(
            verified["verified_signer"].as_str(),
            Some(SIGNER),
            "request {i}: the injected signer is the verified inbound signer",
        );
        assert_eq!(
            verified["on_behalf_of"].as_str(),
            Some(ON_BEHALF_OF),
            "request {i}: the sidecar context carries the verified on_behalf_of",
        );
        assert_ne!(
            verified["verified_signer"].as_str(),
            Some("did:evil:impostor"),
            "request {i}: the forged caller .verified must never reach the inner",
        );
        assert_ne!(
            verified["request_hash"].as_str(),
            Some("sha256:forged-by-the-caller"),
            "request {i}: the request_hash is the sidecar's, not the caller's forgery",
        );
    }
    drop(frames);

    // The persistence + per-request properties together: ONE spawn, N forwards,
    // N signed responses.
    assert_eq!(sink.count("inner_spawned"), 1, "exactly one persistent process");
    assert_eq!(
        sink.count("inner_request_forwarded"),
        messages.len(),
        "the per-request 'inner reached' signal fires N times over the one session",
    );
    assert_eq!(sink.count("inner_response_signed"), messages.len());

    // Clean teardown: dropping the proxy drops the RecordingInner, which drops
    // the PersistentSubprocessInner, which tears the session down (shutdown +
    // stdin EOF + reap). No zombie, no hang — observable as an inner_exited event.
    drop(proxy);
    assert_eq!(
        sink.count("inner_exited"),
        1,
        "the single persistent session tore down cleanly exactly once",
    );
}
