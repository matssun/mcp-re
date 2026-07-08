//! Runnable NEGATIVE / security-path demo (MCPS-050, MCP-RE-EPIC-P6 Child Issue 6).
//!
//! The fail-closed counterpart to `demo_positive`: it drives each rejected case
//! end to end and prints ONE structured denial line per case, carrying the frozen
//! `mcp-re.*` reason code the proxy (or the HostSession client, for the response-
//! side cases) emitted:
//!
//! ```text
//! denial case=1_tampered_body         reason=mcp-re.invalid_signature        inner_reached=false
//! denial case=2_tampered_id           reason=mcp-re.invalid_signature        inner_reached=false
//! denial case=3_replay                reason=mcp-re.replay_detected          inner_reached=true
//! ...
//! ```
//!
//! Run it with either build system:
//!
//! ```sh
//! bazel run //mcp-re-demo:demo_negative
//! # or, after `cargo build --workspace --bins`:
//! cargo run -p mcp-re-demo --bin demo_negative
//! ```
//!
//! The inner `mcp-re-demo-fileserver` binary and the committed `demo_root/` fixture
//! are resolved by [`mcp_re_demo::demo_paths`]: under Bazel from the
//! `INNER_FILESERVER_BIN` / `DEMO_ROOT_README` runfiles env vars; under Cargo from
//! the `target/<profile>/` build output and the workspace-relative fixture — so no
//! env setup is required for the Cargo quickstart. Nothing is hardcoded.
//!
//! This is a DEMO entry point: it fails LOUDLY (non-zero exit, clear message) if
//! ANY case is not rejected with the EXPECTED reason — a missing rejection is a
//! security regression, not a quiet pass. The library paths it drives never panic
//! on bad input; they fail closed with a JSON-RPC error, surfaced here.

use std::process::ExitCode;
use std::sync::Arc;

use mcp_re_core::request_hash;
use mcp_re_core::InMemoryTrustResolver;
use mcp_re_core::McpReError;
use mcp_re_core::SigningKey;
use mcp_re_core::REQUEST_META_KEY;
use mcp_re_core::RESPONSE_META_KEY;
use mcp_re_core::VERIFIED_META_KEY;
use mcp_re_demo::build_demo_proxy_with_policy;
use mcp_re_demo::demo_bridge_binary;
use mcp_re_demo::demo_inner_binary;
use mcp_re_demo::demo_policy_evaluator;
use mcp_re_demo::demo_root_dir;
use mcp_re_demo::demo_revocation_source;
use mcp_re_demo::mint_demo_grant;
use mcp_re_demo::BridgeInnerMode;
use mcp_re_demo::BridgeProcess;
use mcp_re_demo::DemoGrant;
use mcp_re_demo::DemoGrantSpec;
use mcp_re_demo::DemoHostClient;
use mcp_re_demo::DemoProxyConfig;
use mcp_re_host::FixedClock;
use mcp_re_host::HostSigner;
use mcp_re_host::SeededNonceSource;
use mcp_re_proxy::test_support::block_on_handle;
use mcp_re_proxy::InnerLogEvent;
use mcp_re_proxy::InnerLogSink;
use mcp_re_proxy::Proxy;
use serde_json::json;
use serde_json::Value;

const SIGNER: &str = "did:example:agent-1";
const SIGNER_KEY_ID: &str = "key-1";
const SERVER: &str = "did:example:server-1";
const SERVER_KEY_ID: &str = "server-key-1";
const ISSUER: &str = "did:example:authority-1";
const ISSUER_KEY_ID: &str = "authority-key-1";
const AUDIENCE: &str = "did:example:server-1";
const WRONG_AUDIENCE: &str = "did:example:server-OTHER";
const ON_BEHALF_OF: &str = "did:example:user-1";

const NOW_UNIX: i64 = 1_779_998_400; // 2026-05-28T20:00:00Z
const GRANT_NOT_BEFORE: &str = "2026-05-28T20:00:00Z";
const GRANT_EXPIRES_AT: &str = "2026-05-28T21:00:00Z";
const SKEW: i64 = 300;
const ALLOWED_PATH: &str = "reports";
const UNAUTHORIZED_PATH: &str = ".";

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
    NOW_UNIX + 60
}

fn host_signer() -> HostSigner {
    HostSigner::new(signer_key(), SIGNER, SIGNER_KEY_ID)
}

fn client() -> DemoHostClient<FixedClock, SeededNonceSource> {
    DemoHostClient::with_defaults(
        host_signer(),
        FixedClock::new(NOW_UNIX),
        SeededNonceSource::new(&[0xABu8; 32]),
    )
}

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

fn demo_grant() -> DemoGrant {
    let spec = DemoGrantSpec {
        issuer: ISSUER.to_string(),
        grantee: SIGNER.to_string(),
        subject: ON_BEHALF_OF.to_string(),
        audience: AUDIENCE.to_string(),
        allowed_path: ALLOWED_PATH.to_string(),
        not_before: GRANT_NOT_BEFORE.to_string(),
        expires_at: GRANT_EXPIRES_AT.to_string(),
        revocation_id: "demo-rev-negative".to_string(),
    };
    mint_demo_grant(&spec, &issuer_key(), ISSUER_KEY_ID).expect("mint demo grant")
}

fn inner_binary() -> Result<String, String> {
    Ok(demo_inner_binary()?.to_string_lossy().into_owned())
}

fn demo_root() -> Result<String, String> {
    Ok(demo_root_dir()?.to_string_lossy().into_owned())
}

#[derive(Default)]
struct CapturingSink {
    events: std::sync::Mutex<Vec<String>>,
}

impl InnerLogSink for CapturingSink {
    fn log(&self, _inner_identity: &str, event: &InnerLogEvent) {
        self.events.lock().expect("lock").push(event.tag().to_string());
    }
    fn log_stderr(&self, _inner_identity: &str, _captured: &[u8]) {}
}

impl CapturingSink {
    fn inner_was_reached(&self) -> bool {
        self.events.lock().expect("lock").iter().any(|t| t.starts_with("inner_"))
    }
}

fn build_proxy(
    sink: Arc<CapturingSink>,
    inner_http_url: &str,
) -> Result<Proxy, String> {
    build_demo_proxy_with_policy(
        DemoProxyConfig {
            inner_http_url: inner_http_url.to_string(),
            server_signing_key: server_key(),
            server_signer: SERVER.to_string(),
            server_key_id: SERVER_KEY_ID.to_string(),
            audience: AUDIENCE.to_string(),
            max_clock_skew_secs: SKEW,
        },
        Box::new(inbound_resolver()),
        sink as Arc<dyn InnerLogSink + Send + Sync>,
        demo_policy_evaluator(),
        Box::new(demo_revocation_source()),
    )
}

fn list_files_params(path: &str, grant: &DemoGrant) -> serde_json::Map<String, Value> {
    let mut params = serde_json::Map::new();
    params.insert("name".to_string(), Value::String("list_files".to_string()));
    params.insert("arguments".to_string(), json!({ "path": path }));
    let mut meta = serde_json::Map::new();
    meta.insert(DemoGrant::meta_key().to_string(), grant.authorization_block());
    params.insert("_meta".to_string(), Value::Object(meta));
    params
}

/// The structured denial reason carried on a rejected response (`error.message`),
/// or `None` for a success response.
fn denial_reason(response: &[u8]) -> Result<Option<String>, String> {
    let value: Value = serde_json::from_slice(response).map_err(|e| format!("parse: {e}"))?;
    match value.get("error") {
        None => Ok(None),
        Some(error) => Ok(Some(
            error["message"].as_str().ok_or("error.message")?.to_string(),
        )),
    }
}

/// Print a category header for the grouped output.
fn group(title: &str) {
    println!("\n{title}:");
}

/// Print + check one grouped `PASS` line. Fails loudly if the observed reason
/// does not equal the expected one, or if the inner-reach expectation is
/// violated — the printed line is cosmetic; the assertions are the contract.
fn report(
    label: &str,
    expected: &str,
    observed: &str,
    inner_reached: bool,
    expect_inner_reached: bool,
) -> Result<(), String> {
    println!("  PASS {label:<24} {observed}");
    if observed != expected {
        return Err(format!("case {label}: expected reason {expected}, observed {observed}"));
    }
    if inner_reached != expect_inner_reached {
        return Err(format!(
            "case {label}: expected inner_reached={expect_inner_reached}, observed {inner_reached}"
        ));
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => {
            println!("\nOK: all 10 fail-closed cases rejected with the expected mcp-re.* reason");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("demo_negative FAILED: {err}");
            ExitCode::FAILURE
        }
    }
}

#[allow(clippy::too_many_lines)]
fn run() -> Result<(), String> {
    let inner_binary = inner_binary()?;
    let demo_root = demo_root()?;
    let grant = demo_grant();
    let auth_hash = grant.authorization_hash().map_err(|e| format!("authorization_hash: {e:?}"))?;

    // Spawn the out-of-TCB bridge fronting the real fileserver ONCE; every case's
    // fresh proxy points its HTTP inner plane at this same bridge URL. Held for
    // the whole run (killed on drop).
    let bridge = BridgeProcess::spawn(
        &demo_bridge_binary()?,
        BridgeInnerMode::OneShot,
        Some(&demo_root),
        &[inner_binary, "--demo-root".to_string(), demo_root.clone()],
    )?;
    let inner_url = bridge.url().to_string();

    println!("MCP-RE local fail-closed paths — each case must be rejected with its frozen mcp-re.* reason:");

    group("Request integrity");

    // Case 1: tampered request body.
    {
        let sink = Arc::new(CapturingSink::default());
        let proxy = build_proxy(Arc::clone(&sink), &inner_url)?;
        let mut cl = client();
        let id = Value::String("req-neg-tamper-body".to_string());
        let signed = cl
            .sign_request(&id, "tools/call", list_files_params(ALLOWED_PATH, &grant), ON_BEHALF_OF, AUDIENCE, &auth_hash)
            .map_err(|e| format!("sign: {e:?}"))?;
        let mut request: Value = serde_json::from_slice(&signed).map_err(|e| format!("parse: {e}"))?;
        request["params"]["arguments"]["path"] = json!("tampered");
        let tampered = serde_json::to_vec(&request).map_err(|e| format!("serialize: {e}"))?;
        let response = block_on_handle(&proxy, &tampered, now());
        let reason = denial_reason(&response)?.ok_or("case 1: expected a denial")?;
        report("tampered_body", McpReError::InvalidSignature.wire_code(), &reason, sink.inner_was_reached(), false)?;
    }

    // Case 2: tampered JSON-RPC id.
    {
        let sink = Arc::new(CapturingSink::default());
        let proxy = build_proxy(Arc::clone(&sink), &inner_url)?;
        let mut cl = client();
        let id = Value::String("req-neg-tamper-id".to_string());
        let signed = cl
            .sign_request(&id, "tools/call", list_files_params(ALLOWED_PATH, &grant), ON_BEHALF_OF, AUDIENCE, &auth_hash)
            .map_err(|e| format!("sign: {e:?}"))?;
        let mut request: Value = serde_json::from_slice(&signed).map_err(|e| format!("parse: {e}"))?;
        request["id"] = json!("req-neg-tamper-id-SWAPPED");
        let tampered = serde_json::to_vec(&request).map_err(|e| format!("serialize: {e}"))?;
        let response = block_on_handle(&proxy, &tampered, now());
        let reason = denial_reason(&response)?.ok_or("case 2: expected a denial")?;
        report("tampered_id", McpReError::InvalidSignature.wire_code(), &reason, sink.inner_was_reached(), false)?;
    }

    group("Freshness / replay");

    // Case 3: replayed request (first send dispatches; second is replay).
    {
        let sink = Arc::new(CapturingSink::default());
        let proxy = build_proxy(Arc::clone(&sink), &inner_url)?;
        let mut cl = client();
        let id = Value::String("req-neg-replay".to_string());
        let signed = cl
            .sign_request(&id, "tools/call", list_files_params(ALLOWED_PATH, &grant), ON_BEHALF_OF, AUDIENCE, &auth_hash)
            .map_err(|e| format!("sign: {e:?}"))?;
        let first = block_on_handle(&proxy, &signed, now());
        if denial_reason(&first)?.is_some() {
            return Err("case 3: first send unexpectedly denied".to_string());
        }
        let second = block_on_handle(&proxy, &signed, now());
        let reason = denial_reason(&second)?.ok_or("case 3: expected a replay denial")?;
        // The inner WAS reached by the (accepted) first send; the replay verdict
        // on the second send is the security property.
        report("replay", McpReError::ReplayDetected.wire_code(), &reason, sink.inner_was_reached(), true)?;
    }

    // Case 4: expired request (verified far past its freshness window).
    {
        let sink = Arc::new(CapturingSink::default());
        let proxy = build_proxy(Arc::clone(&sink), &inner_url)?;
        let mut cl = client();
        let id = Value::String("req-neg-expired".to_string());
        let signed = cl
            .sign_request(&id, "tools/call", list_files_params(ALLOWED_PATH, &grant), ON_BEHALF_OF, AUDIENCE, &auth_hash)
            .map_err(|e| format!("sign: {e:?}"))?;
        let response = block_on_handle(&proxy, &signed, NOW_UNIX + 10 * 3600);
        let reason = denial_reason(&response)?.ok_or("case 4: expected a denial")?;
        report("expired", McpReError::ExpiredRequest.wire_code(), &reason, sink.inner_was_reached(), false)?;
    }

    group("Routing / binding");

    // Case 5: wrong audience.
    {
        let sink = Arc::new(CapturingSink::default());
        let proxy = build_proxy(Arc::clone(&sink), &inner_url)?;
        let mut cl = client();
        let id = Value::String("req-neg-audience".to_string());
        let signed = cl
            .sign_request(&id, "tools/call", list_files_params(ALLOWED_PATH, &grant), ON_BEHALF_OF, WRONG_AUDIENCE, &auth_hash)
            .map_err(|e| format!("sign: {e:?}"))?;
        let response = block_on_handle(&proxy, &signed, now());
        let reason = denial_reason(&response)?.ok_or("case 5: expected a denial")?;
        report("wrong_audience", McpReError::InvalidAudience.wire_code(), &reason, sink.inner_was_reached(), false)?;
    }

    // Case 6: missing MCP-RE request envelope.
    {
        let sink = Arc::new(CapturingSink::default());
        let proxy = build_proxy(Arc::clone(&sink), &inner_url)?;
        let mut cl = client();
        let id = Value::String("req-neg-noenv".to_string());
        let signed = cl
            .sign_request(&id, "tools/call", list_files_params(ALLOWED_PATH, &grant), ON_BEHALF_OF, AUDIENCE, &auth_hash)
            .map_err(|e| format!("sign: {e:?}"))?;
        let mut request: Value = serde_json::from_slice(&signed).map_err(|e| format!("parse: {e}"))?;
        request["params"]["_meta"]
            .as_object_mut()
            .ok_or("_meta object")?
            .remove(REQUEST_META_KEY);
        let stripped = serde_json::to_vec(&request).map_err(|e| format!("serialize: {e}"))?;
        let response = block_on_handle(&proxy, &stripped, now());
        let reason = denial_reason(&response)?.ok_or("case 6: expected a denial")?;
        report("missing_envelope", McpReError::MissingEnvelope.wire_code(), &reason, sink.inner_was_reached(), false)?;
    }

    group("Verified context");

    // Case 7: caller-supplied `.verified` is stripped + replaced (NOT a denial:
    // the request still authorizes; the proxy's sidecar context replaces the
    // impostor and the response binds + verifies under the SERVER key).
    {
        let sink = Arc::new(CapturingSink::default());
        let proxy = build_proxy(Arc::clone(&sink), &inner_url)?;
        let mut cl = client();
        let mut params = list_files_params(ALLOWED_PATH, &grant);
        params
            .get_mut("_meta")
            .and_then(Value::as_object_mut)
            .ok_or("_meta")?
            .insert(
                VERIFIED_META_KEY.to_string(),
                json!({ "verified_signer": "did:evil:impostor", "verifier": "did:evil:impostor" }),
            );
        let id = Value::String("req-neg-verified".to_string());
        let signed = cl
            .sign_request(&id, "tools/call", params, ON_BEHALF_OF, AUDIENCE, &auth_hash)
            .map_err(|e| format!("sign: {e:?}"))?;
        let stored = cl.stored_request_hash(&id).ok_or("stored hash")?.to_string();
        let response = block_on_handle(&proxy, &signed, now());
        if denial_reason(&response)?.is_some() {
            return Err("case 7: smuggled .verified should not deny".to_string());
        }
        let verified = cl
            .verify_response(&response, &server_resolver())
            .map_err(|e| format!("case 7 verify_response: {e:?}"))?;
        if verified.server_signer() != SERVER || verified.request_hash() != stored {
            return Err("case 7: sidecar did not replace the impostor .verified".to_string());
        }
        println!(
            "  PASS {:<24} {} (impostor .verified stripped; verifier={})",
            "caller_verified", "stripped+replaced", verified.server_signer(),
        );
    }

    group("Authorization");

    // Case 8: valid signature, failed Phase 5 authorization (unauthorized path).
    {
        let sink = Arc::new(CapturingSink::default());
        let proxy = build_proxy(Arc::clone(&sink), &inner_url)?;
        let mut cl = client();
        let id = Value::String("req-neg-unauthorized".to_string());
        let signed = cl
            .sign_request(&id, "tools/call", list_files_params(UNAUTHORIZED_PATH, &grant), ON_BEHALF_OF, AUDIENCE, &auth_hash)
            .map_err(|e| format!("sign: {e:?}"))?;
        let response = block_on_handle(&proxy, &signed, now());
        let reason = denial_reason(&response)?.ok_or("case 8: expected a denial")?;
        report("unauthorized_path", "mcp-re.authorization_scope_denied", &reason, sink.inner_was_reached(), false)?;
    }

    group("Response binding");

    // Case 9: wrong response hash — the HostSession client refuses the binding.
    {
        let sink = Arc::new(CapturingSink::default());
        let proxy = build_proxy(Arc::clone(&sink), &inner_url)?;
        let mut cl = client();
        let id = Value::String("req-neg-resphash".to_string());
        // Client signs A (stores hash A); proxy runs a DIFFERENT B (same id) and
        // signs a response bound to hash B.
        let _signed_a = cl
            .sign_request(&id, "tools/call", list_files_params(ALLOWED_PATH, &grant), ON_BEHALF_OF, AUDIENCE, &auth_hash)
            .map_err(|e| format!("sign A: {e:?}"))?;
        let signed_b = host_signer()
            .sign_request(
                &id,
                "tools/call",
                list_files_params(ALLOWED_PATH, &grant),
                ON_BEHALF_OF,
                AUDIENCE,
                &auth_hash,
                "nonce-neg-resphash-B",
                "2026-05-28T20:00:30Z",
                "2026-05-28T20:05:30Z",
            )
            .map_err(|e| format!("sign B: {e:?}"))?;
        let _ = request_hash(&serde_json::from_slice::<Value>(&signed_b).map_err(|e| format!("parse B: {e}"))?);
        let response_b = block_on_handle(&proxy, &signed_b, now());
        if denial_reason(&response_b)?.is_some() {
            return Err("case 9: proxy unexpectedly denied request B".to_string());
        }
        let err = cl
            .verify_response(&response_b, &server_resolver())
            .err()
            .ok_or("case 9: client must reject the wrong-hash binding")?;
        report("wrong_response_hash", McpReError::ResponseHashMismatch.wire_code(), err.wire_code(), sink.inner_was_reached(), true)?;
    }

    // Case 10: invalid response signature — the HostSession client refuses it.
    {
        let sink = Arc::new(CapturingSink::default());
        let proxy = build_proxy(Arc::clone(&sink), &inner_url)?;
        let mut cl = client();
        let id = Value::String("req-neg-respsig".to_string());
        let signed = cl
            .sign_request(&id, "tools/call", list_files_params(ALLOWED_PATH, &grant), ON_BEHALF_OF, AUDIENCE, &auth_hash)
            .map_err(|e| format!("sign: {e:?}"))?;
        let response = block_on_handle(&proxy, &signed, now());
        if denial_reason(&response)?.is_some() {
            return Err("case 10: proxy unexpectedly denied".to_string());
        }
        let mut value: Value = serde_json::from_slice(&response).map_err(|e| format!("parse: {e}"))?;
        let sig = value["result"]["_meta"][RESPONSE_META_KEY]["signature"]["value"]
            .as_str()
            .ok_or("signature value")?
            .to_string();
        let mut chars: Vec<char> = sig.chars().collect();
        chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
        value["result"]["_meta"][RESPONSE_META_KEY]["signature"]["value"] =
            Value::String(chars.into_iter().collect());
        let corrupted = serde_json::to_vec(&value).map_err(|e| format!("serialize: {e}"))?;
        let err = cl
            .verify_response(&corrupted, &server_resolver())
            .err()
            .ok_or("case 10: client must reject the invalid response signature")?;
        report("bad_response_signature", McpReError::ResponseSigInvalid.wire_code(), err.wire_code(), sink.inner_was_reached(), true)?;
    }

    Ok(())
}
