// SPDX-License-Identifier: Apache-2.0
//! `http_profile_client` — drives the `http_profile_proxy` front to prove the
//! ADR-MCPRE-050 HTTP-profile round trip end-to-end against a real FastMCP
//! Streamable-HTTP backend.
//!
//! It exercises two legs with ONE signed request:
//!   1. HAPPY PATH: sign an RFC 9421 request (`sign_request_full`), POST it, and
//!      `verify_response` the reply — proving the response is server-signed AND
//!      bound to THIS request (`;req`). The FastMCP tool result is printed from the
//!      verified body.
//!   2. REPLAY: POST the SAME signed bytes again. The proxy fails closed and
//!      returns a DELEGATED-signed rejection; the same delegated verifier proves it
//!      authentic and bound, and the frozen wire code (`mcp-re.replay_detected`) is read
//!      from the trusted body.
//!
//! Run (target from config/ports.toml via the launcher, never a literal):
//!   HPP_TARGET=http://127.0.0.1:8601/mcp \
//!   cargo run -p mcp-re-proxy --example http_profile_client

use std::io::Read;

use serde_json::json;
use serde_json::Value;

use mcp_re_http_profile::verify_delegated_response_bound_full;
use mcp_re_http_profile::DelegationExpectations;
use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ArtifactType;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::PROFILE_TAG;

// Shared demo material; each example uses a different subset, so allow dead code.
#[allow(dead_code)]
#[path = "hpp_common/mod.rs"]
mod hpp_common;

fn main() {
    let target = hpp_common::target();
    // Where each leg is actually POSTed. Both sign over the SAME canonical
    // @target-uri (HPP_TARGET) — the logical service URI a load balancer fronts —
    // so ONE signed request is valid at ANY replica. HPP_POST_A/B point the two
    // legs at distinct replica addresses to prove CROSS-replica replay detection;
    // unset, both default to the canonical target (single-replica mode).
    let post_a = std::env::var("HPP_POST_A").unwrap_or_else(|_| target.clone());
    let post_b = std::env::var("HPP_POST_B").unwrap_or_else(|_| post_a.clone());
    let agent = ureq::AgentBuilder::new().build();
    let now = hpp_common::now_unix();
    let resolver = hpp_common::resolver();
    // ADR-MCPRE-052: the client enrols ONLY the root; the credential the response carries
    // is what authorizes the delegated key. A directly root-signed response is rejected
    // (`delegation_credential_missing`) — delegation is required, not preferred.
    let verifier_audiences = [hpp_common::AUDIENCE_ID];
    let accepted_epochs = [hpp_common::EPOCH];
    let expect = DelegationExpectations {
        policy: mcp_re_http_profile::VerifierPolicy::default(),
        verifier_audiences: &verifier_audiences,
        expected_audience_hash: hpp_common::AUD_SCOPE,
        accepted_epochs: &accepted_epochs,
        max_clock_skew: 60,
    };
    // No delegated key is revoked in the proof; a real client resolves this from its
    // revocation source.
    let is_revoked = |_kid: &str| false;

    // A plain MCP tools/call (add(2,40)) — the payload the backend actually runs.
    let call = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "add", "arguments": { "a": 2, "b": 40 } }
    });

    // Compose the request evidence block. It requires at least one artifact
    // binding; we bind an OAuth DPoP credential, whose bytes the verifier derives
    // from the covered `Authorization: Bearer` header. `sign_request_full` inserts
    // the block, then emits Content-Digest + Signature-Input + Signature (covering
    // the Authorization header because it is present).
    let block = HttpRequestEvidenceBlock {
        profile: PROFILE_TAG.into(),
        audience: hpp_common::audience(),
        artifact_bindings: vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthDpop,
            hpp_common::ACCESS_TOKEN.as_bytes(),
        )],
        continuation: None,
    };
    let nonce = format!("nonce-{now}");
    let mut request = HttpRequest {
        method: "POST".into(),
        target_uri: target.clone(),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("Authorization".into(), format!("Bearer {}", hpp_common::ACCESS_TOKEN)),
        ],
        body: serde_json::to_vec(&call).expect("serialize call"),
    };
    // The delegated verifier binds the response to THIS request's evidence handle, so
    // keep what signing produced rather than recomputing it.
    let request_evidence = sign_request_full(
        &mut request,
        &block,
        &hpp_common::client_key(),
        hpp_common::CLIENT_KEY_ID,
        now,
        now + 300,
        &nonce,
    )
    .expect("sign request");

    // --- Leg 1: happy path -------------------------------------------------
    eprintln!("leg 1  POST {post_a}  (nonce={nonce})");
    let resp = post(&agent, &post_a, &request);
    // Verify the RESPONSE against CURRENT time: its `created`/`expires` freshness is
    // stamped by the server when it replies, which is necessarily after the `now` we
    // captured for signing — reusing the stale `now` would spuriously reject a
    // response created "in the future" relative to it.
    match verify_delegated_response_bound_full(
        &resp,
        &request,
        &request_evidence,
        &resolver,
        &expect,
        &is_revoked,
        hpp_common::now_unix(),
    ) {
        // A signed rejection ALSO verifies as a bound response, so distinguish a
        // success (`result`) from a fail-closed receipt (`error`) on the trusted body.
        Ok(_) if is_error_body(&resp.body) => {
            println!(
                "leg 1  UNEXPECTED signed rejection  status={}  wire_code={}",
                resp.status,
                body_wire_code(&resp.body).unwrap_or_default()
            );
            std::process::exit(1);
        }
        Ok(verified) => {
            println!(
                "leg 1  ACCEPTED  server_signer={}  status={}  fastmcp_result={}",
                verified.resolved_server_actor.identity.subject,
                resp.status,
                mcp_result(&resp.body)
            );
        }
        Err(e) => {
            println!("leg 1  UNEXPECTED verify failure: {}", e.wire_code());
            std::process::exit(1);
        }
    }

    // --- Leg 2: replay (same signed request, possibly a DIFFERENT replica) --
    let cross = if post_b == post_a { "" } else { "  [CROSS-REPLICA]" };
    eprintln!("leg 2  POST {post_b}  (SAME nonce -> replay){cross}");
    let resp2 = post(&agent, &post_b, &request);
    // A DELEGATED rejection receipt is verified through the SAME delegated path as an
    // answer — it is signed by the delegated key and carries the same credential, so the
    // refusal is as verifiable as an acceptance. `verify_signed_rejection` is the
    // direct-root verifier: it has no credential chain, so it cannot resolve the
    // delegated kid and would fail `actor_binding_failed` on a genuine receipt.
    //
    // Verifying only proves the receipt is authentic and bound to THIS request; whether
    // it is an acceptance is then read from the trusted body.
    match verify_delegated_response_bound_full(
        &resp2,
        &request,
        &request_evidence,
        &resolver,
        &expect,
        &is_revoked,
        hpp_common::now_unix(),
    ) {
        Ok(_) if is_error_body(&resp2.body) => {
            let wire_code = body_wire_code(&resp2.body).unwrap_or_default();
            println!(
                "leg 2  REJECTED  delegated rejection verified  status={}  wire_code={}",
                resp2.status, wire_code
            );
            if wire_code != "mcp-re.replay_detected" {
                println!("leg 2  WARNING: expected mcp-re.replay_detected");
                std::process::exit(1);
            }
        }
        Ok(_) => {
            println!("leg 2  UNEXPECTED: replay was ACCEPTED");
            std::process::exit(1);
        }
        Err(e) => {
            println!("leg 2  UNEXPECTED: rejection did not verify: {}", e.wire_code());
            std::process::exit(1);
        }
    }

    println!("OK  HTTP-profile round trip + replay rejection both proven");
}

/// POST the signed request, returning the response as an `HttpResponse` for BOTH
/// success and error statuses (a rejection is a 4xx/5xx the profile still signs).
fn post(agent: &ureq::Agent, url: &str, request: &HttpRequest) -> HttpResponse {
    let mut r = agent.post(url);
    for (k, v) in &request.headers {
        r = r.set(k, v);
    }
    match r.send_bytes(&request.body) {
        Ok(resp) => read_response(resp),
        Err(ureq::Error::Status(_code, resp)) => read_response(resp),
        Err(e) => panic!("transport error to {url}: {e}"),
    }
}

/// Reconstruct the profile `HttpResponse` from a ureq response. Header names +
/// values are read BEFORE consuming the body reader.
fn read_response(resp: ureq::Response) -> HttpResponse {
    let status = resp.status();
    let headers: Vec<(String, String)> = resp
        .headers_names()
        .iter()
        .filter_map(|name| resp.header(name).map(|v| (name.clone(), v.to_owned())))
        .collect();
    let mut body = Vec::new();
    resp.into_reader()
        .take(1024 * 1024)
        .read_to_end(&mut body)
        .expect("read response body");
    HttpResponse {
        status,
        headers,
        body,
    }
}

/// `true` when the verified body is a JSON-RPC error (a signed rejection receipt),
/// not a success `result`.
fn is_error_body(body: &[u8]) -> bool {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v.get("error").cloned())
        .is_some()
}

/// The frozen `mcp-re.*` wire code from an error body, if present.
fn body_wire_code(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<Value>(body)
        .ok()?
        .pointer("/error/data/mcp_re_error/wire_code")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// Strip the proxy-owned top-level `_meta` (response evidence block) from a
/// verified body and render the MCP `result` for display.
fn mcp_result(body: &[u8]) -> String {
    match serde_json::from_slice::<Value>(body) {
        Ok(v) => v
            .get("result")
            .map(|r| r.to_string())
            .unwrap_or_else(|| v.to_string()),
        Err(_) => String::from_utf8_lossy(body).into_owned(),
    }
}
