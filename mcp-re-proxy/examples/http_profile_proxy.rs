// SPDX-License-Identifier: Apache-2.0
//! `http_profile_proxy` — a networked MCP-RE **HTTP-profile** proxy front that
//! forwards to a real **Streamable-HTTP** MCP backend (FastMCP). This is the
//! ADR-MCPRE-050 go-forward carrier wired end-to-end over the wire, using the
//! proxy's own verify / replay / forward / sign code — NOT the object/legacy path
//! and NOT a stdio inner.
//!
//! Per POST it runs the real pipeline:
//!   1. reconstruct the `HttpRequest` (method, `@target-uri`, headers, body);
//!   2. `verify_request_full` — RFC 9421 signature + RFC 9530 Content-Digest +
//!      the request evidence block (audience/artifact bindings);
//!   3. `dispatch_request_with_tier_gate` — replay admission (fail-closed);
//!   4. strip the proxy-owned top-level `_meta` and forward the clean JSON-RPC to
//!      the Streamable-HTTP backend through the proxy's real `HttpInnerPool`;
//!   5. `sign_response_full` — sign the backend's reply, bound to THIS request.
//! Any fail-closed step emits a `build_signed_rejection` receipt instead.
//!
//! This proof front is PLAIN HTTP: the HTTP-profile security is application-layer
//! (RFC 9421 request/response signatures), so a plain-HTTP local proof isolates the
//! profile crypto. mTLS transport binding is an additive layer folded in later.
//!
//! Launch (addresses come from config/ports.toml via the environment, never a
//! literal):
//!   HPP_BIND=127.0.0.1:8601 \
//!   HPP_INNER_URL=http://127.0.0.1:8620/mcp/ \
//!   HPP_TARGET=http://127.0.0.1:8601/mcp \
//!   cargo run -p mcp-re-proxy --example http_profile_proxy

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::Request;
use hyper::Response;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use mcp_re_core::InMemoryReplayCache;
use mcp_re_core::ReplayCache;
use mcp_re_http_profile::build_signed_rejection;
use mcp_re_http_profile::sign_response_full;
use mcp_re_http_profile::verify_request_full;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::RejectionReason;

use mcp_re_proxy::async_inner::AsyncInnerServer;
use mcp_re_proxy::http_inner::HttpInnerPool;
use mcp_re_proxy::http_profile_dispatch::dispatch_request_with_tier_gate;
use mcp_re_proxy::http_profile_dispatch::ProxyDispatchConfig;
use mcp_re_proxy::replay_tier::ReplayDurabilityTier;
#[cfg(feature = "redis_replay")]
use mcp_re_proxy::redis_store::RedisAtomicReplayStore;
#[cfg(feature = "redis_replay")]
use mcp_re_proxy::shared_replay::SharedReplayCache;

// Shared demo material; each example uses a different subset, so allow dead code.
#[allow(dead_code)]
#[path = "hpp_common/mod.rs"]
mod hpp_common;

/// Shared proxy state: the inner-plane client pool, the replay cache (in-memory
/// single-process OR a shared Redis tier), and the dispatch policy. All shared
/// across connections — replay must be detected across requests AND, with a shared
/// tier, across replicas.
struct ProxyState {
    inner: HttpInnerPool,
    replay: Box<dyn ReplayCache + Send + Sync>,
    dispatch_cfg: ProxyDispatchConfig,
}

#[tokio::main]
async fn main() {
    let bind = std::env::var("HPP_BIND").expect("HPP_BIND (e.g. 127.0.0.1:8601)");
    let inner_url = std::env::var("HPP_INNER_URL").expect("HPP_INNER_URL (e.g. http://127.0.0.1:8620/mcp/)");
    let inner_uri = inner_url.parse().expect("HPP_INNER_URL is a valid URI");

    // Replay tier: a shared Redis tier under fleet-strict when HPP_REDIS_URL is set
    // (the multi-replica production posture — a nonce admitted on one replica is
    // rejected on any other sharing the store); otherwise a single-process
    // in-memory cache (fleet_strict off).
    let (replay, dispatch_cfg): (Box<dyn ReplayCache + Send + Sync>, ProxyDispatchConfig) =
        match std::env::var("HPP_REDIS_URL") {
            Ok(url) => {
                let tier_str = std::env::var("HPP_REPLAY_TIER")
                    .unwrap_or_else(|_| "redis-wait-quorum:2:2000".to_string());
                let tier = ReplayDurabilityTier::parse(&tier_str).expect("HPP_REPLAY_TIER");
                #[cfg(feature = "redis_replay")]
                {
                    let mut store = RedisAtomicReplayStore::connect(&url)
                        .unwrap_or_else(|e| panic!("connect redis {url}: {e:?}"));
                    if let ReplayDurabilityTier::RedisWaitQuorum { quorum, timeout_ms } = tier {
                        store = store.with_wait_quorum(quorum, timeout_ms);
                    }
                    eprintln!("{}", tier.startup_audit_line("redis"));
                    (
                        Box::new(SharedReplayCache::new(Box::new(store), 5))
                            as Box<dyn ReplayCache + Send + Sync>,
                        ProxyDispatchConfig {
                            fleet_strict: true,
                            tier: Some(tier),
                        },
                    )
                }
                #[cfg(not(feature = "redis_replay"))]
                {
                    let _ = (url, tier);
                    panic!(
                        "HPP_REDIS_URL is set but this example was built without the \
                         `redis_replay` feature; rebuild with \
                         `--features redis_replay` for the shared multi-replica tier"
                    );
                }
            }
            Err(_) => (
                Box::new(InMemoryReplayCache::new(0)),
                ProxyDispatchConfig {
                    fleet_strict: false,
                    tier: None,
                },
            ),
        };

    let state = Arc::new(ProxyState {
        inner: HttpInnerPool::new(vec![inner_uri], Duration::from_secs(10))
            .expect("build inner pool"),
        replay,
        dispatch_cfg,
    });

    let listener = TcpListener::bind(&bind).await.expect("bind HPP_BIND");
    eprintln!(
        "http_profile_proxy: listening on http://{bind}  ->  inner {inner_url}  (target {}; fleet_strict={})",
        hpp_common::target(),
        state.dispatch_cfg.fleet_strict
    );

    loop {
        let (tcp, _peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => continue,
        };
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let io = TokioIo::new(tcp);
            let service = service_fn(move |req| handle(Arc::clone(&state), req));
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });
    }
}

/// One request through the full HTTP-profile pipeline. Always returns a hyper
/// response — a signed reply on success, a signed rejection receipt on any
/// fail-closed step.
async fn handle(
    state: Arc<ProxyState>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().as_str().to_owned();
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(name, value)| (name.as_str().to_owned(), value.to_str().unwrap_or("").to_owned()))
        .collect();
    let body = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes().to_vec(),
        Err(_) => return Ok(to_hyper(rejection(None, "mcp-re.serialization_failed", 400))),
    };

    // The canonical @target-uri both sides sign over (deployment-configured).
    let http_req = HttpRequest {
        method,
        target_uri: hpp_common::target(),
        headers,
        body,
    };

    let now = hpp_common::now_unix();
    let resolver = hpp_common::resolver();
    let expected_audience = hpp_common::audience();
    // The proof request carries no artifact bindings, so no credential material is
    // needed; a binding with no obtainable credential still fails closed.
    let no_material = |_b: &ArtifactBinding| None;

    // Step 2 — verify (RFC 9421 + 9530 + evidence block).
    let verified = match verify_request_full(
        &http_req,
        &expected_audience,
        &no_material,
        &resolver,
        now,
    ) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("reject: verify_request_full -> {}", e.wire_code());
            return Ok(to_hyper(rejection(Some(&http_req), e.wire_code(), 403)));
        }
    };

    // Step 3 — replay admission (fail-closed) through the configured tier: a shared
    // Redis tier detects a replay across ALL replicas; the fleet-strict gate refuses
    // a sub-minimum/undeclared tier before touching the store.
    if let Err(e) =
        dispatch_request_with_tier_gate(&verified, state.replay.as_ref(), None, &state.dispatch_cfg)
    {
        return Ok(to_hyper(rejection(Some(&http_req), e.wire_code(), 409)));
    }

    // Step 4 — strip the proxy-owned top-level `_meta` (the request evidence
    // block) so the backend sees clean MCP, then forward through the real inner
    // pool. `dispatch` never errors: a dead/hostile backend yields a synthesized
    // inner-unavailable response, which we STILL sign (fail-closed, never a silent
    // allow).
    let forwarded = strip_top_level_meta(&http_req.body);
    let inner_bytes = state.inner.dispatch(&forwarded).await;

    // Step 5 — sign the backend reply, bound to THIS request.
    let mut response = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: inner_bytes,
    };
    match sign_response_full(
        &mut response,
        &http_req,
        &verified.evidence,
        &hpp_common::server_identity(),
        &hpp_common::server_key(),
        hpp_common::SERVER_KEY_ID,
        now,
        now + 300,
    ) {
        Ok(()) => Ok(to_hyper(response)),
        Err(e) => Ok(to_hyper(rejection(Some(&http_req), e.wire_code(), 500))),
    }
}

/// Build a signed rejection receipt bound to `request` (when available).
fn rejection(request: Option<&HttpRequest>, wire_code: &'static str, status: u16) -> HttpResponse {
    let now = hpp_common::now_unix();
    build_signed_rejection(
        request,
        &RejectionReason {
            wire_code,
            message: format!("mcp-re http-profile proxy rejected: {wire_code}"),
        },
        status,
        &hpp_common::server_key(),
        hpp_common::SERVER_KEY_ID,
        now,
        now + 300,
    )
    .expect("rejection signs")
}

/// Remove the top-level `_meta` object (carrying the proxy-owned request evidence
/// block) so the forwarded body is clean MCP JSON-RPC. Non-object bodies pass
/// through unchanged (the inner would reject them anyway).
fn strip_top_level_meta(body: &[u8]) -> Vec<u8> {
    match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(mut v) => {
            if let Some(obj) = v.as_object_mut() {
                obj.remove("_meta");
            }
            serde_json::to_vec(&v).unwrap_or_else(|_| body.to_vec())
        }
        Err(_) => body.to_vec(),
    }
}

/// Translate the profile `HttpResponse` (status + headers + body) into a hyper
/// response, preserving every signed header (Content-Digest, Signature-Input,
/// Signature, Content-Type).
fn to_hyper(resp: HttpResponse) -> Response<Full<Bytes>> {
    let mut builder = Response::builder().status(resp.status);
    for (k, v) in &resp.headers {
        builder = builder.header(k, v);
    }
    builder
        .body(Full::new(Bytes::from(resp.body)))
        .expect("response builds")
}
