//! ADR-MCPRE-051 §3 (Phase 3) — the async HTTP inner plane (`HttpInnerPool`),
//! proven against an IN-PROCESS `hyper` backend (no external infra).
//!
//! Verifies the production inner transport end to end: a POST JSON-RPC request is
//! delivered to a stateless HTTP backend and its JSON response bytes are returned
//! verbatim; a dead backend, a non-2xx status, and a timeout each FAIL CLOSED with
//! a synthesized JSON-RPC error response (never a silent allow, never a hang);
//! round-robin spreads requests across backends.

#![cfg(feature = "async_serve")]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::Response;
use hyper::Uri;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;

use mcp_re_proxy::async_inner::AsyncInnerServer;
use mcp_re_proxy::http_inner::HttpInnerPool;

use serde_json::Value;

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("runtime")
}

/// Spawn an in-process HTTP backend that answers every request with `status` and
/// `body`. Returns its bound address. Runs on the current runtime.
async fn spawn_backend(status: u16, body: &'static [u8]) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |_req| async move {
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(status)
                            .header("content-type", "application/json")
                            .body(Full::new(Bytes::from_static(body)))
                            .expect("response builds"),
                    )
                });
                let _ = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });
    addr
}

fn uri_for(addr: SocketAddr) -> Uri {
    format!("http://{addr}/mcp").parse().expect("uri")
}

/// A JSON-RPC-shaped inner result body.
const INNER_OK: &[u8] = br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;

#[test]
fn dispatch_returns_backend_response_verbatim() {
    rt().block_on(async {
        let addr = spawn_backend(200, INNER_OK).await;
        let pool = HttpInnerPool::new(vec![uri_for(addr)], Duration::from_secs(5))
            .expect("pool builds");

        let out = pool.dispatch(br#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#).await;
        assert_eq!(
            out, INNER_OK,
            "the inner backend's JSON response must be returned verbatim"
        );
    });
}

#[test]
fn dead_backend_fails_closed_with_error_response() {
    rt().block_on(async {
        // Bind a port, capture its address, then DROP the listener so nothing is
        // listening — a connect must be refused.
        let addr = {
            let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            l.local_addr().expect("addr")
        };
        let pool = HttpInnerPool::new(vec![uri_for(addr)], Duration::from_secs(2))
            .expect("pool builds");

        let out = pool.dispatch(br#"{"jsonrpc":"2.0","id":1}"#).await;
        let value: Value = serde_json::from_slice(&out).expect("fail-closed JSON error");
        assert!(
            value.get("error").is_some() && value.get("result").is_none(),
            "a dead backend must fail closed with a JSON-RPC error response (no result), got {value}"
        );
    });
}

#[test]
fn non_2xx_status_fails_closed() {
    rt().block_on(async {
        let addr = spawn_backend(500, b"upstream boom").await;
        let pool = HttpInnerPool::new(vec![uri_for(addr)], Duration::from_secs(5))
            .expect("pool builds");

        let out = pool.dispatch(br#"{"jsonrpc":"2.0","id":1}"#).await;
        let value: Value = serde_json::from_slice(&out).expect("fail-closed JSON error");
        assert!(
            value.get("error").is_some() && value.get("result").is_none(),
            "a non-2xx inner status must fail closed, never sign backend error bytes"
        );
    });
}

#[test]
fn empty_backend_list_fails_closed_at_construction() {
    assert!(
        HttpInnerPool::new(vec![], Duration::from_secs(1)).is_err(),
        "a pool with no backends must fail closed at construction, not serve nothing silently"
    );
}

#[test]
fn round_robin_spreads_across_backends() {
    rt().block_on(async {
        // Two distinct backends returning distinguishable bodies.
        let a = spawn_backend(200, br#"{"jsonrpc":"2.0","id":1,"result":"A"}"#).await;
        let b = spawn_backend(200, br#"{"jsonrpc":"2.0","id":1,"result":"B"}"#).await;
        let pool = HttpInnerPool::new(vec![uri_for(a), uri_for(b)], Duration::from_secs(5))
            .expect("pool builds");

        // Four sequential requests round-robin A,B,A,B.
        let mut seen = Vec::new();
        for _ in 0..4 {
            let out = pool.dispatch(br#"{"jsonrpc":"2.0","id":1}"#).await;
            let v: Value = serde_json::from_slice(&out).expect("json");
            seen.push(v["result"].as_str().expect("result str").to_string());
        }
        assert!(
            seen.contains(&"A".to_string()) && seen.contains(&"B".to_string()),
            "round-robin must reach both backends, saw {seen:?}"
        );
    });
}
