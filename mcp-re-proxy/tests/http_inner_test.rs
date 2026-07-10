//! ADR-MCPRE-051 §3 (Phase 3) — the async HTTP inner plane (`HttpInnerPool`),
//! proven against an IN-PROCESS `hyper` backend (no external infra).
//!
//! Verifies the production inner transport end to end: a POST JSON-RPC request is
//! delivered to a stateless HTTP backend and its JSON response bytes are returned
//! verbatim; a dead backend, a non-2xx status, and a timeout each FAIL CLOSED with
//! a synthesized JSON-RPC error response (never a silent allow, never a hang);
//! round-robin spreads requests across backends.
//!
//! Resilience (ADR-MCPRE-051 §3, MCPRE-119): a failing or slow backend is ejected
//! after a bounded number of failures, traffic rebalances onto healthy backends,
//! an all-ejected pool fails closed WITHOUT dispatching, and a recovered backend is
//! re-admitted via a Half-Open probe.

#![cfg(feature = "async_serve")]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
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
use mcp_re_proxy::http_inner::BreakerConfig;
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

// --- Resilience: outlier ejection, circuit breaking, health-aware LB (MCPRE-119) -

/// A backend that COUNTS every request it receives and always answers with
/// `status` + `body`. The counter lets a test assert that an ejected backend stops
/// receiving traffic.
async fn spawn_counting_backend(status: u16, body: &'static [u8]) -> (SocketAddr, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    let hits_srv = Arc::clone(&hits);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { continue };
            let hits_conn = Arc::clone(&hits_srv);
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |_req| {
                    let hits_req = Arc::clone(&hits_conn);
                    async move {
                        hits_req.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(status)
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from_static(body)))
                                .expect("response builds"),
                        )
                    }
                });
                let _ = auto::Builder::new(TokioExecutor::new()).serve_connection(io, svc).await;
            });
        }
    });
    (addr, hits)
}

/// A backend that counts each request, then SLEEPS `delay` before answering — so a
/// pool whose `request_timeout` is shorter sees every call as a timeout failure.
async fn spawn_slow_counting_backend(delay: Duration, body: &'static [u8]) -> (SocketAddr, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    let hits_srv = Arc::clone(&hits);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { continue };
            let hits_conn = Arc::clone(&hits_srv);
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |_req| {
                    let hits_req = Arc::clone(&hits_conn);
                    async move {
                        hits_req.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(delay).await;
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(200)
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from_static(body)))
                                .expect("response builds"),
                        )
                    }
                });
                let _ = auto::Builder::new(TokioExecutor::new()).serve_connection(io, svc).await;
            });
        }
    });
    (addr, hits)
}

/// A backend that answers 200+`body` while `healthy` is set, else 500 — used to
/// prove recovery re-admission (fail → eject → recover → probe closes the breaker).
async fn spawn_flappy_backend(healthy: Arc<AtomicBool>, body: &'static [u8]) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { continue };
            let healthy_conn = Arc::clone(&healthy);
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |_req| {
                    let healthy_req = Arc::clone(&healthy_conn);
                    async move {
                        let status = if healthy_req.load(Ordering::SeqCst) { 200 } else { 500 };
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(status)
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from_static(body)))
                                .expect("response builds"),
                        )
                    }
                });
                let _ = auto::Builder::new(TokioExecutor::new()).serve_connection(io, svc).await;
            });
        }
    });
    addr
}

fn has_result(bytes: &[u8]) -> bool {
    serde_json::from_slice::<Value>(bytes).ok().and_then(|v| v.get("result").cloned()).is_some()
}

fn is_error(bytes: &[u8]) -> bool {
    serde_json::from_slice::<Value>(bytes)
        .ok()
        .map(|v| v.get("error").is_some() && v.get("result").is_none())
        .unwrap_or(false)
}

#[test]
fn failing_backend_is_ejected_and_traffic_rebalances_to_healthy() {
    rt().block_on(async {
        let (dead, dead_hits) = spawn_counting_backend(500, b"boom").await;
        let (live, live_hits) = spawn_counting_backend(200, INNER_OK).await;
        let pool = HttpInnerPool::with_breaker_config(
            vec![uri_for(dead), uri_for(live)],
            Duration::from_secs(2),
            BreakerConfig { failure_threshold: 2, ejection_duration: Duration::from_secs(10) },
        )
        .expect("pool builds");

        let mut ok = 0;
        for _ in 0..30 {
            if has_result(&pool.dispatch(br#"{"jsonrpc":"2.0","id":1}"#).await) {
                ok += 1;
            }
        }

        assert_eq!(pool.ejected_backend_count(), 1, "the failing backend must be ejected");
        let dead_n = dead_hits.load(Ordering::SeqCst);
        let live_n = live_hits.load(Ordering::SeqCst);
        assert!(dead_n <= 3, "ejected backend must stop receiving traffic (~threshold hits), got {dead_n}");
        assert!(live_n >= 25, "healthy backend must absorb rebalanced traffic, got {live_n}");
        assert!(ok >= 25, "most requests succeed via the healthy backend, got {ok}");
    });
}

#[test]
fn slow_backend_is_ejected_and_does_not_stall_the_plane() {
    rt().block_on(async {
        // The slow backend never answers within the pool's 300ms timeout.
        let (slow, slow_hits) = spawn_slow_counting_backend(Duration::from_secs(30), INNER_OK).await;
        let (fast, fast_hits) = spawn_counting_backend(200, INNER_OK).await;
        let pool = HttpInnerPool::with_breaker_config(
            vec![uri_for(slow), uri_for(fast)],
            Duration::from_millis(300),
            BreakerConfig { failure_threshold: 2, ejection_duration: Duration::from_secs(10) },
        )
        .expect("pool builds");

        let start = std::time::Instant::now();
        let mut ok = 0;
        for _ in 0..20 {
            if has_result(&pool.dispatch(br#"{"jsonrpc":"2.0","id":1}"#).await) {
                ok += 1;
            }
        }
        let elapsed = start.elapsed();

        assert_eq!(pool.ejected_backend_count(), 1, "the slow backend must be ejected");
        assert!(
            slow_hits.load(Ordering::SeqCst) <= 3,
            "the slow backend must stop receiving traffic after ejection, got {}",
            slow_hits.load(Ordering::SeqCst)
        );
        assert!(fast_hits.load(Ordering::SeqCst) >= 17, "the fast backend serves the rest");
        assert!(ok >= 17, "the vast majority succeed via the fast backend, got {ok}");
        // Only the ~2 pre-ejection timeouts cost 300ms; the rest are fast. Total must
        // be far below 20×300ms — one slow backend did not stall the plane's p99.
        assert!(elapsed < Duration::from_secs(3), "the slow backend stalled the plane: {elapsed:?}");
    });
}

#[test]
fn all_backends_open_fails_closed_without_dispatching() {
    rt().block_on(async {
        let (dead, dead_hits) = spawn_counting_backend(500, b"boom").await;
        let pool = HttpInnerPool::with_breaker_config(
            vec![uri_for(dead)],
            Duration::from_secs(2),
            BreakerConfig { failure_threshold: 1, ejection_duration: Duration::from_secs(10) },
        )
        .expect("pool builds");

        // One failure ejects the only backend (threshold = 1).
        assert!(is_error(&pool.dispatch(br#"{"id":1}"#).await));
        assert_eq!(pool.ejected_backend_count(), 1);
        let hits_after_eject = dead_hits.load(Ordering::SeqCst);

        // With the circuit open, further requests fail closed WITHOUT dispatching —
        // no unbounded queuing onto a known-dead backend.
        for _ in 0..5 {
            assert!(is_error(&pool.dispatch(br#"{"id":1}"#).await), "all-open must fail closed");
        }
        assert_eq!(
            dead_hits.load(Ordering::SeqCst),
            hits_after_eject,
            "an open circuit must not dispatch to the ejected backend"
        );
    });
}

#[test]
fn ejected_backend_is_readmitted_after_cooldown_probe_succeeds() {
    rt().block_on(async {
        let healthy = Arc::new(AtomicBool::new(false)); // starts unhealthy (500s)
        let addr = spawn_flappy_backend(Arc::clone(&healthy), INNER_OK).await;
        let pool = HttpInnerPool::with_breaker_config(
            vec![uri_for(addr)],
            Duration::from_secs(2),
            BreakerConfig { failure_threshold: 2, ejection_duration: Duration::from_millis(300) },
        )
        .expect("pool builds");

        // Two failures eject the only backend.
        for _ in 0..2 {
            let _ = pool.dispatch(br#"{"id":1}"#).await;
        }
        assert_eq!(pool.ejected_backend_count(), 1);
        // Before the cooldown elapses it stays fail-closed.
        assert!(is_error(&pool.dispatch(br#"{"id":1}"#).await));

        // The backend recovers; after the cooldown a Half-Open probe re-admits it.
        healthy.store(true, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(400)).await;
        let out = pool.dispatch(br#"{"id":1}"#).await;
        assert!(has_result(&out), "recovered backend must be re-admitted via probe: {:?}", String::from_utf8_lossy(&out));
        assert_eq!(pool.ejected_backend_count(), 0, "a successful probe closes the breaker");
    });
}

// --- concurrency + pool-exhaustion backpressure (MCPRE-118, ADR-051 §3) -------

#[test]
fn concurrent_dispatches_are_in_flight_together_not_serialized() {
    rt().block_on(async {
        // One slow backend (300ms/req). Six dispatches issued concurrently must
        // OVERLAP: a serial pipe would take ~1.8s; concurrent keep-alive/H2 in-flight
        // finishes in ~one backend delay. This is the "no serial pipe" proof (#1).
        let (addr, hits) = spawn_slow_counting_backend(Duration::from_millis(300), INNER_OK).await;
        let pool = HttpInnerPool::new(vec![uri_for(addr)], Duration::from_secs(5)).expect("pool");

        let req = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#;
        let start = std::time::Instant::now();
        let (a, b, c, d, e, f) = tokio::join!(
            pool.dispatch(req),
            pool.dispatch(req),
            pool.dispatch(req),
            pool.dispatch(req),
            pool.dispatch(req),
            pool.dispatch(req),
        );
        let elapsed = start.elapsed();

        for out in [&a, &b, &c, &d, &e, &f] {
            assert_eq!(
                out.as_slice(),
                INNER_OK,
                "every concurrent dispatch returns the inner response verbatim"
            );
        }
        assert_eq!(hits.load(Ordering::SeqCst), 6, "all six requests reached the backend");
        assert!(
            elapsed < Duration::from_millis(1500),
            "6×300ms dispatches took {elapsed:?}; concurrent in-flight must finish far below \
             the ~1.8s serial time (no serial pipe)"
        );
    });
}

#[test]
fn pool_exhaustion_fails_closed_immediately_without_queuing() {
    rt().block_on(async {
        // A backend that sleeps far longer than the test, so a dispatch that acquires
        // an in-flight permit holds it. Cap concurrency at 2. Two dispatches occupy both
        // permits; a third, attempted while they are in flight, must fail closed
        // IMMEDIATELY — no queue, no wait, never reaching a backend (#2).
        let (addr, hits) = spawn_slow_counting_backend(Duration::from_secs(30), INNER_OK).await;
        let pool = HttpInnerPool::new(vec![uri_for(addr)], Duration::from_secs(60))
            .expect("pool")
            .with_max_in_flight(2);
        assert_eq!(pool.max_in_flight(), 2);

        let req = br#"{"jsonrpc":"2.0","id":1}"#;

        // Two long-lived dispatches hold both permits.
        let holders = async {
            tokio::join!(pool.dispatch(req), pool.dispatch(req))
        };
        // Concurrently: once both permits are held, a third dispatch must be rejected
        // fast and never touch a backend. Completing the prober ends the test; the
        // holders are then dropped (no 30s wait).
        let prober = async {
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert_eq!(
                pool.in_flight_available(),
                0,
                "both in-flight permits must be held by the two long dispatches"
            );
            let start = std::time::Instant::now();
            let out = pool.dispatch(req).await;
            let took = start.elapsed();
            assert!(
                is_error(&out),
                "a saturated pool must fail closed: {:?}",
                String::from_utf8_lossy(&out)
            );
            assert!(
                took < Duration::from_millis(100),
                "fail-closed on saturation must be immediate, not queued: {took:?}"
            );
            assert_eq!(
                hits.load(Ordering::SeqCst),
                2,
                "the rejected dispatch must never reach a backend (2 holders only)"
            );
        };

        tokio::select! {
            _ = holders => unreachable!("holders sleep well past the prober"),
            _ = prober => {}
        }

        // Permits are released once the holders are dropped: a fresh dispatch is
        // admitted again (bounded, not permanently wedged).
        assert_eq!(pool.in_flight_available(), 2, "permits are released after the holders drop");
    });
}
