// SPDX-License-Identifier: Apache-2.0
//! Inner echo backend for the saturation rig, as its OWN process.
//!
//! The §7 harness runs its backend inside the test process on a four-worker runtime, so
//! its CPU is indistinguishable from the load generator's and from the proxy's. When the
//! measured ceiling stopped moving with proxy cores there was no way to tell which of the
//! three had bound it.
//!
//! Here it is a separate process with a configurable worker count, so `ps` attributes its
//! CPU separately and a saturated backend is visible instead of inferred.

use std::convert::Infallible;

use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::body::Incoming;
use hyper::Request;
use hyper::Response;
use hyper::StatusCode;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto;
use serde_json::Value;

/// Answer a JSON-RPC request by echoing its method, so a success corresponds to a
/// genuinely parsed request rather than a static 200.
async fn echo(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let body = req.into_body().collect().await.map(|b| b.to_bytes());
    let method = body
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .and_then(|v| v.get("method").and_then(|m| m.as_str()).map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_string());
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "req-1",
        "result": { "echo": method },
    });
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(payload.to_string())))
        .expect("response"))
}

fn main() {
    let mut workers = 4usize;
    let mut bind = "127.0.0.1:0".to_string();
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut val = || it.next().expect("flag needs a value");
        match flag.as_str() {
            "--workers" => workers = val().parse().expect("workers"),
            "--bind" => bind = val(),
            other => panic!("unknown flag {other}"),
        }
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
        .expect("runtime");

    rt.block_on(async move {
        let listener = tokio::net::TcpListener::bind(&bind).await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        // The orchestrator reads this line to learn the ephemeral port, so it must be
        // the first thing on stdout and must be flushed.
        println!("saturation-backend listening on {addr}");
        use std::io::Write;
        std::io::stdout().flush().expect("flush");
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let _ = stream.set_nodelay(true);
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let _ = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(io, hyper::service::service_fn(echo))
                    .await;
            });
        }
    });
}
