// SPDX-License-Identifier: Apache-2.0
//! Async load generator for the saturation rig.
//!
//! SEPARATE from `tls_load_harness_bench` on purpose. That harness is the
//! ADR-MCPRE-051 §7 regression detector and every historical anchor was measured with
//! it; changing its client would make those numbers incomparable. This one answers a
//! different question — how fast can the proxy actually go — and its numbers are NOT
//! comparable to the §7 anchor.
//!
//! Three things the §7 client does that make it unable to saturate a fast proxy, and
//! that this one does not:
//!
//! 1. **One OS thread per connection.** At 1024 connections that is 1024 threads on a
//!    14-core box, so the client spends its time context-switching. Here each connection
//!    is a tokio task over a small worker pool.
//! 2. **Ed25519 signing on the hot path.** The §7 anchor notes client-side crypto costs
//!    as much as server-side, so a co-located client taxes the measurement twice. Here
//!    the corpus is signed BEFORE the clock starts and replayed from memory.
//! 3. **No remote target.** It spawns its own proxy, which is why every run so far has
//!    been co-located. This one drives `--target`.
//!
//! Nonces must stay unique or the replay tier rejects the request, so the corpus is
//! sized to the request count and each entry carries its own.

use std::sync::atomic::AtomicU64;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use mcp_re_client_core::build_signed_request;
use mcp_re_client_core::ArtifactBinding;
use mcp_re_client_core::ArtifactType;
use mcp_re_client_core::AudienceTuple;
use mcp_re_client_core::RequestSigningInputs;
use mcp_re_client_core::SignedRequest;
use mcp_re_core::SigningKey;

use rustls::client::danger::HandshakeSignatureValid;
use rustls::client::danger::ServerCertVerified;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::ring;
use rustls::ClientConfig;
use rustls::DigitallySignedStruct;
use rustls::SignatureScheme;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::ServerName;
use rustls_pki_types::UnixTime;

use serde_json::json;
use serde_json::Map;
use serde_json::Value;

use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

const AUDIENCE: &str = "did:example:server-1";
const SIGNER_A_KEY_ID: &str = "key-a";
const TARGET_URI: &str = "https://localhost/";
const DPOP_TOKEN: &str = "loadgen-dpop-token";

/// The rig drives its own proxy over loopback or a private link, and the server leaf is
/// minted per run — pinning it would only re-test rcgen. Client AUTH is still real: the
/// proxy verifies the client chain and the RFC 9421 signature, which is what is being
/// measured.
#[derive(Debug)]
struct AcceptAnyServer;

impl ServerCertVerifier for AcceptAnyServer {
    fn verify_server_cert(
        &self,
        _e: &CertificateDer<'_>,
        _i: &[CertificateDer<'_>],
        _s: &ServerName<'_>,
        _o: &[u8],
        _n: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

struct Args {
    target: String,
    connections: usize,
    requests: usize,
    mode: String,
    client_cert: String,
    client_key: String,
    out: Option<String>,
    id: String,
}

fn args() -> Args {
    let mut a = Args {
        target: String::new(),
        connections: 128,
        requests: 20000,
        mode: "keepalive".into(),
        client_cert: String::new(),
        client_key: String::new(),
        out: None,
        id: "gen0".into(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut val = || it.next().expect("flag needs a value");
        match flag.as_str() {
            "--target" => a.target = val(),
            "--connections" => a.connections = val().parse().expect("connections"),
            "--requests" => a.requests = val().parse().expect("requests"),
            "--mode" => a.mode = val(),
            "--client-cert" => a.client_cert = val(),
            "--client-key" => a.client_key = val(),
            "--out" => a.out = Some(val()),
            "--id" => a.id = val(),
            other => panic!("unknown flag {other}"),
        }
    }
    assert!(!a.target.is_empty(), "--target is required");
    a
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

/// Sign one request. Called only during the pre-signing phase.
fn sign(nonce: &str, key: &SigningKey) -> SignedRequest {
    let nonce = format!("{nonce}-padded-to-the-128-bit-floor");
    let now = now_unix();
    let audience = AudienceTuple {
        audience_id: AUDIENCE.to_string(),
        target_uri: TARGET_URI.to_string(),
        route: None,
    };
    let binding = ArtifactBinding::opaque_digest(ArtifactType::OauthDpop, DPOP_TOKEN.as_bytes());
    let inputs = RequestSigningInputs::new(
        SIGNER_A_KEY_ID,
        audience,
        vec![binding],
        &nonce,
        now,
        // Wide enough that a long pre-signing phase cannot expire the head of the
        // corpus before the tail is sent.
        now + 3600,
    )
    .with_headers(vec![(
        "Authorization".to_string(),
        format!("Bearer {DPOP_TOKEN}"),
    )]);
    let mut params = Map::new();
    params.insert("text".to_string(), Value::String("hello".to_string()));
    build_signed_request(
        &Value::String("req-1".to_string()),
        "echo",
        params,
        TARGET_URI,
        &inputs,
        key,
    )
    .expect("sign")
}

/// Serialise a signed request to wire bytes once, so the hot loop only writes.
fn wire(signed: &SignedRequest, keep_alive: bool) -> Vec<u8> {
    let req = signed.request();
    let mut head = String::new();
    head.push_str("POST / HTTP/1.1\r\nHost: localhost\r\n");
    head.push_str(if keep_alive {
        "Connection: keep-alive\r\n"
    } else {
        "Connection: close\r\n"
    });
    for (name, value) in &req.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str(&format!("Content-Length: {}\r\n\r\n", req.body.len()));
    let mut out = head.into_bytes();
    out.extend_from_slice(&req.body);
    out
}

/// Read one HTTP response far enough to know it completed. Content-Length only — the
/// proxy always sets it, and chunked parsing here would measure the client.
fn note(slot: &Arc<std::sync::Mutex<Option<String>>>, msg: String) {
    let mut g = slot.lock().expect("first_err");
    if g.is_none() {
        *g = Some(msg);
    }
}

async fn read_response(
    stream: &mut (impl AsyncReadExt + Unpin),
    buf: &mut Vec<u8>,
) -> Result<(), String> {
    buf.clear();
    let mut tmp = [0u8; 8192];
    let head_end = loop {
        let n = stream.read(&mut tmp).await.map_err(|e| format!("io {e}"))?;
        if n == 0 {
            return Err(format!(
                "eof before headers ({} bytes: {:?})",
                buf.len(),
                String::from_utf8_lossy(&buf[..buf.len().min(200)])
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        if buf.len() > 1 << 20 {
            return Err("headers exceeded 1 MiB".into());
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
    // A READABLE response is not a SERVED one. This used to count any parseable reply as
    // a success, so a proxy rejecting every request at the replay tier reported zero
    // failures and a healthy rate — while serving nothing. A rejection is cheaper than a
    // real request (no backend dispatch, no response signature), so counting it inflates
    // throughput precisely when the run is least valid.
    let status_ok = head
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .is_some_and(|c| (200..300).contains(&c));
    if !status_ok {
        let status_line = head
            .lines()
            .next()
            .unwrap_or("(no status line)")
            .to_string();
        return Err(format!("non-2xx response: {status_line}"));
    }
    let Some(len) = head
        .split("content-length:")
        .nth(1)
        .and_then(|r| r.split("\r\n").next())
        .and_then(|v| v.trim().parse::<usize>().ok())
    else {
        return Err(format!(
            "no parseable content-length in: {:?}",
            &head[..head.len().min(300)]
        ));
    };
    while buf.len() < head_end + len {
        let n = stream.read(&mut tmp).await.map_err(|e| format!("io {e}"))?;
        if n == 0 {
            return Err("eof mid-body".into());
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    Ok(())
}

fn main() {
    let a = args();
    let keep_alive = a.mode == "keepalive";

    // DER, not PEM: the orchestrator writes what rustls consumes directly, so the
    // generator needs no PEM parser and the rig gains no dependency.
    let chain = vec![CertificateDer::from(
        std::fs::read(&a.client_cert).expect("client cert der"),
    )];
    let key_der = PrivateKeyDer::try_from(std::fs::read(&a.client_key).expect("client key der"))
        .expect("client key is PKCS#8 DER");

    let config = Arc::new(
        ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServer))
            .with_client_auth_cert(chain, key_der)
            .expect("client auth"),
    );

    // PRE-SIGN. Every Ed25519 signature happens here, before the clock starts, so the
    // measured window contains no client-side asymmetric crypto.
    let signer = SigningKey::from_seed_bytes(&[1u8; 32]);
    let sign_started = Instant::now();
    // The nonce must be unique across RUNS, not just across generators within one run.
    // It used to be `sat-{id}-{i}`, which is identical in every run — so the
    // orchestrator's M+1 saturation probe replayed the measurement run's corpus verbatim
    // and the proxy correctly rejected 6 of every 7 requests at the replay tier. Those
    // rejections skip the backend AND the response signature, so they are cheap, the
    // probe looked FASTER than the run it was probing, and every row was stamped CLIENT
    // on a gain that was pure replay rejection. The pid/start salt makes each process's
    // corpus its own.
    let salt = format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    );
    let corpus: Arc<Vec<Vec<u8>>> = Arc::new(
        (0..a.requests)
            .map(|i| {
                wire(
                    &sign(&format!("sat-{salt}-{}-{i}", a.id), &signer),
                    keep_alive,
                )
            })
            .collect(),
    );
    let presign_secs = sign_started.elapsed().as_secs_f64();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let next = Arc::new(AtomicUsize::new(0));
    let ok = Arc::new(AtomicUsize::new(0));
    let failed = Arc::new(AtomicUsize::new(0));
    let handshakes = Arc::new(AtomicU64::new(0));
    let lat = Arc::new(std::sync::Mutex::new(Vec::<u64>::with_capacity(a.requests)));
    // First failure reason, kept verbatim. A rig that reports "8000 failures" without
    // saying why costs more time than the line that records it.
    let first_err: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));

    // Absolute wall clock, so the orchestrator can compute TRUE aggregate throughput
    // over the union of the generators' windows. Summing each generator's own
    // successes/elapsed overstates the total whenever their windows are staggered — and
    // they are, because each pre-signs its corpus first.
    let start_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64;
    let started = Instant::now();
    rt.block_on(async {
        let mut tasks = Vec::with_capacity(a.connections);
        for _ in 0..a.connections {
            let first_err = Arc::clone(&first_err);
            let (corpus, next, ok, failed, handshakes, lat, config, target) = (
                Arc::clone(&corpus),
                Arc::clone(&next),
                Arc::clone(&ok),
                Arc::clone(&failed),
                Arc::clone(&handshakes),
                Arc::clone(&lat),
                Arc::clone(&config),
                a.target.clone(),
            );
            tasks.push(tokio::spawn(async move {
                let connector = tokio_rustls::TlsConnector::from(config);
                let name = ServerName::try_from("localhost").expect("name");
                let mut held: Option<tokio_rustls::client::TlsStream<TcpStream>> = None;
                let mut local: Vec<u64> = Vec::new();
                let mut buf = Vec::with_capacity(16 * 1024);
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= corpus.len() {
                        break;
                    }
                    let t0 = Instant::now();
                    let mut stream = match held.take() {
                        Some(s) => s,
                        None => {
                            let tcp = match TcpStream::connect(&target).await {
                                Ok(t) => t,
                                Err(e) => {
                                    note(&first_err, format!("tcp connect: {e}"));
                                    failed.fetch_add(1, Ordering::Relaxed);
                                    continue;
                                }
                            };
                            let _ = tcp.set_nodelay(true);
                            handshakes.fetch_add(1, Ordering::Relaxed);
                            match connector.connect(name.clone(), tcp).await {
                                Ok(s) => s,
                                Err(e) => {
                                    note(&first_err, format!("tls handshake: {e}"));
                                    failed.fetch_add(1, Ordering::Relaxed);
                                    continue;
                                }
                            }
                        }
                    };
                    if let Err(e) = stream.write_all(&corpus[i]).await {
                        note(&first_err, format!("write: {e}"));
                        failed.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    if let Err(e) = stream.flush().await {
                        note(&first_err, format!("flush: {e}"));
                        failed.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    match read_response(&mut stream, &mut buf).await {
                        Ok(()) => {}
                        Err(e) => {
                            note(&first_err, format!("read: {e}"));
                            failed.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    }
                    local.push(t0.elapsed().as_micros() as u64);
                    ok.fetch_add(1, Ordering::Relaxed);
                    if keep_alive {
                        held = Some(stream);
                    }
                }
                lat.lock().expect("lat").extend(local);
            }));
        }
        for t in tasks {
            let _ = t.await;
        }
    });
    let elapsed = started.elapsed().as_secs_f64();
    let end_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64;

    let mut lat = lat.lock().expect("lat").clone();
    lat.sort_unstable();
    let q = |p: f64| -> u64 {
        if lat.is_empty() {
            return 0;
        }
        lat[((lat.len() as f64 * p) as usize).min(lat.len() - 1)]
    };
    let successes = ok.load(Ordering::Relaxed);
    let report = json!({
        "schema": "mcp-re-saturation-loadgen/v1",
        "id": a.id,
        "mode": a.mode,
        "connections": a.connections,
        "requests": a.requests,
        "successes": successes,
        "failures": failed.load(Ordering::Relaxed),
        "handshakes": handshakes.load(Ordering::Relaxed),
        "wall_secs": elapsed,
        "start_ms": start_ms,
        "end_ms": end_ms,
        "presign_secs": presign_secs,
        "throughput_rps": successes as f64 / elapsed,
        "latency_us": { "p50": q(0.50), "p99": q(0.99), "p999": q(0.999),
                        "max": lat.last().copied().unwrap_or(0) },
        "first_error": *first_err.lock().expect("first_err"),
    });
    let text = serde_json::to_string_pretty(&report).expect("json");
    if let Some(path) = a.out {
        std::fs::write(path, &text).expect("write report");
    }
    println!("{text}");
}
