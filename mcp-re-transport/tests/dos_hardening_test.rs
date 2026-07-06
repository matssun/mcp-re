//! MCPS-081 — transport-client denial-of-service hardening (audit M-3/M-4/M-5/M-6).
//!
//! The verifying mTLS client is the symmetric counterpart of the proxy server,
//! which already defends slow-loris and OOM via `ServerLimits`
//! (read/write timeouts + `max_body_bytes`). These tests prove the client now
//! has the same bounds and that they are LOAD-BEARING: removing either control
//! flips the matching test red.
//!
//!   1. `handshake_stall_times_out_not_hangs` — a peer that accepts the TCP
//!      connection but never speaks TLS must NOT pin the client thread forever;
//!      with a read timeout the round trip fails fast (well inside the budget).
//!      Without `set_read_timeout`, the client would block until the peer gives
//!      up and the elapsed-time assertion would fail.
//!   2. `oversized_response_is_rejected_not_oom` — a fully-authenticated server
//!      that floods a response larger than `max_response_bytes` is rejected with
//!      `ResponseTooLarge`, not read unbounded into memory. Without the cap the
//!      client would return `Ok` with the whole flood and the assertion fails.
//!   3. `slow_trickle_response_aborts_at_aggregate_deadline` — a peer trickling
//!      the RESPONSE one byte under the per-read timeout is cut off by the
//!      aggregate response-read deadline (MCPS-093).
//!   4. `handshake_byte_trickle_aborts_at_aggregate_deadline` (#4081, M-28/M-30) —
//!      a peer trickling raw TLS-HANDSHAKE bytes one at a time, each gap under the
//!      per-read timeout, can never complete the handshake but keeps `complete_io`
//!      reading forever under a purely per-read inactivity timeout. The aggregate
//!      handshake deadline caps total wall-clock and aborts it. Without that
//!      deadline the recv_timeout below elapses and the test fails (self-disarming).

use std::io::Read;
use std::io::Write;
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use mcp_re_proxy::RustlsDirectProvider;

use mcp_re_transport::ClientLimits;
use mcp_re_transport::ClientTlsConfig;
use mcp_re_transport::MtlsClient;
use mcp_re_transport::TransportError;

use rcgen::BasicConstraints;
use rcgen::CertificateParams;
use rcgen::DnType;
use rcgen::ExtendedKeyUsagePurpose;
use rcgen::IsCa;
use rcgen::KeyPair;
use rcgen::KeyUsagePurpose;
use rcgen::SanType;

use rustls_pki_types::CertificateDer;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::PrivatePkcs8KeyDer;

// ---------------------------------------------------------------------------
// rcgen CA + leaves (same idiom as mtls_client_test.rs).
// ---------------------------------------------------------------------------

struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

fn make_ca() -> Ca {
    let key = KeyPair::generate().expect("ca key");
    let mut params = CertificateParams::new(Vec::new()).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
        .distinguished_name
        .push(DnType::CommonName, "mcp-re-test-ca");
    let cert = params.self_signed(&key).expect("ca self-signed");
    Ca { cert, key }
}

fn make_leaf(
    ca: &Ca,
    sans: Vec<SanType>,
    common_name: Option<&str>,
    client_auth: bool,
) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let key = KeyPair::generate().expect("leaf key");
    let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
    params.subject_alt_names = sans;
    if let Some(cn) = common_name {
        params.distinguished_name.push(DnType::CommonName, cn);
    }
    params.extended_key_usages = vec![if client_auth {
        ExtendedKeyUsagePurpose::ClientAuth
    } else {
        ExtendedKeyUsagePurpose::ServerAuth
    }];
    let cert = params
        .signed_by(&key, &ca.cert, &ca.key)
        .expect("leaf signed by ca");
    let der = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    (der, key_der)
}

fn uri(value: &str) -> SanType {
    SanType::URI(value.try_into().expect("ia5 uri"))
}
fn dns(value: &str) -> SanType {
    SanType::DnsName(value.try_into().expect("ia5 dns"))
}

const SERVER_NAME: &str = "proxy.internal";
const CLIENT_SPIFFE: &str = "spiffe://example.org/agent-1";

/// Build the SERVER config: presents `server_chain`/`server_key`, requires +
/// verifies a client cert against `client_ca`.
fn server_config(
    server_chain: Vec<CertificateDer<'static>>,
    server_key: PrivateKeyDer<'static>,
    client_ca: &Ca,
) -> Arc<rustls::ServerConfig> {
    let config = RustlsDirectProvider::build_server_config(
        server_chain,
        server_key,
        vec![client_ca.cert.der().clone()],
    )
    .expect("server config");
    Arc::new(config)
}

/// Build a verifying client presenting a trusted client cert and trusting
/// `server_ca_der` to authenticate the proxy.
fn client_config_with_server_ca(
    client_ca: &Ca,
    server_ca_der: CertificateDer<'static>,
) -> ClientTlsConfig {
    let (client_cert, client_key) = make_leaf(client_ca, vec![uri(CLIENT_SPIFFE)], None, true);
    ClientTlsConfig::from_der(vec![client_cert], client_key, vec![server_ca_der])
        .expect("client config")
}

// ---------------------------------------------------------------------------
// 1. A peer that never completes the TLS handshake must time out, not hang.
// ---------------------------------------------------------------------------

#[test]
fn handshake_stall_times_out_not_hangs() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");

    // Accept the TCP connection but never send a single TLS byte. Hold it open
    // well past the client's read timeout. Detached: the client errors on its
    // own timeout, so the test never waits on this thread.
    let _stall = thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        thread::sleep(Duration::from_secs(5));
        drop(sock);
    });

    let client_ca = make_ca();
    let server_ca = make_ca();
    let client_config = client_config_with_server_ca(&client_ca, server_ca.cert.der().clone());
    let limits = ClientLimits {
        connect_timeout: Some(Duration::from_secs(2)),
        read_timeout: Some(Duration::from_millis(300)),
        write_timeout: Some(Duration::from_millis(300)),
        max_response_bytes: 16 * 1024 * 1024,
    };
    let client = MtlsClient::with_limits(client_config, SERVER_NAME, limits).expect("client");

    let start = Instant::now();
    let result = client.round_trip(addr, b"{\"jsonrpc\":\"2.0\"}");
    let elapsed = start.elapsed();

    assert!(
        result.is_err(),
        "a stalled handshake must surface an error, not succeed"
    );
    // Load-bearing assertion: with no read timeout the client blocks until the
    // peer drops at 5s; the 2s budget would then fail.
    assert!(
        elapsed < Duration::from_secs(2),
        "round_trip must fail within the read timeout, not block forever (took {elapsed:?})"
    );
}

// ---------------------------------------------------------------------------
// 2. A fully-authenticated server that floods the response is rejected by the
//    response-size cap, not read unbounded into memory.
// ---------------------------------------------------------------------------

#[test]
fn oversized_response_is_rejected_not_oom() {
    let server_ca = make_ca();
    let client_ca = make_ca();
    let (server_cert, server_key) =
        make_leaf(&server_ca, vec![dns(SERVER_NAME)], Some(SERVER_NAME), false);
    let server_cfg = server_config(vec![server_cert], server_key, &client_ca);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");

    // Real mTLS server: complete the handshake, read the request, then emit a
    // response body far larger than the client's cap. Best-effort writes — the
    // client closes the connection once it trips the cap.
    let flood_len: usize = 4 * 1024 * 1024;
    let _server = thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        let conn = rustls::ServerConnection::new(server_cfg).expect("server conn");
        let mut tls = rustls::StreamOwned::new(conn, sock);
        let _ = tls.conn.complete_io(&mut tls.sock);
        let mut scratch = [0u8; 1024];
        let _ = tls.read(&mut scratch);
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {flood_len}\r\nConnection: close\r\n\r\n"
        );
        let _ = tls.write_all(header.as_bytes());
        let _ = tls.write_all(&vec![b'x'; flood_len]);
        let _ = tls.flush();
    });

    let client_config = client_config_with_server_ca(&client_ca, server_ca.cert.der().clone());
    let limits = ClientLimits {
        max_response_bytes: 64 * 1024,
        ..ClientLimits::default()
    };
    let client = MtlsClient::with_limits(client_config, SERVER_NAME, limits).expect("client");

    let result = client.round_trip(addr, b"{\"jsonrpc\":\"2.0\"}");
    assert!(
        matches!(result, Err(TransportError::ResponseTooLarge { .. })),
        "oversized response must be rejected by the cap, got {result:?}"
    );
}

// ---------------------------------------------------------------------------
// 3. MCPS-093 — a fully-authenticated peer that trickles the response one byte
//    at a time, each chunk JUST UNDER the per-read timeout, must be cut off by
//    the AGGREGATE read deadline — not allowed to extend total read time without
//    bound (slow-loris below the per-read threshold).
// ---------------------------------------------------------------------------

#[test]
fn slow_trickle_response_aborts_at_aggregate_deadline() {
    use std::sync::mpsc;

    let server_ca = make_ca();
    let client_ca = make_ca();
    let (server_cert, server_key) =
        make_leaf(&server_ca, vec![dns(SERVER_NAME)], Some(SERVER_NAME), false);
    let server_cfg = server_config(vec![server_cert], server_key, &client_ca);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");

    // Real mTLS server: complete the handshake, read the request, then dribble a
    // never-ending response ONE byte every 100ms — each gap well UNDER the 300ms
    // per-read timeout, so no individual read ever times out. Only the aggregate
    // deadline can stop it. Detached: the client aborts on its own deadline.
    let _server = thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        let conn = rustls::ServerConnection::new(server_cfg).expect("server conn");
        let mut tls = rustls::StreamOwned::new(conn, sock);
        let _ = tls.conn.complete_io(&mut tls.sock);
        let mut scratch = [0u8; 1024];
        let _ = tls.read(&mut scratch);
        // A header promising a large body, then a byte-at-a-time trickle forever.
        let header = "HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\nConnection: close\r\n\r\n";
        let _ = tls.write_all(header.as_bytes());
        let _ = tls.flush();
        for _ in 0..10_000 {
            if tls.write_all(b"x").is_err() {
                break;
            }
            let _ = tls.flush();
            thread::sleep(Duration::from_millis(100));
        }
    });

    let client_config = client_config_with_server_ca(&client_ca, server_ca.cert.der().clone());
    // Per-read timeout 300ms (each 100ms trickle gap stays UNDER it, so the
    // per-read bound never fires); aggregate read budget 1s. Without the aggregate
    // deadline the trickle would run for the server's full 1000-second dribble and
    // the recv_timeout below would elapse → test FAILS (self-disarming).
    let limits = ClientLimits {
        connect_timeout: Some(Duration::from_secs(2)),
        read_timeout: Some(Duration::from_millis(1000)),
        write_timeout: Some(Duration::from_millis(300)),
        max_response_bytes: 16 * 1024 * 1024,
    };
    let client = MtlsClient::with_limits(client_config, SERVER_NAME, limits).expect("client");

    // Run on a spawned thread joined via recv_timeout so ABSENCE of the aggregate
    // deadline makes the test FAIL (timeout elapses) rather than hang the runner.
    let (tx, rx) = mpsc::channel();
    let start = Instant::now();
    thread::spawn(move || {
        let result = client.round_trip(addr, b"{\"jsonrpc\":\"2.0\"}");
        let _ = tx.send(result);
    });
    let result = rx
        .recv_timeout(Duration::from_secs(6))
        .expect("round_trip must abort at the aggregate read deadline, not trickle unbounded");
    let elapsed = start.elapsed();

    assert!(
        matches!(result, Err(TransportError::Timeout(_))),
        "a sub-per-read-timeout trickle must surface as a Timeout via the aggregate deadline, got {result:?}"
    );
    // Load-bearing: bounded by ~read_timeout (1s) + slack, NOT the server's
    // multi-second dribble.
    assert!(
        elapsed < Duration::from_secs(4),
        "round_trip must abort near the aggregate read deadline, not run for the full trickle (took {elapsed:?})"
    );
}

// ---------------------------------------------------------------------------
// 4. #4081 (audit M-28/M-30) — a peer that trickles raw TLS-HANDSHAKE bytes one
//    at a time, each gap JUST UNDER the per-read timeout, never completes the
//    handshake but resets the per-read inactivity timer on every byte. Only an
//    AGGREGATE wall-clock handshake deadline can stop it; the per-read timeout
//    alone lets `complete_io` read forever (slow-loris below the per-read
//    threshold, evading the zero-byte-stall guard above).
// ---------------------------------------------------------------------------

#[test]
fn handshake_byte_trickle_aborts_at_aggregate_deadline() {
    use std::sync::mpsc;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");

    // Accept the TCP connection, then dribble a never-ending stream of raw bytes
    // ONE byte every 100ms — each gap well UNDER the 1000ms per-read timeout, so
    // no individual handshake read ever times out. The bytes are NOT a valid TLS
    // record body, so the handshake can never complete; absent an aggregate
    // deadline `complete_io` would keep consuming this trickle until the server's
    // multi-minute dribble ends. Detached: the client aborts on its own deadline.
    let _stall = thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        // A valid TLS record header (handshake, TLS 1.2) promising a 16383-byte
        // body (under rustls' max accepted record length, so it is NOT rejected as
        // MessageTooLarge), then a byte-at-a-time trickle of that body. rustls
        // keeps reading, waiting for the rest of the record fragment, forever.
        let header = [0x16u8, 0x03, 0x03, 0x3f, 0xff];
        let _ = sock.write_all(&header);
        let _ = sock.flush();
        for _ in 0..10_000 {
            if sock.write_all(b"\x00").is_err() {
                break;
            }
            let _ = sock.flush();
            thread::sleep(Duration::from_millis(100));
        }
    });

    let client_ca = make_ca();
    let server_ca = make_ca();
    let client_config = client_config_with_server_ca(&client_ca, server_ca.cert.der().clone());
    // Per-read timeout 1000ms (each 100ms trickle gap stays UNDER it, so the
    // per-read bound never fires); aggregate handshake budget = read_timeout (1s).
    // Without the aggregate handshake deadline the trickle drives `complete_io`
    // for the server's full dribble and the recv_timeout below elapses → the test
    // FAILS (self-disarming).
    let limits = ClientLimits {
        connect_timeout: Some(Duration::from_secs(2)),
        read_timeout: Some(Duration::from_millis(1000)),
        write_timeout: Some(Duration::from_millis(300)),
        max_response_bytes: 16 * 1024 * 1024,
    };
    let client = MtlsClient::with_limits(client_config, SERVER_NAME, limits).expect("client");

    // Run on a spawned thread joined via recv_timeout so ABSENCE of the aggregate
    // handshake deadline makes the test FAIL (timeout elapses) rather than hang.
    let (tx, rx) = mpsc::channel();
    let start = Instant::now();
    thread::spawn(move || {
        let result = client.round_trip(addr, b"{\"jsonrpc\":\"2.0\"}");
        let _ = tx.send(result);
    });
    let result = rx
        .recv_timeout(Duration::from_secs(6))
        .expect("handshake must abort at the aggregate deadline, not trickle unbounded");
    let elapsed = start.elapsed();

    assert!(
        matches!(result, Err(TransportError::Timeout(_))),
        "a sub-per-read-timeout handshake trickle must surface as a Timeout via the aggregate handshake deadline, got {result:?}"
    );
    // Load-bearing: bounded by ~read_timeout (1s) + slack, NOT the server's
    // multi-second dribble.
    assert!(
        elapsed < Duration::from_secs(4),
        "round_trip must abort near the aggregate handshake deadline, not run for the full trickle (took {elapsed:?})"
    );
}
