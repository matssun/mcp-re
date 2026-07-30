// SPDX-License-Identifier: Apache-2.0
//! MCPRE-116: the serving fleet must read its TLS config PER CONNECTION from the
//! [`ServerConfigSnapshot`], so the CRL hot-reload task's atomic swap takes effect
//! without a restart.
//!
//! `config_snapshot.rs` documents exactly this ("read the current rustls `ServerConfig`
//! per connection from a `ServerConfigSnapshot` instead of a fixed `Arc`"), but the
//! async accept loop built its `TlsAcceptor` once, before the loop, from a
//! `config_snapshot.load()` taken at startup — so `--client-crl-reload-secs` rebuilt a
//! config nothing ever read again, and a client certificate revoked after process
//! start kept being admitted until restart.
//!
//! Swapping the trusted client CA is the sharpest observable proxy for "the swapped
//! config is in force": it changes, per connection, which client certificates the
//! handshake admits. If the accept loop pinned the startup config, the post-swap
//! assertions below fail.
#![cfg(feature = "async_serve")]

use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use mcp_re_proxy::async_serve;
use mcp_re_proxy::config_snapshot::ServerConfigSnapshot;
use mcp_re_proxy::tls::RustlsDirectProvider;

use mcp_re_proxy::ServerLimits;
use mcp_re_proxy::ServerOptions;

use rcgen::BasicConstraints;
use rcgen::CertificateParams;
use rcgen::DnType;
use rcgen::ExtendedKeyUsagePurpose;
use rcgen::IsCa;
use rcgen::KeyPair;
use rcgen::KeyUsagePurpose;
use rcgen::SanType;

use rustls::client::danger::HandshakeSignatureValid;
use rustls::client::danger::ServerCertVerified;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::ring;
use rustls::ClientConfig;
use rustls::ClientConnection;
use rustls::DigitallySignedStruct;
use rustls::SignatureScheme;
use rustls::StreamOwned;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::PrivatePkcs8KeyDer;
use rustls_pki_types::ServerName;
use rustls_pki_types::UnixTime;

const CLIENT_URI_SAN: &str = "spiffe://example.org/agent-1";

struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

fn make_ca(cn: &str) -> Ca {
    let key = KeyPair::generate().expect("ca key");
    let mut params = CertificateParams::new(Vec::new()).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.distinguished_name.push(DnType::CommonName, cn);
    let cert = params.self_signed(&key).expect("ca self-signed");
    Ca { cert, key }
}

fn make_leaf(ca: &Ca, sans: Vec<SanType>, client_auth: bool) -> (rcgen::Certificate, KeyPair) {
    let key = KeyPair::generate().expect("leaf key");
    let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
    params.subject_alt_names = sans;
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2035, 1, 1);
    params.extended_key_usages = vec![if client_auth {
        ExtendedKeyUsagePurpose::ClientAuth
    } else {
        ExtendedKeyUsagePurpose::ServerAuth
    }];
    let cert = params
        .signed_by(&key, &ca.cert, &ca.key)
        .expect("leaf signed");
    (cert, key)
}

fn uri(value: &str) -> SanType {
    SanType::URI(value.try_into().expect("ia5 uri"))
}
fn dns(value: &str) -> SanType {
    SanType::DnsName(value.try_into().expect("ia5 dns"))
}

/// A server config trusting exactly `client_ca` for client authentication.
fn server_config_trusting(client_ca: &Ca) -> Arc<rustls::ServerConfig> {
    let server_ca = make_ca("mcp-re-snapshot-server-ca");
    let (server_cert, server_key) = make_leaf(&server_ca, vec![dns("localhost")], false);
    let server_key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der()));
    Arc::new(
        RustlsDirectProvider::build_server_config(
            vec![server_cert.der().clone()],
            server_key_der,
            vec![client_ca.cert.der().clone()],
        )
        .expect("server config"),
    )
}

#[derive(Debug)]
struct AcceptAnyServer;
impl ServerCertVerifier for AcceptAnyServer {
    fn verify_server_cert(
        &self,
        _e: &CertificateDer<'_>,
        _i: &[CertificateDer<'_>],
        _n: &ServerName<'_>,
        _o: &[u8],
        _t: UnixTime,
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

fn client_config(ca: &Ca) -> ClientConfig {
    let (leaf, key) = make_leaf(ca, vec![uri(CLIENT_URI_SAN)], true);
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let provider = Arc::new(ring::default_provider());
    ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("client versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServer))
        .with_client_auth_cert(vec![leaf.der().clone()], key_der)
        .expect("client auth")
}

type TlsStream = StreamOwned<ClientConnection, TcpStream>;

fn request_status(addr: SocketAddr, config: &ClientConfig) -> std::io::Result<u16> {
    let tcp = TcpStream::connect(addr)?;
    tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
    let server_name = ServerName::try_from("localhost").expect("server name");
    let conn = ClientConnection::new(Arc::new(config.clone()), server_name)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let mut stream: TlsStream = StreamOwned::new(conn, tcp);
    let body = b"hi";
    let head = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;

    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "closed before response headers",
            ));
        }
        buf.push(byte[0]);
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            break;
        }
    }
    String::from_utf8_lossy(&buf)
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "no status line"))
}

struct Server {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn spawn(snapshot: Arc<ServerConfigSnapshot>) -> Server {
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_srv = Arc::clone(&shutdown);
    let (tx, rx) = mpsc::channel::<SocketAddr>();
    let handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            tx.send(listener.local_addr().expect("addr"))
                .expect("send addr");
            let handler =
                move |_req: async_serve::ServedHttpRequest| -> async_serve::HandlerResponseFuture {
                    Box::pin(async move {
                        async_serve::ServedHttpResponse {
                            status: 200,
                            headers: Vec::new(),
                            body: b"ok".to_vec(),
                        }
                    })
                };
            let options = ServerOptions {
                limits: ServerLimits::default(),
                ..Default::default()
            };
            async_serve::serve(
                listener,
                snapshot,
                Arc::new(options),
                Arc::new(handler),
                shutdown_srv,
            )
            .await;
        });
    });
    let addr = rx
        .recv_timeout(Duration::from_secs(30))
        .expect("server bound");
    Server {
        addr,
        shutdown,
        handle: Some(handle),
    }
}

/// The regression: a config swapped into the snapshot AFTER the accept loop started
/// must govern the NEXT handshake. With the acceptor built once outside the loop, the
/// post-swap assertions below both fail.
#[test]
fn swapped_server_config_is_in_force_on_the_next_connection() {
    let ca_a = make_ca("client-ca-A");
    let ca_b = make_ca("client-ca-B");

    let snapshot = Arc::new(ServerConfigSnapshot::new(server_config_trusting(&ca_a)));
    let server = spawn(Arc::clone(&snapshot));

    let client_a = client_config(&ca_a);
    let client_b = client_config(&ca_b);

    // Before the swap: CA-A is trusted, CA-B is not.
    assert_eq!(
        request_status(server.addr, &client_a).expect("CA-A admitted before swap"),
        200
    );
    assert!(
        request_status(server.addr, &client_b).is_err(),
        "CA-B must be rejected before the swap"
    );

    // Swap in a config that trusts only CA-B — the shape of a CRL/trust reload.
    snapshot.store(server_config_trusting(&ca_b));

    // After the swap, with NO restart: the new config governs.
    assert_eq!(
        request_status(server.addr, &client_b).expect("CA-B admitted after swap"),
        200,
        "the swapped config must be read on the next connection"
    );
    assert!(
        request_status(server.addr, &client_a).is_err(),
        "a client trusted only by the PRE-swap config must now be rejected — this is the \
         revoked-client case the CRL hot-reload exists to handle"
    );
}
