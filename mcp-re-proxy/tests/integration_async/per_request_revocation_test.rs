// SPDX-License-Identifier: Apache-2.0
//! Revocation must take effect on the connection a revoked peer is ALREADY holding.
//!
//! rustls consults the CRLs during client authentication, and client authentication
//! runs on a full handshake only. Every later request on a keep-alive or HTTP/2
//! connection is served without the verifier being consulted again — so before the
//! per-request check, a peer added to a reloaded CRL kept full authenticated access
//! for as long as it did not reconnect. `config_snapshot_hot_reload_test` proves the
//! reload governs the NEXT CONNECTION; this file proves it governs the next REQUEST
//! on an open one, which is the case a revoked peer controls.
//!
//! The tests below share one TLS connection across two requests deliberately. Opening
//! a second connection would re-run the handshake and prove nothing about the gap.
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
use mcp_re_proxy::client_revocation::ClientRevocationIndex;
use mcp_re_proxy::client_revocation::SharedClientRevocation;
use mcp_re_proxy::config_snapshot::ServerConfigSnapshot;
use mcp_re_proxy::tls::RustlsDirectProvider;
use mcp_re_proxy::ServerLimits;
use mcp_re_proxy::ServerOptions;

use rcgen::BasicConstraints;
use rcgen::CertificateParams;
use rcgen::CertificateRevocationListParams;
use rcgen::DnType;
use rcgen::ExtendedKeyUsagePurpose;
use rcgen::IsCa;
use rcgen::KeyPair;
use rcgen::KeyUsagePurpose;
use rcgen::RevocationReason;
use rcgen::RevokedCertParams;
use rcgen::SanType;
use rcgen::SerialNumber;

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

/// Serials the two client certificates are minted with, so the CRL can name one of
/// them exactly.
const REVOKED_SERIAL: u64 = 0x4242;
const INNOCENT_SERIAL: u64 = 0x1337;

struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
    /// Retained so an `Issuer` can be borrowed per signature: rcgen derives the issuer
    /// DN, key-identifier method and key usages from these, not from `cert`.
    params: CertificateParams,
}

impl Ca {
    fn issuer(&self) -> rcgen::Issuer<'_, &KeyPair> {
        rcgen::Issuer::from_params(&self.params, &self.key)
    }
}

fn make_ca(cn: &str) -> Ca {
    let key = KeyPair::generate().expect("ca key");
    let mut params = CertificateParams::new(Vec::new()).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.distinguished_name.push(DnType::CommonName, cn);
    let cert = params.self_signed(&key).expect("ca self-signed");
    Ca { cert, key, params }
}

fn dns(value: &str) -> SanType {
    SanType::DnsName(value.try_into().expect("ia5 dns"))
}

/// A client leaf with an explicit serial, so a CRL can revoke exactly this certificate.
fn make_client_leaf(ca: &Ca, serial: u64) -> (rcgen::Certificate, KeyPair) {
    let key = KeyPair::generate().expect("leaf key");
    let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
    params.serial_number = Some(SerialNumber::from(serial));
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2035, 1, 1);
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let cert = params.signed_by(&key, &ca.issuer()).expect("leaf signed");
    (cert, key)
}

/// A real signed CRL from `ca`, revoking each serial in `revoked`. An empty list is a
/// CRL that covers the issuer and revokes nothing — the "in force, all good" state the
/// proxy starts in.
fn make_crl(ca: &Ca, revoked: &[u64]) -> Vec<u8> {
    let params = CertificateRevocationListParams {
        this_update: rcgen::date_time_ymd(2020, 1, 1),
        next_update: rcgen::date_time_ymd(2035, 1, 1),
        crl_number: SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs: revoked
            .iter()
            .map(|serial| RevokedCertParams {
                serial_number: SerialNumber::from(*serial),
                revocation_time: rcgen::date_time_ymd(2021, 1, 1),
                reason_code: Some(RevocationReason::KeyCompromise),
                invalidity_date: None,
            })
            .collect(),
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    };
    params
        .signed_by(&ca.issuer())
        .expect("crl signed")
        .der()
        .to_vec()
}

fn index_revoking(ca: &Ca, revoked: &[u64]) -> ClientRevocationIndex {
    ClientRevocationIndex::from_crl_ders(&[make_crl(ca, revoked)]).expect("index builds")
}

fn server_config_trusting(client_ca: &Ca) -> Arc<rustls::ServerConfig> {
    let server_ca = make_ca("mcp-re-revocation-server-ca");
    let key = KeyPair::generate().expect("server key");
    let mut params = CertificateParams::new(Vec::new()).expect("server params");
    params.subject_alt_names = vec![dns("localhost")];
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2035, 1, 1);
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = params
        .signed_by(&key, &server_ca.issuer())
        .expect("server leaf");
    let server_key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    Arc::new(
        // NO CRLs on the handshake verifier: the peer is admitted at the handshake, so
        // what the second request observes is the per-request check alone and not a
        // handshake that would have refused it anyway.
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

fn client_config(ca: &Ca, serial: u64) -> ClientConfig {
    let (leaf, key) = make_client_leaf(ca, serial);
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

/// ONE mTLS connection that stays open across requests — the thing a revoked peer
/// holds, and the reason the handshake-time check is not enough.
struct WarmConnection {
    stream: TlsStream,
}

impl WarmConnection {
    fn open(addr: SocketAddr, config: &ClientConfig) -> std::io::Result<Self> {
        let tcp = TcpStream::connect(addr)?;
        tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
        let server_name = ServerName::try_from("localhost").expect("server name");
        let conn = ClientConnection::new(Arc::new(config.clone()), server_name)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(WarmConnection {
            stream: StreamOwned::new(conn, tcp),
        })
    }

    /// Send one request over the SAME connection and return the HTTP status.
    /// `Connection: keep-alive` and a `Content-Length`-framed reply keep it open.
    fn request(&mut self) -> std::io::Result<u16> {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
        let head = format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: keep-alive\r\n\r\n",
            body.len()
        );
        self.stream.write_all(head.as_bytes())?;
        self.stream.write_all(body)?;
        self.stream.flush()?;

        // Read the header block, then exactly `Content-Length` body bytes, so the next
        // request starts at a message boundary rather than mid-reply.
        let mut headers = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            if self.stream.read(&mut byte)? == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed before response headers",
                ));
            }
            headers.push(byte[0]);
            if headers.len() >= 4 && &headers[headers.len() - 4..] == b"\r\n\r\n" {
                break;
            }
        }
        let text = String::from_utf8_lossy(&headers).to_string();
        let status = text
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse::<u16>().ok())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "no status line")
            })?;
        let content_length = text
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.trim()
                    .eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0);
        let mut drained = vec![0u8; content_length];
        if content_length > 0 {
            self.stream.read_exact(&mut drained)?;
        }
        Ok(status)
    }
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

fn spawn(snapshot: Arc<ServerConfigSnapshot>, revocation: Arc<SharedClientRevocation>) -> Server {
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
                            headers: vec![(
                                "content-type".to_string(),
                                "application/json".to_string(),
                            )],
                            body: br#"{"jsonrpc":"2.0","id":1,"result":{}}"#.to_vec(),
                        }
                    })
                };
            let options = ServerOptions {
                limits: ServerLimits::default(),
                client_revocation: Some(revocation),
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

/// THE REGRESSION. A peer that completed a good handshake keeps one connection open.
/// Its certificate is then revoked and the CRL reloaded. Without the per-request check
/// the second request is served exactly like the first, because the verifier is never
/// consulted again on an established connection.
#[test]
fn a_reloaded_crl_refuses_the_next_request_on_an_already_open_connection() {
    let ca = make_ca("client-ca-revocation");
    let revocation = Arc::new(SharedClientRevocation::new(index_revoking(&ca, &[])));
    let snapshot = Arc::new(ServerConfigSnapshot::new(server_config_trusting(&ca)));
    let server = spawn(Arc::clone(&snapshot), Arc::clone(&revocation));

    let mut warm = WarmConnection::open(server.addr, &client_config(&ca, REVOKED_SERIAL))
        .expect("handshake succeeds while the peer is in good standing");
    assert_eq!(
        warm.request().expect("first request served"),
        200,
        "a peer in good standing is served"
    );

    // The CRL reload: the peer's certificate is now revoked. The TLS connection is
    // untouched and the peer never reconnects.
    revocation.store(index_revoking(&ca, &[REVOKED_SERIAL]));

    assert_eq!(
        warm.request().expect("second request answered"),
        403,
        "the SAME open connection must stop being served once the peer's certificate is \
         revoked — this is the request that used to be served"
    );
}

/// The other half: refusing the revoked peer must not refuse everyone. A second peer
/// under the same CA, not named on the CRL, keeps being served across the same reload.
#[test]
fn a_peer_absent_from_the_crl_keeps_being_served_across_the_reload() {
    let ca = make_ca("client-ca-revocation");
    let revocation = Arc::new(SharedClientRevocation::new(index_revoking(&ca, &[])));
    let snapshot = Arc::new(ServerConfigSnapshot::new(server_config_trusting(&ca)));
    let server = spawn(Arc::clone(&snapshot), Arc::clone(&revocation));

    let mut innocent = WarmConnection::open(server.addr, &client_config(&ca, INNOCENT_SERIAL))
        .expect("handshake succeeds");
    assert_eq!(innocent.request().expect("served"), 200);

    revocation.store(index_revoking(&ca, &[REVOKED_SERIAL]));

    assert_eq!(
        innocent.request().expect("still served"),
        200,
        "a peer the CRL does not name must keep its warm connection — revoking one \
         credential must not shed every established connection"
    );
}

/// Warm connections are the point: with the per-request check in force, a connection
/// serving many requests is checked on each of them, not once.
#[test]
fn every_request_on_a_warm_connection_is_checked_not_just_the_first() {
    let ca = make_ca("client-ca-revocation");
    let revocation = Arc::new(SharedClientRevocation::new(index_revoking(&ca, &[])));
    let snapshot = Arc::new(ServerConfigSnapshot::new(server_config_trusting(&ca)));
    let server = spawn(Arc::clone(&snapshot), Arc::clone(&revocation));

    let mut warm = WarmConnection::open(server.addr, &client_config(&ca, REVOKED_SERIAL))
        .expect("handshake succeeds");
    for i in 0..8 {
        assert_eq!(warm.request().expect("served"), 200, "request {i}");
    }
    revocation.store(index_revoking(&ca, &[REVOKED_SERIAL]));
    for i in 0..3 {
        assert_eq!(
            warm.request().expect("answered"),
            403,
            "request {i} after revocation"
        );
    }
}

/// The serial the INTERMEDIATE CA is minted with, so the root's CRL can revoke exactly
/// that certificate rather than the leaf under it.
const INTERMEDIATE_SERIAL: u64 = 0x9001;

/// An intermediate CA signed by `root`, with an explicit serial so a CRL can name it.
fn make_intermediate(root: &Ca, cn: &str, serial: u64) -> Ca {
    let key = KeyPair::generate().expect("intermediate key");
    let mut params = CertificateParams::new(Vec::new()).expect("intermediate params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.serial_number = Some(SerialNumber::from(serial));
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2035, 1, 1);
    params.distinguished_name.push(DnType::CommonName, cn);
    let cert = params
        .signed_by(&key, &root.issuer())
        .expect("intermediate signed by root");
    Ca { cert, key, params }
}

/// The CRLs a two-level deployment actually publishes: one from the root (which is
/// where an intermediate is revoked) and one from the intermediate (which is where a
/// leaf is). Both are needed for either certificate to have a covered status at all.
fn index_for_chain(
    root: &Ca,
    intermediate: &Ca,
    root_revokes: &[u64],
    intermediate_revokes: &[u64],
) -> ClientRevocationIndex {
    ClientRevocationIndex::from_crl_ders(&[
        make_crl(root, root_revokes),
        make_crl(intermediate, intermediate_revokes),
    ])
    .expect("index builds")
}

/// A client presenting the FULL chain it was issued: leaf first, then the intermediate
/// that signed it, exactly as a real peer does so the server can build a path.
fn client_config_with_chain(intermediate: &Ca, serial: u64) -> ClientConfig {
    let (leaf, key) = make_client_leaf(intermediate, serial);
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let provider = Arc::new(ring::default_provider());
    ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("client versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServer))
        .with_client_auth_cert(
            vec![leaf.der().clone(), intermediate.cert.der().clone()],
            key_der,
        )
        .expect("client auth")
}

/// R7-C105: revoking an INTERMEDIATE must reach the connections already open under it.
///
/// The handshake verifier checks revocation to the trust anchor
/// (`RevocationCheckDepth::Chain`), so a per-request check that consulted the leaf alone
/// was strictly weaker than the handshake: an operator responding to a compromised
/// intermediate published it on the parent's CRL, every NEW handshake was refused, and
/// every peer already holding a keep-alive or HTTP/2 connection kept full authenticated
/// access until `max_connection_age` closed it.
///
/// The leaf here is never revoked. Only the CA above it is, so this can only pass if the
/// whole presented chain is re-checked per request.
#[test]
fn revoking_an_intermediate_refuses_the_next_request_on_an_open_connection() {
    let root = make_ca("client-root-ca-revocation");
    let intermediate = make_intermediate(&root, "client-intermediate-ca", INTERMEDIATE_SERIAL);
    let revocation = Arc::new(SharedClientRevocation::new(index_for_chain(
        &root,
        &intermediate,
        &[],
        &[],
    )));
    let snapshot = Arc::new(ServerConfigSnapshot::new(server_config_trusting(&root)));
    let server = spawn(Arc::clone(&snapshot), Arc::clone(&revocation));

    let mut warm = WarmConnection::open(
        server.addr,
        &client_config_with_chain(&intermediate, INNOCENT_SERIAL),
    )
    .expect("handshake succeeds while the whole chain is in good standing");
    assert_eq!(
        warm.request().expect("first request served"),
        200,
        "a peer whose chain is entirely in good standing is served"
    );

    // The intermediate is compromised and published on the ROOT's CRL. The leaf is
    // still not named anywhere.
    revocation.store(index_for_chain(
        &root,
        &intermediate,
        &[INTERMEDIATE_SERIAL],
        &[],
    ));

    assert_eq!(
        warm.request().expect("second request answered"),
        403,
        "the open connection must stop being served once its ISSUING CA is revoked — a \
         leaf-only per-request check served this request"
    );
}

/// The converse, so the chain walk cannot be read as "refuse whenever the chain is
/// longer than one": an untouched intermediate keeps its peers served.
#[test]
fn an_unrevoked_intermediate_keeps_its_peers_served() {
    let root = make_ca("client-root-ca-revocation");
    let intermediate = make_intermediate(&root, "client-intermediate-ca", INTERMEDIATE_SERIAL);
    let other = make_intermediate(&root, "another-intermediate-ca", INTERMEDIATE_SERIAL + 1);
    let revocation = Arc::new(SharedClientRevocation::new(index_for_chain(
        &root,
        &intermediate,
        &[],
        &[],
    )));
    let snapshot = Arc::new(ServerConfigSnapshot::new(server_config_trusting(&root)));
    let server = spawn(Arc::clone(&snapshot), Arc::clone(&revocation));

    let mut warm = WarmConnection::open(
        server.addr,
        &client_config_with_chain(&intermediate, INNOCENT_SERIAL),
    )
    .expect("handshake succeeds");
    assert_eq!(warm.request().expect("served"), 200);

    // A DIFFERENT intermediate is revoked.
    revocation.store(index_for_chain(
        &root,
        &intermediate,
        &[INTERMEDIATE_SERIAL + 1],
        &[],
    ));
    let _ = &other;

    assert_eq!(
        warm.request().expect("still served"),
        200,
        "revoking one CA must not shed the peers of every other"
    );
}
