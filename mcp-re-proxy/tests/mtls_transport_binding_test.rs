// SPDX-License-Identifier: Apache-2.0
//! mTLS transport binding — RFC 8705 `x5t#S256` channel binding for the RFC 9421
//! HTTP profile, proven END TO END over a REAL rustls mutual-TLS handshake.
//!
//! The existing http-profile tests prove the `verify_mtls_x5t_s256` PRIMITIVE with
//! caller-supplied cert bytes (`full_profile_test.rs`) and pin golden vectors over
//! FAKE DER (`h11`/`h12`). This test closes the remaining gap: it drives an actual
//! mutual-TLS handshake (the production `RustlsDirectProvider` server config + the
//! production `mcp-re-transport` client config presenting a client cert), captures
//! the leaf certificate the TLS layer ACTUALLY negotiated, and feeds THAT into
//! `verify_request_full`. So the bytes the x5t#S256 binding is checked against are
//! the bytes rustls saw on the wire — not test-fabricated material.
//!
//! The property (ADR-MCPRE-050 transport binding): a signed request commits to the
//! SHA-256 thumbprint of the client certificate. It verifies only when presented
//! over an mTLS channel using THAT certificate. A captured/relayed signed request
//! replayed over a DIFFERENT mTLS channel (a different client identity's cert) —
//! or over plain HTTP with no cert at all — fails closed `artifact_binding_failed`.

use std::io::Write;
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::Arc;
use std::thread;

use rcgen::BasicConstraints;
use rcgen::CertificateParams;
use rcgen::DnType;
use rcgen::ExtendedKeyUsagePurpose;
use rcgen::IsCa;
use rcgen::KeyPair;
use rcgen::KeyUsagePurpose;
use rcgen::SanType;

use rustls::ClientConnection;
use rustls::ServerConnection;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::PrivatePkcs8KeyDer;
use rustls_pki_types::ServerName;

use mcp_re_core::SigningKey;
use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::verify_request_full;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ArtifactType;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::PROFILE_TAG;

use mcp_re_proxy::tls::RustlsDirectProvider;
use mcp_re_transport::ClientTlsConfig;

const SERVER_NAME: &str = "proxy.internal";
const TARGET: &str = "https://proxy.internal:8601/mcp";
const CLIENT_KEY_ID: &str = "client-key-1";
const SIGNER_URI: &str = "did:example:agent-1";

// --- minted TLS material -----------------------------------------------------

/// A self-signed CA (root) plus its keypair.
struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

fn make_ca(common_name: &str) -> Ca {
    let key = KeyPair::generate().expect("ca key");
    let mut params = CertificateParams::new(Vec::new()).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.use_authority_key_identifier_extension = true;
    params.distinguished_name.push(DnType::CommonName, common_name);
    let cert = params.self_signed(&key).expect("ca self-signed");
    Ca { cert, key }
}

/// A leaf signed by `ca` with the given SANs and client/server EKU.
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
    params.use_authority_key_identifier_extension = true;
    let cert = params.signed_by(&key, &ca.cert, &ca.key).expect("leaf signed");
    (cert, key)
}

fn uri_san(value: &str) -> SanType {
    SanType::URI(value.try_into().expect("ia5 uri"))
}
fn dns_san(value: &str) -> SanType {
    SanType::DnsName(value.try_into().expect("ia5 dns"))
}

fn key_der(key: &KeyPair) -> PrivateKeyDer<'static> {
    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()))
}

/// The server + client trust material for one handshake scenario.
struct Pki {
    server_config: rustls::ServerConfig,
}

impl Pki {
    /// A server that REQUIRES + verifies a client cert chaining to `client_ca`.
    fn new(server_ca: &Ca, client_ca: &Ca) -> Self {
        let (server_leaf, server_key) =
            make_leaf(server_ca, vec![dns_san(SERVER_NAME)], false);
        let server_config = RustlsDirectProvider::build_server_config(
            vec![server_leaf.der().clone()],
            key_der(&server_key),
            vec![client_ca.cert.der().clone()],
        )
        .expect("server config");
        Pki { server_config }
    }
}

/// Build the production client config presenting `client_leaf`+`client_key`, and
/// trusting `server_ca` to authenticate the server.
fn client_config(
    client_leaf: &rcgen::Certificate,
    client_key: &KeyPair,
    server_ca: &Ca,
) -> Arc<rustls::ClientConfig> {
    ClientTlsConfig::from_pem(
        client_leaf.pem().as_bytes(),
        client_key.serialize_pem().as_bytes(),
        server_ca.cert.pem().as_bytes(),
    )
    .expect("client tls config")
    .rustls_config()
}

/// Drive a REAL blocking mutual-TLS handshake on loopback and return the leaf
/// certificate DER the SERVER captured from the client (`peer_certificates`).
/// This is the exact byte source the proxy would feed to `verify_mtls_x5t_s256`.
fn handshake_capture_presented_leaf(
    server_config: rustls::ServerConfig,
    client_config: Arc<rustls::ClientConfig>,
) -> Vec<u8> {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("addr");

    let server = thread::spawn(move || {
        let (mut tcp, _peer) = listener.accept().expect("accept");
        let mut conn = ServerConnection::new(Arc::new(server_config)).expect("server conn");
        while conn.is_handshaking() {
            conn.complete_io(&mut tcp).expect("server handshake io");
        }
        conn.peer_certificates()
            .expect("client presented a cert")
            .first()
            .expect("at least one peer cert")
            .as_ref()
            .to_vec()
    });

    let name = ServerName::try_from(SERVER_NAME).expect("server name");
    let mut tcp = TcpStream::connect(addr).expect("connect");
    let mut conn = ClientConnection::new(client_config, name).expect("client conn");
    while conn.is_handshaking() {
        conn.complete_io(&mut tcp).expect("client handshake io");
    }
    // Keep the client socket alive until the server has captured the peer cert;
    // dropping it early could race the server's read of the client's Finished.
    let presented = server.join().expect("server thread");
    let _ = tcp.flush();
    presented
}

// --- the signed request under test -------------------------------------------

fn audience() -> AudienceTuple {
    AudienceTuple {
        audience_id: "verifier-1".into(),
        target_uri: TARGET.into(),
        route: Some("a".into()),
    }
}

fn signer_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[11u8; 32])
}

fn resolver() -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> {
    move |key_id: &str, slot: SignerSlot| match (key_id, slot) {
        (CLIENT_KEY_ID, SignerSlot::Request) => Some(ResolvedActor {
            identity: ActorIdentity {
                role: "client".into(),
                trust_domain: "example.com".into(),
                subject: SIGNER_URI.into(),
                keyid: CLIENT_KEY_ID.into(),
            },
            verification_key: signer_key().public_key(),
            slot,
        }),
        _ => None,
    }
}

/// A signed RFC 9421 request whose sole artifact binding is an mTLS `x5t#S256`
/// commitment over `bound_cert_der` (the client's own certificate DER).
fn signed_request_bound_to_cert(bound_cert_der: &[u8]) -> HttpRequest {
    let block = HttpRequestEvidenceBlock {
        profile: PROFILE_TAG.into(),
        audience: audience(),
        artifact_bindings: vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthMtls,
            bound_cert_der,
        )],
        continuation: None,
            admission: None,
    };
    let mut request = HttpRequest {
        method: "POST".into(),
        target_uri: TARGET.into(),
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"add"}}"#.to_vec(),
    };
    sign_request_full(
        &mut request,
        &block,
        &signer_key(),
        CLIENT_KEY_ID,
        1_000,
        1_000 + 300,
        "nonce-mtls-1",
    )
    .expect("sign request");
    request
}

/// The proxy's transport-binding material resolver: an `oauth-mtls` binding is
/// checked against the leaf cert the TLS layer presented on THIS connection;
/// every other artifact type is unavailable here.
fn mtls_material(presented_leaf: Option<Vec<u8>>) -> impl Fn(&ArtifactBinding) -> Option<Vec<u8>> {
    move |binding: &ArtifactBinding| match binding.artifact_type {
        ArtifactType::OauthMtls => presented_leaf.clone(),
        _ => None,
    }
}

// --- tests -------------------------------------------------------------------

/// Positive: the request is presented over the SAME certificate it commits to.
/// The server captures that leaf from a real handshake and the x5t#S256 binding
/// verifies — the RFC 9421 signer is bound to the mTLS channel.
#[test]
fn request_over_its_own_mtls_channel_verifies() {
    let server_ca = make_ca("mcp-re test server CA");
    let client_ca = make_ca("mcp-re test client CA");
    let (client_leaf, client_key) =
        make_leaf(&client_ca, vec![uri_san(SIGNER_URI)], true);
    let client_leaf_der = client_leaf.der().as_ref().to_vec();

    let presented = handshake_capture_presented_leaf(
        Pki::new(&server_ca, &client_ca).server_config,
        client_config(&client_leaf, &client_key, &server_ca),
    );
    // Sanity: the server saw exactly the client's leaf, byte-for-byte.
    assert_eq!(
        presented, client_leaf_der,
        "the negotiated peer leaf must equal the client's certificate"
    );

    let request = signed_request_bound_to_cert(&client_leaf_der);
    verify_request_full(
        &request,
        &audience(),
        &mtls_material(Some(presented)),
        &resolver(),
        1_100,
    )
    .expect("a request presented over its bound mTLS channel verifies");
}

/// Negative — the relayed-request attack: a signed request bound to client A's
/// certificate is replayed by client B over B's OWN valid mTLS channel (B's cert
/// also chains to the trusted client CA, so the handshake SUCCEEDS). The presented
/// leaf is B's, its thumbprint differs from A's commitment, so the binding fails
/// closed. This is what stops a captured signed request from being reused on a
/// different channel.
#[test]
fn request_relayed_onto_a_different_mtls_channel_fails_closed() {
    let server_ca = make_ca("mcp-re test server CA");
    let client_ca = make_ca("mcp-re test client CA");
    // Client A — the certificate the request commits to.
    let (leaf_a, _key_a) = make_leaf(&client_ca, vec![uri_san(SIGNER_URI)], true);
    let a_der = leaf_a.der().as_ref().to_vec();
    // Client B — a DIFFERENT identity under the same (trusted) client CA.
    let (leaf_b, key_b) =
        make_leaf(&client_ca, vec![uri_san("spiffe://example.org/agent-2")], true);

    // B completes a real handshake; the server captures B's leaf.
    let presented_b = handshake_capture_presented_leaf(
        Pki::new(&server_ca, &client_ca).server_config,
        client_config(&leaf_b, &key_b, &server_ca),
    );
    assert_ne!(presented_b, a_der, "B's leaf must differ from A's");

    // The request is bound to A's cert but arrives over B's channel.
    let request = signed_request_bound_to_cert(&a_der);
    let err = verify_request_full(
        &request,
        &audience(),
        &mtls_material(Some(presented_b)),
        &resolver(),
        1_100,
    )
    .expect_err("a request relayed onto a different mTLS channel must fail closed");
    assert_eq!(err, HttpProfileError::ArtifactBindingFailed);
    assert_eq!(err.wire_code(), "mcp-re.artifact_binding_failed");
}

/// Negative — no channel: the same signed request presented over plain HTTP (no
/// client certificate) has no mTLS material, so the required binding cannot be
/// satisfied and verification fails closed rather than silently accepting.
#[test]
fn mtls_bound_request_over_plain_http_fails_closed() {
    let server_ca = make_ca("mcp-re test server CA");
    let client_ca = make_ca("mcp-re test client CA");
    let (client_leaf, _client_key) =
        make_leaf(&client_ca, vec![uri_san(SIGNER_URI)], true);
    let client_leaf_der = client_leaf.der().as_ref().to_vec();
    let _ = (&server_ca, &client_ca); // trust material minted, no handshake driven

    let request = signed_request_bound_to_cert(&client_leaf_der);
    // No presented cert (plain HTTP): the material resolver yields None.
    let err = verify_request_full(
        &request,
        &audience(),
        &mtls_material(None),
        &resolver(),
        1_100,
    )
    .expect_err("an mTLS-bound request with no presented cert must fail closed");
    assert_eq!(err, HttpProfileError::ArtifactBindingFailed);
}
