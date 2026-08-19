// SPDX-License-Identifier: Apache-2.0
//! ADR-MCPRE-055 acceptance: resumption is a shortcut only while the trust that
//! authorised it still stands.
//!
//! The unit tests in `tls_auth_epoch` prove the store's contract on synthetic values.
//! These drive REAL rustls handshakes, because the property that matters is whether
//! rustls actually resumed — `HandshakeKind::Resumed` — not whether a `HashMap` returned
//! bytes. A store that silently never resumed would pass the unit tests and fail the
//! whole point of the ADR; only this file can tell the difference.

use std::sync::Arc;

use mcp_re_proxy::tls_auth_epoch::EpochBoundSessionStore;
use mcp_re_proxy::tls_auth_epoch::SharedTlsAuthEpoch;
use mcp_re_proxy::tls_auth_epoch::TlsAuthEpoch;

use rcgen::BasicConstraints;
use rcgen::CertificateParams;
use rcgen::DnType;
use rcgen::ExtendedKeyUsagePurpose;
use rcgen::IsCa;
use rcgen::KeyPair;
use rcgen::KeyUsagePurpose;
use rcgen::SanType;

use rustls::client::Resumption;
use rustls::crypto::ring;
use rustls::server::WebPkiClientVerifier;
use rustls::ClientConfig;
use rustls::ClientConnection;
use rustls::HandshakeKind;
use rustls::RootCertStore;
use rustls::ServerConfig;
use rustls::ServerConnection;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::PrivatePkcs8KeyDer;
use rustls_pki_types::ServerName;

struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
    params: CertificateParams,
}

impl Ca {
    fn issuer(&self) -> rcgen::Issuer<'_, &KeyPair> {
        rcgen::Issuer::from_params(&self.params, &self.key)
    }
    fn der(&self) -> CertificateDer<'static> {
        self.cert.der().clone()
    }
}

fn make_ca(cn: &str) -> Ca {
    let key = KeyPair::generate().expect("ca key");
    let mut params = CertificateParams::new(Vec::new()).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.distinguished_name.push(DnType::CommonName, cn);
    let cert = params.self_signed(&key).expect("ca self-signed");
    Ca { cert, key, params }
}

fn make_leaf(
    ca: &Ca,
    san: &str,
    client_auth: bool,
) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let key = KeyPair::generate().expect("leaf key");
    let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
    params.subject_alt_names = vec![SanType::DnsName(san.try_into().expect("dns san"))];
    params.extended_key_usages = vec![if client_auth {
        ExtendedKeyUsagePurpose::ClientAuth
    } else {
        ExtendedKeyUsagePurpose::ServerAuth
    }];
    let cert = params.signed_by(&key, &ca.issuer()).expect("leaf signed");
    (
        cert.der().clone(),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
}

/// A server config over `anchors`, with resumption gated by `epoch` — the same wiring
/// `tls.rs` installs, reproduced here so the test can move the epoch under a live store.
fn server_config(
    anchors: &[CertificateDer<'static>],
    server_chain: Vec<CertificateDer<'static>>,
    server_key: PrivateKeyDer<'static>,
    epoch: Arc<SharedTlsAuthEpoch>,
) -> Arc<ServerConfig> {
    let provider = Arc::new(ring::default_provider());
    let mut roots = RootCertStore::empty();
    for anchor in anchors {
        roots.add(anchor.clone()).expect("anchor");
    }
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .expect("client verifier");
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_chain, server_key)
        .expect("server cert");
    config.session_storage = Arc::new(EpochBoundSessionStore::new(
        epoch,
        rustls::server::ServerSessionMemoryCache::new(64),
    ));
    config.max_early_data_size = 0;
    Arc::new(config)
}

fn client_config(
    server_ca: &CertificateDer<'static>,
    client_chain: Vec<CertificateDer<'static>>,
    client_key: PrivateKeyDer<'static>,
) -> Arc<ClientConfig> {
    let provider = Arc::new(ring::default_provider());
    let mut roots = RootCertStore::empty();
    roots.add(server_ca.clone()).expect("server ca");
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_root_certificates(roots)
        .with_client_auth_cert(client_chain, client_key)
        .expect("client cert");
    // A client-side cache is what makes a SECOND connection able to offer a ticket at
    // all; without it every handshake is full and the test proves nothing.
    config.resumption = Resumption::in_memory_sessions(16);
    Arc::new(config)
}

/// Drive a full client/server handshake in memory and report how the SERVER classified
/// it. No sockets: the property under test is the handshake kind, and a loopback would
/// only add flakiness.
fn handshake(client: &Arc<ClientConfig>, server: &Arc<ServerConfig>) -> Option<HandshakeKind> {
    let name = ServerName::try_from("localhost").expect("server name");
    let mut c = ClientConnection::new(Arc::clone(client), name).expect("client conn");
    let mut s = ServerConnection::new(Arc::clone(server)).expect("server conn");

    // Pump until both sides stop wanting to write. TLS 1.3 completes in a bounded
    // number of flights; the cap stops a protocol bug becoming a hung test.
    for _ in 0..16 {
        let mut buf = Vec::new();
        if c.wants_write() {
            c.write_tls(&mut buf).expect("client write");
            if !buf.is_empty() {
                s.read_tls(&mut buf.as_slice()).expect("server read");
                s.process_new_packets().expect("server process");
            }
        }
        let mut buf = Vec::new();
        if s.wants_write() {
            s.write_tls(&mut buf).expect("server write");
            if !buf.is_empty() {
                c.read_tls(&mut buf.as_slice()).expect("client read");
                c.process_new_packets().expect("client process");
            }
        }
        if !c.wants_write() && !s.wants_write() && !c.is_handshaking() && !s.is_handshaking() {
            break;
        }
    }
    s.handshake_kind()
}

#[test]
fn a_second_connection_resumes_while_the_trust_epoch_holds() {
    let client_ca = make_ca("epoch-client-ca");
    let server_ca = make_ca("epoch-server-ca");
    let (server_leaf, server_key) = make_leaf(&server_ca, "localhost", false);
    let (client_leaf, client_key) = make_leaf(&client_ca, "client", true);

    let anchors = vec![client_ca.der()];
    let epoch = Arc::new(SharedTlsAuthEpoch::new(TlsAuthEpoch::compute(&anchors)));
    let server = server_config(&anchors, vec![server_leaf], server_key, epoch);
    let client = client_config(&server_ca.der(), vec![client_leaf], client_key);

    assert_eq!(
        handshake(&client, &server),
        Some(HandshakeKind::Full),
        "the first handshake has no ticket to offer"
    );
    assert_eq!(
        handshake(&client, &server),
        Some(HandshakeKind::Resumed),
        "ADR-MCPRE-055 is worthless if the second connection does not actually resume"
    );
}

#[test]
fn withdrawing_a_trusted_ca_stops_resumption_and_forces_a_full_handshake() {
    let ca_a = make_ca("epoch-ca-a");
    let ca_b = make_ca("epoch-ca-b");
    let server_ca = make_ca("epoch-server-ca");
    let (server_leaf, server_key) = make_leaf(&server_ca, "localhost", false);
    let (client_leaf, client_key) = make_leaf(&ca_a, "client", true);

    // Both CAs trusted: the client's chain builds under A.
    let anchors = vec![ca_a.der(), ca_b.der()];
    let epoch = Arc::new(SharedTlsAuthEpoch::new(TlsAuthEpoch::compute(&anchors)));
    let server = server_config(&anchors, vec![server_leaf], server_key, Arc::clone(&epoch));
    let client = client_config(&server_ca.der(), vec![client_leaf], client_key);

    assert_eq!(handshake(&client, &server), Some(HandshakeKind::Full));
    assert_eq!(
        handshake(&client, &server),
        Some(HandshakeKind::Resumed),
        "precondition: resumption works before the withdrawal"
    );

    // Withdraw CA A. The verifier this `ServerConfig` holds is unchanged — this test
    // isolates the EPOCH's effect, so a pass cannot be explained by the chain simply
    // failing to build.
    epoch.store(TlsAuthEpoch::compute(&[ca_b.der()]));

    assert_eq!(
        handshake(&client, &server),
        Some(HandshakeKind::Full),
        "a session stored under withdrawn trust must not resume"
    );
}

/// The negative half of [`withdrawing_a_trusted_ca_stops_resumption_and_forces_a_full_handshake`],
/// and the one with production consequences.
///
/// Every CRL reload rebuilds the `ServerConfig` and REPUBLISHES the epoch computed from
/// the anchors that build was given. If republishing an unchanged epoch invalidated
/// stored sessions, each reload interval would be a fleet-wide teardown — TLS 1.3 has no
/// renegotiation, so an epoch change is connection-fatal. Resumption must therefore
/// survive an arbitrary number of republishes while the anchor set holds.
///
/// This replaces `a_policy_change_alone_stops_resumption`, which asserted that moving
/// `allow_unknown_revocation_status` moved the epoch. That parameter no longer exists —
/// unknown revocation status is denied unconditionally — so the anchor set is the epoch's
/// only input and "policy changed" is not a state the system can be in.
#[test]
fn republishing_the_epoch_of_an_unchanged_ca_set_does_not_stop_resumption() {
    let client_ca = make_ca("epoch-client-ca");
    let server_ca = make_ca("epoch-server-ca");
    let (server_leaf, server_key) = make_leaf(&server_ca, "localhost", false);
    let (client_leaf, client_key) = make_leaf(&client_ca, "client", true);

    let anchors = vec![client_ca.der()];
    let epoch = Arc::new(SharedTlsAuthEpoch::new(TlsAuthEpoch::compute(&anchors)));
    let server = server_config(&anchors, vec![server_leaf], server_key, Arc::clone(&epoch));
    let client = client_config(&server_ca.der(), vec![client_leaf], client_key);

    assert_eq!(handshake(&client, &server), Some(HandshakeKind::Full));
    assert_eq!(handshake(&client, &server), Some(HandshakeKind::Resumed));

    // Three reloads' worth of republishing, from the same anchors each time.
    for reload in 1..=3 {
        epoch.store(TlsAuthEpoch::compute(&anchors));
        assert_eq!(
            handshake(&client, &server),
            Some(HandshakeKind::Resumed),
            "reload {reload} republished an unchanged epoch and must not have torn down \
             resumption; a CRL reload would otherwise be a fleet-wide teardown"
        );
    }

    // And the lever still works afterwards: the store was never the reason it resumed.
    epoch.store(TlsAuthEpoch::compute(&[make_ca("someone-else").der()]));
    assert_eq!(
        handshake(&client, &server),
        Some(HandshakeKind::Full),
        "withdrawing the anchors must still force a full handshake after the republishes"
    );
}

#[test]
fn resumption_returns_once_the_original_trust_is_restored() {
    // Restoring the same anchors restores the same digest, so the mechanism is a
    // function of trust rather than a one-way latch that degrades on every reload.
    let ca_a = make_ca("epoch-ca-a");
    let server_ca = make_ca("epoch-server-ca");
    let (server_leaf, server_key) = make_leaf(&server_ca, "localhost", false);
    let (client_leaf, client_key) = make_leaf(&ca_a, "client", true);

    let anchors = vec![ca_a.der()];
    let epoch = Arc::new(SharedTlsAuthEpoch::new(TlsAuthEpoch::compute(&anchors)));
    let server = server_config(&anchors, vec![server_leaf], server_key, Arc::clone(&epoch));
    let client = client_config(&server_ca.der(), vec![client_leaf], client_key);

    assert_eq!(handshake(&client, &server), Some(HandshakeKind::Full));
    epoch.store(TlsAuthEpoch::compute(&[make_ca("other").der()]));
    assert_eq!(handshake(&client, &server), Some(HandshakeKind::Full));

    // Restoring the anchors restores the digest, but NOT the evicted session: a stale
    // entry is destroyed when it is rejected, so it cannot be resurrected by putting the
    // old trust back. The peer re-establishes one instead...
    epoch.store(TlsAuthEpoch::compute(&anchors));
    assert_eq!(
        handshake(&client, &server),
        Some(HandshakeKind::Full),
        "a rejected session is evicted, not merely refused"
    );

    // ...and from there resumption works again. That is the property that matters: the
    // epoch gates on current trust rather than latching a config permanently degraded.
    assert_eq!(
        handshake(&client, &server),
        Some(HandshakeKind::Resumed),
        "the epoch is a function of trust, not a latch"
    );
}
