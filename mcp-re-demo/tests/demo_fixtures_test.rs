//! MCPS-055 — the shared demo fixtures helper, proven internally consistent
//! (Phase 6.6, epic #3948).
//!
//! These tests assert the ONE-source-of-truth guarantee: the material
//! `DemoFixtures` mints is mutually consistent across the proxy (server) side and
//! the client side. Rather than only re-parsing the certs, the positive case
//! drives a REAL `mcp_re_proxy::serve_once` mTLS round trip wired ENTIRELY from the
//! fixture's PEM — server config from the server leaf + client CA, client config
//! from the client leaf + server CA — and asserts the handshake succeeds AND the
//! verified client identity equals the configured request signer. The mismatched
//! identity is proven to (a) chain to the SAME client CA (so it passes the
//! handshake) yet (b) differ from the signer (so the proxy's `exact` transport
//! binding rejects it — the T3 case).

use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

use mcp_re_demo::DemoFixtureSpec;
use mcp_re_demo::DemoFixtures;

use mcp_re_proxy::serve_once;
use mcp_re_proxy::RustlsDirectProvider;
use mcp_re_proxy::ServerOptions;

use mcp_re_transport::ClientTlsConfig;
use mcp_re_transport::MtlsClient;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;

/// Parse a single-cert PEM into DER (used to feed the proxy server config + to
/// assert chaining).
fn cert_der(pem: &str) -> CertificateDer<'static> {
    let mut it = CertificateDer::pem_slice_iter(pem.as_bytes());
    it.next().expect("a certificate in PEM").expect("valid cert")
}

/// Build a proxy server config from the fixture's server leaf + the client CA the
/// fixture issued the client leaves from.
fn server_config(fx: &DemoFixtures) -> Arc<rustls::ServerConfig> {
    let server_cert = cert_der(fx.server_cert_pem());
    let server_key =
        rustls_pki_types::PrivateKeyDer::from_pem_slice(fx.server_key_pem().as_bytes())
            .expect("server key");
    let client_ca = cert_der(fx.client_ca_pem());
    let config =
        RustlsDirectProvider::build_server_config(vec![server_cert], server_key, vec![client_ca])
            .expect("server config from fixture material");
    Arc::new(config)
}

#[test]
fn matching_client_identity_round_trips_and_equals_signer() {
    let fx = DemoFixtures::generate_default();
    let config = server_config(&fx);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server = thread::spawn(move || {
        serve_once(&listener, config, &ServerOptions::default(), |request, _id| {
            assert_eq!(request, b"{\"jsonrpc\":\"2.0\"}");
            b"{\"ok\":true}".to_vec()
        })
    });

    // Client config built ENTIRELY from the fixture PEM (the same bytes the demo
    // bin loads from `--client-cert-file` / `--client-key-file` / `--server-ca-file`).
    let tls = ClientTlsConfig::from_pem(
        fx.client_cert_pem().as_bytes(),
        fx.client_key_pem().as_bytes(),
        fx.server_ca_pem().as_bytes(),
    )
    .expect("client tls config from fixture material");
    let client = MtlsClient::new(tls, fx.server_name()).expect("mtls client");

    let response = client
        .round_trip(addr, b"{\"jsonrpc\":\"2.0\"}")
        .expect("the fixture material completes a verifying mTLS round trip");
    assert_eq!(response, b"{\"ok\":true}");

    let identity = server.join().expect("join").expect("serve ok");
    let identity = identity.expect("a verified client identity");
    assert_eq!(
        identity.value,
        fx.actor_id(),
        "the positive client URI-SAN identity must EQUAL the resolved RFC 9421 actor id \
         (role:trust_domain:signer:keyid), which the proxy's `exact` binding compares"
    );
}

#[test]
fn mismatched_client_chains_to_the_same_ca_but_differs_from_signer() {
    let fx = DemoFixtures::generate_default();
    let config = server_config(&fx);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server = thread::spawn(move || {
        serve_once(&listener, config, &ServerOptions::default(), |_req, _id| {
            b"{\"ok\":true}".to_vec()
        })
    });

    // The MISMATCHED client cert still chains to the configured client CA, so the
    // handshake SUCCEEDS — it is the transport BINDING (identity != signer), not
    // the chain, that distinguishes it (the T3 case).
    let tls = ClientTlsConfig::from_pem(
        fx.mismatched_client_cert_pem().as_bytes(),
        fx.mismatched_client_key_pem().as_bytes(),
        fx.server_ca_pem().as_bytes(),
    )
    .expect("mismatched client tls config");
    let client = MtlsClient::new(tls, fx.server_name()).expect("mtls client");

    let response = client
        .round_trip(addr, b"{}")
        .expect("mismatched client still passes the handshake (same CA)");
    assert_eq!(response, b"{\"ok\":true}");

    let identity = server.join().expect("join").expect("serve ok");
    let identity = identity.expect("a verified client identity");
    assert_eq!(identity.value, fx.mismatched_identity());
    assert_ne!(
        identity.value,
        fx.signer(),
        "the mismatched identity must DIFFER from the signer (drives T3 binding denial)"
    );
}

#[test]
fn server_leaf_does_not_chain_to_the_client_ca() {
    // A consistency cross-check: the server leaf must NOT verify against the
    // client CA (distinct trust domains). Using the wrong CA must fail the client.
    let fx = DemoFixtures::generate_default();
    let config = server_config(&fx);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = thread::spawn(move || {
        serve_once(&listener, config, &ServerOptions::default(), |_req, _id| {
            b"{\"ok\":true}".to_vec()
        })
    });

    // Trust the CLIENT CA as the server root: the server leaf does not chain to
    // it, so server authentication must fail (the body never reaches the wire).
    let tls = ClientTlsConfig::from_pem(
        fx.client_cert_pem().as_bytes(),
        fx.client_key_pem().as_bytes(),
        fx.client_ca_pem().as_bytes(),
    )
    .expect("client tls config (wrong server root)");
    let client = MtlsClient::new(tls, fx.server_name()).expect("mtls client");

    let result = client.round_trip(addr, b"{}");
    assert!(
        result.is_err(),
        "the server leaf must NOT chain to the client CA (distinct trust domains)"
    );
    let _ = server.join();
}

#[test]
fn write_files_materializes_every_input_and_cleans_up_on_drop() {
    let fx = DemoFixtures::generate(DemoFixtureSpec::default());
    let dir;
    {
        let files = fx.write_files().expect("write fixture files");
        dir = files.dir().to_path_buf();

        for path in [
            files.server_cert_path(),
            files.server_key_path(),
            files.server_ca_path(),
            files.client_ca_path(),
            files.client_cert_path(),
            files.client_key_path(),
            files.mismatched_client_cert_path(),
            files.mismatched_client_key_path(),
            files.trust_path(),
            files.signing_seed_path(),
            files.signer_seed_path(),
        ] {
            assert!(path.exists(), "expected fixture file to exist: {path:?}");
        }

        // The on-disk seed file content matches the in-memory SERVER seed (the
        // proxy's `--signing-key-seed`), and the trust.json content matches.
        let seed_on_disk =
            std::fs::read_to_string(files.signing_seed_path()).expect("read seed");
        assert_eq!(seed_on_disk, fx.signing_seed_b64url());
        let trust_on_disk =
            std::fs::read_to_string(files.trust_path()).expect("read trust");
        assert_eq!(trust_on_disk, fx.trust_json());
    }
    // Dropped: the whole temp directory is removed.
    assert!(
        !dir.exists(),
        "the fixture temp directory must be removed on drop"
    );
}

#[test]
fn trust_json_carries_the_signer_public_key() {
    let fx = DemoFixtures::generate_default();
    let value: serde_json::Value =
        serde_json::from_str(fx.trust_json()).expect("trust.json parses");
    let entry = &value[0];
    assert_eq!(entry["signer"], fx.signer());
    assert_eq!(entry["key_id"], fx.signer_key_id());
    assert!(
        entry["public_key"].as_str().is_some_and(|s| !s.is_empty()),
        "trust.json must carry the signer's public key"
    );
    // The server public key (the client's response-verify anchor) is DISTINCT
    // from the signer's: distinct keypairs for the two directions.
    assert_ne!(
        entry["public_key"].as_str().unwrap(),
        fx.server_public_key_b64url(),
        "the signer and the server response key must be distinct"
    );
}
