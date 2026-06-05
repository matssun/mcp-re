//! MCPS-054 — the runnable mTLS client orchestration, end to end (Phase 6.6,
//! epic #3948).
//!
//! Proves the CLIENT PATH the runnable bin drives: the `HostSession` SIGNS a
//! `tools/call`, the reusable `mcps-transport` `MtlsClient` PRESENTS the client
//! cert + VERIFIES the server cert against a configured server CA + round-trips
//! the signed bytes over mTLS to a REAL `mcps_proxy::serve_once` server, and the
//! session VERIFIES the signed response against the STORED request hash.
//!
//! The server thread plays the proxy: it verifies the inbound request and signs
//! a response bound to the request's `request_hash` with the SERVER signing key,
//! using `mcps-core` primitives (the same envelope the proxy produces). The full
//! multi-process wiring against `mcps_proxy_cli` is #3943; this validates the
//! client path in-process against the real server transport without doing #3943's
//! job. Certificates are minted in-process with `rcgen` (no committed fixtures).

use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

use mcps_core::request_hash;
use mcps_core::response_signing_preimage;
use mcps_core::unix_to_rfc3339_utc;
use mcps_core::InMemoryTrustResolver;
use mcps_core::SigningKey;
use mcps_core::RESPONSE_META_KEY;
use mcps_core::SIG_ALG_ED25519;

use mcps_demo::MtlsClientRunner;
use mcps_demo::RunnerError;

use mcps_host::FixedClock;
use mcps_host::HostSigner;
use mcps_host::SeededNonceSource;

use mcps_proxy::serve_once;
use mcps_proxy::RustlsDirectProvider;
use mcps_proxy::ServerOptions;

use mcps_transport::ClientTlsConfig;
use mcps_transport::MtlsClient;

use rcgen::CertificateParams;
use rcgen::DnType;
use rcgen::ExtendedKeyUsagePurpose;
use rcgen::IsCa;
use rcgen::BasicConstraints;
use rcgen::KeyPair;
use rcgen::KeyUsagePurpose;
use rcgen::SanType;

use rustls_pki_types::CertificateDer;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::PrivatePkcs8KeyDer;

use serde_json::json;
use serde_json::Value;

// --- Identities / fixed clock + RNG (deterministic, like the rest of the demo) ---

const SIGNER: &str = "did:example:agent-1";
const SIGNER_KEY_ID: &str = "key-1";
const SERVER: &str = "did:example:server-1";
const SERVER_KEY_ID: &str = "server-key-1";
const AUDIENCE: &str = "did:example:server-1";
const ON_BEHALF_OF: &str = "did:example:user-1";
const AUTHORIZATION_HASH: &str = "sha-256:demo-authz-hash";
const SERVER_NAME: &str = "proxy.internal";
const CLIENT_SPIFFE: &str = "spiffe://example.org/agent-1";
const NOW_UNIX: i64 = 1_779_998_400;

fn signer_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[1u8; 32])
}
fn server_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[2u8; 32])
}

/// Trust anchor the CLIENT uses to verify the signed RESPONSE (the server's key).
fn server_resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SERVER, SERVER_KEY_ID, server_key().public_key());
    r
}

// --- rcgen CA + leaves (same idiom as mcps-transport/tests/mtls_client_test.rs) ---

struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

fn make_ca() -> Ca {
    let key = KeyPair::generate().expect("ca key");
    let mut params = CertificateParams::new(Vec::new()).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.distinguished_name.push(DnType::CommonName, "mcps-test-ca");
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
    let cert = params.signed_by(&key, &ca.cert, &ca.key).expect("leaf signed");
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

// --- The server thread: play the proxy — verify-ish and sign the response. ---

/// Sign an MCP-S response for `request_bytes` with the server key, bound to the
/// request's `request_hash` (the envelope the real proxy produces). The handler
/// can also corrupt the binding (`bind_hash`) or the signature (`good_sig`) to
/// exercise the client's fail-closed response checks.
fn sign_response(request_bytes: &[u8], bind_hash: Option<&str>, good_sig: bool) -> Vec<u8> {
    let request: Value = serde_json::from_slice(request_bytes).expect("request json");
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let computed_hash = request_hash(&request).expect("request hash");
    let bound = bind_hash.map(str::to_string).unwrap_or(computed_hash);

    let mut response = json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": { "structuredContent": { "entries": [ { "name": "report-a.txt" } ] } },
    });
    response["result"]["_meta"][RESPONSE_META_KEY] = json!({
        "request_hash": bound,
        "server_signer": SERVER,
        "issued_at": unix_to_rfc3339_utc(NOW_UNIX),
        "signature": { "alg": SIG_ALG_ED25519, "key_id": SERVER_KEY_ID },
    });
    let preimage = response_signing_preimage(&response).expect("preimage");
    let mut signature = server_key().sign(&preimage);
    if !good_sig {
        // Flip a character to corrupt the signature while keeping it Base64URL.
        let mut chars: Vec<char> = signature.chars().collect();
        chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
        signature = chars.into_iter().collect();
    }
    response["result"]["_meta"][RESPONSE_META_KEY]["signature"]["value"] = Value::String(signature);
    serde_json::to_vec(&response).expect("response bytes")
}

fn server_config(client_ca: &Ca) -> (Arc<rustls::ServerConfig>, CertificateDer<'static>) {
    let server_ca = make_ca();
    let (server_cert, server_key_der) =
        make_leaf(&server_ca, vec![dns(SERVER_NAME)], Some(SERVER_NAME), false);
    let config = RustlsDirectProvider::build_server_config(
        vec![server_cert],
        server_key_der,
        vec![client_ca.cert.der().clone()],
    )
    .expect("server config");
    (Arc::new(config), server_ca.cert.der().clone())
}

/// Spawn a one-shot server that signs the response with `bind_hash` / `good_sig`.
fn spawn_signing_server(
    listener: TcpListener,
    config: Arc<rustls::ServerConfig>,
    bind_hash: Option<String>,
    good_sig: bool,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let _ = serve_once(
            &listener,
            config,
            &ServerOptions::default(),
            move |request, _identity| sign_response(request, bind_hash.as_deref(), good_sig),
        );
    })
}

fn build_runner(
    client_ca: &Ca,
    server_ca_der: CertificateDer<'static>,
) -> MtlsClientRunner<FixedClock, SeededNonceSource> {
    let (client_cert, client_key) = make_leaf(client_ca, vec![uri(CLIENT_SPIFFE)], None, true);
    let tls = ClientTlsConfig::from_der(vec![client_cert], client_key, vec![server_ca_der])
        .expect("client tls config");
    let client = MtlsClient::new(tls, SERVER_NAME).expect("mtls client");
    MtlsClientRunner::new(
        HostSigner::new(signer_key(), SIGNER, SIGNER_KEY_ID),
        FixedClock::new(NOW_UNIX),
        SeededNonceSource::new(&[0xABu8; 32]),
        client,
    )
}

// --- Tests ---------------------------------------------------------------------

#[test]
fn signed_request_round_trips_over_mtls_and_response_verifies() {
    let client_ca = make_ca();
    let (config, server_ca_der) = server_config(&client_ca);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = spawn_signing_server(listener, config, None, true);

    let mut runner = build_runner(&client_ca, server_ca_der);
    assert_eq!(runner.signer(), SIGNER);

    let outcome = runner
        .run_tool_call(
            addr,
            &Value::String("req-mtls-1".to_string()),
            "list_files",
            json!({ "path": "reports" }),
            ON_BEHALF_OF,
            AUDIENCE,
            AUTHORIZATION_HASH,
            "reports",
            &server_resolver(),
        )
        .expect("verified round trip");

    assert_eq!(outcome.signer, SIGNER);
    assert_eq!(outcome.audience, AUDIENCE);
    assert_eq!(outcome.server_signer, SERVER);
    assert_eq!(outcome.tool, "list_files");
    assert_eq!(outcome.path, "reports");
    assert!(!outcome.request_hash.is_empty());
    assert_eq!(
        runner.pending_count(),
        0,
        "a verified response must evict the pending entry"
    );
    server.join().expect("server thread");
}

#[test]
fn untrusted_server_cert_aborts_before_sending_request() {
    // Client trusts a DIFFERENT CA than the one that signed the server cert.
    let client_ca = make_ca();
    let (config, _real_server_ca) = server_config(&client_ca);
    let rogue_server_ca = make_ca();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = spawn_signing_server(listener, config, None, true);

    let mut runner = build_runner(&client_ca, rogue_server_ca.cert.der().clone());
    let result = runner.run_tool_call(
        addr,
        &Value::String("req-mtls-untrusted".to_string()),
        "list_files",
        json!({ "path": "reports" }),
        ON_BEHALF_OF,
        AUDIENCE,
        AUTHORIZATION_HASH,
        "reports",
        &server_resolver(),
    );
    assert!(
        matches!(result, Err(RunnerError::Transport(_))),
        "an untrusted server cert must surface as a transport error, got {result:?}"
    );
    let _ = server.join();
}

#[test]
fn wrong_response_hash_is_refused() {
    let client_ca = make_ca();
    let (config, server_ca_der) = server_config(&client_ca);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    // Server signs a VALID signature but binds the response to a WRONG hash.
    let server =
        spawn_signing_server(listener, config, Some("sha-256:not-the-request".to_string()), true);

    let mut runner = build_runner(&client_ca, server_ca_der);
    let result = runner.run_tool_call(
        addr,
        &Value::String("req-mtls-badhash".to_string()),
        "list_files",
        json!({ "path": "reports" }),
        ON_BEHALF_OF,
        AUDIENCE,
        AUTHORIZATION_HASH,
        "reports",
        &server_resolver(),
    );
    assert!(
        matches!(result, Err(RunnerError::Verify(_))),
        "a response bound to the wrong request hash must be refused, got {result:?}"
    );
    let _ = server.join();
}

#[test]
fn bad_response_signature_is_refused() {
    let client_ca = make_ca();
    let (config, server_ca_der) = server_config(&client_ca);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = spawn_signing_server(listener, config, None, false);

    let mut runner = build_runner(&client_ca, server_ca_der);
    let result = runner.run_tool_call(
        addr,
        &Value::String("req-mtls-badsig".to_string()),
        "list_files",
        json!({ "path": "reports" }),
        ON_BEHALF_OF,
        AUDIENCE,
        AUTHORIZATION_HASH,
        "reports",
        &server_resolver(),
    );
    assert!(
        matches!(result, Err(RunnerError::Verify(_))),
        "a corrupted response signature must be refused, got {result:?}"
    );
    let _ = server.join();
}
