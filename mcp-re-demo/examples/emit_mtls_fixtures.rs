//! emit_mtls_fixtures — materialize the `DemoFixtures` mTLS security material into
//! a directory so an EXTERNAL consumer (the Python SDK's mTLS/HTTP interop test)
//! can launch `mcp-re-proxy` and connect to it with a matching client cert.
//!
//! Only the TLS certs/keys vary per run (rcgen mints fresh keys); the MCP-RE
//! identities/seeds/audience are the deterministic `DemoFixtureSpec` defaults
//! (signer seed [1;32], server seed [2;32], audience `did:example:server-1`,
//! server name `proxy.internal`), so the consumer hardcodes those.
//!
//!   cargo run -p mcp-re-demo --example emit_mtls_fixtures -- <out-dir>

use std::fs;
use std::path::Path;

use mcp_re_core::SigningKey;
use mcp_re_demo::demo_fixtures::DemoFixtures;

fn main() {
    let dir = std::env::args()
        .nth(1)
        .expect("usage: emit_mtls_fixtures <out-dir>");
    fs::create_dir_all(&dir).expect("create out dir");
    let fx = DemoFixtures::generate_default();

    let write = |name: &str, data: &str| {
        fs::write(Path::new(&dir).join(name), data).expect("write fixture file");
    };
    // Proxy CLI inputs.
    write("server_cert.pem", fx.server_cert_pem()); // --tls-cert
    write("server_key.pem", fx.server_key_pem()); // --tls-key
    write("client_ca.pem", fx.client_ca_pem()); // --client-ca
    write("trust.json", fx.trust_json()); // --trust
    write("signing_seed", fx.signing_seed_b64url()); // --signing-key-seed (b64url)
    // Client (Python) inputs.
    write("server_ca.pem", fx.server_ca_pem()); // verify the proxy's server cert
    write("client_cert.pem", fx.client_cert_pem()); // mTLS client cert (URI SAN == signer)
    write("client_key.pem", fx.client_key_pem());
    // Client-side inputs: the client's OWN request-signing seed
    // (distinct from the proxy's response-signing `signing_seed` above) and the
    // server's response-signing PUBLIC key the client trusts (derived from the
    // server seed). These complete the client env without hardcoding key material.
    write("client_signing_seed", &fx.signer_seed_b64url()); // --signing-key-seed
    write(
        "server_pubkey",
        &SigningKey::from_seed_bytes(&fx.server_seed())
            .public_key()
            .to_b64url(),
    ); // --server-pubkey

    eprintln!("emit_mtls_fixtures: wrote DemoFixtures mTLS material to {dir}");
    eprintln!(
        "  signer={} key={} server-signer={} server-key={} audience={} server-name={}",
        fx.signer(),
        fx.signer_key_id(),
        fx.server_signer(),
        fx.server_key_id(),
        fx.audience(),
        fx.server_name(),
    );
}
