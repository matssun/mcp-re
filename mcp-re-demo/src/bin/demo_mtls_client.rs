//! Runnable mTLS client binary — the LLM caller (MCPS-054, Phase 6.6, epic #3948).
//!
//! Signs ONE MCP-RE `tools/call` with the stateful `HostSession` (nonce from an
//! injected RNG, freshness from an injected clock, `request_hash` correlation by
//! JSON-RPC id), PRESENTS its mTLS client certificate, POSTs the signed request to
//! the proxy over mTLS via the reusable `mcp-re-transport` client (which also
//! verifies the proxy's server certificate + identity against a configured server
//! CA), and VERIFIES the signed response against the STORED request hash.
//!
//! This bin only ORCHESTRATES: signing/correlation live in `mcp-re-host`
//! ([`MtlsClientRunner`](mcp_re_demo::MtlsClientRunner) drives `HostSession`) and the
//! mTLS connection + wire framing live in `mcp-re-transport`. The bin holds NO
//! transport logic and exposes NO private-key accessor — it builds the signer from
//! a seed and signs through the session.
//!
//! Run it with (from `components/mcp-re`):
//!
//! ```sh
//! bazel run //mcp-re-demo:demo_mtls_client -- \
//!   --signing-key-seed-file <b64url-seed-file> \
//!   --client-cert-file <client.pem> --client-key-file <client.key.pem> \
//!   --server-ca-file <server-ca.pem> --expected-server-name proxy.internal \
//!   --proxy-addr 127.0.0.1:8443 --audience did:example:server-1 \
//!   --on-behalf-of did:example:user-1 --signer did:example:agent-1 --key-id key-1 \
//!   --response-signer did:example:server-1 --response-key-id server-key-1 \
//!   --response-public-key <b64url-pubkey> \
//!   --tool list_files --path reports --authorization-hash <sha-256:...>
//! ```
//!
//! It fails LOUDLY (non-zero exit, clear message) on any error rather than masking
//! it; the libraries it drives never panic on bad input — they fail closed with a
//! typed error which this bin surfaces.

use std::process::ExitCode;

use mcp_re_core::b64url_decode;
use mcp_re_core::InMemoryTrustResolver;
use mcp_re_core::SigningKey;
use mcp_re_core::VerificationKey;
use mcp_re_demo::MtlsClientRunner;
use mcp_re_host::FixedClock;
use mcp_re_host::HostSigner;
use mcp_re_host::SeededNonceSource;
use mcp_re_host::SystemClock;
use mcp_re_host::SystemNonceSource;
use mcp_re_transport::ClientTlsConfig;
use mcp_re_transport::MtlsClient;
use serde_json::json;
use serde_json::Value;

/// Parsed command-line arguments for the client bin. All locations are file
/// paths; nothing is hardcoded.
struct Args {
    signing_key_seed_file: String,
    client_cert_file: String,
    client_key_file: String,
    server_ca_file: String,
    expected_server_name: String,
    proxy_addr: String,
    signer: String,
    key_id: String,
    on_behalf_of: String,
    audience: String,
    authorization_hash: String,
    tool: String,
    path: String,
    response_signer: String,
    response_key_id: String,
    response_public_key: String,
    request_id: String,
    /// When set, the signer is seeded deterministically (fixed clock + seeded
    /// RNG) for reproducible demos/tests; otherwise the system clock + RNG drive
    /// freshness and the nonce.
    deterministic: bool,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("demo_mtls_client FAILED: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args = parse_args(std::env::args().skip(1).collect())?;

    let addr = args
        .proxy_addr
        .parse()
        .map_err(|e| format!("invalid --proxy-addr '{}': {e}", args.proxy_addr))?;

    // Signing key from the b64url Ed25519 seed file (the LLM caller's identity).
    let signing_key = load_signing_key(&args.signing_key_seed_file)?;
    let signer = HostSigner::new(signing_key, &args.signer, &args.key_id);

    // Verifying mTLS client: present the client cert, verify the server cert +
    // identity against the configured server CA. All TLS lives in mcp-re-transport.
    let client_cert = read_file(&args.client_cert_file)?;
    let client_key = read_file(&args.client_key_file)?;
    let server_ca = read_file(&args.server_ca_file)?;
    let tls = ClientTlsConfig::from_pem(&client_cert, &client_key, &server_ca)
        .map_err(|e| format!("building client TLS config: {e}"))?;
    let client = MtlsClient::new(tls, &args.expected_server_name)
        .map_err(|e| format!("building mTLS client: {e}"))?;

    // The server's trust anchor for verifying the SIGNED RESPONSE.
    let response_public_key = VerificationKey::from_b64url(&args.response_public_key)
        .map_err(|e| format!("invalid --response-public-key: {e:?}"))?;
    let mut resolver = InMemoryTrustResolver::new();
    resolver.insert(&args.response_signer, &args.response_key_id, response_public_key);

    let id = Value::String(args.request_id.clone());
    let arguments = json!({ "path": args.path });

    // Drive the round trip. The runner is generic over the injected clock/RNG, so
    // dispatch on the deterministic flag without duplicating the orchestration.
    let outcome = if args.deterministic {
        let mut runner = MtlsClientRunner::new(
            signer,
            FixedClock::new(deterministic_now()),
            SeededNonceSource::new(&[0xABu8; 32]),
            client,
        );
        runner.run_tool_call(
            addr,
            &id,
            &args.tool,
            arguments,
            &args.on_behalf_of,
            &args.audience,
            &args.authorization_hash,
            &args.path,
            &resolver,
        )
    } else {
        let mut runner = MtlsClientRunner::new(signer, SystemClock, SystemNonceSource, client);
        runner.run_tool_call(
            addr,
            &id,
            &args.tool,
            arguments,
            &args.on_behalf_of,
            &args.audience,
            &args.authorization_hash,
            &args.path,
            &resolver,
        )
    };

    match outcome {
        Ok(outcome) => {
            println!(
                "mtls-client signer={} audience={} request_hash={} tool={} path={} server_signer={} outcome=verified",
                outcome.signer,
                outcome.audience,
                outcome.request_hash,
                outcome.tool,
                outcome.path,
                outcome.server_signer,
            );
            Ok(())
        }
        Err(err) => {
            println!(
                "mtls-client signer={} audience={} tool={} path={} outcome=failed reason={}",
                args.signer, args.audience, args.tool, args.path, err,
            );
            Err(format!("round trip failed: {err}"))
        }
    }
}

/// The fixed instant used in deterministic mode (matches the rest of the demo).
fn deterministic_now() -> i64 {
    1_779_998_400 // 2026-05-28T20:00:00Z
}

/// Load a Base64URL Ed25519 32-byte signing-key seed from a file.
fn load_signing_key(path: &str) -> Result<SigningKey, String> {
    let raw = read_file(path)?;
    let text = String::from_utf8(raw)
        .map_err(|_| format!("signing-key seed file '{path}' is not UTF-8"))?;
    let bytes = b64url_decode(text.trim())
        .map_err(|e| format!("signing-key seed in '{path}' is not valid Base64URL: {e:?}"))?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("signing-key seed in '{path}' is not 32 bytes"))?;
    Ok(SigningKey::from_seed_bytes(&seed))
}

fn read_file(path: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("cannot read '{path}': {e}"))
}

/// Parse `--flag value` pairs into [`Args`]. Returns a human-readable error on any
/// missing/unknown argument — the bin surfaces it loudly without panicking.
fn parse_args(argv: Vec<String>) -> Result<Args, String> {
    let mut signing_key_seed_file = None;
    let mut client_cert_file = None;
    let mut client_key_file = None;
    let mut server_ca_file = None;
    let mut expected_server_name = None;
    let mut proxy_addr = None;
    let mut signer = None;
    let mut key_id = None;
    let mut on_behalf_of = None;
    let mut audience = None;
    let mut authorization_hash = None;
    let mut tool = None;
    let mut path = None;
    let mut response_signer = None;
    let mut response_key_id = None;
    let mut response_public_key = None;
    let mut request_id = Some("req-mtls-1".to_string());
    let mut deterministic = false;

    let mut it = argv.into_iter();
    while let Some(flag) = it.next() {
        if flag == "--deterministic" {
            deterministic = true;
            continue;
        }
        let value = it
            .next()
            .ok_or_else(|| format!("flag '{flag}' requires a value"))?;
        match flag.as_str() {
            "--signing-key-seed-file" => signing_key_seed_file = Some(value),
            "--client-cert-file" => client_cert_file = Some(value),
            "--client-key-file" => client_key_file = Some(value),
            "--server-ca-file" => server_ca_file = Some(value),
            "--expected-server-name" => expected_server_name = Some(value),
            "--proxy-addr" => proxy_addr = Some(value),
            "--signer" => signer = Some(value),
            "--key-id" => key_id = Some(value),
            "--on-behalf-of" => on_behalf_of = Some(value),
            "--audience" => audience = Some(value),
            "--authorization-hash" => authorization_hash = Some(value),
            "--tool" => tool = Some(value),
            "--path" => path = Some(value),
            "--response-signer" => response_signer = Some(value),
            "--response-key-id" => response_key_id = Some(value),
            "--response-public-key" => response_public_key = Some(value),
            "--request-id" => request_id = Some(value),
            other => return Err(format!("unknown flag '{other}'")),
        }
    }

    Ok(Args {
        signing_key_seed_file: require(signing_key_seed_file, "--signing-key-seed-file")?,
        client_cert_file: require(client_cert_file, "--client-cert-file")?,
        client_key_file: require(client_key_file, "--client-key-file")?,
        server_ca_file: require(server_ca_file, "--server-ca-file")?,
        expected_server_name: require(expected_server_name, "--expected-server-name")?,
        proxy_addr: require(proxy_addr, "--proxy-addr")?,
        signer: require(signer, "--signer")?,
        key_id: require(key_id, "--key-id")?,
        on_behalf_of: require(on_behalf_of, "--on-behalf-of")?,
        audience: require(audience, "--audience")?,
        authorization_hash: require(authorization_hash, "--authorization-hash")?,
        tool: require(tool, "--tool")?,
        path: require(path, "--path")?,
        response_signer: require(response_signer, "--response-signer")?,
        response_key_id: require(response_key_id, "--response-key-id")?,
        response_public_key: require(response_public_key, "--response-public-key")?,
        request_id: require(request_id, "--request-id")?,
        deterministic,
    })
}

fn require(value: Option<String>, flag: &str) -> Result<String, String> {
    value.ok_or_else(|| format!("missing required flag {flag}"))
}
