//! `mcp-re-transport` — the MCP-RE client-side mTLS transport (MCPS-053,
//! Phase 6.6, epic #3948).
//!
//! This is the symmetric counterpart to the server side in `mcp-re-proxy`
//! (`RustlsDirectProvider` / `serve` / `serve_once`): a REUSABLE, blocking
//! `rustls` (ring) CLIENT that
//!
//!   1. PRESENTS a client certificate + key to the proxy (mTLS client-auth), and
//!   2. VERIFIES THE PROXY'S SERVER CERTIFICATE AND SERVER IDENTITY against a
//!      configured server CA — using rustls' standard `WebPkiServerVerifier`,
//!      NOT a fake accept-any verifier. A server cert that is untrusted (wrong
//!      CA), carries the wrong identity (wrong SAN/name), or is expired is
//!      rejected during the handshake and the request body is never sent.
//!
//! It is transport-only: it produces/consumes HTTP request/response messages and
//! does NO signing (that stays in `mcp-re-client-core`) and has NO dependency on
//! `mcp-re-proxy`. Blocking `std::net` + `rustls`, NO async runtime — mirroring
//! the proxy's single-request-per-connection HTTP/1.1 framing (one request in,
//! one response out).
//!
//! # Carrying the evidence
//!
//! Under ADR-MCPRE-050 the RFC 9421 `Signature`/`Signature-Input` and RFC 9530
//! `Content-Digest` are the sole evidence carrier, and they live in the HTTP
//! HEADERS — on the request AND on the response — while the status line
//! distinguishes a success from a signed rejection receipt. A byte-in/byte-out
//! transport therefore cannot carry the profile in either direction.
//! [`MtlsClient::round_trip_http`] is the profile-carrying entry point: it emits
//! caller-supplied request headers and returns the whole
//! [`HttpResponseParts`] (status + headers + body).
//! [`remote::MtlsRemoteTransport`] plugs that into `mcp-re-client-proxy`'s
//! `RemoteTransport` seam, which is what makes an end-to-end mTLS client leg with
//! bound response verification a shipped component rather than integrator work.
//!
//! ```no_run
//! use mcp_re_transport::ClientTlsConfig;
//! use mcp_re_transport::MtlsClient;
//!
//! # fn demo(client_cert_pem: &[u8], client_key_pem: &[u8], server_ca_pem: &[u8]) -> Result<(), mcp_re_transport::TransportError> {
//! let config = ClientTlsConfig::from_pem(client_cert_pem, client_key_pem, server_ca_pem)?;
//! let client = MtlsClient::new(config, "proxy.internal")?;
//! let response = client.round_trip_http(
//!     "127.0.0.1:8443".parse().unwrap(),
//!     "POST",
//!     "/mcp",
//!     &[("signature".to_owned(), "sig1=:AAAA:".to_owned())],
//!     b"{\"jsonrpc\":\"2.0\"}",
//! )?;
//! # let _ = response.status;
//! # Ok(())
//! # }
//! ```

pub mod remote;

/// Whom this client trusts to be the proxy, and what it presents to prove itself.
mod tls_config;

/// How long a round trip may take, and how much it may read.
mod limits;

/// Building the request bytes, and refusing anything that could be read two ways.
mod request;

/// Reading the reply: what came back, bounded, and framed exactly one way.
mod response;

/// What one `io::Error` MEANS, which depends on the phase it arrived in.
mod io_errors;

/// The reusable mTLS client: what it composes, and in what order.
mod client;

/// One round trip's phases, in the order that keeps them separable.
mod exchange;

pub use client::MtlsClient;
pub use limits::ClientLimits;
pub use response::HttpResponseParts;
pub use tls_config::ClientTlsConfig;

use std::io;

/// Errors building the client TLS configuration or performing a round trip.
///
/// Mirrors the proxy's `thiserror` idiom (`tls::TlsError`). The transport never
/// panics on bad input — malformed PEM, an empty server-CA bundle, a bad server
/// name, a failed handshake, or an IO error all surface as a `TransportError`.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// The client certificate or key PEM could not be parsed.
    #[error("invalid client certificate/key PEM: {0}")]
    BadClientMaterial(String),
    /// A server-CA certificate could not be parsed or added to the trust store.
    #[error("invalid server CA certificate: {0}")]
    BadServerCa(String),
    /// No server-CA certificate was supplied — server authentication would be
    /// impossible, so building the config fails closed rather than trusting any
    /// server.
    #[error("no server CA certificate supplied (server authentication is mandatory)")]
    EmptyServerCa,
    /// The server-certificate verifier could not be built from the trust store.
    #[error("server verifier build failed: {0}")]
    Verifier(String),
    /// The client TLS configuration (protocol versions / client-auth) was rejected.
    #[error("client TLS config failed: {0}")]
    Config(String),
    /// The expected server name (used for SAN/identity verification) was invalid.
    #[error("invalid expected server name: {0}")]
    BadServerName(String),
    /// The TLS handshake failed — e.g. the server presented an untrusted,
    /// wrong-identity, or expired certificate. Server authentication rejection
    /// surfaces here, before any request body is sent.
    #[error("TLS handshake failed: {0}")]
    Handshake(String),
    /// A transport (TCP/IO) error occurred opening or using the connection.
    #[error("transport IO failed: {0}")]
    Io(#[from] io::Error),
    /// A connect, handshake, or read/write operation exceeded its configured
    /// timeout. A peer that accepts the TCP connection but stalls the handshake
    /// or trickles the response (slow-loris) surfaces here rather than pinning
    /// the calling thread forever.
    #[error("transport timed out: {0}")]
    Timeout(String),
    /// The response exceeded [`ClientLimits::max_response_bytes`]. A
    /// verified-but-hostile or buggy proxy that floods the response is rejected
    /// here rather than read unbounded into memory.
    #[error("response exceeds maximum allowed size ({limit} bytes)")]
    ResponseTooLarge {
        /// The configured ceiling that was exceeded.
        limit: usize,
    },
    /// The peer's HTTP/1.1 response framing was malformed: no header terminator,
    /// an unparsable status line, a bad header line, an obs-fold continuation, a
    /// bare CR/LF inside the header block, or a `Content-Length` that disagrees
    /// with the bytes received. Fails closed — a response whose framing cannot be
    /// read unambiguously is never handed on as a body.
    #[error("malformed HTTP response: {0}")]
    MalformedResponse(String),
    /// A caller-supplied request line or header could not be emitted safely: an
    /// empty or non-token method/header name, a CR/LF in a value (request
    /// splitting), or an attempt to set a header this transport owns
    /// (`host`, `content-length`, `connection`, `transfer-encoding`).
    #[error("invalid request: {0}")]
    InvalidRequest(String),
}

/// MCPS-071 fault-injection module ("test of the tests"). Compiled ONLY under the
/// `fault_accept_any_server` feature, which is off by default and never enabled by
/// production targets or the default `bazel test //...`. It re-introduces the
/// `AcceptAnyServer` anti-pattern the verifying transport was built to eliminate,
/// so the periodic fault-injection harness can prove the server-auth guard tests
/// would FAIL if the control were broken.
#[cfg(feature = "fault_accept_any_server")]
mod fault_accept_any {
    use std::sync::Arc;

    use rustls::client::danger::HandshakeSignatureValid;
    use rustls::client::danger::ServerCertVerified;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::crypto::verify_tls12_signature;
    use rustls::crypto::verify_tls13_signature;
    use rustls::crypto::CryptoProvider;
    use rustls::DigitallySignedStruct;
    use rustls::Error as RustlsError;
    use rustls::SignatureScheme;
    use rustls_pki_types::CertificateDer;
    use rustls_pki_types::ServerName;
    use rustls_pki_types::UnixTime;

    /// A server-certificate verifier that accepts ANY server certificate: any CA,
    /// any identity, any validity window. Handshake SIGNATURES are still checked
    /// via the crypto provider (so the TLS handshake completes against a real
    /// server) — only the trust/identity/expiry decision is neutered. This is the
    /// exact shape of the control break the server-auth tests exist to catch.
    #[derive(Debug)]
    pub struct AcceptAnyServerVerifier {
        provider: Arc<CryptoProvider>,
    }

    impl AcceptAnyServerVerifier {
        pub fn new(provider: Arc<CryptoProvider>) -> Self {
            AcceptAnyServerVerifier { provider }
        }
    }

    impl ServerCertVerifier for AcceptAnyServerVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, RustlsError> {
            // THE BREAK: trust, identity, and expiry are never checked.
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, RustlsError> {
            verify_tls12_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, RustlsError> {
            verify_tls13_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.provider
                .signature_verification_algorithms
                .supported_schemes()
        }
    }
}
