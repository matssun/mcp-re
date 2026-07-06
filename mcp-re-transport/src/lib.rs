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
//! It is transport-only: it produces/consumes raw request/response bytes and
//! does NO signing (that stays in `mcp-re-host`'s `HostSession`/`HostSigner`) and
//! has NO dependency on `mcp-re-proxy` or `mcp-re-host`. Blocking `std::net` +
//! `rustls`, NO async runtime — mirroring the proxy's single-request-per-
//! connection HTTP/1.1 framing (one POST in, one JSON response out).
//!
//! ```no_run
//! use mcp_re_transport::ClientTlsConfig;
//! use mcp_re_transport::MtlsClient;
//!
//! # fn demo(client_cert_pem: &[u8], client_key_pem: &[u8], server_ca_pem: &[u8]) -> Result<(), mcp_re_transport::TransportError> {
//! let config = ClientTlsConfig::from_pem(client_cert_pem, client_key_pem, server_ca_pem)?;
//! let client = MtlsClient::new(config, "proxy.internal")?;
//! let response = client.round_trip("127.0.0.1:8443".parse().unwrap(), b"{\"jsonrpc\":\"2.0\"}")?;
//! # let _ = response;
//! # Ok(())
//! # }
//! ```

use std::io;
use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::WebPkiServerVerifier;
use rustls::ClientConfig;
use rustls::ClientConnection;
use rustls::RootCertStore;
use rustls::StreamOwned;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::ServerName;

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
}

/// Connection resource limits for the client — the symmetric counterpart of the
/// proxy's `ServerLimits`. Every bound fails closed: a connect/handshake/read
/// that stalls past its timeout, or a response that exceeds the size cap, is
/// surfaced as a [`TransportError`] rather than blocking the thread or
/// allocating without bound.
///
/// Defaults mirror the proxy server: 30s connect/read/write timeouts and a
/// 16 MiB response ceiling. A `None` timeout disables that one bound.
#[derive(Debug, Clone)]
pub struct ClientLimits {
    /// Maximum time to establish the TCP connection. `None` uses a plain
    /// (OS-default) blocking connect.
    pub connect_timeout: Option<Duration>,
    /// Per-socket read timeout. Covers a stalled TLS handshake AND slow-loris
    /// response trickling, since reading drives the handshake. `None` disables.
    pub read_timeout: Option<Duration>,
    /// Per-socket write timeout. `None` disables.
    pub write_timeout: Option<Duration>,
    /// Maximum response bytes read before failing closed with
    /// [`TransportError::ResponseTooLarge`]. Mirrors the proxy's
    /// `max_body_bytes`.
    pub max_response_bytes: usize,
}

impl Default for ClientLimits {
    fn default() -> Self {
        ClientLimits {
            connect_timeout: Some(Duration::from_secs(30)),
            read_timeout: Some(Duration::from_secs(30)),
            write_timeout: Some(Duration::from_secs(30)),
            max_response_bytes: 16 * 1024 * 1024,
        }
    }
}

/// A built, REUSABLE client TLS configuration: it presents a client certificate
/// for mTLS client-auth AND verifies the server's certificate chain against a
/// configured server CA via rustls' standard `WebPkiServerVerifier`.
///
/// Cheap to clone (the inner `ClientConfig` is `Arc`-shared by rustls). Build it
/// once and reuse it for many connections (e.g. by #3941's client bin and
/// #3943's multi-process test).
#[derive(Debug, Clone)]
pub struct ClientTlsConfig {
    inner: Arc<ClientConfig>,
}

impl ClientTlsConfig {
    /// Build a verifying client config from PEM bytes: the client certificate
    /// chain + private key (presented to the proxy) and the server-CA bundle
    /// (the only roots trusted to authenticate the proxy's server certificate).
    ///
    /// Uses the `ring` provider explicitly (no process-global default install),
    /// matching the proxy. Fails closed if the server-CA bundle is empty.
    pub fn from_pem(
        client_cert_pem: &[u8],
        client_key_pem: &[u8],
        server_ca_pem: &[u8],
    ) -> Result<Self, TransportError> {
        let client_chain = certs_from_pem(client_cert_pem)
            .map_err(|e| TransportError::BadClientMaterial(e))?;
        if client_chain.is_empty() {
            return Err(TransportError::BadClientMaterial(
                "no client certificate in PEM".to_string(),
            ));
        }
        let client_key = PrivateKeyDer::from_pem_slice(client_key_pem)
            .map_err(|e| TransportError::BadClientMaterial(e.to_string()))?;
        let server_ca = certs_from_pem(server_ca_pem).map_err(TransportError::BadServerCa)?;
        Self::from_der(client_chain, client_key, server_ca)
    }

    /// Build a verifying client config from already-parsed DER material. Lower
    /// level than [`from_pem`](Self::from_pem); used by tests that mint material
    /// in-process and by callers that load DER directly.
    pub fn from_der(
        client_chain: Vec<CertificateDer<'static>>,
        client_key: PrivateKeyDer<'static>,
        server_ca: Vec<CertificateDer<'static>>,
    ) -> Result<Self, TransportError> {
        if server_ca.is_empty() {
            return Err(TransportError::EmptyServerCa);
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());

        // Build the server trust anchors: ONLY the configured server CA is
        // trusted to authenticate the proxy. WebPkiServerVerifier enforces the
        // chain-of-trust AND (via ClientConnection's server_name) the server's
        // identity (SAN/name) and validity window.
        let mut roots = RootCertStore::empty();
        for ca in server_ca {
            roots
                .add(ca)
                .map_err(|e| TransportError::BadServerCa(e.to_string()))?;
        }
        let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .map_err(|e| TransportError::Verifier(e.to_string()))?;

        // MCPS-071 fault injection ("test of the tests"). When — and ONLY when —
        // the `fault_accept_any_server` feature is compiled in (off by default,
        // never in production or the default `bazel test //...`), the verifying
        // `WebPkiServerVerifier` above is DISCARDED and replaced by an accept-any
        // verifier. This is the deliberately-broken server-auth control: it lets
        // the periodic fault-injection harness demonstrate that the server-cert
        // guard tests are load-bearing (with the fault active, an untrusted/
        // wrong-identity/expired server cert is NO LONGER rejected). The verifying
        // build never constructs this; the byte-for-byte default path is the
        // WebPkiServerVerifier branch.
        #[cfg(feature = "fault_accept_any_server")]
        let config = {
            let _ = verifier; // the verifying path is intentionally bypassed
            ClientConfig::builder_with_provider(provider.clone())
                .with_safe_default_protocol_versions()
                .map_err(|e| TransportError::Config(e.to_string()))?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(
                    fault_accept_any::AcceptAnyServerVerifier::new(provider),
                ))
                .with_client_auth_cert(client_chain, client_key)
                .map_err(|e| TransportError::Config(e.to_string()))?
        };

        #[cfg(not(feature = "fault_accept_any_server"))]
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| TransportError::Config(e.to_string()))?
            .with_webpki_verifier(verifier)
            .with_client_auth_cert(client_chain, client_key)
            .map_err(|e| TransportError::Config(e.to_string()))?;

        Ok(ClientTlsConfig {
            inner: Arc::new(config),
        })
    }

    /// The shared inner rustls config (for callers that drive their own
    /// connections; most callers use [`MtlsClient`]).
    pub fn rustls_config(&self) -> Arc<ClientConfig> {
        Arc::clone(&self.inner)
    }
}

/// A reusable verifying mTLS client bound to an expected server name. Each
/// [`round_trip`](Self::round_trip) opens a fresh connection (single-request-
/// per-connection, matching the proxy), completing the handshake — which
/// authenticates the server against the configured CA and the expected name —
/// before sending the request body.
#[derive(Debug, Clone)]
pub struct MtlsClient {
    config: ClientTlsConfig,
    server_name: ServerName<'static>,
    limits: ClientLimits,
}

impl MtlsClient {
    /// Build a client that will verify the proxy presents a certificate valid
    /// for `expected_server_name` (matched against the certificate's SAN/name by
    /// rustls during the handshake). A wrong-identity server cert is rejected.
    ///
    /// Uses the default [`ClientLimits`] (30s connect/read/write timeouts, 16 MiB
    /// response ceiling). Use [`with_limits`](Self::with_limits) to override.
    pub fn new(
        config: ClientTlsConfig,
        expected_server_name: &str,
    ) -> Result<Self, TransportError> {
        Self::with_limits(config, expected_server_name, ClientLimits::default())
    }

    /// Like [`new`](Self::new) but with explicit connection resource limits
    /// (timeouts + response-size cap).
    pub fn with_limits(
        config: ClientTlsConfig,
        expected_server_name: &str,
        limits: ClientLimits,
    ) -> Result<Self, TransportError> {
        let server_name = ServerName::try_from(expected_server_name.to_string())
            .map_err(|e| TransportError::BadServerName(e.to_string()))?;
        Ok(MtlsClient {
            config,
            server_name,
            limits,
        })
    }

    /// Open one mTLS connection to `addr`, send a single HTTP/1.1 POST carrying
    /// `request_body`, and return the response BODY bytes.
    ///
    /// The handshake authenticates the server BEFORE the body is sent: an
    /// untrusted, wrong-identity, or expired server certificate causes the
    /// handshake to fail and returns `Err(TransportError::Handshake(..))` — the
    /// request body never reaches the wire.
    pub fn round_trip(
        &self,
        addr: SocketAddr,
        request_body: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        // Bound the connect (slow-loris at the TCP layer) then bound every
        // subsequent blocking read/write on the socket. This mirrors the proxy's
        // apply_socket_timeouts; the read timeout in particular covers a stalled
        // handshake (reading drives complete_io) and a trickled response body.
        let tcp = match self.limits.connect_timeout {
            Some(timeout) => TcpStream::connect_timeout(&addr, timeout)?,
            None => TcpStream::connect(addr)?,
        };
        tcp.set_read_timeout(self.limits.read_timeout)?;
        tcp.set_write_timeout(self.limits.write_timeout)?;

        let mut conn = ClientConnection::new(self.config.rustls_config(), self.server_name.clone())
            .map_err(|e| TransportError::Handshake(e.to_string()))?;

        // MCPS-094 (#4081, audit M-28/M-30): drive the handshake through an
        // AGGREGATE wall-clock deadline, not only the per-socket read timeout. A
        // peer trickling raw TLS-handshake bytes one at a time — each gap UNDER the
        // per-read timeout — resets the per-read inactivity timer on every byte and
        // would otherwise keep `complete_io` reading forever (slow-loris below the
        // per-read threshold, evading the zero-byte-stall guard). The
        // `DeadlineStream` caps total handshake wall-clock at `read_timeout`,
        // mirroring the response-read aggregate deadline below and the proxy's
        // persistent-inner reader (MCPS-074). `None` (timeout disabled) yields no
        // aggregate deadline either, preserving the existing knob's semantics.
        let handshake_deadline = self
            .limits
            .read_timeout
            .and_then(|t| std::time::Instant::now().checked_add(t));
        let mut handshake_io =
            DeadlineStream::new(tcp, handshake_deadline, self.limits.read_timeout);

        // Drive the handshake explicitly so server-authentication failure is
        // distinguishable from a later IO error and so we never send the body to
        // an unauthenticated peer.
        conn.complete_io(&mut handshake_io).map_err(handshake_error)?;

        // The handshake is complete; reclaim the bare socket for the request/
        // response phase (which has its OWN aggregate deadline below).
        let tcp = handshake_io.into_inner();
        let mut stream = StreamOwned::new(conn, tcp);

        let request = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            server_name_host(&self.server_name),
            request_body.len(),
        );
        stream.write_all(request.as_bytes()).map_err(write_error)?;
        stream.write_all(request_body).map_err(write_error)?;
        stream.flush().map_err(write_error)?;

        // MCPS-093 (audit M-3 residual): a single Instant-based AGGREGATE read
        // deadline over the WHOLE response-read phase, mirroring the proxy's
        // persistent-inner reader (MCPS-074, `cli.rs`). The per-socket read timeout
        // bounds each individual read, but a peer trickling bytes just under that
        // per-read timeout could otherwise extend the TOTAL read time without
        // bound (slow-loris below the per-read threshold). The aggregate deadline
        // caps total wall-clock at `read_timeout`; `None` (timeout disabled) yields
        // no aggregate deadline either, preserving the existing knob's semantics.
        let read_deadline = self
            .limits
            .read_timeout
            .and_then(|t| std::time::Instant::now().checked_add(t));
        let response = read_response_bounded(
            &mut stream,
            self.limits.max_response_bytes,
            read_deadline,
            self.limits.read_timeout,
        )?;
        Ok(extract_body(&response))
    }
}

/// Read the response in bounded chunks, failing closed at `max_bytes`.
///
/// Replaces an unbounded `read_to_end`: a verified-but-hostile or buggy proxy
/// that floods the response can no longer drive the client to OOM. A peer that
/// closes without `close_notify` surfaces as `UnexpectedEof` and is tolerated
/// (matches the proxy's framing); a read that times out (slow-loris) surfaces as
/// [`TransportError::Timeout`].
///
/// MCPS-093: in addition to the per-socket read timeout (which bounds each
/// individual `read`), an optional `aggregate_deadline` (`Instant`) caps the TOTAL
/// time spent reading the response — mirroring the proxy's persistent-inner reader
/// (MCPS-074). A peer trickling bytes just under the per-read timeout cannot
/// extend total read time without bound: once the aggregate deadline passes, the
/// next iteration fails closed with [`TransportError::Timeout`]. `aggregate_timeout`
/// is the configured value, used only for the error message.
fn read_response_bounded<R: Read>(
    reader: &mut R,
    max_bytes: usize,
    aggregate_deadline: Option<std::time::Instant>,
    aggregate_timeout: Option<Duration>,
) -> Result<Vec<u8>, TransportError> {
    let mut response = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        // Enforce the aggregate read deadline BEFORE each read: a peer trickling a
        // byte just under the per-read timeout indefinitely is cut off here once
        // the total budget elapses, regardless of per-read progress.
        if let Some(deadline) = aggregate_deadline {
            if std::time::Instant::now() >= deadline {
                return Err(TransportError::Timeout(format!(
                    "aggregate response read exceeded {aggregate_timeout:?} (slow-loris trickle)"
                )));
            }
        }
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if response.len() + n > max_bytes {
                    return Err(TransportError::ResponseTooLarge { limit: max_bytes });
                }
                response.extend_from_slice(&chunk[..n]);
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::TimedOut =>
            {
                return Err(TransportError::Timeout(e.to_string()));
            }
            Err(e) => return Err(io_or_handshake(e)),
        }
    }
    Ok(response)
}

/// An `io` wrapper that enforces an AGGREGATE wall-clock deadline across many
/// reads/writes on the inner stream (MCPS-094, #4081, audit M-28/M-30).
///
/// The per-socket read timeout (`set_read_timeout`) bounds each INDIVIDUAL read,
/// but a peer trickling one byte just under that timeout resets the per-read
/// inactivity timer on every byte and can extend a phase (here, the TLS
/// handshake) without bound. Driving `complete_io` through this wrapper caps the
/// TOTAL time: once `deadline` passes, the next read/write fails closed with an
/// `io::ErrorKind::TimedOut` error — which `handshake_error` classifies as
/// [`TransportError::Timeout`]. `None` deadline disables the aggregate bound,
/// preserving the inner stream's own (per-read) semantics. `timeout` is the
/// configured value, surfaced only in the error message.
struct DeadlineStream<S> {
    inner: S,
    deadline: Option<std::time::Instant>,
    timeout: Option<Duration>,
}

impl<S> DeadlineStream<S> {
    fn new(inner: S, deadline: Option<std::time::Instant>, timeout: Option<Duration>) -> Self {
        DeadlineStream {
            inner,
            deadline,
            timeout,
        }
    }

    fn into_inner(self) -> S {
        self.inner
    }

    /// Fail closed if the aggregate deadline has elapsed BEFORE delegating the IO.
    fn check_deadline(&self) -> io::Result<()> {
        if let Some(deadline) = self.deadline {
            if std::time::Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "aggregate handshake deadline exceeded {:?} (slow-loris trickle)",
                        self.timeout
                    ),
                ));
            }
        }
        Ok(())
    }
}

impl<S: Read> Read for DeadlineStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.check_deadline()?;
        self.inner.read(buf)
    }
}

impl<S: Write> Write for DeadlineStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.check_deadline()?;
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Parse a PEM bundle into a chain of DER certificates.
fn certs_from_pem(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, String> {
    let mut out = Vec::new();
    for item in CertificateDer::pem_slice_iter(pem) {
        out.push(item.map_err(|e| e.to_string())?);
    }
    Ok(out)
}

/// The host header value for the expected server name.
fn server_name_host(name: &ServerName<'_>) -> String {
    match name {
        ServerName::DnsName(dns) => dns.as_ref().to_string(),
        ServerName::IpAddress(ip) => {
            let addr: std::net::IpAddr = (*ip).into();
            addr.to_string()
        }
        _ => "localhost".to_string(),
    }
}

/// Map a handshake-phase IO error: a socket timeout (stalled handshake)
/// surfaces as [`TransportError::Timeout`]; any other IO error here is a server
/// authentication rejection and surfaces as [`TransportError::Handshake`].
fn handshake_error(e: io::Error) -> TransportError {
    if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut {
        TransportError::Timeout(e.to_string())
    } else {
        TransportError::Handshake(e.to_string())
    }
}

/// Classify a request-WRITE-phase IO error (MCPS-093, audit M-6 residual). A
/// socket write timeout (the peer's receive window is full / it is not draining —
/// slow-loris on the write side) surfaces as [`TransportError::Timeout`], exactly
/// as [`handshake_error`] classifies a stalled-handshake timeout. Otherwise it
/// defers to [`io_or_handshake`] (a rustls-wrapped error is a handshake failure;
/// anything else stays `Io`).
fn write_error(e: io::Error) -> TransportError {
    if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut {
        return TransportError::Timeout(e.to_string());
    }
    io_or_handshake(e)
}

/// During/after the handshake an IO error may carry a rustls `Error` (e.g. the
/// server cert was rejected). Classify a rustls-wrapped error as a handshake
/// failure; a plain transport error stays `Io`.
fn io_or_handshake(e: io::Error) -> TransportError {
    if e.get_ref()
        .map(|inner| inner.is::<rustls::Error>())
        .unwrap_or(false)
    {
        TransportError::Handshake(e.to_string())
    } else {
        TransportError::Io(e)
    }
}

/// Split an HTTP/1.1 response and return the body bytes (after the header
/// terminator). If no terminator is found, returns the whole buffer.
fn extract_body(response: &[u8]) -> Vec<u8> {
    let split = b"\r\n\r\n";
    let pos = response
        .windows(split.len())
        .position(|w| w == split)
        .map(|p| p + split.len())
        .unwrap_or(0);
    response[pos..].to_vec()
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
