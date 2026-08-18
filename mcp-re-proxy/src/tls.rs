//! `RustlsDirectProvider` — Rust-native TLS termination + mTLS (MCPS-025,
//! ADR-MCPS-014).
//!
//! The proxy terminates TLS itself with `rustls` (the `ring` provider), requires
//! and verifies a client certificate against a configured client-CA
//! (`WebPkiClientVerifier`), and extracts the verified client identity from the
//! leaf certificate (first URI SAN → DNS SAN → CN). It is blocking and uses
//! `std::net` + threads — NO async runtime — mirroring the Phase-3 std::net HTTP
//! framing. The extracted identity is handed to the request handler, where the
//! Phase-6 transport-binding policy (MCPS-026) ties it to the request `signer`.
//!
//! Streamable HTTP here is single-request-per-connection JSON (one POST in, one
//! JSON response out) — SSE streaming is intentionally not implemented.

use std::io;
use std::io::Read;
use std::io::Write;
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use mcp_re_core::json_rpc_error_object;
use mcp_re_core::McpReError;
use rustls::crypto::ring;
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use rustls::ServerConfig;
use rustls::ServerConnection;
use rustls::StreamOwned;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::CertificateRevocationListDer;
use rustls_pki_types::PrivateKeyDer;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::FromDer;

use crate::transport::IdentityPolicy;
use crate::transport::IdentitySource;
use crate::transport::RequestHeaders;
use crate::transport::ReverseProxyMtlsProvider;
use crate::transport::TransportBindingProvider;
use crate::transport::TransportIdentity;

/// Resource limits applied to every served connection — the blocking server's
/// defense against slow-loris, oversized-request, and connection-exhaustion
/// denial of service. Every limit fails closed: a connection that exceeds one is
/// dropped (or never accepted), never served partially.
#[derive(Debug, Clone)]
pub struct ServerLimits {
    /// Maximum bytes accepted before the end-of-headers marker. Caps header
    /// floods and unterminated header streams.
    pub max_header_bytes: usize,
    /// Maximum request body (`Content-Length`, and bytes actually read). Caps
    /// oversized payloads.
    pub max_body_bytes: usize,
    /// Per-socket read timeout (covers a stalled TLS handshake and slow-loris
    /// body trickling, since reading drives the handshake). `None` disables.
    pub read_timeout: Option<Duration>,
    /// AGGREGATE wall-clock deadline over the WHOLE server read phase (TLS
    /// handshake + HTTP header block + body), the server-side mirror of
    /// mcp-re-transport's `DeadlineStream` (MCPS-094) and bounded response read
    /// (MCPS-093). The per-socket `read_timeout` bounds each INDIVIDUAL read, but a
    /// peer trickling one byte just under that timeout resets the per-read
    /// inactivity timer on every byte and can extend a single connection's total
    /// lifetime without bound (slow-loris below the per-read threshold), holding a
    /// serve thread. This caps the TOTAL handshake+request read wall-clock; once it
    /// elapses the next read fails closed (the connection is dropped). `None`
    /// disables the aggregate bound, preserving the per-read-only semantics.
    pub request_deadline: Option<Duration>,
    /// Per-socket write timeout. `None` disables.
    pub write_timeout: Option<Duration>,
    /// Maximum simultaneously-served connections in the threaded [`serve`] loop.
    /// Connections beyond the cap are dropped (TCP-accepted then closed) rather
    /// than queued unboundedly.
    pub max_concurrent_connections: usize,
    /// MCPRE-114 (ADR-MCPRE-051 §1): per-core bounded ADMISSION control — the
    /// maximum number of requests being served CONCURRENTLY on one core (async
    /// serving path). A request that arrives while the ceiling is full is rejected
    /// fail-closed with `503 Service Unavailable` BEFORE the handler runs, rather
    /// than queued without bound — so tail latency stays bounded under overload
    /// instead of degrading unboundedly. `None` disables the ceiling (unbounded
    /// in-flight; the historical behavior). Bounds only the async
    /// (`async_serve`) path; the blocking loop bounds concurrency via
    /// `max_concurrent_connections`.
    ///
    /// # RESOLVED, not requested
    ///
    /// On the validated path this is not what an operator wrote. The admission limit is
    /// stated once, in
    /// [`DeploymentRequest::in_flight_limit`](crate::deployment_request::DeploymentRequest::in_flight_limit), which can express
    /// per-core, fleet-wide, or nothing at all; the boundary resolves that to a basis and
    /// the composition root writes the per-core answer HERE. Setting this field on a
    /// `DeploymentRequest` therefore states nothing — it is overwritten.
    ///
    /// The fail-safe default remains, and is the same constant the basis resolves an
    /// unstated limit to, so a `ServerLimits` built directly — by a test, or an embedder
    /// driving `async_serve` with no `DeploymentRequest` — is bounded on exactly the same terms.
    pub max_in_flight_requests: Option<usize>,
    /// MCPRE-115 (ADR-MCPRE-051 §6): the BOUNDED GRACE WINDOW for graceful drain on
    /// the async serving path. On shutdown each per-core [`serve`] loop stops
    /// accepting and then waits up to this long for its IN-FLIGHT requests to
    /// complete before returning (after which the runtime is dropped and any
    /// still-running request is abandoned). Each in-flight request is ALSO bounded by
    /// `request_deadline`, so with `drain_grace >= request_deadline` every admitted
    /// request finishes within the window — zero abandoned. Size it UNDER the
    /// deployment's k8s `terminationGracePeriodSeconds` and AT OR ABOVE
    /// `request_deadline`: `request_deadline <= drain_grace < terminationGracePeriodSeconds`.
    /// Idle keep-alive connections carry no in-flight request and do not extend the
    /// drain — an idle drain returns promptly.
    pub drain_grace: Duration,
    /// The maximum age of a single mTLS connection before it is gracefully closed,
    /// forcing the peer to re-handshake.
    ///
    /// What this bounds is CHAIN re-validation for an already-established peer.
    /// Client-certificate chain building happens at the handshake and nowhere else, so
    /// a change to the trusted client CAs — a CA withdrawn, a CA expired — reaches a
    /// keep-alive or HTTP/2 connection only when the peer re-handshakes.
    ///
    /// Revocation and the certificates' own validity windows no longer depend on it:
    /// both are re-checked on EVERY request whenever a per-request certificate control
    /// is configured, and to the same depth the handshake checks — the whole presented
    /// chain, not just the leaf (see
    /// [`client_revocation`](crate::client_revocation)). Chain BUILDING is what remains
    /// bound by this age instead: whether a path to a trusted anchor still exists —
    /// signatures, name constraints, anchor membership — is settled by the handshake
    /// verifier and nowhere else.
    ///
    /// Graceful: in-flight requests on the connection finish; only new requests are
    /// refused, and the peer reconnects transparently. `None` disables the bound,
    /// which restores the unbounded behaviour and is refused under `--fleet`.
    pub max_connection_age: Option<Duration>,
}

impl Default for ServerLimits {
    fn default() -> Self {
        ServerLimits {
            max_header_bytes: 64 * 1024,
            max_body_bytes: 16 * 1024 * 1024,
            read_timeout: Some(Duration::from_secs(30)),
            request_deadline: Some(Duration::from_secs(30)),
            write_timeout: Some(Duration::from_secs(30)),
            max_concurrent_connections: 256,
            // A DEFENSIBLE per-core ceiling rather than the unbounded historical
            // default. Unbounded meant one peer holding a valid client certificate
            // could multiplex unbounded HTTP/2 streams, each buffering up to
            // `max_body_bytes` BEFORE the verify gate — attacker-controlled memory
            // with zero authenticated requests, and it also left hyper's HTTP/2
            // `max_concurrent_streams` unset.
            //
            // MATCHED TO `max_concurrent_connections` on purpose. That cap already
            // admitted 256 concurrent connections per core, so one in-flight request
            // per admitted connection tightens nothing that was previously allowed —
            // it just stops the H2 multiplexer exceeding it. A smaller number would be
            // a throughput policy rather than a memory bound, and it would shed inside
            // the ADR-MCPRE-051 §7 envelope (concurrency 128), which is a load-shaping
            // decision no default should make silently.
            max_in_flight_requests: Some(
                crate::config_state::in_flight_limit::DEFAULT_PER_CORE_IN_FLIGHT,
            ),
            // >= request_deadline (so every admitted request can finish) and, in
            // production, < k8s terminationGracePeriodSeconds.
            drain_grace: Duration::from_secs(30),
            // Bounds how long a peer keeps serving on a certificate validated only at
            // its handshake. 300s is well inside the 1h `max_client_cert_lifetime`
            // ceiling and short enough that a CRL reload takes effect within one
            // cadence, while being long enough that re-handshake cost is negligible.
            max_connection_age: Some(Duration::from_secs(300)),
        }
    }
}

/// The trusted-ingress Tier-3 (ADR-MCPS-023, issue #71) assertion header. A single
/// HTTP header carrying the LB-signed, request-bound ingress assertion (the
/// `<key_id>.<identity>.<request_hash>.<validation_time>.<signature>` wire form).
/// Lowercased for case-insensitive [`RequestHeaders`] lookup. The serve loop fails
/// closed on a DUPLICATED header (via [`RequestHeaders::count`]) before the value
/// is ever read — a duplicate signals a downstream injection attempt.
pub const MCP_INGRESS_ASSERTION_HEADER: &str = "mcp-ingress-assertion";

/// Where the served request's verified transport identity comes from. These are
/// mutually exclusive: a connection is bound EITHER by a locally-terminated mTLS
/// client certificate OR by a header set by a trusted upstream reverse proxy,
/// OR by an LB-signed request-bound ingress assertion — never more than one. The
/// CLI enforces the exclusivity; the serve loop honours the one chosen strategy
/// and never mixes them on a single connection.
#[derive(Debug, Clone, Default)]
pub enum IdentityStrategy {
    /// Direct mTLS: the identity is the configured field of the verified peer
    /// (leaf) certificate. This is the default and leaves the local-TLS path
    /// fully intact.
    #[default]
    DirectTls,
    /// Reverse-proxy ingress: mTLS is terminated UPSTREAM and the verified client
    /// identity is read from a trusted forwarded header. The local client-cert is
    /// NOT consulted for identity (the two sources are mutually exclusive). The
    /// operator asserts the listening socket is reachable only by the trusted
    /// upstream (see [`ReverseProxyMtlsProvider`]).
    ReverseProxyHeader(ReverseProxyMtlsProvider),
    /// ADR-MCPS-023 Tier 3 (issue #71): the verified transport identity comes from
    /// an LB-signed, request-bound ingress assertion presented in the
    /// [`MCP_INGRESS_ASSERTION_HEADER`]. The identity CANNOT be resolved at the
    /// connection seam (the assertion binds the request hash, known only after
    /// object verification), so under this strategy [`resolve_identity`] yields
    /// `None` and the serve loop instead extracts the raw assertion header and
    /// hands it to the post-verification check (`Proxy::with_lb_assertion`). The
    /// local client certificate is NOT consulted for identity.
    LbAssertion,
}

/// How the serve loop turns a connection into a served request: which client-cert
/// field is the authoritative identity, the resource limits, and the maximum
/// client-certificate lifetime.
#[derive(Debug, Clone, Default)]
pub struct ServerOptions {
    /// The authoritative client-certificate identity field (no implicit fallback).
    /// Used for [`IdentityStrategy::DirectTls`]; for the reverse-proxy strategy the
    /// field is carried inside the provider instead.
    pub identity_policy: IdentityPolicy,
    /// Where the request's verified transport identity is taken from (local mTLS
    /// vs a trusted upstream header). Mutually exclusive by construction.
    pub identity_strategy: IdentityStrategy,
    /// Connection resource limits (DoS defense).
    pub limits: ServerLimits,
    /// Maximum allowed client-certificate validity span
    /// (`not_after - not_before`). This is the v1 revocation posture: with no
    /// online CRL/OCSP, a compromised client cert is usable until expiry, so the
    /// proxy ENFORCES short lifetimes — a cert whose span exceeds this (or whose
    /// validity cannot be parsed) is rejected with `mcp-re.transport_binding_failed`.
    /// `None` disables the check. The production CLI defaults this to 1 hour; this
    /// library `Default` leaves it `None` so existing callers are unchanged.
    ///
    /// Exposure window of a compromised transport credential is bounded by
    /// `max_client_cert_lifetime`. The end-to-end request-authority exposure
    /// window is `cert_lifetime + resolver_cache_ttl + request_lifetime +
    /// max_clock_skew`.
    pub max_client_cert_lifetime: Option<Duration>,
    /// PER-REQUEST offline CRL revocation: the revoked-serial index built from the
    /// SAME CRLs the handshake verifier holds, behind an atomic swap so a reload
    /// reaches connections that are already open.
    ///
    /// rustls runs client authentication on a full handshake only, so without this a
    /// revoked peer keeps serving for as long as it holds one connection — the
    /// `--client-crl-reload-secs` rebuild reaches only NEW connections, and
    /// `max_connection_age` bounds the exposure without ending it. `None` disables
    /// the per-request check; `app.rs` installs it only when CRLs are configured, so
    /// a deployment with none is unchanged.
    pub client_revocation: Option<Arc<crate::client_revocation::SharedClientRevocation>>,
    /// ONLINE OCSP client-cert revocation (#4030), the online sibling of #3839's
    /// offline CRL posture. When `Some`, after the handshake the serve loop asks
    /// the leaf's OCSP responder whether it is revoked, BEFORE the handler, and
    /// fails closed (rejects) on `Revoked`/`Unknown`/error unless the checker is
    /// in soft-fail mode (see [`ocsp_rejection`]). `None` disables the online
    /// check (the default). This field — and the entire online check — exists
    /// ONLY in a build with the `online_ocsp` feature; the default build has no
    /// such field and the hook is a compile-time no-op, so it is byte-for-byte
    /// unchanged.
    #[cfg(feature = "online_ocsp")]
    pub ocsp_checker: Option<crate::ocsp::OcspChecker>,
    /// The canonical RFC 9421 `@target-uri` this deployment binds requests to
    /// (ADR-MCPRE-050). Client and server MUST agree on it byte-for-byte; the
    /// verifier checks it against the request evidence block's audience tuple. Empty
    /// when unset (the audience/target check then fails closed).
    pub target_uri: String,
    /// Whether producing the handshake signature may BLOCK — set when the TLS server
    /// key is delegated to a KMS or a PKCS#11 token (ADR-MCPS-028 §G).
    ///
    /// rustls' `Signer::sign` is synchronous, so on those custody paths the
    /// CertificateVerify signature is a blocking HTTPS round trip or an FFI `C_Sign`
    /// executed inside a single `poll`. On the per-core `current_thread` runtime that
    /// freezes the WHOLE core — its accept loop, its keep-alive connections and every
    /// in-flight request — for the duration, and `tokio::time::timeout` cannot preempt
    /// it because the timer never gets to run. Any peer opening connections triggers
    /// it; a stalled KMS costs seconds per connection and a wedged token is unbounded.
    ///
    /// When set, the handshake is run on the blocking pool instead of the runtime
    /// thread (see `async_serve::serve_connection`). Left `false` for the exported-key
    /// path, where signing is in-memory and the async handshake is both correct and
    /// cheaper.
    pub tls_signing_may_block: bool,
}

/// Errors building the TLS server configuration.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// A client-CA certificate could not be added to the trust store.
    #[error("invalid client CA certificate")]
    BadClientCa,
    /// The client-certificate verifier could not be built.
    #[error("client verifier build failed: {0}")]
    Verifier(String),
    /// The server certificate/key or protocol configuration was rejected.
    #[error("server TLS config failed: {0}")]
    Config(String),
    /// Delegated TLS (ADR-MCPS-028 §G, issue #58): the leaf certificate's
    /// `SubjectPublicKeyInfo` is not an RFC 8410 Ed25519 key (delegated TLS is
    /// Ed25519-only), OR the delegated signer's public key does not match the leaf
    /// certificate's public key. Either is a deployment error and FAILS CLOSED at
    /// config construction — no server is started.
    #[error("delegated TLS credential mismatch: {0}")]
    DelegatedKeyMismatch(String),
}

/// Marker for the production direct-TLS transport-binding provider. The verified
/// identity is produced per connection by the serve loop (see [`serve_once`] /
/// [`serve`]); the binding policy (MCPS-026) consumes it.
#[derive(Debug, Clone, Copy, Default)]
pub struct RustlsDirectProvider;

impl RustlsDirectProvider {
    /// Build a `rustls` server config that REQUIRES and verifies a client
    /// certificate against `client_ca`, presenting `server_chain` + `server_key`.
    /// Uses the `ring` provider explicitly (no process-global default install).
    ///
    /// Equivalent to [`build_server_config_with_crls`](Self::build_server_config_with_crls)
    /// with no CRLs — preserved byte-for-byte for callers that do not configure
    /// offline revocation.
    pub fn build_server_config(
        server_chain: Vec<CertificateDer<'static>>,
        server_key: PrivateKeyDer<'static>,
        client_ca: Vec<CertificateDer<'static>>,
    ) -> Result<ServerConfig, TlsError> {
        Self::build_server_config_with_crls(server_chain, server_key, client_ca, Vec::new(), false)
    }

    /// As [`build_server_config`](Self::build_server_config), additionally checking
    /// each presented client certificate against the supplied OFFLINE certificate
    /// revocation lists (#3839). This is OFFLINE CRL revocation only: the CRLs are
    /// loaded from disk at startup and never refreshed over the network. ONLINE
    /// OCSP / CRL-distribution-point fetching is intentionally NOT implemented here
    /// (it would require an HTTP client + a live responder, expanding the
    /// firewalled supply chain) and is deferred to a follow-up.
    ///
    /// Fail-closed posture (the rustls 0.23 builder defaults, made explicit):
    ///   * a client cert listed as revoked by any CRL → handshake REJECTED;
    ///   * the FULL chain to the trust anchor has revocation checked
    ///     (`RevocationCheckDepth::Chain`, the default);
    ///   * a cert whose revocation status cannot be determined from the CRLs is
    ///     REJECTED (`UnknownStatusPolicy::Deny`, the default) UNLESS
    ///     `allow_unknown_revocation_status` is `true` (operator opt-out).
    ///
    /// When `crls` is empty this behaves exactly like the no-CRL path:
    /// `.with_crls([])` adds nothing and rustls performs no revocation checks, so
    /// `allow_unknown_revocation_status` has no effect.
    pub fn build_server_config_with_crls(
        server_chain: Vec<CertificateDer<'static>>,
        server_key: PrivateKeyDer<'static>,
        client_ca: Vec<CertificateDer<'static>>,
        crls: Vec<CertificateRevocationListDer<'static>>,
        allow_unknown_revocation_status: bool,
    ) -> Result<ServerConfig, TlsError> {
        let resumption = new_resumption_state(&client_ca, allow_unknown_revocation_status);
        Self::build_server_config_with_crls_resuming(
            server_chain,
            server_key,
            client_ca,
            crls,
            allow_unknown_revocation_status,
            &resumption,
        )
    }

    /// As [`build_server_config_with_crls`](Self::build_server_config_with_crls), reusing
    /// a resumption state that OUTLIVES this config.
    ///
    /// The reload path builds through here so the session cache survives the rebuild and
    /// the epoch is republished from the anchors this build was given — the only way the
    /// epoch is a live trust lever rather than a constant fixed at construction.
    pub(crate) fn build_server_config_with_crls_resuming(
        server_chain: Vec<CertificateDer<'static>>,
        server_key: PrivateKeyDer<'static>,
        client_ca: Vec<CertificateDer<'static>>,
        crls: Vec<CertificateRevocationListDer<'static>>,
        allow_unknown_revocation_status: bool,
        resumption: &Arc<crate::tls_auth_epoch::EpochBoundSessionStore>,
    ) -> Result<ServerConfig, TlsError> {
        // Computed BEFORE `client_ca` is moved into the verifier: the anchors are the
        // epoch's primary input (ADR-MCPRE-055).
        let epoch = crate::tls_auth_epoch::TlsAuthEpoch::compute(
            &client_ca,
            allow_unknown_revocation_status,
        );
        let provider = Arc::new(ring::default_provider());
        let verifier = build_client_verifier(
            client_ca,
            crls,
            allow_unknown_revocation_status,
            provider.clone(),
        )?;

        // MCPS-079 fault injection ("test of the tests"), the symmetric mirror of
        // mcp-re-transport's `fault_accept_any_server`. When — and ONLY when — the
        // `fault_accept_any_client` feature is compiled in (off by default, never
        // in production or the default `bazel test //...`), the verifying
        // `WebPkiClientVerifier` above is DISCARDED and replaced by an accept-any
        // CLIENT verifier. This is the deliberately-broken client-auth control: it
        // lets the periodic fault-injection harness demonstrate that the proxy's
        // client-cert-rejection guards are load-bearing (with the fault active, a
        // missing OR untrusted client cert is NO LONGER rejected). The verifying
        // build never constructs this; the byte-for-byte default path is the
        // WebPkiClientVerifier branch below.
        #[cfg(feature = "fault_accept_any_client")]
        let server_config = {
            let _ = verifier; // the verifying path is intentionally bypassed
            ServerConfig::builder_with_provider(provider.clone())
                .with_safe_default_protocol_versions()
                .map_err(|e| TlsError::Config(e.to_string()))?
                .with_client_cert_verifier(Arc::new(
                    fault_accept_any::AcceptAnyClientVerifier::new(provider),
                ))
                .with_single_cert(server_chain, server_key)
                .map_err(|e| TlsError::Config(e.to_string()))
        };

        #[cfg(not(feature = "fault_accept_any_client"))]
        let server_config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| TlsError::Config(e.to_string()))?
            .with_client_cert_verifier(verifier)
            .with_single_cert(server_chain, server_key)
            .map_err(|e| TlsError::Config(e.to_string()));

        server_config.map(|config| epoch_bound_resumption(config, resumption, epoch))
    }
}

/// The resumption state one listener is built around: the epoch in force and the session
/// cache tagged with it.
///
/// Created ONCE per listener and handed to every `ServerConfig` build for it. A state
/// created per build pairs a fresh epoch with a fresh empty cache, which discards every
/// resumable session on each rebuild and leaves the epoch unable to move.
pub(crate) fn new_resumption_state(
    client_ca: &[CertificateDer<'_>],
    allow_unknown_revocation_status: bool,
) -> Arc<crate::tls_auth_epoch::EpochBoundSessionStore> {
    Arc::new(
        crate::tls_auth_epoch::EpochBoundSessionStore::memory_backed(
            crate::tls_auth_epoch::TlsAuthEpoch::compute(
                client_ca,
                allow_unknown_revocation_status,
            ),
            TLS_SESSION_CACHE_ENTRIES,
        ),
    )
}

/// Bind TLS session resumption to the trust epoch (ADR-MCPRE-055).
///
/// rustls runs client authentication — chain building, the CRL consultation, and the
/// certificate's own validity window — on a FULL handshake only. A resumed session
/// restores the stored peer certificate chain verbatim and skips all three, so an
/// authentication result would otherwise outlive the trust it was derived from: a peer
/// that completed one good handshake keeps an authenticated, identity-bearing channel
/// for the life of the cached session. The `ExactMatchBinding` still matches, because
/// the restored identity is the original one.
///
/// Two of the three are recovered per request — the validity window and, when CRLs are
/// configured, revocation (see [`client_revocation`](crate::client_revocation)). CHAIN
/// BUILDING is not, and cannot be cheaply: it is the ECDSA work that dominates a full
/// handshake. So resumption is gated instead on
/// [`TlsAuthEpoch`](crate::tls_auth_epoch::TlsAuthEpoch), a digest of the trusted
/// client-CA set and the client-auth policy — exactly the inputs chain building depends
/// on. While that digest holds, a stored chain is still one the current trust would
/// build; when an operator withdraws a CA it changes, every stored session stops being a
/// shortcut, and the peer takes a full handshake against current trust.
///
/// A stale session is never an authorization failure — it is the absence of a shortcut.
///
/// The store is shared by every per-core worker serving through this config, which is
/// what makes resumption effective under `SO_REUSEPORT`: a reconnect landing on a
/// different worker still finds the session. It is also shared with every LATER build of
/// the same listener's config, so a CRL reload keeps the cache instead of emptying it.
///
/// Each build republishes the epoch its own trust inputs digest to. Republishing an
/// unchanged epoch is the common case and changes nothing; a change is announced, and
/// from that moment every session stored under the old digest is evicted the next time
/// it is looked up.
///
/// Early data stays disabled (rustls' default): a 0-RTT payload would be replayable and
/// is accepted before the handshake completes.
///
/// STATELESS tickets are disabled here too, and that is part of the gate rather than a
/// tuning choice. rustls offers two independent resumption mechanisms: the session store
/// installed below, and [`ProducesTickets`](rustls::server::ProducesTickets) encrypted
/// tickets. When a ticketer is enabled the server resumes straight out of the
/// client-supplied ticket and the session store is never consulted — so the epoch tag,
/// the mismatch eviction, and every claim made above would be bypassed silently. The
/// store is the ONLY resumption path only while [`NoStatelessTickets`] is the ticketer.
fn epoch_bound_resumption(
    mut config: ServerConfig,
    resumption: &Arc<crate::tls_auth_epoch::EpochBoundSessionStore>,
    epoch: crate::tls_auth_epoch::TlsAuthEpoch,
) -> ServerConfig {
    if let Some(previous) = resumption.republish(epoch) {
        eprintln!(
            "mcp-re-proxy: TLS auth epoch advanced {} -> {} (trusted client CAs or the \
             client-auth policy changed); every stored session stops being a shortcut and \
             its peer takes a full handshake against current trust",
            previous.short(),
            epoch.short()
        );
    }
    config.session_storage =
        Arc::clone(resumption) as Arc<dyn rustls::server::StoresServerSessions>;
    config.ticketer = Arc::new(NoStatelessTickets);
    config.max_early_data_size = 0;
    config
}

/// The ticketer that issues no stateless session tickets, so every resumption decision
/// goes through the epoch-tagged session store.
///
/// `enabled()` is false, which is what rustls reads: a server whose ticketer is disabled
/// stores the session server-side and resumes only from that store. The remaining methods
/// refuse as well, so a caller that consults them directly cannot mint or accept a ticket
/// either.
#[derive(Debug)]
struct NoStatelessTickets;

impl rustls::server::ProducesTickets for NoStatelessTickets {
    fn enabled(&self) -> bool {
        false
    }

    fn lifetime(&self) -> u32 {
        0
    }

    fn encrypt(&self, _plain: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn decrypt(&self, _cipher: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

/// How many resumable sessions one `ServerConfig` retains.
///
/// Matched to `ServerLimits::max_concurrent_connections` (256) times a small factor, so
/// a peer set that fills the connection cap can still resume after briefly disconnecting
/// rather than evicting itself. Each entry is a few hundred bytes; the cache is bounded,
/// so this cannot grow with peer count.
const TLS_SESSION_CACHE_ENTRIES: usize = 4096;

/// Build the fail-closed WebPKI client-certificate verifier shared by the
/// exported-key ([`RustlsDirectProvider::build_server_config_with_crls`]) and delegated-key
/// ([`build_server_config_delegated_with_crls`]) server-config paths. Sharing it
/// keeps the security-critical verifier posture identical across both: strict
/// unknown-status rejection by default, full-chain revocation, operator opt-out
/// only via `allow_unknown_revocation_status`, and a malformed CRL → startup
/// `TlsError::Verifier` (fail closed).
///
/// ADR-MCPS-023 §A1 (v0.9, MCPS-58): the verifier now **enforces CRL expiration**
/// (`enforce_revocation_expiration`). Before this, the builder used the rustls
/// default `ExpirationPolicy::Ignore`, i.e. a CRL past its `nextUpdate` was still
/// honored — revocation checking silently failed OPEN on staleness. Enforcing it
/// means a stale CRL causes new handshakes to fail CLOSED. Because a stale CRL
/// then rejects everything, this ships together with the startup freshness gate
/// ([`crl_freshness`]) and the "restart before `nextUpdate`" operator contract;
/// the in-process hot-reloader is tracked as a v0.10 follow-up. The call is a
/// no-op when no CRLs are configured (revocation checks are not performed).
fn build_client_verifier(
    client_ca: Vec<CertificateDer<'static>>,
    crls: Vec<CertificateRevocationListDer<'static>>,
    allow_unknown_revocation_status: bool,
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Result<Arc<dyn rustls::server::danger::ClientCertVerifier>, TlsError> {
    let mut roots = RootCertStore::empty();
    for ca in client_ca {
        roots.add(ca).map_err(|_| TlsError::BadClientCa)?;
    }
    let mut builder = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
        .with_crls(crls)
        .enforce_revocation_expiration();
    if allow_unknown_revocation_status {
        builder = builder.allow_unknown_revocation_status();
    }
    builder
        .build()
        .map_err(|e| TlsError::Verifier(e.to_string()))
}

/// The freshness of a configured client CRL relative to a verification instant
/// (ADR-MCPS-023 §A1, MCPS-58).
///
/// [`build_client_verifier`] now enforces `nextUpdate` at handshake time, so a
/// `Stale` CRL fails every new handshake closed. This startup gate surfaces that
/// condition **loudly at boot**: under strict the proxy refuses to start, rather
/// than coming up and silently rejecting every client at the first handshake, and
/// it warns while a CRL is `NearExpiry` so the operator can reload/restart with a
/// refreshed CRL before the cutover (the "restart before `nextUpdate`" contract;
/// the in-process hot-reloader is a v0.10 follow-up).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrlFreshness {
    /// `now < nextUpdate - warn_window` — comfortably valid.
    Fresh,
    /// `nextUpdate - warn_window <= now < nextUpdate` — still valid, but a
    /// refreshed CRL must be in place before `next_update_unix` or new handshakes
    /// will start failing closed.
    NearExpiry { next_update_unix: i64 },
    /// `now >= nextUpdate` — expired; the verifier fails all new handshakes closed.
    Stale { next_update_unix: i64 },
    /// The CRL carries no `nextUpdate` at all, so it never falls out of force.
    ///
    /// Neither rustls' expiration enforcement nor
    /// [`client_revocation`](crate::client_revocation) has anything to compare against,
    /// so such a CRL would be honoured — and its issuer answered `Good` for — for the
    /// whole process lifetime, however long the reload has been failing. That is the
    /// exact opposite of the self-bounding property the TLS plane's fail-closed argument
    /// rests on, so it is a refusal rather than a freshness class the caller may ignore.
    NoNextUpdate,
}

/// Refuse a client CRL that omits `nextUpdate`.
///
/// RFC 5280 §5.1.2.5 requires a conforming CRL issuer to include it, and every
/// self-bounding claim this proxy makes about revocation is a claim about it: past
/// `nextUpdate` the handshake verifier fails closed and the per-request index downgrades
/// the issuer to `Unknown`, which is refused. A CRL without one reaches neither point,
/// so it is refused where it is read — at startup and on every reload — rather than
/// admitted into a posture that says it bounds itself.
pub fn crl_next_update_required(crl_der: &[u8], index: usize) -> Result<(), TlsError> {
    if crl_freshness(crl_der, 0, 0)? == CrlFreshness::NoNextUpdate {
        return Err(TlsError::Verifier(format!(
            "client CRL #{index} omits nextUpdate. It would never fall out of force, so a \
             reload that stops working (unreadable mount, dead reload thread) would leave \
             this replica admitting certificates revoked afterwards for the rest of its \
             lifetime. RFC 5280 §5.1.2.5 requires conforming CRL issuers to include \
             nextUpdate; publish a CRL that does."
        )));
    }
    Ok(())
}

/// Classify a DER-encoded client CRL's `nextUpdate` against `now_unix`, warning
/// `warn_window_secs` ahead of expiry. Pure and offline-testable.
///
/// A CRL with no `nextUpdate` is classified [`CrlFreshness::NoNextUpdate`], which
/// [`crl_next_update_required`] turns into a refusal: nothing in the stack can age such
/// a CRL out. A CRL that cannot be parsed is a hard error — the verifier build would
/// reject it too, so this fails closed rather than silently skipping the gate.
pub fn crl_freshness(
    crl_der: &[u8],
    now_unix: i64,
    warn_window_secs: i64,
) -> Result<CrlFreshness, TlsError> {
    use der::Decode;
    use x509_cert::crl::CertificateList;
    let crl = CertificateList::from_der(crl_der)
        .map_err(|e| TlsError::Verifier(format!("malformed client CRL: {e}")))?;
    let next_update = match crl.tbs_cert_list.next_update {
        Some(t) => t.to_unix_duration().as_secs() as i64,
        None => return Ok(CrlFreshness::NoNextUpdate),
    };
    Ok(if now_unix >= next_update {
        CrlFreshness::Stale {
            next_update_unix: next_update,
        }
    } else if now_unix >= next_update - warn_window_secs {
        CrlFreshness::NearExpiry {
            next_update_unix: next_update,
        }
    } else {
        CrlFreshness::Fresh
    })
}

/// The startup revocation-posture facts for a configured client CRL
/// (ADR-MCPS-023 §A1, MCPS-58).
///
/// These feed the operator-visible `mcp-re.revocation.posture` diagnostic line. That
/// line is a **posture diagnostic, not a structured per-request audit guarantee** —
/// the structured evidence/audit vocabulary lands with Mode C attested ingress
/// (MCPS-62), where `delegated_attestor_crl` actually exists. The field names here
/// (`crl_digest`, `crl_this_update`, `crl_next_update`) are the canonical ones so a
/// future structured audit sink can reuse them verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrlPosture {
    /// `sha256:<base64url>` over the CRL DER (the MCP-RE hash-identifier format).
    pub crl_digest: String,
    /// `thisUpdate` as a Unix timestamp.
    pub this_update_unix: i64,
    /// `nextUpdate` as a Unix timestamp, if present (RFC 5280 permits omission).
    pub next_update_unix: Option<i64>,
}

/// Extract the [`CrlPosture`] facts from a DER-encoded client CRL. Pure and
/// offline-testable. A malformed CRL is a hard error (fail closed), consistent
/// with [`crl_freshness`] and the verifier build.
pub fn crl_posture(crl_der: &[u8]) -> Result<CrlPosture, TlsError> {
    use der::Decode;
    use x509_cert::crl::CertificateList;
    let crl = CertificateList::from_der(crl_der)
        .map_err(|e| TlsError::Verifier(format!("malformed client CRL: {e}")))?;
    let this_update = crl.tbs_cert_list.this_update.to_unix_duration().as_secs() as i64;
    let next_update_unix = crl
        .tbs_cert_list
        .next_update
        .map(|t| t.to_unix_duration().as_secs() as i64);
    Ok(CrlPosture {
        crl_digest: mcp_re_core::sha256_hash_id(crl_der),
        this_update_unix: this_update,
        next_update_unix,
    })
}

/// Build a mutual-TLS [`ServerConfig`] whose server certificate is signed by a
/// non-exporting device/KMS via a [`ResolvesServerCert`] (ADR-MCPS-028 §G), rather
/// than from an exported private key. The TLS server private key never leaves the
/// device; rustls drives the handshake signature through the resolver's
/// [`SigningKey`](rustls::sign::SigningKey).
///
/// The client-cert verifier posture is IDENTICAL to the exported-key path (shared
/// [`build_client_verifier`]). The `fault_accept_any_client` test bypass is NOT
/// wired here: it exercises the standard exported-key serving path, and weakening
/// client auth is orthogonal to (and must not be conflated with) server-key
/// delegation — the delegated path always uses the real verifier.
pub fn build_server_config_delegated_with_crls(
    cert_resolver: Arc<dyn rustls::server::ResolvesServerCert>,
    client_ca: Vec<CertificateDer<'static>>,
    crls: Vec<CertificateRevocationListDer<'static>>,
    allow_unknown_revocation_status: bool,
) -> Result<ServerConfig, TlsError> {
    let resumption = new_resumption_state(&client_ca, allow_unknown_revocation_status);
    build_server_config_delegated_with_crls_resuming(
        cert_resolver,
        client_ca,
        crls,
        allow_unknown_revocation_status,
        &resumption,
    )
}

/// As [`build_server_config_delegated_with_crls`], reusing a resumption state that
/// outlives this config. See
/// [`RustlsDirectProvider::build_server_config_with_crls_resuming`].
pub(crate) fn build_server_config_delegated_with_crls_resuming(
    cert_resolver: Arc<dyn rustls::server::ResolvesServerCert>,
    client_ca: Vec<CertificateDer<'static>>,
    crls: Vec<CertificateRevocationListDer<'static>>,
    allow_unknown_revocation_status: bool,
    resumption: &Arc<crate::tls_auth_epoch::EpochBoundSessionStore>,
) -> Result<ServerConfig, TlsError> {
    // Computed BEFORE `client_ca` is moved into the verifier (ADR-MCPRE-055).
    let epoch =
        crate::tls_auth_epoch::TlsAuthEpoch::compute(&client_ca, allow_unknown_revocation_status);
    let provider = Arc::new(ring::default_provider());
    let verifier = build_client_verifier(
        client_ca,
        crls,
        allow_unknown_revocation_status,
        provider.clone(),
    )?;
    let server_config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| TlsError::Config(e.to_string()))?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(cert_resolver);
    Ok(epoch_bound_resumption(server_config, resumption, epoch))
}

/// Extract the 32 raw Ed25519 public-key bytes from a leaf certificate's
/// `SubjectPublicKeyInfo` (issue #58, ADR-MCPS-028 §G). Reuses the RFC 8410 SPKI
/// parser shared with the KMS public-key path ([`ed25519_raw_point_from_spki`]),
/// so a non-Ed25519 leaf (RSA / NIST P-curve / malformed) is rejected with the
/// same fail-closed posture. The DER SPKI bytes are taken verbatim from the parsed
/// certificate (`x509-parser`), not re-encoded.
fn leaf_ed25519_raw_point(leaf_der: &[u8]) -> Result<[u8; 32], TlsError> {
    let (_, cert) = X509Certificate::from_der(leaf_der).map_err(|e| {
        TlsError::DelegatedKeyMismatch(format!("leaf certificate is not parseable DER: {e}"))
    })?;
    let spki_der = cert.public_key().raw;
    crate::kms_keysource::ed25519_raw_point_from_spki(spki_der).map_err(|e| {
        TlsError::DelegatedKeyMismatch(format!(
            "delegated TLS is Ed25519-only; leaf certificate public key is not an RFC 8410 \
             Ed25519 SubjectPublicKeyInfo: {e}"
        ))
    })
}

/// Build a delegated mTLS [`ServerConfig`] (ADR-MCPS-028 §G, issue #58) with the
/// security preconditions VALIDATED at config construction — a wrapper around the
/// FROZEN [`build_server_config_delegated_with_crls`] that fails closed BEFORE any
/// server starts when the credential is unsafe:
///
///   * **Ed25519-only** — the leaf certificate's `SubjectPublicKeyInfo` MUST be an
///     RFC 8410 Ed25519 key (the only scheme the delegated signer can produce).
///   * **cert ↔ signer key match** — the delegated signer's Ed25519 public key MUST
///     equal the leaf certificate's public key, so the handshake the signer signs
///     verifies against the cert it presents. A mismatch is rejected here rather
///     than surfacing as an opaque handshake failure at runtime.
///
/// The client-cert verifier posture is identical to every other path (shared
/// [`build_client_verifier`], via the wrapped frozen builder). The server's TLS
/// private key never leaves the device/KMS.
pub fn build_server_config_delegated_validated(
    server_chain: Vec<CertificateDer<'static>>,
    signer: Arc<dyn crate::delegated_tls::RawEd25519TlsSigner>,
    client_ca: Vec<CertificateDer<'static>>,
    crls: Vec<CertificateRevocationListDer<'static>>,
    allow_unknown_revocation_status: bool,
) -> Result<ServerConfig, TlsError> {
    let resumption = new_resumption_state(&client_ca, allow_unknown_revocation_status);
    let budget = Arc::new(crate::delegated_tls::TlsHandshakeSignBudget::default());
    build_server_config_delegated_validated_resuming(
        server_chain,
        signer,
        client_ca,
        crls,
        allow_unknown_revocation_status,
        &resumption,
        &budget,
    )
}

/// As [`build_server_config_delegated_validated`], reusing a resumption state AND a
/// handshake-signature budget that both outlive this config.
///
/// The budget is carried across rebuilds for the same reason the resumption cache is: it
/// bounds how fast unauthenticated peers can drive a remote, billed, account-throttled
/// signer, and a bucket refilled to full on every reload cadence bounds a window rather
/// than a rate.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_server_config_delegated_validated_resuming(
    server_chain: Vec<CertificateDer<'static>>,
    signer: Arc<dyn crate::delegated_tls::RawEd25519TlsSigner>,
    client_ca: Vec<CertificateDer<'static>>,
    crls: Vec<CertificateRevocationListDer<'static>>,
    allow_unknown_revocation_status: bool,
    resumption: &Arc<crate::tls_auth_epoch::EpochBoundSessionStore>,
    budget: &Arc<crate::delegated_tls::TlsHandshakeSignBudget>,
) -> Result<ServerConfig, TlsError> {
    let leaf = server_chain.first().ok_or_else(|| {
        TlsError::DelegatedKeyMismatch(
            "delegated TLS server certificate chain is empty".to_string(),
        )
    })?;
    // Ed25519-only (fail closed) + extract the leaf's raw public point.
    let leaf_point = leaf_ed25519_raw_point(leaf.as_ref())?;

    // The signer's public key, parsed through the SAME RFC 8410 Ed25519 SPKI guard.
    let signer_spki = signer.tls_public_key_spki_der().map_err(|e| {
        TlsError::DelegatedKeyMismatch(format!(
            "delegated TLS signer did not yield an exportable public key: {e}"
        ))
    })?;
    let signer_point =
        crate::kms_keysource::ed25519_raw_point_from_spki(&signer_spki).map_err(|e| {
            TlsError::DelegatedKeyMismatch(format!(
                "delegated TLS signer public key is not an RFC 8410 Ed25519 \
                 SubjectPublicKeyInfo: {e}"
            ))
        })?;

    // cert ↔ signer key match (fail closed). Without this, rustls would present a
    // certificate the signer cannot match, and the handshake would fail with an
    // opaque error every time — reject at construction instead.
    if signer_point != leaf_point {
        return Err(TlsError::DelegatedKeyMismatch(
            "the delegated TLS signer's Ed25519 public key does not match the leaf \
             certificate's SubjectPublicKeyInfo; the signer signs for a different key than \
             the certificate presents"
                .to_string(),
        ));
    }

    let resolver = crate::delegated_tls::DelegatedCertResolver::with_budget(
        server_chain,
        signer,
        Arc::clone(budget),
    );
    build_server_config_delegated_with_crls_resuming(
        resolver,
        client_ca,
        crls,
        allow_unknown_revocation_status,
        resumption,
    )
}

/// Extract the verified client identity from a leaf certificate (DER) using the
/// authoritative field named by `policy`. There is NO fallback: the configured
/// field is read and nothing else. Returns `None` if the certificate cannot be
/// parsed, does not carry the selected field, or carries a value that fails the
/// strict identity-value rules — the caller (transport binding) then fails closed
/// rather than accepting a weaker identity.
///
/// The extracted value is held to the SAME rules as an asserted trusted-ingress
/// identity ([`validate_asserted_identity_value`]): non-empty, length-bounded, and
/// free of control characters. A certificate field is not self-validating — an
/// issuer can mint a SAN or CN holding a CR/LF or a megabyte of padding, and this
/// value is carried into the transport binding and the logs, so the two identity
/// provenances must not disagree about what a well-formed identity is. Only the
/// FIRST matching field is considered, and a malformed first value is a rejection
/// rather than a reason to look at the next one — searching on would be exactly
/// the fallback this function disclaims.
pub fn extract_identity(leaf_der: &[u8], policy: IdentityPolicy) -> Option<TransportIdentity> {
    let (_, cert) = X509Certificate::from_der(leaf_der).ok()?;

    // Bind to an owned String so the borrow of `cert` ends before return.
    let (raw, source): (String, IdentitySource) = match policy {
        IdentityPolicy::UriSan => {
            let san = cert.subject_alternative_name().ok().flatten()?;
            let uri = san.value.general_names.iter().find_map(|name| match name {
                GeneralName::URI(uri) => Some((*uri).to_string()),
                _ => None,
            })?;
            (uri, IdentitySource::UriSan)
        }
        IdentityPolicy::DnsSan => {
            let san = cert.subject_alternative_name().ok().flatten()?;
            let dns = san.value.general_names.iter().find_map(|name| match name {
                GeneralName::DNSName(dns) => Some((*dns).to_string()),
                _ => None,
            })?;
            (dns, IdentitySource::DnsSan)
        }
        IdentityPolicy::CnLegacy => {
            let common_name = cert
                .subject()
                .iter_common_name()
                .next()
                .and_then(|cn| cn.as_str().ok())
                .map(str::to_string)?;
            (common_name, IdentitySource::CommonName)
        }
    };

    let validated = crate::transport::validate_asserted_identity_value(&raw).ok()?;
    Some(TransportIdentity::new(validated, source))
}

/// The verified client identity for an established server connection (the leaf of
/// the peer certificate chain) under `policy`, or `None` if no peer certificate
/// is present or it lacks the selected identity field.
fn connection_identity(
    conn: &ServerConnection,
    policy: IdentityPolicy,
) -> Option<TransportIdentity> {
    let certs = conn.peer_certificates()?;
    let leaf = certs.first()?;
    extract_identity(leaf.as_ref(), policy)
}

/// Resolve the verified transport identity for one served request under the
/// configured [`IdentityStrategy`]. The two strategies are MUTUALLY EXCLUSIVE on
/// a per-connection basis:
///   * [`IdentityStrategy::DirectTls`] reads it from the verified peer
///     certificate via [`connection_identity`] and IGNORES request headers;
///   * [`IdentityStrategy::ReverseProxyHeader`] reads it from the trusted
///     forwarded header via the [`ReverseProxyMtlsProvider`] and NEVER consults
///     the local client certificate (mTLS is terminated upstream).
///
/// Either way a missing/unparseable identity is `None`, and the downstream
/// transport-binding policy fails closed.
fn resolve_identity(
    conn: &ServerConnection,
    options: &ServerOptions,
    headers: &RequestHeaders,
) -> Option<TransportIdentity> {
    match &options.identity_strategy {
        IdentityStrategy::DirectTls => connection_identity(conn, options.identity_policy),
        IdentityStrategy::ReverseProxyHeader(provider) => provider.verified_identity(headers),
        // The Tier-3 identity binds the request hash and is resolved AFTER object
        // verification (inside the proxy), so it is intentionally absent here.
        IdentityStrategy::LbAssertion => None,
    }
}

/// Leaf-DER form of [`resolve_identity`] for the opt-in async serve path
/// (ADR-MCPRE-051 §1): identical strategy dispatch, but `DirectTls` reads the peer
/// identity from the leaf DER captured once at handshake (`hyper` owns the TLS
/// stream thereafter) rather than from the live `ServerConnection`. `extract_identity`
/// is the SAME extractor the blocking path's `connection_identity` calls, so the
/// resolved identity is byte-identical.
#[cfg_attr(not(feature = "async_serve"), allow(dead_code))]
pub(crate) fn resolve_identity_from_leaf(
    leaf_der: Option<&[u8]>,
    options: &ServerOptions,
    headers: &RequestHeaders,
) -> Option<TransportIdentity> {
    match &options.identity_strategy {
        IdentityStrategy::DirectTls => extract_identity(leaf_der?, options.identity_policy),
        IdentityStrategy::ReverseProxyHeader(provider) => provider.verified_identity(headers),
        IdentityStrategy::LbAssertion => None,
    }
}

/// Captured-chain form of [`connection_rejection`] for the async serve path, which
/// cannot read the live connection: hyper owns the TLS stream once the handshake is
/// done, so the peer chain is captured at handshake and handed here per request.
///
/// `chain[0]` is the leaf and the rest are the intermediates the peer presented,
/// leaf-first — the same order and the same decision as the blocking path, which
/// reads them from `ServerConnection::peer_certificates`. An empty chain is an absent
/// peer certificate and fails closed in the core.
///
/// NOTE: online-OCSP revocation (`#[cfg(feature = "online_ocsp")]`) needs the live
/// connection and is NOT yet wired on the async path — combining `async_serve` with
/// `online_ocsp` is a tracked follow-up; the default and shared-replay tier builds have
/// full parity.
#[cfg_attr(not(feature = "async_serve"), allow(dead_code))]
pub(crate) fn connection_rejection_for_chain(
    chain: &[&[u8]],
    options: &ServerOptions,
    request: &[u8],
    now: i64,
) -> Option<Vec<u8>> {
    cert_lifetime_rejection_for_chain(chain, options, request, now)
}

/// Extract the raw Tier-3 ingress-assertion header value to hand to the
/// post-verification LB check (issue #71), under the [`IdentityStrategy::LbAssertion`]
/// strategy ONLY. The header is fetched case-insensitively and fails CLOSED on a
/// DUPLICATE: a single header value is returned only when EXACTLY one is present.
///
/// Returns `Some(value)` for a single present header; `None` when the strategy is
/// not LB-assertion, when the header is absent (the proxy then fails closed because
/// the LB verifier requires it), or when the header is duplicated (a downstream
/// injection attempt — fail closed). The `None`-on-duplicate behaviour mirrors the
/// reverse-proxy provider's duplicate-trust-header rule: the proxy's required-header
/// guard turns the resulting `None` into a closed rejection.
pub(crate) fn assertion_header<'a>(
    options: &ServerOptions,
    headers: &'a RequestHeaders,
) -> Option<&'a str> {
    match &options.identity_strategy {
        IdentityStrategy::LbAssertion => {
            // Fail closed on a duplicated trust header before reading any value.
            if headers.count(MCP_INGRESS_ASSERTION_HEADER) != 1 {
                return None;
            }
            headers.first(MCP_INGRESS_ASSERTION_HEADER)
        }
        _ => None,
    }
}

/// Everything the per-request transport checks need from the peer leaf, borrowed from
/// the DER rather than copied.
pub(crate) struct LeafFacts<'a> {
    pub(crate) not_before: i64,
    pub(crate) not_after: i64,
    /// The raw DER of the issuer `Name`, matched byte-for-byte against a CRL's issuer.
    pub(crate) issuer_der: &'a [u8],
    /// The serial's DER INTEGER content octets.
    pub(crate) serial: &'a [u8],
}

/// Parse the peer leaf ONCE for every per-request transport decision: its validity
/// window, and the (issuer, serial) coordinate revocation is keyed by.
///
/// One parse because these are separate questions about the same certificate, and
/// parsing X.509 DER twice per request is measurable on the §7 envelope — it cost ~18%
/// of throughput when the validity checks alone were two functions.
///
/// `None` if the certificate cannot be parsed, or its window is degenerate
/// (`not_after <= not_before`). A degenerate window is treated exactly like an
/// unparseable certificate: the caller fails closed (G-5) rather than admitting a cert
/// whose negative span would trivially satisfy any `<= max` bound.
fn leaf_facts(leaf_der: &[u8]) -> Option<LeafFacts<'_>> {
    let (_, cert) = X509Certificate::from_der(leaf_der).ok()?;
    let not_before = cert.validity().not_before.timestamp();
    let not_after = cert.validity().not_after.timestamp();
    if not_after <= not_before {
        return None;
    }
    Some(LeafFacts {
        not_before,
        not_after,
        issuer_der: cert.tbs_certificate.issuer.as_raw(),
        serial: cert.tbs_certificate.raw_serial(),
    })
}

/// Enforce the configured maximum client-certificate lifetime (the v1 revocation
/// posture). Returns `Some(error_bytes)` — a `mcp-re.transport_binding_failed`
/// JSON-RPC error bound to the request id — when a limit is set and the verified
/// client cert's validity span exceeds it (or the cert is absent or cannot be
/// parsed); `None` when the cert is within the limit or no limit is configured.
/// Emitting the
/// transport-layer error here is consistent with the proxy being the sole holder
/// of the connection (see `transport` module docs).
fn cert_lifetime_rejection(
    conn: &ServerConnection,
    options: &ServerOptions,
    request: &[u8],
) -> Option<Vec<u8>> {
    // An absent peer certificate is passed THROUGH as an EMPTY chain rather than
    // short-circuiting here, so the decision (including the no-leaf case) is made
    // in one place by the fail-closed core. The WHOLE chain is handed over, because
    // the handshake verifier checks revocation to the trust anchor
    // (`RevocationCheckDepth::Chain`) and a per-request check that stopped at the
    // leaf would keep honouring a revoked intermediate.
    let chain: Vec<&[u8]> = conn
        .peer_certificates()
        .map(|chain| chain.iter().map(|cert| cert.as_ref()).collect())
        .unwrap_or_default();
    cert_lifetime_rejection_for_chain(&chain, options, request, wall_clock_unix())
}

/// Wall-clock Unix seconds for the transport-layer certificate-validity check.
///
/// The serving path's own `now` is threaded from `app.rs` for every EVIDENCE
/// decision; this one is read here because the check runs at the transport layer,
/// below the request pipeline, and a pre-epoch fault clamps to 0 — which fails every
/// validity window closed.
pub(crate) fn wall_clock_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The certificate core of [`cert_lifetime_rejection`], shared by the blocking serve
/// loop (which reads the chain from the live `ServerConnection`) and the async serving
/// fleet (which captures it once at handshake, because `hyper` takes ownership of the
/// TLS stream for keep-alive/H2). The DECISION is identical on both — only the chain's
/// provenance differs.
///
/// `chain[0]` is the peer leaf and the rest are the intermediates the peer presented,
/// leaf-first, exactly as `ServerConnection::peer_certificates` orders them. An empty
/// chain is an absent peer certificate.
///
/// The leaf carries the lifetime, validity-window and revocation decision; every
/// further certificate carries a validity window and a revocation decision. That matches
/// what the handshake verifier does — chain-deep revocation to the trust anchor, one
/// validity window per certificate checked by the path builder — so a peer cannot be
/// admitted on request 2 under an intermediate that was refused on request 1, and a
/// session resumed after its issuing intermediate expired stops being served.
///
/// Intermediates are refused only on an EXPLICIT `Revoked` verdict, never on `Unknown`.
/// Whether the chain reaches a CRL-covered issuer is a path-building question the
/// handshake already settled; re-deciding it here from the certificates the peer chose
/// to send would refuse chains the handshake admitted.
pub(crate) fn cert_lifetime_rejection_for_chain(
    chain: &[&[u8]],
    options: &ServerOptions,
    request: &[u8],
    now: i64,
) -> Option<Vec<u8>> {
    // Nothing to enforce: no lifetime ceiling AND no CRLs. Return before the parse, so
    // a deployment that configures neither pays nothing for either.
    let ceiling = options.max_client_cert_lifetime;
    let revocation = options.client_revocation.as_ref();
    if ceiling.is_none() && revocation.is_none() {
        return None;
    }

    // An ABSENT leaf is treated exactly like an unparseable one. Only a leaf that
    // parses AND passes every configured check is admitted; every other case —
    // no peer certificate, unparseable DER, inverted validity window, over-long
    // span, revoked serial — falls through to the rejection below. Returning `None`
    // for a missing leaf would waive the very checks these exist to perform, and would
    // do it one line before an unparseable cert fails closed.
    let leaf_admitted = chain
        .first()
        .and_then(|leaf| leaf_facts(leaf))
        .is_some_and(|facts| {
            // The certificate's OWN validity window, independent of every configured
            // control. A short-lived certificate satisfies a span ceiling for the rest
            // of time, so without this comparison a peer that keeps one connection open
            // keeps serving under an EXPIRED credential. It is checked whenever any
            // per-request certificate control is configured, because it is a property of
            // the certificate rather than of the ceiling: fusing it to
            // `max_client_cert_lifetime` made a CRL-only deployment stop re-checking
            // expiry at all.
            let within_window = now >= facts.not_before && now < facts.not_after;
            // SPAN within the ceiling — the short-lived-certificate posture.
            let within_lifetime = ceiling
                .is_none_or(|max| facts.not_after - facts.not_before <= max.as_secs() as i64);
            // And NOT REVOKED as of the CRLs in force right now. The handshake consulted
            // them once; every later request on a keep-alive or HTTP/2 connection is served
            // without the verifier ever running again, so this is the only point at which a
            // reloaded CRL reaches the connection a revoked peer is already holding open.
            let not_revoked = revocation.is_none_or(|revocation| {
                revocation
                    .load()
                    .admits(facts.issuer_der, facts.serial, now)
            });
            within_window && within_lifetime && not_revoked
        });
    if leaf_admitted
        && chain_issuers_within_validity(chain, now)
        && chain_issuers_not_revoked(chain, options, now)
    {
        return None;
    }
    // Absent, unparseable, over-long or revoked cert → fail closed with the transport
    // error, bound to the request id when we can read it.
    let id = serde_json::from_slice::<serde_json::Value>(request)
        .ok()
        .and_then(|value| value.get("id").cloned())
        .unwrap_or(serde_json::Value::Null);
    Some(json_rpc_error_object(
        &McpReError::TransportBindingFailed,
        &id,
    ))
}

/// Is every certificate ABOVE the leaf still inside its own validity window?
///
/// Chain building runs during client authentication, which rustls performs on a FULL
/// handshake only. A resumed session restores the stored peer chain verbatim and skips
/// it, so without this a peer whose issuing INTERMEDIATE has since expired keeps being
/// admitted on every reconnect that resumes — and the trust epoch cannot catch it,
/// because the epoch digests the configured anchor set and an intermediate is not in it.
///
/// The handshake's path builder refuses an expired certificate on the path it builds, so
/// refusing one here can only agree with what a full handshake would have decided.
///
/// A SELF-ISSUED certificate (issuer `Name` == subject `Name`) is exempt. A peer may
/// send its root, path building matches that against the CONFIGURED anchor set rather
/// than against its own validity window, and holding it to a window here would refuse
/// chains a full handshake admits.
///
/// A certificate whose DER does not parse is refused — the same fail-closed direction
/// the leaf takes, and the handshake already parsed every one of these.
fn chain_issuers_within_validity(chain: &[&[u8]], now: i64) -> bool {
    let Some(issuers) = chain.get(1..).filter(|rest| !rest.is_empty()) else {
        return true;
    };
    issuers
        .iter()
        .all(|der| match X509Certificate::from_der(der) {
            Err(_) => false,
            Ok((_, cert)) => {
                let self_issued =
                    cert.tbs_certificate.issuer.as_raw() == cert.tbs_certificate.subject.as_raw();
                self_issued
                    || (now >= cert.validity().not_before.timestamp()
                        && now < cert.validity().not_after.timestamp())
            }
        })
}

/// Is every certificate ABOVE the leaf still un-revoked as of the CRLs in force?
///
/// The handshake verifier checks revocation to the trust anchor, so an operator who
/// revokes a compromised intermediate expects that to reach open connections the same
/// way a revoked leaf does. Without this, a peer holding a keep-alive or HTTP/2
/// connection under a leaf issued by that intermediate kept full authenticated access
/// until the connection-age bound closed it.
///
/// `Revoked` is the only refusal: see [`cert_lifetime_rejection_for_chain`]. An
/// intermediate whose DER does not parse is refused too — the same fail-closed
/// direction the leaf takes, and the handshake already parsed every one of these.
fn chain_issuers_not_revoked(chain: &[&[u8]], options: &ServerOptions, now: i64) -> bool {
    let Some(revocation) = options.client_revocation.as_ref() else {
        return true;
    };
    let Some(issuers) = chain.get(1..).filter(|rest| !rest.is_empty()) else {
        return true;
    };
    let index = revocation.load();
    if index.is_empty() {
        return true;
    }
    issuers.iter().all(|der| match leaf_facts(der) {
        None => false,
        Some(facts) => {
            index.verdict(facts.issuer_der, facts.serial, now)
                != crate::client_revocation::RevocationVerdict::Revoked
        }
    })
}

/// ADR-MCPS-025 routing-header hygiene rejection — runs at the SAME per-connection
/// point as [`cert_lifetime_rejection`] (after the verified handshake, before the
/// handler). Returns `Some(error_bytes)` when a SEP-2243 routing header
/// (`Mcp-Method` / `Mcp-Name`) is duplicated or malformed, `None` when the routing
/// headers are absent or well-formed.
///
/// The proxy never routes on these headers — the signed body is authoritative —
/// so this is anti-smuggling hygiene (ADR-MCPS-025 rule 4 applying the ADR-MCPS-023
/// strict-header rules). A defect maps to `mcp-re.transport_binding_failed`, the same
/// transport-boundary token the sibling cert-lifetime / OCSP rejections use.
pub(crate) fn routing_header_rejection(
    headers: &RequestHeaders,
    request: &[u8],
) -> Option<Vec<u8>> {
    crate::transport::validate_routing_headers(headers)
        .err()
        .map(|_rejection| {
            let id = serde_json::from_slice::<serde_json::Value>(request)
                .ok()
                .and_then(|value| value.get("id").cloned())
                .unwrap_or(serde_json::Value::Null);
            json_rpc_error_object(&McpReError::TransportBindingFailed, &id)
        })
}

/// Online OCSP revocation rejection (#4030) — the online sibling of
/// [`cert_lifetime_rejection`], running at the SAME per-connection point (after
/// the verified handshake, before the handler). Returns `Some(error_bytes)` (a
/// `mcp-re.transport_binding_failed` JSON-RPC error bound to the request id) when
/// an OCSP checker is configured AND the verified client leaf must be rejected;
/// `None` when no checker is configured or the leaf is admitted.
///
/// Fail-closed posture (mirrors the offline CRL deny-unknown default): the leaf
/// is REJECTED when the responder reports `Revoked` (always), or `Unknown`, or
/// the check errors (unreachable / timeout / parse), UNLESS the checker is in
/// soft-fail mode — in which case only `Revoked` rejects. The issuer is taken
/// from the verified peer chain (the cert directly after the leaf); a leaf with
/// no chained issuer cannot be checked and is treated as an indeterminate
/// result (rejected unless soft-fail). The HTTP fetch carries the checker's
/// mandatory timeout so this can never wedge the blocking serve thread.
#[cfg(feature = "online_ocsp")]
fn ocsp_rejection(
    conn: &ServerConnection,
    options: &ServerOptions,
    request: &[u8],
) -> Option<Vec<u8>> {
    let checker = options.ocsp_checker.as_ref()?;
    let reject = || {
        let id = serde_json::from_slice::<serde_json::Value>(request)
            .ok()
            .and_then(|value| value.get("id").cloned())
            .unwrap_or(serde_json::Value::Null);
        Some(json_rpc_error_object(
            &McpReError::TransportBindingFailed,
            &id,
        ))
    };

    let certs = conn.peer_certificates()?;
    let leaf = certs.first()?;
    // The issuer is the next cert in the verified chain. Without it we cannot
    // build a CertID; treat as an indeterminate (Unknown) result and apply the
    // fail-closed policy (reject unless soft-fail).
    let Some(issuer) = certs.get(1) else {
        return if checker.allows_on_error() {
            None
        } else {
            reject()
        };
    };

    match checker.check(leaf.as_ref(), issuer.as_ref()) {
        Ok(status) => {
            if checker.allows(status) {
                None
            } else {
                reject()
            }
        }
        // Transport/codec error: indeterminate, fail closed unless soft-fail.
        Err(_) => {
            if checker.allows_on_error() {
                None
            } else {
                reject()
            }
        }
    }
}

/// The per-connection rejection decision: the lifetime guard then (under the
/// `online_ocsp` feature) the online OCSP guard, in that order. Returns the
/// first rejection's error bytes, or `None` if the connection is admitted. In a
/// default build this is exactly `cert_lifetime_rejection` (the OCSP arm does
/// not exist), so the path is byte-for-byte unchanged.
fn connection_rejection(
    conn: &ServerConnection,
    options: &ServerOptions,
    request: &[u8],
) -> Option<Vec<u8>> {
    if let Some(error) = cert_lifetime_rejection(conn, options, request) {
        return Some(error);
    }
    #[cfg(feature = "online_ocsp")]
    if let Some(error) = ocsp_rejection(conn, options, request) {
        return Some(error);
    }
    None
}

/// Accept ONE TLS connection, complete the handshake (mTLS — a missing or
/// untrusted client certificate fails here), read one HTTP request body (bounded
/// by `options.limits`), invoke `handler(request_bytes, identity)`, and write the
/// response. Returns the verified client identity that was observed (for test
/// assertions), extracted with `options.identity_policy`.
///
/// Blocking; the caller owns the accept loop policy (see [`serve`]).
///
/// # NOT an MCP-RE serving path
///
/// This loop frames every reply as a literal `HTTP/1.1 200 OK` with a fixed header
/// set ([`write_http_response`]): the handler signature carries no status and no
/// headers, so there is nowhere for them to come from. Under ADR-MCPRE-050 the RFC
/// 9421 `Signature`/`Signature-Input`, the RFC 9530 `Content-Digest` and the STATUS
/// LINE are the evidence carrier — so a response written here can never be verified,
/// and a signed 403 rejection receipt would be flattened to a 200.
///
/// It exists as an mTLS TERMINATION + identity-extraction harness (the transport
/// crate's client tests run against it), and the shipped proxy does not use it:
/// `app.rs` serves on the async fleet, where `HttpProfileProxy` owns the status and
/// the headers. An integrator wanting a verifiable MCP-RE endpoint wants that path,
/// not this one.
pub fn serve_once<H>(
    listener: &TcpListener,
    config: Arc<ServerConfig>,
    options: &ServerOptions,
    handler: H,
) -> io::Result<Option<TransportIdentity>>
where
    H: FnOnce(&[u8], Option<TransportIdentity>) -> Vec<u8>,
{
    // Adapt the 2-arg handler to the assertion-aware form (the assertion header is
    // ignored — this entry point predates Tier-3 and stays byte-for-byte for its
    // many callers). The Tier-3 serve path uses [`serve_once_with_assertion`].
    serve_once_with_assertion(
        listener,
        config,
        options,
        |request, identity, _assertion| handler(request, identity),
    )
}

/// As [`serve_once`], but the handler ALSO receives the raw Tier-3 ingress-assertion
/// header value (issue #71) when the [`IdentityStrategy::LbAssertion`] strategy is
/// active. Under any other strategy the third argument is always `None`. This is the
/// entry point the production serve loop uses so the assertion can reach the proxy's
/// post-verification LB check (`Proxy::with_lb_assertion`); a duplicated assertion
/// header yields `None` (fail closed at the proxy's required-header guard).
pub fn serve_once_with_assertion<H>(
    listener: &TcpListener,
    config: Arc<ServerConfig>,
    options: &ServerOptions,
    handler: H,
) -> io::Result<Option<TransportIdentity>>
where
    H: FnOnce(&[u8], Option<TransportIdentity>, Option<&str>) -> Vec<u8>,
{
    let (tcp, _peer) = listener.accept()?;
    // MCPS-88: the production serve loop sets the LISTENER non-blocking so it can
    // poll for a shutdown signal between connections. Accepted connection sockets
    // inherit O_NONBLOCK on some platforms (BSD/macOS) but not others (Linux), so
    // force this one back to blocking — the bounded read/write phase below relies
    // on blocking semantics (plus the socket timeouts applied next). Harmless when
    // the listener is already blocking.
    tcp.set_nonblocking(false)?;
    apply_socket_timeouts(&tcp, &options.limits)?;
    let conn = ServerConnection::new(config).map_err(|e| io::Error::other(e.to_string()))?;
    // AGGREGATE wall-clock deadline over the WHOLE read phase (handshake + header/
    // body), the server-side mirror of mcp-re-transport's `DeadlineStream`
    // (MCPS-094/093): a peer trickling bytes just under `read_timeout` cannot hold
    // this serve thread without bound (slow-loris). Reads go through the wrapper;
    // writes delegate straight to the socket (bounded by `write_timeout`).
    let mut stream = StreamOwned::new(conn, DeadlineStream::new(tcp, &options.limits));

    // Reading the request drives the handshake to completion; an unauthenticated
    // or untrusted client certificate surfaces here as an error (fail closed).
    let request = read_http_request(&mut stream, &options.limits)?;
    let headers = RequestHeaders::parse(&request.header_block);
    let identity = resolve_identity(&stream.conn, options, &headers);
    let assertion = assertion_header(options, &headers);
    // Enforce the per-connection rejection guards (max client-cert lifetime, then
    // online OCSP revocation under the `online_ocsp` feature) BEFORE the handler
    // (inner never reached when rejected).
    let response = match connection_rejection(&stream.conn, options, &request.body)
        .or_else(|| routing_header_rejection(&headers, &request.body))
    {
        Some(error) => error,
        None => handler(&request.body, identity.clone(), assertion),
    };
    write_http_response(&mut stream, &response)?;
    // Clean TLS shutdown: send close_notify so the peer does not see an
    // unexpected EOF, then flush it out.
    stream.conn.send_close_notify();
    let _ = stream.flush();
    Ok(identity)
}

/// Production accept loop: handle each connection on its own thread (blocking,
/// no async). Each connection runs `handler` once. The number of simultaneously-
/// served connections is capped at `options.limits.max_concurrent_connections`;
/// connections beyond the cap are accepted and immediately dropped (fail closed
/// against connection exhaustion) rather than queued without bound. Runs until
/// `listener` errors.
pub fn serve<H>(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    options: ServerOptions,
    handler: H,
) where
    H: Fn(&[u8], Option<TransportIdentity>) -> Vec<u8> + Send + Sync + 'static,
{
    let handler = Arc::new(handler);
    let options = Arc::new(options);
    let in_flight = Arc::new(AtomicUsize::new(0));
    for incoming in listener.incoming() {
        let Ok(tcp) = incoming else { continue };
        let max = options.limits.max_concurrent_connections;
        // Reserve a slot; if the server is saturated, drop the connection.
        if in_flight.fetch_add(1, Ordering::AcqRel) >= max {
            in_flight.fetch_sub(1, Ordering::AcqRel);
            drop(tcp); // close immediately — do not serve beyond the cap
            continue;
        }
        let config = Arc::clone(&config);
        let handler = Arc::clone(&handler);
        let options = Arc::clone(&options);
        let in_flight = Arc::clone(&in_flight);
        std::thread::spawn(move || {
            let _ = serve_connection(tcp, config, &options, handler.as_ref());
            in_flight.fetch_sub(1, Ordering::AcqRel);
        });
    }
}

/// Handle a single already-accepted TCP stream: handshake, extract identity, one
/// request/response, bounded by `options.limits`.
fn serve_connection<H>(
    tcp: TcpStream,
    config: Arc<ServerConfig>,
    options: &ServerOptions,
    handler: &H,
) -> io::Result<()>
where
    H: Fn(&[u8], Option<TransportIdentity>) -> Vec<u8>,
{
    apply_socket_timeouts(&tcp, &options.limits)?;
    let conn = ServerConnection::new(config).map_err(|e| io::Error::other(e.to_string()))?;
    // Aggregate read-phase wall-clock deadline (slow-loris defense); see
    // [`serve_once_with_assertion`] and [`DeadlineStream`].
    let mut stream = StreamOwned::new(conn, DeadlineStream::new(tcp, &options.limits));
    let request = read_http_request(&mut stream, &options.limits)?;
    let headers = RequestHeaders::parse(&request.header_block);
    let identity = resolve_identity(&stream.conn, options, &headers);
    let response = match connection_rejection(&stream.conn, options, &request.body)
        .or_else(|| routing_header_rejection(&headers, &request.body))
    {
        Some(error) => error,
        None => handler(&request.body, identity),
    };
    write_http_response(&mut stream, &response)?;
    stream.conn.send_close_notify();
    let _ = stream.flush();
    Ok(())
}

/// Apply the configured read/write timeouts to a freshly-accepted socket.
fn apply_socket_timeouts(tcp: &TcpStream, limits: &ServerLimits) -> io::Result<()> {
    tcp.set_read_timeout(limits.read_timeout)?;
    tcp.set_write_timeout(limits.write_timeout)?;
    Ok(())
}

/// A `Read`/`Write` wrapper that enforces an AGGREGATE wall-clock deadline across
/// every READ on the inner stream — the server-side mirror of mcp-re-transport's
/// `DeadlineStream` (MCPS-094, #4081) and bounded response read (MCPS-093).
///
/// The per-socket `read_timeout` (`apply_socket_timeouts`) bounds each INDIVIDUAL
/// read, but a malicious peer trickling one byte just under that timeout resets
/// the per-read inactivity timer on every byte and can extend a single
/// connection's total read time without bound — driving the TLS handshake
/// (reading completes `complete_io`) and the HTTP header/body read forever
/// (slow-loris below the per-read threshold), holding a serve thread. Routing all
/// server-side reads through this wrapper caps the TOTAL read wall-clock: once
/// `deadline` passes, the next read fails closed with `io::ErrorKind::TimedOut`
/// and the connection is dropped. `None` deadline (the `request_deadline` knob
/// disabled) preserves the inner stream's own (per-read) semantics.
///
/// Writes delegate straight to the inner socket (bounded by the per-socket
/// `write_timeout`): the aggregate deadline governs the inbound read phase only,
/// so a legitimate slow response write is never spuriously dropped — symmetric
/// with mcp-re-transport, where `DeadlineStream` wraps only the handshake read and
/// the bare socket is reclaimed for the request write.
struct DeadlineStream<S> {
    inner: S,
    deadline: Option<std::time::Instant>,
    timeout: Option<Duration>,
}

impl<S> DeadlineStream<S> {
    /// Build the wrapper from the configured limits: the aggregate deadline is
    /// `now + request_deadline` (or `None`, disabling the bound). `request_deadline`
    /// is retained only for the error message.
    ///
    /// FAIL CLOSED: if a deadline was requested but `now + t` overflows `Instant`,
    /// we MUST NOT silently drop the bound — that would disable the slow-loris
    /// defense. The CLI caps `--request-deadline-secs` at parse time
    /// (`cli::parse_timeout`) so this overflow is practically unreachable, but as
    /// defense-in-depth we saturate to the current instant (deadline already
    /// elapsed → next read fails closed) rather than disable the control. The
    /// `None` deadline is reserved exclusively for "no deadline was requested".
    fn new(inner: S, limits: &ServerLimits) -> Self {
        let now = std::time::Instant::now();
        let deadline = limits
            .request_deadline
            .map(|t| now.checked_add(t).unwrap_or(now));
        DeadlineStream {
            inner,
            deadline,
            timeout: limits.request_deadline,
        }
    }

    /// Fail closed if the aggregate read deadline has elapsed BEFORE delegating the
    /// read.
    fn check_deadline(&self) -> io::Result<()> {
        if let Some(deadline) = self.deadline {
            if std::time::Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "aggregate request read deadline exceeded {:?} (slow-loris trickle)",
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
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// One parsed HTTP/1.1 request: the request/header block (text up to and
/// including the `\r\n\r\n` terminator) and the body bytes (the JSON-RPC
/// payload). The header block is retained so the reverse-proxy identity strategy
/// can read its trusted forwarded header; the direct-TLS path simply ignores it.
struct HttpRequest {
    /// The full header block (request line + headers + terminator), lossily
    /// decoded as UTF-8 (header bytes are ASCII in practice).
    header_block: String,
    /// The request body (the JSON-RPC payload).
    body: Vec<u8>,
}

/// Read one HTTP/1.1 request and return its header block + body bytes (the
/// JSON-RPC payload). Reads headers up to `\r\n\r\n`, honours `Content-Length`.
/// Minimal by design — single request per connection, no chunked encoding, no
/// SSE. Bounded by `limits`: the header block may not exceed `max_header_bytes`
/// and the body may not exceed `max_body_bytes` (either overflow fails closed
/// with an error rather than allocating without bound).
/// Reject malformed HTTP/1.1 header framing (issue #38) before the header block is
/// handed to the line-based parser. Enforces strict CRLF and bans obs-fold:
///   * a bare CR (not immediately followed by LF) — `str::lines()` would embed it
///     verbatim in a header value;
///   * a bare LF (not immediately preceded by CR) — `str::lines()` splits on it, so
///     it would smuggle an extra header line;
///   * an obs-fold continuation line (a line beginning with SP/HTAB after a CRLF) —
///     RFC 7230 §3.2.4 requires rejection, and the downstream parser would silently
///     drop it (a colon-less line) rather than fold it.
///
/// Fails closed with `InvalidData` so the connection is dropped, consistent with the
/// other framing guards here (oversized header / body).
fn reject_malformed_header_framing(header_bytes: &[u8]) -> io::Result<()> {
    for (i, &byte) in header_bytes.iter().enumerate() {
        match byte {
            b'\r' if header_bytes.get(i + 1) != Some(&b'\n') => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "malformed HTTP header framing: bare CR (not part of a CRLF)",
                ));
            }
            b'\n' if i == 0 || header_bytes[i - 1] != b'\r' => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "malformed HTTP header framing: bare LF (not part of a CRLF)",
                ));
            }
            b'\n' if matches!(header_bytes.get(i + 1), Some(b' ') | Some(b'\t')) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "malformed HTTP header framing: obs-fold continuation line",
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn read_http_request<S: Read>(stream: &mut S, limits: &ServerLimits) -> io::Result<HttpRequest> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];

    // Read until end-of-headers, capping total header bytes.
    let header_end = loop {
        if let Some(pos) = find_subsequence(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > limits.max_header_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP header block exceeds max_header_bytes",
            ));
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before end of HTTP headers",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    let header_bytes = &buf[..header_end];
    reject_malformed_header_framing(header_bytes)?;
    let header_block = String::from_utf8_lossy(header_bytes).into_owned();
    let content_length = parse_content_length(&header_block)?.unwrap_or(0);
    if content_length > limits.max_body_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Content-Length exceeds max_body_bytes",
        ));
    }

    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        // Defend against a Content-Length that under-states a flood of body bytes.
        if body.len() > limits.max_body_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request body exceeds max_body_bytes",
            ));
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_length);
    Ok(HttpRequest { header_block, body })
}

/// Write a minimal HTTP/1.1 JSON response carrying `body`.
///
/// Fixed `200 OK` and a fixed header set: this is the mTLS harness path, not an
/// MCP-RE serving path — see [`serve_once`]. Nothing here can carry RFC 9421
/// evidence, and no caller on the shipped proxy reaches it.
fn write_http_response<S: Write>(stream: &mut S, body: &[u8]) -> io::Result<()> {
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    Ok(())
}

/// Parse the `Content-Length` header value (case-insensitive) from a header block.
///
/// Fails closed with `InvalidData` on a duplicated `Content-Length` header (a
/// request-smuggling primitive: two lengths disagree on the body boundary) or a
/// present-but-unparseable value, consistent with the other framing guards here.
/// An absent header returns `Ok(None)` (the caller treats that as a zero-length
/// body); only present-but-malformed / conflicting lengths are rejected.
fn parse_content_length(headers: &str) -> io::Result<Option<usize>> {
    let mut seen: Option<usize> = None;
    for line in headers.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                if seen.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "malformed HTTP header framing: duplicate Content-Length",
                    ));
                }
                let parsed = value.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "malformed HTTP header framing: unparseable Content-Length",
                    )
                })?;
                seen = Some(parsed);
            }
        }
    }
    Ok(seen)
}

/// Index of the first occurrence of `needle` in `haystack`.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Load the configured offline client-certificate revocation lists (#3839) into
/// the DER form rustls' `WebPkiClientVerifier` consumes. Each path may hold one or
/// more CRLs in PEM (`-----BEGIN X509 CRL-----`) or a single raw DER CRL. Fails
/// closed: a missing or malformed CRL file is a hard startup error (`Err`) rather
/// than a silently-skipped revocation check. An empty `paths` yields an empty vec
/// (revocation checking disabled — the pre-#3839 behavior).
///
/// OFFLINE only: these bytes are read once at startup and never refreshed over the
/// network. Online OCSP / CRL-distribution-point fetching is deliberately NOT done
/// here and is deferred to a follow-up (it needs an HTTP client + a live
/// responder, which would expand the firewalled supply chain).
pub fn load_client_crls(
    paths: &[String],
) -> Result<Vec<rustls_pki_types::CertificateRevocationListDer<'static>>, String> {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::CertificateRevocationListDer;

    let mut crls: Vec<CertificateRevocationListDer<'static>> = Vec::new();
    for path in paths {
        let bytes = std::fs::read(path).map_err(|e| format!("client CRL {path}: {e}"))?;
        // Try PEM first (one file may carry several `X509 CRL` blocks). If the file
        // contains no PEM CRL block, treat the whole file as a single DER CRL.
        let pem: Vec<CertificateRevocationListDer<'static>> =
            CertificateRevocationListDer::pem_slice_iter(&bytes)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("client CRL {path}: malformed PEM: {e}"))?;
        if pem.is_empty() {
            // No PEM CRL block found → interpret the bytes as one DER CRL. Empty
            // input cannot be a valid DER CRL, so reject it (fail closed) rather
            // than load a no-op file.
            if bytes.is_empty() {
                return Err(format!("client CRL {path}: file is empty"));
            }
            crls.push(CertificateRevocationListDer::from(bytes));
        } else {
            crls.extend(pem);
        }
    }
    Ok(crls)
}

#[cfg(test)]
mod lifetime_tests {
    //! MCPS-078 (audit gap G-5): `leaf_facts` is private, so the
    //! fail-closed behaviour on an inverted validity window is exercised here,
    //! inline, over real DER minted with rcgen (mirroring the rcgen 0.14 idiom in
    //! `tests/tls_test.rs`). The caller `cert_lifetime_rejection` uses
    //! `leaf_facts(..).is_some_and(..)`; a `None` therefore
    //! fails closed (the cert is rejected), which is precisely what an
    //! inverted/degenerate span must produce.

    use super::leaf_facts;

    use rcgen::CertificateParams;
    use rcgen::ExtendedKeyUsagePurpose;
    use rcgen::KeyPair;

    /// Mint a self-signed leaf with an explicit validity window (day granularity)
    /// and return its DER bytes. Self-signed is sufficient here: the function
    /// under test only reads the validity fields, not the signature chain.
    fn mint_leaf_der(not_before: (i32, u8, u8), not_after: (i32, u8, u8)) -> Vec<u8> {
        let key = KeyPair::generate().expect("leaf key");
        let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
        params.not_before = rcgen::date_time_ymd(not_before.0, not_before.1, not_before.2);
        params.not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let cert = params.self_signed(&key).expect("leaf self-signed");
        cert.der().as_ref().to_vec()
    }

    #[test]
    fn normal_validity_window_yields_positive_span() {
        // not_before (2020) < not_after (2021): a well-formed ~1y window.
        let der = mint_leaf_der((2020, 1, 1), (2021, 1, 1));
        let span = leaf_facts(&der)
            .map(|facts| facts.not_after - facts.not_before)
            .expect("a normal cert has a parseable span");
        assert!(
            span > 0,
            "a well-formed validity window must yield a positive lifetime, got {span}"
        );
    }

    #[test]
    fn inverted_validity_window_is_none_and_fails_closed() {
        // not_after (2020) < not_before (2021): inverted/degenerate window. The
        // G-5 fix returns None so the caller's `is_some_and(|l| l <= max)` is
        // false and `cert_lifetime_rejection` fails closed (rejects the cert).
        let der = mint_leaf_der((2021, 1, 1), (2020, 1, 1));
        assert!(
            leaf_facts(&der).is_none(),
            "an inverted validity window must yield None (fail closed), not a negative span"
        );
    }

    #[test]
    fn garbage_bytes_are_none() {
        // Not a certificate at all → unparseable → None (fail closed).
        let garbage = b"this is definitely not a DER X.509 certificate";
        assert!(
            leaf_facts(garbage).is_none(),
            "unparseable bytes must yield None"
        );
    }

    #[test]
    fn routing_header_rejection_fails_closed_on_bad_headers_only() {
        // ADR-MCPS-025 rule 4 enforcement at the transport seam. Clean/absent
        // routing headers pass; a duplicate or malformed one fails closed with
        // mcp-re.transport_binding_failed bound to the request id.
        use crate::transport::RequestHeaders;
        let req = br#"{"jsonrpc":"2.0","id":"req-1","method":"tools/call"}"#;

        let clean = RequestHeaders::from_pairs([("Mcp-Method", "tools/call")]);
        assert!(super::routing_header_rejection(&clean, req).is_none());

        let duplicate = RequestHeaders::from_pairs([
            ("Mcp-Method", "tools/call"),
            ("mcp-method", "tools/list"),
        ]);
        let rejected =
            super::routing_header_rejection(&duplicate, req).expect("duplicate must reject");
        let value: serde_json::Value =
            serde_json::from_slice(&rejected).expect("json error object");
        assert_eq!(value["error"]["message"], "mcp-re.transport_binding_failed");
        assert_eq!(value["id"], "req-1");

        let malformed = RequestHeaders::from_pairs([("Mcp-Name", "echo\r\nX-Spoof: evil")]);
        assert!(super::routing_header_rejection(&malformed, req).is_some());
    }

    #[test]
    fn absent_leaf_is_rejected_when_a_lifetime_ceiling_is_configured() {
        // C095: the ceiling is a check on the peer certificate, so "there is no peer
        // certificate to check" must not be an admission. This is the ONE case that
        // used to short-circuit to `None` (= admit) one line before an unparseable
        // cert failed closed. Negative control: restore `let leaf = leaf_der?;` and
        // this asserts `Some(..)` on a `None`.
        let req = br#"{"jsonrpc":"2.0","id":"req-7","method":"tools/call"}"#;
        let options = super::ServerOptions {
            max_client_cert_lifetime: Some(std::time::Duration::from_secs(3600)),
            ..Default::default()
        };
        let rejected = super::cert_lifetime_rejection_for_chain(&[], &options, req, 0)
            .expect("an absent leaf must be rejected when a ceiling is configured");
        let value: serde_json::Value =
            serde_json::from_slice(&rejected).expect("json error object");
        assert_eq!(value["error"]["message"], "mcp-re.transport_binding_failed");
        assert_eq!(value["id"], "req-7", "the rejection binds the request id");
    }

    #[test]
    fn absent_leaf_is_admitted_only_when_no_ceiling_is_configured() {
        // The converse, so the fix above cannot be read as "always reject a missing
        // leaf": with the check DISABLED there is nothing to enforce, and this
        // function is not the mandatory-client-auth gate (rustls' verifier is).
        let req = br#"{"jsonrpc":"2.0","id":"req-8","method":"tools/call"}"#;
        let options = super::ServerOptions {
            max_client_cert_lifetime: None,
            ..Default::default()
        };
        assert!(
            super::cert_lifetime_rejection_for_chain(&[], &options, req, 0).is_none(),
            "with no ceiling configured there is no lifetime decision to make"
        );
    }

    #[test]
    fn within_limit_leaf_is_admitted_and_over_long_leaf_is_rejected() {
        // Pins the two ordinary outcomes THROUGH the same entry point the absent-leaf
        // cases use, so the fail-closed rewrite is shown not to have broken admission.
        let req = br#"{"jsonrpc":"2.0","id":"req-9","method":"tools/call"}"#;
        let options = super::ServerOptions {
            max_client_cert_lifetime: Some(std::time::Duration::from_secs(3600)),
            ..Default::default()
        };
        // ~1 year span — far over a 1h ceiling.
        let long = mint_leaf_der((2020, 1, 1), (2021, 1, 1));
        assert!(
            super::cert_lifetime_rejection_for_chain(&[&long], &options, req, IN_2020).is_some(),
            "a 1-year cert must be rejected under a 1-hour ceiling"
        );
        // Day granularity is the coarsest this fixture mints, so admit-side coverage
        // uses a ceiling wide enough for a 1-day span.
        let generous = super::ServerOptions {
            max_client_cert_lifetime: Some(std::time::Duration::from_secs(48 * 3600)),
            ..Default::default()
        };
        let short = mint_leaf_der((2020, 1, 1), (2020, 1, 2));
        assert!(
            super::cert_lifetime_rejection_for_chain(&[&short], &generous, req, IN_2020).is_none(),
            "a 1-day cert must be admitted under a 2-day ceiling"
        );
    }

    /// 2020-01-01T01:00:00Z — inside the `mint_leaf_der((2020,1,1), (2020,1,2))`
    /// window used by the admit-side fixtures.
    const IN_2020: i64 = 1_577_836_800 + 3600;

    #[test]
    fn a_leaf_past_not_after_is_rejected_however_short_its_span() {
        // The SPAN check alone admits this forever: a 1-day certificate satisfies a
        // 2-day ceiling in 2020 and equally in 2030. On a keep-alive or HTTP/2
        // connection the leaf is captured once at handshake, so this per-request
        // clock comparison is the only thing that ever notices the expiry.
        let req = br#"{"jsonrpc":"2.0","id":"req-10","method":"tools/call"}"#;
        let options = super::ServerOptions {
            max_client_cert_lifetime: Some(std::time::Duration::from_secs(48 * 3600)),
            ..Default::default()
        };
        let short = mint_leaf_der((2020, 1, 1), (2020, 1, 2));
        assert!(
            super::cert_lifetime_rejection_for_chain(&[&short], &options, req, IN_2020).is_none(),
            "inside its validity window the cert is admitted"
        );
        // One day later — same certificate, same span, same ceiling.
        assert!(
            super::cert_lifetime_rejection_for_chain(&[&short], &options, req, IN_2020 + 86_400)
                .is_some(),
            "past not_after the cert must be refused even though its span is small"
        );
        // And before it is valid.
        assert!(
            super::cert_lifetime_rejection_for_chain(&[&short], &options, req, IN_2020 - 86_400)
                .is_some(),
            "before not_before the cert must be refused"
        );
    }

    #[test]
    fn zero_length_validity_window_is_none_and_fails_closed() {
        // not_after == not_before: a DEGENERATE (zero-length) window. Without the
        // `<=` guard this returned Some(0), which `cert_lifetime_rejection` treats
        // as within ANY max lifetime — admitting a useless instant-lifetime cert.
        // The fix fails closed (None) for the degenerate span too, matching the
        // documented "negative OR degenerate span is rejected" contract.
        let der = mint_leaf_der((2021, 1, 1), (2021, 1, 1));
        assert!(
            leaf_facts(&der).is_none(),
            "a zero-length validity window must yield None (fail closed)"
        );
    }
}

#[cfg(test)]
mod identity_parity_tests {
    //! M23 (audit 0.2, MCP-RE-MED-7 / #4080): cross-strategy identity PARITY.
    //!
    //! The SAME verified client certificate must resolve to the SAME identity
    //! string under a given [`IdentityPolicy`] REGARDLESS of whether the cert was
    //! terminated locally (direct-TLS, [`extract_identity`]) or upstream and
    //! forwarded in an Envoy XFCC `Subject=` field (the [`ReverseProxyMtlsProvider`]).
    //! Before the fix, the direct-TLS `CnLegacy` path extracted only the CN
    //! (`agent-1`) while the XFCC `Subject=` path yielded the full RFC2253 DN
    //! (`CN=agent-1,OU=agents,O=example`) — so one `IdentityPolicy` resolved two
    //! different identities for the same cert, and the ExactMatch / Mapped binding
    //! could not be configured to admit both transports with one signer mapping.
    //!
    //! These are black-box tests over the two PUBLIC extraction paths: they mint a
    //! real cert (rcgen), read its identity via the direct-TLS path, build the XFCC
    //! header the way Envoy would (`Subject="<full DN>"`), read it via the
    //! reverse-proxy path, and assert the resolved identity strings are EQUAL.

    use super::extract_identity;

    use crate::transport::IdentityPolicy;
    use crate::transport::IdentitySource;
    use crate::transport::RequestHeaders;
    use crate::transport::ReverseProxyHeaderFormat;
    use crate::transport::ReverseProxyMtlsProvider;
    use crate::transport::TransportBindingProvider;

    use rcgen::CertificateParams;
    use rcgen::DnType;
    use rcgen::ExtendedKeyUsagePurpose;
    use rcgen::KeyPair;

    /// Mint a self-signed client leaf whose subject carries the given CN, OU and O,
    /// plus a URI SAN and a DNS SAN. Returns `(der, rfc2253_subject_dn)` where the
    /// DN string is the Envoy-style `CN=..,OU=..,O=..` rendering an upstream proxy
    /// would put in the XFCC `Subject=` field.
    fn mint_client_leaf() -> (Vec<u8>, String) {
        let key = KeyPair::generate().expect("leaf key");
        let mut params =
            CertificateParams::new(vec!["agent-1.example.org".to_string()]).expect("leaf params");
        params
            .distinguished_name
            .push(DnType::CommonName, "agent-1");
        params
            .distinguished_name
            .push(DnType::OrganizationalUnitName, "agents");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "example");
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let cert = params.self_signed(&key).expect("leaf self-signed");
        // The RFC2253 DN as a reverse-proxy would forward it in `Subject=`.
        let subject_dn = "CN=agent-1,OU=agents,O=example".to_string();
        (cert.der().as_ref().to_vec(), subject_dn)
    }

    /// Build the XFCC reverse-proxy identity for the given full Subject DN under the
    /// given policy (Envoy quotes a DN because it contains commas).
    fn xfcc_identity(subject_dn: &str, policy: IdentityPolicy) -> Option<String> {
        let provider = ReverseProxyMtlsProvider::new(
            "x-forwarded-client-cert",
            ReverseProxyHeaderFormat::Xfcc,
            policy,
        );
        let header = format!("Hash=abc;Subject=\"{subject_dn}\"");
        let req = RequestHeaders::from_pairs([("x-forwarded-client-cert", header)]);
        provider.verified_identity(&req).map(|id| id.value)
    }

    #[test]
    fn cn_legacy_identity_is_equal_across_direct_tls_and_xfcc() {
        // THE PARITY ASSERTION (M23): the SAME cert, the SAME CnLegacy policy, must
        // yield the SAME identity string whether terminated locally or forwarded as
        // an XFCC Subject DN. Direct-TLS extracts the CN; the XFCC path must extract
        // the CN out of the Subject DN too — not the whole DN.
        let (der, subject_dn) = mint_client_leaf();

        let direct = extract_identity(&der, IdentityPolicy::CnLegacy)
            .expect("direct-TLS CnLegacy must extract the CN");
        assert_eq!(direct.source, IdentitySource::CommonName);

        let xfcc = xfcc_identity(&subject_dn, IdentityPolicy::CnLegacy)
            .expect("XFCC CnLegacy must extract an identity from the Subject DN");

        assert_eq!(
            direct.value, xfcc,
            "the SAME cert under CnLegacy must resolve to the SAME identity via \
             direct-TLS and via the XFCC Subject DN (got direct={:?}, xfcc={:?})",
            direct.value, xfcc
        );
        // And concretely: both are the bare CN, not the full DN.
        assert_eq!(direct.value, "agent-1");
        assert_eq!(xfcc, "agent-1");
    }

    #[test]
    fn explicit_cn_field_still_equals_direct_tls_cn() {
        // An upstream that forwards an explicit `CN=` pair (rather than a full
        // `Subject=` DN) must agree with the direct-TLS CN too.
        let (der, _dn) = mint_client_leaf();
        let direct = extract_identity(&der, IdentityPolicy::CnLegacy)
            .expect("direct-TLS CnLegacy CN")
            .value;

        let provider = ReverseProxyMtlsProvider::new(
            "x-forwarded-client-cert",
            ReverseProxyHeaderFormat::Xfcc,
            IdentityPolicy::CnLegacy,
        );
        let req = RequestHeaders::from_pairs([("x-forwarded-client-cert", "Hash=abc;CN=agent-1")]);
        let xfcc = provider
            .verified_identity(&req)
            .expect("explicit CN pair")
            .value;
        assert_eq!(
            direct, xfcc,
            "explicit XFCC CN must equal the direct-TLS CN"
        );
    }

    // --- issue #38: obs-fold / bare-CR / bare-LF header framing must fail closed ---

    fn read_req(bytes: &[u8]) -> std::io::Result<super::HttpRequest> {
        super::read_http_request(
            &mut std::io::Cursor::new(bytes.to_vec()),
            &super::ServerLimits::default(),
        )
    }

    #[test]
    fn obs_fold_continuation_line_is_rejected() {
        // RFC 7230 §3.2.4: an obs-fold continuation (line starting with SP/HTAB)
        // must be rejected, not silently dropped by the downstream line parser.
        let block = b"POST /mcp HTTP/1.1\r\nMcp-Name: good\r\n\tinjected\r\n\r\n";
        assert!(
            read_req(block).is_err(),
            "an obs-fold continuation line must fail closed"
        );
    }

    #[test]
    fn bare_cr_in_header_section_is_rejected() {
        // A bare CR (not part of a CRLF) must be rejected rather than embedded
        // verbatim in a header value by `str::lines()`.
        let block = b"POST /mcp HTTP/1.1\r\nMcp-Name: good\rinjected\r\n\r\n";
        assert!(read_req(block).is_err(), "a bare CR must fail closed");
    }

    #[test]
    fn bare_lf_line_ending_is_rejected() {
        // A bare LF line ending (not CRLF) must be rejected — `str::lines()` splits
        // on it, so a bare LF would otherwise smuggle an extra header line.
        let block = b"POST /mcp HTTP/1.1\nMcp-Name: good\r\n\r\n";
        assert!(
            read_req(block).is_err(),
            "a bare LF line ending must fail closed"
        );
    }

    #[test]
    fn well_formed_strict_crlf_request_is_accepted() {
        // Regression: a clean CRLF-framed request still parses, and its headers are
        // intact (the framing guard must not reject well-formed input).
        let block = b"POST /mcp HTTP/1.1\r\nMcp-Name: good\r\n\r\n";
        let req = read_req(block).expect("a well-formed CRLF request must be accepted");
        let headers = crate::transport::RequestHeaders::parse(&req.header_block);
        assert_eq!(headers.first("mcp-name"), Some("good"));
    }
}

#[cfg(test)]
mod aggregate_deadline_tests {
    //! Issue #100: the server read path's AGGREGATE wall-clock deadline
    //! (`DeadlineStream`) must fail closed when a peer trickles bytes just under
    //! the per-read timeout but past the aggregate budget (slow-loris), the
    //! server-side mirror of mcp-re-transport's `DeadlineStream` (MCPS-094/093).
    //!
    //! Hermetic and fast: a `TricklingReader` always makes per-read progress (so
    //! the per-socket `read_timeout`/zero-byte-stall guard NEVER fires) but never
    //! completes the header block, so only the aggregate deadline can stop it.

    use std::io;
    use std::io::Read;
    use std::time::Duration;
    use std::time::Instant;

    use super::DeadlineStream;
    use super::ServerLimits;

    /// A reader that always returns exactly one byte per `read` (never 0, never an
    /// error) and never emits the `\r\n\r\n` header terminator — modelling a peer
    /// that keeps the per-read inactivity timer alive forever while never finishing
    /// the request. Optionally sleeps per read to model a real trickle rate without
    /// making the test slow.
    struct TricklingReader {
        per_read_sleep: Duration,
    }

    impl Read for TricklingReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            // A zero-length buffer is legal per the `Read` contract; return
            // `Ok(0)` before touching `buf[0]` so we never panic.
            if buf.is_empty() {
                return Ok(0);
            }
            if !self.per_read_sleep.is_zero() {
                std::thread::sleep(self.per_read_sleep);
            }
            // A non-terminator byte: progress is always made, so a per-read-only
            // guard can never cut this off.
            buf[0] = b'A';
            Ok(1)
        }
    }

    #[test]
    fn aggregate_deadline_fires_on_sub_per_read_trickle() {
        // Small aggregate budget; the per-read sleep is well UNDER it, so each
        // individual read "succeeds" and only the aggregate deadline can stop the
        // header read. Without the wrapper, `read_http_request` would loop forever.
        let limits = ServerLimits {
            // Per-read timeout disabled to prove the AGGREGATE bound (not the
            // per-socket timeout) is what fails closed.
            read_timeout: None,
            request_deadline: Some(Duration::from_millis(150)),
            ..ServerLimits::default()
        };
        let mut stream = DeadlineStream::new(
            TricklingReader {
                per_read_sleep: Duration::from_millis(5),
            },
            &limits,
        );

        let start = Instant::now();
        let result = super::read_http_request(&mut stream, &limits);
        let elapsed = start.elapsed();

        let err = match result {
            Ok(_) => panic!("a sub-per-read trickle past the aggregate deadline must fail closed"),
            Err(e) => e,
        };
        assert_eq!(
            err.kind(),
            io::ErrorKind::TimedOut,
            "the aggregate read deadline must surface as TimedOut (fail closed), got: {err}"
        );
        // It must be cut off PROMPTLY after the deadline, not hang. Generous upper
        // bound to stay non-flaky on a loaded CI host.
        assert!(
            elapsed < Duration::from_secs(5),
            "the connection must be dropped promptly at the aggregate deadline, took {elapsed:?}"
        );
    }

    #[test]
    fn disabled_deadline_does_not_cut_off_a_completing_read() {
        // `request_deadline: None` disables the aggregate bound; a reader that DOES
        // complete the request must still parse cleanly (the wrapper is transparent
        // when the deadline is off).
        let limits = ServerLimits {
            request_deadline: None,
            ..ServerLimits::default()
        };
        let body = b"POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n".to_vec();
        let mut stream = DeadlineStream::new(io::Cursor::new(body), &limits);
        let req = super::read_http_request(&mut stream, &limits)
            .expect("a complete request must parse when the aggregate deadline is disabled");
        assert!(req.body.is_empty());
    }
}

#[cfg(test)]
mod content_length_framing_tests {
    //! Audit LOW (ledger `84224733b1228db8`): a duplicated or unparseable
    //! `Content-Length` must fail closed with `InvalidData` rather than silently
    //! collapsing to a zero-length body. Two disagreeing lengths are a classic
    //! request-smuggling primitive; every sibling duplicate-header guard here
    //! already rejects, so this one must too.

    use std::io;

    use super::read_http_request;
    use super::ServerLimits;

    fn read(raw: &[u8]) -> io::Result<super::HttpRequest> {
        let mut stream = io::Cursor::new(raw.to_vec());
        read_http_request(&mut stream, &ServerLimits::default())
    }

    // `HttpRequest` intentionally has no `Debug`, so assert the error arm by hand
    // rather than via `expect_err`.
    fn assert_invalid_data(raw: &[u8], why: &str) {
        match read(raw) {
            Ok(_) => panic!("{why}"),
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{why}: {e}"),
        }
    }

    #[test]
    fn duplicate_content_length_is_rejected() {
        // Two Content-Length lines that disagree on the body boundary: the smuggling
        // case. Must fail closed rather than pick one (first-wins) silently.
        let raw = b"POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 0\r\n\r\nhello";
        assert_invalid_data(raw, "duplicate Content-Length must fail closed");
    }

    #[test]
    fn duplicate_content_length_same_value_is_still_rejected() {
        // Even agreeing duplicates are rejected — the strict, uniform posture (no
        // "are they equal" special-case that a smuggler could probe).
        let raw = b"POST / HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n";
        assert_invalid_data(raw, "any duplicate Content-Length must fail closed");
    }

    #[test]
    fn unparseable_content_length_is_rejected() {
        let raw = b"POST / HTTP/1.1\r\nContent-Length: not-a-number\r\n\r\n";
        assert_invalid_data(raw, "unparseable Content-Length must fail closed");
    }

    #[test]
    fn negative_content_length_is_rejected() {
        // `usize` parse rejects the sign; previously this collapsed to 0.
        let raw = b"POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n";
        assert_invalid_data(raw, "negative Content-Length must fail closed");
    }

    #[test]
    fn absent_content_length_is_a_zero_length_body() {
        // Absent (not present-but-malformed) stays permissive: zero-length body.
        let raw = b"POST / HTTP/1.1\r\n\r\n";
        let req = read(raw).expect("absent Content-Length is a well-formed empty body");
        assert!(req.body.is_empty());
    }

    #[test]
    fn single_valid_content_length_parses() {
        let raw = b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        let req = read(raw).expect("a single valid Content-Length must parse");
        assert_eq!(req.body, b"hello");
    }
}

/// MCPS-079 fault-injection module ("test of the tests"), the symmetric mirror of
/// mcp-re-transport's `fault_accept_any` (server-side). Compiled ONLY under the
/// `fault_accept_any_client` feature, which is off by default and never enabled by
/// production targets or the default `bazel test //...`. It re-introduces the
/// `AcceptAnyClient` anti-pattern the verifying proxy was built to eliminate, so
/// the periodic fault-injection harness can prove the proxy's client-cert
/// rejection guards (the more important boundary — the proxy guards the inner)
/// would FAIL if the control were broken.
#[cfg(feature = "fault_accept_any_client")]
mod fault_accept_any {
    use std::sync::Arc;

    use rustls::client::danger::HandshakeSignatureValid;
    use rustls::crypto::verify_tls12_signature;
    use rustls::crypto::verify_tls13_signature;
    use rustls::crypto::CryptoProvider;
    use rustls::server::danger::ClientCertVerified;
    use rustls::server::danger::ClientCertVerifier;
    use rustls::DigitallySignedStruct;
    use rustls::DistinguishedName;
    use rustls::Error as RustlsError;
    use rustls::SignatureScheme;
    use rustls_pki_types::CertificateDer;
    use rustls_pki_types::UnixTime;

    /// A client-certificate verifier that accepts ANY client certificate: any CA,
    /// any identity, any validity window — and, via the `client_auth_mandatory`
    /// override, also accepts a connection that presents NO client certificate at
    /// all. Handshake SIGNATURES are still checked via the crypto provider (so the
    /// TLS handshake completes against a real client) — only the trust/identity/
    /// expiry decision is neutered. This is the exact shape of the control break
    /// the proxy's client-auth tests exist to catch.
    #[derive(Debug)]
    pub struct AcceptAnyClientVerifier {
        provider: Arc<CryptoProvider>,
    }

    impl AcceptAnyClientVerifier {
        pub fn new(provider: Arc<CryptoProvider>) -> Self {
            AcceptAnyClientVerifier { provider }
        }
    }

    impl ClientCertVerifier for AcceptAnyClientVerifier {
        fn verify_client_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _now: UnixTime,
        ) -> Result<ClientCertVerified, RustlsError> {
            // THE BREAK: trust, identity, and expiry are never checked.
            Ok(ClientCertVerified::assertion())
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

        fn root_hint_subjects(&self) -> &[DistinguishedName] {
            // No trust anchors are advertised — the faulted verifier ignores trust
            // entirely, so there are no issuer hints to send to the client.
            &[]
        }

        fn client_auth_mandatory(&self) -> bool {
            // THE SECOND BREAK: a client certificate is no longer required. This is
            // what flips T1 (`missing_client_certificate_is_rejected`): with this
            // returning `false`, a connection presenting NO client cert completes
            // the handshake instead of being rejected. T2
            // (`untrusted_client_certificate_is_rejected`) flips via
            // `verify_client_cert` above accepting any presented cert.
            false
        }
    }
}

#[cfg(test)]
mod resumption_state_tests {
    //! ADR-MCPRE-055: the TLS session cache and the trust epoch belong to the LISTENER,
    //! not to one `ServerConfig`.
    //!
    //! Both properties below are invisible from outside a rebuild, which is why they are
    //! asserted here over real `ServerConfig`s rather than over the store's synthetic
    //! contract (`tls_auth_epoch`'s own tests do that): the defect they catch is a
    //! resumption state constructed INSIDE the builder, which reads correctly in
    //! isolation and empties the cache — and freezes the epoch — on every CRL reload.

    use super::*;
    use rcgen::CertificateParams;
    use rcgen::KeyPair;
    use rustls::server::ProducesTickets;

    fn ca_der() -> CertificateDer<'static> {
        let key = KeyPair::generate().expect("ca key");
        let mut params = CertificateParams::new(Vec::new()).expect("ca params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "resumption-test-ca");
        params.self_signed(&key).expect("ca").der().clone()
    }

    fn server_credential() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let key = KeyPair::generate().expect("server key");
        let params = CertificateParams::new(vec!["localhost".to_string()]).expect("params");
        let cert = params.self_signed(&key).expect("server cert");
        (
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(
                key.serialize_der(),
            )),
        )
    }

    fn build(
        client_ca: Vec<CertificateDer<'static>>,
        resumption: &Arc<crate::tls_auth_epoch::EpochBoundSessionStore>,
    ) -> ServerConfig {
        let (chain, key) = server_credential();
        RustlsDirectProvider::build_server_config_with_crls_resuming(
            chain,
            key,
            client_ca,
            Vec::new(),
            false,
            resumption,
        )
        .expect("server config")
    }

    /// A rebuild with unchanged trust keeps every resumable session.
    ///
    /// The broken implementation this catches: `epoch_bound_resumption` installing a
    /// fresh `ServerSessionMemoryCache` per build, so `--client-crl-reload-secs` throws
    /// the whole fleet's resumption state away on its cadence and every peer pays a full
    /// handshake — the cost ADR-MCPRE-055 exists to avoid.
    #[test]
    fn a_crl_reload_does_not_empty_the_session_cache() {
        let ca = ca_der();
        let resumption = new_resumption_state(std::slice::from_ref(&ca), false);
        let before = build(vec![ca.clone()], &resumption);
        assert!(before
            .session_storage
            .put(b"ticket".to_vec(), b"session".to_vec()));
        // Exactly what `TlsKeyMaterial::rebuild` does on the reload cadence: same
        // anchors, same resumption state, a brand-new ServerConfig.
        let after = build(vec![ca], &resumption);
        assert_eq!(
            after.session_storage.take(b"ticket"),
            Some(b"session".to_vec()),
            "a reload must not discard the sessions the fleet already established"
        );
    }

    /// A rebuild whose trusted client CAs CHANGED advances the epoch, and the sessions
    /// stored under the withdrawn trust stop being shortcuts.
    ///
    /// The broken implementation this catches: an epoch constructed inside the builder
    /// and never republished, which leaves `SharedTlsAuthEpoch::store` with no production
    /// caller at all — the epoch becomes a constant tag and TB-06's mismatch eviction can
    /// never fire.
    #[test]
    fn a_rebuild_with_a_withdrawn_client_ca_advances_the_epoch() {
        let original = ca_der();
        let replacement = ca_der();
        let resumption = new_resumption_state(std::slice::from_ref(&original), false);
        let original_again = original.clone();
        let before = build(vec![original], &resumption);
        let epoch_before = *resumption.epoch();
        assert!(before
            .session_storage
            .put(b"ticket".to_vec(), b"session".to_vec()));

        let after = build(vec![replacement], &resumption);
        assert_ne!(
            epoch_before,
            *resumption.epoch(),
            "withdrawing the trusted client CA must move the epoch"
        );
        // `None` here only means something because the cache SURVIVES a rebuild: the
        // companion test proves an unchanged rebuild still returns this ticket, so the
        // absence below is the epoch mismatch and not an emptied cache.
        assert_eq!(
            after.session_storage.get(b"ticket"),
            None,
            "a session stored under withdrawn trust must stop resuming"
        );
        // And it was EVICTED, not merely refused: restoring the original trust must not
        // resurrect it.
        build(vec![original_again], &resumption);
        assert_eq!(
            after.session_storage.get(b"ticket"),
            None,
            "the stale entry was not evicted"
        );
    }

    /// A built config resumes ONLY through the epoch-tagged session store.
    ///
    /// rustls has a second, independent resumption mechanism: an enabled ticketer makes
    /// the server resume straight out of the client's encrypted ticket and never consult
    /// `session_storage` at all (`attempt_tls13_ticket_decryption`), which bypasses the
    /// epoch tag, the mismatch eviction, and both properties asserted above — while the
    /// startup line still reports epoch-bound resumption.
    #[test]
    fn a_built_config_issues_no_stateless_session_tickets() {
        let ca = ca_der();
        let resumption = new_resumption_state(std::slice::from_ref(&ca), false);
        let config = build(vec![ca], &resumption);
        assert!(
            !config.ticketer.enabled(),
            "an enabled ticketer resumes without consulting the epoch-tagged store"
        );
        assert_eq!(config.ticketer.encrypt(b"session"), None);
        assert_eq!(config.ticketer.decrypt(b"ticket"), None);
    }

    /// The installed ticketer refuses through every method, not only the flag rustls
    /// reads, so a caller driving it directly cannot mint or accept a ticket either.
    #[test]
    fn the_installed_ticketer_refuses_through_every_method() {
        let ticketer = NoStatelessTickets;
        assert!(!ticketer.enabled());
        assert_eq!(ticketer.lifetime(), 0);
        assert_eq!(ticketer.encrypt(b"session"), None);
        assert_eq!(ticketer.decrypt(b"ticket"), None);
    }
}

#[cfg(test)]
mod chain_validity_tests {
    //! ADR-MCPRE-055: a resumed TLS 1.3 handshake restores the stored peer chain and
    //! skips chain building, so the per-request gate is the only place an INTERMEDIATE's
    //! expiry is ever re-read. The trust epoch cannot cover it — the epoch digests the
    //! configured anchor set, and an intermediate is not in it.

    use super::*;
    use rcgen::BasicConstraints;
    use rcgen::CertificateParams;
    use rcgen::DnType;
    use rcgen::IsCa;
    use rcgen::KeyPair;
    use rcgen::KeyUsagePurpose;

    struct Signer {
        params: CertificateParams,
        key: KeyPair,
        der: CertificateDer<'static>,
    }

    impl Signer {
        fn issuer(&self) -> rcgen::Issuer<'_, &KeyPair> {
            rcgen::Issuer::from_params(&self.params, &self.key)
        }
    }

    fn root(name: &str) -> Signer {
        let key = KeyPair::generate().expect("root key");
        let mut params = CertificateParams::new(Vec::new()).expect("root params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.distinguished_name.push(DnType::CommonName, name);
        let der = params.self_signed(&key).expect("root").der().clone();
        Signer { params, key, der }
    }

    /// A CA signed by `issuer` with an explicit validity window, so its expiry is a
    /// deterministic input rather than a wall-clock accident.
    fn intermediate(issuer: &Signer, name: &str, not_after: (i32, u8, u8)) -> Signer {
        let key = KeyPair::generate().expect("intermediate key");
        let mut params = CertificateParams::new(Vec::new()).expect("intermediate params");
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.distinguished_name.push(DnType::CommonName, name);
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2);
        let der = params
            .signed_by(&key, &issuer.issuer())
            .expect("intermediate")
            .der()
            .clone();
        Signer { params, key, der }
    }

    fn leaf(issuer: &Signer) -> CertificateDer<'static> {
        let key = KeyPair::generate().expect("leaf key");
        let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
        params.distinguished_name.push(DnType::CommonName, "peer");
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2999, 1, 1);
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        params
            .signed_by(&key, &issuer.issuer())
            .expect("leaf")
            .der()
            .clone()
    }

    /// The gate runs whenever any per-request certificate control is configured; a
    /// lifetime ceiling wide enough to admit the leaf isolates the chain decision.
    fn options() -> ServerOptions {
        ServerOptions {
            max_client_cert_lifetime: Some(Duration::from_secs(365 * 24 * 3600 * 1000)),
            ..Default::default()
        }
    }

    const NOW: i64 = 1_800_000_000; // 2027-01-15

    fn rejected(chain: &[&[u8]]) -> bool {
        cert_lifetime_rejection_for_chain(chain, &options(), b"{\"id\":1}", NOW).is_some()
    }

    /// A leaf under a still-valid intermediate is served.
    #[test]
    fn a_chain_whose_intermediate_is_current_is_admitted() {
        let root = root("chain-root");
        let ica = intermediate(&root, "chain-ica", (2999, 1, 1));
        let peer = leaf(&ica);
        assert!(!rejected(&[peer.as_ref(), ica.der.as_ref()]));
    }

    /// A leaf under an EXPIRED intermediate is refused, even though the leaf itself is
    /// current, un-revoked and within the lifetime ceiling.
    ///
    /// The broken implementation this catches: applying `within_window` to `chain[0]`
    /// only. With resumption enabled the peer never re-runs chain building, so every
    /// reconnect restores the same expired chain and keeps being admitted.
    #[test]
    fn a_chain_whose_intermediate_has_expired_is_refused() {
        let root = root("chain-root");
        let ica = intermediate(&root, "chain-ica", (2021, 1, 1));
        let peer = leaf(&ica);
        assert!(
            rejected(&[peer.as_ref(), ica.der.as_ref()]),
            "an expired issuing intermediate must stop the leaf being served"
        );
    }

    /// A peer that redundantly sends its (self-issued) root is NOT refused on that
    /// root's window. Path building matches a root against the configured anchor set
    /// rather than against its own validity, so refusing it here would refuse chains a
    /// full handshake admits.
    #[test]
    fn a_self_issued_root_in_the_presented_chain_is_not_held_to_a_window() {
        let root = root("chain-root");
        let ica = intermediate(&root, "chain-ica", (2999, 1, 1));
        let peer = leaf(&ica);
        assert!(!rejected(&[
            peer.as_ref(),
            ica.der.as_ref(),
            root.der.as_ref()
        ]));
    }

    /// An unparseable certificate above the leaf fails closed, matching the leaf.
    #[test]
    fn an_unparseable_intermediate_is_refused() {
        let root = root("chain-root");
        let ica = intermediate(&root, "chain-ica", (2999, 1, 1));
        let peer = leaf(&ica);
        assert!(rejected(&[peer.as_ref(), b"not der".as_ref()]));
    }
}

#[cfg(test)]
mod per_request_revocation_tests {
    //! The per-request CRL consultation in [`cert_lifetime_rejection_for_chain`] is the
    //! ONLY way a revocation reaches a peer that already holds a connection: rustls runs
    //! client authentication on a full handshake only, and the trust epoch deliberately
    //! digests the anchor set and the client-auth policy — not the CRLs — so a revocation
    //! published after the handshake moves nothing the epoch can see.
    //!
    //! The certificates here are real and signed, and the CRLs are real and signed, so
    //! the (issuer `Name` DER, serial) coordinate the index is keyed by is the one the
    //! serving path actually extracts rather than a synthetic pair.

    use super::*;
    use crate::client_revocation::ClientRevocationIndex;
    use crate::client_revocation::SharedClientRevocation;
    use rcgen::BasicConstraints;
    use rcgen::CertificateParams;
    use rcgen::CertificateRevocationListParams;
    use rcgen::DnType;
    use rcgen::IsCa;
    use rcgen::KeyPair;
    use rcgen::KeyUsagePurpose;
    use rcgen::RevocationReason;
    use rcgen::RevokedCertParams;
    use rcgen::SerialNumber;

    /// 2027-01-15 — inside every window minted below, and before the CRLs' `nextUpdate`.
    const NOW: i64 = 1_800_000_000;
    const LEAF_SERIAL: u64 = 0x2a;
    const ICA_SERIAL: u64 = 0x2b;

    struct Ca {
        params: CertificateParams,
        key: KeyPair,
        der: CertificateDer<'static>,
    }

    impl Ca {
        fn issuer(&self) -> rcgen::Issuer<'_, &KeyPair> {
            rcgen::Issuer::from_params(&self.params, &self.key)
        }
    }

    fn ca_params(name: &str, constraints: BasicConstraints) -> CertificateParams {
        let mut params = CertificateParams::new(Vec::new()).expect("ca params");
        params.is_ca = IsCa::Ca(constraints);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.distinguished_name.push(DnType::CommonName, name);
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2035, 1, 1);
        params
    }

    fn root(name: &str) -> Ca {
        let key = KeyPair::generate().expect("root key");
        let params = ca_params(name, BasicConstraints::Unconstrained);
        let der = params.self_signed(&key).expect("root").der().clone();
        Ca { params, key, der }
    }

    /// A CA signed by `issuer` carrying an explicit serial, so `issuer`'s CRL can name
    /// exactly this intermediate.
    fn intermediate(issuer: &Ca, name: &str, serial: u64) -> Ca {
        let key = KeyPair::generate().expect("intermediate key");
        let mut params = ca_params(name, BasicConstraints::Constrained(0));
        params.serial_number = Some(SerialNumber::from(serial));
        let der = params
            .signed_by(&key, &issuer.issuer())
            .expect("intermediate")
            .der()
            .clone();
        Ca { params, key, der }
    }

    /// A client leaf with an explicit serial, so a CRL can revoke exactly this
    /// certificate.
    fn leaf(issuer: &Ca, serial: u64) -> CertificateDer<'static> {
        let key = KeyPair::generate().expect("leaf key");
        let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
        params.distinguished_name.push(DnType::CommonName, "peer");
        params.serial_number = Some(SerialNumber::from(serial));
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2035, 1, 1);
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        params
            .signed_by(&key, &issuer.issuer())
            .expect("leaf")
            .der()
            .clone()
    }

    /// A signed CRL from `ca` revoking each serial in `revoked`. An empty list is the
    /// "issuer covered, nothing revoked" state a deployment runs in most of the time.
    fn crl(ca: &Ca, revoked: &[u64], next_update: (i32, u8, u8)) -> Vec<u8> {
        let params = CertificateRevocationListParams {
            this_update: rcgen::date_time_ymd(2020, 1, 1),
            next_update: rcgen::date_time_ymd(next_update.0, next_update.1, next_update.2),
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
        params.signed_by(&ca.issuer()).expect("crl").der().to_vec()
    }

    fn shared(crls: &[Vec<u8>]) -> Arc<SharedClientRevocation> {
        Arc::new(SharedClientRevocation::new(
            ClientRevocationIndex::from_crl_ders(crls, false).expect("index builds"),
        ))
    }

    /// No lifetime ceiling: revocation ALONE must arm the per-request gate, and nothing
    /// else here can account for a refusal.
    fn options(revocation: &Arc<SharedClientRevocation>) -> ServerOptions {
        ServerOptions {
            client_revocation: Some(Arc::clone(revocation)),
            ..Default::default()
        }
    }

    fn rejected(chain: &[&[u8]], options: &ServerOptions) -> bool {
        cert_lifetime_rejection_for_chain(chain, options, b"{\"id\":1}", NOW).is_some()
    }

    /// A leaf whose issuer is covered by a CRL that does not list it keeps being served.
    ///
    /// This is the control every refusal below is read against, and it is also what
    /// catches the (issuer, serial) coordinate being passed in the wrong order: the
    /// swapped call finds no CRL for the "issuer" it was handed, answers `Unknown`, and
    /// refuses this request under the deny-unknown policy.
    #[test]
    fn a_leaf_a_current_crl_does_not_list_is_served() {
        let ca = root("revocation-ca");
        let peer = leaf(&ca, LEAF_SERIAL);
        let revocation = shared(&[crl(&ca, &[], (2035, 1, 1))]);
        assert!(!rejected(&[peer.as_ref()], &options(&revocation)));
    }

    /// A leaf listed on a CRL in force is refused on every request, with no lifetime
    /// ceiling configured at all.
    ///
    /// The broken implementation this catches: dropping the `not_revoked` conjunct, or
    /// arming the gate on `max_client_cert_lifetime` alone — either leaves a revoked peer
    /// serving on the connection it already holds for as long as it holds it.
    #[test]
    fn a_leaf_on_a_current_crl_is_refused() {
        let ca = root("revocation-ca");
        let peer = leaf(&ca, LEAF_SERIAL);
        let revocation = shared(&[crl(&ca, &[LEAF_SERIAL], (2035, 1, 1))]);
        assert!(
            rejected(&[peer.as_ref()], &options(&revocation)),
            "a revoked leaf must stop being served"
        );
    }

    /// A CRL reload reaches a request on a connection whose handshake is long past.
    ///
    /// The broken implementation this catches: reading the index once per connection (or
    /// hoisting `load()` out of the per-request decision), which is exactly the
    /// handshake-only posture this check exists to replace.
    #[test]
    fn a_reloaded_crl_refuses_a_leaf_that_was_served_a_moment_earlier() {
        let ca = root("revocation-ca");
        let peer = leaf(&ca, LEAF_SERIAL);
        let revocation = shared(&[crl(&ca, &[], (2035, 1, 1))]);
        let options = options(&revocation);
        assert!(!rejected(&[peer.as_ref()], &options));

        revocation.store(
            ClientRevocationIndex::from_crl_ders(&[crl(&ca, &[LEAF_SERIAL], (2035, 1, 1))], false)
                .expect("index builds"),
        );
        assert!(
            rejected(&[peer.as_ref()], &options),
            "the reloaded CRL must reach the connection already being served"
        );
    }

    /// A leaf whose issuer no configured CRL covers is `Unknown`, and deny-unknown is the
    /// handshake's posture, so it is refused.
    #[test]
    fn a_leaf_whose_issuer_no_crl_covers_is_refused() {
        let ca = root("revocation-ca");
        let other = root("unrelated-ca");
        let peer = leaf(&ca, LEAF_SERIAL);
        let revocation = shared(&[crl(&other, &[], (2035, 1, 1))]);
        assert!(rejected(&[peer.as_ref()], &options(&revocation)));
    }

    /// A CRL past its `nextUpdate` can no longer answer `Good`, so its issuer's
    /// certificates become `Unknown` and are refused — the same direction as rustls'
    /// `enforce_revocation_expiration`.
    #[test]
    fn a_leaf_under_a_crl_that_has_fallen_out_of_force_is_refused() {
        let ca = root("revocation-ca");
        let peer = leaf(&ca, LEAF_SERIAL);
        let revocation = shared(&[crl(&ca, &[], (2021, 1, 1))]);
        assert!(rejected(&[peer.as_ref()], &options(&revocation)));
    }

    /// A chain whose intermediate is covered and unlisted is served — the control for
    /// the refusal below.
    #[test]
    fn a_chain_whose_intermediate_is_on_no_crl_is_served() {
        let ca = root("revocation-root");
        let ica = intermediate(&ca, "revocation-ica", ICA_SERIAL);
        let peer = leaf(&ica, LEAF_SERIAL);
        let revocation = shared(&[crl(&ca, &[], (2035, 1, 1)), crl(&ica, &[], (2035, 1, 1))]);
        assert!(!rejected(
            &[peer.as_ref(), ica.der.as_ref()],
            &options(&revocation)
        ));
    }

    /// Revoking the ISSUING INTERMEDIATE stops the leaf being served, even though the
    /// leaf's own serial is on no CRL.
    ///
    /// The broken implementation this catches: asking the index about `chain[0]` only.
    /// The handshake verifier checks revocation to the trust anchor, so a per-request
    /// check that stopped at the leaf would keep honouring a revoked intermediate on
    /// every connection the peer already holds.
    #[test]
    fn a_chain_under_a_revoked_intermediate_is_refused() {
        let ca = root("revocation-root");
        let ica = intermediate(&ca, "revocation-ica", ICA_SERIAL);
        let peer = leaf(&ica, LEAF_SERIAL);
        let revocation = shared(&[
            crl(&ca, &[ICA_SERIAL], (2035, 1, 1)),
            crl(&ica, &[], (2035, 1, 1)),
        ]);
        assert!(
            rejected(&[peer.as_ref(), ica.der.as_ref()], &options(&revocation)),
            "a revoked issuing intermediate must stop the leaf being served"
        );
    }

    /// An intermediate is refused only on an EXPLICIT `Revoked` verdict. Whether the
    /// presented chain reaches a CRL-covered issuer is a path-building question the
    /// handshake settled, so an `Unknown` intermediate must not be re-decided here.
    #[test]
    fn an_intermediate_no_crl_covers_does_not_refuse_the_chain() {
        let ca = root("revocation-root");
        let ica = intermediate(&ca, "revocation-ica", ICA_SERIAL);
        let peer = leaf(&ica, LEAF_SERIAL);
        let revocation = shared(&[crl(&ica, &[], (2035, 1, 1))]);
        assert!(!rejected(
            &[peer.as_ref(), ica.der.as_ref()],
            &options(&revocation)
        ));
    }
}

#[cfg(test)]
mod crl_next_update_tests {
    //! The TLS plane performs no security transition on `Drop` and gives its CRL reload
    //! loop no failure budget, both on the ground that a CRL bounds ITSELF. That argument
    //! holds only while every loaded CRL states a `nextUpdate`, so a CRL without one is
    //! refused where it is read rather than admitted into a posture that claims it
    //! self-bounds.

    use super::*;
    use der::Decode;
    use der::Encode;
    use x509_cert::crl::CertificateList;

    fn crl_with_next_update() -> Vec<u8> {
        let key = rcgen::KeyPair::generate().expect("ca key");
        let mut params = rcgen::CertificateParams::new(Vec::new()).expect("ca params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "crl-gate-ca");
        let _ca = params.self_signed(&key).expect("ca");
        let crl_params = rcgen::CertificateRevocationListParams {
            this_update: rcgen::date_time_ymd(2024, 1, 1),
            next_update: rcgen::date_time_ymd(2999, 1, 1),
            crl_number: rcgen::SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: Vec::new(),
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        };
        crl_params
            .signed_by(&rcgen::Issuer::from_params(&params, &key))
            .expect("crl")
            .der()
            .to_vec()
    }

    /// The same CRL with its `nextUpdate` removed. RFC 5280 permits the encoding, which
    /// is exactly why the gate has to refuse it rather than assume no CA emits one.
    fn crl_without_next_update() -> Vec<u8> {
        let mut list = CertificateList::from_der(&crl_with_next_update()).expect("parse");
        list.tbs_cert_list.next_update = None;
        list.to_der().expect("re-encode")
    }

    #[test]
    fn a_crl_that_states_its_next_update_is_accepted() {
        let der = crl_with_next_update();
        assert_eq!(
            crl_freshness(&der, 0, 0).expect("parse"),
            CrlFreshness::Fresh
        );
        assert!(crl_next_update_required(&der, 0).is_ok());
    }

    /// The broken implementation this catches: classifying a `nextUpdate`-less CRL as
    /// `Fresh`. Nothing downstream can age it out — rustls' expiration enforcement has
    /// no field to compare and `ClientRevocationIndex::verdict` answers `Good` for its
    /// issuer at any `now` — so a permanently failing reload would leave the replica
    /// admitting certificates revoked afterwards for the rest of its lifetime.
    #[test]
    fn a_crl_that_never_falls_out_of_force_is_refused() {
        let der = crl_without_next_update();
        assert_eq!(
            crl_freshness(&der, 0, 0).expect("parse"),
            CrlFreshness::NoNextUpdate
        );
        let err = crl_next_update_required(&der, 3).expect_err("must be refused");
        let message = err.to_string();
        assert!(message.contains("#3"), "names the offending CRL: {message}");
        assert!(
            message.contains("nextUpdate"),
            "names what is missing: {message}"
        );
    }
}

/// Reading the configured CRL files, which is a TLS concern and was a CLI one.
///
/// It moved here with `TlsPlan`: the TLS plane is the only caller, and reaching for it
/// through `cli` was the last thing keeping a configuration module named in a plane that
/// no longer takes configuration.
#[cfg(test)]
mod client_crl_loading_tests {
    #[test]
    fn missing_client_crl_file_fails_closed() {
        // A configured-but-unreadable CRL path is a hard error, never a silently
        // skipped revocation check.
        let err =
            super::load_client_crls(&["/no/such/MCPS3839_MISSING.crl".to_string()]).unwrap_err();
        assert!(err.contains("MCPS3839_MISSING"), "got: {err}");
    }

    #[test]
    fn no_crl_paths_loads_empty_vec() {
        // The no-CRL path: empty input → empty vec (revocation disabled), no error.
        let crls = super::load_client_crls(&[]).expect("empty load");
        assert!(crls.is_empty());
    }
}
