// SPDX-License-Identifier: Apache-2.0
//! Config assembly and resumption binding — PRIVATE to the listener-state subtree.
//!
//! The two halves the EX-004 census found could be assembled independently: a verifier over
//! one anchor set, and a session store over an unrelated epoch. `pub(crate)` in `tls.rs`
//! sealed them against nobody, so they live here, `pub(super)`, reachable only from
//! [`TlsListenerSecurityState`](super::TlsListenerSecurityState) — the sole construction
//! authority for the pairing. See that module for the seal's one residual limit.

use std::sync::Arc;

use rustls::crypto::ring;
use rustls::ServerConfig;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::CertificateRevocationListDer;
use rustls_pki_types::PrivateKeyDer;

use crate::tls::TlsError;

use super::client_verifier::build_client_verifier;

/// Assemble a serving `ServerConfig` under EXPORTED key custody: requires and verifies a
/// client certificate against `client_ca`, presenting `server_chain` + `server_key`, using
/// the `ring` provider explicitly (no process-global default install).
///
/// Offline CRL revocation only — the CRLs are loaded from disk at startup and never
/// refreshed over the network. ONLINE OCSP / CRL-distribution-point fetching is
/// intentionally not implemented (it would require an HTTP client and a live responder,
/// expanding the firewalled supply chain).
///
/// Fail-closed posture (the rustls 0.23 builder defaults, made explicit):
///   * a client cert listed as revoked by any CRL → handshake REJECTED;
///   * the FULL chain to the trust anchor has revocation checked
///     (`RevocationCheckDepth::Chain`, the default);
///   * a cert whose revocation status cannot be determined from the CRLs is REJECTED
///     (`UnknownStatusPolicy::Deny`). Unconditional — see [`build_client_verifier`], which
///     takes no policy input that could relax it.
///
/// An empty `crls` behaves exactly like the no-CRL path: `.with_crls([])` adds nothing and
/// rustls performs no revocation checks.
///
/// `pub(super)` and RESUMPTION-FREE. It assembles the verifier and the credential and stops
/// there: binding the config to a listener's epoch-tagged session cache belongs to
/// [`TlsListenerSecurityState`](super::TlsListenerSecurityState), which is the only thing
/// that can pair a cache with the anchors it was established from.
///
/// The visibility is the boundary, so it is stated exactly: `pub(crate)` — what this was —
/// would not have prevented the mispairing, because every consumer lives in this crate.
pub(super) fn assemble_exported_key_config(
    server_chain: Vec<CertificateDer<'static>>,
    server_key: PrivateKeyDer<'static>,
    client_ca: Vec<CertificateDer<'static>>,
    crls: Vec<CertificateRevocationListDer<'static>>,
) -> Result<ServerConfig, TlsError> {
    let provider = Arc::new(ring::default_provider());
    let verifier = build_client_verifier(client_ca, crls, provider.clone())?;

    // MCPS-079 fault injection ("test of the tests"), the symmetric mirror of
    // mcp-re-transport's `fault_accept_any_server`. When — and ONLY when — the
    // `fault_accept_any_client` feature is compiled in (off by default, never in
    // production or the default `bazel test //...`), the verifying `WebPkiClientVerifier`
    // above is DISCARDED and replaced by an accept-any CLIENT verifier. This is the
    // deliberately-broken client-auth control: it lets the periodic fault-injection
    // harness demonstrate that the proxy's client-cert-rejection guards are load-bearing
    // (with the fault active, a missing OR untrusted client cert is NO LONGER rejected).
    // The verifying build never constructs this; the byte-for-byte default path is the
    // WebPkiClientVerifier branch below.
    #[cfg(feature = "fault_accept_any_client")]
    {
        let _ = verifier; // the verifying path is intentionally bypassed
        return ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| TlsError::Config(e.to_string()))?
            .with_client_cert_verifier(Arc::new(
                crate::tls::fault_accept_any::AcceptAnyClientVerifier::new(provider),
            ))
            .with_single_cert(server_chain, server_key)
            .map_err(|e| TlsError::Config(e.to_string()));
    }

    #[cfg(not(feature = "fault_accept_any_client"))]
    ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| TlsError::Config(e.to_string()))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_chain, server_key)
        .map_err(|e| TlsError::Config(e.to_string()))
}

/// Assemble a serving `ServerConfig` around a certificate RESOLVER — the delegated-custody
/// shape (ADR-MCPS-028 §G, issue #58), where the server's TLS private key never leaves the
/// device/KMS and rustls drives the handshake signature through the resolver's
/// [`SigningKey`](rustls::sign::SigningKey).
///
/// The client-cert verifier posture is IDENTICAL to the exported-key path (shared
/// [`build_client_verifier`]). The `fault_accept_any_client` bypass is NOT wired here: it
/// exercises the standard exported-key serving path, and weakening client auth is
/// orthogonal to — and must not be conflated with — server-key delegation.
///
/// Resumption-free, for the reason [`assemble_exported_key_config`] states.
pub(super) fn assemble_delegated_config(
    cert_resolver: Arc<dyn rustls::server::ResolvesServerCert>,
    client_ca: Vec<CertificateDer<'static>>,
    crls: Vec<CertificateRevocationListDer<'static>>,
) -> Result<ServerConfig, TlsError> {
    let provider = Arc::new(ring::default_provider());
    let verifier = build_client_verifier(client_ca, crls, provider.clone())?;
    Ok(ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| TlsError::Config(e.to_string()))?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(cert_resolver))
}
