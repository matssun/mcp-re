// SPDX-License-Identifier: Apache-2.0
//! Whom this client trusts to be the proxy, and what it presents to prove itself.
//!
//! Two directions in one value, and the second is the one a transport can get wrong
//! silently. Presenting a client certificate is visible when it is missing — the handshake
//! fails. VERIFYING the server is not: an accept-any verifier completes every handshake, so
//! nothing about a working deployment tells you the check is absent.
//!
//! This builds the standard `WebPkiServerVerifier` over ONLY the configured server CA, so a
//! server certificate that is untrusted, carries the wrong identity, or is expired is
//! rejected during the handshake and the request body is never sent. The one build that
//! discards it is the fault-injection feature, which exists to prove the guard tests would
//! fail if the control were broken — see [`super::fault_accept_any`].

use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;
use rustls::ClientConfig;
use rustls::RootCertStore;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::PrivateKeyDer;

use super::TransportError;

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
        let client_chain =
            certs_from_pem(client_cert_pem).map_err(TransportError::BadClientMaterial)?;
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
        let verifier =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
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

/// Parse a PEM bundle into a chain of DER certificates.
fn certs_from_pem(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, String> {
    let mut out = Vec::new();
    for item in CertificateDer::pem_slice_iter(pem) {
        out.push(item.map_err(|e| e.to_string())?);
    }
    Ok(out)
}
