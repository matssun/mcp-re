// SPDX-License-Identifier: Apache-2.0
//! Client-certificate verifier construction — census authority B, private to the
//! listener-state subtree.
//!
//! Separated from [`super::assembly`] because it answers a different question: assembly
//! decides what a serving config IS; this decides what a valid client certificate is.
//!
//! On its own it confers no dangerous capability — a verifier installs no session store,
//! so it cannot produce the mispairing the owner forbids. It is `pub(super)` anyway,
//! because the subtree is the boundary and a crate-wide export would have to justify
//! itself rather than be the default.

use std::sync::Arc;

use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::CertificateRevocationListDer;

use crate::tls::TlsError;

/// Build the fail-closed WebPKI client-certificate verifier shared by the
/// exported-key ([`assemble_exported_key_config`]) and delegated-key
/// ([`assemble_delegated_config`]) server-config paths. Sharing it
/// keeps the security-critical verifier posture identical across both: unconditional
/// unknown-status rejection with no operator opt-out, full-chain revocation, and a
/// malformed CRL → startup `TlsError::Verifier` (fail closed).
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
/// Build the client-certificate verifier every serving path shares.
///
/// `allow_unknown_revocation_status()` is NOT called, and there is no parameter that
/// could cause it to be: rustls' `UnknownStatusPolicy::Deny` default stands on every
/// verifier this function can produce. Deny-unknown is therefore a property of the
/// construction rather than of an argument a caller passed correctly — the same
/// invariant `ClientRevocationIndex::admits` holds on the per-request side, which is
/// what keeps the handshake and the per-request check from disagreeing.
pub(super) fn build_client_verifier(
    client_ca: Vec<CertificateDer<'static>>,
    crls: Vec<CertificateRevocationListDer<'static>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Result<Arc<dyn rustls::server::danger::ClientCertVerifier>, TlsError> {
    let mut roots = RootCertStore::empty();
    for ca in client_ca {
        roots.add(ca).map_err(|_| TlsError::BadClientCa)?;
    }
    WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
        .with_crls(crls)
        .enforce_revocation_expiration()
        .build()
        .map_err(|e| TlsError::Verifier(e.to_string()))
}
