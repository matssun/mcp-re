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
/// ([`crl_freshness`]) and the CRL reload worker (`--client-crl-reload-secs`), which
/// rebuilds the verifier from the re-read CRLs. The call is a no-op when no CRLs are
/// configured (revocation checks are not performed).
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

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::server::danger::ClientCertVerifier;
    use rustls_pki_types::UnixTime;

    struct TestCa {
        key: rcgen::KeyPair,
        params: rcgen::CertificateParams,
    }

    fn test_ca(common_name: &str) -> TestCa {
        let key = rcgen::KeyPair::generate().expect("ca key");
        let mut params = rcgen::CertificateParams::new(Vec::new()).expect("ca params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        TestCa { key, params }
    }

    impl TestCa {
        fn issuer(&self) -> rcgen::Issuer<'_, &rcgen::KeyPair> {
            rcgen::Issuer::from_params(&self.params, &self.key)
        }

        fn anchor(&self) -> CertificateDer<'static> {
            self.params
                .self_signed(&self.key)
                .expect("ca certificate")
                .der()
                .clone()
        }

        fn leaf(&self, serial: u64) -> CertificateDer<'static> {
            let key = rcgen::KeyPair::generate().expect("leaf key");
            let mut params = rcgen::CertificateParams::new(Vec::new()).expect("leaf params");
            params.serial_number = Some(rcgen::SerialNumber::from(serial));
            params
                .signed_by(&key, &self.issuer())
                .expect("leaf signed")
                .der()
                .clone()
        }

        fn crl(
            &self,
            revoked: &[u64],
            next_update_year: i32,
        ) -> CertificateRevocationListDer<'static> {
            let params = rcgen::CertificateRevocationListParams {
                this_update: rcgen::date_time_ymd(2020, 1, 1),
                next_update: rcgen::date_time_ymd(next_update_year, 1, 1),
                crl_number: rcgen::SerialNumber::from(1u64),
                issuing_distribution_point: None,
                revoked_certs: revoked
                    .iter()
                    .map(|serial| rcgen::RevokedCertParams {
                        serial_number: rcgen::SerialNumber::from(*serial),
                        revocation_time: rcgen::date_time_ymd(2021, 1, 1),
                        reason_code: Some(rcgen::RevocationReason::KeyCompromise),
                        invalidity_date: None,
                    })
                    .collect(),
                key_identifier_method: rcgen::KeyIdMethod::Sha256,
            };
            CertificateRevocationListDer::from(
                params
                    .signed_by(&self.issuer())
                    .expect("crl signed")
                    .der()
                    .to_vec(),
            )
        }
    }

    fn verifier(
        cas: &[&TestCa],
        crls: Vec<CertificateRevocationListDer<'static>>,
    ) -> Arc<dyn ClientCertVerifier> {
        build_client_verifier(
            cas.iter().map(|ca| ca.anchor()).collect(),
            crls,
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .expect("verifier builds")
    }

    fn admits(verifier: &Arc<dyn ClientCertVerifier>, leaf: &CertificateDer<'_>) -> bool {
        verifier
            .verify_client_cert(leaf, &[], UnixTime::now())
            .is_ok()
    }

    #[test]
    fn a_fresh_crl_admits_an_unrevoked_leaf_of_its_issuer() {
        let ca = test_ca("ca-a");
        let v = verifier(&[&ca], vec![ca.crl(&[], 2099)]);
        assert!(admits(&v, &ca.leaf(7)));
    }

    #[test]
    fn a_leaf_its_issuers_crl_revokes_is_refused() {
        let ca = test_ca("ca-a");
        let v = verifier(&[&ca], vec![ca.crl(&[7], 2099)]);
        assert!(!admits(&v, &ca.leaf(7)));
    }

    #[test]
    fn a_stale_crl_refuses_an_unrevoked_leaf_of_its_issuer() {
        let ca = test_ca("ca-a");
        let v = verifier(&[&ca], vec![ca.crl(&[], 2021)]);
        assert!(!admits(&v, &ca.leaf(7)));
    }

    #[test]
    fn a_leaf_whose_issuer_has_no_crl_is_refused_when_crls_are_configured() {
        let ca_a = test_ca("ca-a");
        let ca_b = test_ca("ca-b");
        let v = verifier(&[&ca_a, &ca_b], vec![ca_a.crl(&[], 2099)]);
        assert!(!admits(&v, &ca_b.leaf(7)));
    }

    #[test]
    fn an_unparseable_client_ca_is_refused_as_bad_client_ca() {
        let result = build_client_verifier(
            vec![CertificateDer::from(vec![0u8; 8])],
            Vec::new(),
            Arc::new(rustls::crypto::ring::default_provider()),
        );
        assert!(matches!(result, Err(TlsError::BadClientCa)));
    }
}
