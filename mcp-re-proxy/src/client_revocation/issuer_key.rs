// SPDX-License-Identifier: Apache-2.0
//! The CA key behind a CRL, and the question of which of several same-named keys issued a
//! certificate.
//!
//! One authority: *which configured client CA key stands behind this document?* A CRL names
//! its issuer by `Name`, which is the document speaking about itself. What it can prove is
//! only that some key signed it, so the answer is a key from the CONFIGURED anchors whose
//! signature verifies, never the name the CRL asserts.

use rustls_pki_types::CertificateDer;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;
use x509_parser::revocation_list::CertificateRevocationList;
use x509_parser::x509::SubjectPublicKeyInfo;

use crate::tls::TlsError;

/// A configured client CA: its subject `Name` and its public key.
///
/// The key is what identifies the CA — compared whole, so no digest of it can collide. Two
/// CAs may share a `Name`; they cannot share a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CaKey {
    /// The subject `Name`, DER-encoded.
    pub(super) name_der: Vec<u8>,
    /// The `SubjectPublicKeyInfo`, DER-encoded.
    pub(super) spki_der: Vec<u8>,
}

impl CaKey {
    /// The subject `Name` this key's CRLs are filed under.
    pub(super) fn name_der(&self) -> &[u8] {
        &self.name_der
    }

    /// Whether THIS key signed `certificate_der`. A certificate that does not parse was
    /// signed by nobody this index can name.
    pub(super) fn issued(&self, certificate_der: &[u8]) -> bool {
        let Ok((_, spki)) = SubjectPublicKeyInfo::from_der(&self.spki_der) else {
            return false;
        };
        let Ok((_, cert)) = X509Certificate::from_der(certificate_der) else {
            return false;
        };
        cert.verify_signature(Some(&spki)).is_ok()
    }
}

/// Whether an anchor may sign CRLs: RFC 5280 §6.3.3 requires `cRLSign` where the
/// `keyUsage` extension is present, and an absent extension permits it.
fn may_sign_crls(anchor: &X509Certificate<'_>) -> bool {
    match anchor.key_usage() {
        Ok(Some(usage)) => usage.value.crl_sign(),
        Ok(None) => true,
        Err(_) => false,
    }
}

/// The configured CA key that signed `crl`.
///
/// Refused when none did: a CRL no anchor key verifies is not a statement by any CA this
/// deployment trusts, and the handshake verifier's own authentication of CRLs does not
/// vouch for this index.
pub(super) fn signing_key(
    crl: &CertificateRevocationList<'_>,
    anchors: &[CertificateDer<'_>],
) -> Result<CaKey, TlsError> {
    for anchor_der in anchors {
        let Ok((_, anchor)) = X509Certificate::from_der(anchor_der.as_ref()) else {
            continue;
        };
        if anchor.tbs_certificate.subject.as_raw() != crl.issuer().as_raw()
            || !may_sign_crls(&anchor)
            || crl.verify_signature(anchor.public_key()).is_err()
        {
            continue;
        }
        return Ok(CaKey {
            name_der: anchor.tbs_certificate.subject.as_raw().to_vec(),
            spki_der: anchor.public_key().raw.to_vec(),
        });
    }
    Err(TlsError::Verifier(format!(
        "client CRL issued by `{}` is not signed by any configured client CA key. A CRL is \
         accepted only if a certificate in the client CA bundle names its issuer and its \
         signature verifies under that certificate's key; a CRL signed by an intermediate \
         needs that intermediate in the bundle",
        crl.issuer()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(name: &[u8], spki: &[u8]) -> CaKey {
        CaKey {
            name_der: name.to_vec(),
            spki_der: spki.to_vec(),
        }
    }

    /// Keys that differ only in the key are different keys: the name is shared by CAs that
    /// rotated, the key is what separates them.
    #[test]
    fn two_cas_with_one_name_are_two_keys() {
        assert_ne!(key(b"n", b"a"), key(b"n", b"b"));
        assert_eq!(key(b"n", b"a"), key(b"n", b"a"));
    }

    /// A key that cannot be read, or a certificate that cannot, issued nothing.
    #[test]
    fn an_unreadable_key_or_certificate_issued_nothing() {
        assert!(!key(b"n", b"not-an-spki").issued(b"not-a-cert"));
    }
}
