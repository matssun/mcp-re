// SPDX-License-Identifier: Apache-2.0
//! The X.509 parse the currency authority needs — the ADR-MCPRE-059 assumed boundary
//! (ASM-0038), confined to one adapter as Slice 1's identity parse is.
//!
//! It reads and decides nothing. Which of these facts is required of which certificate,
//! and what an absent one means, is [`super::evaluation`]'s: a peer's own leaf and the
//! issuers it presented are held to deliberately different rules, and an adapter that
//! folded either rule in would put that decision below the authority that owns it.

use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

/// What one certificate says about its own currency.
///
/// Borrowed from the DER rather than copied: this is read per request on the serving
/// path, and a per-request allocation of the issuer name and serial would be paid on
/// every request of every keep-alive connection.
pub(super) struct CertificateCurrencyFacts<'a> {
    /// `notBefore`, Unix seconds.
    pub(super) not_before: i64,
    /// `notAfter`, Unix seconds.
    pub(super) not_after: i64,
    /// The issuer `Name`, DER-encoded — the key a CRL index is looked up by.
    pub(super) issuer_der: &'a [u8],
    /// This certificate's serial number, as DER.
    pub(super) serial: &'a [u8],
    /// The certificate itself, DER: read by the CRL index only when several configured CA
    /// keys share this certificate's issuer name, to find the one that signed it.
    pub(super) certificate_der: &'a [u8],
    /// Issuer `Name` == subject `Name` AND the signature verifies under this
    /// certificate's own public key.
    ///
    /// A peer may send its root. Path building matches that against the CONFIGURED
    /// anchor set rather than against its own validity window, so holding it to a window
    /// would refuse chains a full handshake admits. A self-signed certificate can only sit
    /// on an accepted path as an anchor-equivalent (same name and key), whereas a
    /// self-issued certificate signed by another key (a key-rollover intermediate) is
    /// window-checked by path building and must stay window-checked. A signature that
    /// does not verify, for any reason, reads `false`. The exemption is the caller's to
    /// apply; this only reports the fact.
    pub(super) self_signed: bool,
}

impl CertificateCurrencyFacts<'_> {
    /// Is the validity window orderable at all?
    ///
    /// `notAfter <= notBefore` is not a window that has closed, it is a certificate that
    /// never had one. Reported separately rather than folded into the parse, because the
    /// production semantics apply it to a peer's own leaf and to an issuer whose
    /// revocation standing is being read, and NOT to an issuer's validity check — where a
    /// self-issued certificate is exempt from the window entirely.
    pub(super) fn window_is_orderable(&self) -> bool {
        self.not_after > self.not_before
    }

    /// Does this certificate's own validity window contain `now`?
    pub(super) fn contains(&self, now: i64) -> bool {
        now >= self.not_before && now < self.not_after
    }

    /// The certificate's validity SPAN in seconds — the quantity a configured ceiling
    /// bounds. Distinct from [`Self::contains`]: a short-lived certificate satisfies a
    /// span ceiling for the rest of time, and an expired one can still have a legal span.
    pub(super) fn span_secs(&self) -> i64 {
        self.not_after.saturating_sub(self.not_before)
    }
}

impl<'a> CertificateCurrencyFacts<'a> {
    /// This certificate's coordinate in a CRL index.
    pub(super) fn coordinate(&self) -> crate::client_revocation::CertificateCoordinate<'a> {
        crate::client_revocation::CertificateCoordinate {
            issuer_der: self.issuer_der,
            serial: self.serial,
            certificate_der: self.certificate_der,
        }
    }
}

/// Read one certificate's currency facts, or `None` if the DER does not parse.
pub(super) fn read_currency_facts(der: &[u8]) -> Option<CertificateCurrencyFacts<'_>> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    let issuer_der = cert.tbs_certificate.issuer.as_raw();
    Some(CertificateCurrencyFacts {
        not_before: cert.validity().not_before.timestamp(),
        not_after: cert.validity().not_after.timestamp(),
        issuer_der,
        serial: cert.tbs_certificate.raw_serial(),
        certificate_der: der,
        self_signed: issuer_der == cert.tbs_certificate.subject.as_raw()
            && cert.verify_signature(None).is_ok(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rubbish_der_reads_no_facts() {
        assert!(read_currency_facts(&[0x30, 0x00]).is_none());
        assert!(read_currency_facts(&[]).is_none());
    }

    #[test]
    fn an_orderable_window_is_not_the_same_question_as_containing_now() {
        // The two are separate because production applies them to different certificates:
        // a leaf must have an orderable window, an issuer's window is skipped entirely
        // when it is self-signed.
        let facts = CertificateCurrencyFacts {
            not_before: 100,
            not_after: 200,
            issuer_der: &[],
            serial: &[],
            certificate_der: &[],
            self_signed: false,
        };
        assert!(facts.window_is_orderable());
        assert!(!facts.contains(99));
        assert!(facts.contains(100));
        assert!(facts.contains(199));
        assert!(
            !facts.contains(200),
            "notAfter is exclusive, as production reads it"
        );
        assert_eq!(facts.span_secs(), 100);
    }

    #[test]
    fn an_inverted_window_is_not_orderable_and_contains_nothing() {
        let inverted = CertificateCurrencyFacts {
            not_before: 200,
            not_after: 100,
            issuer_der: &[],
            serial: &[],
            certificate_der: &[],
            self_signed: false,
        };
        assert!(!inverted.window_is_orderable());
        for now in [99, 100, 150, 200, 201] {
            assert!(!inverted.contains(now));
        }
    }

    #[test]
    fn a_self_issued_certificate_is_self_signed_only_under_its_own_key() {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

        fn ca_params() -> CertificateParams {
            let mut params = CertificateParams::new(Vec::new()).expect("ca params");
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params
                .distinguished_name
                .push(DnType::CommonName, "same-name");
            params
        }

        let root_key = KeyPair::generate().expect("root key");
        let root_params = ca_params();
        let root = root_params.self_signed(&root_key).expect("root");
        let root_der = root.der().clone();
        let facts = read_currency_facts(root_der.as_ref()).expect("root parses");
        assert!(
            facts.self_signed,
            "a root signed by its own key is self-signed"
        );

        let rollover_key = KeyPair::generate().expect("rollover key");
        let issuer = rcgen::Issuer::from_params(&root_params, &root_key);
        let rollover = ca_params()
            .signed_by(&rollover_key, &issuer)
            .expect("rollover");
        let rollover_der = rollover.der().clone();
        let facts = read_currency_facts(rollover_der.as_ref()).expect("rollover parses");
        assert_eq!(
            facts.issuer_der,
            read_currency_facts(root_der.as_ref())
                .expect("root")
                .issuer_der
        );
        assert!(
            !facts.self_signed,
            "same Name under a different key is self-issued, not self-signed"
        );
    }
}
