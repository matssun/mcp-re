// SPDX-License-Identifier: Apache-2.0
//! The X.509 parse the currency authority needs — the ADR-MCPRE-059 assumed boundary
//! (ASM-0030), confined to one adapter as Slice 1's identity parse is.
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
    /// Issuer `Name` == subject `Name`.
    ///
    /// A peer may send its root. Path building matches that against the CONFIGURED
    /// anchor set rather than against its own validity window, so holding it to a window
    /// would refuse chains a full handshake admits. The exemption is the caller's to
    /// apply; this only reports the shape.
    pub(super) self_issued: bool,
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

/// Read one certificate's currency facts, or `None` if the DER does not parse.
pub(super) fn read_currency_facts(der: &[u8]) -> Option<CertificateCurrencyFacts<'_>> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    let issuer_der = cert.tbs_certificate.issuer.as_raw();
    Some(CertificateCurrencyFacts {
        not_before: cert.validity().not_before.timestamp(),
        not_after: cert.validity().not_after.timestamp(),
        issuer_der,
        serial: cert.tbs_certificate.raw_serial(),
        self_issued: issuer_der == cert.tbs_certificate.subject.as_raw(),
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
        // when it is self-issued.
        let facts = CertificateCurrencyFacts {
            not_before: 100,
            not_after: 200,
            issuer_der: &[],
            serial: &[],
            self_issued: false,
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
            self_issued: false,
        };
        assert!(!inverted.window_is_orderable());
        for now in [99, 100, 150, 200, 201] {
            assert!(!inverted.contains(now));
        }
    }
}
