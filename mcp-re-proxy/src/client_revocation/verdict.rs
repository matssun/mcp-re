// SPDX-License-Identifier: Apache-2.0
//! What the per-request client-revocation index answers about one certificate, and how a
//! certificate is named to it.
//!
//! The vocabulary of the answer, kept apart from the index that computes it: a consumer
//! reading a verdict, or naming a certificate, needs no view of how the lists are held.

/// What the current CRLs say about one client certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationVerdict {
    /// The issuer is covered by a CRL that is in force, and this serial is not on it.
    Good,
    /// This serial is listed as revoked by a CRL for its issuer.
    Revoked,
    /// No CRL in force covers this leaf's issuer — either none was configured for it,
    /// or the one that was is past its `nextUpdate`.
    Unknown,
}

/// The coordinate of one certificate in the index: who it names as its issuer, its serial,
/// and the certificate itself — which is read only when several configured CA keys share
/// its issuer `Name`, to find the one that signed it.
#[derive(Debug, Clone, Copy)]
pub struct CertificateCoordinate<'a> {
    /// The issuer `Name`, DER-encoded.
    pub issuer_der: &'a [u8],
    /// The serial number, as DER.
    pub serial: &'a [u8],
    /// The whole certificate, DER.
    pub certificate_der: &'a [u8],
}

/// Strip leading zero bytes from a DER INTEGER's content octets.
///
/// A positive integer whose high bit is set is encoded with a leading `0x00` pad, and
/// a certificate and a CRL are free to encode the same serial with or without it. A
/// raw byte comparison would then miss the revocation, which is the one direction this
/// must never fail in.
///
/// Borrows rather than allocating: this runs on the request path, and the lookup below
/// queries a `HashSet<Vec<u8>>` through `Borrow<[u8]>`, so the normalized form never
/// needs to own its bytes to be compared.
pub(super) fn normalize_serial(serial: &[u8]) -> &[u8] {
    let mut significant = serial;
    while let Some((&0, rest)) = significant.split_first() {
        significant = rest;
    }
    significant
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A positive serial whose high bit is set may carry a leading zero pad in a certificate
    /// and none in a CRL (or the reverse); the normal form drops the pad and nothing else.
    #[test]
    fn a_zero_pad_is_the_only_thing_normalisation_removes() {
        assert_eq!(normalize_serial(b"\x00\x80\x01"), b"\x80\x01");
        assert_eq!(normalize_serial(b"\x80\x01"), b"\x80\x01");
        assert_eq!(normalize_serial(b"\x01\x00"), b"\x01\x00");
    }

    /// The three verdicts are three values: `Unknown` must never compare equal to `Good`.
    #[test]
    fn the_three_verdicts_are_distinct() {
        assert_ne!(RevocationVerdict::Good, RevocationVerdict::Unknown);
        assert_ne!(RevocationVerdict::Revoked, RevocationVerdict::Unknown);
        assert_ne!(RevocationVerdict::Good, RevocationVerdict::Revoked);
    }
}
