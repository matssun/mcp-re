// SPDX-License-Identifier: Apache-2.0
//! Building the per-request index: parse each CRL, authenticate it, file it under the CA key
//! that signed it.
//!
//! The one place a [`ClientRevocationIndex`] acquires CRLs, which is what makes "every CRL in
//! an index was signed by a configured client CA key" a property of the type: there is no
//! other producer to forget the check.

use std::collections::HashMap;

use rustls_pki_types::CertificateDer;
use x509_parser::prelude::FromDer;

use super::issuer_key;
use super::verdict::normalize_serial;
use super::ClientRevocationIndex;
use super::IssuerCrl;
use super::KeyedCrl;
use crate::tls::TlsError;

impl ClientRevocationIndex {
    /// Build the index from DER-encoded CRLs, each authenticated against `anchors`.
    ///
    /// A CRL whose signature no anchor key verifies is a hard error: it is bytes somebody
    /// wrote, and an index that carried it would revoke, or certify, on their say-so. A
    /// malformed CRL is a hard error too, matching the verifier build and
    /// [`crl_posture`](crate::client_crl_publication::crl_posture): the same bytes are about
    /// to be given to rustls, which would refuse them, so accepting them here would leave
    /// the two disagreeing about what is enforced. So is an empty `crls`, a CRL without a
    /// `nextUpdate`, and a CRL followed by trailing bytes.
    pub fn from_crl_ders(
        crls: &[impl AsRef<[u8]>],
        anchors: &[CertificateDer<'_>],
    ) -> Result<Self, TlsError> {
        // x509-parser for BOTH sides of the issuer comparison — the same crate the
        // leaf is parsed with. Decoding the name and RE-ENCODING it (x509-cert's
        // `Name::to_der()`) would compare a round-tripped spelling against the leaf's
        // original bytes, so a CA whose DER is not exactly what the encoder emits would
        // fail to match. Under deny-unknown that is not a missed revocation, it is a
        // refusal of every request — fail-closed, and an outage. Raw bytes on both
        // sides cannot drift.
        if crls.is_empty() {
            return Err(TlsError::Verifier("no client CRLs to index".into()));
        }
        let mut per_issuer: HashMap<Vec<u8>, Vec<KeyedCrl>> = HashMap::new();
        for crl_der in crls {
            let (rest, crl) =
                x509_parser::revocation_list::CertificateRevocationList::from_der(crl_der.as_ref())
                    .map_err(|e| TlsError::Verifier(format!("malformed client CRL: {e}")))?;
            rest.is_empty()
                .then_some(())
                .ok_or_else(|| TlsError::Verifier("client CRL has trailing bytes".into()))?;
            let key = issuer_key::signing_key(&crl, anchors)?;
            let next_update_unix = crl
                .next_update()
                .ok_or_else(|| TlsError::Verifier("client CRL states no nextUpdate".into()))?
                .timestamp();
            let facts = IssuerCrl {
                revoked: crl
                    .iter_revoked_certificates()
                    .map(|entry| normalize_serial(entry.raw_serial()).to_vec())
                    .collect(),
                next_update_unix,
            };

            // Several CRLs may be signed by one key: their serials union and the EARLIEST
            // nextUpdate stands, so a list that has fallen out of force is not held in force
            // by a fresher sibling, or a revocation published only on the stale one would
            // silently stop being enforced.
            let keyed = per_issuer.entry(key.name_der().to_vec()).or_default();
            match keyed.iter_mut().find(|k| k.key == key) {
                Some(existing) => existing.crl.absorb(facts),
                None => keyed.push(KeyedCrl { key, crl: facts }),
            }
        }
        Ok(ClientRevocationIndex { per_issuer })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No CRLs is no index: "revocation not configured" is the absence of one upstream, never
    /// an empty one built here.
    #[test]
    fn no_crls_build_no_index_even_with_anchors() {
        let err = ClientRevocationIndex::from_crl_ders(&[] as &[Vec<u8>], &[])
            .expect_err("no CRLs is refused");
        assert!(matches!(err, TlsError::Verifier(_)));
    }
}
