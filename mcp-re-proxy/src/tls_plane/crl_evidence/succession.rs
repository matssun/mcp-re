// SPDX-License-Identifier: Apache-2.0
//! Where a CRL stands in its issuer's sequence, and whether one set may replace another.
//!
//! One fact: **a set of CRLs may replace the one in force only if it succeeds it** under
//! RFC 5280 §5.2.3 `crlNumber`, keyed by the issuer's KEY. The CRL path's writer is not
//! trusted, so "the operator path is authoritative" does not admit an older, or a
//! different-bytes-same-number, set: either would retract revocations the replica already
//! enforces.

use der::oid::AssociatedOid;
use der::{Decode, Encode};
use x509_cert::crl::CertificateList;
use x509_cert::ext::pkix::{AuthorityKeyIdentifier, CrlNumber};

/// One CRL's place in its issuer's sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CrlRecency {
    /// The issuer Name DER and the `authorityKeyIdentifier` key identifier: the issuer KEY,
    /// not the distinguished name alone.
    issuer: (Vec<u8>, Vec<u8>),
    /// The `crlNumber` magnitude, leading zero bytes stripped.
    number: Vec<u8>,
    /// The hash identity of the CRL's bytes.
    digest: String,
}

impl CrlRecency {
    /// Read the recency of one CRL; a CRL whose place in its issuer's sequence cannot be
    /// ordered is refused, because it could not be safely replaced.
    pub(super) fn of(der: &[u8], index: usize) -> Result<CrlRecency, String> {
        let list = CertificateList::from_der(der)
            .map_err(|e| format!("client CRL #{index} does not decode: {e}"))?;
        let extensions = list.tbs_cert_list.crl_extensions.as_deref().unwrap_or(&[]);
        let value = |oid| {
            extensions
                .iter()
                .find(|e| e.extn_id == oid)
                .map(|e| e.extn_value.as_bytes())
        };
        let number = value(CrlNumber::OID)
            .ok_or_else(|| format!("client CRL #{index} omits crlNumber"))
            .and_then(|b| {
                CrlNumber::from_der(b).map_err(|e| format!("client CRL #{index} crlNumber: {e}"))
            })?;
        let key_id = value(AuthorityKeyIdentifier::OID)
            .ok_or_else(|| format!("client CRL #{index} omits authorityKeyIdentifier"))
            .and_then(|b| {
                AuthorityKeyIdentifier::from_der(b)
                    .map_err(|e| format!("client CRL #{index} authorityKeyIdentifier: {e}"))
            })?
            .key_identifier
            .ok_or_else(|| {
                format!("client CRL #{index} authorityKeyIdentifier omits keyIdentifier")
            })?;
        let issuer = list
            .tbs_cert_list
            .issuer
            .to_der()
            .map_err(|e| format!("client CRL #{index} issuer: {e}"))?;
        let magnitude = number.0.as_bytes();
        let start = magnitude
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(magnitude.len());
        Ok(CrlRecency {
            issuer: (issuer, key_id.as_bytes().to_vec()),
            number: magnitude.get(start..).unwrap_or_default().to_vec(),
            digest: mcp_re_core::sha256_hash_id(der),
        })
    }

    /// Magnitudes ordered as (length, bytes), which is numeric order once zeros are stripped.
    fn order_key(&self) -> (usize, &[u8]) {
        (self.number.len(), &self.number)
    }
}

/// The highest `crlNumber` among `set`'s CRLs from `issuer`, if there is any.
fn newest<'a>(set: &'a [CrlRecency], issuer: &(Vec<u8>, Vec<u8>)) -> Option<&'a CrlRecency> {
    set.iter()
        .filter(|c| &c.issuer == issuer)
        .max_by_key(|c| c.order_key())
}

/// Refuse `next` unless it may replace `prior`: no issuer dropped, no `crlNumber` regressed,
/// no `crlNumber` reused with other bytes. An identical re-read passes; an empty `prior`
/// admits any `next`.
pub(super) fn succeeds(next: &[CrlRecency], prior: &[CrlRecency]) -> Result<(), String> {
    for (i, old) in prior.iter().enumerate() {
        let Some(newest_next) = newest(next, &old.issuer) else {
            return Err(format!(
                "client CRL set drops the issuer of in-force CRL #{i}"
            ));
        };
        let newest_prior = newest(prior, &old.issuer).unwrap_or(old);
        if newest_next.order_key() < newest_prior.order_key() {
            return Err(format!(
                "client CRL set regresses the crlNumber of the issuer of in-force CRL #{i}"
            ));
        }
    }
    for (i, new) in next.iter().enumerate() {
        let same_number = |p: &&CrlRecency| p.issuer == new.issuer && p.number == new.number;
        let mut held = prior.iter().filter(same_number).peekable();
        if held.peek().is_some() && !held.any(|p| p.digest == new.digest) {
            return Err(format!(
                "client CRL #{i} reuses an in-force crlNumber with different bytes"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recency(issuer: u8, number: &[u8], digest: &str) -> CrlRecency {
        CrlRecency {
            issuer: (vec![issuer], vec![issuer]),
            number: number.to_vec(),
            digest: digest.to_owned(),
        }
    }

    #[test]
    fn numbers_order_numerically_not_lexically() {
        let low = recency(1, &[9], "a");
        let high = recency(1, &[1, 0], "b");
        assert_eq!(
            succeeds(std::slice::from_ref(&high), std::slice::from_ref(&low)),
            Ok(())
        );
        assert!(succeeds(&[low], &[high]).is_err());
    }

    #[test]
    fn an_empty_prior_admits_anything() {
        assert_eq!(succeeds(&[recency(1, &[1], "a")], &[]), Ok(()));
    }
}
