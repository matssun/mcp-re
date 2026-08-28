// SPDX-License-Identifier: Apache-2.0
//! SCITT statement typing — authority B.
//!
//! One fact: **this `COSE_Sign1` is MCP-RE call evidence, attributed to the key that signed
//! it.** `SignedStatement` was already sealed at the census: private representation,
//! `from_cose` the only producer, and this module is where that stays true.

use ciborium::Value;
use coset::CoseSign1;
use coset::Label;
use coset::TaggedCborSerializable;

use crate::error::HttpProfileError;
mod issuance;

pub use issuance::issue_signed_statement;

use super::commitment::EvidenceCommitment;
use super::wire::CWT_IAT;
use super::wire::CWT_ISS;
use super::wire::CWT_SUB;
use super::wire::HEADER_CWT_CLAIMS;

/// The subject every MCP-RE Signed Statement is about: one MCP call's evidence.
/// SCITT requires a `sub`, and a stable value keeps statements from this issuer
/// groupable without leaking anything about the call.
pub const STATEMENT_SUBJECT: &str = "mcp-re:call-evidence";

/// The `typ` of an MCP-RE Signed Statement payload.
pub const STATEMENT_CONTENT_TYPE: &str = "application/mcp-re-evidence+cbor";

/// A SCITT Signed Statement (RFC 9943): the issuer's signed claim about a call,
/// encoded as a tagged `COSE_Sign1` (RFC 9052 §4.2).
///
/// The wire form IS the COSE bytes. They are kept verbatim rather than re-derived,
/// because a signature is over the exact protected-header and payload bytes that
/// arrived: reconstructing them to verify would make the check depend on this
/// encoder reproducing another implementation's CBOR byte-for-byte, which is
/// precisely the canonicalization dependency COSE's `Sig_structure` exists to avoid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedStatement {
    /// The tagged `COSE_Sign1` bytes — what is transmitted and registered.
    cose: Vec<u8>,
    /// The issuer key id, from the protected header `kid`.
    issuer_kid: String,
    /// The decoded payload.
    commitment: EvidenceCommitment,
    /// The CWT `iat` from the protected header.
    issued_at: i64,
}

impl SignedStatement {
    /// The tagged `COSE_Sign1` bytes.
    pub fn to_cose(&self) -> &[u8] {
        &self.cose
    }
    /// The issuer key id this statement names. Naming is not trust: it is resolved
    /// through the trust seam before any signature is believed.
    pub fn issuer_kid(&self) -> &str {
        &self.issuer_kid
    }
    /// The evidence commitment the statement carries.
    pub fn commitment(&self) -> &EvidenceCommitment {
        &self.commitment
    }
    /// The CWT `iat` the statement was issued at.
    pub fn issued_at(&self) -> i64 {
        self.issued_at
    }

    /// Parse a tagged `COSE_Sign1` into a statement WITHOUT verifying its signature.
    ///
    /// Parsing is not acceptance: nothing here is trustworthy until
    /// [`verify_receipt_offline`] has checked the issuer signature over these exact
    /// bytes. It is separate so a malformed statement fails as malformed rather than
    /// as a bad signature.
    /// This statement with a DIFFERENT decoded commitment beside the same COSE bytes.
    ///
    /// `#[cfg(test)]`, and it is the point of the test it serves: a decoded view is a
    /// convenience, the signed bytes are the record, and a consumer that reads the view
    /// instead of re-deriving from the bytes is reading something nobody signed. There is
    /// no production path that produces such a value, and there must not be.
    #[cfg(test)]
    pub(super) fn with_edited_view(&self, commitment: EvidenceCommitment) -> Self {
        SignedStatement {
            commitment,
            ..self.clone()
        }
    }

    pub fn from_cose(bytes: &[u8]) -> Result<Self, HttpProfileError> {
        let sign1 = CoseSign1::from_tagged_slice(bytes)
            .map_err(|_| HttpProfileError::MalformedEvidence("scitt statement cose"))?;
        let issuer_kid = String::from_utf8(sign1.protected.header.key_id.clone())
            .map_err(|_| HttpProfileError::MalformedEvidence("scitt statement kid"))?;
        // RFC 9052 §3.1: a recipient that does not understand a critical parameter MUST
        // fail. This profile defines no critical statement parameter, so every label in
        // `crit` is one this verifier does not implement. Ignoring them is what would let
        // an issuer attach a scope restriction, an expiry or a revised evidence-profile
        // tag that MCP-RE accepts and disregards while a conforming reader refuses the
        // statement — two correct readers of one audit artifact disagreeing about whether
        // it is valid evidence. [`Receipt::from_cose`] holds the same rule.
        if !sign1.protected.header.crit.is_empty() {
            return Err(HttpProfileError::MalformedEvidence(
                "scitt statement critical header unsupported",
            ));
        }
        let issued_at = cwt_claim(&sign1.protected.header, CWT_IAT)
            .and_then(|v| v.as_integer())
            .and_then(|i| i64::try_from(i).ok())
            .ok_or(HttpProfileError::MalformedEvidence("scitt statement iat"))?;
        // RFC 9943 §6.1 REQUIRES `iss` and `sub` in the protected header, and they
        // have to be read, not merely written at issuance.
        //
        // `iss` must equal the `kid`. The kid is the selector this verifier resolves
        // trust through; `iss` is the identity an RFC 9943 consumer reads. Left
        // unbound, one signer can mint a statement that names a THIRD PARTY as issuer
        // — MCP-RE attributes it to the kid, a conforming reader attributes it to
        // `iss`, and two correct readers of an audit artifact disagree about who said
        // it. This is the same binding `admission.rs` makes between its header kid and
        // its claims issuer, for the same reason.
        let iss = cwt_claim(&sign1.protected.header, CWT_ISS)
            .and_then(|v| v.as_text().map(str::to_owned))
            .ok_or(HttpProfileError::MalformedEvidence("scitt statement iss"))?;
        if iss != issuer_kid {
            return Err(HttpProfileError::MalformedEvidence(
                "scitt statement iss does not match the signing kid",
            ));
        }
        // `sub` and the content type are the TYPE TAG. Without them, any other
        // COSE_Sign1 the same issuer key signs is accepted as MCP-RE call evidence as
        // soon as its payload happens to CBOR-decode into an `EvidenceCommitment` —
        // cross-protocol type confusion at the issuer-key seam.
        let sub = cwt_claim(&sign1.protected.header, CWT_SUB)
            .and_then(|v| v.as_text().map(str::to_owned))
            .ok_or(HttpProfileError::MalformedEvidence("scitt statement sub"))?;
        if sub != STATEMENT_SUBJECT {
            return Err(HttpProfileError::MalformedEvidence(
                "scitt statement sub is not mcp-re call evidence",
            ));
        }
        match &sign1.protected.header.content_type {
            Some(coset::ContentType::Text(t)) if t == STATEMENT_CONTENT_TYPE => {}
            _ => {
                return Err(HttpProfileError::MalformedEvidence(
                    "scitt statement content type is not the mcp-re evidence media type",
                ))
            }
        }
        let payload = sign1
            .payload
            .as_deref()
            .ok_or(HttpProfileError::MalformedEvidence(
                "scitt statement payload",
            ))?;
        let commitment: EvidenceCommitment = ciborium::from_reader(payload)
            .map_err(|_| HttpProfileError::MalformedEvidence("scitt statement commitment"))?;
        Ok(SignedStatement {
            cose: bytes.to_vec(),
            issuer_kid,
            commitment,
            issued_at,
        })
    }
}

/// Read one CWT claim out of a protected header's claims map.
fn cwt_claim(header: &coset::Header, key: i64) -> Option<Value> {
    let claims = header
        .rest
        .iter()
        .find(|(label, _)| *label == Label::Int(HEADER_CWT_CLAIMS))
        .map(|(_, v)| v)?;
    claims
        .as_map()?
        .iter()
        .find(|(k, _)| k.as_integer().is_some_and(|i| i == key.into()))
        .map(|(_, v)| v.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::ChainLabel;
    use crate::chain::IncompleteReason;
    use crate::scitt::commitment::EvidenceCommitment;
    use crate::scitt::fixtures::*;
    use crate::scitt::offline::verify_receipt_offline;
    use crate::scitt::prototype::PrototypeTransparencyService;

    /// The same `crit` rule on a Signed Statement. This profile defines no critical
    /// statement parameter, so any label marked critical is one this verifier does not
    /// implement: accepting the statement while disregarding the parameter is what RFC
    /// 9052 §3.1 forbids, and is how two conforming readers of one audit artifact end up
    /// disagreeing about whether it is valid evidence.
    #[test]
    fn a_critical_header_on_a_signed_statement_is_refused() {
        let st = statement(EvidenceCommitment::from_reconstruction(
            &recon(ChainLabel::Complete, 1),
            None,
            None,
        ));
        SignedStatement::from_cose(st.to_cose()).expect("the issued statement parses");

        let mut sign1 = CoseSign1::from_tagged_slice(st.to_cose()).expect("parses");
        sign1
            .protected
            .header
            .crit
            .push(coset::RegisteredLabelWithPrivate::Text(
                "evidence-profile-revision".to_owned(),
            ));
        sign1.protected.original_data = None;
        let bytes = sign1.to_tagged_vec().expect("encode");
        assert_eq!(
            SignedStatement::from_cose(&bytes).unwrap_err(),
            HttpProfileError::MalformedEvidence("scitt statement critical header unsupported"),
        );
    }

    /// A statement whose decoded VIEW is edited but whose signed bytes are not is
    /// still the statement that was signed. The verifier reads the bytes, never the
    /// view — this pins that, because the opposite would let a caller "verify" a
    /// record it had quietly rewritten in memory.
    #[test]
    fn editing_a_decoded_view_does_not_change_what_was_signed() {
        let st = statement(EvidenceCommitment::from_reconstruction(
            &recon(ChainLabel::Complete, 1),
            None,
            None,
        ));
        let mut svc = PrototypeTransparencyService::new(TS_KID);
        let receipt = register(&mut svc, &st);

        let lying = EvidenceCommitment::from_reconstruction(
            &recon(
                ChainLabel::Incomplete {
                    hop: 0,
                    reason: IncompleteReason::MissingContinuation,
                },
                1,
            ),
            None,
            None,
        );
        let edited = st.with_edited_view(lying);
        // It verifies, because the COSE bytes are untouched — and the commitment a
        // consumer should read is the one recovered from those bytes.
        verify_receipt_offline(&edited, &receipt, ir(), tr()).expect("the signed bytes are intact");
        let recovered = SignedStatement::from_cose(edited.to_cose()).expect("parses");
        assert_eq!(recovered.commitment().chain_label(), "complete");
    }
}
