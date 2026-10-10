// SPDX-License-Identifier: Apache-2.0
//! SCITT statement typing — authority B.
//!
//! One fact: **this `COSE_Sign1` is MCP-RE call evidence, attributed to the key that signed
//! it.** `SignedStatement` was already sealed at the census: private representation,
//! `from_cose` the only producer, and this module is where that stays true.

mod issuance;

/// Reading a tagged `COSE_Sign1` into a statement, and refusing what this profile
/// cannot use.
mod parse;

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
    /// The RFC 9052 §4.4 `Sig_structure` these bytes were signed over:
    /// `["Signature1", protected, external_aad, payload]`.
    ///
    /// Carried on the value rather than re-derived where it is wanted, because there is
    /// exactly one constructor and it already holds the parsed envelope — so holding a
    /// `SignedStatement` means the structure is known, with no clause about which callers
    /// remembered to recompute it. A transparency service that keys its log on the signing
    /// ACT rather than on the transmitted octets hashes this
    /// ([`super::StatementLeafProfile::SigStructureDigest`]).
    sig_structure: Vec<u8>,
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
    /// The RFC 9052 §4.4 `Sig_structure` this statement was signed over.
    ///
    /// `pub(in crate::scitt)`: the one legitimate consumer is the leaf rule of a service
    /// that logs the signing ACT, and it is not something a caller outside this profile
    /// has a use for.
    pub(in crate::scitt) fn sig_structure(&self) -> &[u8] {
        &self.sig_structure
    }

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::ChainLabel;
    use crate::chain::IncompleteReason;
    use crate::error::HttpProfileError;
    use crate::scitt::commitment::EvidenceCommitment;
    use crate::scitt::fixtures::*;
    use crate::scitt::offline::verify_receipt_offline;
    use crate::scitt::prototype::PrototypeTransparencyService;
    use coset::CoseSign1;
    use coset::TaggedCborSerializable;

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

    /// The decoded commitment and the signed payload octets are one-to-one: octets after
    /// the one CBOR item are signed but unread, so a second reader could assign them a
    /// meaning this one never sees.
    #[test]
    fn a_statement_payload_with_trailing_octets_is_refused() {
        let st = statement(EvidenceCommitment::from_reconstruction(
            &recon(ChainLabel::Complete, 1),
            None,
            None,
        ));
        SignedStatement::from_cose(st.to_cose()).expect("the issued statement parses");

        let mut sign1 = CoseSign1::from_tagged_slice(st.to_cose()).expect("parses");
        sign1.payload.as_mut().expect("attached payload").push(0x00);
        let bytes = sign1.to_tagged_vec().expect("encode");
        assert_eq!(
            SignedStatement::from_cose(&bytes).expect_err("trailing octets refused"),
            HttpProfileError::MalformedEvidence("scitt statement commitment trailing octets"),
        );
    }

    /// A claim present twice has no single value to attribute the statement by.
    #[test]
    fn a_duplicate_cwt_claim_in_a_signed_statement_is_refused() {
        let st = statement(EvidenceCommitment::from_reconstruction(
            &recon(ChainLabel::Complete, 1),
            None,
            None,
        ));
        SignedStatement::from_cose(st.to_cose()).expect("the issued statement parses");

        let mut sign1 = CoseSign1::from_tagged_slice(st.to_cose()).expect("parses");
        let claims = sign1
            .protected
            .header
            .rest
            .iter_mut()
            .find(|(label, _)| *label == coset::Label::Int(HEADER_CWT_CLAIMS))
            .and_then(|(_, v)| v.as_map_mut())
            .expect("cwt claims map");
        claims.push((
            ciborium::Value::Integer(CWT_ISS.into()),
            ciborium::Value::Text("a-third-party".to_owned()),
        ));
        sign1.protected.original_data = None;
        let bytes = sign1.to_tagged_vec().expect("encode");
        assert_eq!(
            SignedStatement::from_cose(&bytes).expect_err("duplicate iss refused"),
            HttpProfileError::MalformedEvidence("scitt statement duplicate cwt claim"),
        );
    }
}
