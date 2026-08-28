// SPDX-License-Identifier: Apache-2.0
//! Issuing a Signed Statement.
//!
//! One fact: **the bytes an MCP-RE issuer signs, and the header that types them.** It is the
//! other direction from [`super`], which READS a statement, and the two are separate because
//! their obligations are opposite: reading must refuse everything it does not recognise,
//! issuing must emit exactly one spelling of what it means.
//!
//! Signing is a CLOSURE the caller supplies, so no key material passes through here.

use ciborium::Value;
use coset::iana;
use coset::CoseSign1Builder;
use coset::HeaderBuilder;
use coset::TaggedCborSerializable;

use crate::error::HttpProfileError;
use crate::scitt::commitment::EvidenceCommitment;
use crate::scitt::wire::CWT_IAT;
use crate::scitt::wire::CWT_ISS;
use crate::scitt::wire::CWT_SUB;
use crate::scitt::wire::HEADER_CWT_CLAIMS;

use super::SignedStatement;
use super::STATEMENT_CONTENT_TYPE;
use super::STATEMENT_SUBJECT;

/// Issue a Signed Statement over `commitment`, signing with the issuer via the
/// external-signer seam (the issuer key never enters this crate).
///
/// The signature is over the RFC 9052 §4.4 `Sig_structure`
/// (`["Signature1", protected, external_aad, payload]`), which is what makes it
/// verifiable by any COSE implementation rather than only by this one.
pub fn issue_signed_statement(
    issuer_kid: &str,
    commitment: EvidenceCommitment,
    issued_at: i64,
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, HttpProfileError>,
) -> Result<SignedStatement, HttpProfileError> {
    let mut payload = Vec::new();
    ciborium::into_writer(&commitment, &mut payload)
        .map_err(|_| HttpProfileError::MalformedEvidence("scitt commitment encode"))?;

    let claims = Value::Map(vec![
        (
            Value::Integer(CWT_ISS.into()),
            Value::Text(issuer_kid.to_owned()),
        ),
        (
            Value::Integer(CWT_SUB.into()),
            Value::Text(STATEMENT_SUBJECT.to_owned()),
        ),
        (
            Value::Integer(CWT_IAT.into()),
            Value::Integer(issued_at.into()),
        ),
    ]);
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::EdDSA)
        .key_id(issuer_kid.as_bytes().to_vec())
        .content_type(STATEMENT_CONTENT_TYPE.to_owned())
        .value(HEADER_CWT_CLAIMS, claims)
        .build();

    // `create_signature` builds the Sig_structure and hands it to the signer, so the
    // bytes signed are the ones a conforming verifier will reconstruct.
    let mut failure = None;
    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload)
        .create_signature(&[], |pt| match sign(pt) {
            Ok(sig) => sig,
            Err(e) => {
                failure = Some(e);
                Vec::new()
            }
        })
        .build();
    if let Some(e) = failure {
        return Err(e);
    }

    let cose = sign1
        .to_tagged_vec()
        .map_err(|_| HttpProfileError::MalformedEvidence("scitt statement encode"))?;
    SignedStatement::from_cose(&cose)
}
