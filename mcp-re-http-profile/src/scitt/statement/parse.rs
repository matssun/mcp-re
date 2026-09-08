// SPDX-License-Identifier: Apache-2.0
//! Reading a tagged `COSE_Sign1` into a Signed Statement.
//!
//! One fact: **these bytes are an MCP-RE Signed Statement of the shape this profile
//! understands, and every claim it rests on is present and agrees with the envelope.**
//!
//! A CHILD of [`super`] rather than a sibling, for the reason the receipt's parser is one:
//! `from_cose` is the statement's SOLE producer — issuance itself ends by calling it — and
//! it fills the private representation directly. Anywhere else it would need a constructor
//! taking every field, which is the seal undone in order to move a function.
//!
//! Parsing is not acceptance. Nothing that comes out of here is trustworthy until the
//! issuer signature over these exact bytes has been checked; what this module establishes
//! is that the bytes are the right SHAPE, so a malformed statement fails as malformed
//! rather than as a bad signature.

use ciborium::Value;
use coset::CoseSign1;
use coset::Label;
use coset::TaggedCborSerializable;

use crate::error::HttpProfileError;

use super::EvidenceCommitment;
use super::SignedStatement;
use super::CWT_IAT;
use super::CWT_ISS;
use super::CWT_SUB;
use super::HEADER_CWT_CLAIMS;
use super::STATEMENT_CONTENT_TYPE;
use super::STATEMENT_SUBJECT;

impl SignedStatement {
    pub fn from_cose(bytes: &[u8]) -> Result<Self, HttpProfileError> {
        let sign1 = CoseSign1::from_tagged_slice(bytes)
            .map_err(|_| HttpProfileError::MalformedEvidence("scitt statement cose"))?;
        let issuer_kid = String::from_utf8(sign1.protected.header.key_id.clone())
            .map_err(|_| HttpProfileError::MalformedEvidence("scitt statement kid"))?;
        let issued_at = checked_claims(&sign1, &issuer_kid)?;
        let payload = sign1
            .payload
            .as_deref()
            .ok_or(HttpProfileError::MalformedEvidence(
                "scitt statement payload",
            ))?;
        let commitment: EvidenceCommitment = ciborium::from_reader(payload)
            .map_err(|_| HttpProfileError::MalformedEvidence("scitt statement commitment"))?;
        Ok(SignedStatement {
            sig_structure: sig_structure_of(&sign1)?,
            cose: bytes.to_vec(),
            issuer_kid,
            commitment,
            issued_at,
        })
    }
}

/// The claims a statement is ATTRIBUTED BY, checked against the envelope that carries them.
///
/// Its own function because it is one obligation with several parts, and the parts are only
/// meaningful together: every check here is about whether this `COSE_Sign1` is an MCP-RE
/// Signed Statement made by the key its header names, and nothing here reads the payload.
///
/// * **`crit` must be empty.** RFC 9052 §3.1: a recipient that does not understand a
///   critical parameter MUST fail. This profile defines none, so every label in `crit` is
///   one this verifier does not implement. Ignoring them is what would let an issuer attach
///   a scope restriction, an expiry or a revised evidence-profile tag that MCP-RE accepts
///   and disregards while a conforming reader refuses the statement — two correct readers of
///   one audit artifact disagreeing about whether it is valid evidence. The receipt parser
///   holds the same rule.
/// * **`iss` must equal the `kid`.** RFC 9943 §6.1 REQUIRES `iss` and `sub`, and they have to
///   be READ rather than merely written at issuance. The kid is the selector this verifier
///   resolves trust through; `iss` is the identity an RFC 9943 consumer reads. Left unbound,
///   one signer can mint a statement naming a THIRD PARTY as issuer — MCP-RE attributes it to
///   the kid, a conforming reader to `iss`, and two correct readers disagree about who said
///   it. `admission.rs` makes the same binding for the same reason.
/// * **`sub` and the content type are the TYPE TAG.** Without them, any other `COSE_Sign1`
///   the same issuer key signs is accepted as MCP-RE call evidence as soon as its payload
///   happens to CBOR-decode into an `EvidenceCommitment` — cross-protocol type confusion at
///   the issuer-key seam.
///
/// Returns the CWT `iat`, which is the one claim that is a value rather than a check.
fn checked_claims(sign1: &CoseSign1, issuer_kid: &str) -> Result<i64, HttpProfileError> {
    if !sign1.protected.header.crit.is_empty() {
        return Err(HttpProfileError::MalformedEvidence(
            "scitt statement critical header unsupported",
        ));
    }
    let issued_at = cwt_claim(&sign1.protected.header, CWT_IAT)
        .and_then(|v| v.as_integer())
        .and_then(|i| i64::try_from(i).ok())
        .ok_or(HttpProfileError::MalformedEvidence("scitt statement iat"))?;
    let iss = cwt_claim(&sign1.protected.header, CWT_ISS)
        .and_then(|v| v.as_text().map(str::to_owned))
        .ok_or(HttpProfileError::MalformedEvidence("scitt statement iss"))?;
    if iss != issuer_kid {
        return Err(HttpProfileError::MalformedEvidence(
            "scitt statement iss does not match the signing kid",
        ));
    }
    let sub = cwt_claim(&sign1.protected.header, CWT_SUB)
        .and_then(|v| v.as_text().map(str::to_owned))
        .ok_or(HttpProfileError::MalformedEvidence("scitt statement sub"))?;
    if sub != STATEMENT_SUBJECT {
        return Err(HttpProfileError::MalformedEvidence(
            "scitt statement sub is not mcp-re call evidence",
        ));
    }
    match &sign1.protected.header.content_type {
        Some(coset::ContentType::Text(t)) if t == STATEMENT_CONTENT_TYPE => Ok(issued_at),
        _ => Err(HttpProfileError::MalformedEvidence(
            "scitt statement content type is not the mcp-re evidence media type",
        )),
    }
}

/// The exact octets a conforming verifier reconstructs to check this statement's signature.
///
/// `coset` builds them rather than this module assembling the array by hand: a second
/// construction of the same structure is a second chance to disagree with every other COSE
/// implementation about it, which is the canonicalization dependency the structure exists to
/// remove. The closure is a capture, not a verification — nothing here checks a signature.
fn sig_structure_of(sign1: &CoseSign1) -> Result<Vec<u8>, HttpProfileError> {
    let mut sig_structure = Vec::new();
    let built: Result<(), ()> = sign1.verify_signature(&[], |_signature, signed| {
        sig_structure = signed.to_vec();
        Ok(())
    });
    if built.is_err() {
        return Err(HttpProfileError::MalformedEvidence(
            "scitt statement sig structure",
        ));
    }
    Ok(sig_structure)
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
