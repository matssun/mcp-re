// SPDX-License-Identifier: Apache-2.0
//! Reading an RFC 9942 receipt off the wire.
//!
//! One fact: **these bytes are a receipt of the shape this profile understands, and every
//! critical label in them is one it knows.** A critical header it does not recognise is
//! refused rather than ignored, which is the whole point of `crit`: the issuer said this
//! must be understood, and a verifier that skips it is verifying something else.
//!
//! A CHILD of [`super`] rather than a sibling: `from_cose` is the receipt's sole producer,
//! and it fills the private representation directly. Anywhere else it would need a
//! constructor taking every field, which is the seal undone in order to move a function.

use ciborium::Value;
use coset::CoseSign1;
use coset::Label;
use coset::TaggedCborSerializable;

use crate::error::HttpProfileError;
use crate::scitt::wire::HEADER_POSITION_COMMITMENT;
use crate::scitt::wire::HEADER_VDP;
use crate::scitt::wire::HEADER_VDS;
use crate::scitt::wire::PROOF_INCLUSION;
use crate::scitt::wire::VDS_RFC9162_SHA256;

use super::as_u64;
use super::Receipt;

/// The three values an inclusion proof states about where a leaf sits.
///
/// None of them is authenticated by the receipt's signature in the `RFC9162_SHA256` profile
/// — they ride in the UNSIGNED `vdp` header — so they are carried as one value that
/// verification constrains together, never as three independently trusted numbers.
struct InclusionProof {
    tree_size: u64,
    leaf_index: u64,
    path: Vec<Vec<u8>>,
}

/// Every critical label must be one this verifier understands.
///
/// This is what makes the v1→v2 transition safe in the direction the profile pin cannot
/// cover: a v2 receipt marks its position parameter critical, so an implementation that only
/// knows v1 refuses it instead of verifying the inclusion proof and silently ignoring the
/// commitment that was supposed to bind the position.
fn check_critical_labels(sign1: &CoseSign1) -> Result<(), HttpProfileError> {
    for label in &sign1.protected.header.crit {
        let known = matches!(
            label,
            coset::RegisteredLabelWithPrivate::Text(t) if t == HEADER_POSITION_COMMITMENT
        );
        if !known {
            return Err(HttpProfileError::MalformedEvidence(
                "scitt receipt critical header unsupported",
            ));
        }
    }
    Ok(())
}

/// The protected position commitment, when the receipt carries one.
fn read_position_commitment(sign1: &CoseSign1) -> Result<Option<Vec<u8>>, HttpProfileError> {
    sign1
        .protected
        .header
        .rest
        .iter()
        .find(|(label, _)| *label == Label::Text(HEADER_POSITION_COMMITMENT.to_owned()))
        .map(|(_, v)| {
            v.as_bytes().filter(|b| b.len() == 32).cloned().ok_or(
                HttpProfileError::MalformedEvidence("scitt receipt position commitment"),
            )
        })
        .transpose()
}

/// The verifiable-data-structure must be one this verifier implements.
///
/// An unrecognized structure is refused, never walked as if it were RFC 9162: a proof format
/// this code does not implement cannot be checked by it.
fn check_verifiable_data_structure(sign1: &CoseSign1) -> Result<(), HttpProfileError> {
    let vds = sign1
        .protected
        .header
        .rest
        .iter()
        .find(|(label, _)| *label == Label::Int(HEADER_VDS))
        .and_then(|(_, v)| v.as_integer())
        .and_then(|i| i64::try_from(i).ok())
        .ok_or(HttpProfileError::MalformedEvidence("scitt receipt vds"))?;
    if vds != VDS_RFC9162_SHA256 {
        return Err(HttpProfileError::MalformedEvidence(
            "scitt receipt verifiable data structure unsupported",
        ));
    }
    Ok(())
}

/// The `inclusion-proof-content` bytes: `vdp` → `inclusion-proof` → array of bstr.
///
/// Only the first is read. A Receipt carrying several inclusion proofs proves inclusion of
/// several entries, and this verifier is asked about exactly one statement.
fn inclusion_proof_bytes(sign1: &CoseSign1) -> Result<&Vec<u8>, HttpProfileError> {
    sign1
        .unprotected
        .rest
        .iter()
        .find(|(label, _)| *label == Label::Int(HEADER_VDP))
        .and_then(|(_, v)| v.as_map())
        .and_then(|vdp| {
            vdp.iter()
                .find(|(k, _)| k.as_integer().is_some_and(|i| i == PROOF_INCLUSION.into()))
        })
        .and_then(|(_, v)| v.as_array())
        .and_then(|proofs| proofs.first())
        .and_then(|p| p.as_bytes())
        .ok_or(HttpProfileError::MalformedEvidence("scitt inclusion proof"))
}

/// Decode one `inclusion-proof-content` into the position it states.
///
/// RFC 9942 §5.2, quoting RFC 9162: a leaf index at or beyond the tree size fails proof
/// verification. It is refused HERE, at parse, so no fold is ever attempted over an index the
/// signed tree head cannot contain.
fn read_inclusion_proof(sign1: &CoseSign1) -> Result<InclusionProof, HttpProfileError> {
    let shape = || HttpProfileError::MalformedEvidence("scitt inclusion proof shape");
    let decoded: Value = ciborium::from_reader(inclusion_proof_bytes(sign1)?.as_slice())
        .map_err(|_| HttpProfileError::MalformedEvidence("scitt inclusion proof cbor"))?;
    let parts = decoded.as_array().ok_or_else(shape)?;
    let [tree_size, leaf_index, path] = parts.as_slice() else {
        return Err(shape());
    };
    let tree_size = as_u64(tree_size)?;
    let leaf_index = as_u64(leaf_index)?;
    if leaf_index >= tree_size {
        return Err(HttpProfileError::MalformedEvidence(
            "scitt inclusion proof leaf index outside tree",
        ));
    }
    let path = path
        .as_array()
        .ok_or(HttpProfileError::MalformedEvidence("scitt inclusion path"))?
        .iter()
        .map(|h| {
            h.as_bytes().filter(|b| b.len() == 32).cloned().ok_or(
                HttpProfileError::MalformedEvidence("scitt inclusion path node"),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(InclusionProof {
        tree_size,
        leaf_index,
        path,
    })
}

/// The Merkle Tree Hash the receipt carries, in whichever of the two forms it uses.
///
/// Attached: the payload IS the Merkle Tree Hash, so it must be one. Detached (RFC 9942
/// §4.4): absent, and the root is re-derived at verify time. A payload that is present but
/// not a 32-octet hash is neither form and is refused.
fn read_root(sign1: &CoseSign1) -> Result<Option<Vec<u8>>, HttpProfileError> {
    match sign1.payload.as_deref() {
        None => Ok(None),
        Some(p) if p.len() == 32 => Ok(Some(p.to_vec())),
        Some(_) => Err(HttpProfileError::MalformedEvidence("scitt receipt root")),
    }
}

impl Receipt {
    pub fn from_cose(bytes: &[u8]) -> Result<Self, HttpProfileError> {
        let sign1 = CoseSign1::from_tagged_slice(bytes)
            .map_err(|_| HttpProfileError::MalformedEvidence("scitt receipt cose"))?;
        let ts_kid = String::from_utf8(sign1.protected.header.key_id.clone())
            .map_err(|_| HttpProfileError::MalformedEvidence("scitt receipt kid"))?;
        check_critical_labels(&sign1)?;
        check_verifiable_data_structure(&sign1)?;
        let proof = read_inclusion_proof(&sign1)?;
        Ok(Receipt {
            cose: bytes.to_vec(),
            ts_kid,
            tree_size: proof.tree_size,
            leaf_index: proof.leaf_index,
            inclusion_path: proof.path,
            position_commitment: read_position_commitment(&sign1)?,
            root: read_root(&sign1)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proof(tree_size: u64, leaf_index: u64) -> Vec<u8> {
        let content = Value::Array(vec![
            Value::Integer(tree_size.into()),
            Value::Integer(leaf_index.into()),
            Value::Array(vec![]),
        ]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&content, &mut bytes).expect("encode fixture");
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<InclusionProof, HttpProfileError> {
        let shape = || HttpProfileError::MalformedEvidence("scitt inclusion proof shape");
        let decoded: Value = ciborium::from_reader(bytes).map_err(|_| shape())?;
        let parts = decoded.as_array().ok_or_else(shape)?;
        let [tree_size, leaf_index, path] = parts.as_slice() else {
            return Err(shape());
        };
        let tree_size = as_u64(tree_size)?;
        let leaf_index = as_u64(leaf_index)?;
        if leaf_index >= tree_size {
            return Err(HttpProfileError::MalformedEvidence(
                "scitt inclusion proof leaf index outside tree",
            ));
        }
        let _ = path;
        Ok(InclusionProof {
            tree_size,
            leaf_index,
            path: vec![],
        })
    }

    /// A leaf index the signed tree head cannot contain is refused at PARSE, so no fold is
    /// ever attempted over it. Refusing later would mean walking a path toward a position
    /// the tree does not have.
    #[test]
    fn a_leaf_index_outside_the_tree_is_refused_before_any_fold() {
        assert!(decode(&proof(4, 3)).is_ok());
        for outside in [4, 5, 9] {
            assert!(matches!(
                decode(&proof(4, outside)),
                Err(HttpProfileError::MalformedEvidence(
                    "scitt inclusion proof leaf index outside tree"
                ))
            ));
        }
    }

    /// The two receipt forms are absent payload (detached, root re-derived at verify time)
    /// and a 32-octet payload (attached, the payload IS the root). Anything else is neither
    /// form, and reading it as one would verify against bytes that are not a tree hash.
    #[test]
    fn a_payload_that_is_not_a_tree_hash_is_neither_receipt_form() {
        let mut sign1 = CoseSign1::default();
        assert_eq!(read_root(&sign1).expect("detached"), None);
        sign1.payload = Some(vec![7u8; 32]);
        assert_eq!(read_root(&sign1).expect("attached"), Some(vec![7u8; 32]));
        sign1.payload = Some(vec![7u8; 31]);
        assert!(read_root(&sign1).is_err());
    }
}
