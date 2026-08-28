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

impl Receipt {
    pub fn from_cose(bytes: &[u8]) -> Result<Self, HttpProfileError> {
        let sign1 = CoseSign1::from_tagged_slice(bytes)
            .map_err(|_| HttpProfileError::MalformedEvidence("scitt receipt cose"))?;
        let ts_kid = String::from_utf8(sign1.protected.header.key_id.clone())
            .map_err(|_| HttpProfileError::MalformedEvidence("scitt receipt kid"))?;
        // Every critical label must be one this verifier understands. This is what makes
        // the v1→v2 transition safe in the direction the profile pin cannot cover: a v2
        // receipt marks its position parameter critical, so an implementation that only
        // knows v1 refuses it instead of verifying the inclusion proof and silently
        // ignoring the commitment that was supposed to bind the position.
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
        let position_commitment = sign1
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
            .transpose()?;
        // The verifiable-data-structure must be one this verifier implements. An
        // unrecognized structure is refused, never walked as if it were RFC 9162:
        // a proof format this code does not implement cannot be checked by it.
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
        // The proof lives at `vdp` → `inclusion-proof` → array of bstr, each holding
        // CBOR `inclusion-proof-content`. Only the first is read: a Receipt carrying
        // several inclusion proofs proves inclusion of several entries, and this
        // verifier is asked about exactly one statement.
        let proof = sign1
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
            .ok_or(HttpProfileError::MalformedEvidence("scitt inclusion proof"))?;
        let decoded: Value = ciborium::from_reader(proof.as_slice())
            .map_err(|_| HttpProfileError::MalformedEvidence("scitt inclusion proof cbor"))?;
        let parts = decoded
            .as_array()
            .ok_or(HttpProfileError::MalformedEvidence(
                "scitt inclusion proof shape",
            ))?;
        let [tree_size, leaf_index, path] = parts.as_slice() else {
            return Err(HttpProfileError::MalformedEvidence(
                "scitt inclusion proof shape",
            ));
        };
        let tree_size = as_u64(tree_size)?;
        let leaf_index = as_u64(leaf_index)?;
        // RFC 9942 §5.2, quoting RFC 9162: a leaf index at or beyond the tree size
        // fails proof verification. Refused at parse so no fold is ever attempted over
        // an index the signed tree head cannot contain.
        if leaf_index >= tree_size {
            return Err(HttpProfileError::MalformedEvidence(
                "scitt inclusion proof leaf index outside tree",
            ));
        }
        let inclusion_path = path
            .as_array()
            .ok_or(HttpProfileError::MalformedEvidence("scitt inclusion path"))?
            .iter()
            .map(|h| {
                h.as_bytes().filter(|b| b.len() == 32).cloned().ok_or(
                    HttpProfileError::MalformedEvidence("scitt inclusion path node"),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        // Attached: the payload IS the Merkle Tree Hash, so it must be one. Detached
        // (RFC 9942 §4.4): absent, and the root is re-derived at verify time. A payload
        // that is present but not a 32-octet hash is neither form and is refused.
        let root = match sign1.payload.as_deref() {
            None => None,
            Some(p) if p.len() == 32 => Some(p.to_vec()),
            Some(_) => {
                return Err(HttpProfileError::MalformedEvidence("scitt receipt root"));
            }
        };
        Ok(Receipt {
            cose: bytes.to_vec(),
            ts_kid,
            tree_size,
            leaf_index,
            inclusion_path,
            position_commitment,
            root,
        })
    }
}
