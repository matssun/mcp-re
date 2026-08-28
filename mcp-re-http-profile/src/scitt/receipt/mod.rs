// SPDX-License-Identifier: Apache-2.0
//! Receipt wire form — authority C.
//!
//! One fact: **these are a well-formed RFC 9942 receipt's fields.** Parsing only; whether
//! the proof it carries actually folds is [`super::merkle`]'s, and whether the whole thing
//! verifies is [`super::offline`]'s.
//!
//! `Receipt` was already sealed at the census — private representation, `from_cose` the
//! only producer — and that is what lets its accessors state what they state without
//! re-reading anything.

use ciborium::Value;

use crate::error::HttpProfileError;

mod parse;

/// A COSE Receipt (RFC 9942): proof that a Signed Statement was registered on a
/// transparency service, as a tagged `COSE_Sign1` signed by the service over the
/// Merkle root.
///
/// The inclusion proof rides in the UNPROTECTED header, which is correct rather than
/// lax: the proof is not a claim the service signs, it is the path a verifier walks
/// to re-derive the root the service DID sign. Tampering with it cannot forge
/// inclusion — it only makes the derived root fail to match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    /// The tagged `COSE_Sign1` bytes — what is transmitted and archived.
    cose: Vec<u8>,
    /// The transparency service key id, from the protected header `kid`.
    ts_kid: String,
    /// The log size the receipt states.
    ///
    /// NOT authenticated. In the `RFC9162_SHA256` profile the receipt payload is the
    /// bare Merkle Tree Hash (RFC 9942 §5), never an RFC 9162 signed tree head, so the
    /// transparency service's signature covers the root and nothing else; this value
    /// rides in the UNSIGNED `vdp` header. Verification constrains it only to a
    /// position the inclusion path can reach — see
    /// [`rfc9162_root_from_inclusion_proof`] for exactly how much that is and how
    /// much it is not.
    tree_size: u64,
    /// The registered leaf's index in the log. NOT authenticated, for the same reason
    /// as [`Receipt::tree_size`].
    leaf_index: u64,
    /// Sibling hashes from leaf to root.
    inclusion_path: Vec<Vec<u8>>,
    /// The protected position commitment, when the receipt carries one.
    ///
    /// Present means the issuing service bound `(profile, log identity, vds, tree_size,
    /// leaf_index, root)` under its signature; absent means it did not, and the position
    /// is a transport hint. Which of the two is acceptable is the pinned
    /// [`ReceiptPositionProfile`]'s decision, not this receipt's.
    position_commitment: Option<Vec<u8>>,
    /// The Merkle root the receipt signs, when it is ATTACHED as the payload.
    ///
    /// `None` for the detached form (RFC 9942 §4.4, and the shape its own Figure 6
    /// shows). Detached is not a weaker receipt: the root is then re-derived from the
    /// statement and the inclusion path, and the signature is checked over THAT — so the
    /// receipt cannot even be verified without the statement it is about, which is a
    /// tighter binding than a receipt carrying its own answer.
    root: Option<Vec<u8>>,
}

impl Receipt {
    /// The tagged `COSE_Sign1` bytes.
    pub fn to_cose(&self) -> &[u8] {
        &self.cose
    }
    /// The transparency service key id this receipt names.
    pub fn ts_kid(&self) -> &str {
        &self.ts_kid
    }
    /// The log size the receipt STATES.
    ///
    /// Authenticated only when the receipt carries a position commitment AND
    /// [`verify_receipt_offline`] has checked it under a
    /// [`ReceiptPositionProfile::Bound`] pin. Without one this is a transport hint and
    /// no ordering, anchoring, freshness or log-maturity reasoning may rest on it: the
    /// service signs the Merkle Tree Hash alone, and a root reached by a path of length
    /// `k` is reachable from a whole class of `(leaf_index, tree_size)` pairs, so a
    /// relayer may restate a small log's receipt as a position in a larger one and it
    /// still verifies. [`rfc9162_root_from_inclusion_proof`] gives the measured extent.
    pub fn tree_size(&self) -> u64 {
        self.tree_size
    }
    /// The leaf index the receipt STATES. Authenticated on exactly the same condition as
    /// [`Self::tree_size`], and by the same commitment — the two are bound together, not
    /// separately.
    pub fn leaf_index(&self) -> u64 {
        self.leaf_index
    }
    /// Whether this receipt carries a protected position commitment.
    /// The inclusion path, as the fold consumes it.
    ///
    /// `pub(super)`, not `pub`: this is the raw proof, and it means nothing without the
    /// index and the size it is folded against. [`super::offline`] is the one consumer
    /// that has all three, and the widening exists so it does not have to hold a copy.
    pub(super) fn inclusion_path(&self) -> &[Vec<u8>] {
        &self.inclusion_path
    }

    /// The root the receipt commits to, when it carries one.
    ///
    /// `None` is a DETACHED receipt, where the fold's output IS the signature payload —
    /// which is why the composition asks this rather than assuming a root is present.
    pub(super) fn committed_root(&self) -> Option<&[u8]> {
        self.root.as_deref()
    }

    /// The signed position commitment, when the receipt carries one (C080).
    pub(super) fn position_commitment(&self) -> Option<&[u8]> {
        self.position_commitment.as_deref()
    }

    pub fn is_position_bound(&self) -> bool {
        self.position_commitment.is_some()
    }

    /// Parse a tagged `COSE_Sign1` receipt WITHOUT verifying it.
    /// This receipt with a different inclusion path, leaving the signed bytes untouched.
    ///
    /// `#[cfg(test)]`. The proof rides in the UNPROTECTED header, which is exactly why the
    /// tamper is worth testing — and exactly why there is no production constructor for
    /// it: `from_cose` is the only way a receipt enters the process.
    #[cfg(test)]
    pub(super) fn with_forged_inclusion_path(&self, inclusion_path: Vec<Vec<u8>>) -> Self {
        Receipt {
            inclusion_path,
            ..self.clone()
        }
    }
}

pub(super) fn as_u64(v: &Value) -> Result<u64, HttpProfileError> {
    v.as_integer()
        .and_then(|i| u64::try_from(i).ok())
        .ok_or(HttpProfileError::MalformedEvidence("scitt receipt integer"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::ChainLabel;
    use crate::scitt::commitment::EvidenceCommitment;
    use crate::scitt::fixtures::*;
    use crate::scitt::prototype::PrototypeTransparencyService;
    use crate::scitt::wire::HEADER_VDP;
    use crate::scitt::wire::HEADER_VDS;
    use crate::scitt::wire::PROOF_INCLUSION;
    use crate::scitt::wire::VDS_RFC9162_SHA256;
    use ciborium::Value;
    use coset::iana;
    use coset::CoseSign1;
    use coset::CoseSign1Builder;
    use coset::HeaderBuilder;
    use coset::Label;
    use coset::TaggedCborSerializable;

    /// The `crit` rule, which is what stops an old implementation from verifying a v2
    /// receipt while ignoring the commitment that binds its position. An unknown
    /// critical label is refused at parse, before any signature work.
    #[test]
    fn an_unknown_critical_header_is_refused() {
        let st = statement(EvidenceCommitment::from_reconstruction(
            &recon(ChainLabel::Complete, 1),
            None,
            None,
        ));
        let mut svc = PrototypeTransparencyService::new(TS_KID);
        let receipt = register(&mut svc, &st);
        let mut sign1 = CoseSign1::from_tagged_slice(receipt.to_cose()).expect("parses");
        sign1
            .protected
            .header
            .crit
            .push(coset::RegisteredLabelWithPrivate::Text(
                "some-future-parameter".to_owned(),
            ));
        sign1.protected.original_data = None;
        let bytes = sign1.to_tagged_vec().expect("encode");
        assert_eq!(
            Receipt::from_cose(&bytes).unwrap_err(),
            HttpProfileError::MalformedEvidence("scitt receipt critical header unsupported"),
        );
    }

    /// The emitted Receipt matches RFC 9942 §5.2.1 Figures 4 and 5 read as raw CBOR,
    /// not as re-parsed by this module's own decoder.
    ///
    /// Round-tripping through our encoder and decoder agrees with itself whatever
    /// labels it picks, so it cannot detect using the wrong ones — which is how
    /// draft-era `vds`/`vdp` labels survive until a foreign implementation rejects
    /// everything we emit. These assertions name the numbers the RFC names.
    #[test]
    fn a_receipt_carries_the_rfc9942_header_labels_and_nesting() {
        let st = statement(EvidenceCommitment::from_reconstruction(
            &recon(ChainLabel::Complete, 2),
            None,
            None,
        ));
        let mut svc = PrototypeTransparencyService::new(TS_KID);
        // Two leaves, so the inclusion path is non-empty as `[ + bstr ]` requires.
        let receipt = {
            let other = statement(EvidenceCommitment::from_reconstruction(
                &recon(ChainLabel::Complete, 1),
                None,
                None,
            ));
            register(&mut svc, &other);
            register(&mut svc, &st)
        };

        let sign1 = CoseSign1::from_tagged_slice(receipt.to_cose()).expect("tagged COSE_Sign1");

        // vds (395) is PROTECTED: it selects how the proof is read.
        let vds = sign1
            .protected
            .header
            .rest
            .iter()
            .find(|(l, _)| *l == Label::Int(395))
            .and_then(|(_, v)| v.as_integer())
            .expect("vds at protected label 395");
        assert_eq!(i64::try_from(vds).expect("small"), 1, "RFC9162_SHA256");

        // vdp (396) is UNPROTECTED and is a MAP keyed by proof type, whose
        // inclusion-proof (-1) value is an array of bstr.
        let vdp = sign1
            .unprotected
            .rest
            .iter()
            .find(|(l, _)| *l == Label::Int(396))
            .and_then(|(_, v)| v.as_map())
            .expect("vdp map at unprotected label 396");
        let proofs = vdp
            .iter()
            .find(|(k, _)| k.as_integer().is_some_and(|i| i == (-1).into()))
            .and_then(|(_, v)| v.as_array())
            .expect("inclusion-proof array at -1");
        let content: Value = ciborium::from_reader(
            proofs
                .first()
                .and_then(|p| p.as_bytes())
                .expect("bstr-wrapped proof content")
                .as_slice(),
        )
        .expect("inclusion-proof-content CBOR");
        let parts = content.as_array().expect("array");
        assert_eq!(parts.len(), 3, "[tree-size, leaf-index, inclusion-path]");
        assert!(
            !parts[2].as_array().expect("path").is_empty(),
            "inclusion-path is [ + bstr ]"
        );

        // This service attaches the root, so the payload is the Merkle Tree Hash and
        // nothing else. (A detached receipt carries no payload; see the Figure 6 test.)
        assert_eq!(
            sign1.payload.as_deref().expect("attached payload"),
            receipt.root.as_deref().expect("attached root"),
        );

        // The draft-era labels must be absent, or a verifier reading only the RFC's
        // labels would see a receipt with two conflicting descriptions of its proof.
        for stale in [-111, -222] {
            assert!(
                !sign1
                    .protected
                    .header
                    .rest
                    .iter()
                    .chain(sign1.unprotected.rest.iter())
                    .any(|(l, _)| *l == Label::Int(stale)),
                "no header at draft label {stale}"
            );
        }
    }

    /// RFC 9942 §5.2.1 Figure 6 — the RFC's OWN illustrated receipt — read against this
    /// parser. A third anchor: neither this implementation nor the third-party peer
    /// authored the figure, so agreement with it is not two readings of the spec
    /// agreeing with each other.
    ///
    /// The structure the figure shows — ES256, `vds` 395 in the protected header,
    /// `vdp` 396 → `inclusion-proof` −1 → bstr of `[20, 17, [3 hashes]]` — parses here in
    /// both the attached and the DETACHED form the figure itself uses.
    #[test]
    fn the_rfc9942_figure_6_shape_parses_in_both_attached_and_detached_form() {
        let proof = {
            let mut bytes = Vec::new();
            ciborium::into_writer(
                &Value::Array(vec![
                    Value::Integer(20.into()),
                    Value::Integer(17.into()),
                    Value::Array(vec![
                        Value::Bytes(vec![0xfc; 32]),
                        Value::Bytes(vec![0xbd; 32]),
                        Value::Bytes(vec![0xd6; 32]),
                    ]),
                ]),
                &mut bytes,
            )
            .expect("encode");
            bytes
        };
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .value(HEADER_VDS, Value::Integer(VDS_RFC9162_SHA256.into()))
            .build();
        let unprotected = HeaderBuilder::new()
            .value(
                HEADER_VDP,
                Value::Map(vec![(
                    Value::Integer(PROOF_INCLUSION.into()),
                    Value::Array(vec![Value::Bytes(proof)]),
                )]),
            )
            .build();
        let build = |payload: Option<Vec<u8>>| {
            let mut builder = CoseSign1Builder::new()
                .protected(protected.clone())
                .unprotected(unprotected.clone())
                .signature(vec![0u8; 64]);
            if let Some(p) = payload {
                builder = builder.payload(p);
            }
            builder.build().to_tagged_vec().expect("encode")
        };

        // Both forms parse, and both report the same proof.
        for (label, receipt) in [
            ("attached", build(Some(vec![0xAB; 32]))),
            ("detached, as the figure itself shows", build(None)),
        ] {
            let parsed = Receipt::from_cose(&receipt).unwrap_or_else(|e| {
                panic!("figure 6 shape ({label}) must parse, got {e:?}");
            });
            assert_eq!(parsed.tree_size(), 20, "{label}");
            assert_eq!(parsed.leaf_index(), 17, "{label}");
            assert_eq!(parsed.inclusion_path.len(), 3, "{label}");
        }

        // A payload that is present but is not a tree hash is neither form.
        assert_eq!(
            Receipt::from_cose(&build(Some(vec![0xAB; 31]))).unwrap_err(),
            HttpProfileError::MalformedEvidence("scitt receipt root"),
        );
    }

    /// RFC 9942 §5.2 quoting RFC 9162: `leaf_index >= tree_size` fails verification.
    /// A tree of size N cannot contain leaf N, so the claim is refuted by arithmetic
    /// before any hashing — and a verifier that folded anyway would be walking a path
    /// for a leaf the signed tree head does not cover.
    #[test]
    fn a_leaf_index_outside_the_tree_is_refused() {
        let st = statement(EvidenceCommitment::from_reconstruction(
            &recon(ChainLabel::Complete, 1),
            None,
            None,
        ));
        let mut svc = PrototypeTransparencyService::new(TS_KID);
        let receipt = register(&mut svc, &st);

        // Re-encode the receipt's proof with the leaf index pushed past the tree size,
        // leaving everything else — including the service's signature — untouched.
        let sign1 = CoseSign1::from_tagged_slice(receipt.to_cose()).expect("parses");
        let mut proof = Vec::new();
        ciborium::into_writer(
            &Value::Array(vec![
                Value::Integer(receipt.tree_size().into()),
                Value::Integer(receipt.tree_size().into()),
                Value::Array(vec![]),
            ]),
            &mut proof,
        )
        .expect("encode");
        let mut forged = sign1.clone();
        forged.unprotected = HeaderBuilder::new()
            .value(
                HEADER_VDP,
                Value::Map(vec![(
                    Value::Integer(PROOF_INCLUSION.into()),
                    Value::Array(vec![Value::Bytes(proof)]),
                )]),
            )
            .build();
        let bytes = forged.to_tagged_vec().expect("re-encode");

        assert_eq!(
            Receipt::from_cose(&bytes).unwrap_err(),
            HttpProfileError::MalformedEvidence("scitt inclusion proof leaf index outside tree"),
        );
    }
}
