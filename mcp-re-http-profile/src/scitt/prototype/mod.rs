// SPDX-License-Identifier: Apache-2.0
//! The in-process Merkle log — the PROTOTYPE stand-in, not a product.
//!
//! `PrototypeTransparencyService` is NOT a running SCITT Transparency Service. Registering
//! against a real one is #501; what this establishes without one is the mapping and the
//! OFFLINE receipt verification the acceptance criterion names.
//!
//! It is `pub` and re-exported at the crate root, so it is a COMPATIBILITY SURFACE whatever
//! its in-repo consumers are. #657 ruling 4 governs: zero production callers is not a
//! deletion argument, and classifying it is its own decision.
//!
//! Its tree BUILDER is one of the two independent RFC 6962 implementations; the fold is
//! [`super::merkle`]'s. See that module for why they stay two.

use ciborium::Value;
use coset::iana;
use coset::CoseSign1Builder;
use coset::HeaderBuilder;
use coset::TaggedCborSerializable;

use crate::error::HttpProfileError;

pub(super) mod tree;

use tree::mth_and_path;

use super::merkle::leaf_hash;
use super::merkle::StatementLeafProfile;
use super::receipt::Receipt;
use super::statement::SignedStatement;
use super::wire::position_commitment;
use super::wire::HEADER_POSITION_COMMITMENT;
use super::wire::HEADER_VDP;
use super::wire::HEADER_VDS;
use super::wire::PROOF_INCLUSION;
use super::wire::VDS_RFC9162_SHA256;

/// A minimal in-process Merkle transparency log — the PROTOTYPE stand-in for a real
/// SCITT Transparency Service, so the mapping and offline receipt verification are
/// demonstrable without an external service. NOT a production ledger.
pub struct PrototypeTransparencyService {
    kid: String,
    leaves: Vec<[u8; 32]>,
}

impl PrototypeTransparencyService {
    pub fn new(kid: &str) -> Self {
        PrototypeTransparencyService {
            kid: kid.to_owned(),
            leaves: Vec::new(),
        }
    }

    /// Register a signed statement and return its COSE Receipt, signing via
    /// `sign_tree_head` (the TS key never enters the caller's hands).
    ///
    /// The receipt is a tagged `COSE_Sign1` whose payload is the Merkle root and
    /// whose unprotected header carries the RFC 9942 inclusion proof — so what the
    /// service signs is the tree, and what the verifier walks is the path to it.
    pub fn register(
        &mut self,
        statement: &SignedStatement,
        sign_tree_head: impl FnOnce(&[u8]) -> Result<Vec<u8>, HttpProfileError>,
    ) -> Result<Receipt, HttpProfileError> {
        let leaf_index = self.leaves.len() as u64;
        self.leaves
            .push(leaf_hash(statement, StatementLeafProfile::StatementBytes));

        let (root, path) = self.root_and_path(leaf_index as usize);
        let tree_size = self.leaves.len() as u64;

        // RFC 9942 §5.2 Figure 3: `inclusion-proof-content` is
        // `[tree-size, leaf-index, inclusion-path]`, carried as a bstr of that CBOR.
        let proof = Value::Array(vec![
            Value::Integer(tree_size.into()),
            Value::Integer(leaf_index.into()),
            Value::Array(path.iter().map(|h| Value::Bytes(h.to_vec())).collect()),
        ]);
        let mut proof_bytes = Vec::new();
        ciborium::into_writer(&proof, &mut proof_bytes)
            .map_err(|_| HttpProfileError::MalformedEvidence("scitt inclusion proof encode"))?;

        // The position commitment goes in the PROTECTED header and is marked CRITICAL:
        // protected so the service's signature covers the tuple, critical so a verifier
        // that does not implement this profile refuses the receipt rather than checking
        // the inclusion proof and ignoring the binding.
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .key_id(self.kid.as_bytes().to_vec())
            .value(HEADER_VDS, Value::Integer(VDS_RFC9162_SHA256.into()))
            .text_value(
                HEADER_POSITION_COMMITMENT.to_owned(),
                Value::Bytes(position_commitment(
                    &self.kid,
                    VDS_RFC9162_SHA256,
                    tree_size,
                    leaf_index,
                    &root,
                )),
            )
            .add_critical_label(coset::RegisteredLabelWithPrivate::Text(
                HEADER_POSITION_COMMITMENT.to_owned(),
            ))
            .build();
        // `vdp` is a map keyed by proof type (RFC 9942 §5.2.1 Figure 5), so a Receipt
        // can carry inclusion and consistency proofs side by side.
        let unprotected = HeaderBuilder::new()
            .value(
                HEADER_VDP,
                Value::Map(vec![(
                    Value::Integer(PROOF_INCLUSION.into()),
                    Value::Array(vec![Value::Bytes(proof_bytes)]),
                )]),
            )
            .build();

        let mut failure = None;
        let sign1 = CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(root.to_vec())
            .create_signature(&[], |pt| match sign_tree_head(pt) {
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
            .map_err(|_| HttpProfileError::MalformedEvidence("scitt receipt encode"))?;
        Receipt::from_cose(&cose)
    }

    /// The Merkle root and the inclusion path for `target`, per RFC 9162 §2.1.1
    /// (`MTH`) and §2.1.3.1 (`PATH`).
    ///
    /// The split is at the LARGEST POWER OF TWO strictly below `n`, never at the
    /// midpoint, and the last node is never duplicated. Those are different trees for
    /// every size that is not a power of two: for leaves `[A, B, C]` the two
    /// constructions produce different roots, so a log built by duplication cannot
    /// produce a receipt any RFC 9162 verifier accepts — while the receipt's own
    /// protected `vds` declares `RFC9162_SHA256` and this parser refuses anything
    /// else. Both corpora happened to be recorded at `tree_size = 2`, where the two
    /// agree, which is why the divergence went unmeasured.
    fn root_and_path(&self, target: usize) -> ([u8; 32], Vec<[u8; 32]>) {
        let mut path = Vec::new();
        let root = mth_and_path(&self.leaves, Some(target), &mut path);
        (root, path)
    }
}
