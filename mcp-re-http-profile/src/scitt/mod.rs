// SPDX-License-Identifier: Apache-2.0
//! Portable audit receipts on SCITT (RFC 9943) + COSE Receipts (RFC 9942) —
//! Layer 5 (issue #434, roadmap design).
//!
//! #414 rev 2 §3.5/§2.4 names IETF SCITT as the preferred Layer 5 realization:
//! "prefer that shape over inventing a new receipt format." This module is the
//! mapping and an OFFLINE-VERIFIABLE prototype, not a production ledger.
//!
//! **What a SCITT receipt gives Layer 5 that a signed rejection does not.** A
//! signed response proves the server said something. A SCITT receipt proves that a
//! statement about a call was *registered on a transparency service* — so a later
//! auditor can verify the record existed at a point in time, independently of the
//! parties to the call, without trusting the log to replay honestly (the inclusion
//! proof is checked offline against a signed tree head). That is the tamper-evident,
//! portable audit record §2.4 asks for.
//!
//! **Retained vs committed (§4.6).** The Signed Statement does NOT carry the call's
//! evidence — it carries HASH COMMITMENTS to it. The full request/response messages,
//! bindings, and continuation chain stay in the evidence store (retained); the
//! statement commits to their digests (committed). A receipt is small and portable, and an
//! auditor with the retained evidence recomputes the digests and checks they match what the
//! receipt committed to.
//!
//! A receipt therefore does not CARRY the call bytes. That is the whole of the claim, and
//! it is not confidentiality: nothing here establishes unlinkability, or resistance to
//! inference from the digests, or resistance to guessing a low-entropy reconstruction and
//! confirming it against the commitment.
//!
//! **Incomplete chains are first-class (§9 seam, #431).** The statement embeds the
//! [`ChainLabel`] from [`crate::chain::reconstruct_chain`], so a receipt commits to a
//! COMPLETE or an explicitly-INCOMPLETE record, and the two are distinguishable in
//! the verified statement. A receipt can never make a truncated call look whole:
//! the label it commits to says which hop was missing.
//!
//! **What is real here, and the one thing that is not.** The wire form is the real
//! one (MCPRE-494): a Signed Statement is a tagged `COSE_Sign1` satisfying the RFC 9943
//! §6.1 CDDL — CWT claims (RFC 9597 label 15) carrying `iss` and `sub` in the PROTECTED
//! header — and a Receipt is a tagged `COSE_Sign1` satisfying RFC 9942 §5.2.1: `vds` in
//! the protected header, the inclusion proof under `vdp` → `inclusion-proof` in the
//! unprotected header, and the RFC 9162 Merkle Tree Hash as the payload. Conformance
//! vectors are frozen from those octets in `mcp-re-conformance/tests/vectors/scitt/`.
//!
//! **What this verifier accepts**, stated here rather than left to be discovered:
//!
//! 1. **Both payload forms, and neither takes the root from the caller.** For an
//!    ATTACHED receipt the payload is the Merkle Tree Hash, and the fold's output must
//!    equal it. For a DETACHED one (RFC 9942 §4.4) there is no payload: the fold's
//!    output IS the payload the signature is checked against, so a wrong fold produces
//!    a different `Sig_structure` and the signature simply fails. Either way the root
//!    is DERIVED from the statement under verification, never supplied. Detached is
//!    the form the real-service interop run produced.
//! 2. **EdDSA and ES256 only.** Any other `alg` is refused rather than attempted, and the
//!    resolved key must agree with the `alg` the protected header names.
//! 3. **MCP-RE statements only.** A Signed Statement must carry the RFC 9943 §6.1 CWT
//!    claims with `iss` equal to the signing `kid`, `sub` equal to
//!    [`STATEMENT_SUBJECT`], and the [`STATEMENT_CONTENT_TYPE`] content type — so a
//!    statement cannot attribute itself to a party other than the key that signed it,
//!    and no other COSE_Sign1 the issuer key produces can be read as call evidence.
//!
//! Interoperability has been demonstrated against `@transmute/cose` (authored by
//! RFC 9942's editor): its RFC 9162 tree, proof encoder and CBOR produced a receipt that
//! verifies here offline, and its decoder reads receipts produced here. The corpus is
//! frozen in `mcp-re-conformance/tests/vectors/scitt/interop/`. That peer is a LIBRARY,
//! not a transparency service — see #501 for what the demonstration does and does not
//! license.
//!
//! The remaining stand-in, called out so nobody mistakes the prototype for the
//! product: [`PrototypeTransparencyService`] is an in-process Merkle log, NOT a
//! running SCITT Transparency Service. Registering against a real one — and obtaining
//! interoperability evidence from a counterparty we do not control — is #501, and it
//! is what an RFC 9942/9943 interoperability CLAIM still waits on. What this module
//! establishes without one is the mapping and the OFFLINE receipt verification the
//! acceptance criterion names.

//! # The authorities, and the facade over them
//!
//! EX-004's census answered §8 question 2 with **seven**, and its question-1 answer needed
//! an "and" at seven clauses. Each of those is now a module that owns one fact, and every
//! one of them is PRIVATE: #657 ruling 2 is that seven authorities does not mean seven
//! public modules, so this file is the facade and the subordinates are reached through it.
//!
//! ```text
//! scitt                        the facade — this file re-exports, and owns nothing
//!   ├─ commitment    A   which digests a record names, and whether they identify a call
//!   ├─ wire              the COSE/CWT labels and byte layouts both sides must agree on
//!   ├─ statement     B   this COSE_Sign1 is MCP-RE call evidence, attributed to its key
//!   ├─ receipt       C   these are a well-formed RFC 9942 receipt's fields
//!   ├─ merkle        D   this path folds this leaf to this root at this position
//!   ├─ cose_key      E   valid under a key whose algorithm the header agrees with
//!   ├─ service           the key + profiles that go together for ONE service
//!   ├─ offline           the composition: verified offline, contacting nobody
//!   ├─ retained      F   these bytes are the ones that statement was made about
//!   ├─ trust_pin     G   the key an interop run verified against, and its provenance
//!   └─ prototype         the in-process stand-in — NOT a product (ruling 4)
//! ```
//!
//! # Two things this split deliberately did not do
//!
//! **The two RFC 9162 implementations stay two.** `prototype` builds a tree and `merkle`
//! verifies a path; they are an independent cross-check that the vector corpus keeps
//! honest, and consolidating them would make a bug in the only implementation invisible to
//! the corpus that exists to see it (#657 ruling 3).
//!
//! **`PrototypeTransparencyService` is not deleted.** It is `pub` and re-exported at the
//! crate root, so it is a compatibility surface whatever its in-repo callers are; zero
//! production callers is not a deletion argument (#657 ruling 4).

mod commitment;
mod cose_key;
mod merkle;
mod offline;
mod prototype;
mod receipt;
mod retained;
mod service;
mod statement;
mod trust_pin;
mod wire;

pub use commitment::EvidenceCommitment;
pub use cose_key::CoseVerificationKey;
pub use cose_key::P256Point;
pub use merkle::StatementLeafProfile;
pub use offline::verify_receipt_offline;
pub use prototype::PrototypeTransparencyService;
pub use receipt::Receipt;
pub use retained::verify_retained_evidence;
pub use retained::EvidenceDigest;
pub use retained::RetainedEvidenceStore;
pub use service::ResolvedTransparencyService;
pub use statement::issue_signed_statement;
pub use statement::SignedStatement;
pub use statement::STATEMENT_CONTENT_TYPE;
pub use statement::STATEMENT_SUBJECT;
pub use trust_pin::PinnedPublicKey;
pub use trust_pin::ScittServiceTrustPin;
pub use trust_pin::TRUST_PIN_SCHEMA;
pub use wire::ReceiptPositionProfile;
pub use wire::EVIDENCE_PROFILE;

#[cfg(test)]
mod fixtures {
    //! Test fixtures shared by the SCITT subtree's owners.
    //!
    //! Inline rather than a file: `scripts/module_size_gate.py` reads FILES, so it cannot
    //! see a `#[cfg(test)]` on a `mod` line and would count a fixture file as production.
    //! The module is the same either way; only the measurement differs, and a measurement
    //! that reports 260 lines of test scaffolding as production code is the wrong one.
    //!
    //! It exists because the propositions this subtree proves are mostly about a REGISTERED
    //! statement: a commitment, signed into a statement, registered in a log, answered by a
    //! receipt. Reaching that state costs a dozen builders, and duplicating them per owner
    //! would make the tests disagree about what a fixture is.
    //!
    //! Nothing here asserts anything. Every assertion lives in the module whose fact it is
    //! about, which is what lets the owners keep their own `mod tests`.

    use ciborium::Value;
    use coset::iana;
    use coset::CoseSign1;
    use coset::CoseSign1Builder;
    use coset::HeaderBuilder;
    use coset::TaggedCborSerializable;
    use mcp_re_core::SigningKey;

    use crate::chain::ChainLabel;
    use crate::chain::ChainReconstruction;
    use crate::chain::HopEvidence;
    use crate::error::HttpProfileError;
    use crate::evidence::RequestEvidence;

    use crate::scitt::commitment::EvidenceCommitment;
    use crate::scitt::cose_key::CoseVerificationKey;
    use crate::scitt::merkle::leaf_hash;
    use crate::scitt::merkle::StatementLeafProfile;
    use crate::scitt::prototype::PrototypeTransparencyService;
    use crate::scitt::receipt::Receipt;
    use crate::scitt::service::ResolvedTransparencyService;
    use crate::scitt::statement::issue_signed_statement;
    use crate::scitt::statement::SignedStatement;
    use crate::scitt::wire::ReceiptPositionProfile;
    use crate::scitt::wire::HEADER_VDP;
    use crate::scitt::wire::HEADER_VDS;
    use crate::scitt::wire::PROOF_INCLUSION;
    use crate::scitt::wire::VDS_RFC9162_SHA256;

    pub(super) const ISSUER_KID: &str = "scitt-issuer-1";

    pub(super) const TS_KID: &str = "scitt-ts-1";

    pub(super) fn issuer() -> SigningKey {
        SigningKey::from_seed_bytes(&[55u8; 32])
    }

    pub(super) fn ts() -> SigningKey {
        SigningKey::from_seed_bytes(&[66u8; 32])
    }

    pub(super) fn recon(label: ChainLabel, hops: usize) -> ChainReconstruction {
        let hop_evidence = (0..hops)
            .map(|i| HopEvidence {
                request_evidence: RequestEvidence::from_signature_base(
                    format!("req-{i}").as_bytes(),
                ),
                response_evidence: RequestEvidence::from_response_signature_base(
                    format!("rsp-{i}").as_bytes(),
                ),
            })
            .collect();
        ChainReconstruction {
            label,
            hop_evidence,
            submitted_commitment: "test-submitted".to_owned(),
        }
    }

    pub(super) fn statement(commitment: EvidenceCommitment) -> SignedStatement {
        issue_signed_statement(ISSUER_KID, commitment, 1_700_000_000, |b| {
            mcp_re_core::b64url_decode(&issuer().sign(b))
                .map_err(|_| HttpProfileError::InvalidSignature)
        })
        .expect("issue")
    }

    pub(super) fn ir() -> impl Fn(&str) -> Option<CoseVerificationKey> {
        |k: &str| (k == ISSUER_KID).then(|| issuer().public_key().into())
    }

    pub(super) fn tr() -> impl Fn(&str) -> Option<ResolvedTransparencyService> {
        |k: &str| {
            (k == TS_KID).then(|| {
                ResolvedTransparencyService::stated(
                    ts().public_key().into(),
                    StatementLeafProfile::StatementBytes,
                    ReceiptPositionProfile::Bound,
                )
            })
        }
    }

    /// A resolver for the prototype service under the PRE-v2 contract, so a test can
    /// show what the position commitment actually buys.
    pub(super) fn tr_unbound() -> impl Fn(&str) -> Option<ResolvedTransparencyService> {
        |k: &str| {
            (k == TS_KID).then(|| {
                ResolvedTransparencyService::stated(
                    ts().public_key().into(),
                    StatementLeafProfile::StatementBytes,
                    ReceiptPositionProfile::Unbound,
                )
            })
        }
    }

    /// Re-issue a receipt in the PRE-v2 shape: same tree, same signature discipline, no
    /// position parameter and no `crit`. This is what the service emitted before the
    /// contract revision, and it is what the restatement test needs in order to
    /// reproduce the finding rather than merely assert it.
    pub(super) fn pre_v2_receipt(receipt: &Receipt) -> Vec<u8> {
        let proof = Value::Array(vec![
            Value::Integer(receipt.tree_size().into()),
            Value::Integer(receipt.leaf_index().into()),
            Value::Array(
                receipt
                    .inclusion_path()
                    .iter()
                    .map(|h| Value::Bytes(h.clone()))
                    .collect(),
            ),
        ]);
        let mut proof_bytes = Vec::new();
        ciborium::into_writer(&proof, &mut proof_bytes).expect("encode");
        CoseSign1Builder::new()
            .protected(
                HeaderBuilder::new()
                    .algorithm(iana::Algorithm::EdDSA)
                    .key_id(TS_KID.as_bytes().to_vec())
                    .value(HEADER_VDS, Value::Integer(VDS_RFC9162_SHA256.into()))
                    .build(),
            )
            .unprotected(
                HeaderBuilder::new()
                    .value(
                        HEADER_VDP,
                        Value::Map(vec![(
                            Value::Integer(PROOF_INCLUSION.into()),
                            Value::Array(vec![Value::Bytes(proof_bytes)]),
                        )]),
                    )
                    .build(),
            )
            .payload(receipt.committed_root().expect("attached root").to_vec())
            .create_signature(&[], |pt| {
                mcp_re_core::b64url_decode(&ts().sign(pt)).expect("sign")
            })
            .build()
            .to_tagged_vec()
            .expect("encode")
    }

    /// Restate a receipt at a DIFFERENT `(leaf_index, tree_size)` that folds the same
    /// path to the same root.
    ///
    /// The proof rides in the UNPROTECTED header, so this rewrites it and leaves the
    /// protected header, payload and signature exactly as the service produced them.
    /// Nothing is forged: the resulting receipt is one the service signed, presented as
    /// a position it never signed.
    pub(super) fn restate_position(receipt: &Receipt, tree_size: u64, leaf_index: u64) -> Vec<u8> {
        let mut sign1 = CoseSign1::from_tagged_slice(receipt.to_cose()).expect("parses");
        let proof = Value::Array(vec![
            Value::Integer(tree_size.into()),
            Value::Integer(leaf_index.into()),
            Value::Array(
                receipt
                    .inclusion_path()
                    .iter()
                    .map(|h| Value::Bytes(h.clone()))
                    .collect(),
            ),
        ]);
        let mut proof_bytes = Vec::new();
        ciborium::into_writer(&proof, &mut proof_bytes).expect("encode");
        sign1.unprotected = HeaderBuilder::new()
            .value(
                HEADER_VDP,
                Value::Map(vec![(
                    Value::Integer(PROOF_INCLUSION.into()),
                    Value::Array(vec![Value::Bytes(proof_bytes)]),
                )]),
            )
            .build();
        sign1.to_tagged_vec().expect("encode")
    }

    pub(super) fn ts_p256_bound() -> impl Fn(&str) -> Option<ResolvedTransparencyService> {
        move |k: &str| {
            (k == TS_KID).then(|| {
                ResolvedTransparencyService::stated(
                    ts_p256_key(),
                    StatementLeafProfile::StatementBytes,
                    ReceiptPositionProfile::Bound,
                )
            })
        }
    }

    /// A resolver for a FOREIGN service using `key`, with the default leaf profile.
    ///
    /// `Unbound`: the receipts these tests build by hand are the shape a real external
    /// SCITT service emits, and no such service carries MCP-RE's position parameter.
    pub(super) fn ts_with(
        key: CoseVerificationKey,
    ) -> impl Fn(&str) -> Option<ResolvedTransparencyService> {
        move |k: &str| {
            (k == TS_KID).then(|| {
                ResolvedTransparencyService::stated(
                    key.clone(),
                    StatementLeafProfile::StatementBytes,
                    ReceiptPositionProfile::Unbound,
                )
            })
        }
    }

    pub(super) fn register(
        svc: &mut PrototypeTransparencyService,
        st: &SignedStatement,
    ) -> Receipt {
        svc.register(st, |b| {
            mcp_re_core::b64url_decode(&ts().sign(b))
                .map_err(|_| HttpProfileError::InvalidSignature)
        })
        .expect("register")
    }

    /// The first occurrence of `needle` in `haystack`.
    pub(super) fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    /// A fixed P-256 key pair. The scalar is a constant so the test is deterministic;
    /// it is a test key and appears nowhere outside these tests.
    pub(super) fn ts_p256() -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::from_slice(&[0x42u8; 32]).expect("a valid P-256 scalar")
    }

    pub(super) fn ts_p256_key() -> CoseVerificationKey {
        let point = ts_p256().verifying_key().to_sec1_point(false);
        CoseVerificationKey::from_ec2_p256(point.x().expect("x"), point.y().expect("y"))
            .expect("a point on the curve")
    }

    /// Re-sign a receipt's `Sig_structure` with ES256, as a foreign service would:
    /// same tree, same proof, `alg: ES256` in the protected header.
    pub(super) fn es256_receipt(statement: &SignedStatement) -> Vec<u8> {
        let leaf = leaf_hash(statement, StatementLeafProfile::StatementBytes);
        let mut proof = Vec::new();
        ciborium::into_writer(
            &Value::Array(vec![
                Value::Integer(1.into()),
                Value::Integer(0.into()),
                Value::Array(vec![]),
            ]),
            &mut proof,
        )
        .expect("encode proof");
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .key_id(TS_KID.as_bytes().to_vec())
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
        CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(leaf.to_vec())
            .create_signature(&[], |pt| {
                use p256::ecdsa::signature::Signer;
                let sig: p256::ecdsa::Signature = ts_p256().sign(pt);
                sig.to_bytes().to_vec()
            })
            .build()
            .to_tagged_vec()
            .expect("encode")
    }
}
