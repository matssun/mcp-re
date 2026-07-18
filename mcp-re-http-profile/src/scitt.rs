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
//! statement commits to their digests (committed). A receipt is small and portable,
//! and revealing it discloses nothing; an auditor with the retained evidence
//! recomputes the digests and checks they match what the receipt committed to.
//!
//! **Incomplete chains are first-class (§9 seam, #431).** The statement embeds the
//! [`ChainLabel`] from [`crate::chain::reconstruct_chain`], so a receipt commits to a
//! COMPLETE or an explicitly-INCOMPLETE record, and the two are distinguishable in
//! the verified statement. A receipt can never make a truncated call look whole:
//! the label it commits to says which hop was missing.
//!
//! **What is faithful here and what is a stand-in.** The cryptographic content is
//! real: Ed25519 signatures over the statement and the tree head, and RFC 6962-style
//! SHA-256 Merkle inclusion proofs, all verified offline. The stand-ins, called out
//! so nobody mistakes the prototype for the product:
//!   - the SERIALIZATION is JSON, not the CBOR/COSE_Sign1 of RFC 9052/9942. The
//!     fields map one-to-one; production swaps the encoder.
//!   - [`PrototypeTransparencyService`] is an in-process Merkle log, NOT a running
//!     SCITT Transparency Service. The #434 scope's "prototype against an existing
//!     SCITT service" is the remaining integration; this proves the mapping and the
//!     OFFLINE receipt verification the acceptance criterion names, without one.

use mcp_re_core::b64url_encode;
use mcp_re_core::verify_ed25519_with;
use mcp_re_core::McpReError;
use mcp_re_core::VerificationKey;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;

use crate::chain::ChainLabel;
use crate::chain::ChainReconstruction;
use crate::error::HttpProfileError;

/// The MCP-RE evidence a receipt commits to (#415 §4.6), as HASH COMMITMENTS. Each
/// field is a digest of externally-retained evidence, never the evidence itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCommitment {
    /// Digest over the request signature base (the request evidence handle).
    pub request_evidence: String,
    /// Digest over the response signature base (the response evidence handle).
    pub response_evidence: String,
    /// Digest over the canonical bytes of the artifact bindings, or `None` when
    /// the call carried none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bindings_commitment: Option<String>,
    /// Digest over the verified-context the PEP produced, or `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_context_commitment: Option<String>,
    /// The chain-reconstruction label this record commits to — complete, or
    /// incomplete naming the failing hop. Serialized as a string so a receipt
    /// distinguishes the two without re-running reconstruction.
    pub chain_label: String,
    /// Digest over the ordered per-hop evidence handles the reconstruction
    /// produced — the commitment to the SHAPE of the retained chain.
    pub chain_commitment: String,
}

impl EvidenceCommitment {
    /// Build the commitment from a chain reconstruction plus the optional
    /// binding/context digests the caller retains.
    pub fn from_reconstruction(
        reconstruction: &ChainReconstruction,
        bindings_commitment: Option<String>,
        verified_context_commitment: Option<String>,
    ) -> Self {
        // The record commits to the FIRST hop's request/response handles as the
        // call's identity, and to a digest over every hop's handles as its shape.
        let (request_evidence, response_evidence) = match reconstruction.hop_evidence.first() {
            Some(h) => (h.request_evidence.digest_value.clone(), h.response_evidence.digest_value.clone()),
            None => (String::new(), String::new()),
        };
        let mut shape = Sha256::new();
        for h in &reconstruction.hop_evidence {
            shape.update(h.request_evidence.digest_value.as_bytes());
            shape.update([0x00]);
            shape.update(h.response_evidence.digest_value.as_bytes());
            shape.update([0x00]);
        }
        EvidenceCommitment {
            request_evidence,
            response_evidence,
            bindings_commitment,
            verified_context_commitment,
            chain_label: label_token(&reconstruction.label),
            chain_commitment: b64url_encode(&shape.finalize()),
        }
    }

    /// Whether this record is a COMPLETE call record. An incomplete one is not a
    /// weaker complete record — it is a distinct, explicitly-labeled record, and a
    /// receipt over it can never read as whole.
    pub fn is_complete_record(&self) -> bool {
        self.chain_label == "complete"
    }
}

/// The chain label as a receipt-embeddable token. `incomplete:<hop>:<reason>`
/// preserves WHICH hop broke the chain, so an auditor reading the receipt learns
/// the failing hop without the retained evidence.
fn label_token(label: &ChainLabel) -> String {
    match label {
        ChainLabel::Complete => "complete".to_owned(),
        ChainLabel::Incomplete { hop, reason } => format!("incomplete:{hop}:{reason:?}"),
    }
}

/// A SCITT Signed Statement (RFC 9943): the issuer's signed claim about a call.
/// The COSE_Sign1 analog — issuer signs the canonical statement bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedStatement {
    /// The issuer key id (resolved through the trust seam; a kid never introduces
    /// trust).
    pub issuer_kid: String,
    /// The evidence commitment — the statement's payload.
    pub commitment: EvidenceCommitment,
    /// The statement issuance time.
    pub issued_at: i64,
    /// Ed25519 signature over the canonical statement bytes, base64url.
    pub signature: String,
}

/// The canonical bytes an issuer signs / a verifier reconstructs. Deterministic
/// field order; a real deployment uses the CBOR COSE_Sign1 payload instead.
fn statement_signing_bytes(
    issuer_kid: &str,
    commitment: &EvidenceCommitment,
    issued_at: i64,
) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"mcp-re-scitt-statement-v1\x00");
    h.update(issuer_kid.as_bytes());
    h.update([0x00]);
    h.update(serde_json::to_vec(commitment).expect("commitment serializes"));
    h.update([0x00]);
    h.update(issued_at.to_le_bytes());
    h.finalize().to_vec()
}

/// Issue a Signed Statement over `commitment`, signing with the issuer via the
/// external-signer seam (the issuer key never enters this crate).
pub fn issue_signed_statement(
    issuer_kid: &str,
    commitment: EvidenceCommitment,
    issued_at: i64,
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, HttpProfileError>,
) -> Result<SignedStatement, HttpProfileError> {
    let bytes = statement_signing_bytes(issuer_kid, &commitment, issued_at);
    let sig = sign(&bytes)?;
    Ok(SignedStatement {
        issuer_kid: issuer_kid.to_owned(),
        commitment,
        issued_at,
        signature: b64url_encode(&sig),
    })
}

/// A COSE Receipt (RFC 9942): proof that a Signed Statement was registered on a
/// transparency service. Carries the leaf index, an RFC 6962-style inclusion
/// proof, and the transparency service's SIGNED tree head — everything an auditor
/// needs to verify inclusion OFFLINE.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    /// The transparency service key id.
    pub ts_kid: String,
    /// The registered leaf's index in the log.
    pub leaf_index: u64,
    /// The log size the tree head commits to.
    pub tree_size: u64,
    /// The Merkle inclusion proof: sibling hashes from leaf to root, base64url.
    pub inclusion_path: Vec<String>,
    /// The Merkle root the tree head commits to, base64url.
    pub root: String,
    /// The transparency service's Ed25519 signature over the tree head, base64url.
    pub tree_head_signature: String,
}

/// The leaf hash of a signed statement (RFC 6962 leaf prefix `0x00`).
fn leaf_hash(statement: &SignedStatement) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(serde_json::to_vec(statement).expect("statement serializes"));
    h.finalize().into()
}

/// An interior Merkle node hash (RFC 6962 node prefix `0x01`).
fn node_hash(left: &[u8], right: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// The bytes a transparency service signs for its tree head.
fn tree_head_bytes(tree_size: u64, root: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"mcp-re-scitt-tree-head-v1\x00");
    h.update(tree_size.to_le_bytes());
    h.update(root);
    h.finalize().to_vec()
}

/// Verify a receipt OFFLINE — the acceptance-criterion property. No transparency
/// service is contacted: given the statement, the receipt, the issuer key, and the
/// TS key, this checks
///   1. the issuer's signature over the statement;
///   2. the RFC 6962 inclusion proof re-derives the receipt's root from the leaf;
///   3. the TS's signature over `(tree_size, root)`.
///
/// Any failure is fail-closed. On success the caller holds a verified, portable
/// record of the call — including whether it was a complete or incomplete chain.
pub fn verify_receipt_offline(
    statement: &SignedStatement,
    receipt: &Receipt,
    resolve_issuer: impl Fn(&str) -> Option<VerificationKey>,
    resolve_ts: impl Fn(&str) -> Option<VerificationKey>,
) -> Result<(), HttpProfileError> {
    // 1. Issuer signature over the statement.
    let issuer = resolve_issuer(&statement.issuer_kid).ok_or(HttpProfileError::ReceiptIssuerUntrusted)?;
    let bytes = statement_signing_bytes(&statement.issuer_kid, &statement.commitment, statement.issued_at);
    verify_ed25519_with(&bytes, &statement.signature, &issuer, McpReError::InvalidSignature)
        .map_err(|_| HttpProfileError::ReceiptInvalid)?;

    // 2. Inclusion proof: fold the leaf up through the sibling path and require the
    //    result to equal the receipt's committed root. The index bits pick the
    //    left/right position at each level, exactly as RFC 6962 defines.
    let mut computed = leaf_hash(statement).to_vec();
    let mut index = receipt.leaf_index;
    for sibling_b64 in &receipt.inclusion_path {
        let sibling = decode32(sibling_b64)?;
        computed = if index & 1 == 0 {
            node_hash(&computed, &sibling).to_vec()
        } else {
            node_hash(&sibling, &computed).to_vec()
        };
        index >>= 1;
    }
    let root = decode32(&receipt.root)?;
    if computed != root {
        return Err(HttpProfileError::ReceiptInclusionInvalid);
    }

    // 3. Tree-head signature: the root the proof produced is the one the TS signed.
    let ts = resolve_ts(&receipt.ts_kid).ok_or(HttpProfileError::ReceiptIssuerUntrusted)?;
    let th = tree_head_bytes(receipt.tree_size, &root);
    verify_ed25519_with(&th, &receipt.tree_head_signature, &ts, McpReError::InvalidSignature)
        .map_err(|_| HttpProfileError::ReceiptInvalid)?;
    Ok(())
}

fn decode32(b64: &str) -> Result<Vec<u8>, HttpProfileError> {
    let bytes = mcp_re_core::b64url_decode(b64).map_err(|_| HttpProfileError::ReceiptInvalid)?;
    if bytes.len() != 32 {
        return Err(HttpProfileError::ReceiptInvalid);
    }
    Ok(bytes)
}

/// A minimal in-process Merkle transparency log — the PROTOTYPE stand-in for a real
/// SCITT Transparency Service, so the mapping and offline receipt verification are
/// demonstrable without an external service. NOT a production ledger.
pub struct PrototypeTransparencyService {
    kid: String,
    leaves: Vec<[u8; 32]>,
}

impl PrototypeTransparencyService {
    pub fn new(kid: &str) -> Self {
        PrototypeTransparencyService { kid: kid.to_owned(), leaves: Vec::new() }
    }

    /// Register a signed statement and return its COSE Receipt, signing the tree
    /// head via `sign_tree_head` (the TS key never enters the caller's hands).
    pub fn register(
        &mut self,
        statement: &SignedStatement,
        sign_tree_head: impl FnOnce(&[u8]) -> Result<Vec<u8>, HttpProfileError>,
    ) -> Result<Receipt, HttpProfileError> {
        let leaf_index = self.leaves.len() as u64;
        self.leaves.push(leaf_hash(statement));

        let (root, path) = self.root_and_path(leaf_index as usize);
        let tree_size = self.leaves.len() as u64;
        let th = tree_head_bytes(tree_size, &root);
        let sig = sign_tree_head(&th)?;
        Ok(Receipt {
            ts_kid: self.kid.clone(),
            leaf_index,
            tree_size,
            inclusion_path: path.iter().map(|h| b64url_encode(h)).collect(),
            root: b64url_encode(&root),
            tree_head_signature: b64url_encode(&sig),
        })
    }

    /// The Merkle root and the inclusion path for `target` over the current leaf
    /// set, using the RFC 6962 layering (duplicate the last node on odd levels).
    fn root_and_path(&self, target: usize) -> ([u8; 32], Vec<[u8; 32]>) {
        let mut level: Vec<[u8; 32]> = self.leaves.clone();
        let mut idx = target;
        let mut path = Vec::new();
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            let mut i = 0;
            while i < level.len() {
                let left = level[i];
                let right = if i + 1 < level.len() { level[i + 1] } else { level[i] };
                if i == idx || i + 1 == idx {
                    let sibling = if idx & 1 == 0 { right } else { left };
                    path.push(sibling);
                }
                next.push(node_hash(&left, &right));
                i += 2;
            }
            idx /= 2;
            level = next;
        }
        (level[0], path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::HopEvidence;
    use crate::chain::IncompleteReason;
    use crate::evidence::RequestEvidence;
    use mcp_re_core::SigningKey;

    const ISSUER_KID: &str = "scitt-issuer-1";
    const TS_KID: &str = "scitt-ts-1";

    fn issuer() -> SigningKey {
        SigningKey::from_seed_bytes(&[55u8; 32])
    }
    fn ts() -> SigningKey {
        SigningKey::from_seed_bytes(&[66u8; 32])
    }

    fn recon(label: ChainLabel, hops: usize) -> ChainReconstruction {
        let hop_evidence = (0..hops)
            .map(|i| HopEvidence {
                request_evidence: RequestEvidence::from_signature_base(format!("req-{i}").as_bytes()),
                response_evidence: RequestEvidence::from_response_signature_base(
                    format!("rsp-{i}").as_bytes(),
                ),
            })
            .collect();
        ChainReconstruction { label, hop_evidence }
    }

    fn statement(commitment: EvidenceCommitment) -> SignedStatement {
        issue_signed_statement(ISSUER_KID, commitment, 1_700_000_000, |b| {
            mcp_re_core::b64url_decode(&issuer().sign(b)).map_err(|_| HttpProfileError::InvalidSignature)
        })
        .expect("issue")
    }

    fn ir() -> impl Fn(&str) -> Option<VerificationKey> {
        |k: &str| (k == ISSUER_KID).then(|| issuer().public_key())
    }
    fn tr() -> impl Fn(&str) -> Option<VerificationKey> {
        |k: &str| (k == TS_KID).then(|| ts().public_key())
    }

    fn register(svc: &mut PrototypeTransparencyService, st: &SignedStatement) -> Receipt {
        svc.register(st, |b| {
            mcp_re_core::b64url_decode(&ts().sign(b)).map_err(|_| HttpProfileError::InvalidSignature)
        })
        .expect("register")
    }

    /// The acceptance case: one call's evidence → Signed Statement → registered →
    /// receipt verified OFFLINE, with no transparency service contacted at verify.
    #[test]
    fn one_calls_evidence_registers_and_the_receipt_verifies_offline() {
        let commitment = EvidenceCommitment::from_reconstruction(
            &recon(ChainLabel::Complete, 3),
            Some("bindings-digest".into()),
            Some("ctx-digest".into()),
        );
        assert!(commitment.is_complete_record());
        let st = statement(commitment);
        let mut svc = PrototypeTransparencyService::new(TS_KID);
        let receipt = register(&mut svc, &st);
        verify_receipt_offline(&st, &receipt, ir(), tr()).expect("offline receipt verifies");
    }

    /// Inclusion holds for any leaf in a multi-statement log — the proof re-derives
    /// the signed root from the specific leaf.
    #[test]
    fn inclusion_holds_across_many_registered_statements() {
        let mut svc = PrototypeTransparencyService::new(TS_KID);
        let mut records = Vec::new();
        for i in 0..5 {
            let st = statement(EvidenceCommitment::from_reconstruction(
                &recon(ChainLabel::Complete, i + 1),
                None,
                None,
            ));
            let r = register(&mut svc, &st);
            records.push((st, r));
        }
        // Each receipt was issued against a DIFFERENT tree size; re-registering all
        // against the final tree so every proof targets the final root.
        let mut svc2 = PrototypeTransparencyService::new(TS_KID);
        let statements: Vec<_> = records.iter().map(|(s, _)| s.clone()).collect();
        let receipts: Vec<_> = statements.iter().map(|s| register(&mut svc2, s)).collect();
        // Only the last receipt commits to the full tree; verify it offline.
        let last = statements.len() - 1;
        verify_receipt_offline(&statements[last], &receipts[last], ir(), tr())
            .expect("the last leaf's proof verifies against its signed root");
    }

    /// An INCOMPLETE chain is representable and DISTINGUISHABLE in the receipt: the
    /// statement commits to the incomplete label naming the failing hop, and a
    /// verifier reads it back. A receipt can never make a truncated call look whole.
    #[test]
    fn an_incomplete_chain_record_is_distinguishable_in_the_receipt() {
        let commitment = EvidenceCommitment::from_reconstruction(
            &recon(
                ChainLabel::Incomplete { hop: 1, reason: IncompleteReason::TerminalExpected },
                1,
            ),
            None,
            None,
        );
        assert!(!commitment.is_complete_record(), "the receipt commits to an incomplete record");
        assert!(commitment.chain_label.starts_with("incomplete:1:"), "and names the failing hop");

        let st = statement(commitment);
        let mut svc = PrototypeTransparencyService::new(TS_KID);
        let receipt = register(&mut svc, &st);
        verify_receipt_offline(&st, &receipt, ir(), tr()).expect("verifies");
        // The verified statement still says incomplete — the receipt did not launder it.
        assert!(!st.commitment.is_complete_record());
    }

    #[test]
    fn a_tampered_statement_fails_the_receipt() {
        let st = statement(EvidenceCommitment::from_reconstruction(&recon(ChainLabel::Complete, 1), None, None));
        let mut svc = PrototypeTransparencyService::new(TS_KID);
        let receipt = register(&mut svc, &st);
        // Tamper the committed label after registration.
        let mut tampered = st.clone();
        tampered.commitment.chain_label = "complete-but-lying".into();
        // The issuer signature no longer covers this statement.
        assert_eq!(
            verify_receipt_offline(&tampered, &receipt, ir(), tr()).unwrap_err(),
            HttpProfileError::ReceiptInvalid,
        );
    }

    #[test]
    fn a_forged_inclusion_path_fails() {
        let st = statement(EvidenceCommitment::from_reconstruction(&recon(ChainLabel::Complete, 2), None, None));
        let mut svc = PrototypeTransparencyService::new(TS_KID);
        let mut receipt = register(&mut svc, &st);
        // Swap a sibling: the recomputed root no longer matches the signed one.
        receipt.inclusion_path = vec![b64url_encode(&[9u8; 32])];
        assert!(matches!(
            verify_receipt_offline(&st, &receipt, ir(), tr()).unwrap_err(),
            HttpProfileError::ReceiptInclusionInvalid | HttpProfileError::ReceiptInvalid,
        ));
    }

    #[test]
    fn an_untrusted_issuer_or_ts_is_rejected() {
        let st = statement(EvidenceCommitment::from_reconstruction(&recon(ChainLabel::Complete, 1), None, None));
        let mut svc = PrototypeTransparencyService::new(TS_KID);
        let receipt = register(&mut svc, &st);
        assert_eq!(
            verify_receipt_offline(&st, &receipt, |_| None, tr()).unwrap_err(),
            HttpProfileError::ReceiptIssuerUntrusted,
        );
    }
}
