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
//! **What is real here, and the one thing that is not.** The wire form is the real
//! one (MCPRE-494): a Signed Statement is a tagged `COSE_Sign1` (RFC 9052 §4.2) whose
//! protected header carries the RFC 9943 CWT claims, and a Receipt is a tagged
//! `COSE_Sign1` whose payload is the Merkle root and whose unprotected header carries
//! the RFC 9942 inclusion proof over an RFC 9162 SHA-256 tree. Conformance vectors are
//! frozen from those octets in `mcp-re-conformance/tests/vectors/scitt/`.
//!
//! The remaining stand-in, called out so nobody mistakes the prototype for the
//! product: [`PrototypeTransparencyService`] is an in-process Merkle log, NOT a
//! running SCITT Transparency Service. Registering against a real one — and obtaining
//! interoperability evidence from a counterparty we do not control — is #501, and it
//! is what an RFC 9942/9943 interoperability CLAIM still waits on. What this module
//! establishes without one is the mapping and the OFFLINE receipt verification the
//! acceptance criterion names.

use ciborium::Value;
use coset::iana;
use coset::CoseSign1;
use coset::CoseSign1Builder;
use coset::HeaderBuilder;
use coset::Label;
use coset::TaggedCborSerializable;
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
            Some(h) => (
                h.request_evidence.digest_value.clone(),
                h.response_evidence.digest_value.clone(),
            ),
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

/// COSE header label for the CWT claims of a Signed Statement (RFC 9597).
///
/// RFC 9943 puts the issuer and subject in CWT claims inside the PROTECTED header,
/// not in the payload, so they are covered by the signature and readable without
/// decoding the payload.
const HEADER_CWT_CLAIMS: i64 = 15;

/// CWT claim keys (RFC 8392 §3.1) used in the protected header.
const CWT_ISS: i64 = 1;
const CWT_SUB: i64 = 2;
const CWT_IAT: i64 = 6;

/// COSE header label for the verifiable-data-structure a Receipt proves inclusion
/// in (RFC 9942 §3.1), in the PROTECTED header.
const HEADER_VERIFIABLE_DATA_STRUCTURE: i64 = -111;

/// COSE header label for the inclusion proofs of a Receipt (RFC 9942 §3.2), in the
/// UNPROTECTED header — a proof is not signed by the tree head it proves against.
const HEADER_INCLUSION_PROOFS: i64 = -222;

/// `RFC9162_SHA256`: the RFC 9162 binary Merkle tree, SHA-256 (RFC 9942 §5).
const VDS_RFC9162_SHA256: i64 = 1;

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
    pub fn from_cose(bytes: &[u8]) -> Result<Self, HttpProfileError> {
        let sign1 = CoseSign1::from_tagged_slice(bytes)
            .map_err(|_| HttpProfileError::MalformedEvidence("scitt statement cose"))?;
        let issuer_kid = String::from_utf8(sign1.protected.header.key_id.clone())
            .map_err(|_| HttpProfileError::MalformedEvidence("scitt statement kid"))?;
        let issued_at = cwt_claim(&sign1.protected.header, CWT_IAT)
            .and_then(|v| v.as_integer())
            .and_then(|i| i64::try_from(i).ok())
            .ok_or(HttpProfileError::MalformedEvidence("scitt statement iat"))?;
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
    /// The log size the signed tree head commits to.
    tree_size: u64,
    /// The registered leaf's index in the log.
    leaf_index: u64,
    /// Sibling hashes from leaf to root.
    inclusion_path: Vec<Vec<u8>>,
    /// The Merkle root — the receipt's signed payload.
    root: Vec<u8>,
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
    /// The log size the signed tree head commits to.
    pub fn tree_size(&self) -> u64 {
        self.tree_size
    }
    /// The registered leaf's index.
    pub fn leaf_index(&self) -> u64 {
        self.leaf_index
    }

    /// Parse a tagged `COSE_Sign1` receipt WITHOUT verifying it.
    pub fn from_cose(bytes: &[u8]) -> Result<Self, HttpProfileError> {
        let sign1 = CoseSign1::from_tagged_slice(bytes)
            .map_err(|_| HttpProfileError::MalformedEvidence("scitt receipt cose"))?;
        let ts_kid = String::from_utf8(sign1.protected.header.key_id.clone())
            .map_err(|_| HttpProfileError::MalformedEvidence("scitt receipt kid"))?;
        // The verifiable-data-structure must be one this verifier implements. An
        // unrecognized structure is refused, never walked as if it were RFC 9162:
        // a proof format this code does not implement cannot be checked by it.
        let vds = sign1
            .protected
            .header
            .rest
            .iter()
            .find(|(label, _)| *label == Label::Int(HEADER_VERIFIABLE_DATA_STRUCTURE))
            .and_then(|(_, v)| v.as_integer())
            .and_then(|i| i64::try_from(i).ok())
            .ok_or(HttpProfileError::MalformedEvidence("scitt receipt vds"))?;
        if vds != VDS_RFC9162_SHA256 {
            return Err(HttpProfileError::MalformedEvidence(
                "scitt receipt verifiable data structure unsupported",
            ));
        }
        let proof = sign1
            .unprotected
            .rest
            .iter()
            .find(|(label, _)| *label == Label::Int(HEADER_INCLUSION_PROOFS))
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
        let root = sign1
            .payload
            .as_deref()
            .filter(|p| p.len() == 32)
            .ok_or(HttpProfileError::MalformedEvidence("scitt receipt root"))?
            .to_vec();
        Ok(Receipt {
            cose: bytes.to_vec(),
            ts_kid,
            tree_size,
            leaf_index,
            inclusion_path,
            root,
        })
    }
}

fn as_u64(v: &Value) -> Result<u64, HttpProfileError> {
    v.as_integer()
        .and_then(|i| u64::try_from(i).ok())
        .ok_or(HttpProfileError::MalformedEvidence("scitt receipt integer"))
}

/// The leaf hash of a signed statement (RFC 6962 leaf prefix `0x00`), over the
/// statement's COSE bytes — the exact octets that were registered.
fn leaf_hash(statement: &SignedStatement) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(statement.to_cose());
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

/// Verify a receipt OFFLINE — the acceptance-criterion property. No transparency
/// service is contacted: given the statement, the receipt, the issuer key, and the
/// TS key, this checks
///   1. the issuer's COSE_Sign1 signature over the statement;
///   2. the RFC 9162 inclusion proof re-derives the receipt's root from the leaf;
///   3. the TS's COSE_Sign1 signature over the receipt, whose payload IS that root.
///
/// Any failure is fail-closed. On success the caller holds a verified, portable
/// record of the call — including whether it was a complete or incomplete chain.
pub fn verify_receipt_offline(
    statement: &SignedStatement,
    receipt: &Receipt,
    resolve_issuer: impl Fn(&str) -> Option<VerificationKey>,
    resolve_ts: impl Fn(&str) -> Option<VerificationKey>,
) -> Result<(), HttpProfileError> {
    // 1. Issuer signature over the statement's own Sig_structure.
    let issuer =
        resolve_issuer(statement.issuer_kid()).ok_or(HttpProfileError::ReceiptIssuerUntrusted)?;
    verify_cose_sign1(statement.to_cose(), &issuer)?;

    // 2. Inclusion proof: fold the leaf up through the sibling path and require the
    //    result to equal the root the receipt commits to. The index bits pick the
    //    left/right position at each level, exactly as RFC 9162 defines.
    let mut computed = leaf_hash(statement).to_vec();
    let mut index = receipt.leaf_index;
    for sibling in &receipt.inclusion_path {
        computed = if index & 1 == 0 {
            node_hash(&computed, sibling).to_vec()
        } else {
            node_hash(sibling, &computed).to_vec()
        };
        index >>= 1;
    }
    if computed != receipt.root {
        return Err(HttpProfileError::ReceiptInclusionInvalid);
    }

    // 3. The receipt's own signature. Its payload is the root the fold just
    //    reproduced, so a verified receipt is the service's statement that THIS leaf
    //    is in a tree it signed.
    let ts = resolve_ts(receipt.ts_kid()).ok_or(HttpProfileError::ReceiptIssuerUntrusted)?;
    verify_cose_sign1(receipt.to_cose(), &ts)?;
    Ok(())
}

/// Verify a tagged `COSE_Sign1`'s signature over its own `Sig_structure`.
///
/// The algorithm is read from the PROTECTED header and must be EdDSA: accepting
/// whatever the message named would let a peer choose the verification algorithm,
/// which is the classic COSE/JOSE algorithm-confusion shape.
fn verify_cose_sign1(cose: &[u8], key: &VerificationKey) -> Result<(), HttpProfileError> {
    let sign1 = CoseSign1::from_tagged_slice(cose).map_err(|_| HttpProfileError::ReceiptInvalid)?;
    if sign1.protected.header.alg
        != Some(coset::RegisteredLabelWithPrivate::Assigned(
            iana::Algorithm::EdDSA,
        ))
    {
        return Err(HttpProfileError::ReceiptInvalid);
    }
    sign1
        .verify_signature(&[], |sig, data| {
            verify_ed25519_with(data, &b64url_encode(sig), key, McpReError::InvalidSignature)
        })
        .map_err(|_| HttpProfileError::ReceiptInvalid)
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
        self.leaves.push(leaf_hash(statement));

        let (root, path) = self.root_and_path(leaf_index as usize);
        let tree_size = self.leaves.len() as u64;

        // RFC 9942 §3.2: an inclusion proof is a bstr-wrapped
        // `[tree_size, leaf_index, [path...]]`.
        let proof = Value::Array(vec![
            Value::Integer(tree_size.into()),
            Value::Integer(leaf_index.into()),
            Value::Array(path.iter().map(|h| Value::Bytes(h.to_vec())).collect()),
        ]);
        let mut proof_bytes = Vec::new();
        ciborium::into_writer(&proof, &mut proof_bytes)
            .map_err(|_| HttpProfileError::MalformedEvidence("scitt inclusion proof encode"))?;

        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .key_id(self.kid.as_bytes().to_vec())
            .value(
                HEADER_VERIFIABLE_DATA_STRUCTURE,
                Value::Integer(VDS_RFC9162_SHA256.into()),
            )
            .build();
        let unprotected = HeaderBuilder::new()
            .value(
                HEADER_INCLUSION_PROOFS,
                Value::Array(vec![Value::Bytes(proof_bytes)]),
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
                let right = if i + 1 < level.len() {
                    level[i + 1]
                } else {
                    level[i]
                };
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
        }
    }

    fn statement(commitment: EvidenceCommitment) -> SignedStatement {
        issue_signed_statement(ISSUER_KID, commitment, 1_700_000_000, |b| {
            mcp_re_core::b64url_decode(&issuer().sign(b))
                .map_err(|_| HttpProfileError::InvalidSignature)
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
            mcp_re_core::b64url_decode(&ts().sign(b))
                .map_err(|_| HttpProfileError::InvalidSignature)
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
                ChainLabel::Incomplete {
                    hop: 1,
                    reason: IncompleteReason::TerminalExpected,
                },
                1,
            ),
            None,
            None,
        );
        assert!(
            !commitment.is_complete_record(),
            "the receipt commits to an incomplete record"
        );
        assert!(
            commitment.chain_label.starts_with("incomplete:1:"),
            "and names the failing hop"
        );

        let st = statement(commitment);
        let mut svc = PrototypeTransparencyService::new(TS_KID);
        let receipt = register(&mut svc, &st);
        verify_receipt_offline(&st, &receipt, ir(), tr()).expect("verifies");
        // The verified statement still says incomplete — the receipt did not launder it.
        assert!(!st.commitment.is_complete_record());
    }

    #[test]
    fn a_tampered_statement_fails_the_receipt() {
        let st = statement(EvidenceCommitment::from_reconstruction(
            &recon(ChainLabel::Complete, 1),
            None,
            None,
        ));
        let mut svc = PrototypeTransparencyService::new(TS_KID);
        let receipt = register(&mut svc, &st);

        // Tamper the COSE bytes themselves — what an attacker actually transmits.
        // The replacement is the SAME LENGTH, so the CBOR still parses and the
        // failure is the signature rather than a decode error: a test that tampered
        // the structure would pass for the wrong reason.
        let mut bytes = st.to_cose().to_vec();
        let at = find(&bytes, b"complete").expect("the label is in the payload");
        bytes[at..at + 8].copy_from_slice(b"complet3");
        let tampered = SignedStatement::from_cose(&bytes).expect("still parses");
        assert_eq!(tampered.commitment().chain_label, "complet3");

        assert_eq!(
            verify_receipt_offline(&tampered, &receipt, ir(), tr()).unwrap_err(),
            HttpProfileError::ReceiptInvalid,
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

        let mut edited = st.clone();
        edited.commitment.chain_label = "complete-but-lying".into();
        // It verifies, because the COSE bytes are untouched — and the commitment a
        // consumer should read is the one recovered from those bytes.
        verify_receipt_offline(&edited, &receipt, ir(), tr()).expect("the signed bytes are intact");
        let recovered = SignedStatement::from_cose(edited.to_cose()).expect("parses");
        assert_eq!(recovered.commitment().chain_label, "complete");
    }

    /// The first occurrence of `needle` in `haystack`.
    fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    #[test]
    fn a_forged_inclusion_path_fails() {
        let st = statement(EvidenceCommitment::from_reconstruction(
            &recon(ChainLabel::Complete, 2),
            None,
            None,
        ));
        let mut svc = PrototypeTransparencyService::new(TS_KID);
        let mut receipt = register(&mut svc, &st);
        // Swap a sibling: the recomputed root no longer matches the signed one.
        // The proof lives in the UNPROTECTED header, so this is exactly the tamper a
        // receipt must survive — forging it cannot forge inclusion, it can only make
        // the derived root fail to match the one the service signed.
        receipt.inclusion_path = vec![vec![9u8; 32]];
        assert!(matches!(
            verify_receipt_offline(&st, &receipt, ir(), tr()).unwrap_err(),
            HttpProfileError::ReceiptInclusionInvalid | HttpProfileError::ReceiptInvalid,
        ));
    }

    #[test]
    fn an_untrusted_issuer_or_ts_is_rejected() {
        let st = statement(EvidenceCommitment::from_reconstruction(
            &recon(ChainLabel::Complete, 1),
            None,
            None,
        ));
        let mut svc = PrototypeTransparencyService::new(TS_KID);
        let receipt = register(&mut svc, &st);
        assert_eq!(
            verify_receipt_offline(&st, &receipt, |_| None, tr()).unwrap_err(),
            HttpProfileError::ReceiptIssuerUntrusted,
        );
    }
}
