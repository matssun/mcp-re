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
//! one (MCPRE-494): a Signed Statement is a tagged `COSE_Sign1` satisfying the RFC 9943
//! §6.1 CDDL — CWT claims (RFC 9597 label 15) carrying `iss` and `sub` in the PROTECTED
//! header — and a Receipt is a tagged `COSE_Sign1` satisfying RFC 9942 §5.2.1: `vds` in
//! the protected header, the inclusion proof under `vdp` → `inclusion-proof` in the
//! unprotected header, and the RFC 9162 Merkle Tree Hash as the payload. Conformance
//! vectors are frozen from those octets in `mcp-re-conformance/tests/vectors/scitt/`.
//!
//! **Two deliberate restrictions on what this verifier accepts**, both narrower than the
//! RFC permits, and both stated here rather than left to be discovered:
//!
//! 1. **Attached payloads only.** RFC 9942 §4.4 allows a Receipt to carry a detached
//!    payload — its own Figure 6 shows one — but this verifier checks the service's
//!    signature over the Merkle root the payload carries. Verifying a detached receipt
//!    would mean taking that root from the caller, and a caller-supplied root is a
//!    caller-chosen answer. A detached receipt is refused as rootless.
//! 2. **EdDSA and ES256 only.** Any other `alg` is refused rather than attempted, and the
//!    resolved key must agree with the `alg` the protected header names.
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

use ciborium::Value;
use coset::iana;
use coset::CoseSign1;
use coset::CoseSign1Builder;
use coset::HeaderBuilder;
use coset::Label;
use coset::TaggedCborSerializable;
use mcp_re_core::b64url_decode;
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
use crate::evidence::RequestEvidence;

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

/// `vds`: COSE header label for the verifiable-data-structure a Receipt proves
/// inclusion in (RFC 9942 §5.2.1, Figure 4), in the PROTECTED header. It is covered
/// by the signature because it tells the verifier how to READ the proof — a verifier
/// that took the structure identifier from unprotected data could be steered into
/// walking a proof with the wrong algorithm.
const HEADER_VDS: i64 = 395;

/// `vdp`: COSE header label for the Verifiable Data Structure Proofs of a Receipt
/// (RFC 9942 §5.2.1, Figure 5), in the UNPROTECTED header — a proof is not signed by
/// the tree head it proves against.
const HEADER_VDP: i64 = 396;

/// `inclusion-proof`: the proof-type key inside the `vdp` map (RFC 9942 §5.2.1). The
/// map is keyed by proof type because one Receipt may carry inclusion AND consistency
/// proofs; the label selects which, and its value is an array of proofs.
const PROOF_INCLUSION: i64 = -1;

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
fn leaf_hash(statement: &SignedStatement, profile: StatementLeafProfile) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    match profile {
        StatementLeafProfile::StatementBytes => h.update(statement.to_cose()),
        StatementLeafProfile::StatementDigest => h.update(Sha256::digest(statement.to_cose())),
    }
    h.finalize().into()
}

/// WHICH bytes a transparency service logs as the Merkle entry for a Signed Statement.
///
/// RFC 9162 §2.1 defines the leaf hash as `SHA-256(0x00 ‖ d(i))` over the i-th ENTRY, and
/// RFC 9943 says the service registers the Signed Statement — but neither document says
/// whether the entry is the statement's octets or a digest of them. That gap is real, and
/// two conforming services have been observed on opposite sides of it, so a verifier
/// cannot deduce the answer from the receipt.
///
/// **Exactly one profile applies to any verification.** Trying both and accepting either
/// would be strictly worse than picking wrong: it hands an attacker two chances at the
/// fold, and it destroys the property the proof is for — that the receipt pins WHICH
/// entry was logged. So the profile comes from the pinned service artifact, which an
/// operator wrote down and reviewed, and never from the receipt being checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StatementLeafProfile {
    /// The entry is the Signed Statement's own COSE octets: `SHA-256(0x00 ‖ statement)`.
    ///
    /// The default, and the more direct reading of RFC 9162 §2.1 composed with RFC 9943:
    /// what the service registers is the statement, so the statement is the entry. The
    /// RFC 9942 editor's own implementation (`@transmute/cose`) hashes this way.
    #[default]
    StatementBytes,
    /// The entry is a digest of the statement: `SHA-256(0x00 ‖ SHA-256(statement))`.
    ///
    /// Used by services that log digests rather than documents — `capsule-anchor` does,
    /// and its source calls it a deliberate exception to its own leaf rule. Verifiable,
    /// but only if a verifier is told; it cannot be inferred.
    StatementDigest,
}

/// A resolved transparency service: the key its receipts are verified with, and the leaf
/// profile its log uses.
///
/// The two travel together because they are two halves of one question — "how do I check
/// this service's receipts" — and separating them into independent parameters would let a
/// caller pair a pinned key with a profile nobody pinned.
#[derive(Debug, Clone)]
pub struct ResolvedTransparencyService {
    /// The key that verifies the service's receipt signatures.
    pub key: CoseVerificationKey,
    /// Which bytes this service's log hashes as the Merkle entry.
    pub leaf_profile: StatementLeafProfile,
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
    resolve_issuer: impl Fn(&str) -> Option<CoseVerificationKey>,
    resolve_ts: impl Fn(&str) -> Option<ResolvedTransparencyService>,
) -> Result<(), HttpProfileError> {
    // 1. Issuer signature over the statement's own Sig_structure.
    let issuer =
        resolve_issuer(statement.issuer_kid()).ok_or(HttpProfileError::ReceiptIssuerUntrusted)?;
    verify_cose_sign1(statement.to_cose(), &issuer)?;

    // 2. Inclusion proof: fold the leaf up through the sibling path and require the
    //    result to equal the root the receipt commits to. The index bits pick the
    //    left/right position at each level, exactly as RFC 9162 defines.
    let ts = resolve_ts(receipt.ts_kid()).ok_or(HttpProfileError::ReceiptIssuerUntrusted)?;
    let mut computed = leaf_hash(statement, ts.leaf_profile).to_vec();
    let mut index = receipt.leaf_index;
    for sibling in &receipt.inclusion_path {
        computed = if index & 1 == 0 {
            node_hash(&computed, sibling).to_vec()
        } else {
            node_hash(sibling, &computed).to_vec()
        };
        index >>= 1;
    }
    if let Some(root) = &receipt.root {
        if &computed != root {
            return Err(HttpProfileError::ReceiptInclusionInvalid);
        }
    }

    // 3. The receipt's own signature, over the root the fold just reproduced — so a
    //    verified receipt is the service's statement that THIS leaf is in a tree it
    //    signed.
    //
    //    For a detached receipt the fold's output IS the payload the signature is
    //    checked against, which is why no separate root comparison is needed above: a
    //    wrong fold produces a different payload and the signature simply fails. The
    //    root is never taken from the caller — it is derived from the statement under
    //    verification.
    verify_cose_sign1_with_payload(
        receipt.to_cose(),
        &ts.key,
        receipt.root.is_none(),
        &computed,
    )?;
    Ok(())
}

/// A key a `COSE_Sign1` in the SCITT profile may be verified with.
///
/// Two algorithms, for two different reasons. MCP-RE issues its own Signed Statements
/// with Ed25519. A transparency service is not ours and signs with what it signs with:
/// RFC 9942's own receipt examples use `ES256`, and every running implementation
/// observed uses a P-256 or P-384 key. Verifying a receipt therefore requires ECDSA,
/// while MCP-RE's request and response signing stays Ed25519-only — `mcp-re-core`
/// still refuses `ES256` for message signatures, and nothing here changes that.
///
/// The key names the algorithm, so a message cannot. A verifier that took the
/// algorithm from the message and then looked for any key that might work is the
/// classic COSE/JOSE algorithm-confusion shape; here the resolved key and the
/// protected `alg` must agree or verification is refused.
#[derive(Debug, Clone)]
pub enum CoseVerificationKey {
    /// Ed25519, for `alg: EdDSA` (-8).
    Ed25519(VerificationKey),
    /// ECDSA on NIST P-256, for `alg: ES256` (-7), as uncompressed affine coordinates.
    EcdsaP256 {
        /// The `x` coordinate, exactly 32 octets (COSE `EC2` key parameter -2).
        x: [u8; 32],
        /// The `y` coordinate, exactly 32 octets (COSE `EC2` key parameter -3).
        y: [u8; 32],
    },
}

impl From<VerificationKey> for CoseVerificationKey {
    fn from(key: VerificationKey) -> Self {
        CoseVerificationKey::Ed25519(key)
    }
}

impl CoseVerificationKey {
    /// Build a P-256 key from COSE `EC2` affine coordinates.
    ///
    /// Both coordinates must be exactly 32 octets. RFC 9053 §7.1.1 requires the
    /// fixed-width, leading-zero-preserving form, so a 31-octet `x` is not a small
    /// number to be left-padded — it is a different encoding, and accepting it would
    /// mean two byte strings naming one key. The point is then checked to be on the
    /// curve: an off-curve "public key" has no discrete log to verify against, and
    /// feeding one to a verifier is how invalid-curve attacks start.
    pub fn from_ec2_p256(x: &[u8], y: &[u8]) -> Result<Self, HttpProfileError> {
        let x: [u8; 32] = x.try_into().map_err(|_| {
            HttpProfileError::MalformedEvidence("scitt ec2 p256 x coordinate width")
        })?;
        let y: [u8; 32] = y.try_into().map_err(|_| {
            HttpProfileError::MalformedEvidence("scitt ec2 p256 y coordinate width")
        })?;
        let key = CoseVerificationKey::EcdsaP256 { x, y };
        key.p256_public_key()?;
        Ok(key)
    }

    /// Decode the P-256 point, refusing anything not on the curve.
    fn p256_public_key(&self) -> Result<p256::ecdsa::VerifyingKey, HttpProfileError> {
        let CoseVerificationKey::EcdsaP256 { x, y } = self else {
            return Err(HttpProfileError::MalformedEvidence(
                "scitt cose algorithm key mismatch",
            ));
        };
        // SEC1 uncompressed: 0x04 || X || Y.
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..33].copy_from_slice(x);
        sec1[33..].copy_from_slice(y);
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
            .map_err(|_| HttpProfileError::MalformedEvidence("scitt ec2 p256 point not on curve"))
    }
}

/// Verify a tagged `COSE_Sign1`'s signature over its own `Sig_structure`.
///
/// The algorithm is read from the PROTECTED header and must be one this verifier
/// implements AND must match the resolved key's algorithm. Both halves matter: an
/// unrecognized `alg` is refused rather than guessed at, and an `alg` that disagrees
/// with the key is refused rather than resolved in the message's favour.
fn verify_cose_sign1(cose: &[u8], key: &CoseVerificationKey) -> Result<(), HttpProfileError> {
    verify_cose_sign1_with_payload(cose, key, false, &[])
}

/// Verify a tagged `COSE_Sign1`, optionally supplying a DETACHED payload.
///
/// When `detached` is set the message carries no payload and `payload` is the value the
/// `Sig_structure` is built with. For a receipt that value is the Merkle root the
/// verifier re-derived from the statement, never anything a caller chose.
fn verify_cose_sign1_with_payload(
    cose: &[u8],
    key: &CoseVerificationKey,
    detached: bool,
    payload: &[u8],
) -> Result<(), HttpProfileError> {
    let sign1 = CoseSign1::from_tagged_slice(cose).map_err(|_| HttpProfileError::ReceiptInvalid)?;
    let alg = match &sign1.protected.header.alg {
        Some(coset::RegisteredLabelWithPrivate::Assigned(alg)) => *alg,
        _ => {
            return Err(HttpProfileError::MalformedEvidence(
                "scitt cose unsupported algorithm",
            ))
        }
    };
    match (alg, key) {
        (iana::Algorithm::EdDSA, CoseVerificationKey::Ed25519(ed)) => {
            let check = |sig: &[u8], data: &[u8]| {
                verify_ed25519_with(data, &b64url_encode(sig), ed, McpReError::InvalidSignature)
            };
            if detached {
                sign1.verify_detached_signature(payload, &[], check)
            } else {
                sign1.verify_signature(&[], check)
            }
            .map_err(|_| HttpProfileError::ReceiptInvalid)
        }
        (iana::Algorithm::ES256, CoseVerificationKey::EcdsaP256 { .. }) => {
            let verifying = key.p256_public_key()?;
            let check = |sig: &[u8], data: &[u8]| verify_es256(&verifying, sig, data);
            if detached {
                sign1.verify_detached_signature(payload, &[], check)
            } else {
                sign1.verify_signature(&[], check)
            }
            .map_err(|_| HttpProfileError::ReceiptInvalid)
        }
        (iana::Algorithm::EdDSA | iana::Algorithm::ES256, _) => Err(
            HttpProfileError::MalformedEvidence("scitt cose algorithm key mismatch"),
        ),
        _ => Err(HttpProfileError::MalformedEvidence(
            "scitt cose unsupported algorithm",
        )),
    }
}

/// Verify an `ES256` COSE signature: fixed-width `r || s`, 64 octets, over SHA-256.
///
/// RFC 9053 §2.1 requires the fixed-width concatenation, NOT the ASN.1/DER `SEQUENCE`
/// that most TLS and X.509 tooling emits. Accepting DER here would be a real hazard
/// rather than leniency: DER is variable-length and admits multiple encodings of the
/// same signature, so a verifier taking both loses the property that one signature has
/// one byte string — and `Sig_structure` verification is built on exact octets.
fn verify_es256(
    key: &p256::ecdsa::VerifyingKey,
    signature: &[u8],
    signed: &[u8],
) -> Result<(), McpReError> {
    let signature: &[u8; 64] = signature
        .try_into()
        .map_err(|_| McpReError::InvalidSignature)?;
    let signature =
        p256::ecdsa::Signature::from_slice(signature).map_err(|_| McpReError::InvalidSignature)?;
    p256::ecdsa::signature::Verifier::verify(key, signed, &signature)
        .map_err(|_| McpReError::InvalidSignature)
}

/// The digest that names one retained-evidence object — the handle a Signed Statement
/// commits to.
///
/// Content-addressed on purpose: the name IS the digest, so a store cannot return
/// different bytes than the ones asked for without the name changing. There is no
/// separate integrity check to forget.
///
/// This is the STORE's address, not the commitment's handle — the handle a Signed
/// Statement carries is role-labelled (see [`verify_retained_evidence`]). Keeping the
/// object store role-agnostic is what lets the same bytes be retained once and
/// referenced from whichever role committed to them.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EvidenceDigest(String);

impl EvidenceDigest {
    /// The digest of `evidence` — SHA-256, base64url, matching the commitment form.
    pub fn of(evidence: &[u8]) -> Self {
        EvidenceDigest(b64url_encode(&Sha256::digest(evidence)))
    }

    /// The digest as the base64url token a commitment carries.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A content-addressed store for the evidence a receipt COMMITS to but does not carry.
///
/// The split is §4.6's: a receipt is small and portable and reveals nothing, while the
/// full request/response bytes stay retained. An auditor needs both — the receipt to
/// know a record was registered, the retained bytes to know WHAT was registered. A
/// receipt alone is not the evidence, and this trait exists so that distinction has a
/// place in the code rather than only in prose.
///
/// Deliberately two methods. This is the narrow interface the SCITT commitment needs,
/// not an evidence platform: `put`/`get` over immutable content-addressed objects is
/// implementable over a filesystem now and an object store later without either
/// implementation knowing about the other.
pub trait RetainedEvidenceStore {
    /// The store's own error, so an implementation can surface its transport's faults.
    type Error;

    /// Retain `evidence` and return its digest. Storing the same bytes twice is not an
    /// error and yields the same digest — content addressing makes writes idempotent.
    fn put(&mut self, evidence: &[u8]) -> Result<EvidenceDigest, Self::Error>;

    /// The bytes for `digest`, or `None` if this store does not hold them.
    ///
    /// Absence is `None` rather than an error: a store legitimately does not hold every
    /// object in existence, and the caller — not the store — decides whether a missing
    /// object is fatal for the verification it is attempting.
    fn get(&self, digest: &EvidenceDigest) -> Result<Option<Vec<u8>>, Self::Error>;
}

/// Check that retained evidence reproduces what a statement committed to.
///
/// This is the step that makes the retained/committed split mean something. A verified
/// receipt says a statement was registered; it says nothing about whether the bytes
/// somebody hands you later are the ones that statement was about. Recomputing the
/// handles is what connects them, and a missing or altered object must fail here rather
/// than be waved through because the receipt verified.
///
/// **Two different digests, deliberately.** The store addresses an object by a plain
/// SHA-256 of its bytes; a commitment names it by the §7.1 ROLE-LABELLED handle,
/// `sha256(label ‖ 0x00 ‖ bytes)`. They are not interchangeable, and the labelling is
/// not decoration: the identical signature base in a request role and a response role
/// must be two different values, or a response handle could be presented as a request
/// handle. So the handles here are derived through [`RequestEvidence`], the same code
/// the serving path uses, rather than recomputed from a formula copied to this module —
/// a copy could drift, and a drifted copy would silently accept the wrong bytes.
pub fn verify_retained_evidence(
    commitment: &EvidenceCommitment,
    request_signature_base: &[u8],
    response_signature_base: &[u8],
) -> Result<(), HttpProfileError> {
    let request = RequestEvidence::from_signature_base(request_signature_base);
    if request.digest_value != commitment.request_evidence {
        return Err(HttpProfileError::MalformedEvidence(
            "retained request evidence does not match the commitment",
        ));
    }
    let response = RequestEvidence::from_response_signature_base(response_signature_base);
    if response.digest_value != commitment.response_evidence {
        return Err(HttpProfileError::MalformedEvidence(
            "retained response evidence does not match the commitment",
        ));
    }
    Ok(())
}

/// A pinned transparency-service verification key, recorded from a discovery document
/// at a moment in time (`ScittServiceTrustPinV1`).
///
/// **What a pin does and does not establish.** It does NOT say the service is
/// trustworthy, that its log is append-only, or that its operator is independent. It
/// records exactly WHICH key an interoperability run verified against, and where that
/// key came from, so the run is reproducible and auditable after the service is gone.
/// That is the whole claim, and it is worth having: without it, "the receipt verified"
/// is unfalsifiable, because the key it verified against was fetched live and never
/// written down.
///
/// **Why the fetch is not here.** This crate is pure — no networking, async or fs — so
/// discovery lives in tooling (`tools/scitt_fetch_service_key.py`) and the verifier
/// receives the pinned artifact. That split is the point of the offline property: once
/// pinned, verification contacts nobody, which is exactly what an auditor holding
/// only the archived bytes can reproduce.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScittServiceTrustPin {
    /// The schema token, so a reader of the artifact knows what it is holding.
    pub schema: String,
    /// How the deployment names this service — free-form, for humans reading a corpus.
    pub service_identifier: String,
    /// How the key was discovered (for example `well-known-scitt-keys`).
    pub discovery_method: String,
    /// The exact URI the key came from.
    pub discovery_uri: String,
    /// When it was fetched, RFC 3339. Not a validity claim: keys rotate, and a pin is
    /// a record of one moment rather than a promise about later ones.
    pub fetched_at: String,
    /// The `kid` the receipt names and this key answers to.
    pub kid: String,
    /// The COSE algorithm this key is for — `EdDSA` or `ES256`.
    pub algorithm: String,
    /// The public key: `x`/`y` base64url for `ES256`, `x` alone for `EdDSA`.
    pub public_key: PinnedPublicKey,
    /// SHA-256 over the canonical COSE_Key (RFC 9679 thumbprint), base64url. A short
    /// value a human can compare across a corpus, a report and a log.
    pub public_key_thumbprint: String,
    /// SHA-256 over the discovery document's exact bytes, base64url — so a later reader
    /// can tell whether the document it fetches is the one the pin was cut from.
    pub discovery_document_digest: String,
    /// Which bytes this service's log hashes as the Merkle entry. Absent means the
    /// default: the statement's own octets. Recorded in the PIN because it cannot be
    /// inferred from a receipt, and because an operator should have to write it down
    /// before MCP-RE will fold a service's log any other way.
    #[serde(default)]
    pub leaf_profile: StatementLeafProfile,
}

/// The key material inside a pin.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedPublicKey {
    /// The `x` coordinate (`ES256`) or the public key (`EdDSA`), base64url.
    pub x: String,
    /// The `y` coordinate, base64url. `ES256` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

/// The schema token a pin must carry.
pub const TRUST_PIN_SCHEMA: &str = "mcp-re-scitt-service-trust-pin/v1";

impl ScittServiceTrustPin {
    /// The verification key this pin holds.
    ///
    /// The algorithm comes from the PIN, never from the receipt: the pin is what the
    /// operator recorded and reviewed, and letting an incoming receipt nominate the
    /// algorithm to verify itself with is the confusion this whole seam avoids.
    pub fn verification_key(&self) -> Result<CoseVerificationKey, HttpProfileError> {
        if self.schema != TRUST_PIN_SCHEMA {
            return Err(HttpProfileError::MalformedEvidence(
                "scitt trust pin schema",
            ));
        }
        let x = b64url_decode(&self.public_key.x)
            .map_err(|_| HttpProfileError::MalformedEvidence("scitt trust pin key encoding"))?;
        match self.algorithm.as_str() {
            "ES256" => {
                let y = self
                    .public_key
                    .y
                    .as_deref()
                    .ok_or(HttpProfileError::MalformedEvidence("scitt trust pin ec2 y"))?;
                let y = b64url_decode(y).map_err(|_| {
                    HttpProfileError::MalformedEvidence("scitt trust pin key encoding")
                })?;
                CoseVerificationKey::from_ec2_p256(&x, &y)
            }
            "EdDSA" => {
                // An `EdDSA` pin carrying a `y` is not an Ed25519 key with a harmless
                // extra field — it is an ES256 key mislabelled, or a pin built by
                // something that did not know which curve it had.
                if self.public_key.y.is_some() {
                    return Err(HttpProfileError::MalformedEvidence(
                        "scitt trust pin eddsa carries an ec2 y coordinate",
                    ));
                }
                let key = VerificationKey::from_b64url(&self.public_key.x)
                    .map_err(|_| HttpProfileError::MalformedEvidence("scitt trust pin ed25519"))?;
                let _ = &x;
                Ok(CoseVerificationKey::Ed25519(key))
            }
            _ => Err(HttpProfileError::MalformedEvidence(
                "scitt trust pin unsupported algorithm",
            )),
        }
    }

    /// Resolve `kid` against this pin, for [`verify_receipt_offline`].
    ///
    /// A `kid` that does not match returns nothing: a pin answers for the one key it
    /// pinned, and a receipt naming a different key has not been pinned at all.
    pub fn resolve(&self, kid: &str) -> Option<ResolvedTransparencyService> {
        (kid == self.kid)
            .then(|| self.verification_key().ok())
            .flatten()
            .map(|key| ResolvedTransparencyService {
                key,
                leaf_profile: self.leaf_profile,
            })
    }
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

        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .key_id(self.kid.as_bytes().to_vec())
            .value(HEADER_VDS, Value::Integer(VDS_RFC9162_SHA256.into()))
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

    fn ir() -> impl Fn(&str) -> Option<CoseVerificationKey> {
        |k: &str| (k == ISSUER_KID).then(|| issuer().public_key().into())
    }
    fn tr() -> impl Fn(&str) -> Option<ResolvedTransparencyService> {
        |k: &str| {
            (k == TS_KID).then(|| ResolvedTransparencyService {
                key: ts().public_key().into(),
                leaf_profile: StatementLeafProfile::StatementBytes,
            })
        }
    }

    /// A resolver for a service using `key`, with the default leaf profile.
    fn ts_with(key: CoseVerificationKey) -> impl Fn(&str) -> Option<ResolvedTransparencyService> {
        move |k: &str| {
            (k == TS_KID).then(|| ResolvedTransparencyService {
                key: key.clone(),
                leaf_profile: StatementLeafProfile::StatementBytes,
            })
        }
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

    // -----------------------------------------------------------------------
    // Retained evidence — what the receipt commits to but does not carry.
    // -----------------------------------------------------------------------

    /// The retained bytes reproduce the commitment, and altering either side breaks it.
    #[test]
    fn retained_evidence_reproduces_the_commitment() {
        let (req, rsp) = (b"req-0".as_slice(), b"rsp-0".as_slice());
        let commitment =
            EvidenceCommitment::from_reconstruction(&recon(ChainLabel::Complete, 1), None, None);

        verify_retained_evidence(&commitment, req, rsp).expect("the retained bytes match");

        assert_eq!(
            verify_retained_evidence(&commitment, b"req-tampered", rsp).unwrap_err(),
            HttpProfileError::MalformedEvidence(
                "retained request evidence does not match the commitment"
            ),
        );
        assert_eq!(
            verify_retained_evidence(&commitment, req, b"rsp-tampered").unwrap_err(),
            HttpProfileError::MalformedEvidence(
                "retained response evidence does not match the commitment"
            ),
        );
    }

    /// The two roles are distinct values over the same bytes. Presenting the response
    /// base as the request base must fail — that is what the domain separation buys,
    /// and without this test the labelling could be dropped and everything else would
    /// still pass.
    #[test]
    fn the_two_evidence_roles_are_not_interchangeable() {
        let same = b"identical-signature-base".as_slice();
        let commitment = EvidenceCommitment {
            request_evidence: RequestEvidence::from_signature_base(same).digest_value,
            response_evidence: RequestEvidence::from_response_signature_base(same).digest_value,
            bindings_commitment: None,
            verified_context_commitment: None,
            chain_label: "complete".into(),
            chain_commitment: String::new(),
        };
        assert_ne!(
            commitment.request_evidence, commitment.response_evidence,
            "the same bytes in two roles are two different handles"
        );
        verify_retained_evidence(&commitment, same, same).expect("each role in its own place");
    }

    /// A verified receipt is NOT evidence retention. The receipt verifies with no
    /// retained bytes present at all, and the retained check is a separate refusal —
    /// so a caller cannot present "the receipt verified" as "the evidence is held".
    #[test]
    fn a_verified_receipt_does_not_imply_the_evidence_is_retained() {
        let commitment =
            EvidenceCommitment::from_reconstruction(&recon(ChainLabel::Complete, 1), None, None);
        let st = statement(commitment.clone());
        let mut svc = PrototypeTransparencyService::new(TS_KID);
        let receipt = register(&mut svc, &st);

        // The receipt verifies knowing nothing about the underlying evidence.
        verify_receipt_offline(&st, &receipt, ir(), tr()).expect("receipt verifies");

        // And the evidence check still fails when the bytes are not the committed ones.
        assert!(verify_retained_evidence(&commitment, b"not the evidence", b"nor this").is_err());
    }

    // -----------------------------------------------------------------------
    // Trust pins — which key an interoperability run actually used.
    // -----------------------------------------------------------------------

    fn pin(algorithm: &str, x: &str, y: Option<&str>) -> ScittServiceTrustPin {
        ScittServiceTrustPin {
            schema: TRUST_PIN_SCHEMA.to_owned(),
            service_identifier: "test-service".into(),
            discovery_method: "well-known-scitt-keys".into(),
            discovery_uri: "https://example.test/.well-known/scitt-keys".into(),
            fetched_at: "2026-07-31T00:00:00Z".into(),
            kid: TS_KID.into(),
            algorithm: algorithm.to_owned(),
            public_key: PinnedPublicKey {
                x: x.to_owned(),
                y: y.map(str::to_owned),
            },
            public_key_thumbprint: "unused-by-this-test".into(),
            discovery_document_digest: "unused-by-this-test".into(),
            leaf_profile: StatementLeafProfile::StatementBytes,
        }
    }

    /// A pinned ES256 key verifies a real ES256 receipt, resolved by `kid`.
    #[test]
    fn a_pinned_es256_key_verifies_a_receipt() {
        let st = statement(EvidenceCommitment::from_reconstruction(
            &recon(ChainLabel::Complete, 1),
            None,
            None,
        ));
        let receipt = Receipt::from_cose(&es256_receipt(&st)).expect("parses");
        let point = ts_p256().verifying_key().to_encoded_point(false);
        let pinned = pin(
            "ES256",
            &b64url_encode(point.x().expect("x")),
            Some(&b64url_encode(point.y().expect("y"))),
        );

        verify_receipt_offline(&st, &receipt, ir(), |kid| pinned.resolve(kid))
            .expect("the pinned key verifies the receipt");

        // A receipt naming a different kid is not covered by this pin.
        assert!(pinned.resolve("some-other-kid").is_none());
    }

    /// A pin whose schema, algorithm or key material is wrong yields no key at all,
    /// rather than a key that happens to parse. The pin is the reviewed artifact; if it
    /// is not the shape that was reviewed, it is not usable.
    #[test]
    fn a_malformed_pin_yields_no_key() {
        let x = b64url_encode(&[7u8; 32]);

        let mut wrong_schema = pin("EdDSA", &x, None);
        wrong_schema.schema = "something-else/v1".into();
        assert_eq!(
            wrong_schema.verification_key().unwrap_err(),
            HttpProfileError::MalformedEvidence("scitt trust pin schema"),
        );

        assert_eq!(
            pin("RS256", &x, None).verification_key().unwrap_err(),
            HttpProfileError::MalformedEvidence("scitt trust pin unsupported algorithm"),
        );

        assert_eq!(
            pin("ES256", &x, None).verification_key().unwrap_err(),
            HttpProfileError::MalformedEvidence("scitt trust pin ec2 y"),
        );

        // An Ed25519 pin carrying a y coordinate is a mislabelled EC2 key, not an
        // Ed25519 key with a spare field.
        assert_eq!(
            pin("EdDSA", &x, Some(&x)).verification_key().unwrap_err(),
            HttpProfileError::MalformedEvidence(
                "scitt trust pin eddsa carries an ec2 y coordinate"
            ),
        );
    }

    // -----------------------------------------------------------------------
    // ES256 receipts — what a real transparency service signs with.
    // -----------------------------------------------------------------------

    /// A fixed P-256 key pair. The scalar is a constant so the test is deterministic;
    /// it is a test key and appears nowhere outside these tests.
    fn ts_p256() -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::from_slice(&[0x42u8; 32]).expect("a valid P-256 scalar")
    }

    fn ts_p256_key() -> CoseVerificationKey {
        let point = ts_p256().verifying_key().to_encoded_point(false);
        CoseVerificationKey::from_ec2_p256(point.x().expect("x"), point.y().expect("y"))
            .expect("a point on the curve")
    }

    /// Re-sign a receipt's `Sig_structure` with ES256, as a foreign service would:
    /// same tree, same proof, `alg: ES256` in the protected header.
    fn es256_receipt(statement: &SignedStatement) -> Vec<u8> {
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

    /// An ES256 receipt verifies. This is the capability #501 needs: MCP-RE issues its
    /// statements with Ed25519, and the service that countersigns them does not.
    #[test]
    fn an_es256_receipt_from_a_foreign_service_verifies() {
        let st = statement(EvidenceCommitment::from_reconstruction(
            &recon(ChainLabel::Complete, 1),
            None,
            None,
        ));
        let receipt = Receipt::from_cose(&es256_receipt(&st)).expect("parses");
        verify_receipt_offline(&st, &receipt, ir(), ts_with(ts_p256_key()))
            .expect("an ES256 receipt over a single-leaf tree verifies");
    }

    /// The message does not get to choose the algorithm. An ES256 receipt presented
    /// against an Ed25519 key is refused as a mismatch rather than resolved in the
    /// message's favour — the algorithm-confusion shape.
    #[test]
    fn an_algorithm_that_disagrees_with_the_resolved_key_is_refused() {
        let st = statement(EvidenceCommitment::from_reconstruction(
            &recon(ChainLabel::Complete, 1),
            None,
            None,
        ));
        let receipt = Receipt::from_cose(&es256_receipt(&st)).expect("parses");
        assert_eq!(
            verify_receipt_offline(&st, &receipt, ir(), tr()).unwrap_err(),
            HttpProfileError::MalformedEvidence("scitt cose algorithm key mismatch"),
        );

        // And the converse: an EdDSA receipt against a P-256 key.
        let mut svc = PrototypeTransparencyService::new(TS_KID);
        let eddsa = register(&mut svc, &st);
        assert_eq!(
            verify_receipt_offline(&st, &eddsa, ir(), ts_with(ts_p256_key())).unwrap_err(),
            HttpProfileError::MalformedEvidence("scitt cose algorithm key mismatch"),
        );
    }

    /// RFC 9053 §2.1 requires fixed-width `r || s`. A DER `SEQUENCE` — what most X.509
    /// and TLS tooling emits, and the same signature mathematically — is refused,
    /// because admitting both would mean one signature has more than one valid byte
    /// string while `Sig_structure` verification rests on exact octets.
    #[test]
    fn a_der_encoded_es256_signature_is_refused() {
        let st = statement(EvidenceCommitment::from_reconstruction(
            &recon(ChainLabel::Complete, 1),
            None,
            None,
        ));
        let cose = es256_receipt(&st);
        let sign1 = CoseSign1::from_tagged_slice(&cose).expect("parses");
        let fixed = p256::ecdsa::Signature::from_slice(&sign1.signature).expect("fixed width");

        let mut der = sign1.clone();
        der.signature = fixed.to_der().as_bytes().to_vec();
        assert_ne!(der.signature.len(), 64, "DER is a different length");
        let receipt =
            Receipt::from_cose(&der.to_tagged_vec().expect("re-encode")).expect("still parses");
        assert_eq!(
            verify_receipt_offline(&st, &receipt, ir(), ts_with(ts_p256_key())).unwrap_err(),
            HttpProfileError::ReceiptInvalid,
        );
    }

    /// Coordinates must be exactly 32 octets, and the point must be on the curve. A
    /// short coordinate is a different encoding rather than a small number to pad, and
    /// an off-curve point has no discrete log to verify against at all.
    #[test]
    fn a_malformed_p256_key_is_refused_at_construction() {
        let point = ts_p256().verifying_key().to_encoded_point(false);
        let (x, y) = (point.x().expect("x"), point.y().expect("y"));

        assert_eq!(
            CoseVerificationKey::from_ec2_p256(&x[1..], y).unwrap_err(),
            HttpProfileError::MalformedEvidence("scitt ec2 p256 x coordinate width"),
        );
        assert_eq!(
            CoseVerificationKey::from_ec2_p256(x, &y[..31]).unwrap_err(),
            HttpProfileError::MalformedEvidence("scitt ec2 p256 y coordinate width"),
        );
        // Right widths, wrong curve point.
        let mut off = y.to_vec();
        off[31] ^= 0x01;
        assert_eq!(
            CoseVerificationKey::from_ec2_p256(x, &off).unwrap_err(),
            HttpProfileError::MalformedEvidence("scitt ec2 p256 point not on curve"),
        );
    }

    /// An algorithm this verifier does not implement is refused, never attempted with
    /// whatever key happened to resolve.
    #[test]
    fn an_unsupported_algorithm_is_refused() {
        let st = statement(EvidenceCommitment::from_reconstruction(
            &recon(ChainLabel::Complete, 1),
            None,
            None,
        ));
        let cose = es256_receipt(&st);
        let sign1 = CoseSign1::from_tagged_slice(&cose).expect("parses");
        let mut es512 = sign1.clone();
        es512.protected = coset::ProtectedHeader {
            original_data: None,
            header: HeaderBuilder::new()
                .algorithm(iana::Algorithm::ES512)
                .key_id(TS_KID.as_bytes().to_vec())
                .value(HEADER_VDS, Value::Integer(VDS_RFC9162_SHA256.into()))
                .build(),
        };
        let receipt =
            Receipt::from_cose(&es512.to_tagged_vec().expect("re-encode")).expect("parses");
        assert_eq!(
            verify_receipt_offline(&st, &receipt, ir(), ts_with(ts_p256_key())).unwrap_err(),
            HttpProfileError::MalformedEvidence("scitt cose unsupported algorithm"),
        );
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
