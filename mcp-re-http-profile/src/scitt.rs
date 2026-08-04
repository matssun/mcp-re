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
    /// Digest over the SUBMITTED hop bytes, verified or not.
    ///
    /// The three fields above are all derived from the VERIFIED prefix, so a chain that
    /// broke at hop 0 left every record with the same two empty handles and the same
    /// fold over zero bytes: byte-identical statements about unrelated calls. This field
    /// gives such a record an identity — of the submission, not of a verified call. Read
    /// it with [`commits_to_verified_evidence`](Self::commits_to_verified_evidence),
    /// which still says whether anything in it verified.
    ///
    /// Defaulted for reading, because a v1 statement genuinely has no submission
    /// identity and refusing to parse one would make every pre-revision record
    /// unreadable rather than merely weaker. That default is safe HERE and would not be
    /// safe in a receipt header: this field lives inside the payload the issuer's
    /// COSE_Sign1 covers, so removing it from a v2 statement breaks the signature.
    /// Nothing an attacker can do turns a v2 record into a v1 one.
    /// [`identifies_a_submission`](Self::identifies_a_submission) is how a reader tells
    /// the two apart.
    #[serde(default)]
    pub submitted_commitment: String,
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
        //
        // A reconstruction that broke at hop 0 — and the empty chain — has no verified
        // prefix, so there is nothing here to take an identity from: the handles are
        // empty and the shape digest folds over nothing. `submitted_commitment` is what
        // distinguishes two such records; it is an identity for the SUBMISSION and
        // asserts nothing about it, so
        // [`commits_to_verified_evidence`](Self::commits_to_verified_evidence) remains
        // how a reader tells whether anything verified. [`verify_retained_evidence`]
        // still refuses to compare retained bytes against such a record rather than
        // reporting a match that holds for every unrelated record that failed the same
        // way.
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
            submitted_commitment: reconstruction.submitted_commitment.clone(),
        }
    }

    /// Whether this record is a COMPLETE call record. An incomplete one is not a
    /// weaker complete record — it is a distinct, explicitly-labeled record, and a
    /// receipt over it can never read as whole.
    pub fn is_complete_record(&self) -> bool {
        self.chain_label == "complete"
    }

    /// Whether this commitment names any verified evidence at all.
    ///
    /// False for a reconstruction with no verified prefix — a chain that broke at hop
    /// 0, and the empty chain. Every such record produces the SAME three identity
    /// fields: two empty handles and SHA-256 over zero bytes. The label still says
    /// which hop broke and why, so the statement is a truthful record of "I was handed
    /// evidence and none of it verified", but it identifies no particular call, and
    /// recomputing the handles from some other archivist's bytes would reproduce it
    /// exactly. Anything that treats a commitment as naming specific bytes — above all
    /// [`verify_retained_evidence`] — must consult this first.
    pub fn commits_to_verified_evidence(&self) -> bool {
        !self.request_evidence.is_empty() || !self.response_evidence.is_empty()
    }

    /// Whether this record identifies the SUBMISSION it was made about.
    ///
    /// False only for a statement issued before the evidence profile carried
    /// [`submitted_commitment`](Self::submitted_commitment). Such a record that also
    /// fails [`commits_to_verified_evidence`](Self::commits_to_verified_evidence) names
    /// nothing at all: it is a truthful account of "I was handed evidence and none of it
    /// verified" that could equally be an account of any other call that failed the same
    /// way. Anything reasoning about WHICH call a record concerns must consult this.
    pub fn identifies_a_submission(&self) -> bool {
        !self.submitted_commitment.is_empty()
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

/// The MCP-RE evidence profile these receipts and statements are issued under.
///
/// It is part of the position commitment's preimage, so a commitment computed under one
/// profile can never be read as valid under another. Bumping it is how a future contract
/// change becomes visible rather than silent.
pub const EVIDENCE_PROFILE: &str = "mcp-re-evidence/v2";

/// Protected header parameter carrying the position commitment (C080).
///
/// A text label, not an integer: this is an MCP-RE profile extension, and a tstr cannot
/// collide with a future IANA assignment in the COSE header registry the way a guessed
/// integer can.
const HEADER_POSITION_COMMITMENT: &str = "mcp-re-position";

/// Domain separator for the position commitment preimage.
const POSITION_COMMITMENT_DOMAIN: &[u8] = b"mcp-re-scitt-position";

/// The position commitment: `H(domain ‖ profile ‖ log_identity ‖ vds ‖ tree_size ‖
/// leaf_index ‖ root_hash)`, every field length-delimited.
///
/// This is what closes C080. `tree_size` and `leaf_index` ride in the UNSIGNED `vdp`
/// header and the `RFC9162_SHA256` receipt payload is the bare Merkle Tree Hash, so the
/// service's signature covers the root and nothing else — and the root does not
/// determine the position. Placing this digest in the PROTECTED header brings the whole
/// tuple under that signature: restating a receipt at a different position changes the
/// recomputed digest and the protected one no longer matches.
///
/// The tuple is bound EXPLICITLY rather than relying on an authenticated `tree_size`
/// making the index derivable. That derivation does hold today — no ambiguity class
/// contains two members sharing a tree size, which
/// `the_tree_size_determines_the_leaf_index_within_every_ambiguity_class` pins — but it
/// is a property of the current verification algorithm, not of the evidence. A contract
/// that depends on a test continuing to pass is weaker than one that states the fact.
///
/// Every component is preceded by its length as 8 octets big-endian, and the integers
/// are fixed-width big-endian. Raw concatenation would let a longer log identity absorb
/// the leading octets of the next field and produce one preimage for two different
/// positions, which is the exact ambiguity this exists to remove.
fn position_commitment(
    log_identity: &str,
    vds: i64,
    tree_size: u64,
    leaf_index: u64,
    root: &[u8],
) -> Vec<u8> {
    let mut h = Sha256::new();
    for part in [
        POSITION_COMMITMENT_DOMAIN,
        EVIDENCE_PROFILE.as_bytes(),
        log_identity.as_bytes(),
        &vds.to_be_bytes()[..],
        &tree_size.to_be_bytes()[..],
        &leaf_index.to_be_bytes()[..],
        root,
    ] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    h.finalize().to_vec()
}

/// Whether a pinned transparency service issues position-bound receipts.
///
/// The old profile authenticates inclusion in the signed root but NOT the exposed
/// position tuple; the new one authenticates the tuple as well. Which applies is a
/// property of the service, so it comes from the pinned artifact an operator wrote down
/// — never from the receipt being checked, which is the value under attack.
///
/// The reverse direction is enforced by the `crit` header rather than by this field: a
/// v2 receipt marks the position parameter critical, so an implementation that does not
/// understand it must refuse rather than verify the receipt while ignoring the
/// commitment. [`Receipt::from_cose`] refuses every critical label it does not know.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReceiptPositionProfile {
    /// Receipts carry no position commitment. `tree_size` and `leaf_index` remain
    /// unauthenticated transport hints, and a relayer may restate them.
    #[default]
    Unbound,
    /// Receipts MUST carry a valid position commitment. A receipt without one is refused
    /// rather than verified under the weaker contract — otherwise pinning the stronger
    /// profile would buy nothing, since an attacker would simply strip the parameter.
    Bound,
}

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
        // RFC 9943 §6.1 REQUIRES `iss` and `sub` in the protected header, and they
        // have to be read, not merely written at issuance.
        //
        // `iss` must equal the `kid`. The kid is the selector this verifier resolves
        // trust through; `iss` is the identity an RFC 9943 consumer reads. Left
        // unbound, one signer can mint a statement that names a THIRD PARTY as issuer
        // — MCP-RE attributes it to the kid, a conforming reader attributes it to
        // `iss`, and two correct readers of an audit artifact disagree about who said
        // it. This is the same binding `admission.rs` makes between its header kid and
        // its claims issuer, for the same reason.
        let iss = cwt_claim(&sign1.protected.header, CWT_ISS)
            .and_then(|v| v.as_text().map(str::to_owned))
            .ok_or(HttpProfileError::MalformedEvidence("scitt statement iss"))?;
        if iss != issuer_kid {
            return Err(HttpProfileError::MalformedEvidence(
                "scitt statement iss does not match the signing kid",
            ));
        }
        // `sub` and the content type are the TYPE TAG. Without them, any other
        // COSE_Sign1 the same issuer key signs is accepted as MCP-RE call evidence as
        // soon as its payload happens to CBOR-decode into an `EvidenceCommitment` —
        // cross-protocol type confusion at the issuer-key seam.
        let sub = cwt_claim(&sign1.protected.header, CWT_SUB)
            .and_then(|v| v.as_text().map(str::to_owned))
            .ok_or(HttpProfileError::MalformedEvidence("scitt statement sub"))?;
        if sub != STATEMENT_SUBJECT {
            return Err(HttpProfileError::MalformedEvidence(
                "scitt statement sub is not mcp-re call evidence",
            ));
        }
        match &sign1.protected.header.content_type {
            Some(coset::ContentType::Text(t)) if t == STATEMENT_CONTENT_TYPE => {}
            _ => {
                return Err(HttpProfileError::MalformedEvidence(
                    "scitt statement content type is not the mcp-re evidence media type",
                ))
            }
        }
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
    pub fn is_position_bound(&self) -> bool {
        self.position_commitment.is_some()
    }

    /// Parse a tagged `COSE_Sign1` receipt WITHOUT verifying it.
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
    /// Whether this service's receipts must carry a position commitment.
    pub position_profile: ReceiptPositionProfile,
}

/// An interior Merkle node hash (RFC 6962 node prefix `0x01`).
fn node_hash(left: &[u8], right: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// The RFC 9162 §2.1.3.2 inclusion-proof verification algorithm, verbatim.
///
/// Returns the Merkle Tree Hash the proof re-derives, or an error if the proof does
/// not fit `(leaf_index, tree_size)`.
///
/// **Why the whole algorithm and not an index-bit fold.** An `index & 1` walk that
/// shifts the index right once per sibling is right only when the tree size is a
/// power of two. Two things break otherwise:
///
///   * **Wrong answer.** In a non-power-of-two tree the right-hand subtree is short,
///     so a node on the right edge is PROMOTED past levels rather than paired. RFC
///     9162's `fn`/`sn` pair is what tracks that: `sn` is the last index at the
///     current level, and `fn == sn` means "right edge, combine as the right child
///     and keep climbing". Without it a conforming receipt for a 3-leaf log folds
///     its operands in the wrong order and is rejected.
///   * **Most restatements are refused.** With only the low bits of `leaf_index`
///     consulted and `tree_size` unused, the trailing bits of the index and the size
///     itself are wholly unconstrained. The terminal `sn == 0` requirement plus the
///     per-step `sn != 0` check makes the PATH LENGTH load-bearing, so `(21, 32)`,
///     `(3, 4)`, `(7, 8)` and `(1, 4)` no longer fold a one-sibling proof to a root.
///
/// **What this function cannot bind, and why.** It does not make `leaf_index` and
/// `tree_size` authentic, and no fold can. In the `RFC9162_SHA256` profile the
/// receipt payload is the bare Merkle Tree Hash (RFC 9942 §5) — unlike an RFC 9162
/// signed tree head, it never covers `tree_size` — and both values ride in the
/// UNSIGNED `vdp` header.
///
/// The scope is not a special family, it is nearly everything. What the verifier
/// computes is fixed by the SEQUENCE of combine directions this loop takes, so any
/// two `(leaf_index, tree_size)` pairs producing the same sequence accept the same
/// path and the same root. Enumerated over every pair with `tree_size <= 1024`,
/// **98.4% lie in a class with at least one other pair**, spread over 251 distinct
/// classes — not one right-edge family. `(1,2)`, `(2,3)`, `(4,5)`, `(8,9)` share the
/// single-sibling class, but so do `(3,4)`, `(5,6)`, `(6,7)` at length 2, and only
/// four pairs in that whole range are unique. Refusing the ambiguous ones is
/// therefore not an available defence: it would refuse essentially every receipt.
///
/// **How it is closed.** Not inside this function — no fold can separate positions that
/// direct it identically. [`position_commitment`] puts the whole tuple in the receipt's
/// PROTECTED header, so the service's signature covers `(profile, log identity, vds,
/// tree_size, leaf_index, root)` and a restatement no longer matches.
///
/// An authenticated `tree_size` ALONE would also suffice: within every class no two
/// members share one, so the size determines the index —
/// `the_tree_size_determines_the_leaf_index_within_every_ambiguity_class` pins that.
/// It is deliberately not what the profile relies on. That sufficiency is a property of
/// this algorithm rather than of the evidence, and a security contract resting on a test
/// continuing to pass is weaker than one that states the fact outright.
///
/// Where a pinned service issues no commitment ([`ReceiptPositionProfile::Unbound`]),
/// the pre-revision contract still applies and both accessors remain transport hints.
///
/// An EMPTY path is admitted only for `tree_size == 1`, which is the one case RFC
/// 9162 defines it for (`PATH(0, D[1]) = {}`); for any larger tree `sn` is non-zero
/// with no siblings left to consume, and the proof is refused.
fn rfc9162_root_from_inclusion_proof(
    leaf: &[u8; 32],
    leaf_index: u64,
    tree_size: u64,
    path: &[Vec<u8>],
) -> Result<[u8; 32], HttpProfileError> {
    if leaf_index >= tree_size {
        return Err(HttpProfileError::ReceiptInclusionInvalid);
    }
    let mut fnode = leaf_index;
    let mut snode = tree_size - 1;
    let mut r = *leaf;
    for sibling in path {
        if snode == 0 {
            // More siblings than the tree has levels for this leaf.
            return Err(HttpProfileError::ReceiptInclusionInvalid);
        }
        if !fnode.is_multiple_of(2) || fnode == snode {
            r = node_hash(sibling, &r);
            while fnode != 0 && fnode.is_multiple_of(2) {
                fnode /= 2;
                snode /= 2;
            }
        } else {
            r = node_hash(&r, sibling);
        }
        fnode /= 2;
        snode /= 2;
    }
    if snode != 0 {
        // Fewer siblings than the tree requires: the proof does not reach the root.
        return Err(HttpProfileError::ReceiptInclusionInvalid);
    }
    Ok(r)
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

    // 2. Inclusion proof: run the RFC 9162 §2.1.3.2 verification algorithm, which
    //    consumes the leaf index AND the tree size, and require the result to equal
    //    the root the receipt commits to.
    let ts = resolve_ts(receipt.ts_kid()).ok_or(HttpProfileError::ReceiptIssuerUntrusted)?;
    let leaf = leaf_hash(statement, ts.leaf_profile);
    let computed = rfc9162_root_from_inclusion_proof(
        &leaf,
        receipt.leaf_index,
        receipt.tree_size,
        &receipt.inclusion_path,
    )?;
    if let Some(root) = &receipt.root {
        if computed.as_slice() != root.as_slice() {
            return Err(HttpProfileError::ReceiptInclusionInvalid);
        }
    }

    let computed = computed.to_vec();

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

    // 4. The position commitment (C080), when the pinned profile says there is one.
    //
    //    AFTER the signature, deliberately. The commitment lives in the protected
    //    header, so before step 3 it is just another attacker-supplied field — comparing
    //    it then would report a position mismatch for a receipt whose real defect is
    //    that nobody signed it. Here it is a value the service demonstrably signed.
    //
    //    It is checked against the root the fold DERIVED, not one supplied beside it, so
    //    the commitment is bound to the statement under verification. A `Bound` pin with
    //    no commitment present is refused rather than falling back to the weaker
    //    contract: accepting on request would let an attacker strip the parameter and
    //    make pinning the stronger profile worth nothing.
    match (ts.position_profile, &receipt.position_commitment) {
        (ReceiptPositionProfile::Bound, None) => {
            return Err(HttpProfileError::ReceiptPositionUnbound)
        }
        (_, Some(bound)) => {
            let expected = position_commitment(
                receipt.ts_kid(),
                VDS_RFC9162_SHA256,
                receipt.tree_size,
                receipt.leaf_index,
                &computed,
            );
            if expected != *bound {
                return Err(HttpProfileError::ReceiptPositionMismatch);
            }
        }
        (ReceiptPositionProfile::Unbound, None) => {}
    }
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
///
/// **The WHOLE record, not the first hop.** An earlier revision compared only
/// `request_evidence` and `response_evidence`, which
/// [`EvidenceCommitment::from_reconstruction`] takes from `hop_evidence.first()`. On a
/// multi-hop call that proved hop 0 and nothing else: `chain_commitment` — the field
/// whose documented job is to commit to the SHAPE of the retained chain — had no
/// reader anywhere in the workspace, so an archivist could retain hop 0 honestly and
/// drop or substitute every hop after it and still pass. That is exactly the quiet
/// truncation the §9 chain seam exists to prevent, so the check now takes the
/// reconstruction and compares EVERY field.
///
/// The comparison is made by REBUILDING the commitment through the same constructor
/// the issuer used and comparing the results, rather than by re-deriving each field
/// here. A second implementation of the same rule is a second thing to keep in sync,
/// and a drifted copy accepts the wrong bytes silently.
///
/// **A record with no verified hop is refused, not matched.** A reconstruction that
/// broke at hop 0 — and the empty chain — has no verified prefix, so
/// [`EvidenceCommitment::from_reconstruction`] emits two empty handles and a shape
/// digest over zero bytes. Those are the same three values for every unrelated call
/// that failed at hop 0, so comparing them proves nothing: an archivist could present
/// call B's retained bytes as the record a statement about call A was made over and
/// every field would match. Reporting `Ok` there would be the check announcing a
/// binding it does not have, on exactly the records an auditor is most likely to be
/// investigating, so this returns an error instead. The statement and its receipt
/// still verify — what fails is the claim that these particular bytes are the ones it
/// was about.
///
/// `bindings_commitment` / `verified_context_commitment` are passed back in because
/// the issuer supplied them as digests: this module never saw the artifact bytes and
/// so cannot recompute them. Passing `None` for a commitment that carries `Some`
/// fails — an absent artifact is a mismatch, not a waiver.
pub fn verify_retained_evidence(
    commitment: &EvidenceCommitment,
    reconstruction: &ChainReconstruction,
    bindings_commitment: Option<String>,
    verified_context_commitment: Option<String>,
) -> Result<(), HttpProfileError> {
    let recomputed = EvidenceCommitment::from_reconstruction(
        reconstruction,
        bindings_commitment,
        verified_context_commitment,
    );
    if !commitment.commits_to_verified_evidence() || !recomputed.commits_to_verified_evidence() {
        return Err(HttpProfileError::MalformedEvidence(
            "a record with no verified hop commits to no call, so retained evidence cannot be bound to it",
        ));
    }
    if recomputed.request_evidence != commitment.request_evidence {
        return Err(HttpProfileError::MalformedEvidence(
            "retained request evidence does not match the commitment",
        ));
    }
    if recomputed.response_evidence != commitment.response_evidence {
        return Err(HttpProfileError::MalformedEvidence(
            "retained response evidence does not match the commitment",
        ));
    }
    if recomputed.chain_commitment != commitment.chain_commitment {
        return Err(HttpProfileError::MalformedEvidence(
            "retained chain does not match the committed chain shape",
        ));
    }
    if recomputed.chain_label != commitment.chain_label {
        return Err(HttpProfileError::MalformedEvidence(
            "retained chain label does not match the commitment",
        ));
    }
    if recomputed.bindings_commitment != commitment.bindings_commitment {
        return Err(HttpProfileError::MalformedEvidence(
            "retained artifact bindings do not match the commitment",
        ));
    }
    if recomputed.verified_context_commitment != commitment.verified_context_commitment {
        return Err(HttpProfileError::MalformedEvidence(
            "retained verified context does not match the commitment",
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
    /// Whether this service's receipts must carry a position commitment. Absent means
    /// the default, `unbound` — the pre-v2 contract, where `tree_size` and `leaf_index`
    /// are unauthenticated hints.
    ///
    /// In the PIN for the same reason as `leaf_profile`: it is a property of the service
    /// that cannot be inferred from the receipt under attack, and requiring it must be a
    /// thing an operator wrote down.
    #[serde(default)]
    pub position_profile: ReceiptPositionProfile,
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
                position_profile: self.position_profile,
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

/// `MTH(D[n])` (RFC 9162 §2.1.1), accumulating `PATH(target, D[n])` (§2.1.3.1) into
/// `path` when `target` is `Some`.
///
/// The two are computed together because they are the same recursion: the audit path
/// is exactly the sequence of sibling subtree roots skipped while descending to the
/// target leaf. `None` means "this subtree contains no target" — it contributes its
/// root and nothing to the path.
///
/// Entries are pushed LEAF-TO-ROOT: the targeted half recurses first, so everything
/// it contributes is already in `path` before this level's sibling is appended.
fn mth_and_path(leaves: &[[u8; 32]], target: Option<usize>, path: &mut Vec<[u8; 32]>) -> [u8; 32] {
    match leaves.len() {
        // `MTH({}) = SHA-256()`. Unreachable from the log (a receipt is only issued
        // for a registered leaf), but defined so the recursion is total.
        0 => Sha256::new().finalize().into(),
        1 => leaves[0],
        n => {
            // k = the largest power of two STRICTLY less than n.
            let k = 1usize << (usize::BITS - 1 - (n - 1).leading_zeros());
            let (left_leaves, right_leaves) = leaves.split_at(k);
            match target {
                Some(t) if t < k => {
                    let left = mth_and_path(left_leaves, Some(t), path);
                    let right = mth_and_path(right_leaves, None, path);
                    path.push(right);
                    node_hash(&left, &right)
                }
                Some(t) => {
                    let left = mth_and_path(left_leaves, None, path);
                    let right = mth_and_path(right_leaves, Some(t - k), path);
                    path.push(left);
                    node_hash(&left, &right)
                }
                None => {
                    let left = mth_and_path(left_leaves, None, path);
                    let right = mth_and_path(right_leaves, None, path);
                    node_hash(&left, &right)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::HopEvidence;

    /// The combine-direction sequence `rfc9162_root_from_inclusion_proof` takes for a
    /// position. Two positions with the same sequence run the same computation, so one
    /// path and one root verify for both — this is what "restatement" means here.
    fn combine_sequence(leaf_index: u64, tree_size: u64) -> Option<Vec<bool>> {
        if leaf_index >= tree_size {
            return None;
        }
        let (mut fnode, mut snode) = (leaf_index, tree_size - 1);
        let mut out = Vec::new();
        while out.len() <= 64 {
            if snode == 0 {
                return Some(out);
            }
            if !fnode.is_multiple_of(2) || fnode == snode {
                out.push(true);
                while fnode != 0 && fnode.is_multiple_of(2) {
                    fnode /= 2;
                    snode /= 2;
                }
            } else {
                out.push(false);
            }
            fnode /= 2;
            snode /= 2;
        }
        None
    }

    /// The property that makes "the service signs the tree size" a COMPLETE fix rather
    /// than a mitigation: within any set of positions that verify interchangeably, no
    /// two share a `tree_size`. An authenticated size therefore pins the index outright.
    ///
    /// If this ever stops holding, signing the size stops being sufficient and the
    /// remedy has to change — which is why it is asserted rather than described.
    #[test]
    fn the_tree_size_determines_the_leaf_index_within_every_ambiguity_class() {
        let mut classes: std::collections::HashMap<Vec<bool>, Vec<(u64, u64)>> =
            std::collections::HashMap::new();
        for tree_size in 1..=256u64 {
            for leaf_index in 0..tree_size {
                if let Some(seq) = combine_sequence(leaf_index, tree_size) {
                    classes
                        .entry(seq)
                        .or_default()
                        .push((leaf_index, tree_size));
                }
            }
        }

        for (seq, members) in &classes {
            let mut sizes: Vec<u64> = members.iter().map(|(_, n)| *n).collect();
            sizes.sort_unstable();
            let before = sizes.len();
            sizes.dedup();
            assert_eq!(
                sizes.len(),
                before,
                "two positions with combine sequence {seq:?} share a tree_size, so \
                 authenticating the size would NOT pin the index: {members:?}"
            );
        }

        // And the exposure itself: ambiguity is the overwhelming norm, so refusing the
        // ambiguous positions is not an available defence. Stated as a floor so the
        // test pins the shape of the problem without pinning an exact census.
        let total: usize = classes.values().map(Vec::len).sum();
        let ambiguous: usize = classes.values().filter(|m| m.len() > 1).map(Vec::len).sum();
        assert!(
            ambiguous * 10 > total * 9,
            "expected the great majority of positions to be restatable ({ambiguous} of \
             {total}); if this dropped, re-derive whether refusal became viable"
        );
    }
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
            submitted_commitment: "test-submitted".to_owned(),
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
                position_profile: ReceiptPositionProfile::Bound,
            })
        }
    }

    /// A resolver for the prototype service under the PRE-v2 contract, so a test can
    /// show what the position commitment actually buys.
    fn tr_unbound() -> impl Fn(&str) -> Option<ResolvedTransparencyService> {
        |k: &str| {
            (k == TS_KID).then(|| ResolvedTransparencyService {
                key: ts().public_key().into(),
                leaf_profile: StatementLeafProfile::StatementBytes,
                position_profile: ReceiptPositionProfile::Unbound,
            })
        }
    }

    /// Re-issue a receipt in the PRE-v2 shape: same tree, same signature discipline, no
    /// position parameter and no `crit`. This is what the service emitted before the
    /// contract revision, and it is what the restatement test needs in order to
    /// reproduce the finding rather than merely assert it.
    fn pre_v2_receipt(receipt: &Receipt) -> Vec<u8> {
        let proof = Value::Array(vec![
            Value::Integer(receipt.tree_size.into()),
            Value::Integer(receipt.leaf_index.into()),
            Value::Array(
                receipt
                    .inclusion_path
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
            .payload(receipt.root.clone().expect("attached root"))
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
    fn restate_position(receipt: &Receipt, tree_size: u64, leaf_index: u64) -> Vec<u8> {
        let mut sign1 = CoseSign1::from_tagged_slice(receipt.to_cose()).expect("parses");
        let proof = Value::Array(vec![
            Value::Integer(tree_size.into()),
            Value::Integer(leaf_index.into()),
            Value::Array(
                receipt
                    .inclusion_path
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

    /// C080. A receipt for leaf 1 of a 2-leaf log is restated as leaf 2 of a 3-leaf log.
    /// The fold takes the same combine directions, so it reproduces the same root and
    /// the service's signature still verifies — the restatement is not a forgery, it is
    /// a true receipt presented at a position nobody signed.
    ///
    /// Both halves are asserted, because the second is what makes the first meaningful:
    /// under the PRE-v2 contract the restatement VERIFIES, and under the position-bound
    /// contract it is refused.
    #[test]
    fn a_receipt_restated_at_another_position_is_refused_only_when_the_position_is_bound() {
        let st = statement(EvidenceCommitment::from_reconstruction(
            &recon(ChainLabel::Complete, 1),
            None,
            None,
        ));
        let other = statement(EvidenceCommitment::from_reconstruction(
            &recon(ChainLabel::Complete, 2),
            None,
            None,
        ));
        let mut svc = PrototypeTransparencyService::new(TS_KID);
        let _ = register(&mut svc, &other);
        let receipt = register(&mut svc, &st);
        assert_eq!((receipt.tree_size(), receipt.leaf_index()), (2, 1));

        // The honest receipt verifies under both contracts.
        verify_receipt_offline(&st, &receipt, ir(), tr()).expect("the honest position");

        // Pre-v2, reproduced rather than asserted: the same tree, issued without the
        // position parameter, restated at (3, 2) — and it VERIFIES. The fold takes the
        // same combine directions, so nothing in the receipt disagrees with the claim.
        let legacy = Receipt::from_cose(&pre_v2_receipt(&receipt)).expect("parses");
        assert!(legacy.position_commitment.is_none());
        verify_receipt_offline(&st, &legacy, ir(), tr_unbound()).expect("the honest legacy claim");
        let legacy_restated = Receipt::from_cose(&restate_position(&legacy, 3, 2)).expect("parses");
        assert_eq!(
            (legacy_restated.tree_size(), legacy_restated.leaf_index()),
            (3, 2)
        );
        verify_receipt_offline(&st, &legacy_restated, ir(), tr_unbound())
            .expect("C080: the unbound contract cannot distinguish the restated position");

        // v2: the protected commitment covers the tuple, so the same restatement fails.
        let restated = Receipt::from_cose(&restate_position(&receipt, 3, 2)).expect("parses");
        assert_eq!((restated.tree_size(), restated.leaf_index()), (3, 2));
        assert_eq!(
            verify_receipt_offline(&st, &restated, ir(), tr()).unwrap_err(),
            HttpProfileError::ReceiptPositionMismatch,
        );

        // And a present-but-wrong commitment is refused even by a pin that would have
        // tolerated its ABSENCE: the pin governs whether the parameter may be missing,
        // never whether a signed one may disagree with the position it accompanies.
        assert_eq!(
            verify_receipt_offline(&st, &restated, ir(), tr_unbound()).unwrap_err(),
            HttpProfileError::ReceiptPositionMismatch,
        );
    }

    /// Pinning the stronger profile must not be defeatable by removing the parameter.
    #[test]
    fn a_bound_service_refuses_a_receipt_that_carries_no_position_commitment() {
        let st = statement(EvidenceCommitment::from_reconstruction(
            &recon(ChainLabel::Complete, 1),
            None,
            None,
        ));
        let stripped = Receipt::from_cose(&es256_receipt(&st)).expect("parses");
        assert!(stripped.position_commitment.is_none());
        assert_eq!(
            verify_receipt_offline(&st, &stripped, ir(), ts_p256_bound()).unwrap_err(),
            HttpProfileError::ReceiptPositionUnbound,
        );
    }

    fn ts_p256_bound() -> impl Fn(&str) -> Option<ResolvedTransparencyService> {
        move |k: &str| {
            (k == TS_KID).then(|| ResolvedTransparencyService {
                key: ts_p256_key(),
                leaf_profile: StatementLeafProfile::StatementBytes,
                position_profile: ReceiptPositionProfile::Bound,
            })
        }
    }

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

    /// A resolver for a FOREIGN service using `key`, with the default leaf profile.
    ///
    /// `Unbound`: the receipts these tests build by hand are the shape a real external
    /// SCITT service emits, and no such service carries MCP-RE's position parameter.
    fn ts_with(key: CoseVerificationKey) -> impl Fn(&str) -> Option<ResolvedTransparencyService> {
        move |k: &str| {
            (k == TS_KID).then(|| ResolvedTransparencyService {
                key: key.clone(),
                leaf_profile: StatementLeafProfile::StatementBytes,
                position_profile: ReceiptPositionProfile::Unbound,
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
    // RFC 9162 conformance — the tree and the fold.
    // -----------------------------------------------------------------------

    /// The RFC 9162 §2.1.1 known answer for a NON-power-of-two tree.
    ///
    /// `MTH(D[3]) = HASH(0x01 ‖ MTH(D[0:2]) ‖ MTH(D[2:3]))` — the split is at the
    /// largest power of two BELOW 3, i.e. 2, and the last leaf is never duplicated.
    /// The duplicate-last-node construction this replaced computed
    /// `node(node(a,b), node(c,c))` instead, which is a different root for every size
    /// that is not a power of two.
    #[test]
    fn the_tree_hash_is_the_rfc_9162_split_not_a_duplicated_last_node() {
        let leaves: Vec<[u8; 32]> = (0u8..3).map(|i| [i; 32]).collect();
        let mut path = Vec::new();
        let root = mth_and_path(&leaves, None, &mut path);

        let expected = node_hash(&node_hash(&leaves[0], &leaves[1]), &leaves[2]);
        assert_eq!(root, expected, "MTH(D[3]) per RFC 9162 §2.1.1");

        let duplicated = node_hash(
            &node_hash(&leaves[0], &leaves[1]),
            &node_hash(&leaves[2], &leaves[2]),
        );
        assert_ne!(
            root, duplicated,
            "the two constructions must be visibly different, or this test proves nothing"
        );
    }

    /// EVERY leaf of a non-power-of-two log verifies. Leaf 2 of a 3-leaf tree sits on
    /// the short right edge, and the old index-bit fold combined its operands in the
    /// wrong order — so a conforming receipt from any real log whose size is not a
    /// power of two was rejected.
    #[test]
    fn every_leaf_of_a_three_leaf_log_verifies() {
        let mut svc = PrototypeTransparencyService::new(TS_KID);
        let mut issued = Vec::new();
        for hops in 1..=3 {
            let st = statement(EvidenceCommitment::from_reconstruction(
                &recon(ChainLabel::Complete, hops),
                None,
                None,
            ));
            let receipt = register(&mut svc, &st);
            issued.push((st, receipt));
        }
        // The last receipt is over the 3-leaf tree; re-register nothing, just check it.
        let (st, receipt) = issued.last().expect("three registered");
        assert_eq!(receipt.tree_size(), 3);
        assert_eq!(receipt.leaf_index(), 2, "the right-edge leaf");
        verify_receipt_offline(st, receipt, ir(), tr())
            .expect("a right-edge leaf of a 3-leaf tree verifies");
    }

    /// `tree_size` and `leaf_index` ride in the UNSIGNED `vdp` header. The RFC 9162
    /// walk's terminal `sn == 0` requirement makes the PATH LENGTH load-bearing, so a
    /// position whose proof would need a different number of siblings is refused.
    #[test]
    fn restating_the_log_position_at_a_different_path_length_does_not_verify() {
        let leaf = [7u8; 32];
        let sibling = vec![9u8; 32];
        // The honest proof: leaf 1 of a 2-leaf tree, one sibling.
        let root = rfc9162_root_from_inclusion_proof(&leaf, 1, 2, std::slice::from_ref(&sibling))
            .expect("the honest position verifies");
        assert_eq!(root, node_hash(&sibling, &leaf));

        for (index, size) in [(3u64, 4u64), (7, 8), (21, 32), (1, 4)] {
            assert!(
                rfc9162_root_from_inclusion_proof(
                    &leaf,
                    index,
                    size,
                    std::slice::from_ref(&sibling)
                )
                .is_err(),
                "leaf_index {index} of a {size}-leaf tree needs a different path length"
            );
        }
    }

    /// The limit of the above, pinned so nobody reads the accessors as authenticated.
    ///
    /// A right-edge leaf is PROMOTED past every level, so leaf `2^k` of a `2^k + 1`-leaf
    /// log consumes exactly one sibling and folds to the same `H(0x01 ‖ sibling ‖ leaf)`
    /// as leaf 1 of a 2-leaf log. The `RFC9162_SHA256` receipt payload is the bare
    /// Merkle Tree Hash, which — unlike an RFC 9162 signed tree head — never covers
    /// `tree_size`, so there is nothing in the signed material that distinguishes these
    /// positions and no fold can refuse them. This test states the residual explicitly:
    /// [`Receipt::tree_size`] and [`Receipt::leaf_index`] are unauthenticated hints,
    /// and any consumer building ordering, anchoring or log-maturity reasoning on them
    /// is reading a relayer-chosen value.
    #[test]
    fn a_right_edge_restatement_is_indistinguishable_and_still_verifies() {
        let leaf = [7u8; 32];
        let sibling = vec![9u8; 32];
        let honest = rfc9162_root_from_inclusion_proof(&leaf, 1, 2, std::slice::from_ref(&sibling))
            .expect("the honest position verifies");

        for k in 1u32..8 {
            let (index, size) = (1u64 << k, (1u64 << k) + 1);
            let restated = rfc9162_root_from_inclusion_proof(
                &leaf,
                index,
                size,
                std::slice::from_ref(&sibling),
            )
            .expect("a right-edge position of the same path length is not distinguishable");
            assert_eq!(
                restated, honest,
                "leaf {index} of a {size}-leaf log folds to the honest 2-leaf root"
            );
        }
    }

    /// An EMPTY inclusion path is admitted only for the single-leaf tree RFC 9162
    /// defines it for. For any larger tree it proves nothing — the fold would collapse
    /// to `root == leaf hash`, so any signature a service made over an ENTRY hash
    /// rather than a tree head would read as a receipt carrying an arbitrary,
    /// unauthenticated size and index.
    #[test]
    fn an_empty_inclusion_path_is_only_valid_for_a_single_leaf_tree() {
        let leaf = [3u8; 32];
        assert_eq!(
            rfc9162_root_from_inclusion_proof(&leaf, 0, 1, &[]).expect("PATH(0, D[1]) = {}"),
            leaf,
            "a one-leaf tree's root IS its leaf hash"
        );
        for size in [2u64, 3, 8] {
            assert!(
                rfc9162_root_from_inclusion_proof(&leaf, 0, size, &[]).is_err(),
                "an empty path cannot reach the root of a {size}-leaf tree"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Retained evidence — what the receipt commits to but does not carry.
    // -----------------------------------------------------------------------

    /// The retained chain reproduces the commitment, and altering any hop breaks it.
    #[test]
    fn retained_evidence_reproduces_the_commitment() {
        let retained = recon(ChainLabel::Complete, 1);
        let commitment = EvidenceCommitment::from_reconstruction(&retained, None, None);

        verify_retained_evidence(&commitment, &retained, None, None)
            .expect("the retained bytes match");

        let mut tampered_request = retained.clone();
        tampered_request.hop_evidence[0].request_evidence =
            RequestEvidence::from_signature_base(b"req-tampered");
        assert_eq!(
            verify_retained_evidence(&commitment, &tampered_request, None, None).unwrap_err(),
            HttpProfileError::MalformedEvidence(
                "retained request evidence does not match the commitment"
            ),
        );

        let mut tampered_response = retained.clone();
        tampered_response.hop_evidence[0].response_evidence =
            RequestEvidence::from_response_signature_base(b"rsp-tampered");
        assert_eq!(
            verify_retained_evidence(&commitment, &tampered_response, None, None).unwrap_err(),
            HttpProfileError::MalformedEvidence(
                "retained response evidence does not match the commitment"
            ),
        );
    }

    /// The defect this check exists for: retain hop 0 honestly, drop the rest. The
    /// first-hop handles still match, so only `chain_commitment` — the field that had
    /// no reader at all — can catch it.
    #[test]
    fn a_truncated_chain_is_refused_even_though_hop_zero_matches() {
        let full = recon(ChainLabel::Complete, 3);
        let commitment = EvidenceCommitment::from_reconstruction(&full, None, None);

        let mut truncated = full.clone();
        truncated.hop_evidence.truncate(1);
        assert_eq!(
            truncated.hop_evidence[0], full.hop_evidence[0],
            "hop 0 is retained honestly — the old check compared only this"
        );
        assert_eq!(
            verify_retained_evidence(&commitment, &truncated, None, None).unwrap_err(),
            HttpProfileError::MalformedEvidence(
                "retained chain does not match the committed chain shape"
            ),
        );

        // Substituting a later hop is the same defect in the other direction.
        let mut substituted = full.clone();
        substituted.hop_evidence[2].request_evidence =
            RequestEvidence::from_signature_base(b"req-substituted");
        assert!(verify_retained_evidence(&commitment, &substituted, None, None).is_err());
    }

    /// A chain that broke at hop 0 has no verified prefix, so all three identity
    /// fields degenerate to constants: two empty handles and SHA-256 over zero bytes.
    /// Every such record — of every unrelated call, whatever the retained bytes were —
    /// produces the same three values.
    ///
    /// This is stated as a test rather than left implicit because it is the reason the
    /// check below has to refuse: the comparison `verify_retained_evidence` makes
    /// simply has no discriminating power here.
    #[test]
    fn a_record_with_no_verified_hop_has_no_identity() {
        let broke_at_hop_zero = recon(
            ChainLabel::Incomplete {
                hop: 0,
                reason: IncompleteReason::ContinuationDoesNotLink,
            },
            0,
        );
        let empty = recon(
            ChainLabel::Incomplete {
                hop: 0,
                reason: IncompleteReason::ContinuationDoesNotLink,
            },
            0,
        );
        let a = EvidenceCommitment::from_reconstruction(&broke_at_hop_zero, None, None);
        let b = EvidenceCommitment::from_reconstruction(&empty, None, None);
        assert_eq!(a, b, "the identity fields carry nothing to tell them apart");
        assert!(a.request_evidence.is_empty());
        assert!(a.response_evidence.is_empty());
        assert_eq!(
            a.chain_commitment,
            b64url_encode(&Sha256::digest(b"")),
            "the shape digest folds over nothing"
        );
        assert!(!a.commits_to_verified_evidence());
        assert!(
            EvidenceCommitment::from_reconstruction(&recon(ChainLabel::Complete, 1), None, None)
                .commits_to_verified_evidence(),
            "a record with a verified hop DOES name evidence"
        );
    }

    /// The retained/committed split must not report a binding it does not have.
    ///
    /// Without the fail-closed gate, `verify_retained_evidence` returns `Ok` for a
    /// hop-0-failure commitment against ANY other hop-0-failure reconstruction —
    /// including one built from a completely different call's retained bytes — because
    /// every field it compares is a constant. That is the archivist substitution the
    /// whole check exists to catch, on the records an auditor most needs pinned.
    #[test]
    fn retained_evidence_cannot_be_bound_to_a_record_with_no_verified_hop() {
        let label = ChainLabel::Incomplete {
            hop: 0,
            reason: IncompleteReason::RequestUnverifiable(HttpProfileError::InvalidSignature),
        };
        let call_a = recon(label.clone(), 0);
        let commitment = EvidenceCommitment::from_reconstruction(&call_a, None, None);

        let expected = HttpProfileError::MalformedEvidence(
            "a record with no verified hop commits to no call, so retained evidence cannot be bound to it",
        );

        // Its own reconstruction is refused too: there is nothing to bind either way.
        assert_eq!(
            verify_retained_evidence(&commitment, &call_a, None, None).unwrap_err(),
            expected
        );

        // A DIFFERENT call that failed at hop 0 for the same reason. Every compared
        // field matches, which is precisely why matching must not be reported.
        let call_b = recon(label, 0);
        assert_eq!(
            EvidenceCommitment::from_reconstruction(&call_b, None, None),
            commitment,
            "the two records are indistinguishable — the check cannot separate them"
        );
        assert_eq!(
            verify_retained_evidence(&commitment, &call_b, None, None).unwrap_err(),
            expected
        );

        // The empty chain lands in the same place rather than matching anything.
        let nothing = recon(
            ChainLabel::Incomplete {
                hop: 0,
                reason: IncompleteReason::EmptyChain,
            },
            0,
        );
        assert_eq!(
            verify_retained_evidence(&commitment, &nothing, None, None).unwrap_err(),
            expected
        );

        // And a real record is not collateral damage.
        let real = recon(ChainLabel::Complete, 2);
        verify_retained_evidence(
            &EvidenceCommitment::from_reconstruction(&real, None, None),
            &real,
            None,
            None,
        )
        .expect("a record with verified hops still binds");
    }

    /// A commitment that names artifact bindings or a verified context is not
    /// satisfied by retained evidence that omits them.
    #[test]
    fn absent_bindings_do_not_satisfy_a_commitment_that_names_them() {
        let retained = recon(ChainLabel::Complete, 1);
        let commitment = EvidenceCommitment::from_reconstruction(
            &retained,
            Some("bindings-digest".into()),
            Some("context-digest".into()),
        );
        assert_eq!(
            verify_retained_evidence(&commitment, &retained, None, None).unwrap_err(),
            HttpProfileError::MalformedEvidence(
                "retained artifact bindings do not match the commitment"
            ),
        );
        assert_eq!(
            verify_retained_evidence(&commitment, &retained, Some("bindings-digest".into()), None)
                .unwrap_err(),
            HttpProfileError::MalformedEvidence(
                "retained verified context does not match the commitment"
            ),
        );
        verify_retained_evidence(
            &commitment,
            &retained,
            Some("bindings-digest".into()),
            Some("context-digest".into()),
        )
        .expect("both artifacts present and matching");
    }

    /// The two roles are distinct values over the same bytes. Presenting the response
    /// base as the request base must fail — that is what the domain separation buys,
    /// and without this test the labelling could be dropped and everything else would
    /// still pass.
    #[test]
    fn the_two_evidence_roles_are_not_interchangeable() {
        let same = b"identical-signature-base".as_slice();
        let retained = ChainReconstruction {
            label: ChainLabel::Complete,
            hop_evidence: vec![HopEvidence {
                request_evidence: RequestEvidence::from_signature_base(same),
                response_evidence: RequestEvidence::from_response_signature_base(same),
            }],
            submitted_commitment: "test-submitted".to_owned(),
        };
        let commitment = EvidenceCommitment::from_reconstruction(&retained, None, None);
        assert_ne!(
            commitment.request_evidence, commitment.response_evidence,
            "the same bytes in two roles are two different handles"
        );
        verify_retained_evidence(&commitment, &retained, None, None)
            .expect("each role in its own place");
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
        let other = recon(ChainLabel::Complete, 2);
        assert!(verify_retained_evidence(&commitment, &other, None, None).is_err());
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
            // A real external SCITT service does not emit MCP-RE's profile extension,
            // so an interoperability pin is `Unbound` and its receipts verify under the
            // pre-v2 contract. This is the transition working as intended: the stronger
            // profile is something a deployment opts into per service, not something
            // that retroactively invalidates every receipt anyone else issues.
            position_profile: ReceiptPositionProfile::Unbound,
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
        let point = ts_p256().verifying_key().to_sec1_point(false);
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
        let point = ts_p256().verifying_key().to_sec1_point(false);
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
        let point = ts_p256().verifying_key().to_sec1_point(false);
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
