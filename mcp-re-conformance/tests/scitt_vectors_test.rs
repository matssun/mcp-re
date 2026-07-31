// SPDX-License-Identifier: Apache-2.0
//! Frozen conformance vectors for the SCITT Signed Statement + COSE Receipt
//! encoding (RFC 9052 / RFC 9942 / RFC 9943) — MCPRE-494.
//!
//! **Why these could not exist before.** The prototype serialized statements and
//! receipts as JSON, an explicit stand-in. Pinning those bytes would have certified a
//! non-wire format: a third party implementing RFC 9943 would have matched nothing,
//! and the corpus would have said they were wrong. So #494 held the rule "no vectors
//! before the encoding is real". The encoding is now real, and these are frozen from
//! it.
//!
//! What each vector pins is the exact `COSE_Sign1` octets — tag 18, protected header,
//! payload, signature — so a change to the encoder that alters the wire form fails
//! here rather than silently producing bytes only this implementation accepts.
//!
//! The negatives matter more than the positive. A corpus that only proves a good
//! receipt verifies says nothing about what an implementation must REFUSE, and every
//! interesting SCITT failure is a refusal: a tampered payload, a forged inclusion
//! path, an untrusted issuer, a leaf index the signed tree cannot contain, a
//! verifiable-data-structure this verifier does not implement.
//!
//! Three of those negatives leave the transparency service's signature VALID and are
//! caught by nothing else — the inclusion path and the leaf index ride in the
//! unprotected header, so a verifier that checked the two signatures and skipped the
//! fold would accept them.
//!
//! These tests cannot see whether the labels are the RIGHT ones: they run the encoder
//! against its own decoder, which agrees with itself whatever numbers it picks.
//! `tools/scitt_independent_verify.py` is the outside opinion, built from the RFC text
//! with no MCP-RE code, and it is what to run when the encoding changes.
//!
//! Regenerate (and re-pin) with:
//!   cargo test -p mcp-re-conformance --test scitt_vectors_test \
//!     write_scitt_fixtures -- --ignored

use std::path::PathBuf;

use mcp_re_core::b64url_decode;
use mcp_re_core::b64url_encode;
use mcp_re_core::SigningKey;
use mcp_re_core::VerificationKey;
use mcp_re_http_profile::chain::ChainLabel;
use mcp_re_http_profile::chain::ChainReconstruction;
use mcp_re_http_profile::chain::HopEvidence;
use mcp_re_http_profile::chain::IncompleteReason;
use mcp_re_http_profile::scitt::issue_signed_statement;
use mcp_re_http_profile::scitt::verify_receipt_offline;
use mcp_re_http_profile::scitt::EvidenceCommitment;
use mcp_re_http_profile::scitt::PrototypeTransparencyService;
use mcp_re_http_profile::scitt::Receipt;
use mcp_re_http_profile::scitt::SignedStatement;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::RequestEvidence;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;

const ISSUER_KID: &str = "scitt-issuer-1";
const TS_KID: &str = "scitt-ts-1";
const ISSUED_AT: i64 = 1_700_000_000;

fn issuer() -> SigningKey {
    SigningKey::from_seed_bytes(&[55u8; 32])
}
fn ts() -> SigningKey {
    SigningKey::from_seed_bytes(&[66u8; 32])
}
/// A real Ed25519 key from a different seed — for the untrusted-issuer vector. A
/// MALFORMED key would be refused as bad configuration and would prove nothing about
/// the trust decision.
fn stranger() -> SigningKey {
    SigningKey::from_seed_bytes(&[77u8; 32])
}

/// The corpus directory: the runfiles copy under Bazel, the source tree under cargo.
///
/// Bazel runs tests in a sandbox where `CARGO_MANIFEST_DIR` is not the source tree, so
/// the manifest's runfile path is passed in. Mirrors `delegation_vectors_test`.
fn vectors_root() -> PathBuf {
    if let Ok(rel) = std::env::var("MCP_RE_SCITT_VECTORS_MANIFEST") {
        for key in ["TEST_SRCDIR", "RUNFILES_DIR"] {
            if let Ok(root) = std::env::var(key) {
                let candidate = std::path::Path::new(&root).join(&rel);
                if candidate.exists() {
                    return candidate.parent().expect("manifest parent").to_path_buf();
                }
            }
        }
        let candidate = PathBuf::from(&rel);
        if candidate.exists() {
            return candidate.parent().expect("manifest parent").to_path_buf();
        }
        panic!("MCP_RE_SCITT_VECTORS_MANIFEST set but runfile not found (rel={rel})");
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("scitt")
}

/// One frozen vector: the exact wire octets, and the verdict a conforming verifier
/// must reach.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Fixture {
    name: String,
    /// What the vector is for, in one line — a corpus a reader cannot interpret is a
    /// corpus that gets regenerated instead of understood.
    description: String,
    /// The tagged `COSE_Sign1` Signed Statement, base64url.
    statement_cose_b64url: String,
    /// The tagged `COSE_Sign1` Receipt, base64url.
    receipt_cose_b64url: String,
    /// The issuer public key a verifier resolves `issuer_kid` to, base64url.
    issuer_pubkey_b64url: String,
    /// The transparency service public key, base64url.
    ts_pubkey_b64url: String,
    /// `verify_ok`, or the frozen `mcp-re.*` wire code of the expected refusal.
    expect: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ManifestEntry {
    file: String,
    sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Manifest {
    schema: String,
    corpus_digest: String,
    fixtures: Vec<ManifestEntry>,
}

fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The corpus digest: SHA-256 over the sorted `file sha256` lines, so the pin is
/// independent of the order the writer happened to emit them in.
fn corpus_digest(entries: &[ManifestEntry]) -> String {
    let mut lines: Vec<String> = entries
        .iter()
        .map(|e| format!("{} {}", e.file, e.sha256))
        .collect();
    lines.sort();
    hex_sha256(lines.join("\n").as_bytes())
}

fn reconstruction(label: ChainLabel, hops: usize) -> ChainReconstruction {
    ChainReconstruction {
        label,
        hop_evidence: (0..hops)
            .map(|i| HopEvidence {
                request_evidence: RequestEvidence::from_signature_base(
                    format!("req-{i}").as_bytes(),
                ),
                response_evidence: RequestEvidence::from_response_signature_base(
                    format!("rsp-{i}").as_bytes(),
                ),
            })
            .collect(),
    }
}

fn statement(commitment: EvidenceCommitment, key: &SigningKey) -> SignedStatement {
    issue_signed_statement(ISSUER_KID, commitment, ISSUED_AT, |input| {
        b64url_decode(&key.sign(input)).map_err(|_| HttpProfileError::InvalidSignature)
    })
    .expect("issue")
}

/// Register `statement` into a log that already holds one unrelated entry, and return
/// its receipt.
///
/// The preceding entry is not decoration. A single-leaf log yields an EMPTY inclusion
/// path, which `inclusion-path = [ + bstr ]` (RFC 9942 §5.2, Figure 3) does not admit
/// and which exercises no folding at all — the leaf would be the root. With a sibling
/// present, every vector pins a proof that actually has to be walked.
fn register(statement: &SignedStatement) -> Receipt {
    let mut svc = PrototypeTransparencyService::new(TS_KID);
    let filler = self::statement(
        EvidenceCommitment::from_reconstruction(
            &reconstruction(ChainLabel::Complete, 4),
            None,
            None,
        ),
        &issuer(),
    );
    svc.register(&filler, sign_tree_head).expect("filler entry");
    svc.register(statement, sign_tree_head).expect("register")
}

/// The transparency service's tree-head signer. A fn item rather than a closure so it
/// can be handed to more than one `register` call.
fn sign_tree_head(head: &[u8]) -> Result<Vec<u8>, HttpProfileError> {
    b64url_decode(&ts().sign(head)).map_err(|_| HttpProfileError::InvalidSignature)
}

fn fixture(
    name: &str,
    description: &str,
    statement: &SignedStatement,
    receipt: &Receipt,
    expect: &str,
) -> Fixture {
    Fixture {
        name: name.to_owned(),
        description: description.to_owned(),
        statement_cose_b64url: b64url_encode(statement.to_cose()),
        receipt_cose_b64url: b64url_encode(receipt.to_cose()),
        issuer_pubkey_b64url: b64url_encode(&issuer().public_key().to_bytes()),
        ts_pubkey_b64url: b64url_encode(&ts().public_key().to_bytes()),
        expect: expect.to_owned(),
    }
}

/// The first occurrence of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// The offset of the one and only occurrence of `needle`. Panics if the pattern is
/// absent or repeated, because a corpus writer that patched the wrong copy of an
/// ambiguous byte string would freeze a vector testing something else entirely.
fn find_once(haystack: &[u8], needle: &[u8]) -> usize {
    let at = find(haystack, needle).unwrap_or_else(|| panic!("pattern {needle:02x?} not found"));
    assert!(
        find(&haystack[at + 1..], needle).is_none(),
        "pattern {needle:02x?} is not unique"
    );
    at
}

/// CBOR head of `inclusion-proof-content` for a two-leaf log proving leaf 1:
/// `array(3), 2, 1, array(1), bstr(32)` (RFC 9942 §5.2 Figure 3).
const PROOF_HEAD: [u8; 6] = [0x83, 0x02, 0x01, 0x81, 0x58, 0x20];

/// CBOR for the protected-header entry `vds(395) => 1` — `uint16 395`, then `1`.
const VDS_ENTRY: [u8; 4] = [0x19, 0x01, 0x8b, 0x01];

/// Replace `needle` with `replacement` of the SAME length, at its unique occurrence.
///
/// Equal length matters for more than convenience: it keeps every surrounding CBOR
/// length header valid, so the receipt still parses and the vector tests the check it
/// names rather than the decoder.
fn splice(bytes: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    assert_eq!(needle.len(), replacement.len(), "same-length patch");
    let at = find_once(bytes, needle);
    let mut out = bytes.to_vec();
    out[at..at + needle.len()].copy_from_slice(replacement);
    out
}

fn build_fixtures() -> Vec<Fixture> {
    let mut out = Vec::new();

    // s01 — a complete call record: the positive.
    let complete = statement(
        EvidenceCommitment::from_reconstruction(
            &reconstruction(ChainLabel::Complete, 2),
            None,
            None,
        ),
        &issuer(),
    );
    let receipt = register(&complete);
    out.push(fixture(
        "s01_complete_record",
        "A two-hop COMPLETE call record, registered and offline-verifiable: issuer \
         COSE_Sign1 signature, RFC 9162 inclusion proof, and the service's signature \
         over the root the proof re-derives.",
        &complete,
        &receipt,
        "verify_ok",
    ));

    // s02 — an INCOMPLETE record. It verifies exactly as well as a complete one, and
    // says so: a receipt can never make a truncated call look whole, because the
    // label it commits to names the failing hop.
    let incomplete = statement(
        EvidenceCommitment::from_reconstruction(
            &reconstruction(
                ChainLabel::Incomplete {
                    hop: 1,
                    reason: IncompleteReason::MissingContinuation,
                },
                2,
            ),
            None,
            None,
        ),
        &issuer(),
    );
    let incomplete_receipt = register(&incomplete);
    out.push(fixture(
        "s02_incomplete_record",
        "An INCOMPLETE record verifies as a receipt and remains labelled incomplete. \
         A valid receipt over a truncated chain is a correct record OF a truncated \
         chain, not evidence the call was whole.",
        &incomplete,
        &incomplete_receipt,
        "verify_ok",
    ));

    // s03 — the payload tampered in the COSE bytes, same length so the CBOR still
    // parses and the failure is the SIGNATURE rather than a decode error.
    let mut tampered = complete.to_cose().to_vec();
    let at = find(&tampered, b"complete").expect("the label is in the payload");
    tampered[at..at + 8].copy_from_slice(b"complet3");
    out.push(Fixture {
        name: "s03_tampered_payload".into(),
        description: "The committed chain label rewritten in the signed payload, at \
                      the same length so the CBOR still parses. The refusal must be \
                      the signature's, not the decoder's."
            .into(),
        statement_cose_b64url: b64url_encode(&tampered),
        ..fixture("", "", &complete, &receipt, "mcp-re.invalid_signature")
    });

    // s04 — a receipt that is genuine, for a DIFFERENT statement. This is the
    // substitution an attacker actually has available: both artifacts verify on
    // their own, and only the binding between them fails. A verifier that checked
    // the two signatures without re-deriving the root from THIS statement's leaf
    // would accept it.
    out.push(fixture(
        "s04_receipt_for_another_statement",
        "A genuine receipt paired with a different genuine statement. Both signatures \
         verify; the inclusion proof does not re-derive the signed root from this \
         statement's leaf. Checking signatures alone would accept the swap.",
        &complete,
        &incomplete_receipt,
        "mcp-re.request_binding_mismatch",
    ));

    // s05 — a statement naming an issuer the verifier does not resolve. The
    // signature over it is perfectly valid; nobody trusted the signer.
    let foreign = issue_signed_statement(
        "scitt-issuer-rogue",
        EvidenceCommitment::from_reconstruction(
            &reconstruction(ChainLabel::Complete, 1),
            None,
            None,
        ),
        ISSUED_AT,
        |input| {
            b64url_decode(&stranger().sign(input)).map_err(|_| HttpProfileError::InvalidSignature)
        },
    )
    .expect("issue");
    let foreign_receipt = register(&foreign);
    out.push(fixture(
        "s05_untrusted_issuer",
        "A statement naming an issuer the verifier does not resolve, signed by a REAL \
         Ed25519 key. The signature is valid; nobody trusted the signer. A kid never \
         introduces trust.",
        &foreign,
        &foreign_receipt,
        "mcp-re.actor_binding_failed",
    ));

    // s06 — a sibling hash altered inside the inclusion path. The path rides in the
    // UNPROTECTED header, so this tamper leaves the service's signature over the root
    // perfectly valid: the ONLY thing that catches it is re-deriving the root from
    // this statement's leaf. A verifier that trusted a valid receipt signature and
    // skipped the fold would accept a forged path.
    let forged_path = {
        let at = find_once(receipt.to_cose(), &PROOF_HEAD) + PROOF_HEAD.len();
        let mut bytes = receipt.to_cose().to_vec();
        bytes[at + 31] ^= 0x01;
        bytes
    };
    out.push(Fixture {
        name: "s06_forged_inclusion_path".into(),
        description: "One sibling hash flipped inside the inclusion path. The proof is \
                      unprotected, so the service's signature over the root still \
                      verifies; only re-deriving the root from this leaf refuses it."
            .into(),
        receipt_cose_b64url: b64url_encode(&forged_path),
        ..fixture(
            "",
            "",
            &complete,
            &receipt,
            "mcp-re.request_binding_mismatch",
        )
    });

    // s07 — a verifiable data structure this verifier does not implement. RFC 9942
    // registers only RFC9162_SHA256 (1); anything else names a proof format whose
    // walk is undefined here. The refusal must come from the structure check, BEFORE
    // any signature is verified — walking an unknown proof format and only then asking
    // about signatures would be the wrong order.
    out.push(Fixture {
        name: "s07_unsupported_vds".into(),
        description: "The vds in the protected header names a structure this verifier \
                      does not implement. It must be refused for that reason, at parse, \
                      before any signature is checked — never walked as if it were \
                      RFC9162_SHA256."
            .into(),
        receipt_cose_b64url: b64url_encode(&splice(
            receipt.to_cose(),
            &VDS_ENTRY,
            &[0x19, 0x01, 0x8b, 0x02],
        )),
        ..fixture("", "", &complete, &receipt, "mcp-re.malformed_envelope")
    });

    // s08 — a leaf index at the tree size. RFC 9942 §5.2, quoting RFC 9162: fail the
    // proof. The index is in the unprotected proof, so the tree-head signature stays
    // valid; a tree of size 2 simply has no leaf 2, and arithmetic settles it before
    // any hashing.
    out.push(Fixture {
        name: "s08_leaf_index_outside_tree".into(),
        description: "leaf-index equal to tree-size. RFC 9942 §5.2 requires failing \
                      such a proof; the signature over the tree head is untouched and \
                      still valid, so only the bounds check refuses it."
            .into(),
        receipt_cose_b64url: b64url_encode(&splice(
            receipt.to_cose(),
            &PROOF_HEAD,
            &[0x83, 0x02, 0x02, 0x81, 0x58, 0x20],
        )),
        ..fixture("", "", &complete, &receipt, "mcp-re.malformed_envelope")
    });

    out
}

fn resolve(kid: &str, expected: &str, key: VerificationKey) -> Option<VerificationKey> {
    (kid == expected).then_some(key)
}

/// Run one fixture exactly as a third party would: from the frozen octets alone.
fn verdict(f: &Fixture) -> String {
    let statement = match SignedStatement::from_cose(
        &b64url_decode(&f.statement_cose_b64url).expect("statement b64url"),
    ) {
        Ok(s) => s,
        Err(e) => return e.wire_code().to_owned(),
    };
    let receipt =
        match Receipt::from_cose(&b64url_decode(&f.receipt_cose_b64url).expect("receipt b64url")) {
            Ok(r) => r,
            Err(e) => return e.wire_code().to_owned(),
        };
    let issuer_key = VerificationKey::from_b64url(&f.issuer_pubkey_b64url).expect("issuer key");
    let ts_key = VerificationKey::from_b64url(&f.ts_pubkey_b64url).expect("ts key");
    match verify_receipt_offline(
        &statement,
        &receipt,
        |kid| resolve(kid, ISSUER_KID, issuer_key.clone()),
        |kid| resolve(kid, TS_KID, ts_key.clone()),
    ) {
        Ok(()) => "verify_ok".to_owned(),
        Err(e) => e.wire_code().to_owned(),
    }
}

// ---------------------------------------------------------------------------
// Writer — run explicitly with --ignored.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "golden writer: regenerates the committed scitt corpus"]
fn write_scitt_fixtures() {
    let root = vectors_root();
    std::fs::create_dir_all(&root).expect("corpus dir");
    let mut entries = Vec::new();
    for f in &build_fixtures() {
        let file = format!("{}.json", f.name);
        let bytes = serde_json::to_string_pretty(f).expect("serialize") + "\n";
        std::fs::write(root.join(&file), &bytes).expect("write fixture");
        // Hash the bytes actually written — the artifact a third party reads, not the
        // in-memory struct they cannot see.
        entries.push(ManifestEntry {
            sha256: hex_sha256(bytes.as_bytes()),
            file,
        });
    }
    let manifest = Manifest {
        schema: "mcp-re-scitt-conformance/v1".into(),
        corpus_digest: corpus_digest(&entries),
        fixtures: entries,
    };
    std::fs::write(
        root.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).expect("serialize") + "\n",
    )
    .expect("write manifest");
}

// ---------------------------------------------------------------------------
// Frozen runner — every committed vector must reach its expected verdict from the
// bytes on disk, never from a freshly regenerated opinion.
// ---------------------------------------------------------------------------

fn committed_fixtures() -> Vec<Fixture> {
    let root = vectors_root();
    let manifest: Manifest = serde_json::from_slice(
        &std::fs::read(root.join("manifest.json")).expect("the scitt corpus is committed"),
    )
    .expect("manifest parses");
    manifest
        .fixtures
        .iter()
        .map(|e| {
            let bytes = std::fs::read(root.join(&e.file)).expect("fixture is committed");
            assert_eq!(
                hex_sha256(&bytes),
                e.sha256,
                "{}: the committed bytes do not match the manifest pin",
                e.file
            );
            serde_json::from_slice(&bytes).expect("fixture parses")
        })
        .collect()
}

#[test]
fn every_committed_vector_reaches_its_expected_verdict() {
    let fixtures = committed_fixtures();
    assert!(!fixtures.is_empty(), "the corpus must not be empty");
    for f in &fixtures {
        assert_eq!(verdict(f), f.expect, "{}: {}", f.name, f.description);
    }
}

#[test]
fn the_corpus_digest_pins_the_whole_set() {
    // A per-file hash catches an edited vector; the corpus digest catches a DELETED
    // one, which per-file hashes cannot see.
    let root = vectors_root();
    let manifest: Manifest =
        serde_json::from_slice(&std::fs::read(root.join("manifest.json")).expect("manifest"))
            .expect("manifest parses");
    assert_eq!(
        corpus_digest(&manifest.fixtures),
        manifest.corpus_digest,
        "the corpus digest does not cover the committed fixture set"
    );
}

#[test]
fn the_corpus_directory_holds_no_unpinned_vector() {
    // The digest catches a deleted fixture; neither it nor the per-file hashes can see
    // an EXTRA one. An unlisted vector is read by no test, so its expectation drifts
    // out of date invisibly — and a reader who finds it in the corpus has no way to
    // tell it is stale. The corpus is exactly what the manifest lists.
    let root = vectors_root();
    let manifest: Manifest =
        serde_json::from_slice(&std::fs::read(root.join("manifest.json")).expect("manifest"))
            .expect("manifest parses");
    let pinned: Vec<&str> = manifest.fixtures.iter().map(|e| e.file.as_str()).collect();
    for entry in std::fs::read_dir(&root).expect("corpus dir") {
        let name = entry.expect("dir entry").file_name();
        let name = name.to_string_lossy();
        if name == "manifest.json" || !name.ends_with(".json") {
            continue;
        }
        assert!(
            pinned.contains(&name.as_ref()),
            "{name} is in the corpus but not in the manifest"
        );
    }
}

#[test]
fn regenerated_fixtures_match_the_committed_bytes() {
    // Determinism: the encoding is signed over fixed inputs with fixed keys, so
    // regenerating must reproduce the frozen octets. If it does not, either the
    // encoder changed (and the corpus must be re-pinned deliberately) or something
    // non-deterministic crept into the wire form — and a non-deterministic wire form
    // cannot be pinned by anyone.
    let committed = committed_fixtures();
    let regenerated = build_fixtures();
    assert_eq!(committed.len(), regenerated.len());
    for (c, r) in committed.iter().zip(regenerated.iter()) {
        assert_eq!(c.name, r.name);
        assert_eq!(
            c.statement_cose_b64url, r.statement_cose_b64url,
            "{}: statement wire bytes drifted",
            c.name
        );
        assert_eq!(
            c.receipt_cose_b64url, r.receipt_cose_b64url,
            "{}: receipt wire bytes drifted",
            c.name
        );
    }
}

/// The wire form must be a TAGGED COSE_Sign1 (tag 18, RFC 9052 §2). An untagged
/// structure is a different thing on the wire, and a consumer that guessed would be
/// interoperating by accident.
#[test]
fn the_wire_form_is_a_tagged_cose_sign1() {
    for f in committed_fixtures() {
        for (what, b64) in [
            ("statement", &f.statement_cose_b64url),
            ("receipt", &f.receipt_cose_b64url),
        ] {
            let bytes = b64url_decode(b64).expect("b64url");
            assert_eq!(
                bytes[0], 0xd2,
                "{}: {what} must start with CBOR tag 18 (0xd2)",
                f.name
            );
        }
    }
}
