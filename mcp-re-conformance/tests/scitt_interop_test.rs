// SPDX-License-Identifier: Apache-2.0
//! MCPRE-501 slice 4 — offline verification of a receipt produced by a THIRD-PARTY
//! implementation of RFC 9942.
//!
//! The peer is `@transmute/cose` 0.3.0 (npm), authored by the RFC 9942 editor. Its
//! RFC 9162 `Tree`, its `encode_inclusion_proof`, and its CBOR encoder built the
//! receipt in `tests/vectors/scitt/interop/`; the Ed25519 signature came from Node's
//! `crypto`. No MCP-RE code produced any of it. The statement it commits to is our own
//! frozen `s01` statement, byte-for-byte.
//!
//! **What this establishes.** MCP-RE Signed Statements are read by an independent SCITT
//! implementation, and a receipt that implementation produces verifies offline under the
//! MCP-RE verifier against a pinned service key, retained evidence, and an RFC 9942
//! inclusion proof.
//!
//! A second peer is a real SCITT Transparency SERVICE: `capsule-anchor`
//! (action-state-group, Apache-2.0), run locally, which accepted our exact statement over
//! HTTP and returned a detached-payload receipt. Its corpus is in `interop/capsule-anchor/`.
//! The two peers disagree about the Merkle LEAF PREIMAGE — `@transmute/cose` hashes the
//! statement's octets, `capsule-anchor` hashes a digest of them — which is why the leaf
//! profile is a qualifier on the pinned service artifact rather than a constant.
//!
//! **What neither establishes, stated so the corpus cannot be read as more than it is.**
//! `@transmute/cose` is a LIBRARY: no registration, no HTTP, no log operated by anyone.
//! `capsule-anchor` is a service, but a LOCAL run of open-source code. So neither says
//! anything about production transparency-service operation, operator independence,
//! resistance to a split-view log, witnessed transparency, or interoperability with any
//! other implementation. Each `exchange-metadata.json` records its own limits.
//!
//! The negatives are the substance. A positive alone would show only that two
//! implementations agree on a happy path; each negative mutates the third party's own
//! receipt to show MCP-RE independently enforces the contract rather than trusting it.

use std::path::PathBuf;

use mcp_re_core::b64url_decode;
use mcp_re_core::VerificationKey;
use mcp_re_http_profile::scitt::verify_receipt_offline;
use mcp_re_http_profile::scitt::verify_retained_evidence;
use mcp_re_http_profile::scitt::Receipt;
use mcp_re_http_profile::scitt::ScittServiceTrustPin;
use mcp_re_http_profile::scitt::SignedStatement;
use mcp_re_http_profile::HttpProfileError;

fn interop_dir() -> PathBuf {
    if let Ok(rel) = std::env::var("MCP_RE_SCITT_INTEROP_MANIFEST") {
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
        panic!("MCP_RE_SCITT_INTEROP_MANIFEST set but runfile not found (rel={rel})");
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("scitt")
        .join("interop")
}

fn artifact(name: &str) -> Vec<u8> {
    std::fs::read(interop_dir().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn pin() -> ScittServiceTrustPin {
    serde_json::from_slice(&artifact("service-key-pin.json")).expect("pin parses")
}

fn statement() -> SignedStatement {
    SignedStatement::from_cose(&artifact("signed-statement.cbor")).expect("statement parses")
}

fn receipt() -> Receipt {
    Receipt::from_cose(&artifact("receipt.cbor")).expect("receipt parses")
}

/// The statement's issuer key — our own corpus issuer, since MCP-RE issued the statement.
fn issuer() -> VerificationKey {
    let s01: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            interop_dir()
                .parent()
                .expect("scitt dir")
                .join("s01_complete_record.json"),
        )
        .expect("s01 committed"),
    )
    .expect("s01 parses");
    VerificationKey::from_b64url(s01["issuer_pubkey_b64url"].as_str().expect("issuer key"))
        .expect("issuer key decodes")
}

fn verify_with(
    statement: &SignedStatement,
    receipt: &Receipt,
    pin: &ScittServiceTrustPin,
) -> Result<(), HttpProfileError> {
    let issuer = issuer();
    verify_receipt_offline(
        statement,
        receipt,
        |_| Some(issuer.clone().into()),
        |kid| pin.resolve(kid),
    )
}

/// THE decisive test: a third party's receipt verifies offline under MCP-RE, contacting
/// nothing. Every input is a committed byte string — statement, receipt, pinned key.
#[test]
fn a_third_party_receipt_verifies_offline_under_mcp_re() {
    verify_with(&statement(), &receipt(), &pin()).expect("the third party's receipt verifies");

    // Offline in the sense that matters: the producing implementation is not installed,
    // not running, and not reachable from this test. Only these bytes are.
    let r = receipt();
    assert_eq!(r.tree_size(), 2, "their tree had two leaves");
    assert_eq!(r.leaf_index(), 1, "our statement is leaf 1");
}

/// The retained evidence reproduces what the statement committed to — the other half of
/// the retained/committed split. A receipt alone is not the evidence.
#[test]
fn the_retained_evidence_reproduces_the_committed_handles() {
    let statement = statement();
    let retained: serde_json::Value =
        serde_json::from_slice(&artifact("retained-evidence.bin")).expect("retained parses");
    let request = retained["request"].as_str().expect("request base");
    let response = retained["response"].as_str().expect("response base");

    verify_retained_evidence(
        statement.commitment(),
        request.as_bytes(),
        response.as_bytes(),
    )
    .expect("the retained bytes match the commitment");

    // Altered retained evidence is refused, even though the receipt still verifies.
    assert!(
        verify_retained_evidence(statement.commitment(), b"req-tampered", response.as_bytes())
            .is_err()
    );
}

/// A pin for a different key does not verify the receipt. The pin is what a run records;
/// pointing it at the wrong key must fail rather than fall back to anything.
#[test]
fn a_wrong_pinned_service_key_is_refused() {
    let mut wrong = pin();
    // A real Ed25519 key that simply is not the signer.
    wrong.public_key.x = mcp_re_core::b64url_encode(
        &mcp_re_core::SigningKey::from_seed_bytes(&[0xAB; 32])
            .public_key()
            .to_bytes(),
    );
    assert_eq!(
        verify_with(&statement(), &receipt(), &wrong).unwrap_err(),
        HttpProfileError::ReceiptInvalid,
    );

    // And a pin whose kid does not match the receipt resolves to nothing at all.
    let mut other_kid = pin();
    other_kid.kid = "not-the-receipts-kid".into();
    assert_eq!(
        verify_with(&statement(), &receipt(), &other_kid).unwrap_err(),
        HttpProfileError::ReceiptIssuerUntrusted,
    );
}

/// Mutating the third party's receipt: each case breaks one property and must be
/// refused. The first three leave the service's signature VALID, because the mutated
/// fields ride in the unprotected header — so a verifier that checked signatures and
/// skipped the inclusion fold would accept them.
#[test]
fn mutations_of_the_third_party_receipt_are_refused() {
    let statement = statement();
    let bytes = artifact("receipt.cbor");

    // The CBOR of `inclusion-proof-content` for [2, 1, [32-byte sibling]].
    const PROOF_HEAD: [u8; 6] = [0x83, 0x02, 0x01, 0x81, 0x58, 0x20];
    let at = bytes
        .windows(PROOF_HEAD.len())
        .position(|w| w == PROOF_HEAD)
        .expect("their proof content is present");

    // 1. Forged inclusion path — signature over the tree head still valid.
    let mut forged = bytes.clone();
    forged[at + PROOF_HEAD.len() + 31] ^= 0x01;
    assert_eq!(
        verify_with(
            &statement,
            &Receipt::from_cose(&forged).expect("still parses"),
            &pin()
        )
        .unwrap_err(),
        HttpProfileError::ReceiptInclusionInvalid,
    );

    // 2. leaf-index == tree-size.
    let mut outside = bytes.clone();
    outside[at + 2] = 0x02;
    assert_eq!(
        Receipt::from_cose(&outside).unwrap_err(),
        HttpProfileError::MalformedEvidence("scitt inclusion proof leaf index outside tree"),
    );

    // 3. A tree size that no longer covers the proof.
    let mut resized = bytes.clone();
    resized[at + 1] = 0x01;
    assert!(
        Receipt::from_cose(&resized).is_err()
            || verify_with(
                &statement,
                &Receipt::from_cose(&resized).expect("parses"),
                &pin()
            )
            .is_err(),
        "a tree size inconsistent with the proof must not verify"
    );

    // 4. The signed payload (the Merkle root) changed — the signature must fail.
    let root_at = bytes.len() - 64 - 34;
    let mut payload = bytes.clone();
    payload[root_at] ^= 0x01;
    let outcome = Receipt::from_cose(&payload).and_then(|r| verify_with(&statement, &r, &pin()));
    assert!(outcome.is_err(), "a changed payload must not verify");
}

/// Their receipt paired with a different statement. Both artifacts are genuine; only the
/// binding between them is wrong, and only re-deriving the root from THIS statement's
/// leaf catches it.
#[test]
fn the_third_party_receipt_does_not_verify_another_statement() {
    let s02: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            interop_dir()
                .parent()
                .expect("scitt dir")
                .join("s02_incomplete_record.json"),
        )
        .expect("s02 committed"),
    )
    .expect("s02 parses");
    let other = SignedStatement::from_cose(
        &b64url_decode(s02["statement_cose_b64url"].as_str().expect("statement")).expect("b64url"),
    )
    .expect("parses");

    assert_eq!(
        verify_with(&other, &receipt(), &pin()).unwrap_err(),
        HttpProfileError::ReceiptInclusionInvalid,
    );
}

/// The corpus records what the peer was and what the exchange did NOT include, so the
/// claim cannot drift upward later.
#[test]
fn the_corpus_records_the_limits_of_the_exchange() {
    let manifest: serde_json::Value =
        serde_json::from_slice(&artifact("manifest.json")).expect("manifest parses");
    assert_eq!(manifest["schema"], "mcp-re-scitt-interop/v1");
    assert!(
        manifest["peer"]
            .as_str()
            .expect("peer")
            .contains("@transmute/cose"),
        "the peer must be named"
    );

    let exchange: serde_json::Value =
        serde_json::from_slice(&artifact("exchange-metadata.json")).expect("metadata parses");
    assert!(
        exchange["not_a_service"]
            .as_str()
            .expect("not_a_service")
            .contains("LIBRARY"),
        "the corpus must say the peer is not a transparency service"
    );
    assert!(
        exchange["local_patch"].as_str().expect("local_patch").len() > 40,
        "the patch applied to the peer must be recorded"
    );

    // Every artifact hash in the manifest must match the bytes on disk.
    use sha2::Digest;
    for (name, expected) in manifest["artifacts"].as_object().expect("artifacts") {
        let actual = mcp_re_core::b64url_encode(&sha2::Sha256::digest(artifact(name)));
        assert_eq!(
            &actual,
            expected.as_str().expect("digest"),
            "{name} drifted"
        );
    }
}

// ---------------------------------------------------------------------------
// capsule-anchor — a real SCITT Transparency SERVICE, run locally.
// ---------------------------------------------------------------------------

/// The corpus from the `capsule-anchor` exchange: it accepted our exact Signed Statement
/// over HTTP and returned a receipt. Frozen so verification is reproducible with the
/// service stopped — which is what "offline" has to mean.
fn capsule_dir() -> PathBuf {
    interop_dir().join("capsule-anchor")
}

fn capsule(name: &str) -> Vec<u8> {
    std::fs::read(capsule_dir().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// A real service's receipt verifies offline — detached payload, and its own leaf
/// profile taken from the pin.
#[test]
fn a_real_transparency_services_receipt_verifies_offline() {
    let statement = SignedStatement::from_cose(&capsule("signed-statement.cbor")).expect("parses");
    let receipt = Receipt::from_cose(&capsule("receipt.cbor")).expect("parses");
    let pin: ScittServiceTrustPin =
        serde_json::from_slice(&capsule("service-key-pin.json")).expect("pin parses");
    let issuer = issuer();

    verify_receipt_offline(
        &statement,
        &receipt,
        |_| Some(issuer.clone().into()),
        |kid| pin.resolve(kid),
    )
    .expect("capsule-anchor's receipt verifies offline");
}

/// The qualifier decides, and exactly one value of it can be right. With the default
/// profile the same receipt does NOT verify — so the profile is doing real work, and
/// nothing silently falls back to trying the other one.
#[test]
fn the_wrong_leaf_profile_refuses_rather_than_falling_back() {
    use mcp_re_http_profile::scitt::StatementLeafProfile;

    let statement = SignedStatement::from_cose(&capsule("signed-statement.cbor")).expect("parses");
    let receipt = Receipt::from_cose(&capsule("receipt.cbor")).expect("parses");
    let mut pin: ScittServiceTrustPin =
        serde_json::from_slice(&capsule("service-key-pin.json")).expect("pin parses");
    assert_eq!(
        pin.leaf_profile,
        StatementLeafProfile::StatementDigest,
        "capsule-anchor logs a digest of the statement"
    );

    pin.leaf_profile = StatementLeafProfile::StatementBytes;
    let issuer = issuer();
    assert_eq!(
        verify_receipt_offline(
            &statement,
            &receipt,
            |_| Some(issuer.clone().into()),
            |kid| pin.resolve(kid)
        )
        .expect_err("the default profile must not verify this service's receipt"),
        HttpProfileError::ReceiptInvalid,
    );
}

/// The corpus records the registration exchange and its limits — including that this was
/// a local run of an open-source service, not a production transparency service.
#[test]
fn the_capsule_anchor_corpus_records_the_exchange_and_its_limits() {
    let meta: serde_json::Value =
        serde_json::from_slice(&capsule("exchange-metadata.json")).expect("metadata parses");
    assert_eq!(meta["leaf_profile"], "statement-digest");
    assert!(meta["registration_request"]["path"]
        .as_str()
        .expect("path")
        .contains("register-statement"));
    assert!(meta["limits"].as_str().expect("limits").contains("LOCAL"));
    assert!(meta["leaf_profile_reason"]
        .as_str()
        .expect("reason")
        .contains("RFC 9162"));

    use sha2::Digest;
    let manifest: serde_json::Value =
        serde_json::from_slice(&capsule("manifest.json")).expect("manifest parses");
    for (name, expected) in manifest["artifacts"].as_object().expect("artifacts") {
        let actual = mcp_re_core::b64url_encode(&sha2::Sha256::digest(capsule(name)));
        assert_eq!(
            &actual,
            expected.as_str().expect("digest"),
            "{name} drifted"
        );
    }
}
