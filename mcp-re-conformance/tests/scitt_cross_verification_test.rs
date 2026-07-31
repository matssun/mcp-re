// SPDX-License-Identifier: Apache-2.0
//! external → us: the MCP-RE verifier against SCITT artifacts built by an INDEPENDENT
//! implementation of RFC 9942 / RFC 9943 as published (MCPRE-501 no-merge gate).
//!
//! **Why this test exists.** A non-conforming receipt encoding shipped: the receipt
//! carried the pre-publication draft header labels `-111`/`-222` rather than RFC 9942
//! §5.2.1's `vds` = 395 and `vdp` = 396, and the whole suite was green throughout. It was
//! green because it ran the encoder against its own decoder — which agrees with itself
//! whatever labels it picks, so no round-trip test could have failed. Nothing in the
//! repository compared our bytes to the standard.
//!
//! This is that comparison. `external_kat.json` is built by
//! `tools/scitt_cross_verify.py` from the RFC text using `cbor2` and `cryptography` —
//! a different CBOR implementation and a different signature implementation than the
//! `ciborium`/`ed25519-dalek`/`p256` this crate verifies with. The statements and
//! receipts in it were never produced by MCP-RE code.
//!
//! It is built against the STABLE standard: RFC 9942 and RFC 9943 as published, not a
//! draft and not any implementation's dialect of one. `x03` is a receipt with the draft
//! labels, present so a regression to them fails here rather than shipping again.
//!
//! The complementary direction (our committed corpus read by third-party code) runs in
//! `tools/scitt_cross_verify.py`, the CI no-merge gate.
//!
//! Regenerate the external vector:
//!   python3 mcp-re-conformance/tools/scitt_cross_verify.py --emit-external-kat

use std::path::PathBuf;

use mcp_re_core::b64url_decode;
use mcp_re_core::VerificationKey;
use mcp_re_http_profile::scitt::verify_receipt_offline;
use mcp_re_http_profile::scitt::Receipt;
use mcp_re_http_profile::scitt::ScittServiceTrustPin;
use mcp_re_http_profile::scitt::SignedStatement;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ExternalKat {
    schema: String,
    produced_by: String,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    description: String,
    statement_cose_b64url: String,
    receipt_cose_b64url: String,
    issuer_pubkey_b64url: String,
    /// The transparency-service key as a pinned trust artifact — the same shape a real
    /// run records, so this exercises the pin path rather than a test-only shortcut.
    ts_trust_pin: ScittServiceTrustPin,
    /// `verify_ok`, or `verify_fail` for the refusals a conforming verifier owes.
    expect: String,
}

/// The corpus directory: the runfiles copy under Bazel, the source tree under cargo.
fn corpus_dir() -> PathBuf {
    if let Ok(rel) = std::env::var("MCP_RE_SCITT_EXTERNAL_KAT") {
        for key in ["TEST_SRCDIR", "RUNFILES_DIR"] {
            if let Ok(root) = std::env::var(key) {
                let candidate = std::path::Path::new(&root).join(&rel);
                if candidate.exists() {
                    return candidate.parent().expect("kat parent").to_path_buf();
                }
            }
        }
        let candidate = PathBuf::from(&rel);
        if candidate.exists() {
            return candidate.parent().expect("kat parent").to_path_buf();
        }
        panic!("MCP_RE_SCITT_EXTERNAL_KAT set but runfile not found (rel={rel})");
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("scitt")
}

fn external_kat() -> ExternalKat {
    let path = corpus_dir().join("external_kat.json");
    serde_json::from_slice(&std::fs::read(&path).expect("external_kat.json committed"))
        .expect("external_kat.json parses")
}

/// The verdict the MCP-RE verifier reaches on one externally built case, from the bytes
/// alone — resolving the service key through the committed trust pin.
fn verdict(case: &Case) -> Result<(), String> {
    let statement =
        SignedStatement::from_cose(&b64url_decode(&case.statement_cose_b64url).expect("b64url"))
            .map_err(|e| format!("statement: {}", e.wire_code()))?;
    let receipt = Receipt::from_cose(&b64url_decode(&case.receipt_cose_b64url).expect("b64url"))
        .map_err(|e| format!("receipt: {}", e.wire_code()))?;
    let issuer = VerificationKey::from_b64url(&case.issuer_pubkey_b64url).expect("issuer key");
    verify_receipt_offline(
        &statement,
        &receipt,
        |_| Some(issuer.clone().into()),
        |kid| case.ts_trust_pin.resolve(kid),
    )
    .map_err(|e| e.wire_code().to_owned())
}

#[test]
fn the_external_corpus_is_the_expected_shape() {
    let kat = external_kat();
    assert_eq!(kat.schema, "mcp-re-scitt-external-kat/v1");
    assert!(
        kat.produced_by.contains("cbor2") && kat.produced_by.contains("cryptography"),
        "the corpus must come from independent CBOR and signature implementations, not \
         from MCP-RE: {}",
        kat.produced_by
    );
    // A gate with no positives proves nothing, and one with no refusals proves only that
    // something can be accepted.
    assert!(
        kat.cases.iter().any(|c| c.expect == "verify_ok"),
        "no positive case"
    );
    assert!(
        kat.cases.iter().filter(|c| c.expect != "verify_ok").count() >= 5,
        "the refusals are the substance of the gate"
    );
}

/// An EdDSA and an ES256 receipt, built by an independent implementation from the
/// published RFCs, verify under the MCP-RE verifier. If our header labels or proof
/// nesting disagreed with RFC 9942 §5.2.1, these would fail — which is exactly what
/// nothing in the repository checked before.
#[test]
fn externally_built_receipts_verify_under_the_mcp_re_verifier() {
    let kat = external_kat();
    for case in kat.cases.iter().filter(|c| c.expect == "verify_ok") {
        verdict(case).unwrap_or_else(|e| {
            panic!(
                "{}: an externally built receipt must verify, got {e}\n  {}",
                case.name, case.description
            )
        });
    }
}

/// Every externally built negative is refused. Each names a distinct property, and three
/// of them leave the service's signature VALID — so a verifier that checked signatures
/// and skipped the inclusion fold would accept them.
#[test]
fn externally_built_negatives_are_refused() {
    let kat = external_kat();
    for case in kat.cases.iter().filter(|c| c.expect != "verify_ok") {
        let outcome = verdict(case);
        assert!(
            outcome.is_err(),
            "{}: must be refused but the verifier accepted it\n  {}",
            case.name,
            case.description
        );
    }
}

/// The draft-label case is called out on its own, because it is the regression this gate
/// exists for: a receipt labelled `-111`/`-222` must be unreadable to this verifier.
#[test]
fn a_receipt_with_the_draft_era_labels_is_refused() {
    let kat = external_kat();
    let case = kat
        .cases
        .iter()
        .find(|c| c.name == "x03_draft_era_labels_refused")
        .expect("the draft-label regression case is present");
    assert_eq!(
        verdict(case).expect_err("draft labels must not verify"),
        "receipt: mcp-re.malformed_envelope",
        "a draft-labelled receipt must be refused as malformed, not verified"
    );
}
