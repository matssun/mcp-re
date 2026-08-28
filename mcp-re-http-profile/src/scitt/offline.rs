// SPDX-License-Identifier: Apache-2.0
//! Offline receipt verification — the composition.
//!
//! One fact: **this statement was registered in this service's log, and everything that
//! claim rests on was checked without contacting anybody.** It decides nothing itself; it
//! composes the owners — the statement's typing, the receipt's wire form, the fold, the
//! COSE verification, and the service's own profiles — in the one order that makes the
//! result mean what it says.
//!
//! What it deliberately does NOT establish is that the evidence the statement commits to
//! still exists. That is [`super::retained`]'s, and keeping the two apart is why a verified
//! receipt cannot be read as a claim about retained bytes.

use crate::error::HttpProfileError;

use super::cose_key::verify_cose_sign1;
use super::cose_key::verify_cose_sign1_with_payload;
use super::cose_key::CoseVerificationKey;
use super::merkle::leaf_hash;
use super::merkle::rfc9162_root_from_inclusion_proof;
use super::receipt::Receipt;
use super::service::ResolvedTransparencyService;
use super::statement::SignedStatement;
use super::wire::position_commitment;
use super::wire::ReceiptPositionProfile;
use super::wire::VDS_RFC9162_SHA256;

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
    let leaf = leaf_hash(statement, ts.leaf_profile());
    let computed = rfc9162_root_from_inclusion_proof(
        &leaf,
        receipt.leaf_index(),
        receipt.tree_size(),
        receipt.inclusion_path(),
    )?;
    if let Some(root) = receipt.committed_root() {
        if computed.as_slice() != root {
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
        ts.key(),
        receipt.committed_root().is_none(),
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
    match (ts.position_profile(), receipt.position_commitment()) {
        (ReceiptPositionProfile::Bound, None) => {
            return Err(HttpProfileError::ReceiptPositionUnbound)
        }
        (_, Some(bound)) => {
            let expected = position_commitment(
                receipt.ts_kid(),
                VDS_RFC9162_SHA256,
                receipt.tree_size(),
                receipt.leaf_index(),
                &computed,
            );
            if expected != bound {
                return Err(HttpProfileError::ReceiptPositionMismatch);
            }
        }
        (ReceiptPositionProfile::Unbound, None) => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::ChainLabel;
    use crate::chain::IncompleteReason;
    use crate::scitt::commitment::EvidenceCommitment;
    use crate::scitt::fixtures::*;
    use crate::scitt::prototype::PrototypeTransparencyService;
    use crate::scitt::receipt::Receipt;

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
        assert!(!legacy.is_position_bound());
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
        assert!(!stripped.is_position_bound());
        assert_eq!(
            verify_receipt_offline(&st, &stripped, ir(), ts_p256_bound()).unwrap_err(),
            HttpProfileError::ReceiptPositionUnbound,
        );
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
            commitment.chain_label().starts_with("incomplete:1:"),
            "and names the failing hop"
        );

        let st = statement(commitment);
        let mut svc = PrototypeTransparencyService::new(TS_KID);
        let receipt = register(&mut svc, &st);
        verify_receipt_offline(&st, &receipt, ir(), tr()).expect("verifies");
        // The verified statement still says incomplete — the receipt did not launder it.
        assert!(!st.commitment().is_complete_record());
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
        assert_eq!(tampered.commitment().chain_label(), "complet3");

        assert_eq!(
            verify_receipt_offline(&tampered, &receipt, ir(), tr()).unwrap_err(),
            HttpProfileError::ReceiptInvalid,
        );
    }

    #[test]
    fn a_forged_inclusion_path_fails() {
        let st = statement(EvidenceCommitment::from_reconstruction(
            &recon(ChainLabel::Complete, 2),
            None,
            None,
        ));
        let mut svc = PrototypeTransparencyService::new(TS_KID);
        let receipt = register(&mut svc, &st);
        // Swap a sibling: the recomputed root no longer matches the signed one.
        // The proof lives in the UNPROTECTED header, so this is exactly the tamper a
        // receipt must survive — forging it cannot forge inclusion, it can only make
        // the derived root fail to match the one the service signed.
        let receipt = receipt.with_forged_inclusion_path(vec![vec![9u8; 32]]);
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
