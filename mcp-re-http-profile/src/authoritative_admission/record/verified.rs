// SPDX-License-Identifier: Apache-2.0
//! The verified product, and the one procedure that produces it.
//!
//! # The seal
//!
//! [`CurrentAdmissionState`]'s representation is private to THIS file and
//! [`verify_admission_state_record`] is its only constructor. The enforcement point
//! consumes this type rather than
//! [`AuthoritativeAdmission`](crate::authoritative_admission::AuthoritativeAdmission), so
//! building the semantic fact is no longer a way to reach the gate: the fact stays freely
//! constructible — the currency theorem's Verus contract reads its fields, and sealing it
//! would cost THM-0003 through THM-0006 their conjuncts — while AUTHENTICATED authoritative
//! state is obtainable only by verifying a record.
//!
//! The parent module cannot assemble one either. Privacy reaches a module's DESCENDANTS,
//! and `mod.rs` is this file's ancestor, so the seal holds against the whole crate and not
//! merely against other crates.

use mcp_re_core::b64url_decode;
use mcp_re_core::b64url_encode;
use mcp_re_core::verify_ed25519_with;
use mcp_re_core::McpReError;
use mcp_re_core::VerificationKey;
use serde::Deserialize;

use crate::authoritative_admission::AuthoritativeAdmission;

use super::currentness::check_currentness;
use super::AdmissionRecordRefusal;
use super::AdmissionStateClaims;
use super::AdmissionStateCurrentness;
use super::AdmissionStateHeader;
use super::ADMISSION_STATE_ALG;
use super::ADMISSION_STATE_TYP;

/// An authoritative admission state that was AUTHENTICATED and found current.
///
/// Possession is the claim: this state was signed by the configured admission authority,
/// is about the workload it was read for, and is inside the deployment's declared
/// currentness budget. Nothing a caller remembers to check afterwards is part of that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentAdmissionState {
    /// The semantic fact, as the currency check consumes it.
    state: AuthoritativeAdmission,
    /// The publication sequence this record carried.
    revision: u64,
}

impl CurrentAdmissionState {
    /// The authoritative state, for the currency comparison.
    pub fn state(&self) -> &AuthoritativeAdmission {
        &self.state
    }

    /// The publication sequence the record carried.
    ///
    /// A caller may keep the highest value it has seen per workload and refuse a lower one.
    /// That is HARDENING and NOT the boundary: a replica that has just started has no
    /// floor, and a restart forgets it, so a monotone floor cannot by itself stop a
    /// rollback. What stops one is the currentness budget, which needs no memory. The floor
    /// narrows the window in which a restored record is useful to a replica that was
    /// already running, which is worth having and is not worth confusing with the boundary.
    pub fn state_revision(&self) -> u64 {
        self.revision
    }
}

/// Verify one stored record and decide whether it is the authority's CURRENT statement
/// about `expected_admission_id`.
///
/// `resolve_issuer` resolves the record's `issuer_kid` to the configured admission
/// authority key — the same seam, and in a correct deployment the same key, the assertion
/// path uses. `observed_revision_floor` is the highest publication sequence this verifier
/// has already accepted for this workload, or `None` if it has none.
///
/// Every refusal is definitive. None of them is an outage; see [`AdmissionRecordRefusal`].
pub fn verify_admission_state_record(
    compact_jws: &str,
    expected_admission_id: &str,
    expected_profile: &str,
    currentness: &AdmissionStateCurrentness,
    observed_revision_floor: Option<u64>,
    now: i64,
    resolve_issuer: impl Fn(&str) -> Option<VerificationKey>,
) -> Result<CurrentAdmissionState, AdmissionRecordRefusal> {
    let (h_seg, p_seg, s_seg) = split_compact(compact_jws)?;
    let header: AdmissionStateHeader = decode_json(h_seg)?;
    if header.typ != ADMISSION_STATE_TYP || header.alg != ADMISSION_STATE_ALG {
        return Err(AdmissionRecordRefusal::Malformed);
    }
    let claims: AdmissionStateClaims = decode_json(p_seg)?;
    if header.kid != claims.issuer_kid {
        return Err(AdmissionRecordRefusal::Malformed);
    }

    let authority =
        resolve_issuer(&claims.issuer_kid).ok_or(AdmissionRecordRefusal::IssuerUntrusted)?;
    let signing_input = format!("{h_seg}.{p_seg}");
    verify_ed25519_with(
        signing_input.as_bytes(),
        &normalize_signature(s_seg)?,
        &authority,
        McpReError::InvalidSignature,
    )
    .map_err(|_| AdmissionRecordRefusal::SignatureInvalid)?;

    if claims.mcp_re_profile != expected_profile {
        return Err(AdmissionRecordRefusal::ProfileMismatch);
    }
    // The subject is checked against the id the record was READ UNDER. Without it, a party
    // that can write the store could copy an admitted workload's record onto a revoked
    // workload's key and the signature would still verify — a forgery by MOVE rather than
    // by mint, which origin alone cannot see.
    if claims.mcp_re_admission_id != expected_admission_id {
        return Err(AdmissionRecordRefusal::SubjectMismatch);
    }

    check_currentness(&claims, currentness, now)?;

    if observed_revision_floor.is_some_and(|floor| claims.mcp_re_state_revision < floor) {
        return Err(AdmissionRecordRefusal::RevisionRewound);
    }

    Ok(CurrentAdmissionState {
        state: AuthoritativeAdmission::new(
            claims.mcp_re_admission_id,
            claims.mcp_re_admission_generation,
            claims.mcp_re_admission_status,
        ),
        revision: claims.mcp_re_state_revision,
    })
}

fn split_compact(jws: &str) -> Result<(&str, &str, &str), AdmissionRecordRefusal> {
    let mut it = jws.split('.');
    match (it.next(), it.next(), it.next(), it.next()) {
        (Some(h), Some(p), Some(s), None) if !h.is_empty() && !p.is_empty() && !s.is_empty() => {
            Ok((h, p, s))
        }
        _ => Err(AdmissionRecordRefusal::Malformed),
    }
}

fn decode_json<T: for<'de> Deserialize<'de>>(seg: &str) -> Result<T, AdmissionRecordRefusal> {
    let bytes = b64url_decode(seg).map_err(|_| AdmissionRecordRefusal::Malformed)?;
    serde_json::from_slice(&bytes).map_err(|_| AdmissionRecordRefusal::Malformed)
}

/// The signature segment is already base64url; decode/re-encode normalizes it to the exact
/// form the core verifier consumes and rejects a malformed one.
fn normalize_signature(s_seg: &str) -> Result<String, AdmissionRecordRefusal> {
    let bytes = b64url_decode(s_seg).map_err(|_| AdmissionRecordRefusal::Malformed)?;
    Ok(b64url_encode(&bytes))
}

#[cfg(test)]
mod tests {
    use super::super::issue_admission_state_record;
    use super::super::test_support::{claims, KID, PROFILE};
    use super::*;
    use crate::admission::AdmissionStatus;
    use mcp_re_core::SigningKey;

    fn authority() -> SigningKey {
        SigningKey::from_seed_bytes(&[7u8; 32])
    }

    fn other_authority() -> SigningKey {
        SigningKey::from_seed_bytes(&[9u8; 32])
    }

    fn sign_with(
        key: &SigningKey,
    ) -> impl FnOnce(&[u8]) -> Result<Vec<u8>, crate::HttpProfileError> + '_ {
        move |bytes: &[u8]| {
            b64url_decode(&key.sign(bytes))
                .map_err(|_| crate::HttpProfileError::MalformedEvidence("test signature"))
        }
    }

    fn issued(c: &AdmissionStateClaims, key: &SigningKey) -> String {
        issue_admission_state_record(c, sign_with(key)).expect("issued")
    }

    fn budget() -> AdmissionStateCurrentness {
        AdmissionStateCurrentness {
            max_record_age: 60,
            max_clock_skew: 5,
        }
    }

    fn resolver(key: VerificationKey) -> impl Fn(&str) -> Option<VerificationKey> {
        move |presented: &str| (presented == KID).then(|| key.clone())
    }

    fn verify_at(
        jws: &str,
        id: &str,
        now: i64,
    ) -> Result<CurrentAdmissionState, AdmissionRecordRefusal> {
        verify_admission_state_record(
            jws,
            id,
            PROFILE,
            &budget(),
            None,
            now,
            resolver(authority().public_key()),
        )
    }

    /// The accepting half. Without it every refusal below is satisfied by a verifier that
    /// refuses everything, which would establish nothing about the record that IS current.
    #[test]
    fn a_record_signed_by_the_configured_authority_is_accepted_and_projects_its_state() {
        let a = authority();
        let verified = verify_at(&issued(&claims("wl-a", 7, 3), &a), "wl-a", 1_030)
            .unwrap_or_else(|e| panic!("a current record must verify: {e}"));
        assert_eq!(verified.state().admission_id(), "wl-a");
        assert_eq!(verified.state().generation(), 7);
        assert_eq!(verified.state().status(), AdmissionStatus::Admitted);
        assert_eq!(verified.state_revision(), 3);
    }

    /// **Store-write is not signing authority: the status.** Changing `admitted` to
    /// `revoked` — or the reverse — in the stored bytes breaks the signature.
    #[test]
    fn a_changed_status_in_the_stored_bytes_is_refused() {
        let a = authority();
        let mut c = claims("wl-a", 7, 3);
        let original = issued(&c, &a);
        c.mcp_re_admission_status = AdmissionStatus::Revoked;
        let forged = tamper_payload(&original, &c);
        assert_eq!(
            verify_at(&forged, "wl-a", 1_030),
            Err(AdmissionRecordRefusal::SignatureInvalid)
        );
    }

    /// **Store-write is not signing authority: the generation.**
    #[test]
    fn a_changed_generation_is_refused() {
        let a = authority();
        let mut c = claims("wl-a", 7, 3);
        let original = issued(&c, &a);
        c.mcp_re_admission_generation = 9;
        assert_eq!(
            verify_at(&tamper_payload(&original, &c), "wl-a", 1_030),
            Err(AdmissionRecordRefusal::SignatureInvalid)
        );
    }

    /// **A Redis-only writer cannot choose an arbitrarily high generation**, because it
    /// cannot produce a signature over one.
    #[test]
    fn a_store_writer_cannot_mint_a_high_generation() {
        let mint = issued(&claims("wl-a", u64::MAX, 1), &other_authority());
        assert_eq!(
            verify_at(&mint, "wl-a", 1_030),
            Err(AdmissionRecordRefusal::SignatureInvalid)
        );
    }

    /// **Moving a record under another workload's key** is a forgery the signature cannot
    /// see, because the bytes are genuine. The subject comparison is what sees it.
    #[test]
    fn a_record_moved_under_another_admission_id_is_refused() {
        let a = authority();
        let genuine = issued(&claims("wl-a", 7, 3), &a);
        assert_eq!(
            verify_at(&genuine, "wl-b", 1_030),
            Err(AdmissionRecordRefusal::SubjectMismatch)
        );
    }

    /// An unknown or wrong issuer is refused BEFORE any signature work — a kid never
    /// introduces trust.
    #[test]
    fn an_unknown_issuer_is_refused() {
        let a = authority();
        let mut c = claims("wl-a", 7, 3);
        c.issuer_kid = "someone/else/1".to_owned();
        assert_eq!(
            verify_at(&issued(&c, &a), "wl-a", 1_030),
            Err(AdmissionRecordRefusal::IssuerUntrusted)
        );
    }

    /// A record signed by a key the deployment does not configure — the unsigned-forgery
    /// case, spelled the only way an attacker can spell it.
    #[test]
    fn a_record_signed_by_an_unconfigured_key_is_refused() {
        assert_eq!(
            verify_at(
                &issued(&claims("wl-a", 7, 3), &other_authority()),
                "wl-a",
                1_030
            ),
            Err(AdmissionRecordRefusal::SignatureInvalid)
        );
    }

    /// The header must agree with the claims about who signed, or the kid that SELECTED the
    /// key is not the identity the signature covers.
    #[test]
    fn a_header_kid_disagreeing_with_the_claims_is_refused() {
        let a = authority();
        let jws = issued(&claims("wl-a", 7, 3), &a);
        let mut segments = jws.split('.');
        let (_, p, s) = (
            segments.next().expect("h"),
            segments.next().expect("p"),
            segments.next().expect("s"),
        );
        let header = AdmissionStateHeader {
            typ: ADMISSION_STATE_TYP.to_owned(),
            alg: ADMISSION_STATE_ALG.to_owned(),
            kid: "someone/else/1".to_owned(),
        };
        let h = b64url_encode(&serde_json::to_vec(&header).expect("header"));
        assert_eq!(
            verify_at(&format!("{h}.{p}.{s}"), "wl-a", 1_030),
            Err(AdmissionRecordRefusal::Malformed)
        );
    }

    /// An admission ASSERTION presented where a record is expected is refused by `typ`.
    /// Both are signed by the same key, so nothing but the artifact's own identity
    /// separates them.
    #[test]
    fn an_assertion_presented_as_a_record_is_refused() {
        let a = authority();
        let mut header = serde_json::json!({
            "typ": crate::admission::ADMISSION_TYP,
            "alg": "EdDSA",
            "kid": KID,
        });
        let h = b64url_encode(&serde_json::to_vec(&header).expect("header"));
        let p = b64url_encode(&serde_json::to_vec(&claims("wl-a", 7, 3)).expect("claims"));
        let sig = a.sign(format!("{h}.{p}").as_bytes());
        assert_eq!(
            verify_at(&format!("{h}.{p}.{sig}"), "wl-a", 1_030),
            Err(AdmissionRecordRefusal::Malformed)
        );
        header["typ"] = serde_json::Value::String(ADMISSION_STATE_TYP.to_owned());
    }

    /// **The rollback attack, end to end.** A legitimate ADMITTED record, a legitimate
    /// REVOKED one, and then the old bytes restored by a party that can write the store.
    /// Both verify as genuine; the restored one stops being useful at the budget.
    #[test]
    fn a_restored_admitted_record_is_refused_past_the_authorized_window() {
        let a = authority();
        let admitted = issued(&claims("wl-a", 7, 1), &a);

        // t1: the authority revokes. Same generation — revocation is not a rotation — and
        // the next publication sequence.
        let mut revoked_claims = claims("wl-a", 7, 2);
        revoked_claims.mcp_re_admission_status = AdmissionStatus::Revoked;
        revoked_claims.iat = 1_010;
        revoked_claims.nbf = 1_010;
        revoked_claims.exp = 1_070;
        let revoked = issued(&revoked_claims, &a);
        assert_eq!(
            verify_at(&revoked, "wl-a", 1_020)
                .expect("the revocation is a genuine record")
                .state()
                .status(),
            AdmissionStatus::Revoked
        );

        // t2: the old bytes are restored. Inside the budget they still verify — the
        // signature is genuine and nothing here detects the substitution. That is the
        // window the deployment declared, not a defect.
        assert_eq!(
            verify_at(&admitted, "wl-a", 1_020)
                .expect("inside the declared budget")
                .state()
                .status(),
            AdmissionStatus::Admitted
        );

        // Past it, the restored record fails closed WITHOUT anyone detecting anything.
        // This is the whole anti-rollback property: the authority's power to revoke is
        // restored by the passage of the budget.
        assert_eq!(
            verify_at(&admitted, "wl-a", 1_066),
            Err(AdmissionRecordRefusal::Expired)
        );
    }

    /// The revision floor is HARDENING: a replica that has already seen publication 2
    /// refuses publication 1, narrowing the window above for a replica that was running.
    #[test]
    fn an_observed_revision_floor_refuses_an_older_publication() {
        let a = authority();
        let old = issued(&claims("wl-a", 7, 1), &a);
        assert_eq!(
            verify_admission_state_record(
                &old,
                "wl-a",
                PROFILE,
                &budget(),
                Some(2),
                1_030,
                resolver(a.public_key()),
            ),
            Err(AdmissionRecordRefusal::RevisionRewound)
        );
        // The floor admits its own value, so a re-read of the current record is not a
        // rewind.
        assert!(verify_admission_state_record(
            &issued(&claims("wl-a", 7, 2), &a),
            "wl-a",
            PROFILE,
            &budget(),
            Some(2),
            1_030,
            resolver(a.public_key()),
        )
        .is_ok());
    }

    #[test]
    fn a_record_from_another_evidence_profile_is_refused() {
        let a = authority();
        let mut c = claims("wl-a", 7, 3);
        c.mcp_re_profile = "some-other-profile".to_owned();
        assert_eq!(
            verify_at(&issued(&c, &a), "wl-a", 1_030),
            Err(AdmissionRecordRefusal::ProfileMismatch)
        );
    }

    #[test]
    fn malformed_bytes_are_refused_as_malformed_and_never_as_anything_softer() {
        for bad in [
            "",
            "not-a-jws",
            "a.b",
            "a.b.c.d",
            ".b.c",
            "a..c",
            "a.b.",
            "!!!.???.###",
        ] {
            assert_eq!(
                verify_at(bad, "wl-a", 1_030),
                Err(AdmissionRecordRefusal::Malformed),
                "{bad:?}"
            );
        }
    }

    /// Re-sign `claims` onto `original`'s header with no valid signature — the shape a
    /// store-write adversary can actually produce, which is genuine-looking bytes it cannot
    /// sign.
    fn tamper_payload(original: &str, claims: &AdmissionStateClaims) -> String {
        let mut segments = original.split('.');
        let h = segments.next().expect("h");
        let s = segments.nth(1).expect("s");
        let p = b64url_encode(&serde_json::to_vec(claims).expect("claims"));
        format!("{h}.{p}.{s}")
    }
}
