// SPDX-License-Identifier: Apache-2.0
//! The AUTHENTICATED authoritative admission record — what the enforcement point is
//! entitled to treat as the admission authority's current statement about a workload.
//!
//! # The boundary this closes
//!
//! [`AuthoritativeAdmission`](crate::authoritative_admission::AuthoritativeAdmission) is a
//! SEMANTIC FACT: whose admission, at which generation, in which status. It says nothing
//! about who said so. The shared store that carries it to every replica used to answer that
//! question by itself — the record was a two-field string, and the argument for believing
//! it was that only trusted parties can write the key. That makes the STORE the admission
//! authority, which it is not: a store is a storage and availability substrate, and write
//! access to it is not admission-signing authority.
//!
//! What a party with store-write access but no signing authority may still do is deny
//! service — delete the record, corrupt it, take the store down. What it must not be able
//! to do is MINT an admission, move a workload from revoked back to admitted, file one
//! workload's state under another's id, change the generation or status undetectably, or
//! restore an old admitted record indefinitely. This module is the boundary between the
//! two.
//!
//! # Not a second trust root
//!
//! The record is a compact JWS in exactly the family the admission authority already
//! publishes in: the same `EdDSA`/Ed25519, the same kid-resolved issuer seam, the same
//! `verify_ed25519_with` primitive, the same shape rules as
//! [`crate::admission::verify_admission_assertion`]. It differs in its `typ`, which is what
//! stops the two from being presented for one another, and a deployment verifies both under
//! the ONE key it already configured as its admission authority
//! (`--admission-authority-kid` / `--admission-authority-pubkey`). No new trust root, no
//! second signer, no private key anywhere near the serving process.
//!
//! # Signature alone is not currentness
//!
//! A valid signature is a statement about the past. The attack it does not stop:
//!
//! ```text
//! t0  the authority signs ADMITTED, generation 7
//! t1  the authority revokes generation 7 and publishes REVOKED
//! t2  a party with store-write access puts the t0 bytes back
//! ```
//!
//! Both records are genuinely signed and name the same workload and generation, so ORIGIN
//! cannot separate them. What separates them is TIME: the t0 record carries its own
//! issuance coordinate, and the verifier refuses it once it is older than the currentness
//! budget the DEPLOYMENT declared — not the window the publisher asked for. Past that bound
//! the restored record fails closed, and the authority's power to revoke is restored by the
//! passage of the budget rather than by anyone detecting the substitution. See
//! [`currentness`].
//!
//! That is why the budget is an input to verification and not a field of the record. A
//! publisher free to choose its own window could choose an unbounded one, and the
//! deployment's stated revocation-propagation promise would be a number the authority is
//! free to ignore.
//!
//! # The revision coordinate is not the generation
//!
//! `generation` is the admitted CONFIGURATION epoch, and revocation deliberately does not
//! advance it — a revoked record that also bumped the generation would be refused for the
//! wrong reason, and an auditor could not tell a revocation from a rotation. So the record
//! carries a SECOND counter, `mcp_re_state_revision`, which advances on every publication
//! whatever the status. Overloading `generation` to carry both would make one number answer
//! two questions, and the answer to one of them would be wrong.

mod currentness;
mod verified;

pub use currentness::AdmissionRecordRefusal;
pub use currentness::AdmissionStateCurrentness;
pub use verified::verify_admission_state_record;
pub use verified::CurrentAdmissionState;

use mcp_re_core::b64url_encode;
use serde::Deserialize;
use serde::Serialize;

use crate::admission::AdmissionStatus;
use crate::error::HttpProfileError;

/// The JWS `typ` of an authoritative admission RECORD.
///
/// Distinct from [`crate::admission::ADMISSION_TYP`], so the authority's statement about
/// what it currently holds can never be presented as a caller's assertion, nor the reverse.
/// Both are signed by the same key; the `typ` is what keeps them different artifacts.
pub const ADMISSION_STATE_TYP: &str = "mcp-re-admission-state+jws";

/// The JWS `alg` — EdDSA, as everywhere in this profile.
pub const ADMISSION_STATE_ALG: &str = "EdDSA";

/// Ed25519 signatures are 64 raw octets.
///
/// Checked on the ISSUING side, because the signer is an external seam: a KMS or HSM that
/// returned a DER-wrapped or truncated signature would otherwise be published as a record
/// no verifier can read, and the symptom would be a fleet-wide admission outage rather than
/// the signer misconfiguration it is. The delegation credential's issuer already holds this
/// line; the admission artifacts did not.
const ED25519_SIGNATURE_LEN: usize = 64;

/// The JWS protected header of an authoritative admission record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdmissionStateHeader {
    pub(crate) typ: String,
    pub(crate) alg: String,
    /// The admission authority's root key id — resolved through the trust seam, never
    /// trusted because it is named here.
    pub(crate) kid: String,
}

/// What the admission authority currently holds for one workload, as signed claims.
///
/// Every coordinate a substitution could change is inside the signature: whose state this
/// is, which generation and status, which publication of it, when it was issued, how long
/// its issuer intends it to be read, and who signed it. The artifact's own identity is the
/// `typ` in the header, which the signature also covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionStateClaims {
    /// The issuing authority's name. Audit provenance; the KEY is what authenticates.
    pub iss: String,
    /// Issuance time — the coordinate the deployment's currentness budget is measured from,
    /// which is why a restored old record expires however valid its signature.
    pub iat: i64,
    /// Not before.
    pub nbf: i64,
    /// The issuer's own validity bound. A FLOOR on how long the record may be read, never a
    /// way to exceed the deployment's budget.
    pub exp: i64,
    /// The MCP-RE evidence profile this record belongs to.
    pub mcp_re_profile: String,
    /// The workload this record is ABOUT. Compared against the id the record was looked up
    /// under, so a record filed under another workload's key is refused rather than
    /// answering for it.
    pub mcp_re_admission_id: String,
    /// The admitted configuration epoch — the anti-rollback counter a call's binding is
    /// compared against. Not advanced by a revocation.
    pub mcp_re_admission_generation: u64,
    /// The authority's current status for this workload.
    pub mcp_re_admission_status: AdmissionStatus,
    /// The publication sequence, advancing on EVERY publication including a revocation.
    /// See the module docs for why this is not the generation.
    pub mcp_re_state_revision: u64,
    /// The issuer root `key_id` — equals the header `kid`.
    pub issuer_kid: String,
}

/// Publish-side: sign an authoritative admission record as a compact JWS.
///
/// `sign_root` is the same external-signer seam the admission assertion and the delegation
/// credential use — the authority's private key never enters this crate, and publication is
/// control-plane work rather than anything on a request path.
pub fn issue_admission_state_record(
    claims: &AdmissionStateClaims,
    sign_root: impl FnOnce(&[u8]) -> Result<Vec<u8>, HttpProfileError>,
) -> Result<String, HttpProfileError> {
    let header = AdmissionStateHeader {
        typ: ADMISSION_STATE_TYP.to_owned(),
        alg: ADMISSION_STATE_ALG.to_owned(),
        kid: claims.issuer_kid.clone(),
    };
    let h = b64url_encode(
        &serde_json::to_vec(&header)
            .map_err(|_| HttpProfileError::MalformedEvidence("admission state header"))?,
    );
    let p = b64url_encode(
        &serde_json::to_vec(claims)
            .map_err(|_| HttpProfileError::MalformedEvidence("admission state claims"))?,
    );
    let signing_input = format!("{h}.{p}");
    let sig = sign_root(signing_input.as_bytes())?;
    if sig.len() != ED25519_SIGNATURE_LEN {
        return Err(HttpProfileError::MalformedEvidence(
            "admission state signature length",
        ));
    }
    Ok(format!("{h}.{p}.{}", b64url_encode(&sig)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_record_typ_is_not_the_assertion_typ() {
        // The two artifacts are signed by the same key. If they shared a `typ`, an
        // authority's statement about what it holds could be presented as a caller's
        // assertion about what it was granted, and the reverse.
        assert_ne!(ADMISSION_STATE_TYP, crate::admission::ADMISSION_TYP);
    }

    #[test]
    fn a_signer_returning_a_non_ed25519_signature_is_refused_at_issuance() {
        // The external signer's contract. A KMS returning DER would otherwise publish
        // bytes no verifier can read, and the symptom would be a fleet-wide admission
        // outage rather than the signer misconfiguration it is.
        let claims = crate::authoritative_admission::record::test_support::claims("wl", 7, 1);
        for wrong in [0usize, 63, 65, 71] {
            let err = issue_admission_state_record(&claims, |_| Ok(vec![0u8; wrong]))
                .err()
                .unwrap_or_else(|| panic!("a {wrong}-byte signature must be refused"));
            assert!(matches!(
                err,
                HttpProfileError::MalformedEvidence("admission state signature length")
            ));
        }
        assert!(issue_admission_state_record(&claims, |_| Ok(vec![0u8; 64])).is_ok());
    }

    #[test]
    fn the_issued_record_is_three_non_empty_compact_segments() {
        let claims = crate::authoritative_admission::record::test_support::claims("wl", 7, 1);
        let jws = issue_admission_state_record(&claims, |_| Ok(vec![0u8; 64])).expect("issued");
        let segments: Vec<&str> = jws.split('.').collect();
        assert_eq!(segments.len(), 3);
        assert!(segments.iter().all(|s| !s.is_empty()));
    }
}

/// Fixtures shared by this module's own batteries and by the proxy's.
///
/// Compiled only under test. The point of naming it rather than duplicating it per file is
/// that a record built two ways is two chances to disagree about what a valid one looks
/// like — which is exactly the failure this artifact exists to prevent.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub(crate) const PROFILE: &str = "mcp-re-http-v1";
    pub(crate) const KID: &str = "authority/root/1";

    /// Claims issued at `iat = 1_000` with a 60-second window.
    pub(crate) fn claims(
        admission_id: &str,
        generation: u64,
        revision: u64,
    ) -> AdmissionStateClaims {
        AdmissionStateClaims {
            iss: "admission-authority".to_owned(),
            iat: 1_000,
            nbf: 1_000,
            exp: 1_060,
            mcp_re_profile: PROFILE.to_owned(),
            mcp_re_admission_id: admission_id.to_owned(),
            mcp_re_admission_generation: generation,
            mcp_re_admission_status: AdmissionStatus::Admitted,
            mcp_re_state_revision: revision,
            issuer_kid: KID.to_owned(),
        }
    }
}
