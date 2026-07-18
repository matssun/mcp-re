// SPDX-License-Identifier: Apache-2.0
//! Admission assertion + §7 admission-state binding (Layer 1 → Layer 4).
//!
//! #414 rev 2 §4.3/§5 defines authoritative admission state — a workload's
//! id, generation, admitted-state digest, status, validity, issuer — distributed
//! as a signed short-lived assertion with push-invalidation and a fail-closed
//! fallback. #415 rev 2 §7 binds a CALL to that admission evidence. This module is
//! both halves: the assertion (a compact JWS, issued from the trust-anchor
//! lifecycle exactly as the delegation credential is) and the evidence-block
//! binding, plus the Layer 4 currency check that decides whether the workload the
//! call came from is still admitted.
//!
//! **What "admitted" buys, and what it does not.** The assertion says an authority
//! admitted this workload at a generation, with a digest of the state it was
//! admitted in. It does NOT say the workload is admitted *now* — an assertion is a
//! snapshot, and a workload can be revoked between issuance and use. That gap is
//! the entire reason for the two-part design: the assertion proves *what an
//! authority said*, and the PEP's currency check proves *that it is still true* by
//! comparing the bound generation against the authoritative state it holds. A
//! system that trusted the assertion alone would admit a revoked workload for as
//! long as its assertion had not expired.
//!
//! **Freshness is a declared budget, not "not expired".** §5.2 frames it as N/P/TTL:
//! how stale an assertion may be (N), how fast a revocation must propagate (P), and
//! the assertion's own lifetime (TTL). The PEP enforces all three, and a deployment
//! that cannot reach the authoritative state falls back to a BOUNDED degraded mode
//! — serving within P on the last-known state — only if it explicitly opted in.
//! Silent indefinite fallback would turn push-invalidation into a suggestion.

use mcp_re_core::b64url_decode;
use mcp_re_core::b64url_encode;
use mcp_re_core::verify_ed25519_with;
use mcp_re_core::McpReError;
use mcp_re_core::VerificationKey;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;

use crate::block::BindingType;
use crate::delegation::Audience;
use crate::error::HttpProfileError;

/// The JWS `typ` of an admission assertion — distinct from the delegation
/// credential's, so one can never be presented for the other.
pub const ADMISSION_TYP: &str = "mcp-re-admission+jws";

/// The JWS `alg` — EdDSA, as everywhere in this profile.
pub const ADMISSION_ALG: &str = "EdDSA";

/// Admission status (§4.3). Only `Admitted` permits a call to proceed; the others
/// are distinct so a rejection can say WHY, and so a suspended workload (a
/// recoverable state) is not conflated with a revoked one (terminal).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionStatus {
    /// The workload is admitted and may act.
    #[serde(rename = "admitted")]
    Admitted,
    /// Temporarily suspended — recoverable, but not admitted right now.
    #[serde(rename = "suspended")]
    Suspended,
    /// Revoked — terminal.
    #[serde(rename = "revoked")]
    Revoked,
}

/// The JWS protected header of an admission assertion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionHeader {
    pub typ: String,
    pub alg: String,
    /// The issuer (admission authority) root key id — resolved through the trust
    /// seam, never trusted because it is named here.
    pub kid: String,
}

/// The claims of an admission assertion (§4.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionClaims {
    pub iss: String,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
    /// Ties to the audit issuance event; not a replay key.
    pub jti: String,
    /// Who may PROCESS this assertion.
    pub aud: Audience,
    /// The MCP-RE evidence profile this assertion is valid for.
    pub mcp_re_profile: String,
    /// The admitted workload's stable id.
    pub mcp_re_admission_id: String,
    /// The monotonic admission generation — the anti-rollback counter. A currency
    /// check compares the call's bound generation against the authoritative one;
    /// an older generation is stale even if the assertion has not expired.
    pub mcp_re_admission_generation: u64,
    /// `base64url(SHA-256(...))` over the state the workload was admitted in
    /// (config, image digest, posture — whatever the authority attests). Opaque
    /// here: this profile binds it, it does not interpret it.
    pub mcp_re_admitted_state_digest: String,
    /// Admission status at issuance.
    pub mcp_re_admission_status: AdmissionStatus,
    /// The issuer root `key_id` — equals the header `kid`.
    pub issuer_kid: String,
}

/// The commitment carried in the request evidence block (§7): the call declares
/// which admission it acts under. Consistent with the artifact-binding split — a
/// digest is the binding, never raw state.
///
/// `opaque-digest`: the digest is over the admitted-state digest the assertion
/// carries, so the binding is checkable against the assertion offline.
/// `reference-digest`: the digest is produced by an external admission authority
/// named by the reference fields, so the record stays verifiable independent of
/// that authority's live state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionBinding {
    pub binding_type: BindingType,
    /// The admitted workload id the call claims.
    pub admission_id: String,
    /// The generation the call was made under — the currency check's subject.
    pub generation: u64,
    pub digest_alg: String,
    /// `base64url(SHA-256(admitted_state_digest_bytes))` for the opaque form.
    pub digest_value: String,
    /// External authority namespace (reference form only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_id: Option<String>,
    /// The authority's decision handle (reference form only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_value: Option<String>,
}

impl AdmissionBinding {
    /// Build an opaque-digest binding committing to `assertion`'s admitted state
    /// at its generation. The digest is over the assertion's
    /// `mcp_re_admitted_state_digest` bytes, so a verifier holding the assertion
    /// recomputes and compares without contacting any authority.
    pub fn opaque_from(assertion: &AdmissionClaims) -> Self {
        AdmissionBinding {
            binding_type: BindingType::OpaqueDigest,
            admission_id: assertion.mcp_re_admission_id.clone(),
            generation: assertion.mcp_re_admission_generation,
            digest_alg: crate::ids::EVIDENCE_DIGEST_ALG.to_owned(),
            digest_value: b64url_encode(&Sha256::digest(
                assertion.mcp_re_admitted_state_digest.as_bytes(),
            )),
            authority_id: None,
            reference_value: None,
        }
    }

    /// The opaque digest this binding commits to, over `admitted_state_digest`.
    fn matches_state(&self, admitted_state_digest: &str) -> bool {
        self.binding_type == BindingType::OpaqueDigest
            && self.digest_alg == crate::ids::EVIDENCE_DIGEST_ALG
            && self.digest_value == b64url_encode(&Sha256::digest(admitted_state_digest.as_bytes()))
    }
}

/// The authoritative admission state a PEP holds for a workload (§4.3). Fed by
/// Layer 1 push-invalidation; how it is fed is out of scope here (the assertion
/// consumes whatever Layer 1 decides).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoritativeAdmission {
    /// The current generation. A call bound to an OLDER generation is stale.
    pub generation: u64,
    /// The current status. Only `Admitted` permits a call.
    pub status: AdmissionStatus,
}

/// The verifier-local admission freshness + fallback budget (§5.2).
#[derive(Debug, Clone, Copy)]
pub struct AdmissionPolicy {
    /// N — the maximum age (seconds) of an assertion the PEP will accept, beyond
    /// its own `exp`-based freshness. Bounds how stale an admitted-state snapshot
    /// may be even within its TTL.
    pub max_assertion_age: i64,
    /// Clock-skew tolerance on the assertion's `[nbf, exp]` window.
    pub max_clock_skew: i64,
    /// P — the bound (seconds) within which the PEP may serve on the LAST-KNOWN
    /// authoritative state when the live state is unreachable, IF degraded mode is
    /// enabled. Past P, an unreachable authority is fail-closed.
    pub degraded_propagation_bound: i64,
    /// Whether degraded mode is enabled at all. Default false: an unreachable
    /// authority fails closed immediately. Enabling it is an explicit deployment
    /// act, because it trades a bounded window of stale-admission risk for
    /// availability.
    pub allow_degraded_mode: bool,
}

impl Default for AdmissionPolicy {
    fn default() -> Self {
        AdmissionPolicy {
            max_assertion_age: 300,
            max_clock_skew: 30,
            degraded_propagation_bound: 0,
            allow_degraded_mode: false,
        }
    }
}

/// The verified outcome of an admission check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAdmission {
    pub admission_id: String,
    pub generation: u64,
    pub status: AdmissionStatus,
    /// True when the verdict was reached in degraded mode (authoritative state
    /// unreachable, within the P bound). An auditor can tell a live-confirmed
    /// admission from a degraded-mode one.
    pub degraded: bool,
}

/// Issue a signed admission assertion (compact JWS), signing with the authority
/// root via `sign_root` (the same external-signer seam the delegation credential
/// uses — the root key never enters this crate).
pub fn issue_admission_assertion(
    claims: &AdmissionClaims,
    sign_root: impl FnOnce(&[u8]) -> Result<Vec<u8>, HttpProfileError>,
) -> Result<String, HttpProfileError> {
    let header = AdmissionHeader {
        typ: ADMISSION_TYP.to_owned(),
        alg: ADMISSION_ALG.to_owned(),
        kid: claims.issuer_kid.clone(),
    };
    let h = b64url_encode(
        &serde_json::to_vec(&header).map_err(|_| HttpProfileError::MalformedEvidence("admission header"))?,
    );
    let p = b64url_encode(
        &serde_json::to_vec(claims).map_err(|_| HttpProfileError::MalformedEvidence("admission claims"))?,
    );
    let signing_input = format!("{h}.{p}");
    let sig = sign_root(signing_input.as_bytes())?;
    Ok(format!("{h}.{p}.{}", b64url_encode(&sig)))
}

fn split_compact(jws: &str) -> Result<(&str, &str, &str), HttpProfileError> {
    let mut it = jws.split('.');
    match (it.next(), it.next(), it.next(), it.next()) {
        (Some(h), Some(p), Some(s), None) if !h.is_empty() && !p.is_empty() && !s.is_empty() => {
            Ok((h, p, s))
        }
        _ => Err(HttpProfileError::MalformedEvidence("admission jws shape")),
    }
}

fn decode_json<T: for<'de> Deserialize<'de>>(seg: &str) -> Result<T, HttpProfileError> {
    let bytes = b64url_decode(seg).map_err(|_| HttpProfileError::MalformedEvidence("admission b64url"))?;
    serde_json::from_slice(&bytes).map_err(|_| HttpProfileError::MalformedEvidence("admission json"))
}

/// Verify an admission assertion's signature, shape, and freshness — WITHOUT the
/// currency check. This is "what the authority said and that it is well-formed";
/// [`check_admission`] adds "and it is still true".
///
/// `resolve_issuer` resolves the assertion's `issuer_kid` to the authority root
/// key through the trust seam (a kid never introduces trust). Fails closed on a
/// wrong `typ`/`alg`, an untrusted issuer, a bad signature, an assertion outside
/// `[nbf, exp]` (± skew), or one older than the policy's `max_assertion_age`.
pub fn verify_admission_assertion(
    compact_jws: &str,
    expected_profile: &str,
    verifier_audiences: &[&str],
    policy: &AdmissionPolicy,
    now: i64,
    resolve_issuer: impl Fn(&str) -> Option<VerificationKey>,
) -> Result<AdmissionClaims, HttpProfileError> {
    let (h_seg, p_seg, s_seg) = split_compact(compact_jws)?;
    let header: AdmissionHeader = decode_json(h_seg)?;
    if header.typ != ADMISSION_TYP || header.alg != ADMISSION_ALG {
        return Err(HttpProfileError::AdmissionAssertionInvalid);
    }
    let claims: AdmissionClaims = decode_json(p_seg)?;
    if header.kid != claims.issuer_kid {
        return Err(HttpProfileError::AdmissionAssertionInvalid);
    }

    // Issuer → trusted authority root (a kid never introduces trust).
    let root = resolve_issuer(&claims.issuer_kid).ok_or(HttpProfileError::AdmissionIssuerUntrusted)?;
    let signing_input = format!("{h_seg}.{p_seg}");
    verify_ed25519_with(
        signing_input.as_bytes(),
        &s_seg_to_b64url(s_seg)?,
        &root,
        McpReError::InvalidSignature,
    )
    .map_err(|_| HttpProfileError::AdmissionAssertionInvalid)?;

    if claims.mcp_re_profile != expected_profile {
        return Err(HttpProfileError::AdmissionAssertionInvalid);
    }
    if !verifier_audiences.iter().any(|a| claims.aud.contains(a)) {
        return Err(HttpProfileError::AdmissionAssertionInvalid);
    }

    // Freshness: within [nbf, exp] ± skew, AND not older than the declared budget
    // N (§5.2). The TTL alone is the issuer's choice; N is the verifier's own cap
    // on how stale a snapshot it will act on.
    let skew = policy.max_clock_skew;
    if claims.nbf - skew > now || claims.exp + skew <= now || claims.exp <= claims.nbf {
        return Err(HttpProfileError::AdmissionAssertionExpired);
    }
    if now - claims.iat > policy.max_assertion_age + skew {
        return Err(HttpProfileError::AdmissionAssertionExpired);
    }
    Ok(claims)
}

fn s_seg_to_b64url(s_seg: &str) -> Result<String, HttpProfileError> {
    // The signature segment is already base64url; decode/re-encode normalizes it
    // to the exact form the core verifier consumes and rejects a malformed one.
    let bytes = b64url_decode(s_seg).map_err(|_| HttpProfileError::AdmissionAssertionInvalid)?;
    Ok(b64url_encode(&bytes))
}

/// The full §7 admission check: verify the assertion, verify the call's binding
/// commits to it, then the CURRENCY check against the authoritative state.
///
/// `authoritative` is what the PEP holds for `binding.admission_id` right now (fed
/// by Layer 1). `None` means the authoritative state is unreachable — the
/// degraded-mode fork.
///
/// Fail-closed rules:
///   - the binding's `admission_id` must match the assertion;
///   - the binding must commit to the assertion's admitted-state digest;
///   - **currency**: the bound generation must equal the authoritative generation.
///     An OLDER bound generation is a call from a workload whose admission has been
///     superseded — stale, rejected, even though its assertion has not expired;
///   - status must be `Admitted` in BOTH the assertion and the authoritative
///     state; a workload revoked after issuance is refused;
///   - authoritative state unreachable → reject, UNLESS degraded mode is enabled
///     AND the assertion is within the P bound, in which case serve on the
///     assertion's own status and mark the verdict degraded.
#[allow(clippy::too_many_arguments)]
pub fn check_admission(
    binding: &AdmissionBinding,
    assertion_jws: &str,
    authoritative: Option<&AuthoritativeAdmission>,
    expected_profile: &str,
    verifier_audiences: &[&str],
    policy: &AdmissionPolicy,
    now: i64,
    resolve_issuer: impl Fn(&str) -> Option<VerificationKey>,
) -> Result<VerifiedAdmission, HttpProfileError> {
    let claims = verify_admission_assertion(
        assertion_jws,
        expected_profile,
        verifier_audiences,
        policy,
        now,
        resolve_issuer,
    )?;

    // The call's binding must describe THIS assertion: same workload, same
    // generation, and committing to the same admitted state.
    if binding.admission_id != claims.mcp_re_admission_id
        || binding.generation != claims.mcp_re_admission_generation
    {
        return Err(HttpProfileError::AdmissionBindingMismatch);
    }
    if !binding.matches_state(&claims.mcp_re_admitted_state_digest) {
        return Err(HttpProfileError::AdmissionBindingMismatch);
    }

    // The assertion itself must say admitted — a suspended/revoked snapshot never
    // permits a call, regardless of currency.
    if claims.mcp_re_admission_status != AdmissionStatus::Admitted {
        return Err(HttpProfileError::AdmissionNotCurrent);
    }

    match authoritative {
        Some(state) => {
            // Currency: the bound generation must be the current one. Older = the
            // workload's admission was superseded; the call is stale.
            if binding.generation != state.generation {
                return Err(HttpProfileError::AdmissionNotCurrent);
            }
            if state.status != AdmissionStatus::Admitted {
                return Err(HttpProfileError::AdmissionNotCurrent);
            }
            Ok(VerifiedAdmission {
                admission_id: claims.mcp_re_admission_id,
                generation: claims.mcp_re_admission_generation,
                status: AdmissionStatus::Admitted,
                degraded: false,
            })
        }
        None => {
            // Authoritative state unreachable. Fail closed unless the deployment
            // explicitly accepts a BOUNDED degraded window (§5.2 P).
            if !policy.allow_degraded_mode {
                return Err(HttpProfileError::AdmissionStateUnavailable);
            }
            if now - claims.iat > policy.degraded_propagation_bound + policy.max_clock_skew {
                // Past P: a revocation could have propagated by now and we would not
                // know. Stop serving on the stale snapshot.
                return Err(HttpProfileError::AdmissionStateUnavailable);
            }
            Ok(VerifiedAdmission {
                admission_id: claims.mcp_re_admission_id,
                generation: claims.mcp_re_admission_generation,
                status: AdmissionStatus::Admitted,
                degraded: true,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_re_core::SigningKey;

    const NOW: i64 = 1_700_000_100;
    const ISSUER_KID: &str = "admission-root-1";

    fn root() -> SigningKey {
        SigningKey::from_seed_bytes(&[44u8; 32])
    }

    fn claims(generation: u64, status: AdmissionStatus, iat: i64) -> AdmissionClaims {
        AdmissionClaims {
            iss: "did:example:admission".into(),
            iat,
            nbf: iat,
            exp: iat + 300,
            jti: format!("adm#{generation}"),
            aud: Audience::One("mcp.example.com".into()),
            mcp_re_profile: crate::ids::PROFILE_TAG.into(),
            mcp_re_admission_id: "workload-7".into(),
            mcp_re_admission_generation: generation,
            mcp_re_admitted_state_digest: b64url_encode(&Sha256::digest(b"admitted-state")),
            mcp_re_admission_status: status,
            issuer_kid: ISSUER_KID.into(),
        }
    }

    fn issue(c: &AdmissionClaims) -> String {
        issue_admission_assertion(c, |input| {
            b64url_decode(&root().sign(input)).map_err(|_| HttpProfileError::InvalidSignature)
        })
        .expect("issue")
    }

    fn resolver() -> impl Fn(&str) -> Option<VerificationKey> {
        |kid: &str| (kid == ISSUER_KID).then(|| root().public_key())
    }

    fn policy(degraded: bool, p: i64) -> AdmissionPolicy {
        AdmissionPolicy {
            allow_degraded_mode: degraded,
            degraded_propagation_bound: p,
            ..AdmissionPolicy::default()
        }
    }

    fn check(
        c: &AdmissionClaims,
        auth: Option<&AuthoritativeAdmission>,
        pol: &AdmissionPolicy,
    ) -> Result<VerifiedAdmission, HttpProfileError> {
        let jws = issue(c);
        let binding = AdmissionBinding::opaque_from(c);
        check_admission(
            &binding,
            &jws,
            auth,
            crate::ids::PROFILE_TAG,
            &["mcp.example.com"],
            pol,
            NOW,
            resolver(),
        )
    }

    #[test]
    fn a_current_admitted_workload_passes() {
        let c = claims(5, AdmissionStatus::Admitted, NOW - 10);
        let auth = AuthoritativeAdmission { generation: 5, status: AdmissionStatus::Admitted };
        let v = check(&c, Some(&auth), &AdmissionPolicy::default()).expect("current");
        assert_eq!(v.generation, 5);
        assert!(!v.degraded);
    }

    /// The load-bearing case: an assertion that is signed, fresh, and says
    /// "admitted" is STILL rejected when the authoritative generation has moved on.
    /// A snapshot is not currency.
    #[test]
    fn a_stale_generation_is_rejected_even_though_the_assertion_is_valid() {
        let c = claims(5, AdmissionStatus::Admitted, NOW - 10);
        // The assertion verifies on its own...
        verify_admission_assertion(
            &issue(&c),
            crate::ids::PROFILE_TAG,
            &["mcp.example.com"],
            &AdmissionPolicy::default(),
            NOW,
            resolver(),
        )
        .expect("the assertion itself is valid");
        // ...but the authority has advanced to generation 6.
        let auth = AuthoritativeAdmission { generation: 6, status: AdmissionStatus::Admitted };
        assert_eq!(
            check(&c, Some(&auth), &AdmissionPolicy::default()).unwrap_err(),
            HttpProfileError::AdmissionNotCurrent,
        );
    }

    #[test]
    fn a_workload_revoked_after_issuance_is_refused() {
        let c = claims(5, AdmissionStatus::Admitted, NOW - 10);
        let auth = AuthoritativeAdmission { generation: 5, status: AdmissionStatus::Revoked };
        assert_eq!(
            check(&c, Some(&auth), &AdmissionPolicy::default()).unwrap_err(),
            HttpProfileError::AdmissionNotCurrent,
        );
    }

    #[test]
    fn a_suspended_assertion_never_permits_a_call() {
        let c = claims(5, AdmissionStatus::Suspended, NOW - 10);
        let auth = AuthoritativeAdmission { generation: 5, status: AdmissionStatus::Admitted };
        assert_eq!(
            check(&c, Some(&auth), &AdmissionPolicy::default()).unwrap_err(),
            HttpProfileError::AdmissionNotCurrent,
        );
    }

    #[test]
    fn an_untrusted_issuer_is_rejected() {
        let mut c = claims(5, AdmissionStatus::Admitted, NOW - 10);
        c.issuer_kid = "rogue-authority".into();
        let jws = issue_admission_assertion(&c, |input| {
            b64url_decode(&root().sign(input)).map_err(|_| HttpProfileError::InvalidSignature)
        })
        .unwrap();
        let binding = AdmissionBinding::opaque_from(&c);
        assert_eq!(
            check_admission(
                &binding, &jws, None, crate::ids::PROFILE_TAG, &["mcp.example.com"],
                &AdmissionPolicy::default(), NOW, resolver(),
            )
            .unwrap_err(),
            HttpProfileError::AdmissionIssuerUntrusted,
        );
    }

    #[test]
    fn a_binding_committing_to_the_wrong_state_is_rejected() {
        let c = claims(5, AdmissionStatus::Admitted, NOW - 10);
        let jws = issue(&c);
        // A binding whose digest does not match the assertion's admitted state.
        let mut binding = AdmissionBinding::opaque_from(&c);
        binding.digest_value = b64url_encode(&Sha256::digest(b"different-state"));
        let auth = AuthoritativeAdmission { generation: 5, status: AdmissionStatus::Admitted };
        assert_eq!(
            check_admission(
                &binding, &jws, Some(&auth), crate::ids::PROFILE_TAG, &["mcp.example.com"],
                &AdmissionPolicy::default(), NOW, resolver(),
            )
            .unwrap_err(),
            HttpProfileError::AdmissionBindingMismatch,
        );
    }

    #[test]
    fn unreachable_state_fails_closed_by_default() {
        let c = claims(5, AdmissionStatus::Admitted, NOW - 10);
        assert_eq!(
            check(&c, None, &AdmissionPolicy::default()).unwrap_err(),
            HttpProfileError::AdmissionStateUnavailable,
        );
    }

    #[test]
    fn degraded_mode_serves_within_p_but_not_beyond() {
        // Within P: a recent assertion is served, marked degraded.
        let recent = claims(5, AdmissionStatus::Admitted, NOW - 20);
        let v = check(&recent, None, &policy(true, 60)).expect("within P");
        assert!(v.degraded, "the verdict records that it was reached degraded");

        // Beyond P: a revocation could have propagated; stop serving the snapshot.
        let old = claims(5, AdmissionStatus::Admitted, NOW - 200);
        assert_eq!(
            check(&old, None, &policy(true, 60)).unwrap_err(),
            HttpProfileError::AdmissionStateUnavailable,
        );
    }
}
