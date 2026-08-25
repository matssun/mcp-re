// SPDX-License-Identifier: Apache-2.0
//! Authenticating a decision — what an authority actually stated, and nothing about the
//! request in hand.
//!
//! Relevance is the adapter's question. Keeping the two apart is what lets each be a
//! separately statable property: this module answers *is this a decision a trusted authority
//! issued, for this profile and this enforcement point, still valid* — exactly the division
//! [`crate::admission::verify_admission_assertion`] draws against `check_admission`.

use mcp_re_core::b64url_decode;
use mcp_re_core::verify_ed25519_with;
use mcp_re_core::McpReError;
use mcp_re_core::VerificationKey;
use serde::Deserialize;

use super::claims::PdpDecisionClaims;
use super::claims::PdpDecisionHeader;
use super::claims::PDP_DECISION_ALG;
use super::claims::PDP_DECISION_TYP;

/// Why a decision is not usable evidence.
///
/// Its own algebra rather than a widening of [`HttpProfileError`]: these are facts about a
/// decision document, and every one of them is a different thing for an operator to do.
/// Flattening them onto one "invalid" is how an untrusted issuer during a rollout reads as a
/// forged signature. The adapter renders them onto the frozen `mcp-re.authorization_*`
/// tokens, which is where the wire vocabulary is owned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PdpDecisionRefusal {
    /// The document is not a well-formed decision. Carries WHICH part failed, because
    /// "malformed" alone sends an operator to read bytes by hand.
    Malformed(&'static str),
    /// The `issuer_kid` does not resolve to an authority this deployment trusts.
    IssuerUntrusted,
    /// The signature did not verify under the resolved authority root.
    SignatureInvalid,
    /// The decision was issued for a different MCP-RE evidence profile.
    ProfileMismatch,
    /// The decision was issued for an enforcement point that is not this one.
    AudienceMismatch,
    /// `now` is outside `[nbf, exp]` (± skew), or the window is degenerate.
    Expired,
    /// The decision is older than this deployment's cap, even though the issuer's own
    /// `exp` has not passed. A separate fact from [`Expired`](Self::Expired): the issuer
    /// chose the lifetime, and this is the verifier declining it.
    Stale,
    /// The decision claims to have been taken in the future. Refused rather than floored
    /// at age zero, which would pass the staleness cap it exists to enforce.
    IssuedInTheFuture,
}

/// What a verifier will accept about a decision's own validity, before relevance is asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PdpDecisionFreshness {
    /// The widest clock disagreement this deployment tolerates.
    pub max_clock_skew: i64,
    /// The verifier's own cap on how old a decision it will act on, independent of the
    /// issuer's chosen `exp`. A long-lived decision is the issuer's choice; how long this
    /// enforcement point is willing to act on one is not.
    pub max_decision_age: i64,
}

/// Verify a decision's signature, shape and freshness — and nothing about the request.
///
/// `resolve_issuer` resolves the decision's `issuer_kid` to the authority root key through
/// the trust seam: a kid never introduces trust. Fails closed on a wrong `typ`/`alg`, a
/// header/claims kid disagreement, an untrusted issuer, a bad signature, the wrong profile,
/// an audience this verifier is not in, a decision outside `[nbf, exp]` (± skew), one issued
/// in the future, or one older than the deployment's cap.
///
/// A `Deny` decision verifies successfully. It is a valid statement by the authority, and
/// turning it into a refusal is the adapter's job — a verifier that refused here could not
/// distinguish *the authority denied* from *the evidence was unusable*.
pub fn verify_authorization_decision(
    compact_jws: &str,
    expected_profile: &str,
    verifier_audiences: &[&str],
    freshness: &PdpDecisionFreshness,
    now: i64,
    resolve_issuer: impl Fn(&str) -> Option<VerificationKey>,
) -> Result<PdpDecisionClaims, PdpDecisionRefusal> {
    let (h_seg, p_seg, s_seg) = split_compact(compact_jws)?;
    let header: PdpDecisionHeader = decode_json(h_seg)?;
    if header.typ != PDP_DECISION_TYP || header.alg != PDP_DECISION_ALG {
        return Err(PdpDecisionRefusal::Malformed("typ/alg"));
    }
    let claims: PdpDecisionClaims = decode_json(p_seg)?;
    if header.kid != claims.issuer_kid {
        return Err(PdpDecisionRefusal::Malformed(
            "header kid disagrees with claims",
        ));
    }

    // Issuer -> trusted authority root. A kid never introduces trust.
    let root = resolve_issuer(&claims.issuer_kid).ok_or(PdpDecisionRefusal::IssuerUntrusted)?;
    let signing_input = format!("{h_seg}.{p_seg}");
    verify_ed25519_with(
        signing_input.as_bytes(),
        &s_seg_to_b64url(s_seg)?,
        &root,
        McpReError::InvalidSignature,
    )
    .map_err(|_| PdpDecisionRefusal::SignatureInvalid)?;

    if claims.mcp_re_profile != expected_profile {
        return Err(PdpDecisionRefusal::ProfileMismatch);
    }
    if !verifier_audiences.iter().any(|a| claims.aud.contains(a)) {
        return Err(PdpDecisionRefusal::AudienceMismatch);
    }

    // SATURATING throughout, matching the primary freshness gate. These operands come
    // straight out of a JWS payload, so `now - claims.iat` with an extreme `iat` wraps in a
    // release build — silently passing the staleness cap the expression exists to enforce —
    // and panics on the serving path in any build with overflow checks.
    let skew = freshness.max_clock_skew;
    if claims.nbf.saturating_sub(skew) > now
        || claims.exp.saturating_add(skew) <= now
        || claims.exp <= claims.nbf
    {
        return Err(PdpDecisionRefusal::Expired);
    }
    // A decision issued in the future is refused outright rather than floored at age zero:
    // `iat` is an independent claim from `[nbf, exp]`, and the age computation below is
    // `now - iat` under saturation, so a future issuance would pass the cap it exists to
    // enforce.
    if claims.iat.saturating_sub(skew) > now {
        return Err(PdpDecisionRefusal::IssuedInTheFuture);
    }
    if now.saturating_sub(claims.iat) > freshness.max_decision_age.saturating_add(skew) {
        return Err(PdpDecisionRefusal::Stale);
    }
    Ok(claims)
}

fn split_compact(jws: &str) -> Result<(&str, &str, &str), PdpDecisionRefusal> {
    let mut it = jws.split('.');
    match (it.next(), it.next(), it.next(), it.next()) {
        (Some(h), Some(p), Some(s), None) if !h.is_empty() && !p.is_empty() && !s.is_empty() => {
            Ok((h, p, s))
        }
        _ => Err(PdpDecisionRefusal::Malformed("compact jws shape")),
    }
}

fn decode_json<T: for<'de> Deserialize<'de>>(seg: &str) -> Result<T, PdpDecisionRefusal> {
    let bytes = b64url_decode(seg).map_err(|_| PdpDecisionRefusal::Malformed("base64url"))?;
    serde_json::from_slice(&bytes).map_err(|_| PdpDecisionRefusal::Malformed("json"))
}

/// The signature segment, validated as base64url and handed on in the form the core verifier
/// expects.
fn s_seg_to_b64url(s_seg: &str) -> Result<String, PdpDecisionRefusal> {
    b64url_decode(s_seg).map_err(|_| PdpDecisionRefusal::Malformed("signature segment"))?;
    Ok(s_seg.to_owned())
}

#[cfg(test)]
mod tests {
    use super::verify_authorization_decision;
    use super::PdpDecisionFreshness;
    use super::PdpDecisionRefusal;
    use crate::delegation::Audience;
    use crate::pdp_decision::claims::DecidedActor;
    use crate::pdp_decision::claims::PdpDecisionClaims;
    use crate::pdp_decision::claims::PdpDecisionHeader;
    use crate::pdp_decision::claims::PdpDecisionOutcome;
    use crate::pdp_decision::claims::PDP_DECISION_ALG;
    use crate::pdp_decision::claims::PDP_DECISION_TYP;
    use crate::pdp_decision::issue::issue_authorization_decision;
    use mcp_re_core::b64url_decode;
    use mcp_re_core::b64url_encode;
    use mcp_re_core::SigningKey;
    use mcp_re_core::VerificationKey;

    const KID: &str = "pdp-root-1";
    const AUD: &str = "verifier-1";
    const PROFILE: &str = "mcp-re-http-v1";
    const NOW: i64 = 1_700_000_100;

    fn authority() -> SigningKey {
        SigningKey::from_seed_bytes(&[91u8; 32])
    }

    fn other_authority() -> SigningKey {
        SigningKey::from_seed_bytes(&[92u8; 32])
    }

    fn resolver() -> impl Fn(&str) -> Option<VerificationKey> {
        |kid: &str| (kid == KID).then(|| authority().public_key())
    }

    fn freshness() -> PdpDecisionFreshness {
        PdpDecisionFreshness {
            max_clock_skew: 30,
            max_decision_age: 600,
        }
    }

    fn claims() -> PdpDecisionClaims {
        PdpDecisionClaims {
            iss: "did:example:pdp".into(),
            iat: NOW - 10,
            nbf: NOW - 10,
            exp: NOW + 300,
            jti: "decision-1".into(),
            aud: Audience::One(AUD.into()),
            mcp_re_profile: PROFILE.into(),
            mcp_re_decided_actor: DecidedActor::Principal {
                trust_domain: "example.com".into(),
                subject: "did:example:a".into(),
            },
            mcp_re_decided_operation: "tools/call".into(),
            mcp_re_decided_target: Some("read".into()),
            mcp_re_decision: PdpDecisionOutcome::Permit,
            mcp_re_policy_version: "2026-08-01".into(),
            issuer_kid: KID.into(),
        }
    }

    fn issue_with(key: &SigningKey, c: &PdpDecisionClaims) -> String {
        issue_authorization_decision(c, |input| {
            b64url_decode(&key.sign(input))
                .map_err(|_| crate::error::HttpProfileError::MalformedEvidence("test signature"))
        })
        .expect("issues")
    }

    fn verify(jws: &str) -> Result<PdpDecisionClaims, PdpDecisionRefusal> {
        verify_authorization_decision(jws, PROFILE, &[AUD], &freshness(), NOW, resolver())
    }

    /// A compact JWS with a chosen header, signed by the genuine authority. Lets a control
    /// vary the header alone, which `issue_authorization_decision` never will.
    fn issue_with_header(typ: &str, alg: &str, c: &PdpDecisionClaims) -> String {
        let header = PdpDecisionHeader {
            typ: typ.to_owned(),
            alg: alg.to_owned(),
            kid: c.issuer_kid.clone(),
        };
        let h = b64url_encode(&serde_json::to_vec(&header).expect("header"));
        let p = b64url_encode(&serde_json::to_vec(c).expect("claims"));
        let sig = b64url_decode(&authority().sign(format!("{h}.{p}").as_bytes())).expect("sig");
        format!("{h}.{p}.{}", b64url_encode(&sig))
    }

    #[test]
    fn a_genuine_decision_round_trips() {
        let got = verify(&issue_with(&authority(), &claims())).expect("verifies");
        assert_eq!(got, claims());
    }

    #[test]
    fn an_untrusted_issuer_is_named_as_one_not_as_a_bad_signature() {
        // The distinction that matters during a rollout: a decision genuinely signed by an
        // authority this deployment has not been told about is not a forgery, and sending an
        // operator to hunt for one is the cost of flattening the two.
        let mut c = claims();
        c.issuer_kid = "some-other-root".into();
        assert_eq!(
            verify(&issue_with(&authority(), &c)),
            Err(PdpDecisionRefusal::IssuerUntrusted)
        );
    }

    #[test]
    fn a_decision_signed_by_the_wrong_key_under_a_trusted_kid_fails_the_signature() {
        assert_eq!(
            verify(&issue_with(&other_authority(), &claims())),
            Err(PdpDecisionRefusal::SignatureInvalid)
        );
    }

    #[test]
    fn a_decision_for_another_enforcement_point_is_refused() {
        let mut c = claims();
        c.aud = Audience::One("verifier-2".into());
        assert_eq!(
            verify(&issue_with(&authority(), &c)),
            Err(PdpDecisionRefusal::AudienceMismatch)
        );
    }

    #[test]
    fn a_decision_for_another_profile_is_refused() {
        let mut c = claims();
        c.mcp_re_profile = "some-other-profile".into();
        assert_eq!(
            verify(&issue_with(&authority(), &c)),
            Err(PdpDecisionRefusal::ProfileMismatch)
        );
    }

    #[test]
    fn expiry_and_staleness_are_different_facts() {
        // The issuer chose the lifetime; the verifier declines to act on an old decision
        // even inside it. Reporting both as "expired" hides which one an operator must fix.
        let mut expired = claims();
        expired.exp = NOW - 100;
        assert_eq!(
            verify(&issue_with(&authority(), &expired)),
            Err(PdpDecisionRefusal::Expired)
        );

        let mut stale = claims();
        stale.iat = NOW - 10_000;
        stale.nbf = NOW - 10_000;
        stale.exp = NOW + 10_000;
        assert_eq!(
            verify(&issue_with(&authority(), &stale)),
            Err(PdpDecisionRefusal::Stale)
        );
    }

    #[test]
    fn a_decision_issued_in_the_future_is_refused_not_floored_to_age_zero() {
        // Flooring would pass the staleness cap the computation exists to enforce, because
        // the age is `now - iat` under saturation.
        let mut c = claims();
        c.iat = NOW + 10_000;
        c.nbf = NOW - 10;
        c.exp = NOW + 20_000;
        assert_eq!(
            verify(&issue_with(&authority(), &c)),
            Err(PdpDecisionRefusal::IssuedInTheFuture)
        );
    }

    #[test]
    fn an_extreme_iat_does_not_wrap_the_age_computation() {
        let mut c = claims();
        c.iat = i64::MIN;
        c.nbf = NOW - 10;
        c.exp = NOW + 300;
        assert_eq!(
            verify(&issue_with(&authority(), &c)),
            Err(PdpDecisionRefusal::Stale)
        );
    }

    #[test]
    fn another_artifacts_typ_cannot_be_presented_as_a_decision() {
        // The delegation credential and the admission assertion are compact JWSs signed by
        // roots a deployment may well also trust. `typ` is what stops one being presented
        // for another.
        assert_eq!(
            verify(&issue_with_header(
                "mcp-re-admission+jws",
                PDP_DECISION_ALG,
                &claims()
            )),
            Err(PdpDecisionRefusal::Malformed("typ/alg"))
        );
        assert_eq!(
            verify(&issue_with_header(PDP_DECISION_TYP, "none", &claims())),
            Err(PdpDecisionRefusal::Malformed("typ/alg"))
        );
    }

    #[test]
    fn a_header_naming_a_different_kid_than_the_claims_is_refused() {
        let c = claims();
        let header = PdpDecisionHeader {
            typ: PDP_DECISION_TYP.into(),
            alg: PDP_DECISION_ALG.into(),
            kid: "another-root".into(),
        };
        let h = b64url_encode(&serde_json::to_vec(&header).expect("header"));
        let p = b64url_encode(&serde_json::to_vec(&c).expect("claims"));
        let sig = b64url_decode(&authority().sign(format!("{h}.{p}").as_bytes())).expect("sig");
        assert_eq!(
            verify(&format!("{h}.{p}.{}", b64url_encode(&sig))),
            Err(PdpDecisionRefusal::Malformed(
                "header kid disagrees with claims"
            ))
        );
    }

    #[test]
    fn a_deny_decision_verifies_and_is_returned_as_one() {
        // Verification answers WHAT THE AUTHORITY SAID. Refusing here would make "the
        // authority denied" indistinguishable from "the evidence was unusable".
        let mut c = claims();
        c.mcp_re_decision = PdpDecisionOutcome::Deny;
        let got = verify(&issue_with(&authority(), &c)).expect("a deny is valid evidence");
        assert_eq!(got.mcp_re_decision, PdpDecisionOutcome::Deny);
    }

    #[test]
    fn a_malformed_document_says_which_part_failed() {
        assert_eq!(
            verify("not.a.jws"),
            Err(PdpDecisionRefusal::Malformed("base64url"))
        );
        assert_eq!(
            verify("only-two.parts"),
            Err(PdpDecisionRefusal::Malformed("compact jws shape"))
        );
    }
}
