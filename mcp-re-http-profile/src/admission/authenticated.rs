// SPDX-License-Identifier: Apache-2.0
//! The first half of the §7 admission check: WHO is asking, and under which admission.
//!
//! [`authenticate_admission`] verifies the authority's assertion, equates it with the
//! verifier-resolved presenter, and equates the call's binding with it. Its product,
//! [`AuthenticatedAdmission`], is the only thing [`super::check_admission`] consumes, so the
//! currency comparison — and the authoritative lookup that feeds it — cannot be reached with
//! an identity nobody authenticated.
//!
//! That ordering is the point of the split. A lookup keyed on `binding.admission_id` before
//! the assertion is verified is a store round trip on a string the caller chose, and an
//! outcome the caller can read: absent and forged-but-present are different answers to a
//! request that never proved it names a workload this authority admitted. Here the lookup
//! key is a projection of the authenticated value, which is the only form it can take.

use crate::admission_policy::AdmissionPolicy;
use crate::error::HttpProfileError;
use mcp_re_core::VerificationKey;

use super::AdmissionBinding;
use super::AdmissionStatus;
#[cfg(feature = "verify")]
use verus_builtin_macros::{verus_spec, verus_verify};
#[cfg(feature = "verify")]
#[allow(unused_imports)]
use vstd::prelude::*;

/// An admission assertion that was issued by the configured authority, to THIS presenter,
/// and that the call's own binding describes.
///
/// # Why the fields are `pub`
///
/// The same trade, measured the same way, as [`VerifiedAdmission`](super::VerifiedAdmission):
/// the §7 contracts of [`authenticate_admission`] and [`super::check_admission`] are stated
/// over these fields, Verus refuses a public function whose `ensures` names a field it
/// treats as opaque, and an opaque type's postconditions are unstatable. A proved
/// postcondition outranks a seal.
///
/// What closes construction anyway is `#[non_exhaustive]`, which binds the consumers that
/// exist — every one is in `mcp-re-proxy`, where a struct literal is refused outright — and
/// the only producer is [`authenticate_admission`]. A consumer reads the lookup key through
/// [`admission_id`](Self::admission_id).
///
/// Not `Clone`: one authentication buys one currency decision.
#[cfg_attr(feature = "verify", verus_verify)]
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuthenticatedAdmission {
    pub admission_id: String,
    pub generation: u64,
    pub admitted_actor: String,
    /// When the authority issued the assertion; the degraded arm's freshness term.
    pub iat: i64,
}

impl AuthenticatedAdmission {
    /// The workload the call acts under, as the authority's assertion states it and the
    /// binding agrees. The key under which the authoritative record is looked up.
    #[must_use]
    pub fn admission_id(&self) -> &str {
        &self.admission_id
    }
}

/// Authenticate the assertion and bind it to the presenter and to the call's binding.
///
/// Fail-closed rules, in order:
///   - the assertion verifies against the configured authority ([`super::verify_admission_assertion`]);
///   - **presenter**: the assertion was issued to the actor the verifier resolved;
///   - the binding's `admission_id`/`generation` equal the assertion's, and the binding
///     commits to the assertion's admitted-state digest;
///   - the assertion itself states `Admitted`.
// ADR-MCPRE-059 §7. Each clause is a rule the prose above states and that no test can
// establish for all inputs:
//
//   * a successful authentication implies the call's binding names the workload and the
//     generation the value carries — so the value a consumer looks up and compares is
//     the one the call was bound to, and cannot describe a different call;
//   * the admitted actor IS the presenter, so an assertion describing some admitted
//     workload cannot authorize a different caller merely because that workload is
//     admissible. Stated over the product rather than left to the body, because the
//     comparison below is the whole difference between "this caller is admitted" and "an
//     admitted workload exists somewhere".
#[allow(clippy::too_many_arguments)]
#[cfg_attr(feature = "verify", verus_spec(out =>
    ensures
        out matches Ok(authenticated) ==> {
            &&& authenticated.admission_id@ == binding.admission_id@
            &&& authenticated.generation == binding.generation
            &&& authenticated.admitted_actor@ == presenter_actor_id@
        },
))]
pub fn authenticate_admission(
    binding: &AdmissionBinding,
    assertion_jws: &str,
    presenter_actor_id: &str,
    expected_profile: &str,
    verifier_audiences: &[&str],
    policy: &AdmissionPolicy,
    now: i64,
    resolve_issuer: impl Fn(&str) -> Option<VerificationKey>,
) -> Result<AuthenticatedAdmission, HttpProfileError> {
    let claims = super::verify_admission_assertion(
        assertion_jws,
        expected_profile,
        verifier_audiences,
        policy,
        now,
        resolve_issuer,
    )?;

    // `presenter_actor_id` is the actor the verifier RESOLVED from the request signature —
    // never anything the request asserts — so a borrowed assertion names a different actor
    // and is refused.
    let presenter = presenter_actor_id.to_owned();
    if claims.mcp_re_admitted_actor != presenter {
        return Err(HttpProfileError::AdmissionBindingMismatch);
    }

    // One condition because there is one refusal — a binding that names another workload
    // and one that commits to another state are the same fact to a caller, and splitting
    // them would promise a distinction the error type does not make.
    if binding.admission_id != claims.mcp_re_admission_id
        || binding.generation != claims.mcp_re_admission_generation
        || !binding.matches_state(&claims.mcp_re_admitted_state_digest)
    {
        return Err(HttpProfileError::AdmissionBindingMismatch);
    }

    // A suspended/revoked snapshot never permits a call, regardless of currency.
    if claims.mcp_re_admission_status != AdmissionStatus::Admitted {
        return Err(HttpProfileError::AdmissionNotCurrent);
    }

    Ok(AuthenticatedAdmission {
        admission_id: claims.mcp_re_admission_id,
        generation: claims.mcp_re_admission_generation,
        admitted_actor: claims.mcp_re_admitted_actor,
        iat: claims.iat,
    })
}

#[cfg(test)]
mod tests {
    use super::super::issue_admission_assertion;
    use super::super::AdmissionClaims;
    use super::*;
    use crate::delegation::Audience;
    use mcp_re_core::b64url_decode;
    use mcp_re_core::SigningKey;

    const NOW: i64 = 1_700_000_100;
    const KID: &str = "admission-root-1";
    const ACTOR: &str = "client:example.com:did:example:host-a:client-key-1";

    fn root() -> SigningKey {
        SigningKey::from_seed_bytes(&[44u8; 32])
    }

    fn claims() -> AdmissionClaims {
        AdmissionClaims {
            iss: "did:example:admission".into(),
            iat: NOW - 10,
            nbf: NOW - 10,
            exp: NOW + 290,
            jti: "adm#5".into(),
            aud: Audience::One("mcp.example.com".into()),
            mcp_re_profile: crate::ids::PROFILE_TAG.into(),
            mcp_re_admission_id: "workload-7".into(),
            mcp_re_admitted_actor: ACTOR.into(),
            mcp_re_admission_generation: 5,
            mcp_re_admitted_state_digest: mcp_re_core::b64url_encode(b"state"),
            mcp_re_admission_status: AdmissionStatus::Admitted,
            issuer_kid: KID.into(),
        }
    }

    fn authenticate(
        c: &AdmissionClaims,
        signer: &SigningKey,
        presenter: &str,
    ) -> Result<AuthenticatedAdmission, HttpProfileError> {
        let jws = issue_admission_assertion(c, |input| {
            b64url_decode(&signer.sign(input)).map_err(|_| HttpProfileError::InvalidSignature)
        })
        .expect("issue");
        let authority = root().public_key();
        authenticate_admission(
            &AdmissionBinding::opaque_from(c),
            &jws,
            presenter,
            crate::ids::PROFILE_TAG,
            &["mcp.example.com"],
            &AdmissionPolicy::default(),
            NOW,
            move |kid: &str| (kid == KID).then(|| authority.clone()),
        )
    }

    /// The lookup key an enforcement point reads is the workload the authority's assertion
    /// names and the call's binding agrees with — and the value carries the presenter it
    /// was issued to, so nothing downstream restates either.
    #[test]
    fn an_authenticated_admission_names_the_workload_and_actor_the_call_bound() {
        let authenticated = authenticate(&claims(), &root(), ACTOR).expect("authenticates");
        assert_eq!(authenticated.admission_id(), "workload-7");
        assert_eq!(authenticated.generation, 5);
        assert_eq!(authenticated.admitted_actor, ACTOR);
    }

    /// An assertion the configured authority did not sign yields no value at all, so no
    /// store lookup can be keyed on the workload id it claims.
    #[test]
    fn an_assertion_the_authority_did_not_sign_authenticates_nothing() {
        let forger = SigningKey::from_seed_bytes(&[45u8; 32]);
        assert_eq!(
            authenticate(&claims(), &forger, ACTOR).unwrap_err(),
            HttpProfileError::AdmissionAssertionInvalid,
        );
    }

    /// The presenter comparison belongs to authentication: a borrowed assertion never
    /// becomes an authenticated value, however genuine it is.
    #[test]
    fn a_borrowed_assertion_authenticates_nothing() {
        assert_eq!(
            authenticate(
                &claims(),
                &root(),
                "client:example.com:did:example:host-b:k2"
            )
            .unwrap_err(),
            HttpProfileError::AdmissionBindingMismatch,
        );
    }
}
