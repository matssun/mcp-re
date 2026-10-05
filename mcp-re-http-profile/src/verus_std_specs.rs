//! Verus specifications for the items the freshness proof calls but does not check.
//!
//! ADR-MCPRE-059 Phase 2. Compiled only under `--features verify`; no production build
//! contains this module.
//!
//! Everything here is trusted, and every entry is registered in
//! `verification/policy/assumptions.toml`. Two kinds live here: `std` arithmetic vstd does
//! not yet specify for signed integers, and the policy accessors, which are field reads
//! the verifier is told to treat as an unknown-but-fixed value per policy object.

use crate::admission::{
    AdmissionBinding, AdmissionClaims, AdmissionStatus, AdmissionVerdict, VerifiedAdmission,
};
use crate::admission_policy::AdmissionPolicy;
use crate::authoritative_admission::AuthoritativeAdmission;
use crate::block::BindingType;
use crate::delegation::Audience;
use crate::error::HttpProfileError;
use crate::policy::{ProfileAlgorithm, VerifierPolicy};
use crate::sigbase::SignatureParams;
use verus_builtin_macros::verus;
use vstd::prelude::*;

verus! {

/// `i64::saturating_sub` — clamps at `i64::MIN` instead of wrapping.
///
/// Trusted against the standard library. vstd specifies the unsigned forms only. The
/// clamp matters to the freshness theorem: it is what makes `created - skew` safe to
/// compare against `now` at the extremes of the range.
pub assume_specification[ i64::saturating_sub ](x: i64, y: i64) -> (result: i64)
    ensures
        result == if x - y < i64::MIN { i64::MIN as int } else if x - y > i64::MAX { i64::MAX as int } else { x - y },
;

/// `i64::saturating_add` — clamps at `i64::MAX` instead of wrapping.
pub assume_specification[ i64::saturating_add ](x: i64, y: i64) -> (result: i64)
    ensures
        result == if x + y > i64::MAX { i64::MAX as int } else if x + y < i64::MIN { i64::MIN as int } else { x + y },
;

/// Makes `VerifierPolicy` nameable in a specification without verifying its
/// construction, its algorithm registry, or its transport policy. Opaque: no theorem here
/// reads a field, and none may — the accessors below are the only way in.
#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExVerifierPolicy(VerifierPolicy);

/// The signature parameters, TRANSPARENT: the freshness theorem is about the `created`
/// and `expires` the message declares, so the verifier must see those fields.
#[verifier::external_type_specification]
pub struct ExSignatureParams(SignatureParams);

/// The resolved algorithm, opaque. The freshness theorem says nothing about which
/// algorithm was accepted, only that admission implies a fresh window.
#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExProfileAlgorithm(ProfileAlgorithm);

/// The refusal taxonomy, TRANSPARENT: the proved function constructs refusals, and a
/// verifier that cannot see the variants cannot follow the paths that produce them.
#[verifier::external_type_specification]
pub struct ExHttpProfileError(HttpProfileError);

/// `Option::<String>::as_deref` — total, and its result is used only for equality tests
/// the theorem does not depend on.
pub assume_specification<T: core::ops::Deref>[ Option::<T>::as_deref ](o: &Option<T>) -> (result: Option<&<T as core::ops::Deref>::Target>)
;

/// The Ed25519 verification key, opaque. No theorem here says anything about a key; the
/// specification exists because the trust seam is an `impl Fn(&str) -> Option<Self>` and
/// the prover needs to name the closure's return type before it can model the parameter.
#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExVerificationKey(mcp_re_core::VerificationKey);

/// The admission datatypes the §7 currency theorem reasons over, all TRANSPARENT.
///
/// The theorem is entirely about how these values relate: the generation the call bound,
/// the generation the authority holds, and the status of each. A verifier that cannot see
/// those fields cannot state the property at all.
#[verifier::external_type_specification]
pub struct ExAdmissionStatus(AdmissionStatus);
#[verifier::external_type_specification]
pub struct ExBindingType(BindingType);
#[verifier::external_type_specification]
pub struct ExAudience(Audience);
#[verifier::external_type_specification]
pub struct ExAdmissionClaims(AdmissionClaims);
#[verifier::external_type_specification]
pub struct ExAdmissionBinding(AdmissionBinding);
#[verifier::external_type_specification]
pub struct ExAuthoritativeAdmission(AuthoritativeAdmission);
#[verifier::external_type_specification]
pub struct ExVerifiedAdmission(VerifiedAdmission);
/// The verdict, TRANSPARENT: THM-0005 states a different postcondition per arm, so opaque
/// would collapse them into one unknown value — the `degraded: bool` defect, one level up.
#[verifier::external_type_specification]
pub struct ExAdmissionVerdict(AdmissionVerdict);

/// `#[derive(PartialEq)]` on a fieldless enum is structural equality. Trusted against the
/// derive rather than against a hand-written impl: without it the currency check's
/// `status != Admitted` tests are opaque booleans and the theorem cannot see that the
/// paths returning `Ok` are the admitted ones.
pub assume_specification[ <AdmissionStatus as core::cmp::PartialEq>::eq ](
    x: &AdmissionStatus,
    y: &AdmissionStatus,
) -> (result: bool)
    ensures
        result == (x == y),
;

/// The admission freshness/fallback budget, TRANSPARENT: `allow_degraded_mode` is the
/// deployment opt-in the degraded clause of the theorem is stated in terms of.
#[verifier::external_type_specification]
pub struct ExAdmissionPolicy(AdmissionPolicy);

/// The tags are TRANSPARENT; the binding is OPAQUE (private representation) and is read
/// only through `artifact_type_of`/`binding_type_of`, which its two getters are specified by.
#[verifier::external_type_specification]
pub struct ExArtifactType(crate::block::ArtifactType);
#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExArtifactBinding(crate::block::ArtifactBinding);

/// As ASM-0014, for the artifact-type tag.
pub assume_specification[ <crate::block::ArtifactType as core::cmp::PartialEq>::eq ](
    x: &crate::block::ArtifactType,
    y: &crate::block::ArtifactType,
) -> (result: bool)
    ensures
        result == (x == y),
;

/// As ASM-0014, for the binding-form tag.
pub assume_specification[ <BindingType as core::cmp::PartialEq>::eq ](
    x: &BindingType,
    y: &BindingType,
) -> (result: bool)
    ensures
        result == (x == y),
;

/// The dispatch model — the types the continuation-unbypassability theorem must see.
///
/// ADR-MCPRE-059 WP2 experiment: every one of these is class A (expose the datatype
/// structure) with no view, equality or arithmetic specification attached, and none
/// introduces an assumption. That is the measurement the experiment was run to take.
#[verifier::external_type_specification]
pub struct ExSignerSlot(crate::block::SignerSlot);
#[verifier::external_type_specification]
pub struct ExActorIdentity(crate::block::ActorIdentity);
#[verifier::external_type_specification]
pub struct ExResolvedActor(crate::block::ResolvedActor);
#[verifier::external_type_specification]
pub struct ExAudienceTuple(crate::block::AudienceTuple);
#[verifier::external_type_specification]
pub struct ExRequestEvidenceDigest(crate::evidence::RequestEvidenceDigest);
#[verifier::external_type_specification]
pub struct ExHttpContinuation(crate::block::HttpContinuation);
#[verifier::external_type_specification]
pub struct ExHttpRequestEvidenceBlock(crate::block::HttpRequestEvidenceBlock);
#[verifier::external_type_specification]
pub struct ExFloorVerifiedRequest(crate::verified_request::CryptographicFloorVerifiedRequest);
#[verifier::external_type_specification]
pub struct ExVerifiedMcpRequest(crate::verified_request::VerifiedMcpRequest);
#[verifier::external_type_specification]
pub struct ExHttpReplayKey(crate::replay::HttpReplayKey);
#[verifier::external_type_specification]
pub struct ExDispatchError(crate::dispatch::DispatchError);
#[verifier::external_type_specification]
pub struct ExRetainedContinuation<'a>(crate::dispatch::RetainedContinuation<'a>);

/// The labeled evidence digest, as an UNINTERPRETED function of its role label and its
/// input bytes (ASM-0023). Nothing is assumed about SHA-256 — only that the digest IS A
/// FUNCTION of `(label, bytes)`, which is what makes role separation provable: a response
/// handle accepted in the request role would need a cross-role collision, which is the
/// `boundary.crypto_primitives` obligation and is not silently assumed away here.
pub uninterp spec fn labeled_digest(label: Seq<char>, bytes: Seq<u8>) -> Seq<char>;

/// The verifier's configured symmetric clock-skew tolerance, as a specification value.
///
/// Uninterpreted on purpose: the freshness theorem must hold for WHATEVER skew a
/// deployment configures, so nothing is assumed about this value except that it is a
/// function of the policy object.
pub uninterp spec fn skew_of(policy: &VerifierPolicy) -> i64;

/// The tags a binding carries, UNINTERPRETED (ASM-0063): the typing theorem holds for any.
pub uninterp spec fn artifact_type_of(binding: &crate::block::ArtifactBinding) -> crate::block::ArtifactType;
pub uninterp spec fn binding_type_of(binding: &crate::block::ArtifactBinding) -> BindingType;

/// The widest `expires - created` this verifier accepts, as a specification value.
pub uninterp spec fn validity_of(policy: &VerifierPolicy) -> i64;

}
