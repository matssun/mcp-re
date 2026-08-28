// SPDX-License-Identifier: Apache-2.0
//! The signature-parameter gate: what this verifier ACCEPTS, as against what the signer SAID.
//!
//! One authority: **the parameters a message presents are ones this verifier's policy
//! admits, and its window contains now.** The distinction the module exists to keep is
//! §13.1 / §5.1's — the signature parameters state what the signer did, and
//! [`VerifierPolicy`] states what is acceptable. Neither is read from the other.
//!
//! It is also the only stage in the floor carrying a Verus postcondition (THM-0001), which
//! is why it is its own module rather than a helper inside a stage: the theorem is about
//! this function, and a prover reaching it must not have to reach a stage as well.

// ADR-MCPRE-059 Phase 2. Absent from every production build: the imports are
// feature-gated and each specification rides a `cfg_attr` that expands to nothing
// unless `--features verify` is on.
#[cfg(feature = "verify")]
use verus_builtin_macros::{verus_spec, verus_verify};
#[cfg(feature = "verify")]
#[allow(unused_imports)]
use vstd::prelude::*;

use crate::error::HttpProfileError;
use crate::ids::PROFILE_TAG;
use crate::policy::ProfileAlgorithm;
use crate::policy::VerifierPolicy;
use crate::sigbase::SignatureParams;

/// Shared parameter gate: tag, algorithm, freshness window, keyid presence.
///
/// Algorithm acceptance and clock-skew tolerance are read from `policy`, never
/// from the message (§13.1 / §5.1): the signature parameters state what the
/// signer did, the policy states what this verifier accepts.
// ADR-MCPRE-059 Phase 2 theorem — the live freshness rule (§5.1).
//
// This is the admission decision every served request passes through: if this function
// returns Ok, the message's window contains `now` after widening by the policy's skew in
// both directions, the window is non-degenerate, and it is no wider than the policy
// allows. Nothing is assumed about the skew or the validity bound themselves — the
// theorem holds for whatever a deployment configures, which is the property that matters,
// since the attacker chooses `created`/`expires` and the operator chooses the policy.
//
// The window-width clause carries its saturation explicitly rather than quietly assuming
// `expires - created` fits in an i64: it does not, for a hostile pair, and a theorem that
// pretended otherwise would be false exactly where it is load-bearing.
#[cfg_attr(feature = "verify", verus_spec(out =>
    ensures
        out matches Ok((created, expires, _nonce, _key_id, _algorithm)) ==> {
            &&& created - crate::verus_std_specs::skew_of(policy) <= now
            &&& now < expires + crate::verus_std_specs::skew_of(policy)
            &&& created < expires
            &&& (if expires - created > i64::MAX { i64::MAX as int } else { expires - created })
                    <= crate::verus_std_specs::validity_of(policy)
        },
))]
pub(crate) fn check_params(
    params: &SignatureParams,
    policy: &VerifierPolicy,
    now: i64,
    require_nonce: bool,
) -> Result<(i64, i64, String, String, ProfileAlgorithm), HttpProfileError> {
    match params.tag.as_deref() {
        Some(PROFILE_TAG) => {}
        _ => return Err(HttpProfileError::UnknownProfileTag),
    }
    // Resolve the DECLARED algorithm to one this verifier both accepts and can
    // check. The resolved value is returned, not discarded, so every caller must
    // dispatch on it — "is it allowed" and "what verifies it" are one answer.
    let algorithm = params
        .alg
        .as_deref()
        .and_then(|alg| policy.accepted_algorithm(alg))
        .ok_or(HttpProfileError::UnsupportedAlgorithm)?;
    let created = params.created.ok_or(HttpProfileError::StaleWindow)?;
    let expires = params.expires.ok_or(HttpProfileError::StaleWindow)?;
    // Freshness with a bounded, symmetric skew tolerance (§5.1): a `created`
    // slightly in the future and an `expires` slightly in the past are honest
    // clock disagreement, not evidence of staleness. `expires <= created` is
    // skew-free — a degenerate window is a property of the message itself, and
    // no amount of clock disagreement makes it well-formed.
    let skew = policy.max_clock_skew();
    if created.saturating_sub(skew) > now
        || expires.saturating_add(skew) <= now
        || expires <= created
    {
        return Err(HttpProfileError::StaleWindow);
    }
    // Bound how WIDE the signer may declare its own window (§5.1). Freshness above
    // decides when a window may be used; it says nothing about its width, so without
    // this a client can present `created = now, expires = now + 10y` — fresh, and
    // therefore accepted — and the replay tier then retains that nonce until
    // `expires + skew`. The retention a single client can pin would be client-chosen
    // and unbounded. The window is the message's own property, so like the degenerate
    // `expires <= created` case this is checked skew-free.
    if expires.saturating_sub(created) > policy.max_signature_validity() {
        return Err(HttpProfileError::StaleWindow);
    }
    let nonce = match (&params.nonce, require_nonce) {
        (Some(n), _) => n.clone(),
        (None, false) => String::new(),
        (None, true) => return Err(HttpProfileError::MissingEvidence("nonce")),
    };
    let key_id = params
        .keyid
        .clone()
        .ok_or(HttpProfileError::MissingEvidence("keyid"))?;
    Ok((created, expires, nonce, key_id, algorithm))
}
