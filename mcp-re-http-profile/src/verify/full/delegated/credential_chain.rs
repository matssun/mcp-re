// SPDX-License-Identifier: Apache-2.0
//! Chaining an inline delegation credential to a root the deployment trusts.
//!
//! One authority: **the key that signed this response was authorized to, by a credential
//! that chains to a root resolved through the SAME trust seam every other path uses**
//! (ADR-MCPRE-052 §3 steps 2–7).
//!
//! # Why this is one function and not one per delegated operation
//!
//! The bound and unbound paths differ in what the SIGNATURE covers, not in how a credential
//! chains to a root. They carried verbatim copies — the same params, the same root-issuer
//! closure, the same outage capture, the same explanatory comment — and two copies of a
//! trust-resolution rule are two places for it to drift. The mutation battery makes the
//! difference concrete: one slot mutation here breaks all 12 delegated controls at once,
//! where before it took two mutations to reach the same set.
//!
//! # The failure it re-reports, and why
//!
//! `verify_delegation_credential`'s resolver returns `Option`, which cannot express the
//! difference between *not trusted* and *the store could not answer*. Resolving inline
//! therefore collapsed a trust-store OUTAGE into `delegation_issuer_untrusted`, sending an
//! operator to look at the caller's credentials instead of at their own store — the exact
//! confusion the C079 fix removed everywhere else — and it dropped the slot assertion, so a
//! resolver handing back a Request-slot actor would have had its key accepted as a
//! delegation root. Both are captured here and re-reported as themselves.

use crate::block::HttpResponseEvidenceBlock;
use crate::block::ResolverOutcome;
use crate::block::SignerSlot;
use crate::delegation::verify_delegation_credential;
use crate::delegation::DelegationVerifyParams;
use crate::delegation::VerifiedDelegation;
use crate::error::HttpProfileError;
use crate::ids::PROFILE_TAG;
use crate::verify::floor::trust_slot::resolve_actor_for_slot;

use super::DelegationExpectations;

/// Verify the inline delegation credential a response block carries (ADR-MCPRE-052 §3
/// steps 2–7), resolving its ROOT issuer through the SAME trust seam every other path uses.
///
/// One function rather than a copy per delegated operation: the bound and unbound paths
/// differ in what the signature covers, not in how a credential chains to a root, and two
/// copies of a trust-resolution rule are two places for it to drift.
///
/// `verify_delegation_credential`'s resolver returns `Option`, which cannot express the
/// difference between "not trusted" and "the store could not answer" — so resolving inline
/// collapsed a trust-store OUTAGE into `mcp-re.delegation_issuer_untrusted`, sending an
/// operator to look at the caller's credentials instead of at their own store (the exact
/// confusion the C079 fix removed everywhere else), and it dropped the `actor.slot != slot`
/// assertion, so a resolver handing back a Request-slot actor would have had its key
/// accepted as a delegation root. The failure is captured here and re-reported as itself.
pub(super) fn chain_to_root<R: Into<ResolverOutcome>>(
    credential: &str,
    block: &HttpResponseEvidenceBlock,
    resolve_actor: &dyn Fn(&str, SignerSlot) -> R,
    expect: &DelegationExpectations<'_>,
    is_revoked: &dyn Fn(&str) -> bool,
    now: i64,
) -> Result<VerifiedDelegation, HttpProfileError> {
    let expected_server_signer = block.server_signer.actor_id();
    let params = DelegationVerifyParams {
        now,
        max_clock_skew: expect.max_clock_skew,
        verifier_audiences: expect.verifier_audiences,
        expected_profile: PROFILE_TAG,
        expected_audience_hash: expect.expected_audience_hash,
        expected_server_signer: &expected_server_signer,
        accepted_epochs: expect.accepted_epochs,
    };
    let resolve_failure: std::cell::RefCell<Option<HttpProfileError>> =
        std::cell::RefCell::new(None);
    let verified = verify_delegation_credential(
        credential,
        &params,
        |issuer_kid| match resolve_actor_for_slot(resolve_actor, issuer_kid, SignerSlot::Response) {
            Ok(actor) => Some(actor.verification_key),
            // A definitive "not trusted" stays the credential layer's own verdict
            // (`mcp-re.delegation_issuer_untrusted`) — that IS the right token for an
            // issuer nobody vouches for. Only an OUTAGE and a wrong-slot actor are
            // propagated, because those are not statements about the credential.
            Err(HttpProfileError::UnresolvedKeyId) => None,
            Err(e) => {
                *resolve_failure.borrow_mut() = Some(e);
                None
            }
        },
        |kid| is_revoked(kid),
    );
    verified.map_err(|e| resolve_failure.into_inner().unwrap_or(e))
}
