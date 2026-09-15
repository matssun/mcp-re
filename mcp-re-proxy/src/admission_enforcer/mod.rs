// SPDX-License-Identifier: Apache-2.0
//! The §7 admission gate — ADR-MCPRE-053.
//!
//! Not a serving stage: this is the deployment's admission posture and the degraded-window
//! arithmetic over it, with its own name, its own invariant, and no dependence on the
//! request being served.
//!
//! The four collaborators enter through [`AdmissionEnforcer::new`]; the fifth member is not
//! one of them, because a caller able to supply it could hand a fresh replica a degraded
//! window it never earned. The representation is private, and the window's arithmetic
//! belongs to [`degraded_window`] — so holding an enforcer means holding a gate that never
//! treated its own startup as a confirmation.

use std::sync::Arc;

use mcp_re_http_profile::check_admission;
use mcp_re_http_profile::AdmissionPolicy;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::VerifiedMcpRequest;

use crate::admission_source::AsyncAdmissionSource;
use crate::http_profile_serve::AdmissionAuthorityResolver;

/// How long a replica may serve on last-known state while the authority is unreachable.
mod degraded_window;

use degraded_window::DegradedWindow;

/// What a request that carries NO admission evidence means to this deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionEnforcement {
    /// Serve it. For a deployment that has not rolled admission out to every client
    /// yet — the binding is honoured when present and absent is not an error.
    Optional,
    /// Refuse it. The only setting under which "every served call acted under a
    /// current admission" is a true statement about the deployment.
    Required,
}

/// The §7 admission gate's collaborators, held together because none of them is
/// meaningful alone. The representation is private, so [`AdmissionEnforcer::new`] is the
/// only producer.
pub(crate) struct AdmissionEnforcer {
    /// The authoritative state this PEP consults per call.
    source: Arc<dyn AsyncAdmissionSource>,
    /// The N/P/TTL freshness budget and the degraded-mode opt-in (§5.2).
    policy: AdmissionPolicy,
    /// What an admission-free request means here.
    enforcement: AdmissionEnforcement,
    /// Resolves an assertion's `issuer_kid` to the admission authority's root key.
    /// A kid never introduces trust: an assertion signed by an unresolvable issuer
    /// is refused, exactly as an unknown request keyid is.
    resolve_authority: AdmissionAuthorityResolver,
    /// How long this replica may still serve on last-known state, and the clock that
    /// decides it. See [`degraded_window`].
    window: DegradedWindow,
}

impl AdmissionEnforcer {
    /// Assemble the gate from its four collaborators. The fifth field is not one of
    /// them: a caller able to supply `last_authoritative_read` could hand a fresh replica
    /// a degraded window it never earned.
    pub(crate) fn new(
        source: Arc<dyn AsyncAdmissionSource>,
        policy: AdmissionPolicy,
        enforcement: AdmissionEnforcement,
        resolve_authority: AdmissionAuthorityResolver,
    ) -> Self {
        Self {
            source,
            policy,
            enforcement,
            resolve_authority,
            window: DegradedWindow::unearned(),
        }
    }

    /// Decide §7 admission for one verified request.
    ///
    /// `Ok(())` means this deployment accepts the admission the call acts under, or that a
    /// call declaring none is acceptable here. `Err` carries the frozen wire code the
    /// refusal is served as — never a reason phrase, and never a status: what a refusal
    /// COSTS the client is a fact about the whole exchange, and the serving path's machine
    /// owns it.
    ///
    /// It takes the verified request and the verifier-resolved actor id, and nothing the
    /// request asserts about itself.
    pub(crate) async fn decide(
        &self,
        verified: &VerifiedMcpRequest,
        actor_id: &str,
        audience_id: &str,
        now: i64,
    ) -> Result<(), HttpProfileError> {
        let block = verified.request_block();
        let (binding, assertion) = match (
            block.admission.as_ref(),
            block.admission_assertion.as_deref(),
        ) {
            (Some(b), Some(a)) => (b, a),
            // The block validator already refuses one half without the other, so
            // reaching here means BOTH are absent: the call declares no admission.
            _ => {
                if self.enforcement == AdmissionEnforcement::Required {
                    return Err(HttpProfileError::AdmissionStateUnavailable);
                }
                return Ok(());
            }
        };

        // The authoritative lookup. An outage yields `None` — the ONLY input that
        // reaches the §5.2 degraded fork — while a store that ANSWERED is a definitive
        // negative whenever it has nothing this deployment will act on: no record, or a
        // record that is not the configured authority's current statement. Both are
        // refused here rather than handed to a fork that would serve the call on its own
        // assertion, which is what would make corrupting a record a cheaper un-revoke than
        // issuing one.
        let authoritative = match self.source.current(&binding.admission_id, now).await {
            Ok(Some(state)) => {
                self.window.record_read(now);
                Some(state)
            }
            Ok(None) => {
                self.window.record_read(now);
                return Err(HttpProfileError::AdmissionNotCurrent);
            }
            // The source is unreachable. Whether the §5.2 degraded fork may be entered
            // at all is decided HERE, by how long the authority has been unreachable —
            // not downstream by how fresh the caller's assertion is, which the caller
            // controls.
            Err(_) => {
                if self.window.exhausted(&self.policy, now) {
                    return Err(HttpProfileError::AdmissionStateUnavailable);
                }
                None
            }
        };

        let resolve = Arc::clone(&self.resolve_authority);
        check_admission(
            binding,
            assertion,
            // The VERIFIER-RESOLVED actor — the FULL signing actor, keyid included, never
            // the bare subject and never anything the request asserts. An assertion issued
            // to another workload, or under another key, names a different actor and is
            // refused, so possession alone does not satisfy the gate (§16.4).
            actor_id,
            // The PROJECTION, not the product. `CurrentAdmissionState` exists so that
            // reaching this line means the state was authenticated as the configured
            // authority's and found current; the currency check below consumes the
            // semantic fact, which is what its Verus contract is stated over.
            authoritative.as_ref().map(|current| current.state()),
            mcp_re_http_profile::PROFILE_TAG,
            &[audience_id],
            &self.policy,
            now,
            move |kid: &str| resolve(kid),
        )
        // Admitted. Note what is NOT recorded: `VerifiedAdmission::degraded`
        // distinguishes a live-confirmed admission from one served on a stale
        // snapshot inside the P window, and the audit stream cannot currently
        // carry that difference — ADR-MCPS-035 §3 freezes the success-event
        // allowlist and says no third success event may be minted without an
        // ADR. So a degraded-mode serve is indistinguishable in audit from a
        // confirmed one. That is a real gap in the record, named here rather
        // than closed by quietly widening a pinned vocabulary.
        .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The window is a MEMBER of the gate and not a constructor parameter, so every
    /// enforcer that exists begins with an unearned one. Its arithmetic is measured in
    /// [`degraded_window`]; what belongs here is that the gate holds one it did not let a
    /// caller choose.
    #[test]
    fn a_new_enforcer_has_a_window_nobody_earned() {
        let enforcer = AdmissionEnforcer::new(
            Arc::new(crate::admission_source::InMemoryAdmissionSource::new(
                crate::admission_source::test_support::verifier_for(
                    &mcp_re_core::SigningKey::from_seed_bytes(&[3u8; 32]),
                    60,
                    5,
                ),
            )),
            AdmissionPolicy {
                max_assertion_age: 300,
                max_clock_skew: 5,
                degraded_propagation_bound: 60,
                allow_degraded_mode: true,
            },
            AdmissionEnforcement::Required,
            Arc::new(|_kid: &str| None),
        );
        assert!(
            enforcer.window.exhausted(&enforcer.policy, 1_000),
            "a gate must not treat its own construction as a confirmation"
        );
    }
}
