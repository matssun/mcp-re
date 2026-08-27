// SPDX-License-Identifier: Apache-2.0
//! The §7 admission gate — ADR-MCPRE-053.
//!
//! Not a serving stage: this is the deployment's admission posture and the degraded-window
//! arithmetic over it, with its own name, its own invariant, and no dependence on the
//! request being served.
//!
//! The four collaborators enter through [`AdmissionEnforcer::new`], the representation is
//! private, and the degraded-window arithmetic has no caller outside this module: holding
//! an enforcer means holding a gate that never treated its own startup as a confirmation.

use std::sync::Arc;

use mcp_re_http_profile::check_admission;
use mcp_re_http_profile::AdmissionPolicy;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::VerifiedMcpRequest;

use crate::admission_source::AsyncAdmissionSource;
use crate::http_profile_serve::AdmissionAuthorityResolver;

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
    /// When the authoritative source was last READ successfully, in unix seconds.
    ///
    /// P bounds how long this PEP may serve on last-known state while the authority is
    /// unreachable. Applied to the presented assertion's `iat`, it bounds the wrong
    /// thing: the revocation channel is the STORE, so during a store outage the
    /// assertion issuer never learns of a revocation and keeps minting assertions with
    /// a current `iat` — and a caller that simply keeps fetching them is served for the
    /// whole outage, however long. Bounding elapsed time since the last successful read
    /// is what makes "degraded serving is bounded by P" a true statement about the
    /// deployment.
    ///
    /// `i64::MIN` until the first successful read: a replica that has never reached the
    /// authority has no last-known state to serve on, so it fails closed rather than
    /// treating startup as a confirmation. The sole producer establishes it, so it
    /// holds for every enforcer that exists rather than for the ones built correctly.
    last_authoritative_read: std::sync::atomic::AtomicI64,
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
            last_authoritative_read: std::sync::atomic::AtomicI64::new(i64::MIN),
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
        // reaches the §5.2 degraded fork — while a healthy authority that has never
        // heard of this workload is a definitive negative, refused here rather than
        // being handed to a fork that would serve it on its own assertion.
        let authoritative = match self.source.current(&binding.admission_id).await {
            Ok(Some(state)) => {
                self.record_authoritative_read(now);
                Some(state)
            }
            Ok(None) => {
                self.record_authoritative_read(now);
                return Err(HttpProfileError::AdmissionNotCurrent);
            }
            // The source is unreachable. Whether the §5.2 degraded fork may be entered
            // at all is decided HERE, by how long the authority has been unreachable —
            // not downstream by how fresh the caller's assertion is, which the caller
            // controls.
            Err(_) => {
                if self.degraded_window_exhausted(now) {
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
            authoritative.as_ref(),
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

    /// Note that the authoritative record was read at `now`.
    ///
    /// A definitive negative counts: the authority answered, which is what P measures.
    fn record_authoritative_read(&self, now: i64) {
        self.last_authoritative_read
            .fetch_max(now, std::sync::atomic::Ordering::Relaxed);
    }

    /// Has the authority been unreachable for longer than P (+ skew)?
    ///
    /// True also when it has never been reachable, and whenever degraded mode is not
    /// enabled at all — in both cases there is no window to be inside of.
    fn degraded_window_exhausted(&self, now: i64) -> bool {
        if !self.policy.allow_degraded_mode {
            return true;
        }
        let last = self
            .last_authoritative_read
            .load(std::sync::atomic::Ordering::Relaxed);
        if last == i64::MIN {
            return true;
        }
        now.saturating_sub(last)
            > self
                .policy
                .degraded_propagation_bound
                .saturating_add(self.policy.max_clock_skew)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every enforcer under test is built the only way one can be built, so these
    // assertions are about the type rather than about a representation assembled here.
    fn enforcer(bound: i64, skew: i64, allow_degraded: bool) -> AdmissionEnforcer {
        AdmissionEnforcer::new(
            Arc::new(crate::admission_source::InMemoryAdmissionSource::new()),
            AdmissionPolicy {
                max_assertion_age: 300,
                max_clock_skew: skew,
                degraded_propagation_bound: bound,
                allow_degraded_mode: allow_degraded,
            },
            AdmissionEnforcement::Required,
            Arc::new(|_kid: &str| None),
        )
    }

    /// A replica that has never reached the authority has no last-known state to serve
    /// on, so startup is not a confirmation.
    #[test]
    fn a_replica_that_never_reached_the_authority_has_no_window() {
        assert!(enforcer(60, 5, true).degraded_window_exhausted(1_000));
    }

    /// R7-C093: the degraded window is elapsed OUTAGE time, not assertion freshness.
    ///
    /// The revocation channel is the store, so during a store outage the issuer never
    /// learns of a revocation and keeps minting assertions with a current `iat`. A
    /// caller that simply keeps fetching them was therefore served for the whole
    /// outage, however long, while the operator was told degraded serving is bounded
    /// by P. Nothing the caller can do moves this clock.
    #[test]
    fn the_degraded_window_closes_p_after_the_last_successful_read() {
        let enforcer = enforcer(60, 5, true);
        enforcer.record_authoritative_read(1_000);

        assert!(
            !enforcer.degraded_window_exhausted(1_060),
            "inside P + skew the last-known state is still usable"
        );
        assert!(
            !enforcer.degraded_window_exhausted(1_065),
            "the skew allowance is on the same clock"
        );
        assert!(
            enforcer.degraded_window_exhausted(1_066),
            "past P + skew an unreachable authority fails closed, however fresh the \
             assertion the caller presents"
        );
    }

    /// The clock only moves forward: a stale read cannot re-open a window a later one
    /// closed.
    #[test]
    fn an_out_of_order_read_does_not_rewind_the_window() {
        let enforcer = enforcer(60, 0, true);
        enforcer.record_authoritative_read(2_000);
        enforcer.record_authoritative_read(1_000);
        assert!(!enforcer.degraded_window_exhausted(2_050));
    }

    /// Degraded mode is opt-in; without it an unreachable authority fails closed at
    /// once, whatever was last read.
    #[test]
    fn without_the_opt_in_there_is_no_window_at_all() {
        let enforcer = enforcer(3_600, 30, false);
        enforcer.record_authoritative_read(1_000);
        assert!(enforcer.degraded_window_exhausted(1_001));
    }
}
