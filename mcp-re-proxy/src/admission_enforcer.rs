// SPDX-License-Identifier: Apache-2.0
//! The §7 admission gate's collaborators — ADR-MCPRE-053.
//!
//! Moved out of `http_profile_serve` by ADR-MCPRE-064 Slice 5. The serving file holds the
//! PIPELINE — the ordered stages and the exchange machine that governs them — and this is
//! not a stage. It is the deployment's admission posture and the degraded-window arithmetic
//! over it: a cohesive unit with its own name, its own invariant, and no dependence on the
//! request being served.
//!
//! The split is the threshold rule working as intended. Slice 5 needed a handful of
//! production lines in the serving file to carry the binding prerequisite, the file is a
//! documented ADR-MCPRE-061 §14 exception already at its debt baseline, and a ratcheted file
//! may not grow whatever its status. The choice was decompose or strip the reasoning out of
//! the comments to fit a number — and the latter is exactly the distortion the rule exists
//! to prevent.

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
/// meaningful alone.
pub(crate) struct AdmissionEnforcer {
    /// The authoritative state this PEP consults per call.
    pub(crate) source: Arc<dyn AsyncAdmissionSource>,
    /// The N/P/TTL freshness budget and the degraded-mode opt-in (§5.2).
    pub(crate) policy: AdmissionPolicy,
    /// What an admission-free request means here.
    pub(crate) enforcement: AdmissionEnforcement,
    /// Resolves an assertion's `issuer_kid` to the admission authority's root key.
    /// A kid never introduces trust: an assertion signed by an unresolvable issuer
    /// is refused, exactly as an unknown request keyid is.
    pub(crate) resolve_authority: AdmissionAuthorityResolver,
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
    /// treating startup as a confirmation.
    pub(crate) last_authoritative_read: std::sync::atomic::AtomicI64,
}

impl AdmissionEnforcer {
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
    ) -> Result<(), &'static str> {
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
                    return Err(HttpProfileError::AdmissionStateUnavailable.wire_code());
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
                return Err(HttpProfileError::AdmissionNotCurrent.wire_code());
            }
            // The source is unreachable. Whether the §5.2 degraded fork may be entered
            // at all is decided HERE, by how long the authority has been unreachable —
            // not downstream by how fresh the caller's assertion is, which the caller
            // controls.
            Err(_) => {
                if self.degraded_window_exhausted(now) {
                    return Err(HttpProfileError::AdmissionStateUnavailable.wire_code());
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
        .map_err(|e| e.wire_code())
    }

    /// Note that the authoritative record was read at `now`.
    ///
    /// A definitive negative counts: the authority answered, which is what P measures.
    pub(crate) fn record_authoritative_read(&self, now: i64) {
        self.last_authoritative_read
            .fetch_max(now, std::sync::atomic::Ordering::Relaxed);
    }

    /// Has the authority been unreachable for longer than P (+ skew)?
    ///
    /// True also when it has never been reachable, and whenever degraded mode is not
    /// enabled at all — in both cases there is no window to be inside of.
    pub(crate) fn degraded_window_exhausted(&self, now: i64) -> bool {
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
