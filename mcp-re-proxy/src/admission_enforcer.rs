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

use mcp_re_http_profile::AdmissionPolicy;

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
