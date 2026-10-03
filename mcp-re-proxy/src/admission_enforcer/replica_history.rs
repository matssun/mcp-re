// SPDX-License-Identifier: Apache-2.0
//! The stateful half of the §7 gate: what THIS replica has seen of the authority.
//!
//! [`check_admission`](mcp_re_http_profile::check_admission) is stateless — one call against
//! one snapshot. Whether this replica may serve on a last-known snapshot is a fact about its
//! own history, and the two methods here are the only places that history is written
//! ([`AdmissionEnforcer::lookup`] records a successful read) and read
//! ([`AdmissionEnforcer::convert`] judges the window). They are one file because a write
//! without its read, or the reverse, is the defect: a window nobody refreshes, or one nobody
//! consults.

use mcp_re_http_profile::admission::AdmissionVerdict;
use mcp_re_http_profile::authoritative_admission::record::CurrentAdmissionState;
use mcp_re_http_profile::HttpProfileError;

use super::AdmissionEnforcer;
use super::AdmissionFacet;

impl AdmissionEnforcer {
    /// The authoritative lookup, keyed on the AUTHENTICATED workload id.
    ///
    /// `Ok(None)` is an outage — the ONLY input that reaches the §5.2 degraded fork — while a
    /// store that ANSWERED is a definitive negative whenever it has nothing this deployment
    /// will act on: no record, or a record that is not the configured authority's current
    /// statement. Both are refused here rather than handed to a fork that would serve the
    /// call on its own assertion, which is what would make corrupting a record a cheaper
    /// un-revoke than issuing one.
    ///
    /// The degraded window is a DURATION, so it is read from the monotonic clock and never
    /// from `now` — see `degraded_window`. A read is recorded at the instant the lookup was
    /// issued, never later than the answer, so it can only shorten the window.
    pub(super) async fn lookup(
        &self,
        admission_id: &str,
        now: i64,
    ) -> Result<Option<CurrentAdmissionState>, HttpProfileError> {
        let elapsed_at = std::time::Instant::now();
        match self.source.current(admission_id, now).await {
            Ok(Some(state)) => {
                self.window.record_read(elapsed_at);
                Ok(Some(state))
            }
            Ok(None) => {
                self.window.record_read(elapsed_at);
                Err(HttpProfileError::AdmissionNotCurrent)
            }
            // The source is unreachable. Whether this replica may still SERVE on it is
            // decided at the conversion and not here: one check, so that deleting it makes an
            // out-of-window serve reachable rather than leaving a second copy still enforcing.
            Err(_) => Ok(None),
        }
    }

    /// THE CONVERSION, and this authority's own conjunct. `check_admission` is stateless: it
    /// saw one call against one snapshot, and a `DegradedCandidate` says only that the
    /// authority was unreachable, that the deployment opted in, and that the assertion the
    /// CALLER presented is recent. That last term is the caller's to choose — during an
    /// outage the issuer keeps minting, so a client that refetches satisfies it for the whole
    /// outage however long it runs.
    ///
    /// What bounds the outage is elapsed time since this replica last reached the authority,
    /// which is replica HISTORY and which only this owner holds. Its window is monotonic and
    /// judged by its owner at the decision instant, so the lookup's duration always falls on
    /// the refusing side.
    ///
    /// The arm is REPORTED, not discarded. `.map(|_| ())` here was R11-106: a serve on a
    /// stale snapshot inside P became indistinguishable in audit from a live-confirmed one,
    /// and the facet is what the record now carries instead.
    pub(super) fn convert(
        &self,
        verdict: AdmissionVerdict,
    ) -> Result<AdmissionFacet, HttpProfileError> {
        match verdict {
            AdmissionVerdict::Live(_) => Ok(AdmissionFacet::LiveConfirmed),
            AdmissionVerdict::DegradedCandidate(_) if self.window.exhausted(&self.policy) => {
                Err(HttpProfileError::AdmissionStateUnavailable)
            }
            AdmissionVerdict::DegradedCandidate(_) => Ok(AdmissionFacet::Degraded),
        }
    }
}
