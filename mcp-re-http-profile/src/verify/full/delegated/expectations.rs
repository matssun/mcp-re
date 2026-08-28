// SPDX-License-Identifier: Apache-2.0
//! What the deployment expects of a delegation CREDENTIAL.
//!
//! One authority, and it is an input rather than a procedure: **the credential's own
//! window, its audience scope, and the trust epochs this verifier accepts.**
//!
//! The response-SIGNATURE policy is deliberately not here. That is the verifier's, held
//! once by [`crate::verifier::Verifier`], and a second copy of it on this record was the
//! `_with_policy` shadow API in miniature — one authority stated twice, free to disagree.
//! What survives is exactly what is specific to the credential.

/// Deployment policy for verifying a delegated-key-signed response (ADR-MCPRE-052 §3).
/// Supplied by the integration layer from the active profile, the verified request
/// context, and the deployment's epoch/audience policy.
pub struct DelegationExpectations<'a> {
    /// This verifier's own audience identifier(s); the credential's `aud` must
    /// name one (§3 step 5).
    pub verifier_audiences: &'a [&'a str],
    /// The service/audience-scope hash the delegated key must be scoped to
    /// (§3 step 5) — the request's audience hash.
    pub expected_audience_hash: &'a str,
    /// The active accepted trust-epoch set — default `{ current }`, optionally
    /// `{ current, previous }` under a bounded rollout window (§3 step 6).
    pub accepted_epochs: &'a [&'a str],
    /// Clock-skew tolerance for credential freshness (§3 step 4).
    pub max_clock_skew: i64,
}
