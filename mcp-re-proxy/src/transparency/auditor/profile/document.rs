// SPDX-License-Identifier: Apache-2.0
//! The profile AS WRITTEN, and the one check that turns it into a profile.
//!
//! One fact: **whether an audit-profile document describes a posture an audit can be
//! performed under.**
//!
//! [`AuditProfileDocument`] is the wire record and it is `pub(super)` at most: nothing
//! outside this subtree may hold one, because holding one means holding a posture that has
//! NOT been checked. [`coherent`] is the check, and [`super::AuditProfile`]'s `TryFrom` is
//! its only caller — which is what makes the profile's projections infallible.

use serde::Deserialize;
use serde::Serialize;

use mcp_re_core::VerificationKey;
use mcp_re_http_profile::AudienceTuple;

/// The schema token a profile must carry.
pub(in crate::transparency::auditor::profile) const AUDIT_PROFILE_SCHEMA: &str =
    "mcp-re-audit-profile/v1";

/// The widest clock-skew tolerance a profile may assert, in seconds.
///
/// An unbounded skew is not a stricter audit that happens to be lenient — it is an audit
/// whose credential-freshness check has been switched off while still reporting a verdict.
/// One hour is the ceiling the serving path's freshness windows are written against.
const MAX_CLOCK_SKEW_CEILING: i64 = 3_600;

/// The profile AS WRITTEN — the wire record, before anything about it is checked.
///
/// Private to the profile subtree, and the only thing `serde` ever sees.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AuditProfileDocument {
    /// The schema token, so a reader of the artifact knows what it is holding.
    pub(super) schema: String,
    /// The trust domain the deployment's identities belong to.
    pub(super) trust_domain: String,
    /// The audience tuple every retained hop's evidence block must equal.
    pub(super) expected_audience: AudienceTuple,
    /// The delegated-credential window this audit accepts.
    pub(super) delegation: DelegationRecord,
    /// The key the deployment's responses were anchored to.
    pub(super) response_anchor: ResponseAnchorRecord,
    /// Key identifiers this audit treats as revoked. Absent means none.
    #[serde(default)]
    pub(super) revoked_key_ids: Vec<String>,
}

/// The delegated-credential expectations, as written.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DelegationRecord {
    /// This verifier's own audience identifier(s); a credential's `aud` must name one.
    pub(super) verifier_audiences: Vec<String>,
    /// The audience-scope hash a delegated key must be scoped to.
    pub(super) expected_audience_hash: String,
    /// The trust epochs this audit accepts a delegated credential from.
    pub(super) accepted_epochs: Vec<String>,
    /// Clock-skew tolerance for credential freshness, in seconds.
    pub(super) max_clock_skew_secs: i64,
}

/// The response anchor, as written.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ResponseAnchorRecord {
    /// The subject the deployment signs responses as.
    pub(super) subject: String,
    /// The `key_id` the response evidence block must name.
    pub(super) key_id: String,
    /// The Ed25519 public key, base64url.
    pub(super) public_key: String,
}

/// The anchor key a coherent document names, or the first rule it breaks.
///
/// Every clause refuses a document that would otherwise produce a VERDICT while one of the
/// comparisons that verdict rests on could not be made. An empty verifier-audience list or
/// an empty epoch set does not audit more strictly, it audits nothing; an unbounded skew
/// reports a freshness result without a freshness check.
pub(super) fn coherent(document: &AuditProfileDocument) -> Result<VerificationKey, String> {
    if document.schema != AUDIT_PROFILE_SCHEMA {
        return Err(format!(
            "audit profile: schema is {:?}, expected {AUDIT_PROFILE_SCHEMA:?}",
            document.schema,
        ));
    }
    if document.expected_audience.target_uri.is_empty()
        || document.expected_audience.audience_id.is_empty()
    {
        return Err(
            "audit profile: expected_audience needs an audience_id and a \
                    target_uri, or no hop can be compared against it"
                .to_owned(),
        );
    }
    if document.delegation.verifier_audiences.is_empty() {
        return Err(
            "audit profile: delegation.verifier_audiences is empty, so no \
                    delegated credential can name this verifier"
                .to_owned(),
        );
    }
    if document.delegation.accepted_epochs.is_empty() {
        return Err(
            "audit profile: delegation.accepted_epochs is empty, so no delegated \
                    credential can be accepted at all"
                .to_owned(),
        );
    }
    if !(0..=MAX_CLOCK_SKEW_CEILING).contains(&document.delegation.max_clock_skew_secs) {
        return Err(format!(
            "audit profile: delegation.max_clock_skew_secs is {}, outside \
             0..={MAX_CLOCK_SKEW_CEILING}; an unbounded tolerance reports a verdict with \
             the freshness check switched off",
            document.delegation.max_clock_skew_secs,
        ));
    }
    VerificationKey::from_b64url(&document.response_anchor.public_key)
        .map_err(|_| "audit profile: response_anchor.public_key is not a key".to_owned())
}
