// SPDX-License-Identifier: Apache-2.0
//! The AUDIT PROFILE — authority B.
//!
//! One fact: **what this auditor asserts about the deployment whose archive it is
//! reading.** An archive of retained messages does not describe the posture they were
//! served under: which audience tuple was expected, which trust epochs were live, which
//! key anchored the responses. Reconstruction needs all of it, and none of it is in the
//! bytes — so it is asserted, by an operator, in a document that can be reviewed and kept
//! beside the run it produced.
//!
//! It is a document rather than a pile of flags for the same reason a trust pin is: an
//! assertion that decides a verdict has to be a thing somebody wrote down. Two audits of
//! one archive that disagree should disagree because their profiles differ, visibly.
//!
//! [`AuditProfile`] is SEALED behind the private `AuditProfileDocument`: `serde` only ever
//! sees the document, and the only way to obtain a profile is to show the document is
//! coherent. So holding one means its audience tuple, delegation window and response
//! anchor were checked — the projections below re-decide nothing.

use std::collections::BTreeSet;

/// The profile AS WRITTEN, and the one check that turns it into a profile.
mod document;

use document::coherent;
use document::AuditProfileDocument;

use mcp_re_core::VerificationKey;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::DelegationExpectations;

/// What this auditor asserts about the deployment it is auditing.
///
/// # What construction proved
///
/// The audience tuple names a target; the delegation window names at least one verifier
/// audience and at least one epoch and a bounded skew; the response anchor's public key
/// decodes. A document failing any of those is not a profile at all, so nothing
/// downstream re-checks them.
///
/// # What is load-bearing here, and what is a label
///
/// The anchor's `key_id` decides a verdict: a response evidence block naming a different
/// `key_id` than the actor the resolver produced is refused. `subject` and `trust_domain`
/// are the auditor's own labels for the identities it resolves — they travel into the
/// reconstruction's identity fields and no comparison turns on them. Stated so an
/// operator writing a profile knows which line matters.
#[derive(Debug, Clone)]
pub struct AuditProfile {
    document: AuditProfileDocument,
    /// Decoded once, at construction, from `document.response_anchor.public_key`.
    anchor_key: VerificationKey,
    /// The revoked set as a set, so membership is a lookup and duplicates in the document
    /// cannot mean anything.
    revoked: BTreeSet<String>,
}

impl TryFrom<AuditProfileDocument> for AuditProfile {
    type Error = String;

    fn try_from(document: AuditProfileDocument) -> Result<Self, Self::Error> {
        let anchor_key = coherent(&document)?;
        let revoked = document.revoked_key_ids.iter().cloned().collect();
        Ok(AuditProfile {
            document,
            anchor_key,
            revoked,
        })
    }
}

impl AuditProfile {
    /// Read a profile from an operator's document bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let document: AuditProfileDocument =
            serde_json::from_slice(bytes).map_err(|e| format!("audit profile: {e}"))?;
        AuditProfile::try_from(document)
    }

    /// The audience tuple every retained hop must equal.
    pub(super) fn expected_audience(&self) -> &AudienceTuple {
        &self.document.expected_audience
    }

    /// The trust domain this auditor labels resolved identities with.
    pub(super) fn trust_domain(&self) -> &str {
        &self.document.trust_domain
    }

    /// The `key_id` the deployment's responses were anchored to.
    pub(super) fn anchor_key_id(&self) -> &str {
        &self.document.response_anchor.key_id
    }

    /// The identity this auditor resolves the response anchor as.
    pub(super) fn anchor_identity(&self) -> ActorIdentity {
        ActorIdentity {
            role: "server".to_owned(),
            trust_domain: self.document.trust_domain.clone(),
            subject: self.document.response_anchor.subject.clone(),
            keyid: self.document.response_anchor.key_id.clone(),
        }
    }

    /// The anchor's verification key.
    ///
    /// INFALLIBLE: the key was decoded at construction, so this returns what the seal
    /// proved rather than re-deciding it.
    pub(super) fn anchor_key(&self) -> &VerificationKey {
        &self.anchor_key
    }

    /// Whether this audit treats `kid` as revoked.
    ///
    /// ONE set, consulted by both consumers — the actor seam and the delegated-credential
    /// check. Two revocation views over one audit could refuse a key in one place and
    /// honour it in the other, and the resulting verdict would describe no posture anyone
    /// asserted.
    pub(super) fn is_revoked(&self, kid: &str) -> bool {
        self.revoked.contains(kid)
    }

    /// Run `f` with the delegation expectations this profile asserts.
    ///
    /// A closure rather than an accessor per field. `DelegationExpectations` borrows four
    /// values that must agree about one window, and handing them out separately would let
    /// a caller assemble a combination the profile never asserted — R-COMPOSE's failure
    /// mode, recreated one field at a time.
    pub(super) fn with_delegation<T>(&self, f: impl FnOnce(&DelegationExpectations<'_>) -> T) -> T {
        let audiences: Vec<&str> = self
            .document
            .delegation
            .verifier_audiences
            .iter()
            .map(String::as_str)
            .collect();
        let epochs: Vec<&str> = self
            .document
            .delegation
            .accepted_epochs
            .iter()
            .map(String::as_str)
            .collect();
        f(&DelegationExpectations {
            verifier_audiences: &audiences,
            expected_audience_hash: &self.document.delegation.expected_audience_hash,
            accepted_epochs: &epochs,
            max_clock_skew: self.document.delegation.max_clock_skew_secs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> String {
        mcp_re_core::SigningKey::from_seed_bytes(&[seed; 32])
            .public_key()
            .to_b64url()
    }

    fn document() -> serde_json::Value {
        serde_json::json!({
            "schema": document::AUDIT_PROFILE_SCHEMA,
            "trust_domain": "example.com",
            "expected_audience": {
                "audience_id": "verifier-1",
                "target_uri": "https://mcp.example.com/mcp?route=a",
                "route": "a",
            },
            "delegation": {
                "verifier_audiences": ["verifier-1"],
                "expected_audience_hash": "verifier-1",
                "accepted_epochs": ["epoch-1"],
                "max_clock_skew_secs": 60,
            },
            "response_anchor": {
                "subject": "did:example:server",
                "key_id": "root-kid",
                "public_key": key(55),
            },
        })
    }

    fn parse(value: &serde_json::Value) -> Result<AuditProfile, String> {
        AuditProfile::parse(&serde_json::to_vec(value).expect("json"))
    }

    #[test]
    fn a_coherent_document_becomes_a_profile() {
        let profile = parse(&document()).expect("a legal profile");
        assert_eq!(profile.anchor_key_id(), "root-kid");
        assert_eq!(profile.trust_domain(), "example.com");
        assert_eq!(profile.expected_audience().audience_id, "verifier-1");
        assert_eq!(profile.anchor_identity().role, "server");
        profile.with_delegation(|expect| {
            assert_eq!(expect.verifier_audiences, ["verifier-1"]);
            assert_eq!(expect.accepted_epochs, ["epoch-1"]);
            assert_eq!(expect.max_clock_skew, 60);
        });
    }

    /// Each of these documents is refused, and none of them becomes a profile that a later
    /// call happens to trip over. That is the seal, stated as the operational test.
    #[test]
    fn an_incoherent_document_never_becomes_a_profile() {
        let cases: [(&str, fn(&mut serde_json::Value)); 7] = [
            ("schema", |d| d["schema"] = "something-else/v1".into()),
            ("audience_id", |d| {
                d["expected_audience"]["audience_id"] = "".into()
            }),
            ("target_uri", |d| {
                d["expected_audience"]["target_uri"] = "".into()
            }),
            ("verifier_audiences", |d| {
                d["delegation"]["verifier_audiences"] = serde_json::json!([])
            }),
            ("accepted_epochs", |d| {
                d["delegation"]["accepted_epochs"] = serde_json::json!([])
            }),
            ("max_clock_skew_secs", |d| {
                d["delegation"]["max_clock_skew_secs"] = serde_json::json!(86_400)
            }),
            ("public_key", |d| {
                d["response_anchor"]["public_key"] = "!!!not-a-key".into()
            }),
        ];
        for (what, break_it) in cases {
            let mut broken = document();
            break_it(&mut broken);
            let refused = parse(&broken);
            assert!(refused.is_err(), "{what}: must not become a profile");
        }
    }

    /// A negative skew is refused too: it is not a stricter window, it is a window whose
    /// end precedes its start.
    #[test]
    fn a_negative_clock_skew_is_refused() {
        let mut d = document();
        d["delegation"]["max_clock_skew_secs"] = serde_json::json!(-1);
        assert!(parse(&d).is_err());
    }

    /// An unknown member is refused rather than ignored, so a typo can never leave an
    /// assertion silently unmade.
    #[test]
    fn an_unknown_member_is_refused() {
        let mut d = document();
        d["revoked_key_ids_typo"] = serde_json::json!(["k"]);
        assert!(parse(&d).is_err());
    }

    /// The revoked set is one fact: what it answers does not depend on which consumer asks.
    #[test]
    fn the_revoked_set_answers_for_the_keys_it_names() {
        let mut d = document();
        d["revoked_key_ids"] = serde_json::json!(["key-1", "key-1", "key-2"]);
        let profile = parse(&d).expect("a legal profile");
        assert!(profile.is_revoked("key-1"));
        assert!(profile.is_revoked("key-2"));
        assert!(!profile.is_revoked("key-3"));
    }
}
