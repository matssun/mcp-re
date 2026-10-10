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
//! coherent. So holding one means its audience tuple, delegation window, response anchor
//! and transparency-service key lifecycles were checked — the projections below re-decide
//! nothing.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// The profile AS WRITTEN, and the one check that turns it into a profile.
mod document;

use document::coherent;
use document::transparency_key_lifecycles;
use document::AuditProfileDocument;

use mcp_re_core::VerificationKey;
use mcp_re_http_profile::scitt::TransparencyKeyLifecycle;
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
    /// The transparency-service key lifecycles, by `kid`, each checked at construction.
    ts_keys: BTreeMap<String, TransparencyKeyLifecycle>,
}

impl TryFrom<AuditProfileDocument> for AuditProfile {
    type Error = String;

    fn try_from(document: AuditProfileDocument) -> Result<Self, Self::Error> {
        let anchor_key = coherent(&document)?;
        let revoked = document.revoked_key_ids.iter().cloned().collect();
        let ts_keys = transparency_key_lifecycles(&document)?;
        Ok(AuditProfile {
            document,
            anchor_key,
            revoked,
            ts_keys,
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

    /// The lifecycle this profile states for transparency-service key `kid`, if any.
    ///
    /// Distinct from [`Self::is_revoked`]: that set names chain keys, and this names the
    /// keys a transparency service signs receipts with.
    pub(in crate::transparency::auditor) fn transparency_key_lifecycle(
        &self,
        kid: &str,
    ) -> Option<&TransparencyKeyLifecycle> {
        self.ts_keys.get(kid)
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

    /// One way of breaking a document, applied to a copy of the legal one.
    type Break = fn(&mut serde_json::Value);

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
        let cases: [(&str, Break); 7] = [
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

    /// Each stated lifecycle is projected by its `kid`, and an unnamed key has none.
    #[test]
    fn a_transparency_key_lifecycle_is_projected_by_its_kid() {
        let mut d = document();
        d["transparency_service_keys"] = serde_json::json!([
            { "kid": "ts-1", "valid_from": 100 },
            { "kid": "ts-2", "valid_from": 100, "valid_until": 200, "revoked_at": 150 },
        ]);
        let profile = parse(&d).expect("a legal profile");
        let open = profile.transparency_key_lifecycle("ts-1").expect("stated");
        assert_eq!(open.admits_at(1_000), Ok(()));
        let revoked = profile.transparency_key_lifecycle("ts-2").expect("stated");
        assert!(revoked.admits_at(150).is_err());
        assert!(profile.transparency_key_lifecycle("ts-3").is_none());
        assert!(parse(&document())
            .expect("absent means none")
            .transparency_key_lifecycle("ts-1")
            .is_none());
    }

    /// An inverted window, a duplicate kid, an empty kid and an unknown member are refused
    /// at construction, never left for registration to trip over.
    #[test]
    fn an_incoherent_transparency_key_lifecycle_never_becomes_a_profile() {
        for (what, keys) in [
            (
                "valid_until",
                serde_json::json!([{ "kid": "ts-1", "valid_from": 100, "valid_until": 100 }]),
            ),
            (
                "revoked_at",
                serde_json::json!([{ "kid": "ts-1", "valid_from": 100, "revoked_at": 99 }]),
            ),
            (
                "duplicate",
                serde_json::json!([
                    { "kid": "ts-1", "valid_from": 100 },
                    { "kid": "ts-1", "valid_from": 100, "revoked_at": 100 },
                ]),
            ),
            (
                "empty kid",
                serde_json::json!([{ "kid": "", "valid_from": 100 }]),
            ),
            (
                "unknown member",
                serde_json::json!([{ "kid": "ts-1", "valid_from": 100, "expires": 200 }]),
            ),
            ("missing valid_from", serde_json::json!([{ "kid": "ts-1" }])),
        ] {
            let mut d = document();
            d["transparency_service_keys"] = keys;
            assert!(parse(&d).is_err(), "{what}: must not become a profile");
        }
    }
}
