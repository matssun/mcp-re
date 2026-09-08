// SPDX-License-Identifier: Apache-2.0
//! The auditor's TRUST VIEW — authority C.
//!
//! One fact: **which keys this audit treats as legitimate signers, frozen for its whole
//! duration.**
//!
//! # Why this is not `crate::app::build_actor_resolver`
//!
//! That one exists to keep trust LIVE: it reads a reloading snapshot and consults the
//! revocation tier on EVERY request, deliberately caching nothing, so a key removed from
//! the trust file leaves the request-signer set at the same instant it stops resolving.
//! That is correct for a server answering calls it has not seen yet.
//!
//! It is wrong here, and not merely unnecessary. A reconstruction is ONE verdict about a
//! chain of hops; a trust view that could move between hop 0 and hop 2 would produce a
//! label describing no posture that ever existed, and re-running the audit would produce a
//! different one from the same archive. So the view is built once, from documents, and
//! cannot change while a chain is being reconstructed. The audit instant is fixed for the
//! same reason.
//!
//! # What it resolves
//!
//! Request signers come from the deployment's own trust document — reused verbatim, with
//! its own refusals: a `key_id` enrolled twice, an unknown slot and a key not listing
//! `request` are all refused there, and re-implementing that reading here would be a
//! second opinion about one file. The response anchor comes from the audit profile,
//! because a deployment's trust document does not contain its own root key.
//!
//! Revocation is applied HERE as well as at the delegated-credential check, from the one
//! set the profile holds: a key the audit calls revoked must not resolve as an actor
//! either, or the two answers would describe different audits.

use mcp_re_core::TrustResolver;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::ResolverOutcome;
use mcp_re_http_profile::SignerSlot;

use crate::trust_document::TrustDocument;

use super::profile::AuditProfile;

/// The frozen trust view for one audit run.
pub(super) struct AuditorTrustView<'a> {
    profile: &'a AuditProfile,
    /// `key_id -> signer`, for keys the document enrolled in the REQUEST slot.
    request_signers: std::collections::HashMap<String, String>,
    /// `(signer, key_id) -> key`, every enrolled entry.
    keys: mcp_re_core::InMemoryTrustResolver,
}

impl<'a> AuditorTrustView<'a> {
    /// Build the view from the deployment's trust document and this audit's profile.
    ///
    /// The anchor's `key_id` is excluded from the request-signer map by the document's own
    /// projection, so the key that answers for responses can never be presented as a
    /// client credential.
    pub(super) fn new(document: &TrustDocument, profile: &'a AuditProfile) -> Self {
        AuditorTrustView {
            profile,
            request_signers: document.request_signers(profile.anchor_key_id()),
            keys: document.resolver(),
        }
    }

    /// The actor seam `reconstruct_chain` verifies every hop through.
    ///
    /// Fail-closed in every direction: an unknown `key_id`, a revoked one, a signer whose
    /// key the document does not hold, and any slot other than the two named here all
    /// yield no actor, which the verifier surfaces as `actor_binding_failed` and the
    /// reconstruction reports as an unverifiable hop.
    pub(super) fn resolve(&self, kid: &str, slot: SignerSlot) -> ResolverOutcome {
        if self.profile.is_revoked(kid) {
            return ResolverOutcome::NotTrusted;
        }
        match slot {
            SignerSlot::Response if kid == self.profile.anchor_key_id() => self.anchor(slot),
            SignerSlot::Request => self.request_signer(kid, slot),
            _ => ResolverOutcome::NotTrusted,
        }
    }

    /// The deployment's response anchor, as the profile records it.
    fn anchor(&self, slot: SignerSlot) -> ResolverOutcome {
        ResolverOutcome::Resolved(Box::new(ResolvedActor {
            identity: self.profile.anchor_identity(),
            verification_key: self.profile.anchor_key().clone(),
            slot,
        }))
    }

    /// A request signer the trust document enrolled, or nothing.
    ///
    /// Two steps that must both succeed: the document names a SIGNER for this `key_id`,
    /// and it holds a key under that `(signer, key_id)` pair. Either half missing is a
    /// definitive negative — a document that names a signer whose key it does not hold is
    /// not a partial answer to build an actor from.
    fn request_signer(&self, kid: &str, slot: SignerSlot) -> ResolverOutcome {
        let Some(signer) = self.request_signers.get(kid) else {
            return ResolverOutcome::NotTrusted;
        };
        let Ok(key) = self.keys.resolve(signer, kid) else {
            return ResolverOutcome::NotTrusted;
        };
        ResolverOutcome::Resolved(Box::new(ResolvedActor {
            identity: mcp_re_http_profile::ActorIdentity {
                role: "client".to_owned(),
                trust_domain: self.profile.trust_domain().to_owned(),
                subject: signer.clone(),
                keyid: kid.to_owned(),
            },
            verification_key: key,
            slot,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_re_core::SigningKey;

    const ANCHOR_KID: &str = "root-kid";

    fn signing(seed: u8) -> SigningKey {
        SigningKey::from_seed_bytes(&[seed; 32])
    }

    fn profile(revoked: &[&str]) -> AuditProfile {
        let document = serde_json::json!({
            "schema": "mcp-re-audit-profile/v1",
            "trust_domain": "example.com",
            "expected_audience": {
                "audience_id": "verifier-1",
                "target_uri": "https://mcp.example.com/mcp",
            },
            "delegation": {
                "verifier_audiences": ["verifier-1"],
                "expected_audience_hash": "verifier-1",
                "accepted_epochs": ["epoch-1"],
                "max_clock_skew_secs": 60,
            },
            "response_anchor": {
                "subject": "did:example:server",
                "key_id": ANCHOR_KID,
                "public_key": signing(55).public_key().to_b64url(),
            },
            "revoked_key_ids": revoked,
        });
        AuditProfile::parse(&serde_json::to_vec(&document).expect("json")).expect("a profile")
    }

    fn trust_file() -> TrustDocument {
        let json = format!(
            r#"[{{"signer":"did:example:agent-1","key_id":"key-1","public_key":"{}"}},
                {{"signer":"did:example:agent-2","key_id":"key-2","public_key":"{}"}}]"#,
            signing(11).public_key().to_b64url(),
            signing(12).public_key().to_b64url(),
        );
        TrustDocument::parse(json.as_bytes()).expect("a trust document")
    }

    fn resolved(outcome: &ResolverOutcome) -> Option<&ResolvedActor> {
        match outcome {
            ResolverOutcome::Resolved(actor) => Some(actor),
            _ => None,
        }
    }

    #[test]
    fn an_enrolled_request_signer_resolves_with_the_auditors_labels() {
        let profile = profile(&[]);
        let document = trust_file();
        let view = AuditorTrustView::new(&document, &profile);

        let outcome = view.resolve("key-1", SignerSlot::Request);
        let actor = resolved(&outcome).expect("an enrolled request signer resolves");
        assert_eq!(actor.identity.subject, "did:example:agent-1");
        assert_eq!(actor.identity.trust_domain, "example.com");
        assert_eq!(actor.identity.role, "client");
        assert_eq!(
            actor.verification_key.to_b64url(),
            signing(11).public_key().to_b64url(),
        );
    }

    #[test]
    fn the_response_anchor_resolves_only_in_the_response_slot() {
        let profile = profile(&[]);
        let document = trust_file();
        let view = AuditorTrustView::new(&document, &profile);

        let outcome = view.resolve(ANCHOR_KID, SignerSlot::Response);
        let actor = resolved(&outcome).expect("the anchor resolves for responses");
        assert_eq!(
            actor.verification_key.to_b64url(),
            signing(55).public_key().to_b64url(),
        );
        assert_eq!(actor.identity.role, "server");

        // The same kid in the request slot is not a client credential.
        assert!(resolved(&view.resolve(ANCHOR_KID, SignerSlot::Request)).is_none());
        // And no other kid answers for responses.
        assert!(resolved(&view.resolve("key-1", SignerSlot::Response)).is_none());
    }

    /// One revoked set, both consumers. The seam refuses a revoked kid in EVERY slot —
    /// including the anchor's, which is the case a "revocation is for clients" reading
    /// would have missed.
    #[test]
    fn a_revoked_key_resolves_in_no_slot() {
        let profile = profile(&["key-1", ANCHOR_KID]);
        let document = trust_file();
        let view = AuditorTrustView::new(&document, &profile);

        assert!(resolved(&view.resolve("key-1", SignerSlot::Request)).is_none());
        assert!(resolved(&view.resolve(ANCHOR_KID, SignerSlot::Response)).is_none());
        // An unrevoked neighbour still resolves, so the refusal is about the key and not
        // about the view having been switched off.
        assert!(resolved(&view.resolve("key-2", SignerSlot::Request)).is_some());
    }

    #[test]
    fn an_unenrolled_key_id_resolves_to_nothing() {
        let profile = profile(&[]);
        let document = trust_file();
        let view = AuditorTrustView::new(&document, &profile);
        assert!(resolved(&view.resolve("key-99", SignerSlot::Request)).is_none());
    }
}
