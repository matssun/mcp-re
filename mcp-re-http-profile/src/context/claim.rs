// SPDX-License-Identifier: Apache-2.0
//! The read half of the carrier: what an inner server found on its channel.
//!
//! Nothing in this file establishes anything. The block carries no signature by
//! design, so a value read off the channel is worth exactly the channel's own
//! isolation — which is an operator assertion, not a check. The type and every
//! projection on it are named so that a consumer treating one as a conclusion has
//! to write the word "claimed" to do it.

use serde::Deserialize;

use crate::block::AudienceTuple;
use crate::error::HttpProfileError;
use crate::evidence::RequestEvidence;
use crate::ids::VERIFIED_CONTEXT_BLOCK_KEY;

/// A verified-context block as READ from a body — an assertion, not a conclusion.
///
/// Distinct from [`super::VerifiedContext`] because the two have different evidence
/// behind them and one type carrying both would say neither. A
/// [`super::VerifiedContext`] exists only because this crate's verifier produced
/// it; one of these exists because some bytes deserialized.
///
/// Every member this PEP writes is REQUIRED here except `audience` and
/// `request_expires`, so a block missing one of the rest fails closed as malformed
/// rather than arriving with a field quietly defaulted. Those two are optional
/// because a sender may omit them and the honest model of the channel has to be
/// able to say so — see [`ClaimedAudience`] and [`ClaimedExpiry`], whose absent
/// variants a consumer must name before it can proceed.
///
/// # Why the read is WIDER than the write, deliberately
///
/// This PEP always emits both members, so on the producing side neither absent case
/// occurs. The read keeps them because a reader and a writer are not required to be
/// the same build: a rolling upgrade puts an older PEP's blocks in front of a newer
/// reader, and a reader that refused them would turn a deployment sequence into an
/// outage. The cost is stated rather than hidden: the read type accepts a block
/// stating less than this PEP states, and a consumer that treats either absent
/// variant permissively has given itself no audience constraint and no bound. The
/// variants exist so that reading is a decision a consumer writes down.
///
/// Closing the window needs a block-shape version member, so that "written before
/// the member existed" becomes a fact the reader can decide rather than infer. That
/// is a change to the verified-context WIRE SCHEMA, which ADR-MCPS-008 governs and
/// `docs/architecture/authorization.md` defers by name, so it is not made here.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnauthenticatedContextClaim {
    profile: String,
    actor_id: String,
    key_id: String,
    #[serde(default)]
    audience: Option<AudienceTuple>,
    request_evidence: RequestEvidence,
    verified_at: i64,
    #[serde(default)]
    request_expires: Option<i64>,
}

/// What a received block says about audience, including that it said nothing.
///
/// [`ClaimedAudience::NotStated`] means the sender omitted the member. It does NOT
/// mean "no audience constraint": a consumer holding this variant has been told
/// nothing at all about which audience the block's author had in mind, and silence
/// on the value that binds an identity to a target is not a permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimedAudience<'a> {
    /// The block stated an audience tuple. It is still only a claim.
    Stated(&'a AudienceTuple),
    /// The block carried no audience member.
    NotStated,
}

/// What a received block says about the expiry of the signature its conclusion was
/// drawn from, including that it said nothing.
///
/// [`ClaimedExpiry::NotStated`] means the sender omitted the member — which a block
/// written before the member existed does. It does NOT mean the conclusion does not
/// expire: a consumer holding this variant has been given no bound at all, and a
/// claim with no bound is the one a copy can outlive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimedExpiry {
    /// The block stated the signature expiry its conclusion was drawn under. It is
    /// still only a claim.
    Stated(i64),
    /// The block carried no `request_expires` member.
    NotStated,
}

impl UnauthenticatedContextClaim {
    /// The profile the block CLAIMS the request was verified under.
    pub fn claimed_profile(&self) -> &str {
        &self.profile
    }

    /// The actor id the block CLAIMS. Authorizing on it is authorizing on the
    /// channel's isolation, which nothing here checks.
    pub fn claimed_actor_id(&self) -> &str {
        &self.actor_id
    }

    /// The keyid the block claims was presented. Audit correlation only.
    pub fn claimed_key_id(&self) -> &str {
        &self.key_id
    }

    /// What the block says about audience, or that it says nothing.
    pub fn claimed_audience(&self) -> ClaimedAudience<'_> {
        match self.audience.as_ref() {
            Some(tuple) => ClaimedAudience::Stated(tuple),
            None => ClaimedAudience::NotStated,
        }
    }

    /// The request-evidence handle the block claims.
    pub fn claimed_request_evidence(&self) -> &RequestEvidence {
        &self.request_evidence
    }

    /// The instant the block claims a PEP verified the request.
    pub fn claimed_verified_at(&self) -> i64 {
        self.verified_at
    }

    /// What the block says about the signature expiry its conclusion was drawn
    /// under — the bound a consumer needs to decide whether this is still a
    /// conclusion at all, or that the block offered none.
    pub fn claimed_request_expires(&self) -> ClaimedExpiry {
        match self.request_expires {
            Some(expires) => ClaimedExpiry::Stated(expires),
            None => ClaimedExpiry::NotStated,
        }
    }
}

/// Read the verified-context block an inner server was handed.
///
/// ONLY call this on a body that arrived over the explicitly trusted channel. On
/// any other channel the block is an unauthenticated assertion — there is no
/// signature to check, by design — and the return type says so.
pub fn extract_verified_context(
    body: &[u8],
) -> Result<UnauthenticatedContextClaim, HttpProfileError> {
    crate::body::extract_meta_block(body, VERIFIED_CONTEXT_BLOCK_KEY, "verified context")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body_with(block: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "_meta": { VERIFIED_CONTEXT_BLOCK_KEY: block },
        }))
        .expect("fixture serializes")
    }

    fn full_block() -> serde_json::Value {
        serde_json::json!({
            "profile": "p",
            "actor_id": "client:example.com:did%3Aexample%3Aa:k",
            "key_id": "k",
            "audience": {
                "audience_id": "aud",
                "target_uri": "https://example.test/mcp",
            },
            "request_evidence": { "digest_alg": "sha256", "digest_value": "AAAA" },
            "verified_at": 1_700_000_100,
            "request_expires": 1_700_000_300,
        })
    }

    /// POSITIVE CONTROL: an ordinary complete block still reads, through the
    /// projections, with the audience STATED.
    #[test]
    fn a_complete_block_reads_through_the_claimed_projections() {
        let claim = extract_verified_context(&body_with(full_block())).expect("a complete block");
        assert_eq!(claim.claimed_profile(), "p");
        assert_eq!(claim.claimed_key_id(), "k");
        assert_eq!(claim.claimed_verified_at(), 1_700_000_100);
        assert_eq!(
            claim.claimed_request_expires(),
            ClaimedExpiry::Stated(1_700_000_300)
        );
        assert_eq!(claim.claimed_request_evidence().digest_value, "AAAA");
        match claim.claimed_audience() {
            ClaimedAudience::Stated(tuple) => assert_eq!(tuple.audience_id, "aud"),
            ClaimedAudience::NotStated => panic!("the block stated an audience"),
        }
    }

    /// An omitted audience is REPORTED as omitted rather than arriving as a value a
    /// consumer can mistake for "no audience constraint".
    #[test]
    fn an_omitted_audience_is_not_stated_rather_than_absent() {
        let mut block = full_block();
        block
            .as_object_mut()
            .expect("object fixture")
            .remove("audience");
        let claim = extract_verified_context(&body_with(block)).expect("audience is optional");
        assert_eq!(claim.claimed_audience(), ClaimedAudience::NotStated);
    }

    /// COMPATIBILITY POSITIVE CONTROL: a block written without `request_expires` —
    /// which is every block written before the member existed — still reads, and
    /// reads as having said nothing rather than as having said "does not expire".
    #[test]
    fn a_block_without_an_expiry_reads_and_states_nothing_about_one() {
        let mut block = full_block();
        block
            .as_object_mut()
            .expect("object fixture")
            .remove("request_expires");
        let claim =
            extract_verified_context(&body_with(block)).expect("the member is additive, not new");
        assert_eq!(claim.claimed_request_expires(), ClaimedExpiry::NotStated);
        assert_eq!(
            claim.claimed_actor_id(),
            "client:example.com:did%3Aexample%3Aa:k",
            "the rest of the block reads exactly as before"
        );
    }

    /// A block missing a member this PEP always writes is malformed, not defaulted.
    #[test]
    fn a_block_missing_a_required_member_fails_closed() {
        for member in [
            "profile",
            "actor_id",
            "key_id",
            "request_evidence",
            "verified_at",
        ] {
            let mut block = full_block();
            block
                .as_object_mut()
                .expect("object fixture")
                .remove(member);
            assert!(
                extract_verified_context(&body_with(block)).is_err(),
                "{member}: an absent member must not default"
            );
        }
    }

    /// A decorated block fails closed: `deny_unknown_fields` means a sender cannot
    /// smuggle a member past a consumer that reads only the projections.
    #[test]
    fn a_decorated_block_is_refused() {
        let mut block = full_block();
        block
            .as_object_mut()
            .expect("object fixture")
            .insert("role".to_owned(), serde_json::json!("admin"));
        assert!(extract_verified_context(&body_with(block)).is_err());
    }

    #[test]
    fn a_body_without_the_block_reports_the_block_missing() {
        assert!(extract_verified_context(br#"{"jsonrpc":"2.0"}"#).is_err());
    }
}
