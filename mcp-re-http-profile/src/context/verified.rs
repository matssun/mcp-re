// SPDX-License-Identifier: Apache-2.0
//! The PEP's own conclusion — the one type in this module whose possession means
//! something, and the write half of the carrier.

use serde::Serialize;

use crate::block::AudienceTuple;
use crate::error::HttpProfileError;
use crate::evidence::RequestEvidence;
use crate::ids::VERIFIED_CONTEXT_BLOCK_KEY;
use crate::verified_request::VerifiedMcpRequest;

use super::policy::TrustedInnerChannel;
use super::reserved_key_strip::StrippedBody;

/// The PEP's verified conclusion about a request, carried to the inner server.
///
/// Every field is a TRUST-RESOLUTION OUTPUT, not a wire claim, with one stated
/// exception: `verified_at` is the instant the PRODUCER passed in (see
/// [`VerifiedContext::verified_at`]). `actor_id` is the resolved actor the trust
/// seam vouched for — deliberately not the presented `keyid`, which is only a
/// selector and would hand the inner server the one value the caller chose. `key_id`
/// is included for audit correlation and is explicitly labelled as such so nobody
/// authorizes on it.
///
/// **The representation is private to this module and
/// [`VerifiedContext::from_verified`] is its only producer**, which takes a
/// [`VerifiedMcpRequest`]. There is no struct literal, no `Deserialize`, and no
/// mutation: holding one of these means a full-profile verification concluded it,
/// with no trailing clause about what the construction site remembered. What
/// arrives on a channel is [`super::UnauthenticatedContextClaim`] instead, because
/// bytes off a wire establish nothing and must not share a type with this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifiedContext {
    profile: String,
    actor_id: String,
    key_id: String,
    audience: AudienceTuple,
    request_evidence: RequestEvidence,
    verified_at: i64,
    request_expires: i64,
}

impl VerifiedContext {
    /// Build the context from the verifier's own output — the sole producer.
    ///
    /// `verified_at` is the producer's reading, not a measurement this type makes,
    /// and nothing relates it to `request_expires`: the verifier's freshness window
    /// admits a skew, so a check here would refuse requests the verifier admitted.
    /// The two are independent readings, not an ordered pair.
    pub fn from_verified(verified: &VerifiedMcpRequest, verified_at: i64) -> Self {
        VerifiedContext {
            profile: verified.profile_id().to_owned(),
            actor_id: verified.resolved_actor().actor_id(),
            key_id: verified.key_id().to_owned(),
            audience: verified.audience().clone(),
            request_evidence: verified.evidence().clone(),
            verified_at,
            request_expires: verified.expires(),
        }
    }

    /// The profile the request was verified under.
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// The resolved actor id — the identity to authorize on.
    pub fn actor_id(&self) -> &str {
        &self.actor_id
    }

    /// The presented keyid. AUDIT CORRELATION ONLY: a keyid is a selector the
    /// caller chose, never a trust-resolution output. Authorize on
    /// [`VerifiedContext::actor_id`].
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The verified audience tuple.
    ///
    /// Not optional, and it cannot become optional: the only producer takes a
    /// [`VerifiedMcpRequest`], so audience equality ran by construction.
    pub fn audience(&self) -> &AudienceTuple {
        &self.audience
    }

    /// The request evidence handle — the audit correlation key linking whatever
    /// the inner server does to the exact signed request that authorized it.
    pub fn request_evidence(&self) -> &RequestEvidence {
        &self.request_evidence
    }

    /// The instant the producer said it verified the request.
    ///
    /// PRODUCER-ASSERTED: `from_verified` stamps whatever `i64` it is given, so this
    /// is a reading the producer chose and not a measurement. No consumer may build
    /// a freshness check on it; [`VerifiedContext::request_expires`] is the bound
    /// that comes from the verifier's own output.
    pub fn verified_at(&self) -> i64 {
        self.verified_at
    }

    /// The `expires` of the signature this conclusion was drawn from.
    ///
    /// Carried so a consumer CAN bound the conclusion by the request that produced
    /// it instead of treating a copied block as timeless. It is the verified
    /// request's own expiry and nothing more: it is not a trust epoch, and a
    /// revocation after this instant is not visible here.
    pub fn request_expires(&self) -> i64 {
        self.request_expires
    }
}

/// Write the PEP's verified context into the forwarded body under the reserved key
/// (§10), replacing anything that was there.
///
/// Two preconditions, both checked by the compiler:
///
/// - `trusted_channel` is a branch on the deployment policy that took the `Trusted`
///   arm. [`super::VerifiedContextPolicy::trusted_inner_channel`] is its only
///   producer, so a `Disabled` deployment cannot reach this function. What that
///   witness does and does not establish is stated on the type.
/// - `stripped` is a body the §10 guard has walked.
///   [`super::strip_proxy_owned_meta`] is its only producer, so this is "replace"
///   applied to bytes the guard cleaned rather than to bytes a caller supplied.
///
/// # Errors
///
/// [`HttpProfileError::MalformedEvidence`] when the block cannot be written — in
/// particular when the caller's body carries a top-level `_meta` that is not an
/// object, which the guard leaves in place because it can hold no member under the
/// reserved name. That branch is live, not defensive, and failing it is what stops
/// a caller choosing whether the PEP's conclusion is carried.
pub fn insert_verified_context(
    stripped: &StrippedBody,
    context: &VerifiedContext,
    _trusted_channel: TrustedInnerChannel<'_>,
) -> Result<Vec<u8>, HttpProfileError> {
    crate::body::insert_meta_block(stripped.bytes(), VERIFIED_CONTEXT_BLOCK_KEY, context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::ActorIdentity;
    use crate::block::HttpRequestEvidenceBlock;
    use crate::block::ResolvedActor;
    use crate::block::SignerSlot;
    use crate::context::extract_verified_context;
    use crate::context::strip_proxy_owned_meta;
    use crate::context::ClaimedAudience;
    use crate::context::ClaimedExpiry;
    use crate::context::VerifiedContextPolicy;
    use crate::verified_request::floor::CryptographicFloorVerifiedRequest;
    use mcp_re_core::SigningKey;

    fn audience() -> AudienceTuple {
        AudienceTuple {
            audience_id: "aud".into(),
            target_uri: "https://example.test/mcp".into(),
            route: None,
        }
    }

    fn verified_request() -> VerifiedMcpRequest {
        let key = SigningKey::from_seed_bytes(&[7u8; 32]);
        VerifiedMcpRequest {
            floor: CryptographicFloorVerifiedRequest {
                profile_id: "p".into(),
                signature_label: "mcpre".into(),
                resolved_actor: ResolvedActor {
                    identity: ActorIdentity {
                        role: "client".into(),
                        trust_domain: "example.com".into(),
                        subject: "did:example:a".into(),
                        keyid: "k".into(),
                    },
                    verification_key: key.public_key(),
                    slot: SignerSlot::Request,
                },
                evidence: RequestEvidence::from_signature_base(b"base"),
                request_signature_base: b"base".to_vec(),
                content_digest: "sha-256=:x:".into(),
                created: 1_700_000_000,
                expires: 1_700_000_300,
                nonce: "n".into(),
                key_id: "k".into(),
            },
            audience: audience(),
            audience_hash: audience().audience_hash(),
            request_block: HttpRequestEvidenceBlock {
                profile: "p".into(),
                audience: audience(),
                artifact_bindings: Vec::new(),
                continuation: None,
                admission: None,
                admission_assertion: None,
                authorization_decision: None,
            },
        }
    }

    const ORDINARY_BODY: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#;

    fn stripped(body: &[u8]) -> StrippedBody {
        strip_proxy_owned_meta(body).expect("an object body is guarded")
    }

    fn write_block(body: &[u8]) -> Result<Vec<u8>, HttpProfileError> {
        let policy = VerifiedContextPolicy::Trusted;
        let trusted = policy
            .trusted_inner_channel()
            .expect("the trusted deployment yields the capability");
        let ctx = VerifiedContext::from_verified(&verified_request(), 1_700_000_100);
        insert_verified_context(&stripped(body), &ctx, trusted)
    }

    #[test]
    fn the_conclusion_projects_the_resolved_actor_not_the_presented_keyid() {
        let verified = verified_request();
        let ctx = VerifiedContext::from_verified(&verified, 1_700_000_100);
        // EQUALITY against the verifier's own output, not merely inequality with the
        // keyid: the claim is that `actor_id` IS the trust-resolution output, and an
        // inequality is satisfied by every wrong value but one.
        assert_eq!(ctx.actor_id(), verified.resolved_actor().actor_id());
        assert_eq!(ctx.key_id(), verified.key_id());
        assert_ne!(
            ctx.actor_id(),
            ctx.key_id(),
            "actor_id is the trust-resolution output, not the caller's selector"
        );
        assert_eq!(ctx.profile(), verified.profile_id());
        assert_eq!(ctx.audience(), verified.audience());
        assert_eq!(ctx.request_evidence(), verified.evidence());
        assert_eq!(ctx.verified_at(), 1_700_000_100);
    }

    /// The conclusion carries the expiry of the signature it was drawn from, so a
    /// consumer holding a copied block can bound it rather than treat it as timeless.
    #[test]
    fn the_conclusion_carries_the_verified_requests_own_expiry() {
        let ctx = VerifiedContext::from_verified(&verified_request(), 1_700_000_100);
        assert_eq!(ctx.request_expires(), 1_700_000_300);
        assert_eq!(
            ctx.request_expires(),
            verified_request().expires(),
            "the expiry is the verifier's own output, not a value this module chose"
        );
    }

    /// POSITIVE CONTROL for the witness and the stripped-body parameters: a trusted
    /// deployment still writes the block, under the reserved key, on an ordinary body.
    #[test]
    fn a_trusted_deployment_writes_the_block_under_the_reserved_key() {
        let out = write_block(ORDINARY_BODY).expect("an ordinary object body accepts the block");
        let v: serde_json::Value = serde_json::from_slice(&out).expect("json out");
        let ctx = VerifiedContext::from_verified(&verified_request(), 1_700_000_100);
        assert_eq!(
            v["_meta"][VERIFIED_CONTEXT_BLOCK_KEY]["actor_id"],
            serde_json::json!(ctx.actor_id()),
        );
        assert_eq!(v["jsonrpc"], serde_json::json!("2.0"), "the body survives");
    }

    /// What this PEP WRITES, this PEP's reader READS, with nothing NotStated — the
    /// one place in the default lane where the two independently maintained field
    /// lists meet.
    #[test]
    fn what_the_writer_emits_the_reader_accepts_with_nothing_unstated() {
        let out = write_block(ORDINARY_BODY).expect("the block is written");
        let claim = extract_verified_context(&out).expect("the PEP's own block reads");
        let ctx = VerifiedContext::from_verified(&verified_request(), 1_700_000_100);
        assert_eq!(claim.claimed_actor_id(), ctx.actor_id());
        assert_eq!(claim.claimed_profile(), ctx.profile());
        assert_eq!(claim.claimed_key_id(), ctx.key_id());
        assert_eq!(claim.claimed_verified_at(), ctx.verified_at());
        assert_eq!(
            claim.claimed_request_expires(),
            ClaimedExpiry::Stated(ctx.request_expires()),
            "a member the writer always emits must never read as NotStated"
        );
        match claim.claimed_audience() {
            ClaimedAudience::Stated(tuple) => assert_eq!(tuple, ctx.audience()),
            ClaimedAudience::NotStated => panic!("the writer always states its audience"),
        }
    }

    /// A caller-supplied non-object `_meta` occupies the PEP's write position, and
    /// the write FAILS CLOSED on it rather than declining silently. This is the
    /// `Err` arm the composer's fail-closed guarantee rests on, driven.
    #[test]
    fn the_write_fails_closed_when_the_callers_meta_occupies_the_write_position() {
        assert!(write_block(br#"{"jsonrpc":"2.0","_meta":[1,2]}"#).is_err());
        // POSITIVE CONTROL: an OBJECT `_meta` carrying the application's own entry
        // is written into, not refused.
        let out = write_block(br#"{"jsonrpc":"2.0","_meta":{"app.trace":"t-1"}}"#)
            .expect("an object `_meta` accepts the block beside the caller's entry");
        let v: serde_json::Value = serde_json::from_slice(&out).expect("json out");
        assert_eq!(v["_meta"]["app.trace"], serde_json::json!("t-1"));
        assert!(v["_meta"].get(VERIFIED_CONTEXT_BLOCK_KEY).is_some());
    }

    /// The key the insert WRITES is the key the strip REMOVES, through one body.
    ///
    /// The guard names the reserved key; so does the write. Two spellings of one
    /// constant would mean the PEP forwarding a block its own guard walks past, and
    /// nothing else in the tree relates them.
    #[test]
    fn what_the_insert_writes_is_what_the_strip_removes() {
        let written = write_block(ORDINARY_BODY).expect("the block is written");
        // CONTROL: before the strip, the written block is there and readable.
        assert!(extract_verified_context(&written).is_ok());

        let restripped = strip_proxy_owned_meta(&written).expect("the written body is walkable");
        assert!(
            restripped.seeded().top_level(),
            "the strip did not find the key the insert wrote"
        );
        let v: serde_json::Value = serde_json::from_slice(restripped.bytes()).expect("json out");
        assert!(
            v.get("_meta")
                .and_then(|m| m.get(VERIFIED_CONTEXT_BLOCK_KEY))
                .is_none(),
            "the reserved key is absent from `_meta` after the strip"
        );
    }
}
