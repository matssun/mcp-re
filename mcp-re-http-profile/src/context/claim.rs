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
use crate::evidence::RequestEvidenceDigest;
use crate::ids::VERIFIED_CONTEXT_BLOCK_KEY;

use super::block_schema::BlockSchema;

/// A verified-context block as READ from a body — an assertion, not a conclusion.
///
/// Distinct from [`super::VerifiedContext`] because the two have different evidence
/// behind them and one type carrying both would say neither. A
/// [`super::VerifiedContext`] exists only because this crate's verifier produced
/// it; one of these exists because some bytes deserialized.
///
/// EVERY member this PEP writes is REQUIRED here, so a block missing one fails
/// closed as malformed rather than arriving with a field quietly defaulted, and
/// `deny_unknown_fields` refuses a decorated one.
///
/// # One representation, declared (Owner Ruling 8)
///
/// `audience` and `request_expires` used to be `Option` + `serde(default)`, to
/// accept blocks written before those members existed. The block carried no shape
/// discriminator, so "omitted because the writer predates the member" and "omitted
/// deliberately" were the same bytes and the tolerance could never be withdrawn —
/// there was nothing it could be withdrawn ON. On a block whose only integrity is
/// the channel's isolation, that left any writer able to hand a consumer no
/// audience constraint and no bound at will.
///
/// [`BlockSchema`] closes it. The block declares its own shape, exactly one shape is
/// current, and a claim holding one has already had that checked. There is no
/// absence-as-v1, no legacy parser and no second reader: when the representation
/// changes, the constant changes and the tree migrates atomically.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnauthenticatedContextClaim {
    /// Evidence that the block declared the current representation.
    ///
    /// First in the struct, which is where a reader looks for it — NOT a claim about
    /// evaluation order: serde visits a JSON object's members in the order the INPUT
    /// carries them, so a block putting the discriminator last has its other members
    /// visited first. That costs nothing, because a wrong or missing discriminator
    /// fails the whole deserialization and no partial value escapes.
    block_schema: BlockSchema,
    profile: String,
    actor_id: String,
    key_id: String,
    audience: AudienceTuple,
    request_evidence: RequestEvidenceDigest,
    verified_at: i64,
    request_expires: i64,
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

    /// The audience tuple the block CLAIMS the request was bound to. Present
    /// unconditionally: a block that omitted it is not a block this reader produces.
    pub fn claimed_audience(&self) -> &AudienceTuple {
        &self.audience
    }

    /// The request-evidence handle the block claims.
    pub fn claimed_request_evidence(&self) -> &RequestEvidenceDigest {
        &self.request_evidence
    }

    /// The instant the block claims a PEP verified the request.
    pub fn claimed_verified_at(&self) -> i64 {
        self.verified_at
    }

    /// The signature expiry the block CLAIMS its conclusion was drawn under — the
    /// bound a consumer needs to decide whether this is still a conclusion at all.
    ///
    /// Present unconditionally, which is what the discriminator bought: a consumer no
    /// longer has an absent case to handle permissively. It is still only a claim.
    pub fn claimed_request_expires(&self) -> i64 {
        self.request_expires
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
    use super::super::block_schema::VERIFIED_CONTEXT_BLOCK_SCHEMA;
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
            "block_schema": VERIFIED_CONTEXT_BLOCK_SCHEMA,
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

    fn without(member: &str) -> serde_json::Value {
        let mut block = full_block();
        block
            .as_object_mut()
            .expect("object fixture")
            .remove(member);
        block
    }

    /// POSITIVE CONTROL: an ordinary complete block still reads, through every
    /// projection.
    #[test]
    fn a_complete_block_reads_through_the_claimed_projections() {
        let claim = extract_verified_context(&body_with(full_block())).expect("a complete block");
        assert_eq!(claim.claimed_profile(), "p");
        assert_eq!(claim.claimed_key_id(), "k");
        assert_eq!(claim.claimed_verified_at(), 1_700_000_100);
        assert_eq!(claim.claimed_request_expires(), 1_700_000_300);
        assert_eq!(claim.claimed_request_evidence().digest_value, "AAAA");
        assert_eq!(claim.claimed_audience().audience_id, "aud");
    }

    /// OWNER RULING 8: a MISSING discriminator is refused. It is the case
    /// absence-as-v1 would have admitted, and the one the ruling names first.
    #[test]
    fn a_block_with_no_schema_discriminator_is_refused() {
        assert!(
            extract_verified_context(&body_with(without("block_schema"))).is_err(),
            "a block that does not declare its shape is not a block this reader accepts"
        );
    }

    /// OWNER RULING 8: an UNKNOWN discriminator is refused rather than read as the
    /// current shape. A required field cannot state this half.
    #[test]
    fn a_block_declaring_another_schema_is_refused() {
        for declared in [
            serde_json::json!("se.syncom/mcp-re.verified-context/2"),
            serde_json::json!("se.syncom/mcp-re.verified-context"),
            serde_json::json!(""),
            serde_json::json!(1),
        ] {
            let mut block = full_block();
            block
                .as_object_mut()
                .expect("object fixture")
                .insert("block_schema".to_owned(), declared.clone());
            assert!(
                extract_verified_context(&body_with(block)).is_err(),
                "{declared}: a schema this build does not write must not read as the one it does"
            );
        }
    }

    /// An omitted audience is REFUSED, not read as "no audience constraint".
    ///
    /// This was the compatibility window: the member was `Option` + `serde(default)`
    /// so a block omitting it parsed and handed the consumer an absent variant. The
    /// discriminator is what makes refusing it correct rather than a rolling-upgrade
    /// outage — a block declaring the current schema and omitting the member is
    /// malformed by definition.
    #[test]
    fn an_omitted_audience_is_refused() {
        assert!(extract_verified_context(&body_with(without("audience"))).is_err());
    }

    /// The same, for the bound: a block declaring the current schema with no
    /// `request_expires` is malformed, so no consumer is ever handed a claim with no
    /// bound at all.
    #[test]
    fn a_block_without_an_expiry_is_refused() {
        assert!(extract_verified_context(&body_with(without("request_expires"))).is_err());
    }

    /// A block missing a member this PEP always writes is malformed, not defaulted —
    /// which since Owner Ruling 8 is EVERY member.
    #[test]
    fn a_block_missing_a_required_member_fails_closed() {
        for member in [
            "block_schema",
            "profile",
            "actor_id",
            "key_id",
            "audience",
            "request_evidence",
            "verified_at",
            "request_expires",
        ] {
            assert!(
                extract_verified_context(&body_with(without(member))).is_err(),
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
