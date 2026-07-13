// SPDX-License-Identifier: Apache-2.0
//! HTTP-profile replay key (ADR-MCPRE-050 §Threat Model, MCPRE-94).
//!
//! The replay key is the five-tuple ratified 2026-07-07:
//!
//! ```text
//! (profile_id, signature_label, actor_id, audience_hash, nonce)
//! ```
//!
//! It extends the native profile's `(signer, audience, nonce)` triple with the
//! profile id and the RFC 9421 signature label, so evidence produced under a
//! different profile or a different signature role can never satisfy a replay
//! check against another. Rather than widen the core [`ReplayCache`] trait (and
//! every native caller), the five-tuple is pre-serialized INJECTIVELY onto the
//! trait's existing three slots — the existing cache tiers, their fail-closed
//! `replay_cache_unavailable` semantics, and their self-declared durability
//! class are reused verbatim (ADR-MCPS-020).
//!
//! Freshness (`created`/`expires`) and the `nonce` come from the RFC 9421
//! signature parameters. DPoP `jti` is a SEPARATE mechanism and never
//! substitutes into this key.

use mcp_re_core::ReplayCache;
use mcp_re_core::ReplayCacheError;
use mcp_re_core::ReplayDecision;

/// Field separator for the composite slots. `0x1F` (unit separator) cannot
/// appear in a profile id, an RFC 9421 label, an escaped `actor_id`, or a
/// base64url `audience_hash`, so the join is injective: equality of the
/// composite slots holds iff the full five-tuple is equal.
const SEP: char = '\u{1f}';

/// The five components of an HTTP-profile replay key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpReplayKey {
    /// The signed profile id (`mcp-re-http-v1`).
    pub profile_id: String,
    /// The RFC 9421 signature label (`mcp-re` / `mcp-re-response`).
    pub signature_label: String,
    /// The resolved-actor identity (see [`crate::ActorIdentity::actor_id`]).
    pub actor_id: String,
    /// SHA-256 over the canonical audience tuple (see
    /// [`crate::AudienceTuple::audience_hash`]).
    pub audience_hash: String,
    /// The RFC 9421 `nonce` signature parameter.
    pub nonce: String,
}

impl HttpReplayKey {
    /// The composite `signer` slot: `profile_id ⟴ signature_label ⟴ actor_id`.
    fn signer_slot(&self) -> String {
        format!(
            "{}{SEP}{}{SEP}{}",
            self.profile_id, self.signature_label, self.actor_id
        )
    }

    /// The composite `audience` slot: the audience hash (already opaque).
    fn audience_slot(&self) -> &str {
        &self.audience_hash
    }

    /// Check-and-insert this key against a shared cache tier. `expires_at_unix`
    /// is the RFC 9421 `expires` value; the tier adds its own clock skew to
    /// compute retention. Fail-closed: an operational cache failure surfaces as
    /// [`ReplayCacheError`] (mapped to `replay_cache_unavailable` upstream),
    /// never as an admit.
    pub fn check_and_insert(
        &self,
        cache: &dyn ReplayCache,
        expires_at_unix: i64,
    ) -> Result<ReplayDecision, ReplayCacheError> {
        cache.check_and_insert(
            &self.signer_slot(),
            self.audience_slot(),
            &self.nonce,
            expires_at_unix,
        )
    }

    /// Project this five-tuple onto the core [`mcp_re_core::ReplayKey`] the
    /// AUTHORITATIVE async replay tier (ADR-MCPRE-051 §4) consumes.
    ///
    /// The async tier (`AsyncReplayTier::check_and_insert`) derives its store key
    /// from `(signer, audience, nonce)` via the same `composite_replay_key`
    /// serialization the sync [`ReplayCache`] uses, so feeding it the injective
    /// composite slots ([`signer_slot`](Self::signer_slot) /
    /// [`audience_slot`](Self::audience_slot)) yields a store key BYTE-IDENTICAL to
    /// the sync path — the HTTP-profile serving path awaits the same authoritative
    /// tier the object path did, with the profile id + signature label folded into
    /// the signer slot so evidence from a different profile/role can never satisfy
    /// another's replay check. `expires_at_unix` is the RFC 9421 `expires`
    /// parameter (the tier folds its own clock skew onto it).
    pub fn to_core_replay_key(&self, expires_at_unix: i64) -> mcp_re_core::ReplayKey {
        mcp_re_core::ReplayKey {
            signer: self.signer_slot(),
            audience: self.audience_slot().to_owned(),
            nonce: self.nonce.clone(),
            expires_at_unix,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_re_core::InMemoryReplayCache;

    const EXPIRES: i64 = 1_000;

    fn key() -> HttpReplayKey {
        HttpReplayKey {
            profile_id: "mcp-re-http-v1".into(),
            signature_label: "mcp-re".into(),
            actor_id: "host:example.com:did%3Aexample%3Ahost:client-key-1".into(),
            audience_hash: "AAAABBBBCCCC".into(),
            nonce: "nonce-1".into(),
        }
    }

    fn admit(cache: &InMemoryReplayCache, k: &HttpReplayKey) -> ReplayDecision {
        k.check_and_insert(cache, EXPIRES)
            .expect("cache never errors")
    }

    #[test]
    fn first_insert_is_fresh_replay_is_detected() {
        let cache = InMemoryReplayCache::new(0);
        assert_eq!(admit(&cache, &key()), ReplayDecision::Fresh);
        assert_eq!(admit(&cache, &key()), ReplayDecision::Replay);
    }

    /// Each of the five components discriminates: a request differing only in
    /// that component is admitted, never merged onto the prior key.
    #[test]
    fn every_component_discriminates() {
        let variants: [(&str, fn(&mut HttpReplayKey)); 5] = [
            ("profile_id", |k| k.profile_id = "mcp-re-http-v2".into()),
            ("signature_label", |k| {
                k.signature_label = "mcp-re-response".into()
            }),
            ("actor_id", |k| {
                k.actor_id = "server:example.com:did%3Aexample%3Aserver:server-key-1".into()
            }),
            ("audience_hash", |k| k.audience_hash = "ZZZZ".into()),
            ("nonce", |k| k.nonce = "nonce-2".into()),
        ];
        for (name, mutate) in variants {
            let cache = InMemoryReplayCache::new(0);
            assert_eq!(
                admit(&cache, &key()),
                ReplayDecision::Fresh,
                "{name}: seed"
            );
            let mut other = key();
            mutate(&mut other);
            assert_eq!(
                admit(&cache, &other),
                ReplayDecision::Fresh,
                "{name}: a request differing only in {name} must be admitted"
            );
        }
    }

    /// The core `ReplayKey` projection carries the SAME three injective slots the
    /// sync `ReplayCache` path uses, so the authoritative async tier stores a
    /// byte-identical composite key — the HTTP profile natively reuses the standard
    /// §4 replay tier, no separate keyspace.
    #[test]
    fn core_replay_key_carries_the_same_injective_slots() {
        let k = key();
        let core = k.to_core_replay_key(EXPIRES);
        assert_eq!(
            core.signer,
            "mcp-re-http-v1\u{1f}mcp-re\u{1f}host:example.com:did%3Aexample%3Ahost:client-key-1"
        );
        assert_eq!(core.audience, "AAAABBBBCCCC");
        assert_eq!(core.nonce, "nonce-1");
        assert_eq!(core.expires_at_unix, EXPIRES);
    }

    /// The injective mapping cannot be forged across slot boundaries: shifting a
    /// separator's worth of text between components must not collide.
    #[test]
    fn composite_slots_are_injective() {
        let cache = InMemoryReplayCache::new(0);
        let a = HttpReplayKey {
            actor_id: "a".into(),
            audience_hash: "b".into(),
            ..key()
        };
        // Would collide with `a` only if the separators were forgeable.
        let b = HttpReplayKey {
            profile_id: "mcp-re-http-v1".into(),
            signature_label: "mcp-re".into(),
            actor_id: "a".into(),
            audience_hash: "b".into(),
            nonce: "nonce-1".into(),
        };
        assert_eq!(admit(&cache, &a), ReplayDecision::Fresh);
        // Identical five-tuple → replay (sanity that equality still detects).
        assert_eq!(admit(&cache, &b), ReplayDecision::Replay);
    }
}
