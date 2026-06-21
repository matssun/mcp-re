//! Declared revocation tier (ADR-MCPS-021, Axis 2).
//!
//! ADR-MCPS-021 names three storage tiers for shared trust/key-status state, each
//! with a *different* revocation-propagation guarantee:
//!
//! - **Tier 1 — bounded-cache eventual.** A verifier may serve cached *active*
//!   trust state for at most the trust-propagation window `T`; revocation is
//!   enforced fleet-wide within `T`, then fails closed. This is the default
//!   posture and is implemented by [`BoundedTrustCache`](crate::BoundedTrustCache).
//! - **Tier 2 — live strong check.** The resolver consults the shared store on
//!   *every* verification (no positive-trust caching) — near-zero propagation
//!   window, at the cost of a store round-trip per request and a hard dependency
//!   on trust-store availability. Implemented by
//!   [`LiveTrustResolver`](crate::LiveTrustResolver).
//! - **Tier 3 — push invalidation.** Caching is allowed (like Tier 1), but a
//!   revocation event invalidates affected entries immediately via an injected
//!   channel. CRITICAL: if the channel is unhealthy it MUST fall back to the
//!   bounded `T` — so its honest guarantee is *near-zero with bounded-`T`
//!   fallback*, NEVER "zero window" (an in-process reference channel does not
//!   prove reliable ordering/delivery). Implemented by
//!   [`PushInvalidationTrustCache`](crate::PushInvalidationTrustCache).
//!
//! This module makes the tier a first-class value carrying the **semantic name**
//! operators quote and the tier's **own honest one-line guarantee**. The proxy
//! surfaces THIS string as its revocation claim; because it is the tier's own
//! guarantee — never a hardcoded stronger one — the proxy **cannot over-claim**
//! the window by construction (the "tier-claim ceiling"). This mirrors
//! [`ReplayDurabilityTier`](crate::ReplayDurabilityTier) for Axis 1.
//!
//! Honesty rule (load-bearing): no tier's guarantee may be described as
//! "zero-window" unless its mechanism proves reliable ordering/delivery. The
//! reference Push channel does not, so [`RevocationTier::Push`] surfaces the
//! near-zero+fallback string — guarded by a unit test.

/// The declared revocation tier of a fleet's shared trust state (ADR-MCPS-021).
///
/// A **deployment assertion** of how strong a revocation-propagation window the
/// operator has wired. The proxy verifies the behavior it controls (Tier 2 never
/// caches positive trust; Tier 3 evicts on a pushed event and degrades to bounded
/// `T` on channel failure) and surfaces the tier's guarantee, but it cannot
/// surface a window stronger than the configured tier proves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationTier {
    /// **Tier 1.** Bounded-cache eventual trust: cached *active* state lives at
    /// most `T` seconds; revocation enforced fleet-wide within `T`, then fail
    /// closed. The default posture.
    BoundedCache {
        /// The trust-propagation window `T` (seconds): the max age of cached
        /// active/revoked state and the documented revocation exposure window.
        t_secs: i64,
    },

    /// **Tier 2.** Live strong check: the store is consulted on every
    /// verification (no positive-trust caching). Near-zero propagation window, at
    /// the cost of a per-request store round-trip and a hard availability
    /// dependency (store unavailability fails closed).
    Live,

    /// **Tier 3.** Push invalidation: caching is allowed (bounded `T`), but a
    /// revocation event evicts affected entries immediately. On invalidation-
    /// channel failure it falls back to bounded `T`. NOT "zero window" — the
    /// reference channel does not prove reliable ordering/delivery, so the honest
    /// guarantee is near-zero with bounded-`T` fallback.
    Push {
        /// The bounded-`T` fallback window (seconds) used when the invalidation
        /// channel is healthy AND, critically, the *ceiling* an entry may live if
        /// the channel goes unhealthy and a push is missed.
        t_secs: i64,
    },
}

impl RevocationTier {
    /// Parse an operator-supplied `--revocation-tier` value into a tier.
    ///
    /// Accepted forms (case-insensitive):
    /// - `bounded-cache:<t_secs>` (e.g. `bounded-cache:60`) — Tier 1
    /// - `live` — Tier 2
    /// - `push:<t_secs>` (e.g. `push:60`) — Tier 3 (bounded-`T` fallback window)
    ///
    /// Returns a human-readable error string (no panics) so the CLI can fail
    /// closed with a precise message. A non-positive `t_secs` is rejected
    /// (ADR-MCPS-021 compliance: reject `T` ≤ 0) so a malformed window can never
    /// silently widen or disable the exposure bound.
    pub fn parse(value: &str) -> Result<RevocationTier, String> {
        let lower = value.trim().to_lowercase();
        if lower == "live" {
            return Ok(RevocationTier::Live);
        }
        if let Some(rest) = lower.strip_prefix("bounded-cache") {
            let t_secs = Self::parse_window(rest, value, "bounded-cache")?;
            return Ok(RevocationTier::BoundedCache { t_secs });
        }
        if let Some(rest) = lower.strip_prefix("push") {
            let t_secs = Self::parse_window(rest, value, "push")?;
            return Ok(RevocationTier::Push { t_secs });
        }
        Err(format!(
            "unknown revocation tier '{value}' (expected bounded-cache:<t_secs> | live | \
             push:<t_secs>)"
        ))
    }

    /// Parse the `:<t_secs>` suffix shared by the `bounded-cache` and `push`
    /// tiers, enforcing a strictly-positive window (ADR-MCPS-021: reject `T` ≤ 0).
    fn parse_window(rest: &str, original: &str, tier: &str) -> Result<i64, String> {
        let mut parts = rest.split(':');
        // After the prefix the first split element is the empty string before ':'.
        if parts.next() != Some("") {
            return Err(format!(
                "{tier} requires ':<t_secs>' (got '{original}')"
            ));
        }
        let t_secs = parts
            .next()
            .and_then(|t| t.parse::<i64>().ok())
            .filter(|t| *t >= 1)
            .ok_or_else(|| {
                format!("{tier} t_secs must be a positive integer (in '{original}')")
            })?;
        if parts.next().is_some() {
            return Err(format!(
                "{tier} takes exactly ':<t_secs>' (got '{original}')"
            ));
        }
        Ok(t_secs)
    }

    /// The semantic wire name operators quote (ADR-MCPS-021). Stable, uppercase,
    /// backend-agnostic — used in config, startup logs, and audit records.
    pub fn wire_name(&self) -> &'static str {
        match self {
            RevocationTier::BoundedCache { .. } => "BOUNDED_CACHE",
            RevocationTier::Live => "LIVE",
            RevocationTier::Push { .. } => "PUSH",
        }
    }

    /// The honest one-line guarantee this tier supports (ADR-MCPS-021 storage-tier
    /// table). The proxy surfaces THIS string as its revocation claim; because it
    /// is the tier's own guarantee — never a hardcoded stronger one — the proxy
    /// cannot surface a window stronger than the configured tier proves
    /// (tier-claim ceiling).
    ///
    /// CRITICAL honesty rule: [`RevocationTier::Push`] is NEVER described as
    /// "zero window" — the reference invalidation channel does not prove reliable
    /// ordering/delivery, so its claim is "near-zero with bounded-`T` fallback".
    pub fn guarantee(&self) -> &'static str {
        match self {
            RevocationTier::BoundedCache { .. } => {
                "revocation enforced fleet-wide within the bounded window T; on \
                 store outage cached active state is usable only until T, then \
                 fail closed; NOT zero-window / NOT live / NOT push"
            }
            RevocationTier::Live => {
                "near-zero revocation window: the store is consulted on every \
                 verification with no positive-trust caching, at the cost of a \
                 per-request store round-trip and a hard availability dependency \
                 (store unavailability fails closed); NOT proven zero-window"
            }
            RevocationTier::Push { .. } => {
                "near-zero revocation window with bounded-T fallback: a pushed \
                 revocation evicts affected entries immediately, but on \
                 invalidation-channel failure entries fall back to expiry within \
                 the bounded window T; NOT zero-window (the reference channel does \
                 not prove reliable ordering/delivery)"
            }
        }
    }

    /// The structured startup/audit line ADR-MCPS-021 implies the proxy should log
    /// for the configured revocation tier: the backend label, the declared tier
    /// wire name, and the honest surfaced guarantee. Carries NO key material.
    pub fn startup_audit_line(&self, backend: &str) -> String {
        format!(
            "trust-store backend={backend} revocation-tier={} guarantee=\"{}\"",
            self.wire_name(),
            self.guarantee()
        )
    }

    /// Whether this tier's surfaced guarantee claims a zero / instantaneous window.
    /// ALWAYS `false`: ADR-MCPS-021's claim matrix forbids a zero-window claim in
    /// v0.4's in-process reference implementation (no tier here proves reliable
    /// ordering/delivery). Exposed so callers and tests can assert the honesty
    /// boundary explicitly rather than re-parsing the guarantee string.
    pub fn claims_zero_window(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::RevocationTier;

    fn all_tiers() -> Vec<RevocationTier> {
        vec![
            RevocationTier::BoundedCache { t_secs: 60 },
            RevocationTier::Live,
            RevocationTier::Push { t_secs: 60 },
        ]
    }

    #[test]
    fn parse_round_trips_each_tier() {
        assert_eq!(
            RevocationTier::parse("bounded-cache:60"),
            Ok(RevocationTier::BoundedCache { t_secs: 60 })
        );
        assert_eq!(RevocationTier::parse("LIVE"), Ok(RevocationTier::Live));
        assert_eq!(
            RevocationTier::parse("  push:30  "),
            Ok(RevocationTier::Push { t_secs: 30 })
        );
    }

    #[test]
    fn parse_rejects_unknown_and_malformed() {
        assert!(RevocationTier::parse("ocsp").is_err());
        // Missing window suffix.
        assert!(RevocationTier::parse("bounded-cache").is_err());
        assert!(RevocationTier::parse("push").is_err());
        // ADR-MCPS-021: reject T <= 0 — a malformed window must never widen or
        // disable the exposure bound.
        assert!(RevocationTier::parse("bounded-cache:0").is_err());
        assert!(RevocationTier::parse("push:0").is_err());
        assert!(RevocationTier::parse("bounded-cache:-5").is_err());
        // Trailing garbage.
        assert!(RevocationTier::parse("push:30:9").is_err());
        assert!(RevocationTier::parse("bounded-cache:two").is_err());
    }

    #[test]
    fn wire_names_are_the_semantic_adr_names() {
        assert_eq!(
            RevocationTier::BoundedCache { t_secs: 60 }.wire_name(),
            "BOUNDED_CACHE"
        );
        assert_eq!(RevocationTier::Live.wire_name(), "LIVE");
        assert_eq!(RevocationTier::Push { t_secs: 60 }.wire_name(), "PUSH");
    }

    #[test]
    fn every_tier_has_a_nonempty_guarantee() {
        for tier in all_tiers() {
            assert!(
                !tier.guarantee().is_empty(),
                "{} must carry an honest guarantee string",
                tier.wire_name()
            );
        }
    }

    #[test]
    fn each_tier_surfaces_its_own_distinct_guarantee() {
        // The tier-claim ceiling: each tier surfaces its OWN string, so a weaker
        // tier can never accidentally surface a stronger tier's window.
        let bounded = RevocationTier::BoundedCache { t_secs: 60 }.guarantee();
        let live = RevocationTier::Live.guarantee();
        let push = RevocationTier::Push { t_secs: 60 }.guarantee();
        assert_ne!(bounded, live);
        assert_ne!(bounded, push);
        assert_ne!(live, push);
        // Tier 1 explicitly disclaims the stronger postures.
        assert!(bounded.contains("NOT zero-window"));
        assert!(bounded.contains("NOT live"));
    }

    #[test]
    fn no_tier_claims_a_zero_window_unless_proven() {
        // CRITICAL honesty rule (ADR-MCPS-021): no tier in the v0.4 in-process
        // reference implementation may claim a zero / instantaneous window.
        for tier in all_tiers() {
            assert!(
                !tier.claims_zero_window(),
                "{} must not claim a zero window in the reference implementation",
                tier.wire_name()
            );
            let g = tier.guarantee().to_lowercase();
            // The literal phrase "zero-window" only ever appears negated.
            let negated_everywhere = g
                .match_indices("zero-window")
                .all(|(i, _)| g[..i].ends_with("not ") || g[..i].ends_with("not proven "));
            assert!(
                negated_everywhere,
                "{} must never assert a zero-window claim un-negated",
                tier.wire_name()
            );
        }
    }

    #[test]
    fn push_guarantee_is_near_zero_with_bounded_fallback_not_zero_window() {
        // The load-bearing Push honesty assertion: the surfaced string is the
        // near-zero+bounded-fallback claim, never the bare zero-window claim.
        let push = RevocationTier::Push { t_secs: 60 }.guarantee();
        assert!(push.contains("near-zero"));
        assert!(push.contains("bounded-T fallback"));
        assert!(push.contains("NOT zero-window"));
    }

    #[test]
    fn live_guarantee_is_near_zero_with_hard_availability_dependency() {
        let live = RevocationTier::Live.guarantee();
        assert!(live.contains("near-zero"));
        assert!(live.contains("every verification"));
        assert!(live.contains("fails closed"));
    }

    #[test]
    fn startup_audit_line_carries_backend_tier_and_guarantee_no_key_material() {
        let line = RevocationTier::Live.startup_audit_line("redis");
        assert!(line.contains("backend=redis"));
        assert!(line.contains("revocation-tier=LIVE"));
        assert!(line.contains("guarantee="));
        // No key/secret material may leak into the startup line.
        assert!(!line.to_lowercase().contains("key-"));
        assert!(!line.to_lowercase().contains("secret"));
    }
}
