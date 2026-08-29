// SPDX-License-Identifier: Apache-2.0
//! The request-signer currency flags, parsed as one — ADR-MCPRE-067 §16.
//!
//! An operator names `--revocation-tier` and then, flatly, the cadence and the epoch
//! source. The request has one tagged value, so this is the adapter.
//!
//! **Three refusals live here now.** Relation X8 (an epoch source under a tier that never
//! consumes it), the epoch key under such a tier, and the two tiers that require a cadence
//! being given none. All three are unbuildable after assembly, so the parser — the one
//! place that still sees the tier beside the value — answers them, with the sentences the
//! boundary used to.

use crate::deployment_request::{RequestSignerCurrencyRequest, TrustEpochStoreRequest};
use crate::revocation_tier::RevocationTier;

/// The currency inputs, as they accumulate across the argument list.
pub(super) struct CurrencyFlags {
    tier: RevocationTier,
    reload_secs: Option<u64>,
    epoch: TrustEpochStoreRequest,
}

impl Default for CurrencyFlags {
    /// Tier 1 at the deployment-default window, reading `--trust` once — the posture an
    /// absent `--revocation-tier` has always meant.
    fn default() -> Self {
        CurrencyFlags {
            tier: RevocationTier::BoundedCache {
                t_secs: crate::trust_plane::DEFAULT_T_SECS,
            },
            reload_secs: None,
            epoch: TrustEpochStoreRequest::default(),
        }
    }
}

impl CurrencyFlags {
    /// Read `--revocation-tier`.
    pub(super) fn take_tier(&mut self, value: &str) -> Result<(), String> {
        self.tier = RevocationTier::parse(value)?;
        Ok(())
    }

    /// Read `--trust-reload-secs`.
    pub(super) fn take_reload_secs(&mut self, secs: u64) {
        self.reload_secs = Some(secs);
    }

    /// Read the epoch source the storage adapter assembled.
    pub(super) fn take_epoch(&mut self, epoch: TrustEpochStoreRequest) {
        self.epoch = epoch;
    }

    /// The posture this command line names, with its own material.
    pub(super) fn finish(self) -> Result<RequestSignerCurrencyRequest, String> {
        let pushing = matches!(self.tier, RevocationTier::Push { .. });
        if !pushing && self.epoch.source.is_some() {
            // Relation X8. The epoch source drives PUSH invalidation only, so any other
            // tier connects nothing and the deployment would believe a networked trust
            // invalidation is active while nothing consumes it.
            return Err(
                "--trust-epoch-redis-url has no effect under this --revocation-tier: the \
                 networked epoch source drives PUSH invalidation only, so any other tier \
                 connects nothing and the deployment would believe a networked trust \
                 invalidation is active while nothing consumes it. Declare \
                 --revocation-tier push:<t_secs>, or remove --trust-epoch-redis-url"
                    .to_string(),
            );
        }
        Ok(match self.tier {
            RevocationTier::BoundedCache { t_secs } => RequestSignerCurrencyRequest::BoundedCache {
                t_secs,
                reload_secs: self.reload_secs,
            },
            RevocationTier::Live => RequestSignerCurrencyRequest::Live {
                reload_secs: self.required_cadence()?,
            },
            RevocationTier::Push { t_secs } => RequestSignerCurrencyRequest::Push {
                t_secs,
                reload_secs: self.required_cadence()?,
                epoch: self.epoch,
            },
        })
    }

    /// The cadence the two near-zero tiers are inhabited by.
    ///
    /// Absence is argv-shaped: an assembled request always carries one under those tiers,
    /// so only a command line can omit it.
    fn required_cadence(&self) -> Result<u64, String> {
        self.reload_secs.ok_or_else(|| {
            "--revocation-tier live|push requires --trust-reload-secs: both tiers state a \
             revocation window in terms of consulting the trust store, but with --trust read \
             once at startup the store cannot change, so revoking a request-signer key would \
             need a restart of every replica while the startup line claims otherwise"
                .to_string()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deployment_request::TrustEpochSource;

    fn with_epoch(tier: &str) -> CurrencyFlags {
        let mut flags = CurrencyFlags::default();
        flags.take_tier(tier).expect("a known tier");
        flags.take_epoch(TrustEpochStoreRequest {
            source: Some(TrustEpochSource::redis("redis://127.0.0.1:6379", None)),
        });
        flags
    }

    /// X8, answered where the pair is still statable.
    #[test]
    fn an_epoch_source_under_a_tier_that_reads_none_is_refused() {
        for tier in ["bounded-cache:30", "live"] {
            let mut flags = with_epoch(tier);
            flags.take_reload_secs(5);
            let err = flags.finish().expect_err("an epoch nothing consumes");
            assert!(
                err.contains("--trust-epoch-redis-url has no effect"),
                "{err}"
            );
        }
    }

    /// The negative control: under the tier that DOES consume it, the same source is
    /// accepted and travels inside the posture.
    #[test]
    fn the_pushing_tier_carries_the_epoch_source_it_reads() {
        let mut flags = with_epoch("push:30");
        flags.take_reload_secs(5);
        let posture = flags.finish().expect("its own tier");
        assert!(posture.epoch().is_some_and(|epoch| epoch.source.is_some()));
    }

    /// The two near-zero tiers are inhabited by a cadence, so a command line that omits one
    /// names no posture at all.
    #[test]
    fn a_near_zero_tier_without_a_cadence_is_refused() {
        for tier in ["live", "push:30"] {
            let mut flags = CurrencyFlags::default();
            flags.take_tier(tier).expect("a known tier");
            let err = flags.finish().expect_err("no cadence");
            assert!(err.contains("--trust-reload-secs"), "{tier}: {err}");
        }
    }

    /// And the one tier whose cadence is optional keeps both postures.
    #[test]
    fn the_bounded_cache_tier_keeps_both_cadence_postures() {
        let read_once = CurrencyFlags::default().finish().expect("the default");
        assert_eq!(read_once.reload_secs(), None);
        let mut reloading = CurrencyFlags::default();
        reloading.take_reload_secs(300);
        assert_eq!(
            reloading.finish().expect("a cadence").reload_secs(),
            Some(300)
        );
    }
}
