// SPDX-License-Identifier: Apache-2.0
//! The `TrustRevocation` configuration machine — `work/CONFIG-STATE-ATLAS.md` §C.2.
//!
//! Four states, distinguished by the declared tier and by whether a networked epoch
//! source is configured:
//!
//! | State | Required | Forbidden | Guards |
//! |---|---|---|---|
//! | `BoundedCache{T}` | — | epoch url, epoch key | `reload <= T` if set |
//! | `Live` | reload | epoch url, epoch key | `reload <= MAX_NEAR_ZERO` |
//! | `PushInert{T}` | reload | epoch key | `reload <= min(MAX_NEAR_ZERO, T)` |
//! | `PushNetworked{T}` | reload, epoch url | — | same, plus a scheme-bearing url |
//!
//! **Each state carries what its Required column names.** The three states that require a
//! cadence hold one, so they cannot be built without it and planning cannot project
//! "read once at startup" from a tier that claims the store is re-read. `PushNetworked`
//! additionally holds the epoch locator whose presence distinguishes it from `PushInert`,
//! and the epoch key already resolved against this machine's default. `BoundedCache`'s
//! cadence is optional, so it stays a validated request parameter.
//!
//! **The epoch source is a selector, not a parameter.** It is what distinguishes the last
//! two states, so a tier that cannot consume it does not merely ignore it — the request is
//! incoherent, and refusing that is atlas rule X8.
//!
//! This machine owns whether the epoch configuration is LEGAL. It does not own what the
//! configuration MEANS to a runtime plane: normalizing that is startup planning's job,
//! done once, and `TrustPlan` and `SigningPlane` are consumers of the one answer
//! (CF-09 — a fact may have two consumers, it must not have two authorities).

use crate::cli::Config;
use crate::cli::MAX_NEAR_ZERO_TRUST_RELOAD_SECS;
use crate::revocation_tier::RevocationTier;

/// Which trust-revocation state a configuration requests, and what makes it inhabitable.
///
/// Each state carries the witnesses its own Required column names. Three of the four
/// require a reload cadence, so those three cannot be constructed without one — planning
/// therefore cannot project `ReadOnceAtStartup` from a tier whose whole claim is that the
/// store is re-read. `BoundedCache` is the exception the columns state: its cadence is
/// optional, so it stays a validated request parameter and both refresh postures remain
/// reachable from it.
///
/// The reload cadence is a `u64` and not a `NonZeroU64` because layer A currently admits
/// zero. Encoding a rule the model does not state would refuse deployments this proxy
/// accepts today; the guard and the narrower type belong together in a change that decides
/// that question, not in this one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustRevocationState {
    /// Tier 1 — cached active trust state lives at most `t_secs`.
    BoundedCache {
        /// The declared trust-propagation window.
        t_secs: i64,
    },
    /// Tier 2 — the store is consulted on every verification.
    Live {
        /// How often `--trust` is re-read. Required: the tier's claim is that a removed
        /// key stops resolving near-instantly, and nothing resolves faster than the re-read.
        reload_secs: u64,
    },
    /// Tier 3 with no epoch source: the push channel is absent, so the honest guarantee
    /// is the bounded-`T` fallback and nothing else.
    PushInert {
        /// The bounded-`T` fallback window.
        t_secs: i64,
        /// How often `--trust` is re-read. Required for the same reason as `Live`.
        reload_secs: u64,
    },
    /// Tier 3 with a networked epoch source: a revocation advances the epoch and the
    /// trust cache flushes within a poll interval.
    PushNetworked {
        /// The bounded-`T` fallback window, used when the channel is unhealthy.
        t_secs: i64,
        /// How often `--trust` is re-read. Required for the same reason as `Live`.
        reload_secs: u64,
        /// Where the epoch counter lives. Its presence is what distinguishes this state
        /// from `PushInert`, so the state that has one carries it.
        epoch_url: String,
        /// Which key holds the counter, already resolved against the default. Downstream
        /// cannot tell whether an operator named it.
        epoch_key: String,
    },
}

/// Which state the request most nearly names, before its witnesses are known to be present.
///
/// Separate from [`TrustRevocationState`] so classification can stay total. A classifier
/// that could fail would have to answer "which state is this?" and "is that state legal?"
/// at once, and the second answer is what the caller accumulates across machines — so a
/// missing cadence is reported as a violation of the state it most nearly requests, with
/// that state's own ceiling, rather than as an unclassifiable config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestedState {
    BoundedCache { t_secs: i64 },
    Live,
    PushInert { t_secs: i64 },
    PushNetworked { t_secs: i64 },
}

impl RequestedState {
    /// Whether the request names a networked epoch source.
    fn has_networked_epoch(self) -> bool {
        matches!(self, Self::PushNetworked { .. })
    }

    /// Whether inhabiting this state requires a reload cadence.
    fn requires_cadence(self) -> bool {
        !matches!(self, Self::BoundedCache { .. })
    }
}

impl TrustRevocationState {
    /// Whether this state carries a networked epoch channel.
    ///
    /// The one question both `TrustPlan` and `SigningPlan` ask, answered from the
    /// classification rather than by re-reading the URL on each plane (CF-09).
    pub fn has_networked_epoch(&self) -> bool {
        matches!(self, Self::PushNetworked { .. })
    }

    /// The declared tier, as the resolver builder's own type.
    ///
    /// A projection OUT of the classification, not a second reading of `--revocation-tier`:
    /// the two push states collapse back to one tier because the epoch source changes what
    /// is established, not which caching discipline the resolver applies. A plane that
    /// re-read the flag instead would be free to disagree with the state that was
    /// classified (CF-10).
    pub fn tier(&self) -> RevocationTier {
        match self {
            Self::BoundedCache { t_secs } => RevocationTier::BoundedCache { t_secs: *t_secs },
            Self::Live { .. } => RevocationTier::Live,
            Self::PushInert { t_secs, .. } | Self::PushNetworked { t_secs, .. } => {
                RevocationTier::Push { t_secs: *t_secs }
            }
        }
    }

    /// Whether this state asks for a push channel that has no source behind it.
    ///
    /// The honest guarantee is then the bounded-`T` fallback and nothing else, which is a
    /// thing to SAY at startup — so it is named here rather than inferred at the surface
    /// from a channel that came back absent.
    pub fn push_channel_is_inert(&self) -> bool {
        matches!(self, Self::PushInert { .. })
    }

    /// The window the state claims, in seconds — `None` for `Live`, whose claim is
    /// near-zero rather than a bound.
    pub fn declared_window_secs(&self) -> Option<i64> {
        match self {
            Self::Live { .. } => None,
            Self::BoundedCache { t_secs }
            | Self::PushInert { t_secs, .. }
            | Self::PushNetworked { t_secs, .. } => Some(*t_secs),
        }
    }
}

/// Recognise the requested state. Total: every `Config` names one.
///
/// Total on purpose. A classifier that could fail would have to answer "which state is
/// this?" and "is that state legal?" at once, and the second answer is what the caller
/// accumulates across machines — so an illegal combination is reported as a violation of
/// the state it most nearly requests, not as an unclassifiable config.
fn classify(config: &Config) -> RequestedState {
    match config.revocation_tier {
        RevocationTier::BoundedCache { t_secs } => RequestedState::BoundedCache { t_secs },
        RevocationTier::Live => RequestedState::Live,
        RevocationTier::Push { t_secs } if config.trust_epoch_redis_url.is_some() => {
            RequestedState::PushNetworked { t_secs }
        }
        RevocationTier::Push { t_secs } => RequestedState::PushInert { t_secs },
    }
}

/// Build the state, once its witnesses are known to be present.
///
/// `None` is never a silent outcome: every path that reaches it has already pushed the
/// violation naming the value that was missing.
fn build(requested: RequestedState, config: &Config) -> Option<TrustRevocationState> {
    let cadence = config.trust_reload_secs;
    Some(match requested {
        RequestedState::BoundedCache { t_secs } => TrustRevocationState::BoundedCache { t_secs },
        RequestedState::Live => TrustRevocationState::Live {
            reload_secs: cadence?,
        },
        RequestedState::PushInert { t_secs } => TrustRevocationState::PushInert {
            t_secs,
            reload_secs: cadence?,
        },
        RequestedState::PushNetworked { t_secs } => TrustRevocationState::PushNetworked {
            t_secs,
            reload_secs: cadence?,
            epoch_url: config.trust_epoch_redis_url.clone()?,
            // The default belongs to this machine, so it is applied here and nothing
            // downstream can tell an omitted key from a named one.
            epoch_key: config
                .trust_epoch_key
                .clone()
                .unwrap_or_else(|| crate::trust_epoch::DEFAULT_TRUST_EPOCH_KEY.to_string()),
        },
    })
}

/// The reload cadence the state requires, and the ceiling it must respect.
///
/// A separate predicate because the cadence is the whole revocation claim: a tier states
/// how fast a key removed from `--trust` stops resolving, and nothing resolves faster than
/// the file is re-read.
fn cadence_violations(state: RequestedState, config: &Config) -> Vec<String> {
    let mut out = Vec::new();
    if state.requires_cadence() && config.trust_reload_secs.is_none() {
        out.push(
            "--revocation-tier live|push requires --trust-reload-secs: both tiers state a \
             revocation window in terms of consulting the trust store, but with --trust read \
             once at startup the store cannot change, so revoking a request-signer key would \
             need a restart of every replica while the startup line claims otherwise"
                .to_string(),
        );
    }
    let Some(secs) = config.trust_reload_secs else {
        return out;
    };
    let (ceiling, claim) = match state {
        RequestedState::Live => (
            MAX_NEAR_ZERO_TRUST_RELOAD_SECS,
            "--revocation-tier live states a NEAR-ZERO revocation window (the store is \
             consulted on every verification)"
                .to_string(),
        ),
        RequestedState::PushInert { t_secs } | RequestedState::PushNetworked { t_secs } => (
            MAX_NEAR_ZERO_TRUST_RELOAD_SECS.min(t_secs.max(1) as u64),
            format!(
                "--revocation-tier push:{t_secs} states a near-zero window with a bounded \
                 {t_secs}s fallback"
            ),
        ),
        RequestedState::BoundedCache { t_secs } => (
            t_secs.max(1) as u64,
            format!(
                "--revocation-tier bounded-cache:{t_secs} states that revocation is \
                 enforced fleet-wide within {t_secs}s"
            ),
        ),
    };
    if secs > ceiling {
        out.push(format!(
            "--trust-reload-secs {secs} is longer than the revocation window the declared \
             tier claims: {claim}, but a key removed from --trust keeps resolving until the \
             file is re-read, which is every {secs}s. Set --trust-reload-secs <= {ceiling}, \
             or declare a tier whose window the deployment can keep"
        ));
    }
    out
}

/// The epoch-source columns: which states may carry one, and what shape it must have.
fn epoch_violations(state: RequestedState, config: &Config) -> Vec<String> {
    let mut out = Vec::new();
    // X8. `PushInert` is the state that has no URL, so only the two non-Push states can
    // reach this: a configured source under a tier that never consumes it.
    if config.trust_epoch_redis_url.is_some() && !state.has_networked_epoch() {
        out.push(
            "--trust-epoch-redis-url has no effect under this --revocation-tier: the \
             networked epoch source drives PUSH invalidation only, so any other tier \
             connects nothing and the deployment would believe a networked trust \
             invalidation is active while nothing consumes it. Declare --revocation-tier \
             push:<t_secs>, or remove --trust-epoch-redis-url"
                .to_string(),
        );
    }
    // CF-04: the key names a location in a store this state has not configured. It is
    // `Option`-typed and mode-specific, so its presence carries intent.
    if config.trust_epoch_key.is_some() && !state.has_networked_epoch() {
        out.push(
            "--trust-epoch-key names a key in a trust-epoch store this configuration does \
             not have; set --trust-epoch-redis-url under --revocation-tier push, or remove \
             --trust-epoch-key"
                .to_string(),
        );
    }
    // Build-independent shape only. Whether the URL RESOLVES is layer C, and whether this
    // binary has a Redis client at all is layer B; both are materialization's to refuse.
    if let Some(url) = &config.trust_epoch_redis_url {
        if !url.contains("://") {
            out.push(format!(
                "--trust-epoch-redis-url {url:?} is not a URL: the trust-epoch source is \
                 what the operator's INCR kill switch reaches, so a value that cannot name \
                 a store leaves delegated credentials unrevocable. Give a scheme-bearing \
                 URL such as redis://host:6379"
            ));
        }
    }
    out
}

/// Classify the requested trust-revocation state and check its four columns.
///
/// The state is returned alongside the violations rather than instead of them: a caller
/// accumulating across machines needs every violation, and a caller that finds none needs
/// the classification (CF-10 — classify, do not classify and discard).
///
/// `None` means the request names a state whose witnesses are not all present — a `Live`
/// or `push` tier with no cadence. The violation naming the missing value is beside it, so
/// a `None` never travels without its reason.
pub fn classify_and_validate(config: &Config) -> (Option<TrustRevocationState>, Vec<String>) {
    let requested = classify(config);
    let mut violations = cadence_violations(requested, config);
    violations.extend(epoch_violations(requested, config));
    (build(requested, config), violations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_state::test_support::legal_config;

    fn state_of(mutate: impl FnOnce(&mut Config)) -> TrustRevocationState {
        let mut config = legal_config();
        mutate(&mut config);
        classify_and_validate(&config)
            .0
            .expect("the case names a state whose witnesses are present")
    }

    fn violations_of(mutate: impl FnOnce(&mut Config)) -> Vec<String> {
        let mut config = legal_config();
        mutate(&mut config);
        classify_and_validate(&config).1
    }

    // ---- the matrix: every legal state form is recognised AND accepted ----

    /// A legal form: the state it must be recognised as, and how to request it.
    type LegalForm = (TrustRevocationState, Box<dyn Fn(&mut Config)>);

    #[test]
    fn every_legal_state_form_is_classified_and_accepted() {
        let cases: Vec<LegalForm> = vec![
            (
                TrustRevocationState::BoundedCache { t_secs: 60 },
                Box::new(|c: &mut Config| {
                    c.revocation_tier = RevocationTier::BoundedCache { t_secs: 60 };
                    c.trust_reload_secs = None;
                }),
            ),
            (
                TrustRevocationState::BoundedCache { t_secs: 60 },
                Box::new(|c: &mut Config| {
                    c.revocation_tier = RevocationTier::BoundedCache { t_secs: 60 };
                    c.trust_reload_secs = Some(60);
                }),
            ),
            (
                TrustRevocationState::Live { reload_secs: 5 },
                Box::new(|c: &mut Config| {
                    c.revocation_tier = RevocationTier::Live;
                    c.trust_reload_secs = Some(5);
                }),
            ),
            (
                TrustRevocationState::PushInert {
                    t_secs: 30,
                    reload_secs: 30,
                },
                Box::new(|c: &mut Config| {
                    c.revocation_tier = RevocationTier::Push { t_secs: 30 };
                    c.trust_reload_secs = Some(30);
                }),
            ),
            (
                TrustRevocationState::PushNetworked {
                    t_secs: 30,
                    reload_secs: 30,
                    epoch_url: "redis://127.0.0.1:6379".to_string(),
                    epoch_key: "mcp-re:trust:epoch".to_string(),
                },
                Box::new(|c: &mut Config| {
                    c.revocation_tier = RevocationTier::Push { t_secs: 30 };
                    c.trust_reload_secs = Some(30);
                    c.trust_epoch_redis_url = Some("redis://127.0.0.1:6379".to_string());
                    c.trust_epoch_key = Some("mcp-re:trust:epoch".to_string());
                }),
            ),
        ];
        for (expected, mutate) in cases {
            let mut config = legal_config();
            mutate(&mut config);
            let (state, violations) = classify_and_validate(&config);
            assert_eq!(
                state,
                Some(expected.clone()),
                "classified as the wrong state"
            );
            assert!(
                violations.is_empty(),
                "{expected:?} refused: {violations:?}"
            );
        }
    }

    // ---- classification is asserted, not only the verdict ----

    #[test]
    fn the_epoch_source_is_what_splits_push_in_two() {
        let inert = state_of(|c| {
            c.revocation_tier = RevocationTier::Push { t_secs: 30 };
            c.trust_reload_secs = Some(30);
        });
        let networked = state_of(|c| {
            c.revocation_tier = RevocationTier::Push { t_secs: 30 };
            c.trust_reload_secs = Some(30);
            c.trust_epoch_redis_url = Some("redis://127.0.0.1:6379".to_string());
        });
        assert!(!inert.has_networked_epoch());
        assert!(networked.has_networked_epoch());
        assert_ne!(inert, networked, "the same tier, two different states");
    }

    /// The projection back to the resolver's own type is total, and the two push states
    /// collapse to one tier: the epoch source changes what gets ESTABLISHED, not which
    /// caching discipline the resolver applies.
    #[test]
    fn the_state_projects_back_to_the_tier_the_resolver_is_built_from() {
        for (state, expected) in [
            (
                TrustRevocationState::BoundedCache { t_secs: 60 },
                RevocationTier::BoundedCache { t_secs: 60 },
            ),
            (
                TrustRevocationState::Live { reload_secs: 5 },
                RevocationTier::Live,
            ),
            (
                TrustRevocationState::PushInert {
                    t_secs: 30,
                    reload_secs: 5,
                },
                RevocationTier::Push { t_secs: 30 },
            ),
            (
                TrustRevocationState::PushNetworked {
                    t_secs: 30,
                    reload_secs: 5,
                    epoch_url: "redis://127.0.0.1:6379".to_string(),
                    epoch_key: "mcp-re:trust:epoch".to_string(),
                },
                RevocationTier::Push { t_secs: 30 },
            ),
        ] {
            assert_eq!(state.tier(), expected, "{state:?}");
        }
        assert!(TrustRevocationState::PushInert {
            t_secs: 30,
            reload_secs: 5
        }
        .push_channel_is_inert());
        assert!(!TrustRevocationState::PushNetworked {
            t_secs: 30,
            reload_secs: 5,
            epoch_url: "redis://127.0.0.1:6379".to_string(),
            epoch_key: "mcp-re:trust:epoch".to_string()
        }
        .push_channel_is_inert());
    }

    #[test]
    fn live_declares_no_bounded_window() {
        assert_eq!(
            state_of(|c| {
                c.revocation_tier = RevocationTier::Live;
                c.trust_reload_secs = Some(5);
            })
            .declared_window_secs(),
            None
        );
    }

    // ---- required parameters ----

    #[test]
    fn live_and_push_require_a_cadence() {
        for tier in [RevocationTier::Live, RevocationTier::Push { t_secs: 30 }] {
            let violations = violations_of(|c| {
                c.revocation_tier = tier;
                c.trust_reload_secs = None;
            });
            assert!(
                violations
                    .iter()
                    .any(|v| v.contains("requires --trust-reload-secs")),
                "{violations:?}"
            );
        }
    }

    #[test]
    fn bounded_cache_does_not_require_a_cadence() {
        assert!(violations_of(|c| {
            c.revocation_tier = RevocationTier::BoundedCache { t_secs: 60 };
            c.trust_reload_secs = None;
        })
        .is_empty());
    }

    #[test]
    fn push_networked_requires_its_url_to_be_a_url() {
        let violations = violations_of(|c| {
            c.revocation_tier = RevocationTier::Push { t_secs: 30 };
            c.trust_reload_secs = Some(30);
            c.trust_epoch_redis_url = Some("127.0.0.1:6379".to_string());
        });
        assert!(
            violations.iter().any(|v| v.contains("is not a URL")),
            "{violations:?}"
        );
    }

    // ---- forbidden parameters: presence carries intent (CF-04) ----

    #[test]
    fn an_epoch_source_under_a_tier_that_cannot_consume_it_is_refused() {
        for tier in [
            RevocationTier::Live,
            RevocationTier::BoundedCache { t_secs: 60 },
        ] {
            let violations = violations_of(|c| {
                c.revocation_tier = tier;
                c.trust_reload_secs = Some(30);
                c.trust_epoch_redis_url = Some("redis://127.0.0.1:6379".to_string());
            });
            assert!(
                violations
                    .iter()
                    .any(|v| v.contains("--trust-epoch-redis-url has no effect")),
                "{violations:?}"
            );
        }
    }

    #[test]
    fn an_epoch_key_without_an_epoch_store_is_refused() {
        let violations = violations_of(|c| {
            c.revocation_tier = RevocationTier::Push { t_secs: 30 };
            c.trust_reload_secs = Some(30);
            c.trust_epoch_key = Some("mcp-re:trust:epoch".to_string());
        });
        assert!(
            violations
                .iter()
                .any(|v| v.contains("--trust-epoch-key names a key")),
            "{violations:?}"
        );
    }

    // ---- guards ----

    #[test]
    fn each_state_holds_the_cadence_to_the_window_it_claims() {
        for (tier, cadence) in [
            (RevocationTier::Live, MAX_NEAR_ZERO_TRUST_RELOAD_SECS + 1),
            (RevocationTier::Push { t_secs: 10 }, 11),
            (RevocationTier::BoundedCache { t_secs: 30 }, 31),
        ] {
            let violations = violations_of(|c| {
                c.revocation_tier = tier;
                c.trust_reload_secs = Some(cadence);
            });
            assert!(
                violations
                    .iter()
                    .any(|v| v.contains("is longer than the revocation window")),
                "cadence {cadence} accepted: {violations:?}"
            );
        }
    }

    #[test]
    fn a_push_window_narrower_than_near_zero_binds_instead_of_it() {
        // `push:10` claims a 10s fallback, so 30s is refused even though it is inside the
        // general near-zero ceiling. The tighter of the two claims is the one that binds.
        const { assert!(MAX_NEAR_ZERO_TRUST_RELOAD_SECS > 30) };
        let violations = violations_of(|c| {
            c.revocation_tier = RevocationTier::Push { t_secs: 10 };
            c.trust_reload_secs = Some(30);
        });
        assert!(
            violations
                .iter()
                .any(|v| v.contains("is longer than the revocation window")),
            "{violations:?}"
        );
    }
}
