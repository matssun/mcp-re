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

use crate::deployment_request::{
    DeploymentRequest, RequestSignerCurrencyRequest, TrustEpochStoreRequest,
};
use crate::revocation_tier::RevocationTier;
use std::num::NonZeroU64;

/// Which trust-revocation state a configuration requests, and what makes it inhabitable.
///
/// Each state carries the witnesses its own Required column names. Three of the four
/// require a reload cadence, so those three cannot be constructed without one — planning
/// therefore cannot project `ReadOnceAtStartup` from a tier whose whole claim is that the
/// store is re-read. `BoundedCache` carries the same fact as an `Option`, because its
/// column makes the cadence optional and the ABSENCE is itself a sub-posture. Carrying it
/// rather than leaving it in the request is what stops planning reconverting a raw value:
/// a `Some(0)` filtered back to `None` there would silently turn a refused request into a
/// different legal deployment.
///
/// The cadence is a `NonZeroU64` because layer A refuses zero: the cadence is the sleep
/// between re-reads, so a zero one re-reads `--trust` and rebuilds the signer directory
/// continuously. The rule and the type are the same fact — the type may encode the
/// invariant because the legality model states it, not instead of it.
/// The representation is private to this module. [`classify_and_validate`] is the only
/// producer, so possessing this state IS the statement that its witnesses were checked
/// against the tier that requires them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRevocationState {
    kind: RevocationKind,
}

/// The four states, as the owner's own representation.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RevocationKind {
    /// Tier 1 — cached active trust state lives at most `t_secs`.
    BoundedCache {
        /// The declared trust-propagation window.
        t_secs: i64,
        /// How often `--trust` is re-read, where the operator asked for that. OPTIONAL
        /// here and required by the other three: this is the one state whose claim holds
        /// without a re-read, so both refresh postures are legal and the absence is itself
        /// the sub-posture. Normalized, so planning never reconverts a raw cadence.
        reload_secs: Option<NonZeroU64>,
    },
    /// Tier 2 — the store is consulted on every verification.
    Live {
        /// How often `--trust` is re-read. Required: the tier's claim is that a removed
        /// key stops resolving near-instantly, and nothing resolves faster than the re-read.
        reload_secs: NonZeroU64,
    },
    /// Tier 3 with no epoch source: the push channel is absent, so the honest guarantee
    /// is the bounded-`T` fallback and nothing else.
    PushInert {
        /// The bounded-`T` fallback window.
        t_secs: i64,
        /// How often `--trust` is re-read. Required for the same reason as `Live`.
        reload_secs: NonZeroU64,
    },
    /// Tier 3 with a networked epoch source: a revocation advances the epoch and the
    /// trust cache flushes within a poll interval.
    PushNetworked {
        /// The bounded-`T` fallback window, used when the channel is unhealthy.
        t_secs: i64,
        /// How often `--trust` is re-read. Required for the same reason as `Live`.
        reload_secs: NonZeroU64,
        /// Where the epoch counter lives. Its presence is what distinguishes this state
        /// from `PushInert`, so the state that has one carries it.
        epoch_url: String,
        /// Which key holds the counter, already resolved against the default. Downstream
        /// cannot tell whether an operator named it.
        epoch_key: String,
    },
}

/// Where the trust epoch counter lives, as a borrowed view of the state that carries one.
///
/// The locator and the key are handed over TOGETHER because they were validated together
/// and are meaningless apart: a counter read from the right store under the wrong key
/// reports an epoch that never advances, which is a revocation channel that silently
/// stops revoking. Borrowed, so it reads a state without being able to assemble one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochSource<'a> {
    url: &'a str,
    key: &'a str,
}

impl<'a> EpochSource<'a> {
    /// Where the epoch counter lives.
    pub fn url(&self) -> &'a str {
        self.url
    }

    /// Which key holds the counter, already resolved against the default.
    pub fn key(&self) -> &'a str {
        self.key
    }
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

impl RequestedState {}

impl TrustRevocationState {
    /// A cadence witness from a literal, for tests and for callers that already hold a
    /// value layer A has accepted. Panics on zero, which layer A refuses.
    #[cfg(test)]
    pub(crate) fn cadence(secs: u64) -> NonZeroU64 {
        NonZeroU64::new(secs).expect("a cadence witness is non-zero")
    }

    /// Whether this state carries a networked epoch channel.
    ///
    /// The one question both `TrustPlan` and `SigningPlan` ask, answered from the
    /// classification rather than by re-reading the URL on each plane (CF-09).
    pub fn has_networked_epoch(&self) -> bool {
        matches!(self.kind, RevocationKind::PushNetworked { .. })
    }

    /// Where the epoch counter lives, or `None` when this state has no networked source.
    ///
    /// The projection replaces a match on the representation performed in planning. Both
    /// halves of the locator come back as one value, so no consumer can pair this
    /// deployment's store with another deployment's key.
    pub fn epoch_source(&self) -> Option<EpochSource<'_>> {
        match &self.kind {
            RevocationKind::PushNetworked {
                epoch_url,
                epoch_key,
                ..
            } => Some(EpochSource {
                url: epoch_url,
                key: epoch_key,
            }),
            _ => None,
        }
    }

    /// The declared tier, as the resolver builder's own type.
    ///
    /// A projection OUT of the classification, not a second reading of `--revocation-tier`:
    /// the two push states collapse back to one tier because the epoch source changes what
    /// is established, not which caching discipline the resolver applies. A plane that
    /// re-read the flag instead would be free to disagree with the state that was
    /// classified (CF-10).
    pub fn tier(&self) -> RevocationTier {
        match &self.kind {
            RevocationKind::BoundedCache { t_secs, .. } => {
                RevocationTier::BoundedCache { t_secs: *t_secs }
            }
            RevocationKind::Live { .. } => RevocationTier::Live,
            RevocationKind::PushInert { t_secs, .. }
            | RevocationKind::PushNetworked { t_secs, .. } => {
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
        matches!(self.kind, RevocationKind::PushInert { .. })
    }

    /// How often `--trust` is re-read, or `None` when the state's claim holds without a
    /// re-read.
    ///
    /// The projection replaces a match over three reload-bearing variants performed in
    /// planning. Which states require a cadence, and which one may legally omit it, is this
    /// machine's rule — a planner re-deciding it could project a reload-bearing state to
    /// read-once and contradict a tier whose whole claim is that the store is re-read.
    /// Layer A normalized the optional cadence, so there is no `Some(0)` left to filter.
    pub fn reload_cadence(&self) -> Option<NonZeroU64> {
        match &self.kind {
            RevocationKind::Live { reload_secs }
            | RevocationKind::PushInert { reload_secs, .. }
            | RevocationKind::PushNetworked { reload_secs, .. } => Some(*reload_secs),
            RevocationKind::BoundedCache { reload_secs, .. } => *reload_secs,
        }
    }

    /// The window the state claims, in seconds — `None` for `Live`, whose claim is
    /// near-zero rather than a bound.
    pub fn declared_window_secs(&self) -> Option<i64> {
        match &self.kind {
            RevocationKind::Live { .. } => None,
            RevocationKind::BoundedCache { t_secs, .. }
            | RevocationKind::PushInert { t_secs, .. }
            | RevocationKind::PushNetworked { t_secs, .. } => Some(*t_secs),
        }
    }
}

/// Recognise the requested state. Total: every `DeploymentRequest` names one.
///
/// Total on purpose. A classifier that could fail would have to answer "which state is
/// this?" and "is that state legal?" at once, and the second answer is what the caller
/// accumulates across machines — so an illegal combination is reported as a violation of
/// the state it most nearly requests, not as an unclassifiable config.
fn classify(config: &DeploymentRequest) -> RequestedState {
    match &config.request_signer_currency {
        RequestSignerCurrencyRequest::BoundedCache { t_secs, .. } => {
            RequestedState::BoundedCache { t_secs: *t_secs }
        }
        RequestSignerCurrencyRequest::Live { .. } => RequestedState::Live,
        RequestSignerCurrencyRequest::Push { t_secs, epoch, .. } => {
            // The two push states differ by whether an epoch source is named, and only the
            // pushing posture has a field for one — which is what relation X8 used to have
            // to enforce across two independent fields.
            if epoch.source.is_some() {
                RequestedState::PushNetworked { t_secs: *t_secs }
            } else {
                RequestedState::PushInert { t_secs: *t_secs }
            }
        }
    }
}

/// Build the state, once its witnesses are known to be present.
///
/// `None` is never a silent outcome: every path that reaches it has already pushed the
/// violation naming the value that was missing.
fn build(requested: RequestedState, config: &DeploymentRequest) -> Option<TrustRevocationState> {
    // A cadence that is present and zero names no legal state at all, so `build` yields
    // nothing rather than an absence — `Some(0)` must never become "no reload requested".
    let cadence = match config.request_signer_currency.reload_secs() {
        None => None,
        Some(secs) => Some(NonZeroU64::new(secs)?),
    };
    Some(TrustRevocationState {
        kind: match requested {
            RequestedState::BoundedCache { t_secs } => RevocationKind::BoundedCache {
                t_secs,
                reload_secs: cadence,
            },
            RequestedState::Live => RevocationKind::Live {
                reload_secs: cadence?,
            },
            RequestedState::PushInert { t_secs } => RevocationKind::PushInert {
                t_secs,
                reload_secs: cadence?,
            },
            RequestedState::PushNetworked { t_secs } => RevocationKind::PushNetworked {
                t_secs,
                reload_secs: cadence?,
                epoch_url: config
                    .request_signer_currency
                    .epoch()?
                    .locator()?
                    .to_string(),
                // The default belongs to this machine, so it is applied here and nothing
                // downstream can tell an omitted key from a named one.
                epoch_key: config
                    .request_signer_currency
                    .epoch()
                    .and_then(TrustEpochStoreRequest::key)
                    .unwrap_or(crate::trust_epoch::DEFAULT_TRUST_EPOCH_KEY)
                    .to_string(),
            },
        },
    })
}

/// The reload cadence the state requires, and the ceiling it must respect.
///
/// A separate predicate because the cadence is the whole revocation claim: a tier states
/// how fast a key removed from `--trust` stops resolving, and nothing resolves faster than
/// the file is re-read.
fn cadence_violations(state: RequestedState, config: &DeploymentRequest) -> Vec<String> {
    let mut out = Vec::new();
    // The "live|push requires a cadence" clause is GONE. Those two tiers are inhabited by
    // one, so absence is not a state to refuse (ADR-MCPRE-067 §7); `cli::currency_flags`
    // answers the command line that omits it.
    let Some(secs) = config.request_signer_currency.reload_secs() else {
        return out;
    };
    // Unconditional, like its CRL sibling: the cadence is the sleep between re-reads, so a
    // zero one re-reads `--trust` and rebuilds the signer directory continuously, on a
    // spinning thread. `BoundedCache` is included because it projects the same reload.
    if secs == 0 {
        out.push(
            "--trust-reload-secs 0 makes the trust reloader spin: the cadence is the sleep \
             between re-reads, so zero re-reads --trust and rebuilds the signer directory \
             continuously. Set a positive cadence, or omit the flag under \
             --revocation-tier bounded-cache to read --trust once at startup"
                .to_string(),
        );
        return out;
    }
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
fn epoch_violations(config: &DeploymentRequest) -> Vec<String> {
    let mut out = Vec::new();
    // TWO clauses are gone from here, and their absence is the result.
    //
    // X8 refused an epoch source under a tier that never consumes it. Only the pushing
    // posture has a field for one now, so no configuration can state the pair
    // (ADR-MCPRE-067 §7). CF-04 refused a `--trust-epoch-key` naming a location in a store
    // this configuration did not have; the coordinate travels inside `TrustEpochSource`.
    // Both argv forms survive — `cli::currency_flags` and `cli::storage_flags` answer them.
    //
    // Build-independent shape only. Whether the URL RESOLVES is layer C, and whether this
    // binary has a Redis client at all is layer B; both are materialization's to refuse.
    if let Some(url) = config
        .request_signer_currency
        .epoch()
        .and_then(TrustEpochStoreRequest::locator)
    {
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
pub fn classify_and_validate(
    config: &DeploymentRequest,
) -> (Option<TrustRevocationState>, Vec<String>) {
    let requested = classify(config);
    let mut violations = cadence_violations(requested, config);
    violations.extend(epoch_violations(config));
    (build(requested, config), violations)
}

/// The ceiling on `--trust-reload-secs` for the tiers that advertise a NEAR-ZERO
/// revocation window (`live`, `push`).
///
/// Those tiers describe how fast a revoked request-signer key stops being honoured, and
/// the only thing that removes a key from the resolver on a running replica is the
/// `--trust` re-read. The cadence is therefore the real window, whatever the tier
/// string says. One minute is the coarsest cadence for which "near-zero" survives
/// contact with an incident: it is inside the 300s default connection-age bound, so a
/// revocation reaches every peer within one connection lifetime.
pub const MAX_NEAR_ZERO_TRUST_RELOAD_SECS: u64 = 60;

#[cfg(test)]
mod tests {
    /// The posture a published tier plus an optional cadence names. A helper because the
    /// tier vocabulary is what the tests are written in, and the union is what the request
    /// holds — the mapping is the CLI adapter's job in production and this is its fixture
    /// twin.
    fn posture(tier: RevocationTier, reload_secs: Option<u64>) -> RequestSignerCurrencyRequest {
        match tier {
            RevocationTier::BoundedCache { t_secs } => RequestSignerCurrencyRequest::BoundedCache {
                t_secs,
                reload_secs,
            },
            RevocationTier::Live => RequestSignerCurrencyRequest::Live {
                reload_secs: reload_secs.unwrap_or_default(),
            },
            RevocationTier::Push { t_secs } => RequestSignerCurrencyRequest::Push {
                t_secs,
                reload_secs: reload_secs.unwrap_or_default(),
                epoch: TrustEpochStoreRequest::default(),
            },
        }
    }

    /// A pushing posture over one epoch source. Written through the request's own types,
    /// so a fixture cannot state an epoch source under a tier that reads none.
    fn pushing(
        t_secs: i64,
        reload_secs: u64,
        url: &str,
        key: Option<&str>,
    ) -> RequestSignerCurrencyRequest {
        RequestSignerCurrencyRequest::Push {
            t_secs,
            reload_secs,
            epoch: TrustEpochStoreRequest {
                source: Some(crate::deployment_request::TrustEpochSource::redis(
                    url,
                    key.map(str::to_string),
                )),
            },
        }
    }

    /// Build a state from the owner's own representation. In-module only: outside this
    /// module a state is obtainable solely from `classify_and_validate`.
    fn state(kind: RevocationKind) -> TrustRevocationState {
        TrustRevocationState { kind }
    }

    use super::*;
    use crate::config_state::test_support::legal_config;

    fn state_of(mutate: impl FnOnce(&mut DeploymentRequest)) -> TrustRevocationState {
        let mut config = legal_config();
        mutate(&mut config);
        classify_and_validate(&config)
            .0
            .expect("the case names a state whose witnesses are present")
    }

    fn violations_of(mutate: impl FnOnce(&mut DeploymentRequest)) -> Vec<String> {
        let mut config = legal_config();
        mutate(&mut config);
        classify_and_validate(&config).1
    }

    /// The defect this closes: a zero cadence reached the reload worker, which sleeps for
    /// the cadence and then re-reads. `Halt::sleep(Duration::from_secs(0))` sets a deadline
    /// already in the past and returns immediately, so `--trust` was re-read and the signer
    /// directory rebuilt continuously, on a spinning thread. The CRL machine refused the
    /// same input; this one did not.
    ///
    /// Every state is covered, `BoundedCache` included: its cadence is optional, but a
    /// cadence it DOES name projects the same reload as the other three.
    #[test]
    fn a_zero_cadence_is_a_spinning_reloader_in_every_state() {
        let tiers = [
            RevocationTier::BoundedCache { t_secs: 60 },
            RevocationTier::Live,
            RevocationTier::Push { t_secs: 30 },
        ];
        for tier in tiers {
            let violations = violations_of(|c| {
                c.request_signer_currency = posture(tier.clone(), Some(0));
            });
            assert!(
                violations.iter().any(|v| v.contains("spin")),
                "{tier:?} must refuse a zero cadence: {violations:?}"
            );
        }
    }

    /// The negative control for the guard above: one second is legal and stays legal. A
    /// guard written as `<= 0` on a signed type, or as a range that swallowed its own
    /// boundary, would refuse this and the test above would still pass.
    #[test]
    fn the_smallest_positive_cadence_is_admitted() {
        for tier in [RevocationTier::Live, RevocationTier::Push { t_secs: 30 }] {
            let violations = violations_of(|c| {
                c.request_signer_currency = posture(tier.clone(), Some(1));
            });
            assert!(
                violations.is_empty(),
                "{tier:?} with a 1s cadence must be admitted: {violations:?}"
            );
        }
        assert_eq!(
            state_of(|c| {
                c.request_signer_currency = RequestSignerCurrencyRequest::Live { reload_secs: 1 };
            }),
            state(RevocationKind::Live {
                reload_secs: TrustRevocationState::cadence(1)
            })
        );
    }

    /// The guard is on the RUNTIME, not on argv. `DeploymentRequest` has public fields, so a caller
    /// that builds one in code reaches the same reloader — which is the altitude mistake
    /// `ValidatedDeployment` exists to correct, and the reason this is checked here rather than
    /// in the parser.
    #[test]
    fn a_programmatic_config_cannot_spin_the_trust_reloader() {
        let mut config = legal_config();
        config.request_signer_currency = RequestSignerCurrencyRequest::Live { reload_secs: 0 };
        let refusal = crate::config_state::validation::ValidatedDeployment::try_from(config)
            .expect_err("a spinning reloader must not validate");
        assert!(refusal.contains("--trust-reload-secs 0"), "{refusal}");
    }

    // ---- the matrix: every legal state form is recognised AND accepted ----

    /// A legal form: the state it must be recognised as, and how to request it.
    type LegalForm = (TrustRevocationState, Box<dyn Fn(&mut DeploymentRequest)>);

    #[test]
    fn every_legal_state_form_is_classified_and_accepted() {
        let cases: Vec<LegalForm> = vec![
            (
                state(RevocationKind::BoundedCache {
                    t_secs: 60,
                    reload_secs: None,
                }),
                Box::new(|c: &mut DeploymentRequest| {
                    c.request_signer_currency =
                        posture(RevocationTier::BoundedCache { t_secs: 60 }, None);
                }),
            ),
            (
                state(RevocationKind::BoundedCache {
                    t_secs: 60,
                    reload_secs: Some(TrustRevocationState::cadence(60)),
                }),
                Box::new(|c: &mut DeploymentRequest| {
                    c.request_signer_currency =
                        posture(RevocationTier::BoundedCache { t_secs: 60 }, Some(60));
                }),
            ),
            (
                state(RevocationKind::Live {
                    reload_secs: crate::config_state::TrustRevocationState::cadence(5),
                }),
                Box::new(|c: &mut DeploymentRequest| {
                    c.request_signer_currency =
                        RequestSignerCurrencyRequest::Live { reload_secs: 5 };
                }),
            ),
            (
                state(RevocationKind::PushInert {
                    t_secs: 30,
                    reload_secs: crate::config_state::TrustRevocationState::cadence(30),
                }),
                Box::new(|c: &mut DeploymentRequest| {
                    // The INERT posture: a pushing tier that names no epoch source. Absence
                    // is what separates the two push states, and only this tier has a field
                    // for one to be absent from.
                    c.request_signer_currency =
                        posture(RevocationTier::Push { t_secs: 30 }, Some(30));
                }),
            ),
            (
                state(RevocationKind::PushNetworked {
                    t_secs: 30,
                    reload_secs: crate::config_state::TrustRevocationState::cadence(30),
                    epoch_url: "redis://127.0.0.1:6379".to_string(),
                    epoch_key: "mcp-re:trust:epoch".to_string(),
                }),
                Box::new(|c: &mut DeploymentRequest| {
                    c.request_signer_currency =
                        pushing(30, 30, "redis://127.0.0.1:6379", Some("mcp-re:trust:epoch"));
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
            c.request_signer_currency = RequestSignerCurrencyRequest::Push {
                t_secs: 30,
                reload_secs: 30,
                epoch: TrustEpochStoreRequest::default(),
            };
        });
        let networked = state_of(|c| {
            c.request_signer_currency = RequestSignerCurrencyRequest::Push {
                t_secs: 30,
                reload_secs: 30,
                epoch: TrustEpochStoreRequest {
                    source: Some(crate::deployment_request::TrustEpochSource::redis(
                        "redis://127.0.0.1:6379",
                        None,
                    )),
                },
            };
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
                state(RevocationKind::BoundedCache {
                    t_secs: 60,
                    reload_secs: None,
                }),
                RevocationTier::BoundedCache { t_secs: 60 },
            ),
            (
                state(RevocationKind::Live {
                    reload_secs: crate::config_state::TrustRevocationState::cadence(5),
                }),
                RevocationTier::Live,
            ),
            (
                state(RevocationKind::PushInert {
                    t_secs: 30,
                    reload_secs: crate::config_state::TrustRevocationState::cadence(5),
                }),
                RevocationTier::Push { t_secs: 30 },
            ),
            (
                state(RevocationKind::PushNetworked {
                    t_secs: 30,
                    reload_secs: crate::config_state::TrustRevocationState::cadence(5),
                    epoch_url: "redis://127.0.0.1:6379".to_string(),
                    epoch_key: "mcp-re:trust:epoch".to_string(),
                }),
                RevocationTier::Push { t_secs: 30 },
            ),
        ] {
            assert_eq!(state.tier(), expected, "{state:?}");
        }
        assert!(state(RevocationKind::PushInert {
            t_secs: 30,
            reload_secs: crate::config_state::TrustRevocationState::cadence(5)
        })
        .push_channel_is_inert());
        assert!(!state(RevocationKind::PushNetworked {
            t_secs: 30,
            reload_secs: crate::config_state::TrustRevocationState::cadence(5),
            epoch_url: "redis://127.0.0.1:6379".to_string(),
            epoch_key: "mcp-re:trust:epoch".to_string()
        })
        .push_channel_is_inert());
    }

    #[test]
    fn live_declares_no_bounded_window() {
        assert_eq!(
            state_of(|c| {
                c.request_signer_currency = RequestSignerCurrencyRequest::Live { reload_secs: 5 };
            })
            .declared_window_secs(),
            None
        );
    }

    // ---- required parameters ----

    // The X8 test left this module with the state it examined. An epoch source under a
    // tier that reads none is not a configuration any more: only the pushing posture has a
    // field for one (ADR-MCPRE-067 §7). The argv form survives and
    // `cli::currency_flags::tests::an_epoch_source_under_a_tier_that_reads_none_is_refused`
    // pins the same sentence.

    #[test]
    fn bounded_cache_does_not_require_a_cadence() {
        assert!(violations_of(|c| {
            c.request_signer_currency = posture(RevocationTier::BoundedCache { t_secs: 60 }, None);
        })
        .is_empty());
    }

    #[test]
    fn push_networked_requires_its_url_to_be_a_url() {
        let violations = violations_of(|c| {
            c.request_signer_currency = RequestSignerCurrencyRequest::Push {
                t_secs: 30,
                reload_secs: 30,
                epoch: TrustEpochStoreRequest {
                    source: Some(crate::deployment_request::TrustEpochSource::redis(
                        "127.0.0.1:6379",
                        None,
                    )),
                },
            };
        });
        assert!(
            violations.iter().any(|v| v.contains("is not a URL")),
            "{violations:?}"
        );
    }

    // ---- forbidden parameters: presence carries intent (CF-04) ----

    // CF-04 — an epoch key naming a place in a store this configuration does not have —
    // has no test here any more, and its absence is the result. The coordinate travels
    // inside `TrustEpochSource`, so a key with no store cannot be constructed and the
    // clause has no configuration to examine. The argv form is still statable, and
    // `cli::storage_flags` refuses it with the same sentence.

    // ---- guards ----

    #[test]
    fn each_state_holds_the_cadence_to_the_window_it_claims() {
        for (tier, cadence) in [
            (RevocationTier::Live, MAX_NEAR_ZERO_TRUST_RELOAD_SECS + 1),
            (RevocationTier::Push { t_secs: 10 }, 11),
            (RevocationTier::BoundedCache { t_secs: 30 }, 31),
        ] {
            let violations = violations_of(|c| {
                c.request_signer_currency = posture(tier, Some(cadence));
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
            c.request_signer_currency = RequestSignerCurrencyRequest::Push {
                t_secs: 10,
                reload_secs: 30,
                epoch: TrustEpochStoreRequest::default(),
            };
        });
        assert!(
            violations
                .iter()
                .any(|v| v.contains("is longer than the revocation window")),
            "{violations:?}"
        );
    }
}
