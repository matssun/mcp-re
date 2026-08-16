// SPDX-License-Identifier: Apache-2.0
//! Pure startup planning: what the proxy INTENDS to build, decided from validated
//! configuration alone (ADR-MCPRE-056 §5.2).
//!
//! Nothing in this module opens a socket, connects to a store, reads a file, spawns a
//! thread or reads the clock. A plan is a description of intent, not an observation — it
//! says "this deployment asked for the linearizable tier over etcd at this endpoint",
//! never "that endpoint answered". Establishing the latter is materialization's job, and
//! keeping the two apart is what lets the configuration matrix be tested entirely in
//! memory instead of by standing up backends.
//!
//! The distinction matters beyond testability. A plan that quietly performed I/O would
//! make "MCP-RE decided to construct X" and "MCP-RE successfully established X"
//! interchangeable claims, and every posture statement derived from them would inherit
//! the confusion.

use crate::config_state::validation::ValidatedDeployment;
use crate::config_state::ContinuationControlState;
use crate::config_state::ReplayState;
use crate::deployment_request::BindingKind;
use crate::replay_tier::ReplayDurabilityTier;
use crate::tls::IdentityStrategy;
use crate::transport::ReverseProxyMtlsProvider;

/// The authoritative replay tier this deployment asked for.
///
/// Carries the configuration each backend needs, already resolved and checked for
/// presence, so materialization has no config lookups left to fail on — only the build and
/// the environment.
///
/// **Two variants, because there are two live states.** There was a `Memory` variant with
/// a full materialization arm that nothing could reach: the boundary refuses
/// `--replay-cache memory` in every build, so no configuration produced it. And there was
/// never a `File` arm at all, which is what made `--replay-cache file` admissible at the
/// boundary and unstartable one stage later (CF-01).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayPlan {
    /// CP / linearizable, over the etcd v3 gateway.
    Etcd {
        endpoint: String,
        tier: ReplayDurabilityTier,
    },
    /// Horizontally scaled, over Redis.
    Redis {
        url: String,
        tier: ReplayDurabilityTier,
    },
}

impl ReplayPlan {
    /// Project the plan from the classified replay state and the validated locators.
    ///
    /// **Infallible.** It used to re-decide legality — which kind is offered, whether the
    /// selected mode has the value it requires — and those decisions are layer A's, made
    /// once, before this. What survives here is the projection: the state says which
    /// backend and carries the endpoint that made it legal, and the tier follows from the
    /// state rather than being fetched back out of the request.
    ///
    /// Refusals that depend on which backends were COMPILED IN stay with materialization.
    /// They are facts about the build, not about the request.
    pub fn from_validated(config: &ValidatedDeployment) -> ReplayPlan {
        let state = config.state().replay();
        // The tier is DERIVED from the state, not read beside it. Each arm therefore gets
        // the only tier its backend can serve, so no construction path pairs the etcd
        // store with a Redis quorum tier.
        let tier = state.durability_tier();
        match state {
            ReplayState::SharedLinearizable { endpoint } => ReplayPlan::Etcd {
                endpoint: endpoint.clone(),
                tier,
            },
            ReplayState::SharedRedis { url, .. } => ReplayPlan::Redis {
                url: url.clone(),
                tier,
            },
        }
    }

    /// Whether establishing THIS tier needs the shared control runtime.
    ///
    /// Only the Redis tier: the etcd store drives its own requests and the in-memory
    /// tier does no I/O. One contributor to the aggregate — never the decision itself.
    pub fn needs_control_runtime(&self) -> bool {
        cfg!(feature = "redis_replay") && matches!(self, ReplayPlan::Redis { .. })
    }
}
/// The in-flight bound the inner plane must not sit below, or `None` to leave its default.
///
/// PURE: `cores` is passed in rather than resolved here, because resolving it reads
/// `available_parallelism` and §5.2 keeps planning free of the environment. The RULE is
/// the pure part and is what needed testing; the machine's core count is an input to it.
///
/// # Why the inner pool is raised to meet the fleet
///
/// The pool is PROCESS-WIDE — one instance behind the `Arc` every core shares — so a bound
/// below the fleet's aggregate admission ceiling means requests that passed every security
/// gate are answered with a signed `inner server unavailable` at a capacity cliff no
/// configured flag names. The shedding decision would move from the admission gate, where
/// it is deliberate and measured, to the inner pool, where it is an accident of core count.
///
/// # One derivation, two consumers
///
/// The admission gate does not enforce a fleet-wide number. It gives every core the
/// per-core ceiling [`derived_per_core_ceiling`](crate::async_fleet::derived_per_core_ceiling)
/// produces and lets each core enforce only its own share, so the aggregate the fleet
/// actually admits is `per_core × cores` — whatever the operator wrote. When
/// `--max-in-flight-total` does not divide evenly the gate rounds each core's share UP,
/// and the aggregate therefore exceeds the requested total: `--max-in-flight-total 1000
/// --cores 3` admits `ceil(1000/3) × 3 = 1002`.
///
/// That is the gate's own rounding, and this ceiling is a PROJECTION of it rather than a
/// second reading of the same flags. A pool bounded at the requested 1000 against a gate
/// admitting 1002 is exactly the capacity cliff above, two requests wide.
pub fn inner_plane_ceiling(
    per_core: Option<usize>,
    total: Option<usize>,
    cores: usize,
) -> Option<usize> {
    crate::async_fleet::derived_per_core_ceiling(per_core, total, cores)
        .map(|n| n.saturating_mul(cores.max(1)))
}

/// Whether that ceiling requires raising the inner plane's default bound.
///
/// Separate from [`inner_plane_ceiling`] because "what is the fleet's ceiling" and "does it
/// exceed the pool's default" are different questions, and only the second one decides
/// whether an operator sees a startup line.
pub fn inner_plane_raise(ceiling: Option<usize>, default_bound: usize) -> Option<usize> {
    ceiling.filter(|c| *c > default_bound)
}

/// A wall-clock reading below this Unix-seconds threshold is treated as a host-clock
/// fault: 2000-01-01 UTC, far below any plausible real deployment time, so a legitimate
/// clock never trips it while a 0/epoch clock always does.
pub const EPOCH_CLOCK_FAULT_THRESHOLD_SECS: i64 = 946_684_800;

/// Whether `now_unix` indicates the host clock is unset or broken rather than merely
/// inaccurate (audit #94 F5).
///
/// The reading comes from the environment, but deciding that a given reading is a FAULT
/// is a rule, and it is the part that had to be testable: the caller cannot conjure a
/// broken host clock to exercise it. A wall clock at/near the epoch makes every freshness
/// check fail closed, so the whole deployment denies every request; that is safe but
/// indistinguishable from a load or policy problem unless startup names the cause.
///
/// `now_unix()` clamps a pre-epoch `SystemTime` error to 0, so 0 is the sentinel this must
/// catch, and any negative value that ever reached here is a fault by the same argument.
pub fn host_clock_is_faulted(now_unix: i64) -> bool {
    now_unix < EPOCH_CLOCK_FAULT_THRESHOLD_SECS
}

/// The kid naming the ROOT issuer that delegated credentials chain to (ADR-MCPRE-052).
///
/// A projection, not a derivation: layer A owns the rule that `--delegated-issuer-kid`
/// wins when set and the server key id names the issuer otherwise, and this reads the
/// value that rule produced
/// ([`DelegatedSigningFacts`](crate::config_state::DelegatedSigningFacts)). Both the trust
/// plane and the signing plane are handed the result rather than either producing it.
///
/// Planned, not materialized: the kid is a statement of INTENT about which issuer this
/// deployment will chain to, not evidence that the issuer answered. That ordering is
/// forced — trust is established well before the root issuer is invoked — and correct for
/// the same reason.
///
/// The invariant that makes it safe belongs to signing, and the two planes consume
/// opposite halves of it: this kid answers the Response slot, and it is never enrolled as
/// a REQUEST signer. They cannot disagree about which key that is, because there is one
/// resolved value and neither of them resolves it.
pub fn response_issuer_kid(config: &ValidatedDeployment) -> String {
    config.state().delegated_signing().issuer_kid().to_string()
}

/// Where the connection seam reads the client's identity from.
///
/// Three mutually-exclusive modes, and the exclusivity is the whole content of the
/// decision: an assertion-carried identity is verified INSIDE the proxy after signature
/// verification, a forwarded header is read at the seam and the local client certificate
/// is ignored, and direct mTLS reads the verified peer certificate. `parse_args` already
/// refuses the combinations, so this chooses rather than validates.
///
/// Pure, and derived from configuration alone, which is why it is here rather than in the
/// composition root: nothing about which field the identity comes from depends on what
/// this process has managed to establish. Selecting it beside the wiring made a
/// three-way exclusivity readable only by reading an `if`/`else` inside a 300-line
/// assembly, and testable only by starting a proxy.
pub fn identity_strategy(config: &ValidatedDeployment) -> IdentityStrategy {
    let values = config.config();
    // Mode B (lb-assertion) and Mode C (attested-ingress) both carry identity in the
    // signed `mcp-ingress-assertion` header, verified post-verification inside the proxy
    // rather than at the connection seam. The serve loop extracts the same header for
    // both, failing closed on a duplicate.
    if matches!(
        values.binding,
        BindingKind::LbAssertion | BindingKind::AttestedIngress
    ) {
        return IdentityStrategy::LbAssertion;
    }
    match &values.reverse_proxy_identity_header {
        None => IdentityStrategy::DirectTls,
        Some(header) => IdentityStrategy::ReverseProxyHeader(ReverseProxyMtlsProvider::new(
            header.clone(),
            values.reverse_proxy_header_format,
            values.identity_source,
        )),
    }
}

/// The shared trust-epoch mechanism, interpreted ONCE (CF-09).
///
/// Two planes act on this fact: trust flushes its cache when the epoch advances, and
/// delegated signing mints under the resulting label so an operator's `INCR` revokes
/// fleet-wide. They are consumers. Before this type they were two authorities — each
/// reading `--trust-epoch-redis-url`, each defaulting `--trust-epoch-key`, each with its
/// own build refusal — and the only reason they agreed was that they read the same fields
/// in the same way. Nothing made them.
///
/// The key is DEFAULTED here, once, for the same reason: a default applied at two sites is
/// two decisions that happen to coincide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustEpochPlan {
    /// No networked source. The trust cache runs at its declared bound, and delegated
    /// signing mints under the bare `--delegated-trust-epoch` label — the honest
    /// single-node shape, not a degraded one.
    NoNetworkChannel,
    /// A networked epoch counter at this location, under this key.
    Redis {
        /// Where the counter lives.
        url: String,
        /// The key holding it, already defaulted.
        key: String,
    },
}

impl TrustEpochPlan {
    /// Project the plan from the classified trust-revocation state and the validated
    /// locator.
    ///
    /// Infallible: `PushNetworked` is the state that HAS a source, so layer A has already
    /// established both that this deployment may carry one and that it does.
    pub fn from_validated(config: &ValidatedDeployment) -> TrustEpochPlan {
        match config.state().trust_revocation() {
            crate::config_state::TrustRevocationState::PushNetworked {
                epoch_url,
                epoch_key,
                ..
            } => TrustEpochPlan::Redis {
                url: epoch_url.clone(),
                key: epoch_key.clone(),
            },
            _ => TrustEpochPlan::NoNetworkChannel,
        }
    }

    /// Why THIS BUILD cannot establish the plan, if it cannot — layer B, stated once.
    ///
    /// Both planes refused a configured epoch source in a build without a Redis client,
    /// in two places, with two different messages naming two different consequences. Each
    /// message was true and neither was complete, and which one an operator met was decided
    /// by materialization order. One refusal states both consequences.
    pub fn unsupported_by_build(&self) -> Option<String> {
        match self {
            TrustEpochPlan::NoNetworkChannel => None,
            TrustEpochPlan::Redis { .. } if cfg!(feature = "redis_replay") => None,
            TrustEpochPlan::Redis { .. } => Some(
                "--trust-epoch-redis-url requires a build with the `redis_replay` feature. \
                 Without it the trust cache has no networked invalidation channel, and \
                 delegated credentials would be minted under the bare --delegated-trust-epoch \
                 label — which the operator's INCR kill switch cannot revoke. Refusing to \
                 start (fail closed, ADR-MCPRE-052 §7)"
                    .to_string(),
            ),
        }
    }
}

/// How the `--trust` file is kept current.
///
/// A state, not a missing value: no tier resolves a revocation faster than the store is
/// re-read, so a deployment that reads it once has declared that revoking a request-signer
/// key costs a restart of every replica.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustReloadPlan {
    /// `--trust` is read once. Only `BoundedCache` may be in this state.
    ReadOnceAtStartup,
    /// Re-read on this cadence, so a key removed from the file stops resolving within it.
    Every {
        /// The cadence, in seconds. Non-zero because a zero cadence is a spinning reloader,
        /// which layer A refuses — so `Every { secs: 0 }` has no constructor.
        secs: std::num::NonZeroU64,
    },
}

impl TrustReloadPlan {
    /// The cadence, where there is one.
    pub fn cadence_secs(&self) -> Option<std::num::NonZeroU64> {
        match self {
            TrustReloadPlan::ReadOnceAtStartup => None,
            TrustReloadPlan::Every { secs } => Some(*secs),
        }
    }
}

/// What the trust plane must establish (ADR-MCPRE-056 §8).
///
/// Everything the plane needs and nothing it could re-decide: the classified revocation
/// state, the two locators, and the epoch mechanism normalized above it. `TrustPlane` used
/// to receive the whole `ValidatedDeployment` and answer "which posture is this?" for itself —
/// a second derivation of a fact layer A had already classified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustPlan {
    /// Which revocation posture this deployment asked for.
    pub revocation: crate::config_state::TrustRevocationState,
    /// The trust document.
    pub trust_path: String,
    /// The root issuer whose key must never be enrolled as a request signer.
    pub response_kid: String,
    /// How the document is kept current.
    pub reload: TrustReloadPlan,
    /// The shared epoch mechanism — an INPUT, so this plane cannot become its authority
    /// merely by being materialized first (CF-09).
    pub epoch: TrustEpochPlan,
}

impl TrustPlan {
    /// Project the plan from the retained classification and the validated locators.
    ///
    /// `response_kid` and `epoch` are passed IN rather than derived here. Both are shared
    /// with the signing plane, and a value derived inside one consumer is a value the other
    /// consumer must re-derive.
    pub fn from_validated(
        config: &ValidatedDeployment,
        response_kid: String,
        epoch: TrustEpochPlan,
    ) -> TrustPlan {
        let values = config.config();
        TrustPlan {
            revocation: config.state().trust_revocation().clone(),
            trust_path: values.trust_path.clone(),
            response_kid,
            reload: trust_reload_plan(config.state().trust_revocation()),
            epoch,
        }
    }
}

/// How often `--trust` is re-read, decided from the state rather than from the request.
///
/// Three of the four states CARRY a cadence, because their Required column names one, so
/// none of them can be projected to `ReadOnceAtStartup` — the posture that would silently
/// contradict a tier whose whole claim is that the store is re-read. Only `BoundedCache`
/// consults the validated request, because only there is the cadence optional and both
/// postures legal.
fn trust_reload_plan(state: &crate::config_state::TrustRevocationState) -> TrustReloadPlan {
    use crate::config_state::TrustRevocationState as S;
    match state {
        S::Live { reload_secs }
        | S::PushInert { reload_secs, .. }
        | S::PushNetworked { reload_secs, .. } => TrustReloadPlan::Every { secs: *reload_secs },
        // Total, and reading no raw value: layer A normalized the optional cadence, so
        // there is no `Some(0)` left to filter here — and therefore no way for a refused
        // request to be re-read as a different legal posture.
        S::BoundedCache { reload_secs, .. } => match reload_secs {
            Some(secs) => TrustReloadPlan::Every { secs: *secs },
            None => TrustReloadPlan::ReadOnceAtStartup,
        },
    }
}

/// What response-signing custody must establish (ADR-MCPRE-052).
///
/// Delegated signing is the only response mode, so this is a STRUCT and not an enum: the
/// atlas classifies it as guard-only, with one state, and manufacturing variants for
/// symmetry with `ClientRevocationPlan` would describe postures that do not exist.
///
/// The plan holds the normalized custody policy itself. Every default is applied here,
/// once — and that is not cosmetic. `issuer_kid` was derived in TWO places: by
/// [`response_issuer_kid`], whose value the startup transcript prints and which the trust
/// plane excludes from the request-signer set, and again inside the delegated wiring, which
/// is the one that reached the credential. Both spelled `--delegated-issuer-kid` falling
/// back to `--server-key-id`, so they agreed; nothing made them. A deployment could
/// therefore have been told it was chaining to one issuer while minting under another —
/// the same class of declared-versus-established gap the TLS custody check closes, except
/// that here it is closed structurally, by there being one derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningPlan {
    /// The credential policy the rotor mints under, fully resolved.
    pub custody: mcp_re_http_profile::CustodyConfig,
    /// The shared epoch mechanism — an INPUT, exactly as it is for `TrustPlan`. Trust
    /// landing first must not make it the source (CF-09).
    pub epoch: TrustEpochPlan,
}

impl SigningPlan {
    /// Project the plan from the validated configuration and the two shared decisions.
    ///
    /// **Infallible.** It used to be two refusals inside the wiring: a missing trust epoch
    /// and `0 < overlap < ttl`. The second was already a boundary clause and the first is
    /// one now, so both are layer A's, made once, before this.
    ///
    /// `response_kid` and `epoch` are passed IN. Signing is the SECOND consumer of both,
    /// and the temptation this shape removes is precisely the one that comes with being
    /// second: deriving from the sibling that landed first, or from configuration, rather
    /// than from the authority above them.
    pub fn from_validated(
        config: &ValidatedDeployment,
        response_kid: String,
        epoch: TrustEpochPlan,
    ) -> SigningPlan {
        let values = config.config();
        let facts = config.state().delegated_signing();
        let identity = config.state().server_identity().actor();
        SigningPlan {
            custody: mcp_re_http_profile::CustodyConfig {
                issuer_kid: response_kid,
                iss: identity.subject.clone(),
                profile: mcp_re_http_profile::PROFILE_TAG.to_string(),
                aud: values.audience.clone(),
                audience_hash: facts.audience_hash().to_string(),
                trust_epoch: facts.trust_epoch().to_string(),
                // The three identity components come from the ONE derived identity rather
                // than from the primitives; a second assembly here is what let this and
                // `app::run_validated` disagree about what the server's actor identity is.
                server_role: identity.role.clone(),
                server_trust_domain: identity.trust_domain.clone(),
                server_subject: identity.subject.clone(),
                ttl: values.delegated_ttl_secs,
                overlap: values.delegated_overlap_secs,
            },
            epoch,
        }
    }
}

/// What offline client-certificate revocation must establish.
///
/// The posture is a VARIANT, not a pair of primitives a consumer re-reads. Layer A already
/// classified `None`/`Static`/`Reloading` (§C.6), and a plan carrying `Vec<String>` beside
/// `Option<u64>` would invite the plane to rediscover that classification from
/// `paths.is_empty()` and `cadence.is_some()` — obeying the letter of "planning consumes
/// the classification" while reconstructing it one field at a time.
///
/// Each variant carries exactly what ITS posture needs. `None` cannot hold paths and
/// `Static` cannot hold a cadence, so the combinations layer A refuses are not merely
/// unreachable but unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientRevocationPlan {
    /// No CRLs. Revocation rests on the client-certificate lifetime ceiling alone, which
    /// is a posture rather than an absence — see [`crate::tls_plane::fleet_crl_bound`].
    None,
    /// CRLs read once at startup. A revocation published afterwards reaches this replica
    /// when the CRL passes its own `nextUpdate`, or on a restart.
    Static {
        /// The files to read.
        paths: Vec<String>,
    },
    /// CRLs re-read on a cadence, so a revocation published after startup takes effect
    /// within it — on established connections as well as at the handshake.
    Reloading {
        /// The files to read.
        paths: Vec<String>,
        /// Seconds between re-reads. Layer A holds it above zero.
        cadence_secs: u64,
    },
}

impl ClientRevocationPlan {
    /// Project the plan from the classified state and the validated locators.
    ///
    /// Infallible: `Static` and `Reloading` are the states that HAVE paths, and
    /// `Reloading` is the state that has a cadence, so layer A has already established
    /// that each value the variant requires is present.
    pub fn from_validated(config: &ValidatedDeployment) -> ClientRevocationPlan {
        use crate::config_state::CrlRevocationState as S;
        match config.state().crl_revocation() {
            S::None => ClientRevocationPlan::None,
            S::Static { paths } => ClientRevocationPlan::Static {
                paths: paths.clone(),
            },
            S::Reloading {
                paths,
                cadence_secs,
            } => ClientRevocationPlan::Reloading {
                paths: paths.clone(),
                cadence_secs: *cadence_secs,
            },
        }
    }

    /// The files to read, empty where the posture reads none.
    ///
    /// For materialization, which loads the same bytes under both CRL-bearing postures —
    /// not for deciding which posture this is. That is what the variant is for.
    pub fn paths(&self) -> &[String] {
        match self {
            ClientRevocationPlan::None => &[],
            ClientRevocationPlan::Static { paths }
            | ClientRevocationPlan::Reloading { paths, .. } => paths,
        }
    }
}

/// What the TLS plane must establish (ADR-MCPRE-056 §8).
///
/// Two classified states and the resource inputs each posture needs. The certificate
/// lifetime and the connection-age bound are INPUTS, not decisions: X5's compatibility
/// relation between them was settled at layer A and is not re-checked here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsPlan {
    /// Whether the handshake key can leave the device it lives on.
    pub custody: crate::config_state::TlsCustodyState,
    /// The offline client-certificate revocation posture.
    pub client_revocation: ClientRevocationPlan,
    /// The client-certificate lifetime ceiling, for the operator-facing exposure window.
    pub max_client_cert_lifetime: Option<std::time::Duration>,
    /// The connection-age bound the exposure window's honesty depends on.
    pub max_connection_age: Option<std::time::Duration>,
}

impl TlsPlan {
    /// Project the plan from the retained classification and the validated inputs.
    ///
    /// **Infallible, deliberately.** Whether this binary has a PKCS#11, AWS or GCP backend
    /// for delegated custody is a fact about the BUILD, and making this fallible for it
    /// would collapse the A/B split: the request is coherent either way, and only
    /// materialization can say whether this executable can serve it.
    pub fn from_validated(config: &ValidatedDeployment) -> TlsPlan {
        let values = config.config();
        TlsPlan {
            custody: config.state().tls_custody().clone(),
            client_revocation: ClientRevocationPlan::from_validated(config),
            max_client_cert_lifetime: values.max_client_cert_lifetime,
            max_connection_age: values.limits.max_connection_age,
        }
    }
}

/// What the MRTR continuation store must establish (ADR-MCPS-047, CF-12).
///
/// `Disabled` is a posture, not an absence: cross-replica continuation is opportunistic,
/// so a deployment without it is a deployment whose multi-round-trip flows are
/// single-replica and whose cross-replica answers fail closed at the binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContinuationControlPlan {
    /// No shared store; flows resolve on the replica that opened them.
    Disabled,
    /// A shared Redis store at this endpoint.
    Redis {
        /// The continuation store's OWN endpoint. It is not the replay store's, even when
        /// an operator points both at the same Redis.
        endpoint: String,
    },
}

impl ContinuationControlPlan {
    /// Project the plan from the classified state and the validated locator.
    ///
    /// Infallible: layer A already decided that this state is legal and that the locator
    /// is present where the state requires one, so there is no second refusal to make.
    pub fn from_validated(config: &ValidatedDeployment) -> ContinuationControlPlan {
        match config.state().continuation_control() {
            ContinuationControlState::Disabled => ContinuationControlPlan::Disabled,
            ContinuationControlState::Redis { endpoint } => ContinuationControlPlan::Redis {
                endpoint: endpoint.clone(),
            },
        }
    }

    /// Whether establishing this plan needs the shared control runtime.
    ///
    /// One contributor to the aggregate — never the decision itself.
    pub fn needs_control_runtime(&self) -> bool {
        cfg!(feature = "redis_replay") && matches!(self, ContinuationControlPlan::Redis { .. })
    }
}

/// Whether the §7 admission-currency gate will be wired (MCPRE-493).
///
/// Its Redis endpoint is its OWN; it has nothing to do with which replay tier was
/// chosen. Deriving it from replay once made admission unimplementable on the
/// CP/linearizable tier, and the natural resolution was to turn the control off.
pub fn admission_needs_control_runtime(config: &ValidatedDeployment) -> bool {
    cfg!(feature = "redis_replay") && config.state().admission().is_enforced()
}

/// Aggregate the control-runtime requirement across EVERY capability that can need it.
///
/// No single consumer owns this decision; each declares, the aggregate decides.
///
/// The `cfg!` guards yield a compile-time `false` without `redis_replay`, and the
/// predicates beside them touch only configuration types present in every build — no
/// Redis-only symbol appears here. `cfg!` does not remove code from compilation the way
/// `#[cfg]` does, so a future contributor that names a feature-gated type would fail to
/// build in the default lane rather than being silently excluded. Keep them that way.
pub fn control_runtime_requirement(
    config: &ValidatedDeployment,
    replay: &ReplayPlan,
) -> crate::control_runtime::ControlRuntimeRequirement {
    crate::control_runtime::ControlRuntimeRequirement::any([
        replay.needs_control_runtime(),
        ContinuationControlPlan::from_validated(config).needs_control_runtime(),
        admission_needs_control_runtime(config),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deployment_request::DeploymentRequest;

    /// A configuration that gets all the way through parsing AND validation, so the
    /// mutation each test applies is the only thing under test.
    ///
    /// Every path points at something that does not exist. That is deliberate: if
    /// planning ever starts reading the environment, these stop passing.
    fn base_argv(extra: &[&str]) -> Vec<String> {
        let mut argv: Vec<String> = [
            "--bind",
            "127.0.0.1:0",
            "--audience",
            "did:example:server-1",
            "--server-signer",
            "did:example:server-1",
            "--server-key-id",
            "k1",
            "--delegated-trust-epoch",
            "epoch-1",
            "--signing-key-seed",
            "/nonexistent/seed",
            "--tls-cert",
            "/nonexistent/cert",
            "--tls-key",
            "/nonexistent/key",
            "--client-ca",
            "/nonexistent/ca",
            "--trust",
            "/nonexistent/trust",
            "--target-uri",
            "https://localhost/",
            "--trust-domain",
            "example.org",
            "--inner-http-url",
            "http://127.0.0.1:9/mcp",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
        argv.extend(extra.iter().map(|s| (*s).to_string()));
        argv
    }

    fn parse(extra: &[&str]) -> Result<DeploymentRequest, String> {
        crate::cli::parse_args(&base_argv(extra))
    }

    fn strategy_for(extra: &[&str]) -> IdentityStrategy {
        let mut argv: Vec<&str> = SHARED_REDIS.to_vec();
        argv.extend_from_slice(extra);
        let config = parse(&argv).expect("args parse");
        let validated = ValidatedDeployment::try_from(config).expect("config validates");
        identity_strategy(&validated)
    }

    /// A deployable configuration reads identity from the verified peer certificate.
    ///
    /// `DirectTls` is the only arm a `ValidatedDeployment` can select today. The other two
    /// belong to capabilities the boundary refuses — see the test below — so this is not
    /// "the default among three" but "the one that exists".
    #[test]
    fn a_deployable_configuration_reads_the_verified_peer_certificate() {
        assert!(matches!(strategy_for(&[]), IdentityStrategy::DirectTls));
    }

    /// The other two arms are unreachable through the boundary, and that is the property
    /// worth pinning.
    ///
    /// `ReverseProxyHeader` trusts a forwarded header any peer reaching the socket could
    /// spoof; `LbAssertion` serves the two ingress-assertion modes. Both are refused by
    /// `unsafe_config_violations`, so no command line reaches them — they are retained
    /// capabilities (`docs/AGENT_INSTRUCTIONS.md` §9), not dead vocabulary, and the
    /// distinction is exactly that a decision gates them rather than nothing does.
    ///
    /// This asserts the refusal rather than the strategy because that is what makes the
    /// classifier's shape honest: if one of these ever becomes selectable, this fails and
    /// the arm needs its own coverage rather than acquiring it silently.
    #[test]
    fn the_assertion_and_forwarded_identity_arms_are_refused_at_the_boundary() {
        for extra in [
            vec!["--reverse-proxy-identity-header", "x-client-id"],
            vec!["--transport-binding", "lb-assertion"],
            vec!["--transport-binding", "attested-ingress"],
        ] {
            let mut argv: Vec<&str> = SHARED_REDIS.to_vec();
            argv.extend_from_slice(&extra);
            assert!(
                parse(&argv).is_err(),
                "{extra:?} must be refused at the boundary; if it now starts, \
                 identity_strategy has a reachable arm with no test"
            );
        }
    }

    /// Plan a configuration that came through the parser intact.
    fn plan_for(extra: &[&str]) -> ReplayPlan {
        let config = parse(extra).expect("args parse");
        let validated = ValidatedDeployment::try_from(config).expect("config validates");
        ReplayPlan::from_validated(&validated)
    }

    /// Why a configuration is not a replay deployment at all.
    ///
    /// `parse_args` runs its own completeness checks, so an incomplete shared tier never
    /// survives the command line. Those checks are not what protects the runtime: `DeploymentRequest`
    /// has public fields and `run` accepts anything that validates, so an embedder that
    /// builds one in code meets only the boundary. Mutating a parsed config reproduces
    /// such a caller exactly — and since layer A now classifies replay, these refusals are
    /// the boundary's, not planning's.
    fn refusal_for_mutated(extra: &[&str], mutate: impl FnOnce(&mut DeploymentRequest)) -> String {
        let mut config = parse(extra).expect("args parse");
        mutate(&mut config);
        ValidatedDeployment::try_from(config).expect_err("the mutation must be refused")
    }

    const SHARED_REDIS: &[&str] = &[
        "--replay-durability-tier",
        "redis-wait-quorum:2:2000",
        "--replay-redis-url",
        "redis://127.0.0.1:6379",
    ];

    const SHARED_LINEARIZABLE: &[&str] = &[
        "--replay-durability-tier",
        "linearizable",
        "--cpstore-etcd-endpoint",
        "http://127.0.0.1:2379",
    ];

    /// The in-memory tier never reaches planning, because validation refuses it outright
    /// — it is non-durable, and a restart re-opens a replay window for any still-fresh
    /// captured envelope.
    ///
    /// `ReplayPlan` no longer has a `Memory` variant to reach: it had a full
    /// materialization arm that no configuration could produce. This is pinned so that a
    /// later change which makes validation accept memory has to fail a test rather than
    /// quietly restore a non-durable production tier.
    /// A request that declares no durable replay configuration fails closed.
    ///
    /// The durability tier is the only replay selector, and there is no node-local state to
    /// fall back to, so saying nothing about replay must refuse rather than acquire an
    /// implicit store. Checked at both altitudes because they can disagree: on the command
    /// line, and for a caller that never touched one.
    #[test]
    fn a_request_with_no_durable_replay_configuration_fails_closed() {
        // A command line carrying every other required flag but no replay configuration.
        let from_argv = parse(&[]).expect_err("no replay configuration must not validate");
        assert!(
            from_argv.contains("--replay-durability-tier"),
            "the refusal must name what is missing: {from_argv}"
        );

        // And for a programmatic request, which is the altitude that guards the runtime.
        let err = refusal_for_mutated(SHARED_REDIS, |c| c.replay_durability_tier = None);
        assert!(
            err.contains("--replay-durability-tier"),
            "a request whose tier is cleared must be refused: {err}"
        );
    }

    #[test]
    fn linearizable_plans_etcd_at_the_declared_endpoint() {
        assert_eq!(
            plan_for(SHARED_LINEARIZABLE),
            ReplayPlan::Etcd {
                endpoint: "http://127.0.0.1:2379".to_string(),
                tier: ReplayDurabilityTier::Linearizable,
            }
        );
    }

    /// The declared WAIT parameters survive planning intact. Materialization sizes the
    /// client response timeout from them BEFORE connecting, so a plan that dropped them
    /// would silently restore the defect where a declared 2000ms wait could never exceed
    /// the redis library's 500ms per-command default.
    #[test]
    fn a_redis_tier_carries_its_url_and_its_wait_parameters() {
        match plan_for(SHARED_REDIS) {
            ReplayPlan::Redis { url, tier } => {
                assert_eq!(url, "redis://127.0.0.1:6379");
                assert_eq!(tier.wait_quorum_params(), Some((2, 2000)));
            }
            other => panic!("expected a redis plan, got {other:?}"),
        }
    }

    #[test]
    fn a_shared_tier_that_skipped_the_parser_is_refused_without_a_durability_tier() {
        let err = refusal_for_mutated(SHARED_REDIS, |c| c.replay_durability_tier = None);
        assert!(err.contains("--replay-durability-tier"), "{err}");
    }

    #[test]
    fn a_shared_redis_tier_that_skipped_the_parser_is_refused_without_a_url() {
        let err = refusal_for_mutated(SHARED_REDIS, |c| c.replay_redis_url = None);
        assert!(err.contains("--replay-redis-url"), "{err}");
    }

    /// The linearizable claim is never silently downgraded to redis or to memory: with no
    /// CPStore endpoint the tier is refused, not resolved to something weaker.
    #[test]
    fn a_linearizable_tier_that_skipped_the_parser_is_refused_without_an_endpoint() {
        let err = refusal_for_mutated(SHARED_LINEARIZABLE, |c| c.cpstore_etcd_endpoint = None);
        assert!(err.contains("--cpstore-etcd-endpoint"), "{err}");
    }

    /// The property that makes the whole layer worth having, asserted rather than left
    /// incidental: a complete networked tier is planned against a TEST-NET-3 host that is
    /// never contacted, from a config whose every file path does not exist.
    #[test]
    fn planning_reaches_a_networked_tier_without_contacting_anything() {
        let plan = plan_for(&[
            "--replay-durability-tier",
            "redis-wait-quorum:2:2000",
            "--replay-redis-url",
            "redis://203.0.113.1:6379",
        ]);
        assert!(matches!(plan, ReplayPlan::Redis { .. }));
    }

    /// The explicit issuer kid wins; without one the server key id names the issuer.
    /// Both planes must be handed the SAME answer, which is why it is derived here.
    #[test]
    fn the_issuer_kid_falls_back_to_the_server_key_id() {
        let config = parse(SHARED_REDIS).expect("args parse");
        let validated = ValidatedDeployment::try_from(config).expect("config validates");
        assert_eq!(
            response_issuer_kid(&validated),
            "k1",
            "with no --delegated-issuer-kid the server key id names the issuer"
        );

        let explicit = parse(&[SHARED_REDIS, &["--delegated-issuer-kid", "root-kms-1"]].concat())
            .expect("args parse");
        let validated = ValidatedDeployment::try_from(explicit).expect("config validates");
        assert_eq!(response_issuer_kid(&validated), "root-kms-1");
    }

    // ---- control-runtime requirement -------------------------------------------
    //
    // Each contributor is asserted on its own, then the aggregation separately. A test
    // that only exercised the aggregate boolean could not tell which consumer had
    // stopped declaring its requirement — and the historical defect was exactly one
    // consumer's need being inferred from another's.

    /// The feature lane is the only one where any of these can be true, because every
    /// Redis-dependent capability refuses outright in a build without the backend.
    const REDIS: bool = cfg!(feature = "redis_replay");

    #[test]
    fn only_the_redis_replay_tier_declares_a_need() {
        let redis = plan_for(SHARED_REDIS);
        assert_eq!(redis.needs_control_runtime(), REDIS);

        let etcd = plan_for(SHARED_LINEARIZABLE);
        assert!(
            !etcd.needs_control_runtime(),
            "the etcd store drives its own requests"
        );
    }

    /// Keyed on its OWN locator, and independent of the replay tier (CF-12).
    ///
    /// This test used to assert that `--replay-redis-url` beside a linearizable tier
    /// switched continuation on. That was the alias: one field naming the replay store
    /// under one tier and the continuation store under another. The configuration it
    /// described is now refused, and the capability it wanted is expressed directly.
    #[test]
    fn continuation_declares_on_its_own_locator_not_the_replay_tier() {
        // The negative control for the split: a CP replay store AND a shared continuation
        // store, which the alias made impossible to state without overloading a field.
        let both = parse(&[
            "--replay-durability-tier",
            "linearizable",
            "--cpstore-etcd-endpoint",
            "http://127.0.0.1:2379",
            "--continuation-control-redis-url",
            "redis://127.0.0.1:6379",
        ])
        .expect("args parse");
        let validated = ValidatedDeployment::try_from(both).expect("independent facts, both legal");
        assert_eq!(
            ContinuationControlPlan::from_validated(&validated).needs_control_runtime(),
            REDIS
        );
        assert!(
            !ReplayPlan::from_validated(&validated).needs_control_runtime(),
            "the tier is etcd, so replay itself declares nothing"
        );

        // And the converse: the replay store's locator no longer reaches continuation.
        let no_continuation = parse(SHARED_LINEARIZABLE).expect("args parse");
        let validated = ValidatedDeployment::try_from(no_continuation).expect("validates");
        assert_eq!(
            ContinuationControlPlan::from_validated(&validated),
            ContinuationControlPlan::Disabled
        );
        assert!(!ContinuationControlPlan::from_validated(&validated).needs_control_runtime());
    }

    /// The clean break: the old overloaded configuration is refused at layer A, not
    /// silently reinterpreted as continuation configuration.
    #[test]
    fn the_old_alias_is_refused_rather_than_reinterpreted() {
        let refusal = parse(&[
            "--replay-durability-tier",
            "linearizable",
            "--cpstore-etcd-endpoint",
            "http://127.0.0.1:2379",
            "--replay-redis-url",
            "redis://127.0.0.1:6379",
        ])
        .expect_err("the alias is refused");
        assert!(
            refusal.contains("--replay-redis-url is not valid"),
            "{refusal}"
        );
        assert!(
            refusal.contains("--continuation-control-redis-url"),
            "the refusal must name the setting that replaces the overloaded use: {refusal}"
        );
    }

    // ---- the trust plan (CF-09, CF-10) ------------------------------------------

    /// A push tier with a networked epoch source, which is the only state that plans one.
    const PUSH_NETWORKED: &[&str] = &[
        "--revocation-tier",
        "push:30",
        "--trust-reload-secs",
        "15",
        "--trust-epoch-redis-url",
        "redis://127.0.0.1:6379",
    ];

    fn validated(extra: &[&str]) -> ValidatedDeployment {
        let config = parse(&[SHARED_REDIS, extra].concat()).expect("args parse");
        ValidatedDeployment::try_from(config).expect("config validates")
    }

    /// The refresh posture comes from the STATE's witness, not from the request beside it.
    ///
    /// Three of the four trust states carry their cadence because their Required column
    /// names one. The structural property that buys: no reload-bearing state can be
    /// projected to `ReadOnceAtStartup`, which would silently contradict a tier whose whole
    /// claim is that the store is re-read.
    ///
    /// The projection cannot consult the request at all — `trust_reload_plan` takes only
    /// the state — so this asserts what remains: that each reload-bearing state projects
    /// its OWN carried cadence rather than some default.
    #[test]
    fn a_reload_bearing_state_cannot_be_projected_to_read_once() {
        use crate::config_state::TrustRevocationState as S;
        let carried = [
            S::Live {
                reload_secs: crate::config_state::TrustRevocationState::cadence(7),
            },
            S::PushInert {
                t_secs: 30,
                reload_secs: crate::config_state::TrustRevocationState::cadence(7),
            },
            S::PushNetworked {
                t_secs: 30,
                reload_secs: crate::config_state::TrustRevocationState::cadence(7),
                epoch_url: "redis://127.0.0.1:6379".to_string(),
                epoch_key: "k".to_string(),
            },
        ];
        for state in carried {
            assert_eq!(
                trust_reload_plan(&state),
                TrustReloadPlan::Every {
                    secs: crate::config_state::TrustRevocationState::cadence(7)
                },
                "{state:?} must project its own cadence, not the request's absence"
            );
        }
    }

    /// The other half of the same rule: `BoundedCache`'s cadence is OPTIONAL, so it is not
    /// a witness and both postures stay reachable through the validated request.
    ///
    /// If this collapsed to one answer it would mean the witness rule had been over-applied
    /// — an optional parameter moved into a state that does not require it.
    #[test]
    fn bounded_cache_keeps_both_refresh_postures() {
        use crate::config_state::TrustRevocationState as S;
        assert_eq!(
            trust_reload_plan(&S::BoundedCache {
                t_secs: 60,
                reload_secs: None,
            }),
            TrustReloadPlan::ReadOnceAtStartup,
            "an omitted cadence under bounded-cache reads the store once"
        );
        assert_eq!(
            trust_reload_plan(&S::BoundedCache {
                t_secs: 60,
                reload_secs: Some(S::cadence(60)),
            }),
            TrustReloadPlan::Every {
                secs: S::cadence(60)
            },
            "a supplied cadence under bounded-cache still re-reads"
        );
    }

    /// The epoch is planned from the CLASSIFICATION, and the key is defaulted here —
    /// once. Both planes used to default it for themselves, which is two decisions that
    /// happened to coincide.
    #[test]
    fn the_epoch_plan_normalizes_the_key_once() {
        assert_eq!(
            TrustEpochPlan::from_validated(&validated(PUSH_NETWORKED)),
            TrustEpochPlan::Redis {
                url: "redis://127.0.0.1:6379".to_string(),
                key: crate::trust_epoch::DEFAULT_TRUST_EPOCH_KEY.to_string(),
            },
            "an unset --trust-epoch-key is resolved in the plan, not in each consumer"
        );
        assert_eq!(
            TrustEpochPlan::from_validated(&validated(
                &[PUSH_NETWORKED, &["--trust-epoch-key", "mcp-re:epoch"]].concat()
            )),
            TrustEpochPlan::Redis {
                url: "redis://127.0.0.1:6379".to_string(),
                key: "mcp-re:epoch".to_string(),
            }
        );
    }

    /// Every state that is not `PushNetworked` plans no channel. Asserted across all four
    /// rather than only on the default, because the absence of a channel is the honest
    /// single-node posture and not a failure to configure one.
    #[test]
    fn only_the_networked_push_state_plans_an_epoch_source() {
        for extra in [
            &[][..],
            &["--revocation-tier", "live", "--trust-reload-secs", "5"][..],
            &["--revocation-tier", "push:30", "--trust-reload-secs", "15"][..],
        ] {
            let plan = TrustEpochPlan::from_validated(&validated(extra));
            assert_eq!(
                plan,
                TrustEpochPlan::NoNetworkChannel,
                "{extra:?} planned a channel"
            );
            assert!(
                plan.unsupported_by_build().is_none(),
                "a plan with no channel is establishable by every build"
            );
        }
    }

    /// The layer-B refusal is the PLAN's, so both consumers state the same one. It names
    /// both consequences, because each plane used to name only its own.
    #[test]
    fn the_build_refusal_is_stated_once_and_names_both_consequences() {
        let plan = TrustEpochPlan::from_validated(&validated(PUSH_NETWORKED));
        match (plan.unsupported_by_build(), cfg!(feature = "redis_replay")) {
            (None, true) => {}
            (Some(refusal), false) => {
                assert!(refusal.contains("redis_replay"), "{refusal}");
                assert!(
                    refusal.contains("invalidation"),
                    "the trust consequence must be named: {refusal}"
                );
                assert!(
                    refusal.contains("kill switch"),
                    "the signing consequence must be named: {refusal}"
                );
            }
            (verdict, redis) => panic!("build support {redis} disagreed with {verdict:?}"),
        }
    }

    /// The plan carries the classified posture rather than the tier flag, and the reload
    /// cadence as a state rather than an `Option` a consumer has to interpret.
    #[test]
    fn the_trust_plan_carries_the_retained_classification() {
        let config = validated(PUSH_NETWORKED);
        let plan = TrustPlan::from_validated(
            &config,
            "root-1".to_string(),
            TrustEpochPlan::from_validated(&config),
        );
        assert_eq!(
            plan.revocation,
            crate::config_state::TrustRevocationState::PushNetworked {
                t_secs: 30,
                reload_secs: crate::config_state::TrustRevocationState::cadence(15),
                epoch_url: "redis://127.0.0.1:6379".to_string(),
                epoch_key: crate::trust_epoch::DEFAULT_TRUST_EPOCH_KEY.to_string(),
            },
            "the plan must hold what layer A classified, not re-read --revocation-tier"
        );
        assert_eq!(
            plan.reload,
            TrustReloadPlan::Every {
                secs: crate::config_state::TrustRevocationState::cadence(15)
            }
        );
        assert_eq!(plan.response_kid, "root-1");
        assert!(matches!(plan.epoch, TrustEpochPlan::Redis { .. }));

        let default_tier = validated(&[]);
        let plan = TrustPlan::from_validated(
            &default_tier,
            "root-1".to_string(),
            TrustEpochPlan::from_validated(&default_tier),
        );
        assert_eq!(
            plan.reload,
            TrustReloadPlan::ReadOnceAtStartup,
            "no cadence is a posture, not a missing value"
        );
    }

    /// The issuer kid and the epoch are INPUTS to the trust plan.
    ///
    /// This is the structural half of CF-09: with both passed in, the trust plan cannot
    /// become their authority merely by being the first consumer written. The assertion is
    /// that a plan built with a value the configuration does not name carries that value —
    /// which is only possible because nothing inside re-derives it.
    #[test]
    fn the_shared_values_are_inputs_the_trust_plan_cannot_re_derive() {
        let config = validated(PUSH_NETWORKED);
        assert_ne!(
            response_issuer_kid(&config),
            "decided-above",
            "the fixture must not coincide with what a re-derivation would produce"
        );
        let plan = TrustPlan::from_validated(
            &config,
            "decided-above".to_string(),
            TrustEpochPlan::Redis {
                url: "redis://198.51.100.1:6379".to_string(),
                key: "decided-above".to_string(),
            },
        );
        assert_eq!(plan.response_kid, "decided-above");
        assert_eq!(
            plan.epoch,
            TrustEpochPlan::Redis {
                url: "redis://198.51.100.1:6379".to_string(),
                key: "decided-above".to_string(),
            }
        );
    }

    // ---- the signing plan ----------------------------------------------------------

    /// The issuer kid has ONE derivation, and the plan carries whatever it is handed.
    ///
    /// The defect this closes: the kid was derived twice — by `response_issuer_kid`, whose
    /// value the startup transcript prints and which trust excludes from the request-signer
    /// set, and again inside the delegated wiring, which is the one that reached the
    /// credential. Both spelled the same fallback, so they agreed. A deployment could
    /// otherwise have been told it was chaining to one issuer while minting under another.
    ///
    /// Asserted with a kid the configuration does not name, which is only possible because
    /// nothing inside re-derives it.
    #[test]
    fn the_issuer_kid_in_the_credential_is_the_one_that_was_planned() {
        let config = validated(&[]);
        assert_ne!(response_issuer_kid(&config), "decided-above");
        let plan = SigningPlan::from_validated(
            &config,
            "decided-above".to_string(),
            TrustEpochPlan::NoNetworkChannel,
        );
        assert_eq!(
            plan.custody.issuer_kid, "decided-above",
            "the credential must be minted under the planned issuer, not a re-derived one"
        );
    }

    /// The audience-scope hash defaults to the response audience, once.
    #[test]
    fn the_audience_scope_defaults_to_the_response_audience_and_is_overridable() {
        let plan = SigningPlan::from_validated(
            &validated(&[]),
            "k1".to_string(),
            TrustEpochPlan::NoNetworkChannel,
        );
        assert_eq!(plan.custody.audience_hash, plan.custody.aud);

        let plan = SigningPlan::from_validated(
            &validated(&["--delegated-audience-hash", "scope-1"]),
            "k1".to_string(),
            TrustEpochPlan::NoNetworkChannel,
        );
        assert_eq!(plan.custody.audience_hash, "scope-1");
        assert_ne!(plan.custody.audience_hash, plan.custody.aud);
    }

    /// CF-09's independence control, on the second consumer.
    ///
    /// Signing is the plane that landed last, which is exactly when the shortcut is
    /// tempting: take the epoch from the sibling that already has one, or from
    /// configuration. This asserts the plan carries what it was GIVEN — an epoch pointing
    /// at a host the configuration never names.
    #[test]
    fn the_signing_plan_carries_the_epoch_it_was_given_not_one_it_found() {
        let config = validated(PUSH_NETWORKED);
        let from_config = TrustEpochPlan::from_validated(&config);
        let handed_down = TrustEpochPlan::Redis {
            url: "redis://198.51.100.7:6379".to_string(),
            key: "decided-above".to_string(),
        };
        assert_ne!(
            from_config, handed_down,
            "the fixture must distinguish them"
        );

        let plan = SigningPlan::from_validated(&config, "k1".to_string(), handed_down.clone());
        assert_eq!(plan.epoch, handed_down);
    }

    /// Both consumers of one decision hold the SAME value — the property CF-09 exists for,
    /// asserted where the two plans meet rather than left to the wiring in `app`.
    #[test]
    fn both_consumers_of_the_epoch_hold_one_decision() {
        let config = validated(PUSH_NETWORKED);
        let epoch = TrustEpochPlan::from_validated(&config);
        let kid = response_issuer_kid(&config);
        let trust = TrustPlan::from_validated(&config, kid.clone(), epoch.clone());
        let signing = SigningPlan::from_validated(&config, kid.clone(), epoch);
        assert_eq!(trust.epoch, signing.epoch);
        assert_eq!(trust.response_kid, signing.custody.issuer_kid);
    }

    // ---- the TLS plan --------------------------------------------------------------

    /// Each CRL posture is projected as the VARIANT that carries its own parameters.
    ///
    /// The combinations layer A refuses are not merely unreachable here, they are
    /// unrepresentable: `None` has nowhere to put paths and `Static` has nowhere to put a
    /// cadence. That is what stops the plane rediscovering the posture from a `Vec` and an
    /// `Option` it was handed side by side.
    #[test]
    fn each_crl_posture_is_projected_as_its_own_variant() {
        assert_eq!(
            ClientRevocationPlan::from_validated(&validated(&[])),
            ClientRevocationPlan::None
        );
        assert_eq!(
            ClientRevocationPlan::from_validated(&validated(&["--client-crl", "/crl.pem"])),
            ClientRevocationPlan::Static {
                paths: vec!["/crl.pem".to_string()],
            }
        );
        assert_eq!(
            ClientRevocationPlan::from_validated(&validated(&[
                "--client-crl",
                "/crl.pem",
                "--client-crl-reload-secs",
                "300",
            ])),
            ClientRevocationPlan::Reloading {
                paths: vec!["/crl.pem".to_string()],
                cadence_secs: 300,
            }
        );
    }

    /// Materialization loads the same bytes under both CRL-bearing postures, so the paths
    /// are reachable without matching — but the accessor answers "which files", never
    /// "which posture". An empty result means this posture reads none, not that the
    /// deployment has no revocation configured.
    #[test]
    fn the_paths_accessor_answers_which_files_not_which_posture() {
        assert!(ClientRevocationPlan::None.paths().is_empty());
        for plan in [
            ClientRevocationPlan::Static {
                paths: vec!["/a.pem".to_string()],
            },
            ClientRevocationPlan::Reloading {
                paths: vec!["/a.pem".to_string()],
                cadence_secs: 60,
            },
        ] {
            assert_eq!(plan.paths(), ["/a.pem".to_string()]);
        }
    }

    /// The plan carries the classified custody, and the cert-lifetime/connection-age
    /// values as INPUTS. X5's relation between the latter two was settled at layer A and
    /// is not re-checked here — the plan simply carries what the posture must state.
    #[test]
    fn the_tls_plan_carries_the_classified_custody_and_its_inputs() {
        let config = validated(&["--max-client-cert-lifetime", "3600"]);
        let plan = TlsPlan::from_validated(&config);
        assert_eq!(
            plan.custody,
            crate::config_state::TlsCustodyState::Exported {
                key_path: "/nonexistent/key".to_string(),
            },
            "the fixture's TLS key is an exported file, and the plan carries its path"
        );
        assert_eq!(
            plan.max_client_cert_lifetime,
            Some(std::time::Duration::from_secs(3600))
        );
        assert_eq!(plan.client_revocation, ClientRevocationPlan::None);
    }

    /// A COMPLETE admission configuration. Setting only `admission` used to be enough
    /// here, which was itself a symptom: the validation boundary did not check admission
    /// at all, so a half-configured gate reached planning. It does now (FF4), and a plan
    /// test must exercise a configuration a deployment could actually hold.
    fn with_admission(
        mut config: crate::deployment_request::DeploymentRequest,
    ) -> crate::deployment_request::DeploymentRequest {
        config.admission = crate::deployment_request::AdmissionKind::Required;
        config.admission_authority_kid = Some("admission-root-1".to_string());
        config.admission_authority_pubkey_b64url =
            Some("1i8Bah79Hk_feT60LNhEceG6nwzwTRKHtcxx9hYofLg".to_string());
        config.admission_redis_url = Some("redis://127.0.0.1:6379".to_string());
        config
    }

    /// Admission's endpoint is its own. Declaring it independently is what stopped it
    /// being unimplementable on the CP/linearizable tier.
    #[test]
    fn admission_declares_independently_of_replay() {
        let off = ValidatedDeployment::try_from(parse(SHARED_LINEARIZABLE).expect("parse"))
            .expect("validates");
        assert!(!admission_needs_control_runtime(&off));

        let on = with_admission(parse(SHARED_LINEARIZABLE).expect("parse"));
        let on = ValidatedDeployment::try_from(on).expect("validates");
        assert_eq!(admission_needs_control_runtime(&on), REDIS);
        assert!(
            !ReplayPlan::from_validated(&on).needs_control_runtime(),
            "admission must not need the replay tier to have asked first"
        );
    }

    /// The aggregation itself: any contributor is enough, none means none.
    #[test]
    fn the_requirement_is_the_or_of_every_contributor() {
        use crate::control_runtime::ControlRuntimeRequirement as Req;

        // Admission alone, on a tier that declares nothing.
        let admission_only = with_admission(parse(SHARED_LINEARIZABLE).expect("parse"));
        let admission_only = ValidatedDeployment::try_from(admission_only).expect("validates");
        let plan = ReplayPlan::from_validated(&admission_only);
        assert_eq!(
            control_runtime_requirement(&admission_only, &plan).is_required(),
            REDIS,
            "one contributor is enough"
        );

        // Nothing networked at all.
        let none = ValidatedDeployment::try_from(parse(SHARED_LINEARIZABLE).expect("parse"))
            .expect("validates");
        let plan = ReplayPlan::from_validated(&none);
        assert_eq!(
            control_runtime_requirement(&none, &plan),
            Req::NotRequired,
            "no contributor declared a need, so no substrate is built"
        );
    }
    /// The sentinel `now_unix()` produces for a pre-epoch `SystemTime` error, and the
    /// unset-clock reading it stands in for, must both be faults. A predicate that only
    /// caught literal 0 would pass a host reading a few days past the epoch.
    #[test]
    fn an_epoch_or_pre_epoch_clock_reading_is_a_fault() {
        assert!(host_clock_is_faulted(0));
        assert!(host_clock_is_faulted(-1));
        assert!(host_clock_is_faulted(86_400));
        assert!(host_clock_is_faulted(EPOCH_CLOCK_FAULT_THRESHOLD_SECS - 1));
    }

    /// The threshold is far enough below any real deployment time that a correct clock
    /// never trips it — otherwise the warning would fire on every start and stop meaning
    /// anything.
    #[test]
    fn a_plausible_deployment_clock_is_not_a_fault() {
        assert!(!host_clock_is_faulted(EPOCH_CLOCK_FAULT_THRESHOLD_SECS));
        // 2026-01-01 UTC.
        assert!(!host_clock_is_faulted(1_767_225_600));
        assert!(!host_clock_is_faulted(i64::MAX));
    }

    /// Both flags reach the pool through the per-core ceiling the gate enforces, so both
    /// multiply by the core count. `--max-in-flight-total` is written fleet-wide but is
    /// not enforced fleet-wide.
    #[test]
    fn both_bounds_reach_the_pool_through_the_gates_per_core_ceiling() {
        assert_eq!(inner_plane_ceiling(Some(10), None, 8), Some(80));
        assert_eq!(inner_plane_ceiling(None, Some(80), 8), Some(80));
        assert_eq!(inner_plane_ceiling(None, None, 8), None);
    }

    /// THE PROPERTY: when a fleet-wide target is projected into equal integer per-core
    /// ceilings, every component enforcing aggregate capacity must use the aggregate that
    /// projection implies — not the operator's original number.
    ///
    /// `--max-in-flight-total 1000 --cores 3` cannot be honoured exactly under equal
    /// per-core partitioning. The gate resolves that by rounding each core's share up, so
    /// the fleet admits 1002; a pool bounded at 1000 would shed the last two at a cliff no
    /// flag names. The divisible case pins that the repair changes nothing there.
    #[test]
    fn a_total_that_does_not_divide_evenly_yields_the_aggregate_the_gate_admits() {
        for (total, cores, expected) in [
            (1000usize, 3usize, 1002usize), // ceil(1000/3) = 334, x3
            (1000, 8, 1000),                // 125 x 8 — divides evenly, unchanged
            (10, 4, 12),                    // ceil(10/4) = 3, x4
            (3, 8, 8),                      // the floor of 1 per core
        ] {
            let per_core = crate::async_fleet::derived_per_core_ceiling(None, Some(total), cores);
            assert_eq!(
                inner_plane_ceiling(None, Some(total), cores),
                Some(per_core.expect("a total yields a per-core ceiling") * cores),
                "total {total} over {cores} cores"
            );
            assert_eq!(
                inner_plane_ceiling(None, Some(total), cores),
                Some(expected)
            );
        }
    }

    /// Both-set is UNREACHABLE from a validated deployment: `InFlightLimitBasis` states one
    /// basis and its two projections are never both `Some`. But this is a total function
    /// over two `Option`s and must still be defined, so the arm is pinned against
    /// `derived_per_core_ceiling`'s rather than left free to grow a second opinion about an
    /// input neither of them should ever see.
    #[test]
    fn the_both_set_arm_agrees_with_the_gate_on_an_unreachable_input() {
        assert_eq!(inner_plane_ceiling(Some(10), Some(999), 4), Some(40));
        assert_eq!(
            crate::async_fleet::derived_per_core_ceiling(Some(10), Some(999), 4),
            Some(10),
        );
    }

    /// A huge per-core bound on a many-core box must not wrap. Saturating rather than
    /// wrapping matters because a wrapped ceiling would be SMALLER than the default and
    /// would silently lower the pool instead of raising it.
    #[test]
    fn a_ceiling_that_would_overflow_saturates_rather_than_wrapping() {
        let huge = inner_plane_ceiling(Some(usize::MAX), None, 64);
        assert_eq!(huge, Some(usize::MAX));
        assert_eq!(inner_plane_raise(huge, 1024), Some(usize::MAX));
    }

    /// The pool is raised only when the fleet's ceiling actually exceeds its default —
    /// equal is not "raised", or every start would print a line saying nothing changed.
    #[test]
    fn the_pool_is_raised_only_when_the_fleet_ceiling_exceeds_its_default() {
        assert_eq!(inner_plane_raise(Some(2048), 1024), Some(2048));
        assert_eq!(inner_plane_raise(Some(1024), 1024), None);
        assert_eq!(inner_plane_raise(Some(512), 1024), None);
        assert_eq!(inner_plane_raise(None, 1024), None);
    }
}
