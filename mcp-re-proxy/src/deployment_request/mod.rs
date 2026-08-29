// SPDX-License-Identifier: Apache-2.0
//! The CLI-neutral request model: what a deployment asks for, before anything judges it.
//!
//! This module is the shared vocabulary at the narrow point of the pipeline:
//!
//! ```text
//! argv -> cli::parse_args -> DeploymentRequest -> config_state -> ValidatedDeployment
//! ```
//!
//! Both sides depend on the request model; neither depends on the other. That direction is
//! the point of the module existing. These types lived in `cli` for as long as the parser
//! was the only thing that built one, which made every configuration-state machine import
//! its subject matter from an argument parser — a dependency that said the state model was
//! downstream of the CLI when it is downstream of the REQUEST.
//!
//! Nothing here validates. A type in this module can hold a combination no deployment may
//! run, and must be able to: refusing a state requires representing it first.

mod admission;
mod authorization;
mod delegated_signing;
mod inner_backend_display;
mod kinds;
mod peer_identity;
mod request_signer_currency;
mod revocation;
mod secret_string;
mod signing_source;
mod storage;

pub use admission::{AdmissionAvailabilityRequest, AdmissionGateRequest, AdmissionRequest};
pub use authorization::AuthorizationRequest;
pub use delegated_signing::DelegatedSigningRequest;
pub(crate) use inner_backend_display::RedactedBackendUrls;
pub use kinds::{AuditSinkKind, AuthzKind, VerifiedContextKind};
pub use peer_identity::{
    AttestedIngressRequest, ChannelCredentialIdentityRequest, IngressAssertionRequest,
    PeerIdentityEvidenceRequest, PinnedChannelAcknowledgement,
};
pub use request_signer_currency::RequestSignerCurrencyRequest;
pub use revocation::{
    OcspResponderRequest, OnlineRevocationEvidenceRequest, PeerRevocationRequest,
    RevocationListRequest,
};
pub use secret_string::SecretString;
pub use storage::{
    ContinuationStoreRequest, EtcdStoreRequest, RedisStoreRequest, ReplayStorageRequest,
    ReplayStoreRequest, SharedStoreRequest, TrustEpochSource, TrustEpochStoreRequest,
};

pub use signing_source::{
    AwsKmsChannelKeyRequest, AwsKmsSigningSourceRequest, ChannelCredentialRequest,
    ChannelKeyRequest, DelegatedChannelKeyRequest, EnvironmentSigningSourceRequest,
    ExportedChannelKeyRequest, FileSigningSourceRequest, GcpKmsChannelKeyRequest,
    GcpKmsSigningSourceRequest, Pkcs11ChannelKeyRequest, Pkcs11SigningSourceRequest,
    ResponseSigningRequest, SigningSourceRequest,
};

use std::time::Duration;

use crate::tls::ServerLimits;

/// A deployment as REQUESTED: every field an operator can state, and nothing decided.
///
/// A request is not a deployment. Whether the state it describes may run is
/// [`ValidatedDeployment`](crate::config_state::validation::ValidatedDeployment)'s question, and holding one of
/// these is evidence of nothing at all — the fields are public, so a test, an embedder or
/// a composition root can build any combination, legal or not.
///
/// It is CLI-neutral on purpose. `parse_args` is the usual way one is built and not the
/// only way, so nothing here refers to flags as the thing that produced a value. Field
/// docs still name the option that sets a field, because that is the vocabulary an
/// operator and a diagnostic share.
#[derive(Debug, Clone)]
pub struct DeploymentRequest {
    /// Listen address, e.g. `127.0.0.1:8443`.
    pub bind: String,
    /// Expected audience (this server's identity).
    pub audience: String,
    /// Response-signing signer identity.
    pub server_signer: String,
    /// Response-signing key id.
    pub server_key_id: String,
    /// Symmetric clock skew (seconds), applied to BOTH the RFC 9421 freshness gate
    /// and the replay `retain_until`. Bounded `0..=VerifierPolicy::MAX_CLOCK_SKEW_BOUND`
    /// at the validation boundary.
    pub max_clock_skew: i64,
    /// Accepted `Mcp-Protocol-Version` values (§4.1). Empty = no MCP transport
    /// contract is enforced.
    pub mcp_protocol_versions: Vec<String>,
    /// The canonical RFC 9421 `@target-uri` this deployment binds requests to
    /// (ADR-MCPRE-050); client and server sign it byte-for-byte.
    pub target_uri: String,
    /// The trust domain assigned to resolved actors (RFC 9421 ActorIdentity).
    pub trust_domain: String,
    /// Optional audience route/tenant discriminator.
    pub route: Option<String>,
    /// Which key signs this deployment's responses, and the mechanism holding it.
    ///
    /// One tagged value rather than a selector beside every provider's parameters: an AWS
    /// selection has nowhere to put a GCP or PKCS#11 value, so the nine "belongs to a
    /// different custody source" refusals that explained the flat shape no longer have a
    /// configuration to refuse (ADR-MCPRE-067 §7).
    pub response_signing: ResponseSigningRequest,
    /// Location of the trust anchors a peer credential must chain to.
    pub peer_trust_anchors: String,
    /// How this deployment establishes that a peer credential is still current: the
    /// published revocation lists it reads, and whether it requires online per-credential
    /// evidence. The two mechanisms COMPOSE — configuring one says nothing about the other
    /// (ADR-MCPRE-067 §7).
    pub peer_revocation: PeerRevocationRequest,
    /// Path to the JSON trust file (request signers + authorization issuers).
    pub trust_path: String,
    /// ADR-MCPRE-051 §3: stateless Streamable-HTTP inner backend URL(s) for the
    /// ASYNC serving path. The proxy serves on the per-core async fleet
    /// (SO_REUSEPORT + tokio) and forwards verified requests over the pooled
    /// `HttpInnerPool` to these backends (round-robin). Each `--inner-http-url`
    /// value (comma-separated and/or repeated) adds a backend. At least one is
    /// REQUIRED — the proxy has no in-tree stdio inner mode (MCPRE-118); a
    /// stdio-only server is fronted by the out-of-TCB `mcp-re-stdio-bridge`.
    pub inner_http_urls: Vec<String>,
    /// ADR-MCPRE-051 §1: number of serving SHARDS (each an `SO_REUSEPORT` listener with
    /// its own runtime). `0` (default) means auto.
    ///
    /// Auto is no longer "one shard per core": it is `ceil(cpus / workers_per_shard)`,
    /// which on a 14-cpu host gives 2 shards of 8 rather than 14 of 1. Shards are
    /// scheduling silos — Tokio steals work only within a runtime — so over-sharding
    /// starves ready tasks. Pinning an explicit count still makes the scaling benchmark
    /// reproducible.
    pub cores: usize,
    /// ADR-MCPRE-051 §1: Tokio worker threads inside EACH serving shard. `0` (default)
    /// means auto — `min(8, cpus)`; an explicit `1` restores the single-threaded
    /// share-nothing shard.
    ///
    /// Depth is what buys throughput: on the cold §7 anchor lane, 1 worker measured
    /// 5,320 rps against 15,454 at 8, and on the warm saturation rig 10,362 against
    /// 44,803. Replay integrity does not depend on single-threaded sequencing — admission
    /// is a server-side atomic `SET NX PX` and `Fresh` can only come from a winning L2
    /// insert — so two workers racing one nonce is the case the tier already handles
    /// across replicas.
    ///
    /// This is configuration rather than a constant because the optimum is a property of
    /// the host: cache domains, SMT, P/E-core asymmetry and epoll-vs-kqueue wakeup
    /// behaviour all move it. Measure it with `scripts/runtime_topology_sweep.sh` rather
    /// than assuming a number carries across machines.
    pub workers_per_shard: usize,
    /// MCPRE-114: the admission limit AS THE OPERATOR STATED IT — per core, fleet-wide, or
    /// not at all.
    ///
    /// One field, because there is one decision. The two flags are alternatives at
    /// different altitudes, and holding them in two `Option`s made the illegal both-set
    /// combination writable and made absence indistinguishable from a value equal to the
    /// default. Neither is expressible here.
    ///
    /// `Unspecified` does NOT mean unbounded:
    /// [`in_flight_limit`](crate::config_state::in_flight_limit) applies the fail-safe
    /// per-core default at the validation boundary.
    pub in_flight_limit: crate::config_state::InFlightLimitRequest,
    /// Where shared replay state lives, and what durability this deployment claims for it.
    ///
    /// The REPLAY store, and nothing else. One field once also decided where the MRTR
    /// continuation store lived, which made it carry two different facts depending on the
    /// tier beside it; `continuation_control` owns that fact, and each role names its own
    /// store (ADR-MCPRE-067 §10, CF-12).
    pub replay: ReplayStorageRequest,
    /// ADR-MCPS-047: where a retained cross-replica MRTR continuation base lives.
    ///
    /// A different fact from replay's store, not the same fact with a second consumer, and
    /// a different fact from admission's. The three may name one Redis; that is then an
    /// operator's deployment choice rather than an alias the configuration forces.
    pub continuation_control: ContinuationStoreRequest,
    /// Whether a call must carry admission evidence, and what verifies it. One tagged
    /// value: the gate's authority, record and availability are members of the two
    /// enforcing forms, so there is no `off` to hang them from and the five dangling
    /// clauses have no configuration left to examine (ADR-MCPRE-067 §7).
    pub admission: AdmissionRequest,
    /// ADR-MCPS-035: where the per-request security record goes. `Stderr` by default,
    /// because the absent case has to be the safe one: an invocation that does not go
    /// through the Helm chart — the container run directly, a harness, a hand-rolled
    /// unit file — would otherwise serve production traffic with no per-request
    /// attribution, and a compromise cannot be scoped after the fact from records that
    /// were never written. Turning it off is available but explicit (`--audit-sink
    /// none`), and the startup line states which posture is in force either way.
    pub audit_sink: AuditSinkKind,
    /// ADR-MCPRE-054: where retained evidence goes. `None` by default — nothing is
    /// retained and the request path is unchanged.
    ///
    /// Setting it changes what the deployment STORES about every call: the full request
    /// and response messages, which is what a later SCITT statement commits to and what
    /// an auditor recomputes the handles from. That is a data-retention decision, which
    /// is why it is opt-in and named rather than derived from some other flag. Once set,
    /// a store failure refuses the exchange with `mcp-re.evidence_retention_unavailable`.
    pub retained_evidence_dir: Option<String>,
    /// #415 rev 2 §10: whether the PEP writes its own verified context into the body
    /// forwarded to the inner server. `Disabled` by default because `Trusted` asserts
    /// an unverifiable property of the inner channel.
    pub verified_context: VerifiedContextKind,
    /// How current this deployment's belief about a request signer is: which ADR-MCPS-021
    /// posture it asserts, and the material that posture is inhabited by. One tagged value,
    /// so the re-read cadence belongs to the tiers that need one and the epoch source to
    /// the only tier that reads one — which is what relation X8 used to have to say
    /// (ADR-MCPRE-067 §7).
    pub request_signer_currency: RequestSignerCurrencyRequest,
    /// Which evidence carries the peer's identity to this node, and the material that
    /// form verifies with. One tagged value: an attested-ingress selection has nowhere to
    /// put a load-balancer key, so the five clauses that refused a value belonging to an
    /// unselected form have no configuration left to examine (ADR-MCPRE-067 §7).
    pub peer_identity: PeerIdentityEvidenceRequest,
    /// Everything this deployment asks for on the authorization axis.
    pub authorization: AuthorizationRequest,
    /// Which key establishes this deployment's communication channel.
    ///
    /// A separate role from [`response_signing`](Self::response_signing), and separate
    /// structurally: the delegated channel key object is not reachable from the
    /// response-signing selection and cannot be read where that key was meant
    /// (ADR-MCPRE-067 §10). Which custody holds the channel key is the tagged
    /// [`ChannelKeyRequest`], so the two cannot both be asserted.
    pub channel_credential: ChannelCredentialRequest,
    /// Connection resource limits (DoS defense).
    pub limits: ServerLimits,
    /// Maximum client-certificate lifetime (v1 revocation posture). Defaults to
    /// 1 hour; `None` disables enforcement (strongly discouraged).
    pub max_client_cert_lifetime: Option<Duration>,
    /// Horizontally-scaled deployment TOPOLOGY (MCPS-79, ADR-MCPS-049 clause 1,
    /// `--fleet`). This is a topology selector, NOT a security toggle — the proxy
    /// always runs the maximal-security posture and refuses unsafe configs. A single
    /// node is the sole verifier, so single-node durable replay (`--replay-cache
    /// file`, ADR-MCPS-014) is valid. Under `--fleet` a replayable request may reach
    /// a DIFFERENT verifier than the one that saw the first nonce during the
    /// evidence-acceptance window, so node-local replay caches (`memory` and `file`)
    /// are REJECTED and a shared replay cache with an adequate durability tier is
    /// required.
    pub fleet: bool,
    /// What the delegated response-signing credential is minted with: its rotation
    /// window, the trust epoch that can withdraw it, and the coordinates it is issued
    /// under. One proposition, so one field (ADR-MCPRE-067 §7).
    pub delegated_signing: DelegatedSigningRequest,
    /// Accept a key file that is group-READABLE (never group-writable, never
    /// world-anything) when its group is one this process is in — the Kubernetes
    /// `fsGroup` mount model, which the strict `0600` floor makes unsatisfiable for a
    /// non-root pod (C053b). Explicit opt-in; the default posture is unchanged.
    pub allow_group_readable_key_files: bool,
}
