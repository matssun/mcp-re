//! MCP-RE server-side sidecar (MCPS-015 + MCPS-016).
//!
//! [`Proxy`] wraps an unmodified inner MCP server ([`InnerServer`]): it verifies
//! every inbound MCP-RE request before dispatch, fails closed on any verification
//! failure (the inner server is never reached), strips the external transport
//! envelope, injects a fresh verified-context block as the sole writer, forwards
//! only verified requests, and signs the inner server's result on the way back.
//!
//! `transport` carries the ADR-MCPS-014 transport-binding abstraction: identity
//! types, the provider seam, and the binding policy that ties the verified request
//! actor to the mTLS channel identity.
//!
//! # Security posture
//!
//! Fleet serving is supported: [`SharedReplayCache`] over an [`AtomicReplayStore`]
//! gives cross-replica replay rejection, and [`redis_store`] is the shared backend
//! that ships for it. Key custody reaches an HSM/KMS through [`key_source`].
//! Client-certificate revocation is a **short-lived-credential** posture plus an
//! in-process CRL: the proxy enforces a maximum client-certificate lifetime, and
//! online OCSP is compiled only under its own feature.

// ADR-MCPRE-065: authorization over verified request evidence. A NEW authority, not
// a continuation of ADR-MCPRE-064 — permission is not produced by assurance about a
// relationship. Always compiled; the frozen ADR-MCPS-013 denial taxonomy is its only
// non-std dependency.
pub mod authorization;
pub mod communication_assurance;
// ADR-MCPS-022: explicit authorized server key set + per-audience response-signing
// identity mode (per_node_keyset default | shared_remote_signer). The verifier-side
// admission anchor; composes with `trust_cache::BoundedTrustCache` (ADR-MCPS-021).
// ADR-MCPRE-051 §6 (MCPRE-116): versioned, atomically-swapped serving-config
// snapshots + the in-process CRL hot-reloader. Always compiled; pure std
// (RwLock<Arc<ServerConfig>>), no new dependency.
pub mod config_snapshot;
mod facades;
// ADR-MCPS-028 §B: native AWS KMS Ed25519 response signer over blocking HTTPS
// (ureq) + a minimal audited SigV4 signer — NO async `aws-sdk-kms`/tokio/Smithy
// (ADR-MCPS-018 lean-sync firewall). Compiled ONLY under the non-default
// `aws_kms_keysource` feature so the default build links no HTTPS/SigV4 code.
#[cfg(feature = "aws_kms_keysource")]
pub mod aws_kms_keysource;
#[cfg(feature = "aws_kms_keysource")]
pub mod aws_sigv4;
// The credential sources the SigV4 signer is fed from: the narrow environment set,
// and IRSA (the projected service-account token exchanged for temporary credentials
// via STS), which is the AWS counterpart of the GKE workload-identity path.
#[cfg(feature = "aws_kms_keysource")]
pub mod aws_sts;
pub mod capability_materialization;
pub mod cli;
/// Wall-clock acquisition — the one place the OS clock enters the proxy, and the module
/// `boundary.clock` names.
pub mod clock;
/// The classified legal deployment state (layer A of the configuration state atlas).
pub mod config_state;
/// The CLI-neutral request model: what a deployment asks for, before anything judges it.
///
/// Both the argument parser and the configuration state model depend on it; neither
/// depends on the other.
pub mod deployment_request;
// Issue #3838 (ADR-MCPS-014): a non-exporting reference `ResponseSigner` proving the
// response-signing delegation seam — a backend whose key never leaves it can drive
// the proxy's full signing path.
pub mod delegated_response_signer;
// ADR-MCPRE-052 §4/§6 + ADR-MCPRE-051 §5: hot-path delegated response signing —
// a shared, atomically-swappable delegated-key snapshot the fleet signs off, and
// the cold-path rotor that keeps it fresh (root issuer off the request path).
pub mod delegated_server_signer;
// ADR-MCPRE-052 phase 2 (MCPRE-122): production wiring — build the delegated signer +
// cold-path rotor from a parsed DeploymentRequest + a ROOT issuer (KMS/HSM/file ResponseSigner).
// Delegated-signing is the only response-signing mode.
pub mod delegated_wiring;
// ADR-MCPS-028 §G: delegated TLS handshake signing — a rustls SigningKey that
// forwards the handshake transcript to a non-exporting device/KMS so the TLS
// server key never leaves it. Generic mechanism (always compiled); the per-backend
// raw signers are wired under their own feature gates.
pub mod delegated_tls;
// MCPRE-501 slice 3: the filesystem side of the SCITT retained-evidence split.
// mcp-re-http-profile declares the store interface and stays pure; the fs lives here.
pub mod retained_evidence;
// ADR-MCPRE-054: the serving path's half of the SCITT vertical — retention on the
// request path, and the reader an auditor reconstructs a chain through.
pub mod transparency;
/// Interpretation and validation of trust-document bytes — the authoritative boundary
/// every construction path reaches, whether or not it meets a parser.
pub mod trust_document;
// ADR-MCPS-028 §C: native GCP Cloud KMS Ed25519 response signer over blocking HTTPS
// (ureq) + OAuth2 bearer — NO async google-cloud SDK. Compiled ONLY under the
// non-default `gcp_kms_keysource` feature.
// ADR-MCPRE-066 Slice 1: what a record IS, kept apart from how one is delivered.
pub mod audit_record;
pub mod audit_sink;
#[cfg(feature = "gcp_kms_keysource")]
pub mod gcp_kms_keysource;
// ADR-MCPS-028 §G: the handshake path's share of a remote signer's quota. Gated on the
// two backends that use it, because a build with neither carries no signer whose quota
// could be spent. Its tests therefore run in the FEATURE lane
// (`cargo test -p mcp-re-proxy --features ...`), not in the default workspace lane.
#[cfg(any(feature = "aws_kms_keysource", feature = "gcp_kms_keysource"))]
pub(crate) mod handshake_quota;
// ADR-MCPS-028 §B/§C: one remote-signer call, as it failed — the HTTP status and the body
// kept SEPARABLE, so the quota question is answered from the wire fact rather than from a
// rendered string. Gated with the two backends that produce it.
pub mod key_source;
/// Whether an operator-supplied KMS/STS endpoint may be used at all — a security rule
/// the command line, the validation boundary and the key sources all consume.
pub mod kms_endpoint_policy;
pub mod log_sink;
#[cfg(any(feature = "aws_kms_keysource", feature = "gcp_kms_keysource"))]
pub(crate) mod remote_signer_call;
// Test / embedding helpers that drive the async serving path synchronously
// (a private current-thread runtime per call). NOT a serving path — the
// production data plane is the per-core async fleet. Used by this crate's tests
// and by downstream crates' proxy test harnesses.
// ADR-MCPS-028: provider-agnostic cloud-KMS response signer (the shared protocol
// mapping behind the #3838 delegation seam). Dependency-free — the per-provider
// network backends (AWS KMS / GCP Cloud KMS) are the feature-gated follow-ups.
pub mod kms_keysource;
// Issue #4030: ONLINE client-cert revocation via OCSP (RFC 6960) checked at
// connection time, the online sibling of #3839's offline CRL revocation.
// Compiled ONLY under the non-default `online_ocsp` feature so the default build
// links no HTTP client and stays byte-for-byte unchanged.
#[cfg(feature = "online_ocsp")]
pub mod ocsp;
// EX-006: the outbound-fetch/SSRF authority, not RFC 6960's. Unconditional.
pub mod outbound_fetch;
// Issue #4034: the PKCS#11-backed response-signing key source (the real,
// non-exporting backend behind the #3838 delegation seam — the response-signing
// key never leaves the token). Compiled ONLY under the non-default
// `pkcs11_keysource` feature so the default build is unchanged.
#[cfg(feature = "pkcs11_keysource")]
pub mod pkcs11_keysource;
// Issue #4034 supply-chain follow-up: a small, OWNED safe wrapper over the raw
// `cryptoki-sys` FFI bindings, replacing the high-level `cryptoki` crate (which
// transitively pulled the unmaintained `paste`, RUSTSEC-2024-0436). Compiled ONLY
// under the same non-default `pkcs11_keysource` feature.
#[cfg(feature = "pkcs11_keysource")]
pub mod pkcs11_native;
// Issue #69 (epic #68 v0.4 Axis 1): the etcd-backed CP / LINEARIZABLE shared
// replay backend that makes `--replay-durability-tier linearizable` declarable
// with a real durable-linearizable store (ADR-MCPS-020). Compiled ONLY under the
// non-default `cpstore_etcd` feature so the default build is unchanged.
#[cfg(feature = "cpstore_etcd")]
pub mod etcd_store;
// ADR-MCPRE-051 §4: the ASYNC etcd authoritative replay backend (hyper over the
// v3 JSON gateway; reuses etcd_store's pure helpers). The linearizable durable
// tier the async serving fleet awaits. Same `cpstore_etcd` gate.
#[cfg(feature = "cpstore_etcd")]
pub mod async_etcd_store;
// Issue #4028: the Redis-backed shared replay backend that makes
// `--replay-cache shared` give real horizontally-scaled replay safety. Compiled
// ONLY under the non-default `redis_replay` feature so the default build is
// unchanged.
#[cfg(feature = "redis_replay")]
pub mod redis_store;
// ADR-MCPS-020: the declared replay-store durability tier (deployment assertion,
// semantic names, honest per-tier guarantee, tier-claim ceiling). Pure type — in
// the default build.
pub mod replay_tier;
// MCPRE-104 (#308): the proxy replay-tier adapter around the pure HTTP-profile
// dispatcher — layers ReplayDurabilityTier::meets_strict_production_minimum above
// the dispatcher's core is_single_process_reference gate, keeping the tier type in
// mcp-re-proxy (the pure profile crate gains no proxy dependency).
pub mod http_profile_dispatch;
pub mod http_profile_serve;
// ADR-MCPRE-066 Slice 0: what a stage decided when it refused, and WHICH AUTHORITY decided
// it. Split from the serving path because the cause must outlive the stage that produced it
// — a pre-rendered token cannot say whether Core or the authorization boundary refused.
pub(crate) mod refusal;
// ADR-MCPS-021 Axis 2: the declared REVOCATION tier (Tier 1 bounded-cache / Tier 2
// live / Tier 3 push) — semantic names, honest per-tier guarantee, tier-claim
// ceiling. Pure type — in the default build. The Axis-2 analogue of replay_tier.
pub mod revocation_tier;
// ADR-MCPS-021 Tier 2: live strong trust check — consults the inner store on every
// verification (no positive-trust caching), with an optional second live
// revocation authority; fail-closed on store/revocation outage.
/// Per-request client-certificate revocation — what makes a warm connection safe to
/// keep, since rustls consults the CRLs at the handshake and never again.
pub mod client_revocation;
/// The re-readable trust store the revocation tiers resolve against — what makes
/// "the store is consulted on every verification" a true statement about a running
/// proxy rather than about a map frozen at boot.
pub mod reloading_trust;
/// Per-stage wall-clock timers for the async serving path.
pub mod stage_timers;
/// ADR-MCPRE-055: the trust epoch that gates TLS session resumption.
pub mod tls_listener_state;
// ADR-MCPS-021 Tier 3: push-invalidation trust cache — bounded-`T` caching plus an
// injected invalidation channel that evicts revoked entries immediately, with a
// bounded-`T` fallback when the channel is unhealthy (never a zero-window claim).
// Issue #3837: shared, server-side-atomic replay cache for horizontally-scaled
// replay safety (the backend-agnostic core + the in-memory reference store).
pub mod shared_replay;
pub mod tls;
// ADR-MCPRE-061 §2 class 4 (MCPRE-138): consumes the TLS authority, owns no policy.
pub mod blocking_mtls_harness;
pub mod transport;
// ADR-MCPRE-051 Phase 2 (§1): OPT-IN async serving path (tokio + tokio-rustls +
// hyper keep-alive/H2). A shared runtime is dev scaffolding only (per-core
// SO_REUSEPORT is MCPRE-113, the production data plane).
pub mod async_serve;
// MCPRE-113 (ADR-MCPRE-051 §1): the per-core serving fleet — one worker thread per
// core, each a current-thread tokio runtime with its own SO_REUSEPORT listener +
// Linux CPU pinning, over one Proxy per core. THE production data plane.
pub mod app;
// ADR-MCPRE-056 §5.2: what startup INTENDS to build, decided from validated
// configuration alone. Pure — no I/O, no environment, no clock — so a plan describes
// intent and never doubles as evidence that the thing was established. Internal to the
// crate: it is the composition root's own decomposition, not a surface anything outside
// builds against.
pub mod async_fleet;
// ADR-MCPRE-057 §3: the global runtime lifecycle as a value, with one closed transition
// relation. Represents which lifecycle transitions are LEGAL; it is not synchronization,
// and does not replace the terminal latches that enforce those rules against in-flight
// work on other threads (§5.4).
pub(crate) mod runtime_state;
// ADR-MCPRE-057 §4: the per-request lifecycle as a value, alongside the continuation and
// backend machines it interacts with. Holds them as a tuple with invariants over
// projections rather than as one combined enum, so that a refusal can state whether the
// action was executed and whether the approval authorizing it was spent — facts no single
// machine holds on its own.
pub(crate) mod exchange_state;
// ADR-MCPRE-057 §9 / ADR-MCPRE-058 §14: the owner of a partly-built runtime. Holds the
// lifecycle and every resource acquired so far, so `Materialized` cannot be asserted over
// an incomplete graph, and a failed materialization reclaims in the documented order
// rather than by reverse-declaration unwinding (F3).
pub(crate) mod materializing_runtime;
// ADR-MCPRE-058 §7.2: the seven optional serving capabilities, each as one domain
// operation producing what to attach and the posture line describing it. The composition
// root states the order they are established in; what each one MEANS lives here.
pub(crate) mod request_stages;
pub(crate) mod serving_capabilities;
pub mod startup_plan;
// ADR-MCPRE-056 §5.4: the optional-capability posture vocabulary. Every seam states
// whether it is ON or OFF, because silence cannot distinguish "not configured here"
// from "not in this build". Declaring takes a value, so the OFF branch is a type
// obligation rather than a convention.
pub(crate) mod startup_posture;
// ADR-MCPRE-056 §10: the assembled runtime. Owns every resource that has a teardown
// obligation, and enforces the order they come apart in — drain, then each plane's own
// post-owner transition, then the shared substrate the proxy bound clients to.
pub(crate) mod materialized_runtime;
// ADR-MCPRE-056 §9: owned background workers. A startup phase may not spawn a
// long-lived thread whose lifetime is not represented by an owned value, so every
// runtime worker belongs to a `WorkerSet` that halts and reclaims it on drop.
pub(crate) mod managed_worker;
// ADR-MCPRE-056 §8: the trust plane — the swappable trust store, its refresh workers,
// and the two narrow live handles it hands out. Owns the authority to CHANGE trust
// state; consumers get read/observe capabilities only.
pub(crate) mod trust_plane;
// ADR-MCPRE-056 §8 (ADR-MCPRE-052): the signing plane — owns the root issuer, the
// delegated key snapshot and the rotation worker. A signer that outlives it is retired,
// so it cannot keep signing off a key nothing rotates and no epoch advance can revoke.
pub(crate) mod signing_plane;
// ADR-MCPRE-056 §8 (ADR-MCPRE-051 §6): the TLS plane — serving TLS config, per-request
// revocation index and the CRL reload worker. Its snapshot needs no fail-closed
// transition on drop: a CRL states its own nextUpdate and unknown status is refused.
pub(crate) mod tls_plane;
// ADR-MCPRE-056 §8: the shared control runtime — execution substrate for every
// networked control-plane client, distinct from the per-core serving runtimes. Owns
// execution lifetime; consumers receive a tokio Handle, which conveys access only.
pub(crate) mod control_runtime;
// ADR-MCPRE-056 §6: the replay plane — establishes the planned tier and hands it over by
// value. Owns nothing afterwards; the substrate its Redis arm binds to must outlive every
// USE of the result, which the fleet drain discharges.
pub(crate) mod replay_plane;
// MCPRE-117 (ADR-MCPRE-051 §4): the async authoritative replay tier — the async
// AtomicReplayStore + the per-core L1-never-Fresh fast-reject wrapper, so the
// per-core data plane checks replay without blocking a runtime worker. Concrete
// async in-memory/Redis/etcd backends plug into this contract.
pub mod async_replay;
// MCPRE (ADR-MCPRE-051 §3): the ASYNC inner-server seam — THE inner path. The async
// serving path awaits it so the inner round-trip never blocks a per-core runtime
// worker. The production impl is the async hyper client pool to stateless
// Streamable-HTTP inner backends; an unmodified stdio server is fronted by the
// out-of-TCB `mcp-re-stdio-bridge` and reached over HTTP like any other backend.
pub mod async_inner;
// ADR-MCPRE-051 §3: the production async inner plane — a per-core pooled hyper
// client to stateless Streamable-HTTP inner backends (keep-alive/H2, round-robin,
// per-request timeout, fail-closed). The AsyncInnerServer the serving path awaits.
pub mod http_inner;
pub(crate) mod inner_plane_bound;
// MCPRE-117 (ADR-MCPRE-051 §4): the ASYNC Redis authoritative replay backend
// (`SET NX PX` via the tokio async client + auto-reconnecting ConnectionManager).
// Behind the redis backend flag; the data plane awaits it without blocking a worker.
#[cfg(feature = "redis_replay")]
pub mod async_redis_store;
// ADR-MCPS-047: the MRTR continuation correlation store — the fleet-shared tier that
// carries a multi-round-trip continuation across a replica switch. The trait +
// in-memory (single-process) impl are always compiled; the Redis (cross-replica)
// backend is `redis_replay`-gated like the async replay store above.
pub mod admission_enforcer;
pub mod admission_source;
pub mod continuation_store;
#[cfg(feature = "redis_replay")]
pub mod redis_admission_source;
#[cfg(feature = "redis_replay")]
pub mod redis_continuation_store;
// trust_epoch: core epoch->event logic always compiled, Redis reader `redis_replay`-gated
// inside. trust_plan: the trust subtree's own projection of its validated state (MCPRE-148).
pub mod trust_epoch;
pub(crate) mod trust_plan;
// ADR-MCPS-021: bounded trust-propagation cache (Tier 1). Caching is a caller
// concern (mcp-re-core does not cache); this wraps the injected TrustResolver with
// the bounded-`T` window + negative-cache classification + fail-closed rules.

// ADR-MCPS-028 §B: the AWS KMS Ed25519 backend (feature-gated). Drives the
// `KmsResponseSigner` core via the `KmsEd25519Backend` seam.
#[cfg(feature = "aws_kms_keysource")]
pub use aws_kms_keysource::AwsKmsConfig;
#[cfg(feature = "aws_kms_keysource")]
pub use aws_kms_keysource::AwsKmsEd25519Backend;
pub use delegated_response_signer::DelegatedResponseSigner;
pub use delegated_server_signer::DelegatedRotor;
pub use delegated_server_signer::DelegatedServerSigner;
pub use delegated_wiring::build_delegated_signing;
pub use delegated_wiring::DelegatedSigningWiring;
pub use delegated_wiring::ProdDelegatedRotor;
// ADR-MCPS-028 §G: delegated TLS signing (generic mechanism).
pub use delegated_tls::DelegatedCertResolver;
pub use delegated_tls::DelegatedEd25519SigningKey;
pub use delegated_tls::RawEd25519TlsSigner;
// ADR-MCPS-028 §C: the GCP Cloud KMS Ed25519 backend (feature-gated).
pub use audit_record::AuditRecord;
pub use audit_record::AuditSubject;
pub use audit_sink::AuditSink;
pub use audit_sink::CollectingAuditSink;
pub use audit_sink::NoAuditSink;
pub use audit_sink::StderrAuditSink;
#[cfg(feature = "gcp_kms_keysource")]
pub use gcp_kms_keysource::GcpKmsConfig;
#[cfg(feature = "gcp_kms_keysource")]
pub use gcp_kms_keysource::GcpKmsEd25519Backend;
pub use log_sink::InnerLogEvent;
pub use log_sink::InnerLogSink;
pub use log_sink::StderrLogSink;
// MCPS-076 (audit gap G-3): EnvKeySource is dev/CI-only and exists only when the
// non-default `dev_env_key_source` feature is enabled.
#[cfg(feature = "dev_env_key_source")]
pub use key_source::EnvKeySource;
pub use key_source::FileKeySource;
pub use key_source::KeyError;
pub use key_source::KeySource;
// Issue #3838: the response-signing delegation seam (a non-exporting HSM/KMS can
// implement this without surrendering its private key).
pub use key_source::ResponseSigner;
pub use kms_keysource::KmsEd25519Backend;
pub use kms_keysource::KmsKeySource;
pub use kms_keysource::KmsResponseSigner;
// Issue #4030: the online OCSP revocation checker (feature-gated). Grouped under ONE
// `cfg`, unlike the one-per-line re-exports around it: six items behind the same gate
// spelled twelve lines is twelve places for the gate to disagree with itself.
#[cfg(feature = "online_ocsp")]
pub use ocsp::{
    CertRevocationStatus, NotEstablished, OcspChecker, OcspError, RevocationEvidence,
    TrustedRevocationAnswer,
};
// Issue #4034: the PKCS#11 key source (feature-gated).
pub use http_profile_serve::ActorResolver;
pub use http_profile_serve::HttpProfileProxy;
#[cfg(feature = "pkcs11_keysource")]
pub use pkcs11_keysource::Pkcs11KeySource;
// Issue #4028: the Redis shared replay backend (feature-gated).
#[cfg(feature = "redis_replay")]
pub use async_redis_store::RedisAsyncAtomicReplayStore;
#[cfg(feature = "cpstore_etcd")]
pub use etcd_store::EtcdAtomicReplayStore;
#[cfg(feature = "redis_replay")]
pub use redis_store::RedisAtomicReplayStore;
pub use replay_tier::ReplayDurabilityTier;
pub use revocation_tier::RevocationTier;
pub use shared_replay::AtomicReplayStore;
pub use shared_replay::InMemoryAtomicReplayStore;
pub use shared_replay::ReplayStoreError;
pub use shared_replay::SharedReplayCache;
pub use trust_plane::InvalidationChannel;
pub use trust_plane::InvalidationEvent;
pub use trust_plane::PushInvalidationTrustCache;
// Kept at the crate root for existing embedders; the provenance is the harness.
pub use blocking_mtls_harness::serve;
pub use blocking_mtls_harness::serve_once;
pub use blocking_mtls_harness::serve_once_with_assertion;
pub use communication_assurance::peer_identity_provenance::PeerIdentityProvenance;
pub use tls::ServerLimits;
pub use tls::ServerOptions;
pub use tls::TlsError;
pub use tls::MCP_INGRESS_ASSERTION_HEADER;
pub use transport::extract_identity;
pub use transport::ingress::AttestedCertVerification;
pub use transport::ingress::AttestedIngressVerified;
pub use transport::ingress::AttestedRevocation;
pub use transport::ingress::LbAssertion;
pub use transport::ingress::LbAssertionBinding;
pub use transport::ingress::LbAssertionRejection;
pub use transport::ingress::LbAssertionV2;
pub use transport::ingress::LbAssertionV2Binding;
pub use transport::ingress::LbAssertionV2Rejection;
pub use transport::ingress::DEFAULT_LB_ASSERTION_MAX_AGE_SECS;
pub use transport::validate_routing_headers;
pub use transport::ExactMatchBinding;
pub use transport::IdentityPolicy;
pub use transport::IdentitySource;
pub use transport::RequestHeaders;
pub use transport::RoutingHeaderRejection;
pub use transport::StaticIdentityProvider;
pub use transport::TransportBindingPolicy;
pub use transport::TransportBindingProvider;
pub use transport::TransportIdentity;
pub use transport::MAX_ASSERTED_IDENTITY_LEN;
pub use transport::MCP_METHOD_HEADER;
pub use transport::MCP_NAME_HEADER;
#[cfg(feature = "redis_replay")]
pub use trust_epoch::redis_trust_epoch_source;
pub use trust_epoch::EpochReader;
#[cfg(feature = "redis_replay")]
pub use trust_epoch::RedisEpochReader;
pub use trust_epoch::TrustEpochSource;
