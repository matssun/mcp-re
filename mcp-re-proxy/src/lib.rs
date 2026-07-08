//! MCP-RE server-side sidecar (MCPS-015 + MCPS-016).
//!
//! [`Proxy`] wraps an unmodified inner MCP server ([`InnerServer`]): it verifies
//! every inbound MCP-RE request before dispatch, fails closed on any verification
//! failure (the inner server is never reached), strips the external transport
//! envelope, injects a fresh verified-context block as the sole writer, forwards
//! only verified requests, and signs the inner server's result on the way back.
//!
//! MCPS-023 adds opt-in Phase 5 policy enforcement; MCPS-024 (ADR-MCPS-014) adds
//! the Phase 6 transport-binding abstraction (`transport`): identity types, the
//! provider seam, and the binding policy that ties the verified `signer` to the
//! mTLS channel identity.
//!
//! # Security posture (v1, Phase 6.1)
//!
//! What this supports: **single-node production hardening** with Rust-native
//! mTLS, file-backed *single-node* durable replay protection, an explicit
//! client-cert identity policy (no implicit fallback), and a **short-lived
//! client-certificate revocation posture** — there is NO online CRL/OCSP, so the
//! proxy ENFORCES a maximum client-cert lifetime (CLI default 1h) and a
//! compromised credential is bounded by that lifetime.
//!
//! What v1 does NOT support (and must not be claimed) until the corresponding
//! work lands: **horizontally-scaled production** replay protection, **enterprise
//! key custody** (needs an HSM/KMS `KeySource`), and **full revocation** (needs
//! CRL/OCSP or equivalent). Issue #3837 adds the SHARED-cache machinery for
//! horizontal scale — [`SharedReplayCache`] over an [`AtomicReplayStore`], with an
//! in-memory reference store proving cross-node rejection — but the only in-tree
//! [`AtomicReplayStore`] today is that in-memory reference store; no production
//! shared backend ships in this build. A real shared backend (the Redis adapter
//! plus the `crates_mcp_re` repin and a live-backend black-box test) is tracked as a
//! separate follow-up. Until it lands, the file cache remains single-node only and
//! multi-node replay safety MUST NOT be claimed in a real deployment.

// ADR-MCPS-022: explicit authorized server key set + per-audience response-signing
// identity mode (per_node_keyset default | shared_remote_signer). The verifier-side
// admission anchor; composes with `trust_cache::BoundedTrustCache` (ADR-MCPS-021).
pub mod authorized_keyset;
// ADR-MCPRE-051 §6 (MCPRE-116): versioned, atomically-swapped serving-config
// snapshots + the in-process CRL hot-reloader (subsumes MCPS-66). Always compiled;
// pure std (RwLock<Arc<ServerConfig>>), no new dependency.
pub mod config_snapshot;
// ADR-MCPS-028 §B: native AWS KMS Ed25519 response signer over blocking HTTPS
// (ureq) + a minimal audited SigV4 signer — NO async `aws-sdk-kms`/tokio/Smithy
// (ADR-MCPS-018 lean-sync firewall). Compiled ONLY under the non-default
// `aws_kms_keysource` feature so the default build links no HTTPS/SigV4 code.
#[cfg(feature = "aws_kms_keysource")]
pub mod aws_kms_keysource;
#[cfg(feature = "aws_kms_keysource")]
pub mod aws_sigv4;
pub mod cli;
// Issue #3838 (ADR-MCPS-014): a non-exporting reference `ResponseSigner` proving the
// response-signing delegation seam — a backend whose key never leaves it can drive
// the proxy's full signing path.
pub mod delegated_response_signer;
// ADR-MCPS-028 §G: delegated TLS handshake signing — a rustls SigningKey that
// forwards the handshake transcript to a non-exporting device/KMS so the TLS
// server key never leaves it. Generic mechanism (always compiled); the per-backend
// raw signers are wired under their own feature gates.
pub mod delegated_tls;
pub mod durable_replay;
// ADR-MCPS-028 §C: native GCP Cloud KMS Ed25519 response signer over blocking HTTPS
// (ureq) + OAuth2 bearer — NO async google-cloud SDK. Compiled ONLY under the
// non-default `gcp_kms_keysource` feature.
#[cfg(feature = "gcp_kms_keysource")]
pub mod gcp_kms_keysource;
pub mod inner_launch;
pub mod key_source;
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
pub mod persistent_inner;
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
pub mod proxy;
// Issue #69 (epic #68 v0.4 Axis 1): the etcd-backed CP / LINEARIZABLE shared
// replay backend that makes `--replay-durability-tier linearizable` declarable
// with a real durable-linearizable store (ADR-MCPS-020). Compiled ONLY under the
// non-default `cpstore_etcd` feature so the default build is unchanged.
#[cfg(feature = "cpstore_etcd")]
pub mod etcd_store;
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
// ADR-MCPS-021 Axis 2: the declared REVOCATION tier (Tier 1 bounded-cache / Tier 2
// live / Tier 3 push) — semantic names, honest per-tier guarantee, tier-claim
// ceiling. Pure type — in the default build. The Axis-2 analogue of replay_tier.
pub mod revocation_tier;
// ADR-MCPS-021 Tier 2: live strong trust check — consults the inner store on every
// verification (no positive-trust caching), with an optional second live
// revocation authority; fail-closed on store/revocation outage.
pub mod live_trust;
// ADR-MCPS-021 Tier 3: push-invalidation trust cache — bounded-`T` caching plus an
// injected invalidation channel that evicts revoked entries immediately, with a
// bounded-`T` fallback when the channel is unhealthy (never a zero-window claim).
pub mod push_trust;
pub mod rlimits;
// Issue #3865: OS sandbox PROFILE + fail-closed platform gate for inner-server
// fs/network containment (the config, CLI, seam, and fail-closed gate).
pub mod sandbox;
// Issue #4039: the LINUX kernel-enforcement backend behind the #3865 seam —
// Landlock fs ruleset + seccomp-bpf egress filter installed on the inner-server
// child before exec. Linux-only: a non-Linux build excludes this module entirely
// and never links landlock/seccompiler.
#[cfg(target_os = "linux")]
pub mod sandbox_linux;
// Issue #3837: shared, server-side-atomic replay cache for horizontally-scaled
// replay safety (the backend-agnostic core + the in-memory reference store).
pub mod shared_replay;
pub mod tls;
pub mod transport;
// ADR-MCPRE-051 Phase 2 (§1): OPT-IN async serving path (tokio + tokio-rustls +
// hyper keep-alive/H2). Behind the non-default `async_serve` feature; the default
// production closure links no tokio/hyper (ADR-MCPS-018 lean-sync firewall stays
// intact) and this module is not compiled. A shared runtime is dev scaffolding
// only (per-core SO_REUSEPORT is MCPRE-113).
#[cfg(feature = "async_serve")]
pub mod async_serve;
// MCPRE-113 (ADR-MCPRE-051 §1, Phase 2): the per-core serving fleet — one worker
// thread per core, each a current-thread tokio runtime with its own SO_REUSEPORT
// listener + Linux CPU pinning, over one Proxy per core. The target data plane;
// supersedes the single-shared-runtime scaffolding above. Same `async_serve` gate.
#[cfg(feature = "async_serve")]
pub mod async_fleet;
// MCPRE-117 (ADR-MCPRE-051 §4, Phase 2): the async authoritative replay tier seam —
// the async AtomicReplayStore analogue + the per-core L1-never-Fresh fast-reject
// wrapper, so the per-core data plane checks replay without blocking a runtime worker.
// Same `async_serve` gate; concrete async Redis/etcd backends plug into this contract.
#[cfg(feature = "async_serve")]
pub mod async_replay;
// MCPRE-117 (ADR-MCPRE-051 §4): the ASYNC Redis authoritative replay backend
// (`SET NX PX` via the tokio async client + auto-reconnecting ConnectionManager).
// Behind BOTH the async serving path and the redis backend flag; the async data
// plane awaits it instead of blocking a per-core worker on the sync client.
#[cfg(all(feature = "async_serve", feature = "redis_replay"))]
pub mod async_redis_store;
// MCPS-84 (ADR-MCPS-049 W2): trust-epoch invalidation source for the ADR-021 Push
// tier. Core epoch->event logic is always compiled (and unit-tested); the Redis
// reader is `redis_replay`-gated inside the module.
pub mod trust_epoch;
// ADR-MCPS-021: bounded trust-propagation cache (Tier 1). Caching is a caller
// concern (mcp-re-core does not cache); this wraps the injected TrustResolver with
// the bounded-`T` window + negative-cache classification + fail-closed rules.
pub mod trust_cache;

pub use authorized_keyset::AuthorizedKeyEntry;
pub use authorized_keyset::AuthorizedKeySet;
pub use authorized_keyset::KeySetError;
pub use authorized_keyset::KeySetTrustResolver;
pub use authorized_keyset::KeyStatus;
pub use authorized_keyset::ResponseSigningIdentityMode;
// ADR-MCPS-028 §B: the AWS KMS Ed25519 backend (feature-gated). Drives the
// `KmsResponseSigner` core via the `KmsEd25519Backend` seam.
#[cfg(feature = "aws_kms_keysource")]
pub use aws_kms_keysource::AwsKmsConfig;
#[cfg(feature = "aws_kms_keysource")]
pub use aws_kms_keysource::AwsKmsEd25519Backend;
pub use delegated_response_signer::DelegatedResponseSigner;
// ADR-MCPS-028 §G: delegated TLS signing (generic mechanism).
pub use delegated_tls::DelegatedCertResolver;
pub use delegated_tls::DelegatedEd25519SigningKey;
pub use delegated_tls::RawEd25519TlsSigner;
// ADR-MCPS-028 §C: the GCP Cloud KMS Ed25519 backend (feature-gated).
#[cfg(feature = "gcp_kms_keysource")]
pub use gcp_kms_keysource::GcpKmsConfig;
#[cfg(feature = "gcp_kms_keysource")]
pub use gcp_kms_keysource::GcpKmsEd25519Backend;
pub use durable_replay::DurableReplayCache;
pub use inner_launch::BoundedStderr;
pub use inner_launch::InnerLaunchConfig;
pub use inner_launch::InnerLogEvent;
pub use inner_launch::InnerLogSink;
pub use inner_launch::StderrLogSink;
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
// Issue #4030: the online OCSP revocation checker (feature-gated).
#[cfg(feature = "online_ocsp")]
pub use ocsp::CertRevocationStatus;
#[cfg(feature = "online_ocsp")]
pub use ocsp::OcspChecker;
#[cfg(feature = "online_ocsp")]
pub use ocsp::OcspError;
pub use persistent_inner::PersistentSubprocessInner;
// Issue #4034: the PKCS#11 key source (feature-gated).
#[cfg(feature = "pkcs11_keysource")]
pub use pkcs11_keysource::Pkcs11KeySource;
pub use proxy::InnerServer;
pub use proxy::Proxy;
// Issue #4028: the Redis shared replay backend (feature-gated).
#[cfg(feature = "cpstore_etcd")]
pub use etcd_store::EtcdAtomicReplayStore;
#[cfg(feature = "redis_replay")]
pub use redis_store::RedisAtomicReplayStore;
#[cfg(all(feature = "async_serve", feature = "redis_replay"))]
pub use async_redis_store::RedisAsyncAtomicReplayStore;
#[cfg(feature = "redis_replay")]
pub use trust_epoch::redis_trust_epoch_source;
#[cfg(feature = "redis_replay")]
pub use trust_epoch::RedisEpochReader;
pub use trust_epoch::EpochReader;
pub use trust_epoch::TrustEpochSource;
pub use replay_tier::ReplayDurabilityTier;
pub use rlimits::RLimits;
pub use sandbox::NetworkPolicy;
pub use sandbox::SandboxMode;
pub use sandbox::SandboxProfile;
pub use shared_replay::AtomicReplayStore;
pub use shared_replay::InMemoryAtomicReplayStore;
pub use shared_replay::ReplayStoreError;
pub use shared_replay::SharedReplayCache;
pub use tls::build_server_config_delegated_validated;
pub use tls::build_server_config_delegated_with_crls;
pub use tls::extract_identity;
pub use tls::IdentityStrategy;
pub use tls::serve;
pub use tls::serve_once;
pub use tls::serve_once_with_assertion;
pub use tls::MCP_INGRESS_ASSERTION_HEADER;
pub use tls::RustlsDirectProvider;
pub use tls::ServerLimits;
pub use tls::ServerOptions;
pub use tls::TlsError;
pub use transport::validate_asserted_identity_value;
pub use transport::validate_routing_headers;
pub use transport::AssertedIdentityRejection;
pub use transport::RoutingHeaderRejection;
pub use transport::MCP_METHOD_HEADER;
pub use transport::MCP_NAME_HEADER;
pub use transport::ExactMatchBinding;
pub use transport::IdentityPolicy;
pub use transport::IdentitySource;
pub use transport::AttestedCertVerification;
pub use transport::AttestedIngressVerified;
pub use transport::AttestedRevocation;
pub use transport::LbAssertion;
pub use transport::LbAssertionBinding;
pub use transport::LbAssertionRejection;
pub use transport::LbAssertionV2;
pub use transport::LbAssertionV2Binding;
pub use transport::LbAssertionV2Rejection;
pub use transport::MappedBinding;
pub use transport::DEFAULT_LB_ASSERTION_MAX_AGE_SECS;
pub use transport::RequestHeaders;
pub use transport::ReverseProxyHeaderFormat;
pub use transport::ReverseProxyMtlsProvider;
pub use trust_cache::BoundedTrustCache;
pub use revocation_tier::RevocationTier;
pub use live_trust::LiveTrustResolver;
pub use push_trust::InMemoryInvalidationChannel;
pub use push_trust::InvalidationChannel;
pub use push_trust::InvalidationEvent;
pub use push_trust::PushInvalidationTrustCache;
pub use transport::StaticIdentityProvider;
pub use transport::TransportBindingPolicy;
pub use transport::TransportBindingProvider;
pub use transport::TransportIdentity;
