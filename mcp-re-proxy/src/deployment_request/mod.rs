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

mod authorization;
mod inner_backend_display;
mod kinds;
mod secret_string;

pub use authorization::AuthorizationRequest;
pub(crate) use inner_backend_display::RedactedBackendUrls;
pub use kinds::{
    AdmissionKind, AuditSinkKind, AuthzKind, BindingKind, KeySourceKind, OcspKind,
    VerifiedContextKind,
};
pub use secret_string::SecretString;

use std::time::Duration;

use crate::tls::ServerLimits;
use crate::transport::IdentityPolicy;

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
    /// Where key material is read from.
    pub key_source: KeySourceKind,
    /// Location (path or env var) of the Base64URL Ed25519 signing-key seed.
    pub signing_key_seed: String,
    /// Location of the PEM TLS server certificate chain.
    pub tls_cert: String,
    /// Location of the PEM TLS server private key.
    pub tls_key: String,
    /// Location of the PEM client-CA trust anchors.
    pub client_ca: String,
    /// Paths to offline client-certificate revocation lists (CRLs), PEM or DER
    /// (#3839). Each `--client-crl` value (comma-separated and/or repeated) adds a
    /// file; empty disables revocation checking (the pre-#3839 behavior). OFFLINE
    /// only — there is no online OCSP / distribution-point fetching.
    ///
    /// These bytes feed TWO checks: the handshake verifier, and the PER-REQUEST
    /// revoked-serial index (`client_revocation`). The second is what makes revocation
    /// take effect on a connection the peer is already holding — client authentication
    /// runs on a full handshake only, so without it a keep-alive or HTTP/2 connection
    /// serves every later request on a certificate nothing re-checks.
    pub client_crl_paths: Vec<String>,
    /// ADR-MCPRE-051 §6 (MCPRE-116) in-process CRL hot-reload cadence, in seconds.
    /// `None` (default) keeps the static-snapshot posture (reload requires a
    /// restart). `Some(n)` spawns a background task that every `n` seconds re-reads
    /// the `--client-crl` files and atomically swaps in a rebuilt verifier AND a
    /// rebuilt per-request revoked-serial index — so a refreshed CRL is honored
    /// WITHOUT a restart, on established connections as well as new ones. A failed
    /// reload keeps the last-good config (which still fails closed once its CRL passes
    /// `nextUpdate`). Has no effect without `--client-crl`.
    ///
    /// This cadence is therefore the revocation-latency bound for every peer, not only
    /// for peers that happen to reconnect.
    pub client_crl_reload_secs: Option<u64>,
    /// ONLINE OCSP client-cert revocation selection (#4030). `Off` (default) does
    /// no online check; `Require` checks the leaf's OCSP responder at connection
    /// time. Honored ONLY in an `online_ocsp` build; a default build fails closed
    /// at construction when `Require` is selected.
    pub client_ocsp: OcspKind,
    /// Explicit OCSP responder URL overriding the leaf's AIA OCSP URL (#4030).
    /// `None` uses the AIA URL from the certificate. Only meaningful when
    /// `client_ocsp == Require`.
    pub ocsp_responder_url: Option<String>,
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
    /// Shared replay-store connection URL (required when `replay == Shared` and the
    /// declared tier is a Redis tier), e.g. `redis://127.0.0.1:6379` (issue #3837).
    ///
    /// The REPLAY store's location, and nothing else. It once also decided where the MRTR
    /// continuation store lived, which made one field carry two different facts: on the
    /// linearizable tier replay is on etcd and this named the continuation store instead.
    /// `continuation_control_redis_url` owns that fact now.
    pub replay_redis_url: Option<String>,
    /// ADR-MCPS-047: the cross-replica MRTR continuation store's Redis URL.
    ///
    /// Separate from `replay_redis_url` because it is a different fact, not the same fact
    /// with a second consumer: replay records where admitted nonces live, this records
    /// where a retained continuation base lives, and the two stores answer to different
    /// owners with disjoint key namespaces. They may name the same Redis — that is then an
    /// operator's deployment choice rather than an alias the configuration forces.
    ///
    /// `None` is a real posture, not missing configuration: cross-replica MRTR is
    /// opportunistic, its absence is announced, and an answer arriving at a replica with
    /// no correlated continuation is refused rather than guessed.
    pub continuation_control_redis_url: Option<String>,
    /// MCPRE-493: what a request carrying NO admission evidence means here —
    /// `off` (admission not enforced at all), `optional`, or `required`. Anything
    /// but `off` requires an authority to verify assertions against and a source to
    /// check currency against; a gate with neither would verify nothing.
    pub admission: AdmissionKind,
    /// The admission authority's root key id, as named in an assertion's
    /// `issuer_kid`. A kid never introduces trust: an assertion naming any other
    /// issuer is refused.
    pub admission_authority_kid: Option<String>,
    /// The admission authority's Ed25519 public key, base64url, no padding.
    pub admission_authority_pubkey_b64url: Option<String>,
    /// Redis URL of the shared authoritative admission record — the tier a
    /// revocation is written to and every replica reads. Separate from
    /// `replay_redis_url` on purpose: admission state and replay state have
    /// different owners, lifetimes and blast radii, and collapsing them would make
    /// one outage two.
    pub admission_redis_url: Option<String>,
    /// P (seconds): how long a replica may keep serving on the LAST-KNOWN state when
    /// the authority is unreachable. Meaningful only with
    /// `admission_allow_degraded`.
    pub admission_degraded_bound_secs: i64,
    /// Whether degraded mode is permitted at all. Off by default: an unreachable
    /// authority fails closed. Enabling it trades a bounded window of stale-admission
    /// risk for availability, and that is a deployment's call to make explicitly.
    pub admission_allow_degraded: bool,
    /// ADR-MCPS-021 Axis 2: how often `--trust` is re-read, in seconds. `None` means
    /// read once at startup — under which no revocation tier can revoke a
    /// request-signer key on a running replica, because every tier resolves against
    /// that one snapshot. Enabling it bounds the exposure window at the cadence.
    pub trust_reload_secs: Option<u64>,
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
    /// MCPS-84 (ADR-MCPS-049 W2): Redis URL for the networked trust-epoch
    /// invalidation source (ADR-021 Tier 3 / `--revocation-tier push`). When set,
    /// the Push tier watches this Redis's monotonic epoch key and flushes the trust
    /// cache on an advance; when `None`, Push runs at its inert bounded-`T`
    /// fallback. Consumed only under the `redis_replay` feature.
    pub trust_epoch_redis_url: Option<String>,
    /// The Redis key holding the monotonic trust epoch (default
    /// [`crate::trust_epoch::DEFAULT_TRUST_EPOCH_KEY`]).
    pub trust_epoch_key: Option<String>,
    /// CP / linearizable replay-store (etcd v3 JSON gateway) endpoint, e.g.
    /// `http://127.0.0.1:2379` (issue #69, epic #68 v0.4 Axis 1). REQUIRED when the
    /// declared durability tier is `LINEARIZABLE`, and meaningless otherwise — a
    /// dangling value is refused (fail closed). Selecting `LINEARIZABLE` WITHOUT this
    /// endpoint is refused by the `Replay` machine, never silently downgraded to Redis /
    /// in-memory (ADR-MCPS-020).
    pub cpstore_etcd_endpoint: Option<String>,
    /// Declared replay-store durability tier (ADR-MCPS-020). Required when
    /// `replay == Shared` — the tier is an explicit deployment assertion that
    /// determines the horizontal replay-safety claim. `None` for single-node
    /// `Memory` / `File` backends.
    pub replay_durability_tier: Option<crate::replay_tier::ReplayDurabilityTier>,
    /// Declared revocation tier (ADR-MCPS-021 Axis 2). Selects how strong a
    /// revocation-propagation window the deployment asserts: Tier 1
    /// (`bounded-cache:<T>`, the default), Tier 2 (`live`), or Tier 3
    /// (`push:<T>`). The proxy surfaces the tier's own honest guarantee and
    /// CANNOT surface a window stronger than the configured tier proves. Defaults
    /// to bounded-cache with the deployment-default window `T` so absent-flag
    /// behavior is byte-for-byte the Tier-1 posture.
    pub revocation_tier: crate::revocation_tier::RevocationTier,
    /// Transport-binding selection.
    pub binding: BindingKind,
    /// The authoritative client-certificate identity field (no implicit fallback).
    pub identity_source: IdentityPolicy,
    /// ADR-MCPS-023 Tier 3 (issue #71): the trusted LB verification keys for
    /// LB-signed request-bound ingress assertions, as `(key_id, base64url-ed25519-pub)`
    /// pairs from repeatable `--ingress-lb-key <keyid>:<base64-pub>`. Required (and
    /// only meaningful) when `binding == LbAssertion`; an unknown asserted key id
    /// fails closed. Empty for every other binding mode.
    pub ingress_lb_keys: Vec<(String, String)>,
    /// ADR-MCPS-023 §C (Mode C): the trusted ingress-attestor verification keys for
    /// `mcp-re/lb-ingress-assertion/v2` assertions, as `(key_id, base64url-ed25519-pub)`
    /// pairs from repeatable `--ingress-attestor-key <keyid>:<base64-pub>`. Required
    /// (and only meaningful) when `binding == AttestedIngress`; an unknown asserted
    /// key id fails closed. Empty for every other binding mode.
    pub ingress_attestor_keys: Vec<(String, String)>,
    /// ADR-MCPS-023 §C (Mode C): the ingress identities the node trusts, from
    /// repeatable `--ingress-identity <id>`. A v2 assertion whose `ingress_identity`
    /// is not in this set fails closed. Required when `binding == AttestedIngress`.
    pub ingress_identities: Vec<String>,
    /// ADR-MCPS-023 §C (Mode C): the node's own audience; a v2 assertion's `audience`
    /// must equal it (route/audience binding). Set from `--ingress-audience`;
    /// required when `binding == AttestedIngress`.
    pub ingress_audience: Option<String>,
    /// ADR-MCPS-023 §C2 (Mode C): the explicit operator acknowledgement, via
    /// `--ingress-pinned-mtls`, that the attestor→node hop is a pinned mTLS channel
    /// (or equivalent pinned workload identity). Mode C REQUIRES it — absent, the
    /// proxy refuses to start (fail closed), so an attested-ingress posture can
    /// never run without the pinned backend channel it depends on.
    pub ingress_pinned_mtls: bool,
    /// Everything this deployment asks for on the authorization axis.
    pub authorization: AuthorizationRequest,
    /// PKCS#11 module (provider `.so`/`.dylib`) path. Required when
    /// `key_source == Pkcs11` (issue #4034).
    pub pkcs11_module: Option<String>,
    /// Path the PKCS#11 token User PIN is read from. Required when
    /// `key_source == Pkcs11`.
    ///
    /// The PIN itself is deliberately NOT a field here. Two reasons, and the config
    /// carrying the path rather than the value answers both:
    ///
    /// * There is no way to pass it on argv. A process's command line is world-readable
    ///   on every platform this runs on (`ps`, `/proc/<pid>/cmdline`), so
    ///   `--pkcs11-pin <pin>` published the credential that unlocks the token holding
    ///   the response-signing (and optionally TLS) private keys to every local user for
    ///   the lifetime of the process.
    /// * [`DeploymentRequest`] derives `Debug` and is cloned freely, so a PIN stored here would
    ///   ride along into any structured log, panic message, or debug print. Keeping only
    ///   the path means there is nothing to redact.
    ///
    /// The file is read once, at key-source construction, into a short-lived
    /// [`SecretString`], and is held to the same permission floor as the other key files
    /// (`key_file_mode_is_insecure`) — the PIN is protected by the same mechanism as the
    /// keys it unlocks.
    pub pkcs11_pin_file: Option<String>,
    /// PKCS#11 token label selecting the slot whose token holds the signing key
    /// (token labels are stable across reboots; slot ids are not). Required when
    /// `key_source == Pkcs11`.
    pub pkcs11_token_label: Option<String>,
    /// CKA_LABEL of the Ed25519 signing-key object on the token. Required when
    /// `key_source == Pkcs11`.
    pub pkcs11_key_label: Option<String>,
    /// CKA_LABEL of the Ed25519 TLS-key object on the token (issue #59,
    /// ADR-MCPS-028 §G). OPTIONAL and independent of `pkcs11_key_label` — a separate
    /// security principal. When `Some`, the TLS handshake is DELEGATED to the
    /// token-resident TLS key (the TLS private key never leaves the device) and an
    /// exported `--tls-key` is rejected by [`validate_tls_signing_exclusivity`].
    /// `None` keeps the file-backed TLS path (issue #4034). Only meaningful when
    /// `key_source == Pkcs11`.
    pub pkcs11_tls_key_label: Option<String>,
    /// AWS region for the AWS KMS key source. Required when `key_source == AwsKms`
    /// (ADR-MCPS-028 §B).
    pub aws_kms_region: Option<String>,
    /// AWS KMS key id / ARN / alias. Required when `key_source == AwsKms`.
    pub aws_kms_key_id: Option<String>,
    /// Optional AWS KMS endpoint override (emulator/test endpoint).
    pub aws_kms_endpoint: Option<String>,
    /// AWS KMS key id / ARN / alias of the SECOND, DISTINCT Ed25519 KMS key that
    /// custodies the TLS server key (issue #60, ADR-MCPS-028 §G). OPTIONAL and
    /// independent of `aws_kms_key_id` (the object-signing key) — a separate
    /// security principal the operator SHOULD scope with a distinct authz policy.
    /// When `Some`, the TLS handshake is DELEGATED to KMS (the TLS private key never
    /// leaves KMS) and an exported `--tls-key` is rejected by
    /// [`validate_tls_signing_exclusivity`]; `None` keeps the file-backed TLS path.
    /// Only meaningful when `key_source == AwsKms` (reuses `--aws-kms-region` /
    /// `--aws-kms-endpoint`).
    pub aws_kms_tls_key_id: Option<String>,
    /// Take the AWS KMS credentials from **IRSA** — exchange the projected
    /// service-account token at `AWS_WEB_IDENTITY_TOKEN_FILE` for temporary
    /// credentials via STS — instead of the static `AWS_ACCESS_KEY_ID` /
    /// `AWS_SECRET_ACCESS_KEY` pair. The AWS counterpart of
    /// `--gcp-kms-use-metadata`, and the flag that lets an EKS deployment hold no
    /// long-lived IAM key material at all.
    pub aws_kms_use_web_identity: bool,
    /// Optional STS endpoint override for the IRSA exchange (tests/emulators).
    /// Defaults to the REGIONAL `https://sts.<region>.amazonaws.com`.
    pub aws_sts_endpoint: Option<String>,
    /// GCP Cloud KMS key-version resource path
    /// (`projects/.../cryptoKeyVersions/N`). Required when `key_source == GcpKms`
    /// (ADR-MCPS-028 §C).
    pub gcp_kms_key_version: Option<String>,
    /// Optional GCP Cloud KMS endpoint override (emulator/test endpoint).
    pub gcp_kms_endpoint: Option<String>,
    /// GCP Cloud KMS key-version resource path of the SECOND, DISTINCT
    /// `EC_SIGN_ED25519` key version that custodies the TLS server key (issue #61,
    /// ADR-MCPS-028 §G). OPTIONAL and independent of `gcp_kms_key_version` (the
    /// object-signing key) — a separate security principal the operator SHOULD scope
    /// with a distinct IAM policy. When `Some`, the TLS handshake is DELEGATED to
    /// Cloud KMS (the TLS private key never leaves KMS) and an exported `--tls-key`
    /// is rejected by [`validate_tls_signing_exclusivity`]; `None` keeps the
    /// file-backed TLS path. Only meaningful when `key_source == GcpKms` (reuses
    /// `--gcp-kms-endpoint` / `--gcp-kms-use-metadata`).
    pub gcp_kms_tls_key_version: Option<String>,
    /// Use the GCE/GKE metadata server (workload identity) for the GCP KMS OAuth2
    /// token instead of an operator-supplied `MCP_RE_GCP_ACCESS_TOKEN`.
    pub gcp_kms_use_metadata: bool,
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
    /// Delegated-key TTL `T` in seconds (ADR-MCPRE-052 §4). The rotor mints a
    /// successor within the overlap window before each key's `exp`. Default 300s.
    pub delegated_ttl_secs: i64,
    /// Delegated-key rotation-overlap window `O` in seconds (0 < O < T). The successor
    /// is minted at `exp − O` so signing never gaps. Default 60s.
    pub delegated_overlap_secs: i64,
    /// The trust epoch minted into every delegation credential (ADR-MCPRE-052 §7 hard
    /// gate). REQUIRED (a verifier admits only credentials whose epoch is in its
    /// accepted set), and load-bearing — it must be coordinated with verifiers, so
    /// there is no silent default.
    pub delegated_trust_epoch: Option<String>,
    /// The root issuer key id the delegation credential chains to (its `issuer_kid`,
    /// resolved by verifiers for the Response slot). Defaults to `--server-key-id`.
    pub delegated_issuer_kid: Option<String>,
    /// The service/audience-scope hash the delegated key is scoped to
    /// (`mcp_re_audience_hash`). Defaults to `--audience`; must match the verifier's
    /// expected audience hash.
    pub delegated_audience_hash: Option<String>,
    /// Accept a key file that is group-READABLE (never group-writable, never
    /// world-anything) when its group is one this process is in — the Kubernetes
    /// `fsGroup` mount model, which the strict `0600` floor makes unsatisfiable for a
    /// non-root pod (C053b). Explicit opt-in; the default posture is unchanged.
    pub allow_group_readable_key_files: bool,
}
