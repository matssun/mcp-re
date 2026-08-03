//! Configuration + wiring for the production `mcp-re-proxy` CLI (MCPS-029,
//! ADR-MCPS-014; folds in MCPS-018 #3807).
//!
//! The pure, testable pieces of the binary live here: argument parsing, the
//! trust-file loader, the subprocess inner server, and the builders that turn a
//! [`Config`] into a [`KeySource`] / [`TrustResolver`] / [`Proxy`]. `main.rs` is a
//! thin shell that parses, builds, and runs the blocking serve loop.

use std::time::Duration;

use mcp_re_core::InMemoryTrustResolver;
use mcp_re_core::VerificationKey;
use serde_json::Value;

// MCPS-076 (audit gap G-3): EnvKeySource is dev/CI-only — compiled only under the
// non-default `dev_env_key_source` feature.
#[cfg(feature = "dev_env_key_source")]
use crate::key_source::EnvKeySource;
use crate::key_source::FileKeySource;
use crate::key_source::KeyError;
use crate::key_source::KeySource;
use crate::tls::ServerLimits;
use crate::transport::IdentityPolicy;
use crate::transport::ReverseProxyHeaderFormat;

/// A secret string that does not leak through `Debug` and is scrubbed on drop.
///
/// [`Config`] derives `Debug`, so any structured log, panic message, or debug print of
/// the config would otherwise carry the PKCS#11 User PIN verbatim. The PIN is the
/// credential that unlocks a token holding the response-signing and (optionally) TLS
/// private keys, so it belongs in the same custody class as the keys themselves.
///
/// `Zeroizing` wipes the heap allocation when the value drops. That is a best effort
/// against a core dump or a freed-page read, not a guarantee: the string was already
/// copied by whatever read it in, and `Clone` (needed because `Config` is `Clone`)
/// makes another copy. It removes the copies this code controls.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretString(zeroize::Zeroizing<String>);

impl SecretString {
    /// Wrap a secret value.
    pub fn new(value: impl Into<String>) -> Self {
        SecretString(zeroize::Zeroizing::new(value.into()))
    }

    /// Borrow the secret. Every call site is a place the value can escape — keep them
    /// few and close to the API that consumes it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No length either: a PIN's length is worth guessing with.
        f.write_str("SecretString(redacted)")
    }
}

/// Where key material is read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySourceKind {
    /// Files on disk (locations are paths).
    File,
    /// Environment variables (locations are variable names).
    Env,
    /// PKCS#11 token (issue #4034): the Ed25519 response-signing key lives on a
    /// hardware/software token and is exercised only via `C_Sign` — it never
    /// leaves the device. The TLS cert/key/CA still come from files in this
    /// build. Honored ONLY in a build with the `pkcs11_keysource` feature; a
    /// default build parses it but FAILS CLOSED at construction (mirrors `Env`).
    Pkcs11,
    /// AWS KMS (ADR-MCPS-028 §B): the Ed25519 response-signing key lives in AWS KMS
    /// and is exercised only via `Sign` — it never leaves KMS. The TLS cert/key/CA
    /// still come from files in this build (`--signing-key-seed` is accepted but
    /// UNUSED, as with `Pkcs11`). Credentials come from the standard AWS env vars.
    /// Honored ONLY in a build with the `aws_kms_keysource` feature; a default build
    /// parses it but FAILS CLOSED at construction (mirrors `Pkcs11`).
    AwsKms,
    /// GCP Cloud KMS (ADR-MCPS-028 §C): the Ed25519 response-signing key lives in
    /// Cloud KMS and is exercised only via `asymmetricSign`. TLS material is from
    /// files (`--signing-key-seed` accepted but UNUSED). The OAuth2 bearer comes
    /// from `MCP_RE_GCP_ACCESS_TOKEN` or the metadata server (`--gcp-kms-use-metadata`).
    /// Honored ONLY in a build with the `gcp_kms_keysource` feature; a default build
    /// parses it but FAILS CLOSED at construction.
    GcpKms,
}

/// Replay-cache backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionKind {
    /// Admission is not enforced. A call's admission binding, if it carries one, is
    /// verified evidence that decides nothing — the pre-MCPRE-493 behaviour.
    Off,
    /// Enforced when present. For a rollout that has not reached every client yet.
    Optional,
    /// Enforced always: a call with no admission evidence is refused. The only
    /// setting under which "every served call acted under a current admission" is a
    /// true statement about this deployment.
    Required,
}

/// Where the ADR-MCPS-035 per-request security record goes.
///
/// The record is the deployment's only per-request attribution surface: which actor
/// was admitted, which calls were refused and under exactly which frozen `mcp-re.*`
/// wire code. A deployment that wants it must say so — and a deployment that does
/// not gets a startup line saying it has none, rather than discovering the absence
/// after an incident.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditSinkKind {
    /// No per-request security record is emitted.
    None,
    /// One structured `key=value` line per decision on the proxy's stderr diagnostic
    /// channel — the same channel the startup lines and rotation warnings use.
    Stderr,
}

/// Whether the PEP writes its own verified context into the body forwarded to the
/// inner server (#415 rev 2 §10).
///
/// The caller-supplied reserved key is stripped either way; this selects only
/// whether the PEP's own context is then written in its place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedContextKind {
    /// Forward the stripped body with no verified context. The inner server makes no
    /// authorization decision on PEP-resolved identity.
    Disabled,
    /// Write the PEP's verified context into the forwarded body. Selecting this
    /// ASSERTS that nothing but this PEP can reach the inner server — the carrier is
    /// unsigned, so the channel is the only thing making it trustworthy, and no check
    /// here can confirm that property.
    Trusted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayKind {
    /// In-memory (lost on restart).
    Memory,
    /// Durable file-backed (SINGLE-NODE only).
    File,
    /// Shared, server-side-atomic cache for HORIZONTALLY-SCALED replay safety
    /// (issue #3837). No production shared backend ships in this build (the Redis
    /// adapter + crate repin + live-backend test are tracked separately), so
    /// selecting `shared` parses but FAILS CLOSED at construction with a clear
    /// "not yet available in this build" error (mirrors the env-keysource gate).
    Shared,
}

/// Transport-binding policy selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingKind {
    /// No transport binding (the mTLS identity is ignored).
    None,
    /// Exact match: request `signer` must equal the verified transport identity.
    Exact,
    /// ADR-MCPS-023 Tier 3 (issue #71): the verified transport identity comes from
    /// an LB-signed, request-bound ingress assertion (the node cryptographically
    /// verifies the LB tied the asserted client identity to THIS request hash),
    /// then binds exactly to the request signer. Honestly downgraded — NOT
    /// `end_to_end_mtls`. Requires at least one `--ingress-lb-key`.
    LbAssertion,
    /// ADR-MCPS-023 §C (v0.10) Mode C **attested ingress**: the verified transport
    /// identity comes from a controlled ingress attestor's request-bound
    /// `mcp-re/lb-ingress-assertion/v2` assertion, verified over the pinned
    /// attestor→node channel, then bound exactly to the request signer. Unlike
    /// `LbAssertion` (Mode B, strict-rejected) this is a strict-ADMITTED, explicit-
    /// opt-in posture — but it is *attested delegation*, NOT `end_to_end_mtls`: the
    /// load balancer witnesses proof-of-possession and stays in the trusted
    /// computing base. Requires `--ingress-attestor-key`, `--ingress-identity`,
    /// `--ingress-audience`, and the explicit `--ingress-pinned-mtls` acknowledgement.
    AttestedIngress,
}

/// ONLINE client-cert OCSP revocation selection (#4030). The online sibling of
/// the offline `--client-crl` posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcspKind {
    /// No online OCSP check (the default). Revocation, if any, comes only from
    /// the offline `--client-crl` set.
    Off,
    /// Require an online OCSP check at connection time. A verified client leaf is
    /// rejected on `Revoked` (always) and, failing closed, on
    /// `Unknown`/unreachable/timeout/parse error too (there is no soft-fail
    /// relaxation). Honored ONLY in a build with the `online_ocsp` feature; a
    /// default build parses it but FAILS CLOSED at construction (mirrors the
    /// env-keysource / shared-replay gates).
    Require,
}

/// Authorization-policy selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthzKind {
    /// No authorization policy.
    Off,
    /// The reference signed-authorization profile.
    Reference,
}

/// Fully-parsed CLI configuration.
#[derive(Debug, Clone)]
pub struct Config {
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
    /// at parse time.
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
    /// ADR-MCPRE-051 §1: number of per-core async worker runtimes (SO_REUSEPORT
    /// listeners). `0` (default) means auto — one worker per core via
    /// `std::thread::available_parallelism`. Pinning an explicit count makes the
    /// per-core linear-scaling benchmark reproducible (drive N=1 then N=cores) and
    /// lets an operator cap workers below the core count.
    pub cores: usize,
    /// MCPRE-114: fleet-GLOBAL in-flight ceiling, divided evenly across cores by
    /// `async_fleet`. `None` = no global target (a per-core `limits
    /// .max_in_flight_requests` may still apply; with neither there is no ceiling).
    pub max_in_flight_total: Option<usize>,
    /// Replay-cache backend.
    pub replay: ReplayKind,
    /// Replay-cache file path (required when `replay == File`).
    pub replay_path: Option<String>,
    /// Shared replay-store connection URL (required when `replay == Shared` and the
    /// declared tier is a Redis tier), e.g. `redis://127.0.0.1:6379` (issue #3837).
    pub replay_redis_url: Option<String>,
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
    /// ADR-MCPS-035: where the per-request security record goes. `None` by default —
    /// the record is a write on every request, so it is a deployment's choice; the
    /// startup line states which posture is in force either way.
    pub audit_sink: AuditSinkKind,
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
    /// dangling value is a hard parse error (fail closed). Selecting `LINEARIZABLE`
    /// WITHOUT this endpoint is rejected at parse time, never silently downgraded
    /// to Redis / in-memory (ADR-MCPS-020).
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
    /// The authoritative identity field (no implicit fallback). For the default
    /// direct-TLS path this is the client-certificate field; for reverse-proxy
    /// mode it selects which forwarded-header field is authoritative.
    pub identity_source: IdentityPolicy,
    /// Reverse-proxy ingress (MCPS-3840): when `Some`, the proxy reads the
    /// verified client identity from this TRUSTED forwarded header (set by an
    /// upstream mTLS-terminating reverse proxy) instead of extracting it from a
    /// locally-terminated client certificate. Enabling this is an explicit
    /// operator assertion that the listening socket is reachable ONLY by the
    /// trusted upstream. Mutually exclusive with local client-cert identity.
    pub reverse_proxy_identity_header: Option<String>,
    /// The wire format of the trusted reverse-proxy identity header (plain
    /// identity string or Envoy XFCC). Only meaningful when
    /// `reverse_proxy_identity_header` is set.
    pub reverse_proxy_header_format: ReverseProxyHeaderFormat,
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
    /// Authorization-policy selection.
    pub authz: AuthzKind,
    /// Offline policy-layer revocation deny-list paths (ADR-MCPS-013). Each
    /// `--revocation-list` value (comma-separated and/or repeated) adds a file of
    /// newline-delimited revoked `revocation_id`s. Loaded once at startup (OFFLINE
    /// only — restart to update). Empty means no grant deny-list is configured.
    pub revocation_list_paths: Vec<String>,
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
    /// * [`Config`] derives `Debug` and is cloned freely, so a PIN stored here would
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

/// Parse CLI arguments (excluding argv[0]) into a [`Config`]. Returns a
/// human-readable error string on any missing/invalid argument.
/// Validate an operator-supplied KMS endpoint override before anything is sent to it.
///
/// These overrides carry the ROOT-KEY trust bootstrap: `getPublicKey` fetches the
/// `spki_der`/verify key that the verify-before-return guardrail is measured against, and
/// on GCP every request also carries a live workload-identity bearer token. An unvalidated
/// override therefore hands a replayable credential to whatever host is named and lets a
/// substituted endpoint supply an attacker-chosen root signing key that every local
/// fail-closed check then passes self-consistently.
///
/// So: `https://` always; `http://` ONLY to loopback, which keeps the LocalStack / KMS
/// emulator lane working without letting a plaintext credential leave the machine.
/// Anything else is refused at parse, before a credential is minted.
fn validated_kms_endpoint(flag: &str, value: &str) -> Result<String, String> {
    let rest = if let Some(rest) = value.strip_prefix("https://") {
        return non_empty_authority(flag, value, rest).map(|()| value.to_string());
    } else if let Some(rest) = value.strip_prefix("http://") {
        rest
    } else {
        return Err(format!(
            "{flag} must be an absolute https:// URL (got {value:?}); this endpoint carries the \
             root-key trust bootstrap and, on GCP, a live bearer token"
        ));
    };
    non_empty_authority(flag, value, rest)?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = match authority.rsplit_once(':') {
        // Bracketed IPv6 literal: the last colon may belong to the address.
        Some((h, _)) if !authority.starts_with('[') || h.ends_with(']') => h,
        _ => authority,
    };
    if matches!(host, "localhost" | "127.0.0.1" | "[::1]") {
        return Ok(value.to_string());
    }
    Err(format!(
        "{flag} may only use http:// for a loopback emulator (localhost, 127.0.0.1, [::1]); \
         got host {host:?}. A plaintext endpoint exfiltrates the KMS credential and lets a \
         substituted host supply the root verify key"
    ))
}

/// Reject a URL whose authority is empty (`https://`, `http:///v1`), which would otherwise
/// produce a request URL with no host.
fn non_empty_authority(flag: &str, value: &str, rest: &str) -> Result<(), String> {
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return Err(format!("{flag} has no host: {value:?}"));
    }
    Ok(())
}

pub fn parse_args(args: &[String]) -> Result<Config, String> {
    let mut bind = None;
    let mut audience = None;
    let mut server_signer = None;
    let mut server_key_id = None;
    // One skew governs BOTH the RFC 9421 freshness gate and the replay `retain_until`,
    // so an admitted nonce is retained exactly as long as its signature can still be
    // accepted. The default is the profile's own `DEFAULT_MAX_CLOCK_SKEW` rather than a
    // locally-chosen number, so proxy and verifier cannot drift apart.
    let mut max_clock_skew: i64 = mcp_re_http_profile::VerifierPolicy::DEFAULT_MAX_CLOCK_SKEW;
    let mut mcp_protocol_versions: Vec<String> = Vec::new();
    // ADR-MCPS-039 (D1): default to the migration posture (admit both wire
    // profiles) so an omitted flag preserves back-compat with draft-01 clients;
    // `--expected-version-policy draft-02-only` tightens it.
    let mut target_uri: Option<String> = None;
    let mut trust_domain: Option<String> = None;
    let mut route: Option<String> = None;
    let mut key_source = KeySourceKind::File;
    let mut signing_key_seed = None;
    let mut tls_cert = None;
    let mut tls_key = None;
    let mut client_ca = None;
    // #3839 offline CRL revocation: zero or more CRL file paths, fail-closed on
    // unknown status by default.
    let mut client_crl_paths: Vec<String> = Vec::new();
    // ADR-MCPRE-051 §3: stateless HTTP inner backend URL(s) for the async serving
    // path (comma-separated and/or repeated).
    let mut inner_http_urls: Vec<String> = Vec::new();
    // ADR-MCPRE-051 §1: per-core worker count; 0 = auto (one per core).
    let mut cores: usize = 0;
    let mut max_in_flight_total: Option<usize> = None;
    // Whether `--max-in-flight` was given. `ServerLimits::max_in_flight_requests` now
    // carries a fail-safe DEFAULT, so its being `Some` no longer means the operator
    // stated a per-core ceiling — and a default must not out-rank an explicit
    // `--max-in-flight-total`.
    let mut max_in_flight_explicit = false;
    let mut client_crl_reload_secs: Option<u64> = None;
    // #4030 online OCSP revocation: off by default; responder-URL override
    // optional; hard-fail (deny on indeterminate) by default.
    let mut client_ocsp = OcspKind::Off;
    let mut ocsp_responder_url: Option<String> = None;
    let mut trust_path = None;
    let mut admission = AdmissionKind::Off;
    let mut admission_authority_kid: Option<String> = None;
    let mut admission_authority_pubkey_b64url: Option<String> = None;
    let mut admission_redis_url: Option<String> = None;
    let mut admission_degraded_bound_secs: i64 = 0;
    let mut admission_allow_degraded = false;
    let mut trust_reload_secs: Option<u64> = None;
    let mut audit_sink = AuditSinkKind::None;
    let mut verified_context = VerifiedContextKind::Disabled;
    let mut replay = ReplayKind::Memory;
    let mut replay_path = None;
    let mut replay_redis_url = None;
    // MCPS-84: networked trust-epoch invalidation backend (optional; only under
    // --revocation-tier push).
    let mut trust_epoch_redis_url = None;
    let mut trust_epoch_key = None;
    // #69 (epic #68 v0.4 Axis 1): the CP/etcd endpoint for the LINEARIZABLE tier.
    let mut cpstore_etcd_endpoint: Option<String> = None;
    let mut replay_durability_tier: Option<crate::replay_tier::ReplayDurabilityTier> = None;
    // ADR-MCPS-021 Axis 2: revocation tier. Defaults to Tier 1 bounded-cache with
    // the deployment-default window T, so an absent flag preserves the existing
    // Tier-1 posture exactly.
    let mut revocation_tier = crate::revocation_tier::RevocationTier::BoundedCache {
        t_secs: crate::trust_cache::DEFAULT_T_SECS,
    };
    let mut binding = BindingKind::Exact;
    let mut identity_source = IdentityPolicy::UriSan;
    let mut reverse_proxy_identity_header: Option<String> = None;
    let mut reverse_proxy_header_format = ReverseProxyHeaderFormat::Xfcc;
    // ADR-MCPS-023 Tier 3 (issue #71): repeatable trusted LB verification keys for
    // request-bound ingress assertions, as (key_id, base64url-ed25519-pub) pairs.
    let mut ingress_lb_keys: Vec<(String, String)> = Vec::new();
    // ADR-MCPS-023 §C (Mode C): attestor verification keys, trusted ingress
    // identities, the node's expected audience, and the pinned-mTLS acknowledgement.
    let mut ingress_attestor_keys: Vec<(String, String)> = Vec::new();
    let mut ingress_identities: Vec<String> = Vec::new();
    let mut ingress_audience: Option<String> = None;
    let mut ingress_pinned_mtls = false;
    let mut authz = AuthzKind::Off;
    // ADR-MCPS-013 policy-layer revocation: zero or more offline deny-list files.
    let mut revocation_list_paths: Vec<String> = Vec::new();
    // #4034 PKCS#11 key source: module path, User PIN (sensitive), token label,
    // and signing-key object label. Required only when `--key-source pkcs11`.
    let mut pkcs11_module: Option<String> = None;
    let mut pkcs11_pin_file: Option<String> = None;
    let mut pkcs11_token_label: Option<String> = None;
    let mut pkcs11_key_label: Option<String> = None;
    // #59 PKCS#11 delegated TLS: optional SECOND token object holding the Ed25519
    // TLS key. When set, TLS signing is delegated to the token (no exported key).
    let mut pkcs11_tls_key_label: Option<String> = None;
    // ADR-MCPS-028 §B AWS KMS: region + key id required when `--key-source aws-kms`;
    // endpoint optional (emulator). Credentials come from AWS_* env vars.
    let mut aws_kms_region: Option<String> = None;
    let mut aws_kms_key_id: Option<String> = None;
    let mut allow_group_readable_key_files = false;
    let mut aws_kms_endpoint: Option<String> = None;
    let mut aws_kms_tls_key_id: Option<String> = None;
    // ADR-MCPS-028 §C GCP Cloud KMS: key-version resource path required when
    // `--key-source gcp-kms`; endpoint optional; metadata-server token off by default
    // (operator MCP_RE_GCP_ACCESS_TOKEN), opt in with `--gcp-kms-use-metadata`.
    let mut gcp_kms_key_version: Option<String> = None;
    let mut gcp_kms_endpoint: Option<String> = None;
    let mut gcp_kms_tls_key_version: Option<String> = None;
    let mut gcp_kms_use_metadata = false;
    let mut limits = ServerLimits::default();
    // v1 revocation posture: short-lived client certs, proxy-enforced, default 1h.
    let mut max_client_cert_lifetime = Some(Duration::from_secs(3600));
    // MCPS-79 (ADR-MCPS-049): horizontally-scaled deployment topology, off by
    // default. This selects the deployment TOPOLOGY (single-node vs multi-verifier
    // fleet); it does NOT relax security — the proxy always refuses an unsafe config.
    // A fleet additionally rejects node-local replay caches.
    let mut fleet = false;
    // ADR-MCPRE-052 (MCPRE-122): delegated-signing is the ONLY response-signing mode.
    // The delegated-custody knobs are tracked as Options so their defaults are applied
    // at validation (trust-epoch is required; there is no direct-root mode to select).
    let mut delegated_ttl_secs: Option<i64> = None;
    let mut delegated_overlap_secs: Option<i64> = None;
    let mut delegated_trust_epoch: Option<String> = None;
    let mut delegated_issuer_kid: Option<String> = None;
    let mut delegated_audience_hash: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        // Valueless boolean flag (ADR-MCPS-028 §C): use the GCE/GKE metadata server
        // (workload identity) for the GCP Cloud KMS OAuth2 token instead of an
        // operator-supplied `MCP_RE_GCP_ACCESS_TOKEN`.
        if flag == "--gcp-kms-use-metadata" {
            gcp_kms_use_metadata = true;
            i += 1;
            continue;
        }
        // Valueless boolean flag (ADR-MCPS-023 §C2, Mode C): the explicit operator
        // acknowledgement that the attestor→node hop is a pinned mTLS channel. Mode C
        // REQUIRES it (checked below); absent, attested ingress refuses to start.
        if flag == "--ingress-pinned-mtls" {
            ingress_pinned_mtls = true;
            i += 1;
            continue;
        }
        // Valueless boolean flag (C053b): accept a group-READABLE key file whose group
        // this process is in — the Kubernetes fsGroup mount model. Explicit, because it
        // widens who can read a signing key; the strict 0600 floor is otherwise
        // unsatisfiable for a non-root pod.
        if flag == "--allow-group-readable-key-files" {
            allow_group_readable_key_files = true;
            i += 1;
            continue;
        }
        // Select the horizontally-scaled (fleet) deployment topology.
        if flag == "--fleet" {
            fleet = true;
            i += 1;
            continue;
        }
        let value = args
            .get(i + 1)
            .ok_or_else(|| format!("flag {flag} requires a value"))?;
        match flag {
            "--bind" => bind = Some(value.clone()),
            "--audience" => audience = Some(value.clone()),
            "--server-signer" => server_signer = Some(value.clone()),
            "--server-key-id" => server_key_id = Some(value.clone()),
            "--max-clock-skew" => {
                max_clock_skew = value
                    .parse()
                    .map_err(|_| "invalid --max-clock-skew".to_string())?;
                // Bounded at parse time, matching `VerifierPolicy::new`: a negative
                // skew narrows the window asymmetrically and a skew above the bound
                // stops the freshness gate being a freshness gate. Refused here so the
                // operator learns at the command line, not from a startup failure.
                if !(0..=mcp_re_http_profile::VerifierPolicy::MAX_CLOCK_SKEW_BOUND)
                    .contains(&max_clock_skew)
                {
                    return Err(format!(
                        "--max-clock-skew must be 0..={} seconds (§5.1 bounded skew), got {}",
                        mcp_re_http_profile::VerifierPolicy::MAX_CLOCK_SKEW_BOUND,
                        max_clock_skew
                    ));
                }
            }
            // §4.1 MCP transport contract. Repeatable; each occurrence adds an
            // accepted `Mcp-Protocol-Version`. Absent = no transport contract.
            "--mcp-protocol-version" => mcp_protocol_versions.push(value.clone()),
            "--target-uri" => target_uri = Some(value.clone()),
            "--trust-domain" => trust_domain = Some(value.clone()),
            "--route" => route = Some(value.clone()),
            "--key-source" => {
                key_source = match value.as_str() {
                    "file" => KeySourceKind::File,
                    // Env key material is a dev/CI-only security downgrade (visible to
                    // the process tree). It EXISTS ONLY in a build with the
                    // `dev_env_key_source` feature — a production build has no `env`
                    // option at all, so there is no runtime knob to enable it.
                    #[cfg(feature = "dev_env_key_source")]
                    "env" => KeySourceKind::Env,
                    "pkcs11" => KeySourceKind::Pkcs11,
                    "aws-kms" => KeySourceKind::AwsKms,
                    "gcp-kms" => KeySourceKind::GcpKms,
                    other => {
                        return Err(format!(
                            "unknown --key-source '{other}' (file|pkcs11|aws-kms|gcp-kms)"
                        ))
                    }
                }
            }
            // #4034 PKCS#11 key source.
            "--pkcs11-module" => pkcs11_module = Some(value.clone()),
            // The PIN is read from a FILE, never argv. See `Config::pkcs11_pin_file`.
            "--pkcs11-pin-file" => pkcs11_pin_file = Some(value.clone()),
            // Still recognised, only to REFUSE it with the reason and the replacement.
            // Falling through to "unknown flag" would be a worse error for the one
            // operator who most needs to understand what changed — and worse, it would
            // report a secret-handling decision as a typo. The PIN has already been
            // exposed at this point (it is in this process's argv, which is
            // world-readable): the refusal is about not making it a standing exposure,
            // and the operator should treat that PIN as compromised and change it.
            "--pkcs11-pin" => {
                return Err(
                    "--pkcs11-pin is refused: a process command line is world-readable \
                     (ps, /proc/<pid>/cmdline), so the PIN unlocking the token that holds \
                     the signing keys would be published to every local user for the \
                     lifetime of the process. Use --pkcs11-pin-file <path> with a 0600 \
                     file. Treat any PIN previously passed this way as compromised."
                        .to_string(),
                )
            }
            "--pkcs11-token-label" => pkcs11_token_label = Some(value.clone()),
            "--pkcs11-key-label" => pkcs11_key_label = Some(value.clone()),
            "--pkcs11-tls-key-label" => pkcs11_tls_key_label = Some(value.clone()),
            // ADR-MCPS-028 §B AWS KMS / §C GCP Cloud KMS key-source parameters.
            "--aws-kms-region" => aws_kms_region = Some(value.clone()),
            "--aws-kms-key-id" => aws_kms_key_id = Some(value.clone()),
            "--aws-kms-endpoint" => {
                aws_kms_endpoint = Some(validated_kms_endpoint("--aws-kms-endpoint", value)?)
            }
            "--aws-kms-tls-key-id" => aws_kms_tls_key_id = Some(value.clone()),
            "--gcp-kms-key-version" => gcp_kms_key_version = Some(value.clone()),
            "--gcp-kms-endpoint" => {
                gcp_kms_endpoint = Some(validated_kms_endpoint("--gcp-kms-endpoint", value)?)
            }
            "--gcp-kms-tls-key-version" => gcp_kms_tls_key_version = Some(value.clone()),
            "--signing-key-seed" => signing_key_seed = Some(value.clone()),
            "--tls-cert" => tls_cert = Some(value.clone()),
            "--tls-key" => tls_key = Some(value.clone()),
            "--client-ca" => client_ca = Some(value.clone()),
            // #3839: repeatable and/or comma-separated CRL file paths. An empty
            // segment (e.g. a trailing comma) is rejected so a typo cannot
            // silently load zero CRLs and quietly disable revocation checking.
            "--client-crl" => {
                for segment in value.split(',') {
                    if segment.is_empty() {
                        return Err(format!(
                            "invalid --client-crl '{value}' (empty path segment)"
                        ));
                    }
                    client_crl_paths.push(segment.to_string());
                }
            }
            // ADR-MCPRE-051 §3: stateless HTTP inner backend URL(s) for the async
            // serving path. Comma-separated and/or repeated; empty segment is a hard
            // parse error (fail closed rather than silently drop a backend).
            "--inner-http-url" => {
                for segment in value.split(',') {
                    if segment.is_empty() {
                        return Err(format!(
                            "invalid --inner-http-url '{value}' (empty URL segment)"
                        ));
                    }
                    inner_http_urls.push(segment.to_string());
                }
            }
            // ADR-MCPRE-051 §6 (MCPRE-116): in-process CRL hot-reload cadence. Must
            // be a positive whole number of seconds (0 or unparseable is a hard
            // parse error — fail closed rather than silently disable/spin).
            "--client-crl-reload-secs" => {
                let secs: u64 = value.parse().map_err(|_| {
                    "invalid --client-crl-reload-secs (expected a positive integer)".to_string()
                })?;
                if secs == 0 {
                    return Err("--client-crl-reload-secs must be greater than 0".to_string());
                }
                client_crl_reload_secs = Some(secs);
            }
            "--trust" => trust_path = Some(value.clone()),
            // ADR-MCPS-013: repeatable and/or comma-separated revocation deny-list
            // file paths. An empty segment (e.g. a trailing comma) is rejected so a
            // typo cannot silently load zero ids and quietly disable revocation.
            "--revocation-list" => {
                for segment in value.split(',') {
                    if segment.is_empty() {
                        return Err(format!(
                            "invalid --revocation-list '{value}' (empty path segment)"
                        ));
                    }
                    revocation_list_paths.push(segment.to_string());
                }
            }
            // #4030 online OCSP revocation mode.
            "--client-ocsp" => {
                client_ocsp = match value.as_str() {
                    "off" => OcspKind::Off,
                    "require" => OcspKind::Require,
                    other => return Err(format!("unknown --client-ocsp '{other}' (off|require)")),
                }
            }
            // #4030 AIA-override responder URL. Must be non-empty when present.
            "--ocsp-responder-url" => {
                if value.trim().is_empty() {
                    return Err("--ocsp-responder-url requires a non-empty URL".to_string());
                }
                ocsp_responder_url = Some(value.clone());
            }
            "--replay-cache" => {
                replay = match value.as_str() {
                    "memory" => ReplayKind::Memory,
                    "file" => ReplayKind::File,
                    "shared" => ReplayKind::Shared,
                    other => {
                        return Err(format!(
                            "unknown --replay-cache '{other}' (memory|file|shared)"
                        ))
                    }
                }
            }
            "--replay-path" => replay_path = Some(value.clone()),
            "--admission" => {
                admission = match value.as_str() {
                    "off" => AdmissionKind::Off,
                    "optional" => AdmissionKind::Optional,
                    "required" => AdmissionKind::Required,
                    other => {
                        return Err(format!(
                            "--admission must be off|optional|required, got {other:?}"
                        ))
                    }
                }
            }
            // ADR-MCPS-021 Axis 2: re-read the trust store on a cadence, so removing
            // a compromised request-signer key from `--trust` takes effect without
            // restarting every replica. `0` disables, which is the historical
            // read-once-at-startup posture.
            "--trust-reload-secs" => {
                let secs: u64 = value
                    .parse()
                    .map_err(|_| "invalid --trust-reload-secs".to_string())?;
                trust_reload_secs = (secs > 0).then_some(secs);
            }
            // ADR-MCPS-035: the per-request security record. Without this the
            // emission points exist and nothing consumes them, so a deployment has no
            // per-request attribution at all.
            "--audit-sink" => {
                audit_sink = match value.as_str() {
                    "none" => AuditSinkKind::None,
                    "stderr" => AuditSinkKind::Stderr,
                    other => {
                        return Err(format!("--audit-sink must be none|stderr, got {other:?}"))
                    }
                }
            }
            // #415 rev 2 §10: the verified-context carrier. `trusted` asserts that
            // nothing but this PEP can reach the inner server — the carrier is
            // unsigned, so that assertion is the entire basis for the inner server
            // trusting it, and nothing here can check it.
            "--verified-context-carrier" => {
                verified_context = match value.as_str() {
                    "disabled" => VerifiedContextKind::Disabled,
                    "trusted" => VerifiedContextKind::Trusted,
                    other => {
                        return Err(format!(
                            "--verified-context-carrier must be disabled|trusted, got {other:?}"
                        ))
                    }
                }
            }
            "--admission-authority-kid" => admission_authority_kid = Some(value.clone()),
            "--admission-authority-pubkey" => {
                admission_authority_pubkey_b64url = Some(value.clone())
            }
            "--admission-redis-url" => admission_redis_url = Some(value.clone()),
            "--admission-degraded-bound-secs" => {
                admission_degraded_bound_secs = value.parse().map_err(|_| {
                    format!("--admission-degraded-bound-secs must be an integer, got {value:?}")
                })?
            }
            "--admission-allow-degraded" => {
                admission_allow_degraded = match value.as_str() {
                    "true" => true,
                    "false" => false,
                    other => {
                        return Err(format!(
                            "--admission-allow-degraded must be true|false, got {other:?}"
                        ))
                    }
                }
            }
            "--replay-redis-url" => replay_redis_url = Some(value.clone()),
            "--trust-epoch-redis-url" => trust_epoch_redis_url = Some(value.clone()),
            "--trust-epoch-key" => trust_epoch_key = Some(value.clone()),
            // #69: the CP / etcd endpoint for the LINEARIZABLE durability tier.
            "--cpstore-etcd-endpoint" => {
                if value.trim().is_empty() {
                    return Err(
                        "--cpstore-etcd-endpoint requires a non-empty etcd v3 gateway URL"
                            .to_string(),
                    );
                }
                cpstore_etcd_endpoint = Some(value.clone());
            }
            "--replay-durability-tier" => {
                replay_durability_tier =
                    Some(crate::replay_tier::ReplayDurabilityTier::parse(value)?)
            }
            "--revocation-tier" => {
                revocation_tier = crate::revocation_tier::RevocationTier::parse(value)?
            }
            "--transport-binding" => {
                binding = match value.as_str() {
                    // `exact` binds the request to the verified mTLS peer identity.
                    "exact" => BindingKind::Exact,
                    // ADR-MCPS-023 Tier 3 (issue #71): LB-signed request-bound
                    // ingress assertion. Honestly downgraded — NOT end_to_end_mtls.
                    "lb-assertion" => BindingKind::LbAssertion,
                    // ADR-MCPS-023 §C (v0.10) Mode C: attested ingress. Strict-
                    // ADMITTED, explicit opt-in; still NOT end_to_end_mtls.
                    "attested-ingress" => BindingKind::AttestedIngress,
                    other => {
                        return Err(format!(
                            "unknown --transport-binding '{other}' \
                         (exact|lb-assertion|attested-ingress)"
                        ))
                    }
                }
            }
            // ADR-MCPS-023 Tier 3 (issue #71): a trusted LB verification key for
            // request-bound ingress assertions, as `<keyid>:<base64url-ed25519-pub>`.
            // Repeatable. The key id is the opaque label the assertion stamps; the
            // base64url body MUST decode to a valid 32-byte Ed25519 public key (a
            // malformed key is rejected when the binding is built). An unknown key
            // id in a presented assertion fails closed at verification.
            "--ingress-lb-key" => {
                let (key_id, key_b64) = value.split_once(':').ok_or_else(|| {
                    format!(
                        "invalid --ingress-lb-key '{value}' (expected <keyid>:<base64url-ed25519-pub>)"
                    )
                })?;
                if key_id.is_empty() || key_b64.is_empty() {
                    return Err(format!(
                        "invalid --ingress-lb-key '{value}' (empty key id or key body)"
                    ));
                }
                ingress_lb_keys.push((key_id.to_string(), key_b64.to_string()));
            }
            // ADR-MCPS-023 §C (Mode C): a trusted ingress-ATTESTOR verification key
            // for `mcp-re/lb-ingress-assertion/v2` assertions, as
            // `<keyid>:<base64url-ed25519-pub>`. Repeatable. Same shape as
            // `--ingress-lb-key`, but a DISTINCT flag so a v1 LB key can never be
            // mistaken for a Mode-C attestor key. Malformed body is rejected when the
            // binding is built; an unknown key id fails closed at verification.
            "--ingress-attestor-key" => {
                let (key_id, key_b64) = value.split_once(':').ok_or_else(|| {
                    format!(
                        "invalid --ingress-attestor-key '{value}' \
                         (expected <keyid>:<base64url-ed25519-pub>)"
                    )
                })?;
                if key_id.is_empty() || key_b64.is_empty() {
                    return Err(format!(
                        "invalid --ingress-attestor-key '{value}' (empty key id or key body)"
                    ));
                }
                ingress_attestor_keys.push((key_id.to_string(), key_b64.to_string()));
            }
            // ADR-MCPS-023 §C (Mode C): a trusted ingress identity. Repeatable. A v2
            // assertion whose `ingress_identity` is not in this set fails closed.
            "--ingress-identity" => {
                if value.trim().is_empty() {
                    return Err(
                        "--ingress-identity requires a non-empty ingress identity".to_string()
                    );
                }
                ingress_identities.push(value.clone());
            }
            // ADR-MCPS-023 §C (Mode C): the node's own audience; a v2 assertion's
            // `audience` must equal it (route/audience binding).
            "--ingress-audience" => {
                if value.trim().is_empty() {
                    return Err("--ingress-audience requires a non-empty audience".to_string());
                }
                ingress_audience = Some(value.clone());
            }
            "--transport-identity-source" => {
                identity_source = match value.as_str() {
                    "uri_san" => IdentityPolicy::UriSan,
                    "dns_san" => IdentityPolicy::DnsSan,
                    "cn_legacy" => IdentityPolicy::CnLegacy,
                    other => {
                        return Err(format!(
                        "unknown --transport-identity-source '{other}' (uri_san|dns_san|cn_legacy)"
                    ))
                    }
                }
            }
            "--reverse-proxy-identity-header" => {
                // The trusted forwarded header name. Presence of this flag selects
                // reverse-proxy ingress mode (mTLS terminated upstream).
                if value.trim().is_empty() {
                    return Err(
                        "--reverse-proxy-identity-header requires a non-empty header name"
                            .to_string(),
                    );
                }
                reverse_proxy_identity_header = Some(value.clone());
            }
            "--reverse-proxy-header-format" => {
                reverse_proxy_header_format = match value.as_str() {
                    "plain" => ReverseProxyHeaderFormat::Plain,
                    "xfcc" => ReverseProxyHeaderFormat::Xfcc,
                    other => {
                        return Err(format!(
                            "unknown --reverse-proxy-header-format '{other}' (plain|xfcc)"
                        ))
                    }
                }
            }
            "--authz" => {
                authz = match value.as_str() {
                    "off" => AuthzKind::Off,
                    "reference" => AuthzKind::Reference,
                    other => return Err(format!("unknown --authz '{other}' (off|reference)")),
                }
            }
            "--max-header-bytes" => {
                limits.max_header_bytes = value
                    .parse()
                    .map_err(|_| "invalid --max-header-bytes".to_string())?
            }
            "--max-body-bytes" => {
                limits.max_body_bytes = value
                    .parse()
                    .map_err(|_| "invalid --max-body-bytes".to_string())?
            }
            "--read-timeout-secs" => {
                limits.read_timeout = parse_timeout(value, "--read-timeout-secs")?
            }
            "--request-deadline-secs" => {
                // Aggregate wall-clock deadline over the whole server read phase
                // (handshake + header/body); slow-loris defense, server mirror of
                // mcp-re-transport's DeadlineStream. `0` disables (like the per-socket
                // read timeout knob).
                limits.request_deadline = parse_timeout(value, "--request-deadline-secs")?
            }
            "--write-timeout-secs" => {
                limits.write_timeout = parse_timeout(value, "--write-timeout-secs")?
            }
            "--max-connections" => {
                let n: usize = value
                    .parse()
                    .map_err(|_| "invalid --max-connections".to_string())?;
                if n == 0 {
                    return Err("--max-connections must be > 0".to_string());
                }
                limits.max_concurrent_connections = n;
            }
            // MCPRE-114: bounded per-request ADMISSION control. A ceiling always
            // applies — `ServerLimits::default()` carries a per-core one — because
            // without it a single client holding a valid mTLS certificate drives
            // unbounded concurrent work, each request buffering up to
            // --max-body-bytes BEFORE the verify gate. `--max-in-flight` overrides the
            // per-core ceiling directly; `--max-in-flight-total` sets a fleet-wide
            // target that async_fleet divides evenly across cores (lock-free: each
            // core enforces only its own share). An EXPLICIT per-core ceiling wins.
            "--max-in-flight" => {
                let n: usize = value
                    .parse()
                    .map_err(|_| "invalid --max-in-flight".to_string())?;
                if n == 0 {
                    return Err("--max-in-flight must be > 0; there is no \"no ceiling\" \
                                setting, because unbounded in-flight requests are \
                                attacker-controlled buffering ahead of the verify gate"
                        .to_string());
                }
                limits.max_in_flight_requests = Some(n);
                max_in_flight_explicit = true;
            }
            // MCPRE-116 / ADR-MCPS-023 §A1: how long one mTLS connection may serve
            // before it is gracefully closed and the peer must re-handshake. The
            // client-cert chain, its CRL status and its validity window are checked at
            // the handshake and NOWHERE else, so this is what bounds revocation
            // latency for a peer that simply keeps its connection open.
            "--max-connection-age-secs" => {
                limits.max_connection_age = parse_timeout(value, "--max-connection-age-secs")?;
            }
            // MCPRE-115 (ADR-MCPRE-051 §6): the bounded drain window. Exposed because
            // the k8s side of the invariant
            // (`request_deadline <= drain_grace < terminationGracePeriodSeconds`,
            // minus any preStop delay) cannot be satisfied from the chart alone while
            // this value is a hardcoded constant.
            "--drain-grace-secs" => {
                let secs: u64 = value
                    .parse()
                    .map_err(|_| "invalid --drain-grace-secs".to_string())?;
                if secs == 0 {
                    return Err("--drain-grace-secs must be > 0: a zero drain window \
                                abandons every in-flight request on SIGTERM"
                        .to_string());
                }
                limits.drain_grace = Duration::from_secs(secs);
            }
            "--max-in-flight-total" => {
                let n: usize = value
                    .parse()
                    .map_err(|_| "invalid --max-in-flight-total".to_string())?;
                if n == 0 {
                    return Err(
                        "--max-in-flight-total must be > 0 (omit it to keep the per-core \
                         default ceiling)"
                            .to_string(),
                    );
                }
                max_in_flight_total = Some(n);
            }
            "--max-client-cert-lifetime" => max_client_cert_lifetime = parse_cert_lifetime(value)?,
            "--cores" => {
                // ADR-MCPRE-051 §1: pin the per-core worker count. `0` = auto (one
                // per core). An explicit count makes the 1→N linear-scaling
                // benchmark reproducible and can cap workers below the core count.
                cores = value.parse().map_err(|_| {
                    "invalid --cores (expected a non-negative integer; 0 = auto)".to_string()
                })?;
            }
            // ADR-MCPRE-052 §4 delegated-key TTL `T` (seconds).
            "--delegated-ttl-secs" => {
                delegated_ttl_secs = Some(value.parse().map_err(|_| {
                    "invalid --delegated-ttl-secs (expected a positive integer)".to_string()
                })?);
            }
            // ADR-MCPRE-052 §4 rotation-overlap window `O` (seconds; 0 < O < T).
            "--delegated-overlap-secs" => {
                delegated_overlap_secs = Some(value.parse().map_err(|_| {
                    "invalid --delegated-overlap-secs (expected a positive integer)".to_string()
                })?);
            }
            // ADR-MCPRE-052 §7 trust epoch minted into every credential (the hard
            // gate). Required under delegated-required; coordinated with verifiers.
            "--delegated-trust-epoch" => {
                if value.trim().is_empty() {
                    return Err("--delegated-trust-epoch requires a non-empty epoch".to_string());
                }
                delegated_trust_epoch = Some(value.clone());
            }
            // ADR-MCPRE-052: the root issuer key id the credential chains to. Defaults
            // to --server-key-id.
            "--delegated-issuer-kid" => {
                if value.trim().is_empty() {
                    return Err("--delegated-issuer-kid requires a non-empty key id".to_string());
                }
                delegated_issuer_kid = Some(value.clone());
            }
            // ADR-MCPRE-052: the audience-scope hash the delegated key is scoped to.
            // Defaults to --audience.
            "--delegated-audience-hash" => {
                if value.trim().is_empty() {
                    return Err("--delegated-audience-hash requires a non-empty value".to_string());
                }
                delegated_audience_hash = Some(value.clone());
            }
            other => return Err(format!("unknown flag {other}")),
        }
        i += 2;
    }

    // A fleet-wide target divides across cores only when no explicit per-core ceiling
    // was given (`derived_per_core_ceiling`). Clearing the DEFAULT here is what keeps
    // that contract: without it the built-in per-core value would silently win over an
    // operator's `--max-in-flight-total`.
    if max_in_flight_total.is_some() && !max_in_flight_explicit {
        limits.max_in_flight_requests = None;
    }

    let require =
        |opt: Option<String>, name: &str| opt.ok_or_else(|| format!("missing required {name}"));
    if replay == ReplayKind::File && replay_path.is_none() {
        return Err("--replay-cache file requires --replay-path".to_string());
    }
    // MCPRE-493: enforcing admission needs BOTH an authority to verify assertions
    // against and a source to check currency against. With neither, the gate would
    // verify nothing while looking enabled — the most dangerous of the three states,
    // because the deployment believes it has admission control.
    if admission != AdmissionKind::Off {
        if admission_authority_kid.is_none() || admission_authority_pubkey_b64url.is_none() {
            return Err("--admission optional|required requires \
                        --admission-authority-kid and --admission-authority-pubkey \
                        (an assertion is only evidence if the issuer is one this \
                        deployment trusts)"
                .to_string());
        }
        if admission_redis_url.is_none() {
            return Err(
                "--admission optional|required requires --admission-redis-url \
                        (the shared authoritative record; without it every call fails \
                        closed on an unreachable authority)"
                    .to_string(),
            );
        }
    }
    // A degraded window of zero is not a window: it would fail closed on every
    // unreachable-authority call while claiming a degraded mode is available.
    if admission_allow_degraded && admission_degraded_bound_secs <= 0 {
        return Err("--admission-allow-degraded true requires a positive \
                    --admission-degraded-bound-secs (P); degraded mode is a BOUNDED \
                    window, and an unbounded or zero one is not a policy"
            .to_string());
    }
    if admission == AdmissionKind::Off
        && (admission_redis_url.is_some() || admission_authority_kid.is_some())
    {
        // A dangling admission setting reads as "admission is configured" to anyone
        // auditing the command line, while nothing is enforced.
        return Err(
            "--admission-authority-kid / --admission-redis-url are set but \
                    --admission is off; enable it or remove them"
                .to_string(),
        );
    }
    // ADR-MCPS-020: the durability tier is an explicit deployment assertion that
    // determines the horizontal replay-safety claim, so a shared store MUST
    // declare it (fail closed rather than assume a tier). Checked BEFORE the
    // backend-endpoint requirement, because the declared tier decides WHICH
    // backend endpoint is required.
    if replay == ReplayKind::Shared && replay_durability_tier.is_none() {
        return Err("--replay-cache shared requires --replay-durability-tier \
                    (redis-async | redis-wait-quorum:<quorum>:<timeout_ms> | linearizable | \
                    single-store-fail-closed)"
            .to_string());
    }
    // #69 (epic #68 v0.4 Axis 1): the declared tier selects the backend, which
    // selects the required endpoint. The LINEARIZABLE tier needs a CP / linearizable
    // store (etcd), so it requires `--cpstore-etcd-endpoint`; every other (Redis)
    // tier requires `--replay-redis-url`. Selecting LINEARIZABLE WITHOUT the etcd
    // endpoint is a HARD config-construction error here — NEVER a silent downgrade
    // to Redis / in-memory (ADR-MCPS-020 fail-closed).
    let tier_is_linearizable = matches!(
        replay_durability_tier,
        Some(crate::replay_tier::ReplayDurabilityTier::Linearizable)
    );
    if replay == ReplayKind::Shared {
        if tier_is_linearizable {
            if cpstore_etcd_endpoint.is_none() {
                return Err(
                    "--replay-durability-tier linearizable requires a CP/linearizable store \
                     endpoint: --cpstore-etcd-endpoint <http://host:2379> (the LINEARIZABLE \
                     claim is forbidden without a configured CPStore; it is NEVER silently \
                     downgraded to Redis or in-memory)"
                        .to_string(),
                );
            }
        } else if replay_redis_url.is_none() {
            return Err("--replay-cache shared requires --replay-redis-url".to_string());
        }
    }
    // A `--cpstore-etcd-endpoint` set for any non-LINEARIZABLE configuration would
    // silently do nothing (a false belief that a CP store is in force), so reject it
    // (fail closed) — mirrors the dangling `--ocsp-responder-url` / KMS-TLS guards.
    if cpstore_etcd_endpoint.is_some() && !(replay == ReplayKind::Shared && tier_is_linearizable) {
        return Err("--cpstore-etcd-endpoint has no effect without \
             --replay-cache shared --replay-durability-tier linearizable"
            .to_string());
    }
    // EnvKeySource is a dev/CI-only downgrade and is compiled in ONLY under the
    // `dev_env_key_source` feature; a production build cannot even parse
    // `--key-source env` (the match arm does not exist), so no runtime ack is needed
    // — the build feature IS the acknowledgement.
    // #4034 PKCS#11 key source: the module path, User PIN, token label, and
    // signing-key object label are all required when this source is selected.
    // Each is checked here (not in build_key_source) so a missing flag is a clear
    // parse error regardless of which feature the binary was built with.
    if key_source == KeySourceKind::Pkcs11 {
        if pkcs11_module.is_none() {
            return Err("--key-source pkcs11 requires --pkcs11-module <path>".to_string());
        }
        if pkcs11_pin_file.is_none() {
            return Err(
                "--key-source pkcs11 requires --pkcs11-pin-file <path>; the User PIN is \
                 never accepted on argv, which is world-readable via ps and \
                 /proc/<pid>/cmdline"
                    .to_string(),
            );
        }
        if pkcs11_token_label.is_none() {
            return Err("--key-source pkcs11 requires --pkcs11-token-label <label>".to_string());
        }
        if pkcs11_key_label.is_none() {
            return Err("--key-source pkcs11 requires --pkcs11-key-label <label>".to_string());
        }
    }
    // #59: the TLS-key label selects the SEPARATE token object that custodies the
    // TLS key. It only has meaning for the PKCS#11 source; a dangling label on any
    // other source would silently do nothing (a false belief that the TLS key is
    // token-resident), so reject it (fail closed).
    if pkcs11_tls_key_label.is_some() && key_source != KeySourceKind::Pkcs11 {
        return Err("--pkcs11-tls-key-label has no effect without --key-source pkcs11".to_string());
    }
    // ADR-MCPS-028 §B AWS KMS: region + key id are required when this source is
    // selected (credentials come from AWS_* env vars; the endpoint is optional).
    // Checked here so a missing flag is a clear parse error regardless of feature.
    if key_source == KeySourceKind::AwsKms {
        if aws_kms_region.is_none() {
            return Err("--key-source aws-kms requires --aws-kms-region <region>".to_string());
        }
        if aws_kms_key_id.is_none() {
            return Err(
                "--key-source aws-kms requires --aws-kms-key-id <key-id|arn|alias>".to_string(),
            );
        }
    }
    // #60: the TLS-key id selects the SEPARATE KMS key that custodies the TLS key.
    // It only has meaning for the AWS KMS source; a dangling id on any other source
    // would silently do nothing (a false belief that the TLS key is KMS-resident),
    // so reject it (fail closed) — mirrors the `--pkcs11-tls-key-label` guard.
    if aws_kms_tls_key_id.is_some() && key_source != KeySourceKind::AwsKms {
        return Err("--aws-kms-tls-key-id has no effect without --key-source aws-kms".to_string());
    }
    // ADR-MCPS-028 §C GCP Cloud KMS: the key-version resource path is required.
    if key_source == KeySourceKind::GcpKms && gcp_kms_key_version.is_none() {
        return Err("--key-source gcp-kms requires --gcp-kms-key-version \
             <projects/.../cryptoKeyVersions/N>"
            .to_string());
    }
    // #61: the TLS-key-version selects the SEPARATE Cloud KMS key version that
    // custodies the TLS key. It only has meaning for the GCP KMS source; a dangling
    // version on any other source would silently do nothing (a false belief that the
    // TLS key is KMS-resident), so reject it (fail closed) — mirrors the
    // `--aws-kms-tls-key-id` / `--pkcs11-tls-key-label` guards.
    if gcp_kms_tls_key_version.is_some() && key_source != KeySourceKind::GcpKms {
        return Err(
            "--gcp-kms-tls-key-version has no effect without --key-source gcp-kms".to_string(),
        );
    }
    // The metadata-server flag only has meaning for the GCP KMS source; a dangling
    // `--gcp-kms-use-metadata` would silently do nothing, so reject it.
    if gcp_kms_use_metadata && key_source != KeySourceKind::GcpKms {
        return Err(
            "--gcp-kms-use-metadata has no effect without --key-source gcp-kms".to_string(),
        );
    }
    // ADR-MCPRE-051 §3: the async serving path forwards verified requests over the
    // pooled HttpInnerPool to one or more stateless HTTP inner backends, so at least
    // one `--inner-http-url` MUST be configured (fail closed rather than start with
    // no inner plane).
    if inner_http_urls.is_empty() {
        return Err(
            "missing required inner server: --inner-http-url <url> (async HTTP inner plane)"
                .to_string(),
        );
    }

    // MCPS-3840 reverse-proxy ingress: identity comes EITHER from a locally-
    // terminated client certificate OR from a trusted forwarded header, never
    // both (the two identity sources are mutually exclusive). When the header
    // strategy is selected, the proxy does NOT extract identity from a local
    // client cert, so a configured local client-cert-lifetime enforcement is
    // contradictory (there is no local client cert to bound). Require it be
    // explicitly disabled (`--max-client-cert-lifetime none`) so the operator
    // cannot believe a local-cert control is in force when it is not.
    if reverse_proxy_identity_header.is_some() && max_client_cert_lifetime.is_some() {
        return Err(
            "--reverse-proxy-identity-header terminates mTLS UPSTREAM, so the local \
             client-certificate identity path is disabled and a local \
             --max-client-cert-lifetime cannot be enforced; pass \
             --max-client-cert-lifetime none to acknowledge that local client-cert \
             controls do not apply in reverse-proxy mode"
                .to_string(),
        );
    }

    // ADR-MCPS-023 Tier 3 (issue #71): LB-signed request-bound ingress assertion.
    // Fail CLOSED at the CLI trust boundary so the operator can never believe a
    // request-binding control is in force when it is not.
    //
    // (a) Dangling `--ingress-lb-key` without `--transport-binding lb-assertion`
    //     would SILENTLY do nothing (an illusion of request-bound ingress). Reject
    //     it — mirrors the OCSP/reverse-proxy dangling-flag guards.
    if !ingress_lb_keys.is_empty() && binding != BindingKind::LbAssertion {
        return Err(
            "--ingress-lb-key has no effect without --transport-binding lb-assertion".to_string(),
        );
    }
    // (b) `lb-assertion` binding with NO trusted LB key can never verify any
    //     assertion — it would reject every request. Require at least one key.
    if binding == BindingKind::LbAssertion && ingress_lb_keys.is_empty() {
        return Err(
            "--transport-binding lb-assertion requires at least one --ingress-lb-key \
             <keyid>:<base64url-ed25519-pub> (the trusted LB verification key)"
                .to_string(),
        );
    }
    // (c) Each configured LB key must be a valid base64url 32-byte Ed25519 public
    //     key, and key ids must be unique — a malformed key or duplicate id is a
    //     misconfiguration, rejected at parse time rather than at first request.
    {
        let mut seen_ids: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for (key_id, key_b64) in &ingress_lb_keys {
            if !seen_ids.insert(key_id.as_str()) {
                return Err(format!(
                    "duplicate --ingress-lb-key id '{key_id}' (each LB key id must be unique)"
                ));
            }
            if mcp_re_core::VerificationKey::from_b64url(key_b64).is_err() {
                return Err(format!(
                    "invalid --ingress-lb-key '{key_id}': the body must be a base64url-no-pad \
                     32-byte Ed25519 public key"
                ));
            }
        }
    }

    // ADR-MCPS-023 §C (v0.10) Mode C attested ingress — fail CLOSED at the CLI trust
    // boundary so an operator can never believe an attested-ingress control is in
    // force when a piece of it is missing. Mode C is strict-ADMITTED but ONLY when
    // fully configured: attestor keys, trusted ingress identities, the expected
    // audience, and the explicit pinned-mTLS acknowledgement.
    //
    // (a) The Mode-C flags SILENTLY do nothing outside `attested-ingress` — reject
    //     dangling ones (mirrors the `--ingress-lb-key` dangling guard).
    if binding != BindingKind::AttestedIngress {
        if !ingress_attestor_keys.is_empty() {
            return Err(
                "--ingress-attestor-key has no effect without --transport-binding attested-ingress"
                    .to_string(),
            );
        }
        if !ingress_identities.is_empty() {
            return Err(
                "--ingress-identity has no effect without --transport-binding attested-ingress"
                    .to_string(),
            );
        }
        if ingress_audience.is_some() {
            return Err(
                "--ingress-audience has no effect without --transport-binding attested-ingress"
                    .to_string(),
            );
        }
        if ingress_pinned_mtls {
            return Err(
                "--ingress-pinned-mtls has no effect without --transport-binding attested-ingress"
                    .to_string(),
            );
        }
    } else {
        // (b) attested-ingress with NO trusted attestor key can never verify any
        //     assertion — it would reject every request. Require at least one.
        if ingress_attestor_keys.is_empty() {
            return Err(
                "--transport-binding attested-ingress requires at least one \
                 --ingress-attestor-key <keyid>:<base64url-ed25519-pub> (the trusted \
                 ingress-attestor verification key)"
                    .to_string(),
            );
        }
        // (c) attested-ingress with NO trusted ingress identity would reject every
        //     assertion — require at least one.
        if ingress_identities.is_empty() {
            return Err(
                "--transport-binding attested-ingress requires at least one \
                 --ingress-identity <id> (a trusted ingress identity)"
                    .to_string(),
            );
        }
        // (d) attested-ingress binds the assertion's audience to the node's own — it
        //     must be configured.
        if ingress_audience.is_none() {
            return Err(
                "--transport-binding attested-ingress requires --ingress-audience <aud> \
                 (the node's expected assertion audience/route)"
                    .to_string(),
            );
        }
        // (e) The pinned attestor→node channel (§C2) is load-bearing: without the
        //     explicit `--ingress-pinned-mtls` acknowledgement, attested ingress
        //     refuses to start (fail closed) — an attested-ingress posture must never
        //     run without the pinned backend channel it depends on.
        if !ingress_pinned_mtls {
            return Err(
                "--transport-binding attested-ingress requires --ingress-pinned-mtls: the \
                 attestor→node hop MUST be a pinned mTLS channel (ADR-MCPS-023 §C2); \
                 acknowledge it explicitly or do not enable attested ingress"
                    .to_string(),
            );
        }
        // (f) Mode C resolves identity from the signed v2 assertion, so a trusted
        //     reverse-proxy identity header would be a second, silently-ignored
        //     identity source — reject the combination.
        if reverse_proxy_identity_header.is_some() {
            return Err(
                "--transport-binding attested-ingress resolves identity from the signed v2 \
                 assertion and is mutually exclusive with --reverse-proxy-identity-header"
                    .to_string(),
            );
        }
        // (g) Each attestor key must be a valid base64url 32-byte Ed25519 public key,
        //     and key ids must be unique.
        let mut seen_ids: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for (key_id, key_b64) in &ingress_attestor_keys {
            if !seen_ids.insert(key_id.as_str()) {
                return Err(format!(
                    "duplicate --ingress-attestor-key id '{key_id}' (each attestor key id \
                     must be unique)"
                ));
            }
            if mcp_re_core::VerificationKey::from_b64url(key_b64).is_err() {
                return Err(format!(
                    "invalid --ingress-attestor-key '{key_id}': the body must be a \
                     base64url-no-pad 32-byte Ed25519 public key"
                ));
            }
        }
    }

    // #4063 (MCPS-088) online-OCSP gating — fail CLOSED at the CLI trust boundary.
    // These arms ensure an operator can never believe an OCSP control is in force
    // when it is not, and that `require` is rejected outright in a build that
    // cannot perform the verified online check.
    //
    // (a) The OCSP knobs are only honored under `--client-ocsp require`. A dangling
    //     `--ocsp-responder-url` without it would SILENTLY do nothing — a dangerous
    //     illusion of a revocation posture — so it is a hard error. (Online OCSP
    //     ALWAYS hard-fails on an indeterminate result; there is no soft-fail knob.)
    if client_ocsp != OcspKind::Require && ocsp_responder_url.is_some() {
        return Err("--ocsp-responder-url has no effect without --client-ocsp require".to_string());
    }
    // (b) `--client-ocsp require` is refused unconditionally: the online-OCSP check is
    //     unreachable on the serving path. `ocsp_rejection` is called only from
    //     `connection_rejection`, which only the blocking serve loops use; the
    //     production data plane is the per-core async fleet (ADR-MCPRE-051 §1), which
    //     calls `connection_rejection_for_leaf` and performs only the cert-lifetime
    //     check. Accepting `require` would print "ONLINE OCSP client-cert revocation
    //     enabled" at startup while admitting every revoked client certificate — the
    //     forbidden-claim shape (security-boundary §2). This holds with OR without the
    //     `online_ocsp` feature: without it the code is absent, with it the code is
    //     present but never called. Refused until the async path carries the full peer
    //     chain and performs the responder round-trip off the runtime worker.
    if client_ocsp == OcspKind::Require {
        return Err(
            "--client-ocsp require cannot be honored: online OCSP is implemented only on \
             the blocking serve loop, while the production data plane is the per-core \
             async fleet, which performs no OCSP revocation check. Accepting it would \
             announce enforcement that does not happen. Use --client-crl (with \
             --client-crl-reload-secs for restart-free refresh) for client-certificate \
             revocation on the async serving path."
                .to_string(),
        );
    }
    // (c) Under the feature, OCSP checks the LOCALLY-terminated client cert, which
    //     does not exist in reverse-proxy (forwarded-header) ingress mode.
    #[cfg(feature = "online_ocsp")]
    if client_ocsp == OcspKind::Require && reverse_proxy_identity_header.is_some() {
        return Err(
            "--client-ocsp require checks the locally-terminated client certificate, \
             which is absent in reverse-proxy mode (--reverse-proxy-identity-header); \
             online OCSP cannot apply there"
                .to_string(),
        );
    }

    // ADR-MCPS-028 §G / issue #58+#59+#60+#61: a source's TLS key is EITHER delegated
    // to a non-exporting device/KMS XOR exported from a file — never both. The
    // delegated selectors are `--pkcs11-tls-key-label` (#59, token-resident),
    // `--aws-kms-tls-key-id` (#60, AWS-KMS-resident) and `--gcp-kms-tls-key-version`
    // (#61, Cloud-KMS-resident); any makes the TLS key non-exporting, so an exported
    // `--tls-key` alongside it is contradictory (the operator would believe the key
    // never leaves the device while a file copy also exists) and fails closed here,
    // before the proxy is constructed.
    let has_delegated_tls = pkcs11_tls_key_label.is_some()
        || aws_kms_tls_key_id.is_some()
        || gcp_kms_tls_key_version.is_some();
    let has_exported_tls_key = tls_key.is_some();
    validate_tls_signing_exclusivity(has_delegated_tls, has_exported_tls_key)?;

    // MCPS-84: a networked trust-epoch backend is only consumed by the Push
    // revocation tier. Reject (not silently ignore) a `--trust-epoch-redis-url`
    // paired with any other tier, so the operator does not believe a networked
    // trust invalidation is active when it is inert.
    if trust_epoch_redis_url.is_some()
        && !matches!(
            revocation_tier,
            crate::revocation_tier::RevocationTier::Push { .. }
        )
    {
        return Err(
            "--trust-epoch-redis-url requires --revocation-tier push:<T> (the trust-epoch source \
             drives the ADR-021 Tier-3 push cache; it is inert under any other tier)"
                .to_string(),
        );
    }

    // ADR-MCPRE-052 (MCPRE-122): delegated-signing is the ONLY response-signing mode.
    // Fail CLOSED at the CLI trust boundary — the trust epoch is required and the
    // rotation window must be sane, for every deployment.
    let (delegated_ttl_secs_final, delegated_overlap_secs_final) = {
        // (a) The trust epoch is the ADR-MCPRE-052 §7 hard gate; a verifier admits
        //     only credentials whose epoch is in its accepted set, so it MUST be
        //     supplied explicitly (no silent default that verifiers would reject).
        if delegated_trust_epoch.is_none() {
            return Err(
                "--delegated-trust-epoch <epoch> is required (the trust epoch minted into every \
                 delegation credential; it must be coordinated with verifiers — ADR-MCPRE-052 §7)"
                    .to_string(),
            );
        }
        // (b) TTL and overlap must satisfy 0 < overlap < ttl so the rotor mints a
        //     successor before the predecessor expires (no signing gap).
        let ttl = delegated_ttl_secs.unwrap_or(300);
        let overlap = delegated_overlap_secs.unwrap_or(60);
        if ttl <= 0 {
            return Err("--delegated-ttl-secs must be greater than 0".to_string());
        }
        if overlap <= 0 || overlap >= ttl {
            return Err(format!(
                "--delegated-overlap-secs must satisfy 0 < overlap < ttl (got overlap={overlap}, \
                 ttl={ttl})"
            ));
        }
        (ttl, overlap)
    };

    let config = Config {
        bind: require(bind, "--bind")?,
        audience: require(audience, "--audience")?,
        server_signer: require(server_signer, "--server-signer")?,
        server_key_id: require(server_key_id, "--server-key-id")?,
        max_clock_skew,
        mcp_protocol_versions,
        // The RFC 9421 `@target-uri` binding (ADR-MCPRE-050). REQUIRED and non-empty:
        // an empty target makes both sides of the audience/target conjunction the same
        // empty string, so the dispatch-boundary binding degrades to a tautology and
        // two deployments sharing an `--audience` become indistinguishable to the
        // verifier. Refused here rather than served as a binding that binds nothing.
        target_uri: {
            let uri = require(target_uri, "--target-uri")?;
            if uri.trim().is_empty() {
                return Err(
                    "--target-uri must not be empty: an empty target makes the audience/target \
                     binding a tautology (both sides compare equal) instead of binding this \
                     deployment's dispatch boundary"
                        .to_string(),
                );
            }
            // ABSOLUTE form is required, and this is the check `async_serve`'s
            // `origin_form_of` says already exists. It did not: a relative or
            // scheme-less target (`/mcp`, `host/mcp`) yields no origin form, which
            // makes the received-vs-configured path comparison return "consistent"
            // for every request and disables the reconstruction check silently. The
            // verifier's own audience comparison cannot catch it either — both sides
            // are the same configured string.
            if !uri.contains("://") {
                return Err(format!(
                    "--target-uri {uri:?} is not an absolute URI: it must be \
                     <scheme>://<authority><path> (e.g. https://proxy.internal:8600/mcp). \
                     A scheme-less target disables the request-target reconstruction check \
                     entirely, so an ingress fanning several paths into one process would \
                     verify signatures over a @target-uri the request never arrived at"
                ));
            }
            uri
        },
        // REQUIRED. It used to default to the placeholder `example.com`, which the
        // Helm chart refuses outright as a shared-identity hazard — so the binary
        // silently accepted the one value the chart exists to reject, and a
        // hand-rolled or scripted deployment inherited an identity coordinate shared
        // with every other install that also never set it.
        trust_domain: {
            let value = require(trust_domain, "--trust-domain")?;
            if value.trim().is_empty() {
                return Err("--trust-domain must not be empty".to_string());
            }
            value
        },
        route,
        key_source,
        // Required only where the seed is actually READ. Under a non-exporting
        // custody (PKCS#11 / AWS KMS / GCP KMS) the response-signing key never leaves
        // the device, and those sources thread this path only into the FileKeySource
        // they use for TLS material — the seed accessor is never called. Requiring it
        // there made every operator provision an Ed25519 root seed into every pod in
        // exactly the mode chosen because no key should land in the pod, so a
        // deployment's most sensitive file existed only to satisfy an argument parser.
        // An explicitly-supplied path is still accepted and still permission-checked.
        signing_key_seed: match key_source {
            KeySourceKind::File | KeySourceKind::Env => {
                require(signing_key_seed, "--signing-key-seed")?
            }
            KeySourceKind::Pkcs11 | KeySourceKind::AwsKms | KeySourceKind::GcpKms => {
                signing_key_seed.unwrap_or_default()
            }
        },
        tls_cert: require(tls_cert, "--tls-cert")?,
        // #59: on the DELEGATED TLS path the TLS key is token-resident and never
        // read from disk, so an exported `--tls-key` is not merely optional — it is
        // forbidden (the exclusivity guard above rejected it). The path is therefore
        // unused; default it to empty rather than requiring a file that must not be
        // consulted. On the non-delegated path `--tls-key` stays required.
        tls_key: if has_delegated_tls {
            tls_key.unwrap_or_default()
        } else {
            require(tls_key, "--tls-key")?
        },
        client_ca: require(client_ca, "--client-ca")?,
        client_crl_paths,
        inner_http_urls,
        cores,
        max_in_flight_total,
        client_crl_reload_secs,
        client_ocsp,
        ocsp_responder_url,
        trust_path: require(trust_path, "--trust")?,
        replay,
        replay_path,
        admission,
        admission_authority_kid,
        admission_authority_pubkey_b64url,
        admission_redis_url,
        admission_degraded_bound_secs,
        admission_allow_degraded,
        trust_reload_secs,
        audit_sink,
        verified_context,
        replay_redis_url,
        trust_epoch_redis_url,
        trust_epoch_key,
        cpstore_etcd_endpoint,
        replay_durability_tier,
        revocation_tier,
        binding,
        identity_source,
        reverse_proxy_identity_header,
        reverse_proxy_header_format,
        ingress_lb_keys,
        ingress_attestor_keys,
        ingress_identities,
        ingress_audience,
        ingress_pinned_mtls,
        authz,
        revocation_list_paths,
        pkcs11_module,
        pkcs11_pin_file,
        pkcs11_token_label,
        pkcs11_key_label,
        pkcs11_tls_key_label,
        aws_kms_region,
        aws_kms_key_id,
        allow_group_readable_key_files,
        aws_kms_endpoint,
        aws_kms_tls_key_id,
        gcp_kms_key_version,
        gcp_kms_endpoint,
        gcp_kms_tls_key_version,
        gcp_kms_use_metadata,
        limits,
        max_client_cert_lifetime,
        fleet,
        delegated_ttl_secs: delegated_ttl_secs_final,
        delegated_overlap_secs: delegated_overlap_secs_final,
        delegated_trust_epoch,
        delegated_issuer_kid,
        delegated_audience_hash,
    };

    // ADR-MCPS-013: the reference signed-authorization profile is a real,
    // signature-verifying profile, but it is a CONFORMANCE/reference implementation,
    // NOT the long-term production authority (Biscuit is the intended first serious
    // external profile). It is never accepted as the sole production authorization
    // authority — there is no ack to override this. Until a production authz profile
    // lands, run with `--authz off`.
    if config.authz == AuthzKind::Reference {
        return Err(
            "--authz reference selects the reference/conformance signed-authorization \
             profile, which is NOT accepted as the production authorization authority \
             (ADR-MCPS-013; Biscuit is the intended production profile). Run --authz off \
             until a production authorization profile is available."
                .to_string(),
        );
    }

    // ADR-MCPS-013: the policy-layer deny-list is consumed by the authorization layer
    // (`LiveTrustResolver::resolve_with_revocation_id`), which only runs under an authz
    // profile. `--authz reference` is refused just above and no production profile has
    // landed, so authz is `Off` in every parseable config and a supplied deny-list
    // could only be silently ignored — an operator would believe a compromised grant
    // was revoked while it kept being authorized. Refused rather than accepted-and-
    // ignored (security-boundary §2: never surface a capability that is not delivered).
    if !config.revocation_list_paths.is_empty() {
        return Err(
            "--revocation-list supplies a policy-layer deny-list (ADR-MCPS-013), but it is \
             consulted only by an authorization profile and no production profile is \
             available (--authz is always off), so the list would enforce NOTHING. Remove \
             --revocation-list; use the trust store and --revocation-tier for key \
             revocation on the request path."
                .to_string(),
        );
    }

    // The proxy ALWAYS runs the maximal-security posture — there is no toggle. Any
    // unsafe configuration is refused at parse time (never merely warned). The
    // decision lives in the pure [`unsafe_config_violations`] helper so it is
    // black-box testable and shared with `main.rs` (which adds the filesystem-
    // dependent key-file-permission check). The proxy never even constructs when a
    // parse-time violation is present.
    let violations = unsafe_config_violations(&config);
    if !violations.is_empty() {
        return Err(format!(
            "mcp-re-proxy refuses unsafe configuration:\n  - {}",
            violations.join("\n  - ")
        ));
    }

    Ok(config)
}

/// Enforce the delegated-XOR-exported TLS-signing rule (ADR-MCPS-028 §G, issue
/// #58): a source's TLS handshake key is EITHER delegated to a non-exporting
/// device/KMS (`has_delegated_tls`) OR exported from a file (`has_exported_tls_key`),
/// never both. A source that asserts both is contradictory — the operator could
/// believe the key never leaves the device while a file copy also exists — so this
/// FAILS CLOSED at parse time, before the proxy is constructed.
///
/// Pure and black-box-testable (no `Config`, no IO). The backend issues (#59–#61)
/// drive `has_delegated_tls` from their CLI flag; #58 wires the call with the
/// current values so the seam is exercised, not dead code.
pub fn validate_tls_signing_exclusivity(
    has_delegated_tls: bool,
    has_exported_tls_key: bool,
) -> Result<(), String> {
    if has_delegated_tls && has_exported_tls_key {
        return Err(
            "TLS signing is delegated XOR exported (ADR-MCPS-028 §G): a delegated-TLS \
             key source must not also be given an exported --tls-key. Remove --tls-key \
             when using a delegated (non-exporting device/KMS) TLS signer."
                .to_string(),
        );
    }
    Ok(())
}

/// The ceiling on `--max-client-cert-lifetime` (ADR-MCPS-023 §A1, MCPS-57). A
/// lifetime above this cannot honestly be audited as `short_lived_cert`, so the
/// proxy rejects it. Matches the 1h default. Exported so test fixtures mint client
/// certs whose validity window is within the SAME bound the proxy enforces — there
/// is one source of truth, not a hand-picked magic number per fixture.
pub const MAX_CLIENT_CERT_LIFETIME: Duration = Duration::from_secs(3600);

/// Collect the parse-time unsafe-configuration violations for `config`.
///
/// The proxy has NO security toggle — it always runs the maximal-security posture,
/// so this is applied unconditionally. This is the pure, black-box-testable core:
/// each returned string names the offending flag and how to fix it. It covers ONLY
/// the conditions knowable from the parsed [`Config`] — the group/world-readable
/// key-file check is filesystem-dependent and lives in `main.rs` (which reads the
/// file mode and reuses the same fail-closed posture).
///
/// ADR-MCPS-023 §A1 (v0.9, MCPS-57): a `--max-client-cert-lifetime` GREATER than
/// [`MAX_CLIENT_CERT_LIFETIME`] is rejected. Mode-A's entire certificate-revocation
/// posture is short-lived certificates (on GCP the online-OCSP path is a no-op and
/// CAS is CRL-only), so a long-lived cert cannot honestly be audited as
/// `short_lived_cert`. DISABLED enforcement (`none`/`0`, i.e.
/// `max_client_cert_lifetime == None`) is likewise rejected.
///
/// The postures rejected here are the pure-config, platform-independent fail-open
/// ones: reverse-proxy header ingress (M10/M22), a non-durable/weak replay tier
/// (#90/ADR-MCPS-020), lb-assertion binding, and cn_legacy identity.
pub fn unsafe_config_violations(config: &Config) -> Vec<String> {
    let mut violations = Vec::new();
    // ADR-MCPS-023 §A1 (MCPS-57): `None` disables enforcement outright; a lifetime
    // above the ceiling would let a NOT-short-lived cert be audited as
    // `short_lived_cert`. Both fail closed.
    match config.max_client_cert_lifetime {
        None => violations.push(
            "--max-client-cert-lifetime none/0 disables client-cert lifetime enforcement; \
             set a bounded lifetime (default 1h)"
                .to_string(),
        ),
        Some(lifetime) if lifetime > MAX_CLIENT_CERT_LIFETIME => violations.push(format!(
            "--max-client-cert-lifetime {}s exceeds the ceiling of {}s: Mode-A's \
             revocation posture is short-lived certificates, so a longer lifetime cannot be \
             audited as short_lived_cert; set a lifetime <= {}s",
            lifetime.as_secs(),
            MAX_CLIENT_CERT_LIFETIME.as_secs(),
            MAX_CLIENT_CERT_LIFETIME.as_secs(),
        )),
        Some(_) => {}
    }
    // A client certificate's chain, CRL status and validity window are checked at the
    // TLS handshake and never again on an established connection. Without a
    // connection-age bound a peer holding a stolen or revoked certificate keeps full
    // authenticated access for as long as it keeps one connection open — so the
    // `--max-client-cert-lifetime` ceiling above and the CRL reload cadence both stop
    // being true statements about the deployment.
    match config.limits.max_connection_age {
        None => violations.push(
            "--max-connection-age-secs 0 disables the connection-age bound: the client \
             certificate is validated only at the handshake, so a peer that never \
             reconnects is never re-checked against an expiry or a reloaded CRL. Set a \
             bounded age (default 300s)"
                .to_string(),
        ),
        Some(age) if age > MAX_CLIENT_CERT_LIFETIME => violations.push(format!(
            "--max-connection-age-secs {}s exceeds the client-cert lifetime ceiling of {}s: \
             a connection would outlive the credential that authenticated it",
            age.as_secs(),
            MAX_CLIENT_CERT_LIFETIME.as_secs(),
        )),
        Some(_) => {}
    }
    // ADR-MCPS-021 Axis 2: LIVE and PUSH both advertise a revocation window measured
    // in the store being consulted or re-consulted. With `--trust` read once at
    // startup there is nothing behind either: a Tier-3 flush evicts entries that
    // immediately re-resolve to the identical key, and Tier 2's per-request round trip
    // hits a frozen map. Refused rather than warned, because the operator asked for a
    // near-zero window and would otherwise be told at startup that they had one.
    if matches!(
        config.revocation_tier,
        crate::revocation_tier::RevocationTier::Live
            | crate::revocation_tier::RevocationTier::Push { .. }
    ) && config.trust_reload_secs.is_none()
    {
        violations.push(
            "--revocation-tier live|push requires --trust-reload-secs: both tiers state a              revocation window in terms of consulting the trust store, but with --trust read              once at startup the store cannot change, so revoking a request-signer key would              need a restart of every replica while the startup line claims otherwise"
                .to_string(),
        );
    }
    // MCPS-093/094: the socket timeouts and the aggregate read-phase deadline ARE the
    // slow-loris defense — a peer trickling bytes just under `read_timeout` is stopped
    // by `request_deadline`, and with either gone a handful of connections pin serve
    // slots up to `max_concurrent_connections` with nothing to drop them.
    //
    // An out-of-range value was already rejected LOUDLY, with the stated reason that
    // "the control can never be turned off by out-of-range input". `0` turned the same
    // control off silently, which left the binary asserting a maximal-security posture
    // while its own defense was disabled. Each default is `Some(30s)`, so `None` here
    // only ever comes from an operator explicitly passing `0`.
    for (value, flag) in [
        (config.limits.read_timeout, "--read-timeout-secs"),
        (config.limits.write_timeout, "--write-timeout-secs"),
        (config.limits.request_deadline, "--request-deadline-secs"),
    ] {
        if value.is_none() {
            violations.push(format!(
                "{flag} 0 disables a slow-loris defense: a peer that trickles bytes then \
                 holds a serve slot indefinitely, up to --max-connections, with no \
                 fail-closed drop. Set a bounded value (default 30s)"
            ));
        }
    }
    if config.identity_source == IdentityPolicy::CnLegacy {
        violations.push(
            "--transport-identity-source cn_legacy is a deprecated, insecure identity binding; \
             use uri_san or dns_san"
                .to_string(),
        );
    }
    // ADR-MCPS-014/020 (#90): the DEFAULT replay backend is `Memory`, an
    // in-process cache whose admitted nonces live ONLY in process memory. A proxy
    // restart loses every admitted nonce, re-opening a replay window for any
    // captured envelope that is still within its `expires_at + skew` freshness
    // window at restart time — the exposure is the in-restart-window captured-but-
    // still-fresh envelope (the atomic check-and-insert means a nonce re-admitted
    // AFTER its freshness window cannot verify). ADR-020 treats durable /
    // cross-instance replay as the production posture, so under strict/production
    // the non-durable in-memory default is rejected (not merely warned), mirroring
    // the fail-open relaxation guards. `File` (single-node durable) and `Shared`
    // (horizontally durable) survive on their own durability merits and are
    // assessed by the tier check below.
    if config.replay == ReplayKind::Memory {
        violations.push(
            "--replay-cache memory is non-durable: it keeps admitted nonces only in process \
             memory (and is the cache used when --replay-cache is omitted), so a proxy RESTART \
             forgets them and re-opens a replay window for any still-fresh captured envelope \
             until its expires_at+skew; production must use a durable replay store: \
             --replay-cache file (single-node durability) or --replay-cache shared (horizontal \
             durability)"
                .to_string(),
        );
    }
    // ADR-MCPS-020: under strict/production a shared replay store must declare a
    // durability tier of REDIS_WAIT_QUORUM or stronger. REDIS_ASYNC carries a
    // bounded-but-real failover replay window, and SINGLE_STORE_FAIL_CLOSED is a
    // single point of availability failure — both are rejected (not just warned)
    // so production cannot silently run on the weaker replay-safety claim.
    if config.replay == ReplayKind::Shared {
        if let Some(tier) = &config.replay_durability_tier {
            if !tier.meets_strict_production_minimum() {
                violations.push(format!(
                    "--replay-durability-tier {} is weaker than the strict-production minimum; \
                     declare redis-wait-quorum:<quorum>:<timeout_ms> or a linearizable tier",
                    tier.wire_name()
                ));
            }
        }
    }
    // MCPS-79 (ADR-MCPS-049 clause 1): the FLEET dimension is orthogonal to the
    // security posture. `--strict` alone is single-node strict, where the node is
    // the sole verifier and `--replay-cache file` (ADR-MCPS-014, single-node
    // durable) is a valid, self-consistent replay store. `--strict --fleet`
    // declares the horizontally-scaled posture: a replayable request may reach a
    // DIFFERENT verifier than the one that admitted the first nonce during the
    // evidence-acceptance window, so a node-local cache (`memory`, lost on
    // restart; or `file`, unshareable across processes) cannot maintain the
    // cross-verifier replay guarantee. Both are rejected (not warned) so a fleet
    // cannot silently run on node-local replay state. The required `shared` tier's
    // quorum/durability strength is enforced by the block above; here we only
    // reject the node-local KINDS, which is exactly what the `ReplayKind` seam
    // (not the injected cache's coarse durability CLASS) can distinguish.
    if config.fleet && (config.replay == ReplayKind::Memory || config.replay == ReplayKind::File) {
        violations.push(format!(
            "--fleet requires a shared replay cache: --replay-cache {} is node-local, so a \
             request replayed to a peer verifier during the acceptance window would not be seen \
             as a replay; use --replay-cache shared with a redis-wait-quorum:<quorum>:<timeout_ms> \
             or linearizable durability tier",
            match config.replay {
                ReplayKind::Memory => "memory",
                ReplayKind::File => "file",
                ReplayKind::Shared => unreachable!(),
            }
        ));
    }
    // #4082 (M10/M22): reverse-proxy identity-header ingress takes the verified
    // identity from a forwarded header and trusts, on the operator's word alone,
    // that the socket is reachable ONLY by the upstream — a process that can
    // reach the socket can SPOOF any identity. Strict refuses to enable this
    // documented spoofable posture silently.
    if config.reverse_proxy_identity_header.is_some() {
        violations.push(
            "--reverse-proxy-identity-header trusts a forwarded identity header that any peer \
             able to reach the socket can spoof; production must terminate mTLS locally (omit \
             --reverse-proxy-identity-header)"
                .to_string(),
        );
    }
    // #4082 (M11): `--transport-binding none` ignores the mTLS channel identity,
    // so a request signed by identity A can be presented over a channel
    // authenticated as identity B. The channel-to-signer binding must be enforced
    // in production.
    if config.binding == BindingKind::None {
        violations.push(
            "--transport-binding none ignores the mTLS channel identity, decoupling the \
             verified request signer from the authenticated channel; production must bind \
             them (--transport-binding exact)"
                .to_string(),
        );
    }
    // ADR-MCPS-023 Tier 3 (issue #71): `--transport-binding lb-assertion` is a
    // cryptographically request-bound ingress assertion, but the load balancer
    // still terminates the client's mTLS and is in the trusted computing base —
    // this is request-bound INGRESS assertion, NOT end-to-end client↔node binding
    // (NOT end_to_end_mtls). Strict/production refuses to enable the downgraded
    // posture silently, mirroring the trusted-ingress-header refusal above.
    if config.binding == BindingKind::LbAssertion {
        violations.push(
            "--transport-binding lb-assertion places the load balancer in the trusted \
             computing base (the LB terminates the client mTLS and signs a request-bound \
             assertion); this is request-bound ingress assertion, NOT end-to-end \
             client↔node mTLS; production must bind end-to-end (--transport-binding exact \
             with locally-terminated client mTLS)"
                .to_string(),
        );
    }
    violations
}

/// Whether a Unix file mode is group- or world-accessible (MCPS-3842). Pure
/// predicate factored out of `main.rs`'s key-file-permission check so the
/// warn-vs-reject decision is black-box testable without touching the filesystem.
/// A sensitive key file must be restricted to the owner (mode `0600`); any
/// group/world permission bit set is an insecure posture.
pub fn key_file_mode_is_insecure(mode: u32) -> bool {
    mode & 0o077 != 0
}

/// Why a key file's posture was refused, or `None` when it is acceptable.
///
/// The strict rule ([`key_file_mode_is_insecure`]) is `0600`/`0400` and nothing else,
/// which is correct on a normal host and IMPOSSIBLE under the Kubernetes model a
/// non-root pod needs: a Secret mounted for a non-root uid is owned by the pod's
/// `fsGroup` and delivered mode `0440`, so the strict predicate refuses to start
/// exactly the deployment that stopped running as root (C053b).
///
/// So group READ is acceptable, but only under all three conditions, and only when the
/// operator has explicitly asked for it:
///
///   1. `allow_group_read` — an explicit opt-in, never a silent default. This widens
///      who can read a signing key, so the deployment states it (the same shape as
///      `replay.allowPlaintextRedis` / `identity.allowExampleFixtures`).
///   2. the file's group is one THIS PROCESS is in — otherwise "group-readable" grants
///      a group the proxy has nothing to do with, which is strictly worse than the
///      posture being relaxed.
///   3. no group WRITE and no other/world bit at all. Group write would let a peer
///      process replace the signing key; that is never a mount-model requirement.
pub fn key_file_posture_violation(
    mode: u32,
    file_gid: u32,
    allow_group_read: bool,
    process_gids: &[u32],
) -> Option<&'static str> {
    if mode & 0o007 != 0 {
        return Some("world-accessible");
    }
    if mode & 0o020 != 0 {
        return Some("group-writable");
    }
    if mode & 0o050 == 0 {
        return None;
    }
    if !allow_group_read {
        return Some("group-accessible (pass --allow-group-readable-key-files if this is an fsGroup-owned mount)");
    }
    if !process_gids.contains(&file_gid) {
        return Some("group-accessible to a group this process is not a member of");
    }
    None
}

/// Read the PKCS#11 User PIN from `path` into a short-lived [`SecretString`].
///
/// Enforces the key-file permission floor here as well as at startup: `run()` checks it
/// via `key_files_read_from_disk`, but `build_key_source` is a public entry point a test
/// or an embedding binary can reach directly, and a secret-reading function that trusts
/// its caller to have checked is one refactor from not being checked at all.
///
/// Trailing whitespace is trimmed — a PIN file written with `echo` ends in a newline, and
/// a token would reject the PIN with an opaque error that looks like a wrong PIN. Interior
/// whitespace is preserved: it may be part of the PIN.
pub fn read_pkcs11_pin(path: &str) -> Result<SecretString, KeyError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path).map_err(|e| {
            KeyError::NotFound(format!("--pkcs11-pin-file {path} cannot be read: {e}"))
        })?;
        let mode = meta.permissions().mode();
        if key_file_mode_is_insecure(mode) {
            return Err(KeyError::NotFound(format!(
                "--pkcs11-pin-file {path} is group/world-accessible (mode {:o}); it unlocks \
                 the token holding the signing keys, so restrict it to 0600",
                mode & 0o777
            )));
        }
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| KeyError::NotFound(format!("--pkcs11-pin-file {path} cannot be read: {e}")))?;
    let pin = SecretString::new(raw.trim_end());
    if pin.expose().is_empty() {
        return Err(KeyError::NotFound(format!(
            "--pkcs11-pin-file {path} is empty; a blank PIN would be sent to the token"
        )));
    }
    Ok(pin)
}

/// Parse a timeout in whole seconds; `0` disables the timeout (`None`). The
/// value is CAPPED at [`MAX_INNER_READ_TIMEOUT_SECS`] (1 day) and an over-cap
/// value is REJECTED loudly. This matters for `--request-deadline-secs`, whose
/// value is later added to `Instant::now()` in the fail-closed deadline reader
/// (`tls::DeadlineStream`): an absurdly large value would overflow `checked_add`
/// and — if not rejected here — silently DISABLE the slow-loris defense. Bounding
/// at parse time keeps the control fail-closed.
fn parse_timeout(value: &str, flag: &str) -> Result<Option<Duration>, String> {
    let secs: u64 = value.parse().map_err(|_| format!("invalid {flag}"))?;
    if secs > MAX_INNER_READ_TIMEOUT_SECS {
        return Err(format!(
            "{flag} must be <= {MAX_INNER_READ_TIMEOUT_SECS} seconds (1 day); got {secs}"
        ));
    }
    Ok(if secs == 0 {
        None
    } else {
        Some(Duration::from_secs(secs))
    })
}

/// The maximum accepted `--inner-read-timeout-secs` (MCPS-074): 1 day. Generous
/// for any legitimate inner yet far below the range that would overflow
/// `Instant::now() + timeout` in the deadline reader, making that overflow
/// practically unreachable (the `checked_add` there is defense-in-depth).
const MAX_INNER_READ_TIMEOUT_SECS: u64 = 86_400;

/// Parse a client-cert lifetime: a number with an optional `h`/`m`/`s` suffix
/// (bare = seconds), or `none`/`0` to disable enforcement. E.g. `1h`, `30m`,
/// `3600`, `none`.
fn parse_cert_lifetime(value: &str) -> Result<Option<Duration>, String> {
    if value == "none" {
        return Ok(None);
    }
    let (digits, multiplier) = match value.strip_suffix('h') {
        Some(d) => (d, 3600),
        None => match value.strip_suffix('m') {
            Some(d) => (d, 60),
            None => (value.strip_suffix('s').unwrap_or(value), 1),
        },
    };
    let n: u64 = digits.parse().map_err(|_| {
        format!("invalid --max-client-cert-lifetime '{value}' (e.g. 1h, 30m, 3600, none)")
    })?;
    Ok(if n == 0 {
        None
    } else {
        Some(Duration::from_secs(n * multiplier))
    })
}

/// Build the configured ADR-MCPS-023 Tier-3 LB-signed, request-bound ingress
/// assertion verifier (issue #71) from `config.ingress_lb_keys`, or `None` when the
/// binding is not `lb-assertion`.
///
/// `parse_args` has ALREADY validated (fail closed) that, under `lb-assertion`,
/// every `--ingress-lb-key` body is a base64url 32-byte Ed25519 public key and that
/// at least one key is present with unique ids — so the per-key decode here cannot
/// be reached with a malformed key in a well-formed config; it nonetheless surfaces
/// a precise error rather than panicking if that invariant is ever violated. The
/// yielded identity's [`IdentitySource`] mirrors the configured identity policy, so
/// a Tier-3 identity reports the same source field the direct-TLS / reverse-proxy
/// paths would.
pub fn build_lb_assertion_binding(
    config: &Config,
) -> Result<Option<crate::transport::LbAssertionBinding>, String> {
    if config.binding != BindingKind::LbAssertion {
        return Ok(None);
    }
    let source = match config.identity_source {
        IdentityPolicy::UriSan => crate::transport::IdentitySource::UriSan,
        IdentityPolicy::DnsSan => crate::transport::IdentitySource::DnsSan,
        IdentityPolicy::CnLegacy => crate::transport::IdentitySource::CommonName,
    };
    let mut binding = crate::transport::LbAssertionBinding::new(source);
    for (key_id, key_b64) in &config.ingress_lb_keys {
        let key = VerificationKey::from_b64url(key_b64).map_err(|_| {
            format!(
                "invalid --ingress-lb-key '{key_id}': the body must be a base64url-no-pad \
                 32-byte Ed25519 public key"
            )
        })?;
        binding.add_key(key_id.clone(), key);
    }
    Ok(Some(binding))
}

/// Build the ADR-MCPS-023 §C (Mode C) attested-ingress verifier from `config`, or
/// `Ok(None)` when `binding != AttestedIngress`. `parse_args` has already enforced
/// that the attestor keys, ≥1 trusted ingress identity, the audience, and the
/// pinned-mTLS acknowledgement are all present (fail closed) and that every attestor
/// key is a valid Ed25519 public key — this only reconstructs the verifier, failing
/// closed with a precise error if any invariant were ever violated.
pub fn build_attested_ingress_binding(
    config: &Config,
) -> Result<Option<crate::transport::LbAssertionV2Binding>, String> {
    if config.binding != BindingKind::AttestedIngress {
        return Ok(None);
    }
    let source = match config.identity_source {
        IdentityPolicy::UriSan => crate::transport::IdentitySource::UriSan,
        IdentityPolicy::DnsSan => crate::transport::IdentitySource::DnsSan,
        IdentityPolicy::CnLegacy => crate::transport::IdentitySource::CommonName,
    };
    let audience = config
        .ingress_audience
        .as_deref()
        .ok_or("internal error: attested-ingress binding selected but no --ingress-audience set")?;
    let mut binding = crate::transport::LbAssertionV2Binding::new(source, audience);
    for (key_id, key_b64) in &config.ingress_attestor_keys {
        let key = VerificationKey::from_b64url(key_b64).map_err(|_| {
            format!(
                "invalid --ingress-attestor-key '{key_id}': the body must be a \
                 base64url-no-pad 32-byte Ed25519 public key"
            )
        })?;
        binding.add_key(key_id.clone(), key);
    }
    for ingress_identity in &config.ingress_identities {
        binding.permit_ingress_identity(ingress_identity.clone());
    }
    Ok(Some(binding))
}

/// Build the configured [`KeySource`].
///
/// MCPS-076 (audit gap G-3): [`KeySourceKind::Env`] is honored ONLY in a build with
/// the non-default `dev_env_key_source` feature. A default (production) build does
/// not compile [`EnvKeySource`] at all and FAILS CLOSED here with a clear error —
/// `--key-source env` still parses (so the message is precise), but no env-backed
/// key can be constructed.
pub fn build_key_source(config: &Config) -> Result<Box<dyn KeySource + Send + Sync>, KeyError> {
    match config.key_source {
        KeySourceKind::File => Ok(Box::new(FileKeySource {
            signing_key_seed_path: config.signing_key_seed.clone(),
            tls_cert_path: config.tls_cert.clone(),
            tls_key_path: config.tls_key.clone(),
            client_ca_path: config.client_ca.clone(),
        })),
        #[cfg(feature = "dev_env_key_source")]
        KeySourceKind::Env => Ok(Box::new(EnvKeySource {
            signing_key_seed_var: config.signing_key_seed.clone(),
            tls_cert_var: config.tls_cert.clone(),
            tls_key_var: config.tls_key.clone(),
            client_ca_var: config.client_ca.clone(),
        })),
        #[cfg(not(feature = "dev_env_key_source"))]
        KeySourceKind::Env => Err(KeyError::NotFound(
            "env key source is development-only; rebuild with \
             --features dev_env_key_source (production must use --key-source file)"
                .to_string(),
        )),
        // #4034 PKCS#11 token-backed source. `parse_args` already guaranteed the
        // four pkcs11 flags are present when this kind is selected, so unwrapping
        // them here cannot be reached with a `None`; surface a clear error rather
        // than panicking if that invariant is ever violated.
        #[cfg(feature = "pkcs11_keysource")]
        KeySourceKind::Pkcs11 => {
            let require = |opt: &Option<String>, flag: &str| -> Result<String, KeyError> {
                opt.clone().ok_or_else(|| {
                    KeyError::NotFound(format!("--key-source pkcs11 requires {flag}"))
                })
            };
            let module = require(&config.pkcs11_module, "--pkcs11-module")?;
            // Read the User PIN here, at the one point it is used, so it exists for as
            // short a window as possible and never lands in `Config` (which is `Debug`
            // and freely cloned). The file must be no more readable than a key file:
            // it unlocks the token holding the signing keys.
            let pin_file = require(&config.pkcs11_pin_file, "--pkcs11-pin-file")?;
            let pin = read_pkcs11_pin(&pin_file)?;
            let token_label = require(&config.pkcs11_token_label, "--pkcs11-token-label")?;
            let key_label = require(&config.pkcs11_key_label, "--pkcs11-key-label")?;
            // #59: an optional SECOND token object holds the Ed25519 TLS key. When
            // present, `open` builds the delegated TLS signer and the proxy never
            // reads `--tls-key` from disk (the exclusivity guard already forbade it).
            Ok(Box::new(crate::pkcs11_keysource::Pkcs11KeySource::open(
                &module,
                pin.expose(),
                &token_label,
                &key_label,
                &config.tls_cert,
                &config.tls_key,
                &config.client_ca,
                config.pkcs11_tls_key_label.as_deref(),
            )?))
        }
        // Default build: the PKCS#11 backend is not compiled, so `--key-source
        // pkcs11` FAILS CLOSED here (mirrors the env-keysource gate). The flag
        // still PARSES so the message is precise; no token-backed key is built.
        #[cfg(not(feature = "pkcs11_keysource"))]
        KeySourceKind::Pkcs11 => Err(KeyError::NotFound(
            "pkcs11 key source requires the pkcs11_keysource feature (build with \
             --features pkcs11_keysource); not available in this build"
                .to_string(),
        )),
        // ADR-MCPS-028 §B: AWS KMS object-signing key, TLS material from files. The
        // response-signing key never leaves KMS. `parse_args` guaranteed region +
        // key id are present; surface a clear error rather than panic if not.
        #[cfg(feature = "aws_kms_keysource")]
        KeySourceKind::AwsKms => {
            let require = |opt: &Option<String>, flag: &str| -> Result<String, KeyError> {
                opt.clone().ok_or_else(|| {
                    KeyError::NotFound(format!("--key-source aws-kms requires {flag}"))
                })
            };
            let region = require(&config.aws_kms_region, "--aws-kms-region")?;
            let kms_config = crate::aws_kms_keysource::AwsKmsConfig {
                region: region.clone(),
                key_id: require(&config.aws_kms_key_id, "--aws-kms-key-id")?,
                endpoint: config.aws_kms_endpoint.clone(),
            };
            let backend = crate::aws_kms_keysource::AwsKmsEd25519Backend::from_env(&kms_config)?;
            let tls = FileKeySource {
                signing_key_seed_path: config.signing_key_seed.clone(),
                tls_cert_path: config.tls_cert.clone(),
                tls_key_path: config.tls_key.clone(),
                client_ca_path: config.client_ca.clone(),
            };
            // #60: a configured TLS-key id custodies the TLS server key in a SECOND,
            // DISTINCT KMS key (independent of the object-signing key). Its own
            // `AwsKmsEd25519Backend` (same region/endpoint, the TLS key id) drives the
            // delegated TLS handshake signature; the proxy then never reads `--tls-key`
            // from disk (the exclusivity guard already forbade it). `None` keeps the
            // file-backed TLS path.
            match &config.aws_kms_tls_key_id {
                Some(tls_key_id) => {
                    let tls_kms_config = crate::aws_kms_keysource::AwsKmsConfig {
                        region,
                        key_id: tls_key_id.clone(),
                        endpoint: config.aws_kms_endpoint.clone(),
                    };
                    let tls_backend =
                        crate::aws_kms_keysource::AwsKmsEd25519Backend::from_env(&tls_kms_config)?;
                    Ok(Box::new(
                        crate::kms_keysource::KmsKeySource::new_with_delegated_tls(
                            Box::new(backend),
                            tls,
                            std::sync::Arc::new(tls_backend),
                        ),
                    ))
                }
                None => Ok(Box::new(crate::kms_keysource::KmsKeySource::new(
                    Box::new(backend),
                    tls,
                ))),
            }
        }
        // Default build: the AWS KMS backend is not compiled, so `--key-source
        // aws-kms` FAILS CLOSED here (mirrors the pkcs11 gate). The flag still PARSES.
        #[cfg(not(feature = "aws_kms_keysource"))]
        KeySourceKind::AwsKms => Err(KeyError::NotFound(
            "aws-kms key source requires the aws_kms_keysource feature (build with \
             --features aws_kms_keysource); not available in this build"
                .to_string(),
        )),
        // ADR-MCPS-028 §C: GCP Cloud KMS object-signing key, TLS material from files.
        #[cfg(feature = "gcp_kms_keysource")]
        KeySourceKind::GcpKms => {
            let key_version = config.gcp_kms_key_version.clone().ok_or_else(|| {
                KeyError::NotFound(
                    "--key-source gcp-kms requires --gcp-kms-key-version".to_string(),
                )
            })?;
            let kms_config = crate::gcp_kms_keysource::GcpKmsConfig {
                key_version_name: key_version,
                endpoint: config.gcp_kms_endpoint.clone(),
            };
            let backend = crate::gcp_kms_keysource::GcpKmsEd25519Backend::new(
                &kms_config,
                config.gcp_kms_use_metadata,
            )?;
            let tls = FileKeySource {
                signing_key_seed_path: config.signing_key_seed.clone(),
                tls_cert_path: config.tls_cert.clone(),
                tls_key_path: config.tls_key.clone(),
                client_ca_path: config.client_ca.clone(),
            };
            // #61: a configured TLS-key-version custodies the TLS server key in a
            // SECOND, DISTINCT Cloud KMS key version (independent of the
            // object-signing key). Its own `GcpKmsEd25519Backend` (same
            // endpoint/token source, the TLS key-version) drives the delegated TLS
            // handshake signature; the proxy then never reads `--tls-key` from disk
            // (the exclusivity guard already forbade it). `None` keeps the
            // file-backed TLS path.
            match &config.gcp_kms_tls_key_version {
                Some(tls_key_version) => {
                    let tls_kms_config = crate::gcp_kms_keysource::GcpKmsConfig {
                        key_version_name: tls_key_version.clone(),
                        endpoint: config.gcp_kms_endpoint.clone(),
                    };
                    let tls_backend = crate::gcp_kms_keysource::GcpKmsEd25519Backend::new(
                        &tls_kms_config,
                        config.gcp_kms_use_metadata,
                    )?;
                    Ok(Box::new(
                        crate::kms_keysource::KmsKeySource::new_with_delegated_tls(
                            Box::new(backend),
                            tls,
                            std::sync::Arc::new(tls_backend),
                        ),
                    ))
                }
                None => Ok(Box::new(crate::kms_keysource::KmsKeySource::new(
                    Box::new(backend),
                    tls,
                ))),
            }
        }
        #[cfg(not(feature = "gcp_kms_keysource"))]
        KeySourceKind::GcpKms => Err(KeyError::NotFound(
            "gcp-kms key source requires the gcp_kms_keysource feature (build with \
             --features gcp_kms_keysource); not available in this build"
                .to_string(),
        )),
    }
}

/// Build the SHARED replay cache selected by `--replay-cache shared` (issue
/// #3837), backed by Redis under the `redis_replay` feature (issue #4028).
///
/// Under `--features redis_replay` this connects to `replay_redis_url` and wires
/// a [`SharedReplayCache`](crate::shared_replay::SharedReplayCache) over a
/// [`RedisAtomicReplayStore`](crate::redis_store::RedisAtomicReplayStore), giving
/// real horizontally-scaled replay safety (a nonce accepted on one node is
/// rejected as a replay on every node sharing that Redis). A connect failure
/// fails closed with a clear error rather than degrading to a non-shared cache.
///
/// In a DEFAULT build the Redis backend is not compiled, so this mirrors
/// [`build_key_source`]'s dev-only gate: `--replay-cache shared` always PARSES
/// (so the message is precise), but it FAILS CLOSED here — there is no shared
/// backend to construct.
///
/// `replay_redis_url` is the connection URL (already required by `parse_args`).
/// `read_timeout` / `write_timeout` are the server's configured socket timeouts
/// (`--read-timeout-secs` / `--write-timeout-secs`); they BOUND the Redis connect
/// and each blocking replay op so a stalled backend fails closed (Unavailable)
/// within a finite window instead of wedging the single-threaded serve loop
/// (MCPS-090 / H-10). The connect timeout is derived from the read timeout (a
/// stalled connect and a stalled read are the same hazard), falling back to a
/// bounded default when the read timeout is disabled (`0`).
#[cfg(feature = "redis_replay")]
pub fn build_shared_replay_cache(
    replay_redis_url: &str,
    max_clock_skew: i64,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    tier: &crate::replay_tier::ReplayDurabilityTier,
) -> Result<Box<dyn mcp_re_core::ReplayCache + Send + Sync>, String> {
    use crate::replay_tier::ReplayDurabilityTier;
    // A disabled socket timeout would re-introduce the hang, so the connect
    // timeout is always bounded: prefer the configured read timeout, else a
    // bounded default.
    let connect_timeout = read_timeout.unwrap_or(Duration::from_secs(30));
    let store = crate::redis_store::RedisAtomicReplayStore::connect_with(
        replay_redis_url,
        connect_timeout,
        read_timeout,
        write_timeout,
        crate::redis_store::system_clock(),
    )
    .map_err(|e| format!("shared replay cache: {e}"))?;
    // Apply the declared durability tier (ADR-MCPS-020). REDIS_WAIT_QUORUM adds
    // the per-insert WAIT; REDIS_ASYNC / SINGLE_STORE_FAIL_CLOSED are the plain
    // SET NX PX path (the tier is the operator's topology assertion). LINEARIZABLE
    // cannot be backed by Redis — it requires the CP/etcd backend — so it fails
    // closed here rather than silently over-claiming.
    let store = match tier {
        ReplayDurabilityTier::RedisWaitQuorum { quorum, timeout_ms } => {
            store.with_wait_quorum(*quorum, *timeout_ms)
        }
        ReplayDurabilityTier::RedisAsyncBounded | ReplayDurabilityTier::SingleStoreFailClosed => {
            store
        }
        ReplayDurabilityTier::Linearizable => {
            return Err(
                "LINEARIZABLE durability tier requires a CP/linearizable store \
                        (the etcd backend); the Redis backend cannot provide a \
                        linearizable guarantee. Use redis-async, \
                        redis-wait-quorum:<quorum>:<timeout_ms>, or \
                        single-store-fail-closed."
                    .to_string(),
            );
        }
    };
    Ok(Box::new(crate::shared_replay::SharedReplayCache::new(
        Box::new(store),
        max_clock_skew,
    )))
}

/// Default-build fail-closed stub: no shared backend is compiled without the
/// `redis_replay` feature, so `--replay-cache shared` fails closed here. See the
/// feature-enabled variant above for the real Redis wiring.
#[cfg(not(feature = "redis_replay"))]
pub fn build_shared_replay_cache(
    replay_redis_url: &str,
    max_clock_skew: i64,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    tier: &crate::replay_tier::ReplayDurabilityTier,
) -> Result<Box<dyn mcp_re_core::ReplayCache + Send + Sync>, String> {
    let _ = (
        replay_redis_url,
        max_clock_skew,
        read_timeout,
        write_timeout,
        tier,
    );
    Err(
        "shared replay cache backend is not yet available in this build (the Redis \
         adapter is behind the non-default redis_replay feature; the etcd \
         LINEARIZABLE backend is behind cpstore_etcd); use --replay-cache file for \
         single-node durability"
            .to_string(),
    )
}

/// Build the CP / LINEARIZABLE replay cache selected by
/// `--replay-durability-tier linearizable` (issue #69, epic #68 v0.4 Axis 1),
/// backed by etcd under the `cpstore_etcd` feature.
///
/// Under `--features cpstore_etcd` this constructs a
/// [`SharedReplayCache`](crate::shared_replay::SharedReplayCache) over an
/// [`EtcdAtomicReplayStore`](crate::etcd_store::EtcdAtomicReplayStore) against the
/// etcd v3 JSON gateway at `cpstore_etcd_endpoint`, giving the strongest
/// horizontal replay-safety claim (conditional on etcd's durable-linearizable
/// write contract, ADR-MCPS-020). The store opens connections lazily, so an
/// unreachable etcd surfaces as a fail-closed `Unavailable` on the FIRST replay
/// op rather than at construction.
///
/// `read_timeout` / `write_timeout` are the server's configured socket timeouts;
/// the larger of the two BOUNDS each blocking etcd op so a stalled backend fails
/// closed within a finite window instead of wedging the single-threaded serve
/// loop (the same MCPS-090 / H-10 hazard the Redis path bounds). A disabled
/// timeout (`0` ⇒ `None`) falls back to a bounded default.
#[cfg(feature = "cpstore_etcd")]
pub fn build_cpstore_replay_cache(
    cpstore_etcd_endpoint: &str,
    max_clock_skew: i64,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
) -> Result<Box<dyn mcp_re_core::ReplayCache + Send + Sync>, String> {
    // A disabled socket timeout would re-introduce the hang, so the per-op timeout
    // is always bounded: prefer the larger configured socket timeout, else a
    // bounded default.
    let timeout = match (read_timeout, write_timeout) {
        (Some(r), Some(w)) => r.max(w),
        (Some(t), None) | (None, Some(t)) => t,
        (None, None) => Duration::from_secs(30),
    };
    let store = crate::etcd_store::EtcdAtomicReplayStore::connect_with(
        cpstore_etcd_endpoint,
        timeout,
        crate::etcd_store::system_clock(),
    );
    Ok(Box::new(crate::shared_replay::SharedReplayCache::new(
        Box::new(store),
        max_clock_skew,
    )))
}

/// Default-build fail-closed stub for the CP / LINEARIZABLE backend: the etcd
/// adapter is compiled ONLY under the non-default `cpstore_etcd` feature, so
/// `--replay-durability-tier linearizable` FAILS CLOSED here in a build without it
/// (it never silently downgrades to Redis / in-memory). Mirrors the
/// `build_shared_replay_cache` redis gate. See the feature-enabled variant above.
#[cfg(not(feature = "cpstore_etcd"))]
pub fn build_cpstore_replay_cache(
    cpstore_etcd_endpoint: &str,
    max_clock_skew: i64,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
) -> Result<Box<dyn mcp_re_core::ReplayCache + Send + Sync>, String> {
    let _ = (
        cpstore_etcd_endpoint,
        max_clock_skew,
        read_timeout,
        write_timeout,
    );
    Err(
        "LINEARIZABLE durability tier needs the cpstore_etcd feature, which is not \
         available in this build (rebuild with --features cpstore_etcd); the \
         LINEARIZABLE claim is forbidden without the CP/etcd backend and is NEVER \
         downgraded to Redis or in-memory"
            .to_string(),
    )
}

/// Parse the trust file into `(signer, key_id, verification_key)` entries so the
/// serving path can build the RFC 9421 [`mcp_re_http_profile::ResolvedActor`]
/// resolver (keyid → structured actor). Same fail-closed duplicate rejection as
/// [`load_trust`].
pub fn load_trust_entries(bytes: &[u8]) -> Result<Vec<(String, String, VerificationKey)>, String> {
    let value: Value = serde_json::from_slice(bytes).map_err(|e| format!("trust file: {e}"))?;
    let array = value.as_array().ok_or("trust file must be a JSON array")?;
    let mut out = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for entry in array {
        let signer = entry["signer"]
            .as_str()
            .ok_or("trust entry missing signer")?;
        let key_id = entry["key_id"]
            .as_str()
            .ok_or("trust entry missing key_id")?;
        if !seen.insert(key_id.to_string()) {
            return Err(format!(
                "trust file: duplicate key_id {key_id} (RFC 9421 resolver keys on key_id)"
            ));
        }
        let pk = entry["public_key"]
            .as_str()
            .ok_or("trust entry missing public_key")?;
        let key = VerificationKey::from_b64url(pk)
            .map_err(|_| format!("trust entry {signer}#{key_id}: invalid public_key"))?;
        out.push((signer.to_string(), key_id.to_string(), key));
    }
    Ok(out)
}

/// The `kid -> signer` map for keys this file enrols FOR THE REQUEST SLOT.
///
/// The SignerSlot type exists so trust resolution — not a role string read after the
/// fact — decides which slot a key may sign in. That only means something if the trust
/// file can express it. Previously it could not: every entry whose `key_id` was not
/// the response kid was granted the request slot unconditionally, so a key enrolled
/// for another purpose (this same file carries authorization-issuer keys) silently
/// became a full request-signing credential, and its resolved actor id then flowed
/// into the replay key, the Mode-A transport binding and the audit record.
///
/// An entry may now declare `"slots": ["request"]`. The rules:
///
///   * `slots` present  — authoritative. A key that does not list `request` is not a
///     request signer, whatever else it is in the file for.
///   * `slots` absent   — treated as `["request"]`, which is exactly the historical
///     behaviour, so an existing trust file keeps working. Declaring slots is how an
///     operator NARROWS a key; it is not a new requirement.
///
/// `response_kid` is excluded either way: the deployment's own issuer key must never
/// be presentable as a client credential.
pub fn load_trust_request_signers(
    bytes: &[u8],
    response_kid: &str,
) -> Result<std::collections::HashMap<String, String>, String> {
    let value: Value = serde_json::from_slice(bytes).map_err(|e| format!("trust file: {e}"))?;
    let array = value.as_array().ok_or("trust file must be a JSON array")?;
    let mut out = std::collections::HashMap::new();
    for entry in array {
        let signer = entry["signer"]
            .as_str()
            .ok_or("trust entry missing signer")?;
        let key_id = entry["key_id"]
            .as_str()
            .ok_or("trust entry missing key_id")?;
        if key_id == response_kid {
            continue;
        }
        let request_slot = match entry.get("slots") {
            None => true,
            Some(slots) => {
                let listed = slots.as_array().ok_or_else(|| {
                    format!("trust entry {signer}#{key_id}: slots must be an array")
                })?;
                let mut found = false;
                for slot in listed {
                    match slot.as_str() {
                        Some("request") => found = true,
                        // Named so a typo is a startup failure rather than a silently
                        // narrower key that then fails every request at verify time.
                        Some(other) if other == "response" || other == "authorization-issuer" => {}
                        _ => {
                            return Err(format!(
                                "trust entry {signer}#{key_id}: unknown slot {slot}                                  (request|response|authorization-issuer)"
                            ))
                        }
                    }
                }
                found
            }
        };
        if request_slot {
            out.insert(key_id.to_string(), signer.to_string());
        }
    }
    Ok(out)
}

/// Load a JSON trust file into an [`InMemoryTrustResolver`]. The file is an array
/// of `{ "signer", "key_id", "public_key" }` (the public key Base64URL-no-pad) with an
/// optional `"slots"` array; it carries both request-signer keys and
/// authorization-issuer keys, and `slots` is what separates them (see
/// [`load_trust_request_signers`]).
pub fn load_trust(bytes: &[u8]) -> Result<InMemoryTrustResolver, String> {
    let value: Value = serde_json::from_slice(bytes).map_err(|e| format!("trust file: {e}"))?;
    let array = value.as_array().ok_or("trust file must be a JSON array")?;
    let mut resolver = InMemoryTrustResolver::new();
    // Fail closed on a duplicate (signer, key_id): the resolver's `insert` is
    // last-write-wins, so a second entry sharing the key coordinate — with a
    // DIFFERENT public_key — would silently swap the trusted key. Reject at load
    // rather than trust the file ordering, mirroring the duplicate-header rigor
    // applied elsewhere.
    let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
    for entry in array {
        let signer = entry["signer"]
            .as_str()
            .ok_or("trust entry missing signer")?;
        let key_id = entry["key_id"]
            .as_str()
            .ok_or("trust entry missing key_id")?;
        if !seen.insert((signer.to_string(), key_id.to_string())) {
            return Err(format!(
                "trust file: duplicate entry for {signer}#{key_id} (last-write-wins \
                 key substitution refused)"
            ));
        }
        let pk = entry["public_key"]
            .as_str()
            .ok_or("trust entry missing public_key")?;
        let key = VerificationKey::from_b64url(pk)
            .map_err(|_| format!("trust entry {signer}#{key_id}: invalid public_key"))?;
        resolver.insert(signer, key_id, key);
    }
    Ok(resolver)
}

/// Wrap the base trust resolver according to the declared revocation tier
/// (ADR-MCPS-021, Axis 2), so the configured tier actually GOVERNS runtime
/// behavior instead of only labeling a startup line.
///
/// - [`RevocationTier::BoundedCache`] → a Tier-1 [`BoundedTrustCache`] caching
///   active state for at most `T`.
/// - [`RevocationTier::Live`] → a Tier-2 [`LiveTrustResolver`] that consults the
///   inner store on every call (no positive caching), so a store revocation is
///   visible on the very next request.
/// - [`RevocationTier::Push`] → a Tier-3 [`PushInvalidationTrustCache`] over an
///   in-process [`InMemoryInvalidationChannel`]. NOTE: no networked event source
///   ships yet, so the reference channel delivers no external pushes and the cache
///   operates at its honest bounded-`T` fallback (exactly what
///   [`RevocationTier::Push`]'s `guarantee()` already states). The wrapping is
///   still correct: it is the same code path a real push backend will drive, and
///   it never claims a near-zero window the channel cannot prove.
///
/// Pure and unit-testable: the `clock` is injected (tests pass a controllable one),
/// and the negative TTL is the named [`crate::trust_cache::DEFAULT_NEGATIVE_TTL_SECS`].
pub fn build_revocation_resolver(
    tier: &crate::revocation_tier::RevocationTier,
    base: Box<dyn mcp_re_core::TrustResolver + Send + Sync>,
    clock: crate::trust_cache::UnixClock,
) -> Box<dyn mcp_re_core::TrustResolver + Send + Sync> {
    build_revocation_resolver_with_channel(tier, base, clock, None)
}

/// As [`build_revocation_resolver`], but for the [`RevocationTier::Push`]
/// (ADR-MCPS-021 Tier 3) tier a caller may inject a networked
/// [`InvalidationChannel`](crate::push_trust::InvalidationChannel) — e.g. the
/// MCPS-84 Redis trust-epoch source. When `push_channel` is `None` the Push tier
/// falls back to the inert in-process reference channel (today's default:
/// bounded-`T`, no networked pushes). Non-Push tiers ignore `push_channel`.
pub fn build_revocation_resolver_with_channel(
    tier: &crate::revocation_tier::RevocationTier,
    base: Box<dyn mcp_re_core::TrustResolver + Send + Sync>,
    clock: crate::trust_cache::UnixClock,
    push_channel: Option<Box<dyn crate::push_trust::InvalidationChannel + Send + Sync>>,
) -> Box<dyn mcp_re_core::TrustResolver + Send + Sync> {
    let negative_ttl_secs = crate::trust_cache::DEFAULT_NEGATIVE_TTL_SECS;
    match tier {
        crate::revocation_tier::RevocationTier::BoundedCache { t_secs } => Box::new(
            crate::trust_cache::BoundedTrustCache::new(base, *t_secs, negative_ttl_secs, clock),
        ),
        crate::revocation_tier::RevocationTier::Live => {
            Box::new(crate::live_trust::LiveTrustResolver::new(base))
        }
        crate::revocation_tier::RevocationTier::Push { t_secs } => {
            // Tier 3: use the injected networked channel (MCPS-84 Redis trust-epoch
            // source) when present; otherwise the in-process reference channel is
            // inert and the cache runs at its bounded-`T` fallback (the honest
            // guarantee when no push backend is wired).
            let channel = push_channel
                .unwrap_or_else(|| Box::new(crate::push_trust::InMemoryInvalidationChannel::new()));
            Box::new(crate::push_trust::PushInvalidationTrustCache::new(
                base,
                *t_secs,
                negative_ttl_secs,
                clock,
                channel,
            ))
        }
    }
}

/// Load the configured offline client-certificate revocation lists (#3839) into
/// the DER form rustls' `WebPkiClientVerifier` consumes. Each path may hold one or
/// more CRLs in PEM (`-----BEGIN X509 CRL-----`) or a single raw DER CRL. Fails
/// closed: a missing or malformed CRL file is a hard startup error (`Err`) rather
/// than a silently-skipped revocation check. An empty `paths` yields an empty vec
/// (revocation checking disabled — the pre-#3839 behavior).
///
/// OFFLINE only: these bytes are read once at startup and never refreshed over the
/// network. Online OCSP / CRL-distribution-point fetching is deliberately NOT done
/// here and is deferred to a follow-up (it needs an HTTP client + a live
/// responder, which would expand the firewalled supply chain).
pub fn load_client_crls(
    paths: &[String],
) -> Result<Vec<rustls_pki_types::CertificateRevocationListDer<'static>>, String> {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::CertificateRevocationListDer;

    let mut crls: Vec<CertificateRevocationListDer<'static>> = Vec::new();
    for path in paths {
        let bytes = std::fs::read(path).map_err(|e| format!("client CRL {path}: {e}"))?;
        // Try PEM first (one file may carry several `X509 CRL` blocks). If the file
        // contains no PEM CRL block, treat the whole file as a single DER CRL.
        let pem: Vec<CertificateRevocationListDer<'static>> =
            CertificateRevocationListDer::pem_slice_iter(&bytes)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("client CRL {path}: malformed PEM: {e}"))?;
        if pem.is_empty() {
            // No PEM CRL block found → interpret the bytes as one DER CRL. Empty
            // input cannot be a valid DER CRL, so reject it (fail closed) rather
            // than load a no-op file.
            if bytes.is_empty() {
                return Err(format!("client CRL {path}: file is empty"));
            }
            crls.push(CertificateRevocationListDer::from(bytes));
        } else {
            crls.extend(pem);
        }
    }
    Ok(crls)
}

/// Load offline policy-layer revocation ids (ADR-MCPS-013) from zero or more
/// newline-delimited files. Each non-blank, non-`#`-comment line (trimmed) is one
/// opaque `revocation_id`. If `paths` is empty, returns an empty list.
/// Mirrors [`load_client_crls`]: OFFLINE only (loaded once at startup; restart to update)
/// and FAIL CLOSED — a missing/unreadable file, or a file that yields zero ids, is an error rather than a silently empty deny-list
/// that would quietly disable revocation.
pub fn load_revocation_list(paths: &[String]) -> Result<Vec<String>, String> {
    let mut ids: Vec<String> = Vec::new();
    for path in paths {
        let text =
            std::fs::read_to_string(path).map_err(|e| format!("revocation list {path}: {e}"))?;
        let before = ids.len();
        for line in text.lines() {
            let id = line.trim();
            if id.is_empty() || id.starts_with('#') {
                continue;
            }
            ids.push(id.to_string());
        }
        if ids.len() == before {
            return Err(format!(
                "revocation list {path}: contains no revocation ids (fail closed rather \
                 than load an empty deny-list)"
            ));
        }
    }
    Ok(ids)
}

/// Build the ONLINE OCSP checker selected by `--client-ocsp require` (#4030),
/// or `None` when `--client-ocsp off` (the default). Compiled ONLY under the
/// `online_ocsp` feature; `parse_args` already fails closed for `require` in a
/// build without the feature, so this is only reached with the backend present.
///
/// The checker uses `ocsp_responder_url` as the AIA override (else the leaf's
/// AIA OCSP URL) and ALWAYS fails closed on an indeterminate result (the
/// `--ocsp-soft-fail` fail-open relaxation was removed). Its HTTP fetch carries a
/// mandatory timeout (fail closed on timeout) so it can never wedge the blocking
/// serve loop.
#[cfg(feature = "online_ocsp")]
pub fn build_ocsp_checker(config: &Config) -> Option<crate::ocsp::OcspChecker> {
    match config.client_ocsp {
        OcspKind::Off => None,
        // Hard-fail (fail closed) always: OCSP has no soft-fail knob any more.
        OcspKind::Require => Some(crate::ocsp::OcspChecker::new(
            config.ocsp_responder_url.clone(),
            false,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::build_attested_ingress_binding;
    use super::load_revocation_list;
    use super::load_trust;
    use super::parse_args;
    use super::unsafe_config_violations;
    use super::AuthzKind;
    use super::BindingKind;
    use super::IdentityPolicy;
    use super::KeySourceKind;
    use super::OcspKind;
    use super::ReplayKind;
    use super::ReverseProxyHeaderFormat;
    use mcp_re_core::SigningKey;
    use mcp_re_core::TrustResolver;
    use std::sync::Arc;
    use std::sync::Mutex;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    // ---- KMS endpoint override validation (C054) --------------------------

    /// Parse `minimal()` plus one KMS endpoint override.
    fn with_kms_endpoint(flag: &str, endpoint: &str) -> Result<super::Config, String> {
        let mut a = minimal();
        // `minimal()` omits --replay-cache, which `unsafe_config_violations` refuses; that
        // refusal is unrelated to endpoint validation and would mask an accept case.
        a.extend(args(&[
            "--replay-cache",
            "file",
            "--replay-path",
            "/tmp/mcp-re-cli-kms-endpoint-test",
        ]));
        a.push(flag.to_string());
        a.push(endpoint.to_string());
        parse_args(&a)
    }

    #[test]
    fn an_https_kms_endpoint_is_accepted() {
        for flag in ["--aws-kms-endpoint", "--gcp-kms-endpoint"] {
            let r = with_kms_endpoint(flag, "https://kms.example.internal");
            assert!(r.is_ok(), "{flag} must accept https, got {:?}", r.err());
        }
    }

    /// The emulator lane (LocalStack et al.) must keep working: plaintext to LOOPBACK
    /// cannot carry a credential off the machine.
    #[test]
    fn a_loopback_http_kms_endpoint_is_accepted_for_emulators() {
        for endpoint in [
            "http://localhost:4566",
            "http://127.0.0.1:4566/",
            "http://[::1]:4566",
        ] {
            assert!(
                with_kms_endpoint("--aws-kms-endpoint", endpoint).is_ok(),
                "{endpoint} is a loopback emulator and must be accepted"
            );
        }
    }

    /// The finding: plaintext to a NON-loopback host hands a live GCP workload-identity
    /// bearer token to that host and lets it serve the root verify key the whole
    /// verify-before-return guardrail is measured against.
    #[test]
    fn a_plaintext_kms_endpoint_to_a_remote_host_is_refused() {
        for flag in ["--aws-kms-endpoint", "--gcp-kms-endpoint"] {
            let err = with_kms_endpoint(flag, "http://kms.attacker.test")
                .expect_err("plaintext to a remote host must be refused");
            assert!(
                err.contains("loopback"),
                "the refusal must name the loopback exception, got {err:?}"
            );
        }
    }

    #[test]
    fn a_non_http_kms_endpoint_scheme_is_refused() {
        for endpoint in ["file:///etc/passwd", "kms.example.internal", "ftp://x.test"] {
            assert!(
                with_kms_endpoint("--gcp-kms-endpoint", endpoint).is_err(),
                "{endpoint} is not an absolute http(s) URL and must be refused"
            );
        }
    }

    #[test]
    fn a_kms_endpoint_with_no_host_is_refused() {
        for endpoint in ["https://", "http:///v1", "https:///"] {
            assert!(
                with_kms_endpoint("--aws-kms-endpoint", endpoint).is_err(),
                "{endpoint} has no authority and must be refused"
            );
        }
    }

    fn minimal() -> Vec<String> {
        args(&[
            "--bind",
            "127.0.0.1:8443",
            "--audience",
            "did:example:server-1",
            "--server-signer",
            "did:example:server-1",
            "--server-key-id",
            "server-key-1",
            "--signing-key-seed",
            "/seed",
            "--tls-cert",
            "/cert",
            "--tls-key",
            "/key",
            "--client-ca",
            "/ca",
            "--trust",
            "/trust.json",
            "--inner-http-url",
            "http://127.0.0.1:8080/mcp",
            // The RFC 9421 @target-uri this deployment binds to. Required and
            // non-empty: an empty target makes the audience/target conjunction a
            // tautology, so it is refused at parse.
            "--target-uri",
            "https://mcp.example.com/mcp",
            // Delegated-signing is the only response mode; the trust epoch is required
            // for every config (ADR-MCPRE-052 §7).
            "--delegated-trust-epoch",
            "epoch-min",
            // Required: it used to default to the `example.com` placeholder the Helm
            // chart refuses, so the binary accepted the one value the chart exists to
            // reject.
            "--trust-domain",
            "mcp.example.com",
        ])
    }

    /// The same required flags as `minimal()` but WITHOUT any inner-server selection,
    /// so a test can supply `--inner-http-url` itself (or assert the missing-inner
    /// error).
    fn minimal_without_inner_command() -> Vec<String> {
        args(&[
            "--bind",
            "127.0.0.1:8443",
            "--audience",
            "did:example:server-1",
            "--server-signer",
            "did:example:server-1",
            "--server-key-id",
            "server-key-1",
            "--signing-key-seed",
            "/seed",
            "--tls-cert",
            "/cert",
            "--tls-key",
            "/key",
            "--client-ca",
            "/ca",
            "--trust",
            "/trust.json",
            "--target-uri",
            "https://mcp.example.com/mcp",
            "--delegated-trust-epoch",
            "epoch-min",
            "--trust-domain",
            "mcp.example.com",
        ])
    }

    /// A durable single-node replay selection (`--replay-cache file --replay-path
    /// <p>`). The DEFAULT replay backend is the non-durable in-memory cache, which
    /// is a production violation (#90, ADR-MCPS-014/020): a restart forgets admitted
    /// nonces and re-opens a replay window. The proxy always runs the strict/
    /// production posture, so ANY config that must parse SUCCESSFULLY has to declare
    /// a durable backend — tests splice these flags into `minimal()`.
    fn durable_replay() -> Vec<String> {
        args(&["--replay-cache", "file", "--replay-path", "/replay"])
    }

    /// `minimal()` plus a durable replay backend — the smallest config that PARSES
    /// under the unconditional strict/production posture (the bare in-memory default
    /// is rejected, #90). Success tests that do not exercise replay selection build
    /// on this.
    fn minimal_durable() -> Vec<String> {
        let mut a = minimal();
        a.splice(0..0, durable_replay());
        a
    }

    // --- MCPRE-493 admission currency ----------------------------------------

    /// The full set an enforcing deployment must supply.
    fn admission_args(mode: &str) -> Vec<String> {
        args(&[
            "--admission",
            mode,
            "--admission-authority-kid",
            "admission-root-1",
            "--admission-authority-pubkey",
            "1i8Bah79Hk_feT60LNhEceG6nwzwTRKHtcxx9hYofLg",
            "--admission-redis-url",
            "redis://127.0.0.1:6379",
        ])
    }

    #[test]
    fn admission_is_off_by_default() {
        // A deployment that has not asked for admission must not get a gate it did
        // not configure — and, more importantly, must not believe it has one.
        let config = parse_args(&minimal_durable()).expect("parses");
        assert_eq!(config.admission, super::AdmissionKind::Off);
    }

    #[test]
    fn enforcing_admission_parses_with_an_authority_and_a_source() {
        for mode in ["optional", "required"] {
            let mut a = minimal_durable();
            a.splice(0..0, admission_args(mode));
            let config =
                parse_args(&a).unwrap_or_else(|e| panic!("--admission {mode} must parse: {e}"));
            assert_ne!(config.admission, super::AdmissionKind::Off);
            assert!(config.admission_redis_url.is_some());
        }
    }

    #[test]
    fn enforcing_admission_without_an_authority_is_refused() {
        // The worst of the three states: a gate that looks enabled and verifies
        // nothing, because no issuer is trusted to have said anything.
        let mut a = minimal_durable();
        a.splice(
            0..0,
            args(&[
                "--admission",
                "required",
                "--admission-redis-url",
                "redis://127.0.0.1:6379",
            ]),
        );
        let err = parse_args(&a).expect_err("an authority is required");
        assert!(err.contains("--admission-authority-kid"), "got: {err}");
    }

    #[test]
    fn enforcing_admission_without_a_source_is_refused() {
        // Currency is a comparison; with nothing to compare against, every call would
        // fail closed on an unreachable authority and the deployment would look broken
        // rather than misconfigured.
        let mut a = minimal_durable();
        a.splice(
            0..0,
            args(&[
                "--admission",
                "required",
                "--admission-authority-kid",
                "admission-root-1",
                "--admission-authority-pubkey",
                "1i8Bah79Hk_feT60LNhEceG6nwzwTRKHtcxx9hYofLg",
            ]),
        );
        let err = parse_args(&a).expect_err("a source is required");
        assert!(err.contains("--admission-redis-url"), "got: {err}");
    }

    #[test]
    fn a_dangling_admission_setting_is_refused() {
        // It reads as "admission is configured" to anyone auditing the command line,
        // while nothing is enforced.
        let mut a = minimal_durable();
        a.splice(
            0..0,
            args(&["--admission-redis-url", "redis://127.0.0.1:6379"]),
        );
        let err = parse_args(&a).expect_err("a dangling admission setting is refused");
        assert!(err.contains("--admission is off"), "got: {err}");
    }

    #[test]
    fn degraded_mode_requires_a_positive_bound() {
        // Degraded mode is a BOUNDED window. Zero is not a window — it would fail
        // closed on every unreachable-authority call while claiming one exists.
        let mut a = minimal_durable();
        a.splice(0..0, admission_args("required"));
        a.push("--admission-allow-degraded".into());
        a.push("true".into());
        let err = parse_args(&a).expect_err("P must be positive");
        assert!(
            err.contains("--admission-degraded-bound-secs"),
            "got: {err}"
        );

        a.push("--admission-degraded-bound-secs".into());
        a.push("120".into());
        let config = parse_args(&a).expect("a bounded degraded window parses");
        assert!(config.admission_allow_degraded);
        assert_eq!(config.admission_degraded_bound_secs, 120);
    }

    #[test]
    fn an_unknown_admission_mode_is_refused() {
        let mut a = minimal_durable();
        a.splice(0..0, args(&["--admission", "sometimes"]));
        let err = parse_args(&a).expect_err("the mode set is closed");
        assert!(err.contains("off|optional|required"), "got: {err}");
    }

    // --- §5.1 bounded skew / §4.1 MCP transport contract ----------------------

    #[test]
    fn max_clock_skew_is_accepted_across_the_whole_bound() {
        for skew in [
            0,
            1,
            30,
            299,
            mcp_re_http_profile::VerifierPolicy::MAX_CLOCK_SKEW_BOUND,
        ] {
            let mut a = minimal_durable();
            a.push("--max-clock-skew".into());
            a.push(skew.to_string());
            let config = parse_args(&a).unwrap_or_else(|e| panic!("skew {skew} must parse: {e}"));
            assert_eq!(config.max_clock_skew, skew);
        }
    }

    /// A skew the freshness gate would refuse must be refused at the command line —
    /// not accepted and then silently applied to replay retention alone.
    #[test]
    fn out_of_bounds_max_clock_skew_is_refused_at_parse() {
        for skew in [-1, -30, 301, 3600] {
            let mut a = minimal_durable();
            a.push("--max-clock-skew".into());
            a.push(skew.to_string());
            let err = parse_args(&a)
                .err()
                .unwrap_or_else(|| panic!("skew {skew} must be refused"));
            assert!(err.contains("--max-clock-skew must be"), "got: {err}");
        }
    }

    /// An empty `--target-uri` would make the audience/target conjunction compare
    /// `"" == ""` on every request. Refused at parse rather than served.
    #[test]
    fn empty_or_missing_target_uri_is_refused() {
        let base: Vec<String> = minimal_durable().into_iter().collect::<Vec<_>>();
        // The helper supplies --target-uri; drop it to prove it is required.
        let mut without = Vec::new();
        let mut skip = false;
        for a in &base {
            if skip {
                skip = false;
                continue;
            }
            if a == "--target-uri" {
                skip = true;
                continue;
            }
            without.push(a.clone());
        }
        let err = parse_args(&without).expect_err("--target-uri must be required");
        assert!(err.contains("--target-uri"), "got: {err}");

        for empty in ["", "   "] {
            let mut a = without.clone();
            a.push("--target-uri".into());
            a.push(empty.into());
            let err = parse_args(&a).expect_err("an empty --target-uri must be refused");
            assert!(err.contains("must not be empty"), "got: {err}");
        }
    }

    /// MCPRE-114: the bounded-admission ceiling exists in `async_serve`/`async_fleet`
    /// but had NO CLI flag, so no shipped configuration could enable it — the proxy
    /// always ran unbounded in-flight. Both knobs must reach the config, and the
    /// no-flags case must be BOUNDED: unbounded in-flight is attacker-controlled
    /// buffering ahead of the verify gate.
    #[test]
    fn admission_ceilings_are_configurable_and_bounded_by_default() {
        let config = parse_args(&minimal_durable()).expect("parse");
        assert_eq!(
            config.limits.max_in_flight_requests,
            Some(256),
            "a per-core ceiling applies with no flags at all"
        );
        assert_eq!(config.max_in_flight_total, None);

        let mut a = minimal_durable();
        a.splice(
            0..0,
            args(&["--max-in-flight", "32", "--max-in-flight-total", "256"]),
        );
        let config = parse_args(&a).expect("parse");
        assert_eq!(config.limits.max_in_flight_requests, Some(32));
        assert_eq!(config.max_in_flight_total, Some(256));
    }

    /// The per-core DEFAULT must not out-rank an explicit fleet-wide target: with
    /// only `--max-in-flight-total`, the per-core ceiling is cleared so
    /// `derived_per_core_ceiling` divides the target across cores.
    #[test]
    fn a_fleet_wide_target_alone_clears_the_per_core_default() {
        let mut a = minimal_durable();
        a.splice(0..0, args(&["--max-in-flight-total", "256"]));
        let config = parse_args(&a).expect("parse");
        assert_eq!(
            config.limits.max_in_flight_requests, None,
            "the default must yield to an explicit global target"
        );
        assert_eq!(config.max_in_flight_total, Some(256));
    }

    /// The connection-age bound is what re-checks a client certificate against an
    /// expiry or a reloaded CRL; disabling it is an unsafe configuration.
    #[test]
    fn the_connection_age_bound_is_defaulted_and_zero_is_refused() {
        let config = parse_args(&minimal_durable()).expect("parse");
        assert_eq!(
            config.limits.max_connection_age,
            Some(std::time::Duration::from_secs(300))
        );
        assert!(unsafe_config_violations(&config).is_empty());

        // `parse_args` applies `unsafe_config_violations` unconditionally, so
        // disabling the bound never produces a Config at all.
        let mut a = minimal_durable();
        a.splice(0..0, args(&["--max-connection-age-secs", "0"]));
        let err = parse_args(&a).expect_err("a disabled connection-age bound is refused");
        assert!(err.contains("--max-connection-age-secs"), "got: {err}");
    }

    /// Zero would silently mean "admit nothing"; refuse it rather than serve a proxy
    /// that 503s every request.
    #[test]
    fn zero_admission_ceiling_is_refused() {
        for flag in ["--max-in-flight", "--max-in-flight-total"] {
            let mut a = minimal_durable();
            a.splice(0..0, args(&[flag, "0"]));
            let err = parse_args(&a).expect_err("zero must be refused");
            assert!(err.contains("must be > 0"), "got: {err}");
        }
    }

    #[test]
    fn mcp_protocol_version_is_repeatable_and_absent_by_default() {
        let mut a = minimal_durable();
        a.push("--mcp-protocol-version".into());
        a.push("2026-07-28".into());
        a.push("--mcp-protocol-version".into());
        a.push("2025-06-18".into());
        let config = parse_args(&a).expect("parse");
        assert_eq!(
            config.mcp_protocol_versions,
            vec!["2026-07-28", "2025-06-18"]
        );
    }

    // --- ADR-MCPRE-052 (MCPRE-122) delegated-signing (the only mode) -----------

    #[test]
    fn delegated_signing_parses_with_defaults() {
        // `minimal()` already supplies the required --delegated-trust-epoch.
        let config = parse_args(&minimal_durable()).expect("parse delegated-signing");
        assert_eq!(config.delegated_trust_epoch.as_deref(), Some("epoch-min"));
        // Defaults: T=300, O=60; issuer kid / audience hash default at build time.
        assert_eq!(config.delegated_ttl_secs, 300);
        assert_eq!(config.delegated_overlap_secs, 60);
        assert_eq!(config.delegated_issuer_kid, None);
        assert_eq!(config.delegated_audience_hash, None);
    }

    #[test]
    fn missing_trust_epoch_is_rejected() {
        // A config WITHOUT the required trust epoch (built by hand, since `minimal()`
        // now includes it) fails closed — the epoch is mandatory for every deployment.
        let a = args(&[
            "--replay-cache",
            "file",
            "--replay-path",
            "/replay",
            "--bind",
            "127.0.0.1:8443",
            "--audience",
            "did:example:server-1",
            "--server-signer",
            "did:example:server-1",
            "--server-key-id",
            "server-key-1",
            "--signing-key-seed",
            "/seed",
            "--tls-cert",
            "/cert",
            "--tls-key",
            "/key",
            "--client-ca",
            "/ca",
            "--trust",
            "/trust.json",
            "--inner-http-url",
            "http://127.0.0.1:8080/mcp",
        ]);
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--delegated-trust-epoch"), "got: {err}");
    }

    #[test]
    fn delegated_overlap_not_less_than_ttl_is_rejected() {
        let mut a = minimal_durable();
        a.extend(args(&[
            "--delegated-ttl-secs",
            "100",
            "--delegated-overlap-secs",
            "100",
        ]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("0 < overlap < ttl"), "got: {err}");
    }

    #[test]
    fn parses_a_minimal_config_with_defaults() {
        // The bare in-memory replay default is a strict/production violation (#90),
        // and the proxy always runs strict, so a minimal PARSEABLE config declares a
        // durable replay backend; every other value here is a plain default.
        let config = parse_args(&minimal_durable()).expect("parse");
        assert_eq!(config.bind, "127.0.0.1:8443");
        assert_eq!(config.audience, "did:example:server-1");
        // The default skew is the profile's own, so the freshness gate the verifier
        // runs and the retention the replay tier applies cannot drift apart.
        assert_eq!(
            config.max_clock_skew,
            mcp_re_http_profile::VerifierPolicy::DEFAULT_MAX_CLOCK_SKEW
        );
        assert!(config.mcp_protocol_versions.is_empty());
        assert_eq!(config.key_source, KeySourceKind::File);
        assert_eq!(config.replay, ReplayKind::File);
        assert_eq!(config.binding, BindingKind::Exact);
        // Safe defaults: URI SAN identity, bounded resources.
        assert_eq!(config.identity_source, IdentityPolicy::UriSan);
        assert_eq!(config.authz, AuthzKind::Off);
        assert_eq!(config.limits.max_header_bytes, 64 * 1024);
        assert_eq!(config.limits.max_body_bytes, 16 * 1024 * 1024);
        assert_eq!(config.limits.max_concurrent_connections, 256);
        assert!(config.limits.read_timeout.is_some());
        // Aggregate read-phase wall-clock deadline (slow-loris defense) defaults on.
        assert_eq!(
            config.limits.request_deadline,
            Some(std::time::Duration::from_secs(30))
        );
        // v1 revocation posture: enforced 1-hour client-cert lifetime by default.
        assert_eq!(
            config.max_client_cert_lifetime,
            Some(std::time::Duration::from_secs(3600))
        );
        assert_eq!(
            config.inner_http_urls,
            vec!["http://127.0.0.1:8080/mcp".to_string()]
        );
    }

    #[test]
    fn parses_client_cert_lifetime_forms() {
        // Only lifetimes at/below the strict ceiling parse (the proxy always runs
        // strict): `none`/`0` (disabled) and over-ceiling values are hard errors,
        // covered by the strict_rejects_* cert-lifetime tests.
        let cases = [("30m", 1800), ("60m", 3600), ("90s", 90), ("45", 45)];
        for (input, expected) in cases {
            let mut a = minimal_durable();
            a.splice(0..0, args(&["--max-client-cert-lifetime", input]));
            let got = parse_args(&a).expect("parse").max_client_cert_lifetime;
            assert_eq!(
                got,
                Some(std::time::Duration::from_secs(expected)),
                "input {input}"
            );
        }
    }

    #[test]
    fn unparseable_client_cert_lifetime_errors() {
        let mut a = minimal();
        a.splice(0..0, args(&["--max-client-cert-lifetime", "soon"]));
        assert!(parse_args(&a)
            .unwrap_err()
            .contains("max-client-cert-lifetime"));
    }

    #[test]
    fn parses_identity_source_selection() {
        // uri_san (default) and dns_san are the production-acceptable sources; the
        // deprecated cn_legacy is always rejected (strict_rejects_cn_legacy_...).
        let mut a = minimal_durable();
        a.splice(0..0, args(&["--transport-identity-source", "uri_san"]));
        assert_eq!(
            parse_args(&a).expect("parse").identity_source,
            IdentityPolicy::UriSan
        );

        let mut a = minimal_durable();
        a.splice(0..0, args(&["--transport-identity-source", "dns_san"]));
        assert_eq!(
            parse_args(&a).expect("parse").identity_source,
            IdentityPolicy::DnsSan
        );
    }

    #[test]
    fn unknown_identity_source_errors() {
        let mut a = minimal();
        a.splice(0..0, args(&["--transport-identity-source", "email_san"]));
        assert!(parse_args(&a).unwrap_err().contains("email_san"));
    }

    // --- MCPS-3840 reverse-proxy ingress flags --------------------------------

    #[test]
    fn no_reverse_proxy_header_by_default() {
        let config = parse_args(&minimal_durable()).expect("parse");
        assert_eq!(config.reverse_proxy_identity_header, None);
        // The default format is irrelevant when the header is unset, but it is
        // the safer XFCC (structured) shape rather than the trust-the-whole-value
        // plain shape.
        assert_eq!(
            config.reverse_proxy_header_format,
            ReverseProxyHeaderFormat::Xfcc
        );
    }

    // NOTE: reverse-proxy identity-header ingress is a spoofable posture that the
    // unconditional strict/production posture always rejects (see
    // `strict_rejects_reverse_proxy_identity_header_ingress`), so there is no
    // successful-parse test for the header-format selection — the mode never parses.

    #[test]
    fn unknown_reverse_proxy_header_format_errors() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--reverse-proxy-identity-header",
                "x-client-identity",
                "--reverse-proxy-header-format",
                "der",
                "--max-client-cert-lifetime",
                "none",
            ]),
        );
        assert!(parse_args(&a).unwrap_err().contains("der"));
    }

    #[test]
    fn empty_reverse_proxy_header_name_errors() {
        let mut a = minimal();
        a.splice(0..0, args(&["--reverse-proxy-identity-header", "   "]));
        assert!(parse_args(&a)
            .unwrap_err()
            .contains("non-empty header name"));
    }

    // ---- ADR-MCPS-023 Tier 3 (issue #71): LB-signed request-bound assertion ----

    /// A valid base64url-no-pad 32-byte Ed25519 public key for `--ingress-lb-key`.
    fn lb_pub_b64() -> String {
        mcp_re_core::SigningKey::from_seed_bytes(&[5u8; 32])
            .public_key()
            .to_b64url()
    }

    // NOTE: lb-assertion is always rejected under the unconditional strict/production
    // posture (see `strict_rejects_lb_assertion_binding`), so there is no
    // successful-parse test for it — only the parse-time argument guards below and
    // the strict rejection are exercised.

    #[test]
    fn lb_assertion_binding_requires_at_least_one_key() {
        // `lb-assertion` with no trusted LB key can never verify any assertion —
        // fail closed at parse time rather than reject every request.
        let mut a = minimal();
        a.splice(0..0, args(&["--transport-binding", "lb-assertion"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--ingress-lb-key"), "got: {err}");
    }

    #[test]
    fn ingress_lb_key_without_lb_assertion_binding_errors() {
        // A dangling `--ingress-lb-key` (without selecting the binding) would
        // silently do nothing — an illusion of request-bound ingress. Reject it.
        let mut a = minimal();
        a.splice(
            0..0,
            args(&["--ingress-lb-key", &format!("lb-1:{}", lb_pub_b64())]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("has no effect"), "got: {err}");
    }

    #[test]
    fn ingress_lb_key_malformed_value_errors() {
        // Missing the `:` separator.
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--transport-binding",
                "lb-assertion",
                "--ingress-lb-key",
                "no-colon-here",
            ]),
        );
        assert!(parse_args(&a).unwrap_err().contains("keyid"));
    }

    #[test]
    fn ingress_lb_key_invalid_public_key_errors() {
        // A syntactically-correct `<id>:<body>` whose body is NOT a valid Ed25519
        // public key fails closed at parse time.
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--transport-binding",
                "lb-assertion",
                "--ingress-lb-key",
                "lb-1:not-a-real-key",
            ]),
        );
        assert!(parse_args(&a).unwrap_err().contains("Ed25519 public key"));
    }

    #[test]
    fn duplicate_ingress_lb_key_id_errors() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--transport-binding",
                "lb-assertion",
                "--ingress-lb-key",
                &format!("lb-1:{}", lb_pub_b64()),
                "--ingress-lb-key",
                &format!("lb-1:{}", lb_pub_b64()),
            ]),
        );
        assert!(parse_args(&a).unwrap_err().contains("duplicate"));
    }

    #[test]
    fn strict_rejects_lb_assertion_binding() {
        // Tier 3 places the LB in the TCB (request-bound INGRESS assertion, NOT
        // end-to-end mTLS); the unconditional strict/production posture refuses it.
        // Durable replay isolates lb-assertion as the sole violation.
        let mut a = minimal_durable();
        a.splice(
            0..0,
            args(&[
                "--transport-binding",
                "lb-assertion",
                "--ingress-lb-key",
                &format!("lb-1:{}", lb_pub_b64()),
            ]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(
            err.contains("lb-assertion") && err.contains("end-to-end"),
            "got: {err}"
        );
    }

    // ---------------------------------------------------------------------
    // ADR-MCPS-023 §C (v0.10) Mode C attested ingress (MCPS-61).
    // ---------------------------------------------------------------------

    /// A distinct valid Ed25519 public key for `--ingress-attestor-key`.
    fn attestor_pub_b64() -> String {
        mcp_re_core::SigningKey::from_seed_bytes(&[9u8; 32])
            .public_key()
            .to_b64url()
    }

    /// The full, valid set of Mode-C flags (attestor key + ingress identity +
    /// audience + pinned-mTLS ack). Prepend `--strict`/etc. as needed.
    fn attested_ingress_flags() -> Vec<String> {
        args(&[
            "--transport-binding",
            "attested-ingress",
            "--ingress-attestor-key",
            &format!("attestor-1:{}", attestor_pub_b64()),
            "--ingress-identity",
            "spiffe://example.org/ingress-1",
            "--ingress-audience",
            "did:example:server-1",
            "--ingress-pinned-mtls",
        ])
    }

    #[test]
    fn parses_attested_ingress_binding_fully_configured() {
        // Attested ingress is strict-ADMITTED, so a durable-replay base parses.
        let mut a = minimal_durable();
        a.splice(0..0, attested_ingress_flags());
        let config = parse_args(&a).expect("parse");
        assert_eq!(config.binding, BindingKind::AttestedIngress);
        assert_eq!(config.ingress_attestor_keys.len(), 1);
        assert_eq!(
            config.ingress_identities,
            vec!["spiffe://example.org/ingress-1"]
        );
        assert_eq!(
            config.ingress_audience.as_deref(),
            Some("did:example:server-1")
        );
        assert!(config.ingress_pinned_mtls);
        // The verifier builds.
        assert!(build_attested_ingress_binding(&config)
            .expect("build")
            .is_some());
    }

    #[test]
    fn attested_ingress_is_admitted_under_strict() {
        // Unlike Mode B (lb-assertion), Mode C is a strict-ADMITTED explicit opt-in.
        let mut a = minimal();
        a.splice(0..0, durable_replay());
        a.splice(0..0, attested_ingress_flags());
        let config = parse_args(&a).expect("Mode C must be admitted under the strict posture");
        assert_eq!(config.binding, BindingKind::AttestedIngress);
        assert!(
            unsafe_config_violations(&config).is_empty(),
            "Mode C is strict-admitted: it must raise no strict violations, got {:?}",
            unsafe_config_violations(&config)
        );
    }

    #[test]
    fn attested_ingress_without_pinned_mtls_fails_closed() {
        // §C2: the pinned attestor→node channel is load-bearing — absent the
        // explicit acknowledgement, attested ingress refuses to start.
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--transport-binding",
                "attested-ingress",
                "--ingress-attestor-key",
                &format!("attestor-1:{}", attestor_pub_b64()),
                "--ingress-identity",
                "spiffe://example.org/ingress-1",
                "--ingress-audience",
                "did:example:server-1",
                // no --ingress-pinned-mtls
            ]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--ingress-pinned-mtls"), "got: {err}");
    }

    #[test]
    fn attested_ingress_requires_attestor_key_identity_and_audience() {
        // Each missing piece fails closed with a precise error.
        let base = args(&[
            "--transport-binding",
            "attested-ingress",
            "--ingress-pinned-mtls",
        ]);
        // Missing attestor key.
        let mut a = minimal();
        a.splice(0..0, base.clone());
        assert!(parse_args(&a)
            .unwrap_err()
            .contains("--ingress-attestor-key"));
        // Missing ingress identity.
        let mut a = minimal();
        let mut f = base.clone();
        f.extend(args(&[
            "--ingress-attestor-key",
            &format!("attestor-1:{}", attestor_pub_b64()),
        ]));
        a.splice(0..0, f);
        assert!(parse_args(&a).unwrap_err().contains("--ingress-identity"));
        // Missing audience.
        let mut a = minimal();
        let mut f = base.clone();
        f.extend(args(&[
            "--ingress-attestor-key",
            &format!("attestor-1:{}", attestor_pub_b64()),
            "--ingress-identity",
            "spiffe://example.org/ingress-1",
        ]));
        a.splice(0..0, f);
        assert!(parse_args(&a).unwrap_err().contains("--ingress-audience"));
    }

    #[test]
    fn attested_ingress_flags_dangle_without_binding() {
        // Each Mode-C flag has no effect outside attested-ingress → reject.
        for (flag, val) in [
            (
                "--ingress-attestor-key",
                format!("attestor-1:{}", attestor_pub_b64()),
            ),
            (
                "--ingress-identity",
                "spiffe://example.org/ingress-1".to_string(),
            ),
            ("--ingress-audience", "did:example:server-1".to_string()),
        ] {
            let mut a = minimal();
            a.splice(0..0, args(&[flag, &val]));
            let err = parse_args(&a).unwrap_err();
            assert!(err.contains("has no effect"), "flag {flag} → got: {err}");
        }
        // The pinned-mTLS boolean too.
        let mut a = minimal();
        a.splice(0..0, args(&["--ingress-pinned-mtls"]));
        assert!(parse_args(&a).unwrap_err().contains("has no effect"));
    }

    #[test]
    fn attested_ingress_invalid_attestor_key_errors() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--transport-binding",
                "attested-ingress",
                "--ingress-attestor-key",
                "attestor-1:not-a-real-key",
                "--ingress-identity",
                "spiffe://example.org/ingress-1",
                "--ingress-audience",
                "did:example:server-1",
                "--ingress-pinned-mtls",
            ]),
        );
        assert!(parse_args(&a).unwrap_err().contains("Ed25519 public key"));
    }

    #[test]
    fn attested_ingress_rejects_reverse_proxy_header() {
        // Mode C resolves identity from the assertion; a reverse-proxy identity
        // header would be a silently-ignored second source → reject the combination.
        let mut a = minimal();
        let mut flags = attested_ingress_flags();
        // A reverse-proxy header disables the local client-cert path, so acknowledge
        // that first — otherwise the cert-lifetime guard fires before the Mode-C one.
        flags.extend(args(&[
            "--reverse-proxy-identity-header",
            "x-forwarded-client-cert",
            "--max-client-cert-lifetime",
            "none",
        ]));
        a.splice(0..0, flags);
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("mutually exclusive"), "got: {err}");
    }

    #[test]
    fn reverse_proxy_mode_conflicts_with_local_cert_lifetime() {
        // The default 1h client-cert lifetime is a LOCAL-mTLS control. Enabling
        // reverse-proxy mode (mTLS terminated upstream) while it is still in force
        // is contradictory and must fail closed at parse time.
        let mut a = minimal();
        a.splice(
            0..0,
            args(&["--reverse-proxy-identity-header", "x-forwarded-client-cert"]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(
            err.contains("reverse-proxy-identity-header")
                && err.contains("max-client-cert-lifetime none"),
            "expected a mutual-exclusion error pointing at the fix; got: {err}"
        );
    }

    // In a production build (no `dev_env_key_source` feature) the env key source does
    // not exist at all — `--key-source env` is an unknown value, not a togglable
    // downgrade. The dev feature is the ONLY way to compile it in.
    #[cfg(not(feature = "dev_env_key_source"))]
    #[test]
    fn env_key_source_rejected_in_production_build() {
        let mut a = minimal();
        a.splice(0..0, args(&["--key-source", "env"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("unknown --key-source"), "got: {err}");
        assert!(err.contains("env"), "got: {err}");
    }

    // NOTE: the env key source is never accepted (the `--allow-env-keysource`
    // opt-out qualifier is rejected and the unconditional strict posture refuses env
    // key material), so `--key-source env` cannot reach a built key source — the
    // `env_key_source_requires_explicit_opt_in` guard above is the operative gate.

    // --- #4034 PKCS#11 key source (CLI parsing + fail-closed gate) -----------

    /// The four pkcs11 flags that `--key-source pkcs11` requires.
    fn pkcs11_flags() -> Vec<String> {
        args(&[
            "--key-source",
            "pkcs11",
            "--pkcs11-module",
            "/opt/pkcs11/libmock_pkcs11.so",
            "--pkcs11-pin-file",
            "/etc/mcp-re/pkcs11-pin",
            "--pkcs11-token-label",
            "mcp-re-test",
            "--pkcs11-key-label",
            "mcp-re-response-signing",
        ])
    }

    #[test]
    fn parses_pkcs11_key_source_flags() {
        let mut a = minimal_durable();
        a.splice(0..0, pkcs11_flags());
        let config = parse_args(&a).expect("parse");
        assert_eq!(config.key_source, KeySourceKind::Pkcs11);
        assert_eq!(
            config.pkcs11_module.as_deref(),
            Some("/opt/pkcs11/libmock_pkcs11.so")
        );
        assert_eq!(
            config.pkcs11_pin_file.as_deref(),
            Some("/etc/mcp-re/pkcs11-pin"),
            "the config carries the PIN's PATH; the PIN itself is not a Config field"
        );
        assert_eq!(config.pkcs11_token_label.as_deref(), Some("mcp-re-test"));
        assert_eq!(
            config.pkcs11_key_label.as_deref(),
            Some("mcp-re-response-signing")
        );
    }

    #[test]
    fn pkcs11_key_source_requires_each_flag() {
        // Drop one required flag at a time; each omission is a clear parse error
        // naming the missing flag. (File/env arms are unchanged: --signing-key-seed
        // and the TLS paths are supplied by `minimal()`.)
        for missing in [
            "--pkcs11-module",
            "--pkcs11-pin-file",
            "--pkcs11-token-label",
            "--pkcs11-key-label",
        ] {
            let mut flags = pkcs11_flags();
            // Remove the flag and its value.
            let idx = flags
                .iter()
                .position(|f| f == missing)
                .expect("flag present");
            flags.drain(idx..idx + 2);
            let mut a = minimal();
            a.splice(0..0, flags);
            let err = parse_args(&a).unwrap_err();
            assert!(
                err.contains(missing),
                "expected error to name {missing}; got: {err}"
            );
        }
    }

    #[test]
    fn argv_pkcs11_pin_is_refused_with_the_replacement_named() {
        // C048: argv is world-readable, so a PIN there is a standing exposure. The flag
        // is still recognised so the refusal explains WHY and what to use instead —
        // falling through to "unknown flag" would report a secret-handling decision as
        // a typo.
        let mut a = minimal_durable();
        a.splice(0..0, pkcs11_flags());
        a.extend(args(&["--pkcs11-pin", "1234"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--pkcs11-pin is refused"), "got: {err}");
        assert!(
            err.contains("--pkcs11-pin-file"),
            "the replacement must be named: {err}"
        );
        assert!(
            err.contains("compromised"),
            "the operator must be told the PIN already leaked: {err}"
        );
        assert!(
            !err.contains("1234"),
            "the refusal must not echo the secret it is refusing: {err}"
        );
    }

    #[test]
    fn a_secret_string_does_not_print_its_value_or_length() {
        // C049: Config derives Debug and is cloned freely. The PIN is no longer a Config
        // field at all, but the type that carries it in transit must not leak either.
        let secret = super::SecretString::new("hunter2");
        let rendered = format!("{secret:?}");
        assert!(
            !rendered.contains("hunter2"),
            "Debug leaked the value: {rendered}"
        );
        assert!(
            !rendered.contains('7'),
            "Debug leaked the length: {rendered}"
        );
        assert_eq!(
            secret.expose(),
            "hunter2",
            "the value is still retrievable on purpose"
        );
    }

    #[test]
    fn the_pin_file_reader_trims_a_trailing_newline_and_refuses_an_empty_file() {
        // A PIN file written with `echo` ends in a newline; sending that to a token gets
        // an opaque failure that looks like a wrong PIN. An EMPTY file is refused rather
        // than sending a blank PIN.
        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let ok_path = dir.join(format!("mcp-re-pin-ok-{pid}"));
        let empty_path = dir.join(format!("mcp-re-pin-empty-{pid}"));
        std::fs::write(&ok_path, b"1234\n").expect("write pin");
        std::fs::write(&empty_path, b"  \n").expect("write empty pin");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for p in [&ok_path, &empty_path] {
                std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600))
                    .expect("chmod 0600");
            }
        }

        let pin = super::read_pkcs11_pin(ok_path.to_str().unwrap()).expect("reads");
        assert_eq!(
            pin.expose(),
            "1234",
            "the trailing newline is not part of the PIN"
        );
        assert!(
            super::read_pkcs11_pin(empty_path.to_str().unwrap()).is_err(),
            "an empty PIN file must not yield a blank PIN"
        );
        let _ = std::fs::remove_file(&ok_path);
        let _ = std::fs::remove_file(&empty_path);
    }

    #[cfg(unix)]
    #[test]
    fn a_group_readable_pin_file_is_refused() {
        // The PIN unlocks the token holding the signing keys, so it sits behind the same
        // permission floor as a key file. Checked in the reader itself, not only at
        // startup: build_key_source is a public entry point.
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("mcp-re-pin-lax-{}", std::process::id()));
        std::fs::write(&path, b"1234").expect("write pin");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
            .expect("chmod 0640");
        let err = super::read_pkcs11_pin(path.to_str().unwrap()).unwrap_err();
        let message = format!("{err:?}");
        assert!(
            message.contains("group/world-accessible"),
            "expected a permission refusal, got: {message}"
        );
        assert!(
            !message.contains("1234"),
            "the refusal must not echo the PIN: {message}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn unknown_key_source_lists_pkcs11() {
        let mut a = minimal();
        a.splice(0..0, args(&["--key-source", "yubikey"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("file|pkcs11"), "got: {err}");
    }

    // In a DEFAULT build (no `pkcs11_keysource` feature) the PKCS#11 backend is
    // not compiled and `build_key_source` must FAIL CLOSED on
    // `KeySourceKind::Pkcs11` with a clear, actionable error — `--key-source
    // pkcs11` still parses so the message is precise, but no token-backed key is
    // built. Mirrors `default_build_rejects_env_key_source`.
    #[cfg(not(feature = "pkcs11_keysource"))]
    #[test]
    fn default_build_rejects_pkcs11_key_source() {
        let mut a = minimal_durable();
        a.splice(0..0, pkcs11_flags());
        let config = parse_args(&a).expect("parse");
        assert_eq!(config.key_source, KeySourceKind::Pkcs11);
        let err = super::build_key_source(&config)
            .err()
            .expect("default build must refuse a pkcs11 key source");
        let rendered = err.to_string();
        assert!(
            rendered.contains("pkcs11_keysource")
                && rendered.contains("not available in this build"),
            "expected a clear feature-rebuild message; got: {rendered}"
        );
    }

    // MCPS-076: the File key source is always constructible (default + dev builds).
    #[test]
    fn file_key_source_is_always_constructible() {
        let config = parse_args(&minimal_durable()).expect("parse");
        assert_eq!(config.key_source, KeySourceKind::File);
        assert!(super::build_key_source(&config).is_ok());
    }

    // ADR-MCPS-028 §B/§C: cloud-KMS key-source CLI wiring.
    fn aws_kms_flags() -> Vec<String> {
        args(&[
            "--key-source",
            "aws-kms",
            "--aws-kms-region",
            "us-east-1",
            "--aws-kms-key-id",
            "alias/mcp-re-response-signing",
        ])
    }

    fn gcp_kms_flags() -> Vec<String> {
        args(&[
            "--key-source",
            "gcp-kms",
            "--gcp-kms-key-version",
            "projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
        ])
    }

    #[test]
    fn parses_aws_kms_key_source_flags() {
        let mut a = minimal_durable();
        a.splice(0..0, aws_kms_flags());
        let config = parse_args(&a).expect("parse");
        assert_eq!(config.key_source, KeySourceKind::AwsKms);
        assert_eq!(config.aws_kms_region.as_deref(), Some("us-east-1"));
        assert_eq!(
            config.aws_kms_key_id.as_deref(),
            Some("alias/mcp-re-response-signing")
        );
    }

    #[test]
    fn aws_kms_requires_region_and_key_id() {
        for missing in ["--aws-kms-region", "--aws-kms-key-id"] {
            let mut flags = aws_kms_flags();
            let idx = flags
                .iter()
                .position(|f| f == missing)
                .expect("flag present");
            flags.drain(idx..idx + 2);
            let mut a = minimal();
            a.splice(0..0, flags);
            let err = parse_args(&a).unwrap_err();
            assert!(
                err.contains(missing),
                "expected error to name {missing}; got: {err}"
            );
        }
    }

    /// #60: `--aws-kms-tls-key-id` parses and is captured as the SECOND, distinct
    /// TLS KMS key id. On this delegated path `--tls-key` is forbidden and not
    /// required, so `minimal()`'s exported TLS key must be dropped first.
    /// AWS KMS leading flags WITHOUT `--tls-key` (delegated TLS path), `--inner-command`
    /// appended last so proxy flags land before the inner tail.
    fn aws_kms_lead_no_tls_key() -> Vec<String> {
        args(&[
            "--bind",
            "127.0.0.1:8443",
            "--audience",
            "did:example:server-1",
            "--server-signer",
            "did:example:server-1",
            "--server-key-id",
            "server-key-1",
            "--key-source",
            "aws-kms",
            "--aws-kms-region",
            "us-east-1",
            "--aws-kms-key-id",
            "alias/mcp-re-response-signing",
            "--signing-key-seed",
            "/unused-seed",
            "--tls-cert",
            "/cert",
            "--client-ca",
            "/ca",
            "--trust",
            "/trust.json",
            "--target-uri",
            "https://mcp.example.com/mcp",
            "--delegated-trust-epoch",
            "epoch-min",
            "--trust-domain",
            "mcp.example.com",
        ])
    }

    #[test]
    fn parses_aws_kms_tls_key_id_flag() {
        let mut a = aws_kms_lead_no_tls_key();
        a.push("--aws-kms-tls-key-id".to_string());
        a.push("alias/mcp-re-tls-signing".to_string());
        a.push("--inner-http-url".to_string());
        a.push("http://127.0.0.1:8080/mcp".to_string());
        a.extend(durable_replay());
        let config = parse_args(&a).expect("delegated TLS path parses without --tls-key");
        assert_eq!(config.key_source, KeySourceKind::AwsKms);
        assert_eq!(
            config.aws_kms_tls_key_id.as_deref(),
            Some("alias/mcp-re-tls-signing"),
        );
        // Distinct credential: the TLS key id differs from the object-signing key id.
        assert_ne!(config.aws_kms_tls_key_id, config.aws_kms_key_id);
    }

    /// #60 / #58: `--aws-kms-tls-key-id` (delegated) PLUS an exported `--tls-key` is
    /// contradictory and must fail closed (the exclusivity guard).
    #[test]
    fn aws_kms_tls_key_id_plus_exported_tls_key_fails_closed() {
        // minimal() carries an exported `--tls-key`; adding a delegated TLS key id
        // alongside it must be rejected.
        let mut a = minimal();
        a.splice(0..0, aws_kms_flags());
        a.splice(0..0, args(&["--aws-kms-tls-key-id", "alias/mcp-re-tls"]));
        let err = parse_args(&a).unwrap_err();
        assert!(
            err.contains("delegated") || err.contains("--tls-key"),
            "expected an exclusivity error, got: {err}"
        );
    }

    /// #60: a dangling `--aws-kms-tls-key-id` on a non-AWS source would silently do
    /// nothing (a false belief the TLS key is KMS-resident), so it must fail closed.
    #[test]
    fn aws_kms_tls_key_id_without_aws_kms_fails_closed() {
        let mut a = minimal();
        a.splice(0..0, args(&["--aws-kms-tls-key-id", "alias/mcp-re-tls"]));
        let err = parse_args(&a).unwrap_err();
        assert!(
            err.contains("--aws-kms-tls-key-id has no effect without --key-source aws-kms"),
            "got: {err}"
        );
    }

    #[test]
    fn parses_gcp_kms_key_source_flags() {
        let mut a = minimal_durable();
        a.splice(0..0, gcp_kms_flags());
        let config = parse_args(&a).expect("parse");
        assert_eq!(config.key_source, KeySourceKind::GcpKms);
        assert!(config
            .gcp_kms_key_version
            .as_deref()
            .unwrap()
            .ends_with("cryptoKeyVersions/1"));
        assert!(!config.gcp_kms_use_metadata);
    }

    #[test]
    fn gcp_kms_requires_key_version() {
        let mut a = minimal();
        a.splice(0..0, args(&["--key-source", "gcp-kms"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--gcp-kms-key-version"), "got: {err}");
    }

    #[test]
    fn gcp_use_metadata_only_with_gcp_kms() {
        // The metadata flag without --key-source gcp-kms must fail (no silent no-op).
        let mut a = minimal();
        a.splice(0..0, args(&["--gcp-kms-use-metadata"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--gcp-kms-use-metadata"), "got: {err}");
    }

    /// #61: GCP Cloud KMS leading flags WITHOUT `--tls-key` (delegated TLS path),
    /// `--inner-command` appended last so proxy flags land before the inner tail.
    fn gcp_kms_lead_no_tls_key() -> Vec<String> {
        args(&[
            "--bind",
            "127.0.0.1:8443",
            "--audience",
            "did:example:server-1",
            "--server-signer",
            "did:example:server-1",
            "--server-key-id",
            "server-key-1",
            "--key-source",
            "gcp-kms",
            "--gcp-kms-key-version",
            "projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
            "--signing-key-seed",
            "/unused-seed",
            "--tls-cert",
            "/cert",
            "--client-ca",
            "/ca",
            "--trust",
            "/trust.json",
            "--target-uri",
            "https://mcp.example.com/mcp",
            "--delegated-trust-epoch",
            "epoch-min",
            "--trust-domain",
            "mcp.example.com",
        ])
    }

    /// #61: `--gcp-kms-tls-key-version` parses and is captured as the SECOND,
    /// distinct TLS KMS key version. On this delegated path `--tls-key` is forbidden
    /// and not required, so the lead omits the exported TLS key.
    #[test]
    fn parses_gcp_kms_tls_key_version_flag() {
        let mut a = gcp_kms_lead_no_tls_key();
        a.push("--gcp-kms-tls-key-version".to_string());
        a.push(
            "projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/2".to_string(),
        );
        a.push("--inner-http-url".to_string());
        a.push("http://127.0.0.1:8080/mcp".to_string());
        a.extend(durable_replay());
        let config = parse_args(&a).expect("delegated TLS path parses without --tls-key");
        assert_eq!(config.key_source, KeySourceKind::GcpKms);
        assert_eq!(
            config.gcp_kms_tls_key_version.as_deref(),
            Some("projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/2"),
        );
        // Distinct credential: the TLS key version differs from the object-signing
        // key version.
        assert_ne!(config.gcp_kms_tls_key_version, config.gcp_kms_key_version);
    }

    /// #61 / #58: `--gcp-kms-tls-key-version` (delegated) PLUS an exported
    /// `--tls-key` is contradictory and must fail closed (the exclusivity guard).
    #[test]
    fn gcp_kms_tls_key_version_plus_exported_tls_key_fails_closed() {
        // minimal() carries an exported `--tls-key`; adding a delegated TLS key
        // version alongside it must be rejected.
        let mut a = minimal();
        a.splice(0..0, gcp_kms_flags());
        a.splice(
            0..0,
            args(&[
                "--gcp-kms-tls-key-version",
                "projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/2",
            ]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(
            err.contains("delegated") || err.contains("--tls-key"),
            "expected an exclusivity error, got: {err}"
        );
    }

    /// #61: a dangling `--gcp-kms-tls-key-version` on a non-GCP source would silently
    /// do nothing (a false belief the TLS key is KMS-resident), so it must fail
    /// closed.
    #[test]
    fn gcp_kms_tls_key_version_without_gcp_kms_fails_closed() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--gcp-kms-tls-key-version",
                "projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/2",
            ]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(
            err.contains("--gcp-kms-tls-key-version has no effect without --key-source gcp-kms"),
            "got: {err}"
        );
    }

    #[test]
    fn unknown_key_source_lists_cloud_kms() {
        let mut a = minimal();
        a.splice(0..0, args(&["--key-source", "azure-kv"]));
        let err = parse_args(&a).unwrap_err();
        assert!(
            err.contains("aws-kms") && err.contains("gcp-kms"),
            "got: {err}"
        );
    }

    // Default build (no cloud-KMS feature): the flags PARSE so the message is
    // precise, but `build_key_source` FAILS CLOSED — mirrors the pkcs11 gate.
    #[cfg(not(feature = "aws_kms_keysource"))]
    #[test]
    fn default_build_rejects_aws_kms_key_source() {
        let mut a = minimal_durable();
        a.splice(0..0, aws_kms_flags());
        let config = parse_args(&a).expect("parse");
        assert_eq!(config.key_source, KeySourceKind::AwsKms);
        let err = super::build_key_source(&config)
            .err()
            .expect("default build must refuse an aws-kms key source");
        assert!(
            err.to_string().contains("aws_kms_keysource")
                && err.to_string().contains("not available in this build"),
            "got: {err}"
        );
    }

    #[cfg(not(feature = "gcp_kms_keysource"))]
    #[test]
    fn default_build_rejects_gcp_kms_key_source() {
        let mut a = minimal_durable();
        a.splice(0..0, gcp_kms_flags());
        let config = parse_args(&a).expect("parse");
        assert_eq!(config.key_source, KeySourceKind::GcpKms);
        let err = super::build_key_source(&config)
            .err()
            .expect("default build must refuse a gcp-kms key source");
        assert!(
            err.to_string().contains("gcp_kms_keysource")
                && err.to_string().contains("not available in this build"),
            "got: {err}"
        );
    }

    #[test]
    fn parses_configurable_limits() {
        let mut a = minimal_durable();
        a.splice(
            0..0,
            args(&[
                "--max-body-bytes",
                "1024",
                "--max-connections",
                "8",
                "--read-timeout-secs",
                "45",
                "--request-deadline-secs",
                "12",
            ]),
        );
        let config = parse_args(&a).expect("parse");
        assert_eq!(config.limits.max_body_bytes, 1024);
        assert_eq!(config.limits.max_concurrent_connections, 8);
        assert_eq!(
            config.limits.read_timeout,
            Some(std::time::Duration::from_secs(45)),
            "--read-timeout-secs sets the per-socket read timeout"
        );
        assert_eq!(
            config.limits.request_deadline,
            Some(std::time::Duration::from_secs(12)),
            "--request-deadline-secs sets the aggregate read-phase deadline"
        );
    }

    /// A `0` timeout is what `parse_timeout` maps to "disabled", and disabling any of
    /// these removes the slow-loris defense. The proxy documents itself as refusing every
    /// unsafe configuration, and an OUT-OF-RANGE value was already rejected for exactly
    /// this reason ("the control can never be turned off by out-of-range input") — `0`
    /// was the hole in that argument.
    #[test]
    fn a_zero_timeout_is_refused_because_it_disables_the_slow_loris_defense() {
        for flag in [
            "--read-timeout-secs",
            "--write-timeout-secs",
            "--request-deadline-secs",
        ] {
            let mut a = minimal_durable();
            a.splice(0..0, args(&[flag, "0"]));
            let err = parse_args(&a).expect_err("a disabled timeout must be refused");
            assert!(
                err.contains("refuses unsafe configuration") && err.contains(flag),
                "{flag} 0 must be named in the refusal; got: {err}"
            );
            assert!(
                err.contains("slow-loris"),
                "the refusal must say what control is being disabled; got: {err}"
            );
        }
    }

    /// Under a non-exporting custody the response key never leaves the device, so the
    /// seed is never read — requiring it made operators put an Ed25519 root seed in
    /// every pod in exactly the mode chosen because no key should land there.
    #[test]
    fn a_non_exporting_custody_does_not_require_a_signing_key_seed() {
        for (source, extra) in [
            (
                "gcp-kms",
                vec![
                    "--gcp-kms-key-version",
                    "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
                ],
            ),
            (
                "aws-kms",
                vec![
                    "--aws-kms-region",
                    "us-east-1",
                    "--aws-kms-key-id",
                    "alias/k",
                ],
            ),
        ] {
            let mut a: Vec<String> = minimal_durable().into_iter().collect::<Vec<_>>();
            // Drop `--signing-key-seed /seed` from the baseline args.
            let i = a
                .iter()
                .position(|s| s == "--signing-key-seed")
                .expect("baseline has it");
            a.drain(i..i + 2);
            a.splice(0..0, args(&["--key-source", source]));
            a.splice(0..0, args(&extra));

            let config =
                parse_args(&a).unwrap_or_else(|e| panic!("{source} must not require a seed: {e}"));
            assert_eq!(
                config.signing_key_seed, "",
                "{source}: an unsupplied seed stays empty rather than naming a phantom file"
            );
        }
    }

    #[test]
    fn file_custody_still_requires_a_signing_key_seed() {
        // Where the seed IS read, omitting it must still fail closed at parse.
        let mut a = minimal_durable();
        let i = a
            .iter()
            .position(|s| s == "--signing-key-seed")
            .expect("baseline has it");
        a.drain(i..i + 2);
        let err = parse_args(&a).expect_err("file custody reads the seed, so it is required");
        assert!(err.contains("--signing-key-seed"), "got: {err}");
    }

    #[test]
    fn the_default_timeouts_are_bounded_so_the_refusal_never_fires_by_default() {
        // The guard above is only safe because every default is Some(30s): it must be
        // impossible to trip by omitting the flags.
        let config = parse_args(&minimal_durable()).expect("the default config parses");
        assert!(config.limits.read_timeout.is_some());
        assert!(config.limits.write_timeout.is_some());
        assert!(config.limits.request_deadline.is_some());
    }

    #[test]
    fn request_deadline_secs_over_cap_is_rejected() {
        // A nonsensically large `--request-deadline-secs` would overflow
        // `Instant::now() + t` in `tls::DeadlineStream` and silently DISABLE the
        // slow-loris defense. Parse-time capping rejects it LOUDLY so the control
        // can never be turned off by out-of-range input. The boundary (cap exactly)
        // is accepted; cap+1 is rejected.
        let cap = super::MAX_INNER_READ_TIMEOUT_SECS;
        let mut at_cap = minimal_durable();
        at_cap.splice(0..0, args(&["--request-deadline-secs", &cap.to_string()]));
        let config = parse_args(&at_cap).expect("the cap value itself is accepted");
        assert_eq!(
            config.limits.request_deadline,
            Some(std::time::Duration::from_secs(cap)),
            "the deadline stays enforced at the maximum",
        );

        let mut over_cap = minimal();
        let over = cap + 1;
        over_cap.splice(0..0, args(&["--request-deadline-secs", &over.to_string()]));
        let err = parse_args(&over_cap).expect_err("over-cap value must be rejected");
        assert!(
            err.contains("--request-deadline-secs") && err.contains("<="),
            "rejection names the flag and the bound; got: {err}"
        );
    }

    #[test]
    fn missing_required_flag_errors() {
        let mut a = minimal();
        // Drop --bind and its value.
        a.drain(0..2);
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--bind"), "got: {err}");
    }

    #[test]
    fn file_replay_requires_path() {
        let mut a = minimal();
        a.splice(0..0, args(&["--replay-cache", "file"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--replay-path"), "got: {err}");
    }

    // Issue #3837: `--replay-cache shared` parses (it is a real selection) and
    // requires a connection URL. It must declare a strict-acceptable durability tier
    // (the weaker `redis-async` tier is rejected, see
    // `strict_rejects_weak_replay_durability_tier`).
    #[test]
    fn parses_shared_replay_selection() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--replay-cache",
                "shared",
                "--replay-redis-url",
                "redis://127.0.0.1:6379",
                "--replay-durability-tier",
                "redis-wait-quorum:2:500",
            ]),
        );
        let config = parse_args(&a).expect("parse");
        assert_eq!(config.replay, ReplayKind::Shared);
        assert_eq!(
            config.replay_redis_url.as_deref(),
            Some("redis://127.0.0.1:6379")
        );
        assert_eq!(
            config.replay_durability_tier,
            Some(crate::replay_tier::ReplayDurabilityTier::RedisWaitQuorum {
                quorum: 2,
                timeout_ms: 500
            })
        );
    }

    #[test]
    fn shared_replay_requires_url() {
        // A Redis tier is declared, so the missing piece is the connection URL.
        // (With no tier the earlier durability-tier guard fires first; that is
        // covered by `shared_replay_requires_durability_tier`.)
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--replay-cache",
                "shared",
                "--replay-durability-tier",
                "redis-async",
            ]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--replay-redis-url"), "got: {err}");
    }

    // ADR-MCPS-020: a shared store must declare its durability tier.
    #[test]
    fn shared_replay_requires_durability_tier() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--replay-cache",
                "shared",
                "--replay-redis-url",
                "redis://127.0.0.1:6379",
            ]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--replay-durability-tier"), "got: {err}");
    }

    #[test]
    fn parses_wait_quorum_durability_tier() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--replay-cache",
                "shared",
                "--replay-redis-url",
                "redis://127.0.0.1:6379",
                "--replay-durability-tier",
                "redis-wait-quorum:2:500",
            ]),
        );
        let config = parse_args(&a).expect("parse");
        assert_eq!(
            config.replay_durability_tier,
            Some(crate::replay_tier::ReplayDurabilityTier::RedisWaitQuorum {
                quorum: 2,
                timeout_ms: 500
            })
        );
    }

    // #69 (epic #68 v0.4 Axis 1) — CONFIG fail-closed: selecting the LINEARIZABLE
    // tier WITHOUT a CP/etcd endpoint is a HARD config-construction error. It must
    // NEVER silently downgrade to Redis or in-memory. The error names the missing
    // --cpstore-etcd-endpoint flag.
    #[test]
    fn linearizable_tier_without_cpstore_endpoint_fails_closed() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--replay-cache",
                "shared",
                "--replay-durability-tier",
                "linearizable",
            ]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(
            err.contains("--cpstore-etcd-endpoint"),
            "LINEARIZABLE without a CPStore endpoint must fail closed naming the flag; got: {err}"
        );
        assert!(
            err.to_lowercase().contains("never") || err.to_lowercase().contains("forbidden"),
            "the error must state the claim is not silently downgraded; got: {err}"
        );
    }

    // #69 — the LINEARIZABLE tier with a CP/etcd endpoint parses, selects the etcd
    // backend (NOT Redis), and does NOT require --replay-redis-url.
    #[test]
    fn linearizable_tier_with_cpstore_endpoint_parses() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--replay-cache",
                "shared",
                "--replay-durability-tier",
                "linearizable",
                "--cpstore-etcd-endpoint",
                "http://127.0.0.1:2379",
            ]),
        );
        let config = parse_args(&a).expect("parse");
        assert_eq!(config.replay, ReplayKind::Shared);
        assert_eq!(
            config.replay_durability_tier,
            Some(crate::replay_tier::ReplayDurabilityTier::Linearizable)
        );
        assert_eq!(
            config.cpstore_etcd_endpoint.as_deref(),
            Some("http://127.0.0.1:2379")
        );
        // The Redis URL is NOT required for the CP tier.
        assert_eq!(config.replay_redis_url, None);
    }

    // #69 — a dangling --cpstore-etcd-endpoint for a non-LINEARIZABLE config is
    // rejected (it would silently do nothing — a false belief a CP store is in
    // force). Fail closed, mirroring the dangling --ocsp-responder-url guard.
    #[test]
    fn cpstore_endpoint_without_linearizable_fails_closed() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--replay-cache",
                "shared",
                "--replay-redis-url",
                "redis://127.0.0.1:6379",
                "--replay-durability-tier",
                "redis-async",
                "--cpstore-etcd-endpoint",
                "http://127.0.0.1:2379",
            ]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(
            err.contains("--cpstore-etcd-endpoint has no effect"),
            "a dangling CPStore endpoint must fail closed; got: {err}"
        );
    }

    // #69 — the CP/LINEARIZABLE builder fails closed in a build WITHOUT the
    // cpstore_etcd feature: the LINEARIZABLE claim is forbidden without the CP
    // backend and is never downgraded. Compiled only when the feature is OFF.
    #[cfg(not(feature = "cpstore_etcd"))]
    #[test]
    fn default_build_cpstore_replay_fails_closed() {
        let err = super::build_cpstore_replay_cache(
            "http://127.0.0.1:2379",
            300,
            Some(std::time::Duration::from_secs(30)),
            Some(std::time::Duration::from_secs(30)),
        )
        .err()
        .expect("a build without cpstore_etcd must refuse the LINEARIZABLE cache");
        assert!(
            err.contains("cpstore_etcd feature"),
            "expected a clear feature-missing message; got: {err}"
        );
    }

    #[test]
    fn rejects_unknown_durability_tier() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--replay-cache",
                "shared",
                "--replay-redis-url",
                "redis://127.0.0.1:6379",
                "--replay-durability-tier",
                "cluster",
            ]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("unknown replay durability tier"), "got: {err}");
    }

    #[test]
    fn revocation_tier_defaults_to_bounded_cache_tier_1() {
        // Absent --revocation-tier preserves the Tier-1 bounded-cache posture with
        // the deployment-default window T (existing behavior unchanged).
        let config = parse_args(&minimal_durable()).expect("parse");
        assert_eq!(
            config.revocation_tier,
            crate::revocation_tier::RevocationTier::BoundedCache {
                t_secs: crate::trust_cache::DEFAULT_T_SECS
            }
        );
    }

    #[test]
    fn parses_each_revocation_tier() {
        for (flag, expected) in [
            (
                "bounded-cache:90",
                crate::revocation_tier::RevocationTier::BoundedCache { t_secs: 90 },
            ),
            ("live", crate::revocation_tier::RevocationTier::Live),
            (
                "push:30",
                crate::revocation_tier::RevocationTier::Push { t_secs: 30 },
            ),
        ] {
            let mut a = minimal_durable();
            // LIVE and PUSH both state their window in terms of consulting the trust
            // store, so both require a reload cadence to make that true.
            a.splice(
                0..0,
                args(&["--revocation-tier", flag, "--trust-reload-secs", "60"]),
            );
            let config = parse_args(&a).unwrap_or_else(|e| panic!("parse {flag}: {e}"));
            assert_eq!(config.revocation_tier, expected, "flag {flag}");
        }
    }

    /// A tier that advertises a near-zero window must have a store that can change.
    /// Read-once `--trust` makes both LIVE and PUSH claims the binary cannot keep.
    #[test]
    fn live_and_push_tiers_require_a_trust_reload_cadence() {
        for flag in ["live", "push:30"] {
            let mut a = minimal_durable();
            a.splice(0..0, args(&["--revocation-tier", flag]));
            let err = parse_args(&a).expect_err("must be refused without a reload cadence");
            assert!(err.contains("--trust-reload-secs"), "got: {err}");
        }
        // Tier 1 makes no such claim: its window is the cache bound T, which holds
        // whether or not the file is re-read.
        let mut a = minimal_durable();
        a.splice(0..0, args(&["--revocation-tier", "bounded-cache:90"]));
        parse_args(&a).expect("bounded-cache does not require a reload cadence");
    }

    #[test]
    fn rejects_unknown_or_malformed_revocation_tier() {
        for flag in ["ocsp", "bounded-cache", "push:0", "bounded-cache:-1"] {
            let mut a = minimal();
            a.splice(0..0, args(&["--revocation-tier", flag]));
            assert!(
                parse_args(&a).is_err(),
                "revocation tier '{flag}' must be rejected"
            );
        }
    }

    #[test]
    fn unknown_replay_cache_lists_shared() {
        let mut a = minimal();
        a.splice(0..0, args(&["--replay-cache", "cluster"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("memory|file|shared"), "got: {err}");
    }

    // Issue #3837: in a DEFAULT build there is no shared replay backend, so
    // constructing the shared replay cache must FAIL CLOSED with the clear
    // not-yet-available error — never silently degrade to a non-shared cache.
    // Mirrors the env-keysource gate. Under `--features redis_replay` (#4028) the
    // real Redis backend is wired instead, so this default-build assertion is
    // compiled only when that feature is OFF.
    #[cfg(not(feature = "redis_replay"))]
    #[test]
    fn default_build_shared_replay_fails_closed() {
        let err = super::build_shared_replay_cache(
            "redis://127.0.0.1:6379",
            300,
            Some(std::time::Duration::from_secs(30)),
            Some(std::time::Duration::from_secs(30)),
            &crate::replay_tier::ReplayDurabilityTier::RedisAsyncBounded,
        )
        .err()
        .expect("this build must refuse the shared replay cache");
        assert!(
            err.contains("not yet available in this build"),
            "expected a clear not-yet-available message; got: {err}"
        );
    }

    // Phase 0 (production packaging): under `--features redis_replay` the shared
    // replay cache wires the REAL Redis backend. If Redis is UNREACHABLE at startup
    // (nothing listening → connection REFUSED), construction must FAIL CLOSED
    // (return Err) so the proxy refuses to start rather than accepting traffic with
    // no replay safety. This drives the production path end-to-end:
    //   build_shared_replay_cache (cli.rs)
    //     → RedisAtomicReplayStore::connect_with (redis_store.rs)
    //       → bounded_connect → get_connection_with_timeout → connection refused
    //         → ReplayStoreError::Unavailable → Err(String) out of the builder.
    // Distinct from `stalled_redis_fails_closed_within_timeout_not_hang` in
    // redis_store.rs, which covers the SINKHOLE (TCP accepts, never answers) case;
    // here NOTHING is listening, so the connect is REFUSED immediately — fast and
    // deterministic, NOT a slow timeout.
    //
    // RED without fail-closed: if `connect_with`/`bounded_connect` swallowed the
    // connect error and returned a degraded non-failing cache, this returns Ok and
    // the `expect` on `.err()` panics — the test fails. Proven by neutralization.
    #[cfg(feature = "redis_replay")]
    #[test]
    fn connection_refused_redis_fails_closed_at_construction() {
        // Port 1 on loopback has nothing listening → connection REFUSED at once.
        let unreachable = "redis://127.0.0.1:1/";
        // A bounded connect deadline; a refused connect returns well inside it.
        let connect_timeout = std::time::Duration::from_secs(2);

        let start = std::time::Instant::now();
        let result = super::build_shared_replay_cache(
            unreachable,
            300,
            Some(connect_timeout),
            Some(std::time::Duration::from_secs(2)),
            &crate::replay_tier::ReplayDurabilityTier::RedisAsyncBounded,
        );
        let elapsed = start.elapsed();

        let err = result
            .err()
            .expect("an unreachable Redis must make the shared replay cache FAIL CLOSED");
        // The builder maps the Unavailable store error into its "shared replay
        // cache: ..." String — assert we got that fail-closed surface, not a
        // degraded usable cache.
        assert!(
            err.contains("shared replay cache"),
            "expected the fail-closed shared-replay-cache error; got: {err}"
        );
        // Connection-REFUSED is immediate: it must complete well within the bounded
        // connect deadline (NOT hang to the full timeout). Generous upper bound to
        // stay robust on a loaded CI box while still proving boundedness.
        assert!(
            elapsed < connect_timeout,
            "refused connect must fail closed PROMPTLY (well inside the {connect_timeout:?} \
             deadline); took {elapsed:?}"
        );
    }

    #[test]
    fn unknown_flag_errors() {
        let mut a = minimal();
        a.splice(0..0, args(&["--bogus", "x"]));
        assert!(parse_args(&a).unwrap_err().contains("--bogus"));
    }

    // --- #3839 offline CRL flags ---------------------------------------------

    #[test]
    fn default_has_no_crls_and_fails_closed_on_unknown_status() {
        let config = parse_args(&minimal_durable()).expect("parse");
        assert!(
            config.client_crl_paths.is_empty(),
            "no CRLs by default (revocation checking disabled until configured)"
        );
        // Unknown CRL revocation status is ALWAYS denied (fail closed) — there is no
        // relax knob to assert.
    }

    #[test]
    fn parses_a_single_client_crl_path() {
        let mut a = minimal_durable();
        a.splice(0..0, args(&["--client-crl", "/etc/mcp-re/clients.crl"]));
        let config = parse_args(&a).expect("parse");
        assert_eq!(
            config.client_crl_paths,
            vec!["/etc/mcp-re/clients.crl".to_string()]
        );
    }

    #[test]
    fn parses_comma_separated_client_crls() {
        let mut a = minimal_durable();
        a.splice(0..0, args(&["--client-crl", "/a.crl,/b.crl,/c.crl"]));
        let config = parse_args(&a).expect("parse");
        assert_eq!(
            config.client_crl_paths,
            vec![
                "/a.crl".to_string(),
                "/b.crl".to_string(),
                "/c.crl".to_string()
            ]
        );
    }

    // --- ADR-MCPRE-051 §3 async HTTP inner backends --------------------------

    #[test]
    fn parses_repeated_and_comma_separated_inner_http_urls() {
        let mut a = minimal_without_inner_command();
        a.extend(durable_replay());
        a.extend(args(&[
            "--inner-http-url",
            "http://10.0.0.1:8080/mcp,http://10.0.0.2:8080/mcp",
            "--inner-http-url",
            "http://10.0.0.3:8080/mcp",
        ]));
        let config = parse_args(&a).expect("parse");
        assert_eq!(
            config.inner_http_urls,
            vec![
                "http://10.0.0.1:8080/mcp".to_string(),
                "http://10.0.0.2:8080/mcp".to_string(),
                "http://10.0.0.3:8080/mcp".to_string(),
            ]
        );
    }

    // --- ADR-MCPRE-051 §1 per-core worker count (--cores) --------------------

    #[test]
    fn cores_defaults_to_auto_zero() {
        let mut a = minimal_without_inner_command();
        a.extend(durable_replay());
        a.extend(args(&["--inner-http-url", "http://10.0.0.1:8080/mcp"]));
        let config = parse_args(&a).expect("parse");
        assert_eq!(
            config.cores, 0,
            "unset --cores means auto (0 = one worker per core)"
        );
    }

    #[test]
    fn parses_explicit_cores() {
        let mut a = minimal_without_inner_command();
        a.extend(durable_replay());
        a.extend(args(&[
            "--inner-http-url",
            "http://10.0.0.1:8080/mcp",
            "--cores",
            "4",
        ]));
        let config = parse_args(&a).expect("parse");
        assert_eq!(config.cores, 4);
    }

    #[test]
    fn non_numeric_cores_fails_closed() {
        let mut a = minimal_without_inner_command();
        a.extend(args(&[
            "--inner-http-url",
            "http://10.0.0.1:8080/mcp",
            "--cores",
            "many",
        ]));
        let err = parse_args(&a).unwrap_err();
        assert!(
            err.contains("--cores"),
            "non-numeric --cores must fail with a --cores message; got: {err}"
        );
    }

    #[test]
    fn empty_inner_http_url_segment_fails_closed() {
        let mut a = minimal();
        a.splice(0..0, args(&["--inner-http-url", "http://a,,http://b"]));
        assert!(
            parse_args(&a).unwrap_err().contains("--inner-http-url"),
            "an empty URL segment must be a hard parse error"
        );
    }

    #[test]
    fn missing_inner_http_url_fails_closed() {
        // The async serving path requires at least one HTTP inner backend; a config
        // with none must fail closed.
        let err = parse_args(&minimal_without_inner_command()).unwrap_err();
        assert!(
            err.contains("--inner-http-url"),
            "missing inner plane must name --inner-http-url; got: {err}"
        );
    }

    // --- ADR-MCPS-013 policy-layer revocation (fail-closed) ------------------

    #[test]
    fn authz_off_does_not_require_a_revocation_list() {
        // The default (authz off) wires no policy enforcement, so revocation is
        // moot — the guard must not spuriously demand a deny-list.
        let config = parse_args(&minimal_durable()).expect("parse");
        assert_eq!(config.authz, AuthzKind::Off);
        assert!(config.revocation_list_paths.is_empty());
    }

    // NOTE: `--authz reference` is NEVER accepted — the reference profile is a
    // conformance implementation, not the production authorization authority, and
    // there is no ack to override this (see `authz_reference_is_refused`).
    // `--revocation-list` itself still parses (authz stays off), exercised below.

    /// The deny-list parses into the config, but a config that CARRIES one is refused:
    /// nothing consults it while authz is off, so accepting it would be a silent
    /// no-op on a control the operator believes is enforcing.
    #[test]
    fn a_supplied_revocation_list_is_refused_because_nothing_consults_it() {
        let mut a = minimal_durable();
        a.splice(0..0, args(&["--revocation-list", "/a,/b,/c"]));
        let err = parse_args(&a).expect_err("a deny-list that enforces nothing must be refused");
        assert!(err.contains("--revocation-list"), "got: {err}");
        assert!(err.contains("enforce NOTHING"), "got: {err}");
    }

    #[test]
    fn empty_revocation_list_segment_is_rejected() {
        let mut a = minimal();
        a.splice(0..0, args(&["--revocation-list", "/a,,/b"]));
        assert!(parse_args(&a).unwrap_err().contains("empty path segment"));
    }

    #[test]
    fn authz_reference_is_refused() {
        // ADR-MCPS-013 (audit #94 F1/F2/F4): the reference profile is a real,
        // signature-verifying profile, but it is a conformance/reference impl, NOT the
        // production authority — and there is no ack to override that. `--authz
        // reference` is refused at parse time even with a revocation list supplied.
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--authz",
                "reference",
                "--revocation-list",
                "/etc/mcp-re/revoked",
            ]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(
            err.contains("--authz reference") && err.contains("ADR-MCPS-013"),
            "expected a reference-authz refusal, got: {err}"
        );
    }

    #[test]
    fn load_revocation_list_reads_ids_skipping_blanks_and_comments() {
        let path = std::env::temp_dir().join(format!("mcp_re_rev_ok_{}.txt", std::process::id()));
        std::fs::write(
            &path,
            "# revoked grants\ngrant-1\n\n  grant-2  \n# trailing comment\ngrant-3\n",
        )
        .expect("write");
        let ids = load_revocation_list(&[path.to_string_lossy().into_owned()]).expect("load");
        std::fs::remove_file(&path).ok();
        assert_eq!(
            ids,
            vec![
                "grant-1".to_string(),
                "grant-2".to_string(),
                "grant-3".to_string()
            ]
        );
    }

    #[test]
    fn load_revocation_list_missing_file_fails_closed() {
        let path =
            std::env::temp_dir().join(format!("mcp_re_rev_absent_{}.txt", std::process::id()));
        std::fs::remove_file(&path).ok();
        let err = load_revocation_list(&[path.to_string_lossy().into_owned()]).unwrap_err();
        assert!(err.contains("revocation list"), "got: {err}");
    }

    #[test]
    fn load_revocation_list_with_no_ids_fails_closed() {
        let path =
            std::env::temp_dir().join(format!("mcp_re_rev_empty_{}.txt", std::process::id()));
        std::fs::write(&path, "# only comments\n\n   \n").expect("write");
        let err = load_revocation_list(&[path.to_string_lossy().into_owned()]).unwrap_err();
        std::fs::remove_file(&path).ok();
        assert!(err.contains("no revocation ids"), "got: {err}");
    }

    #[test]
    fn repeated_client_crl_flags_accumulate() {
        let mut a = minimal_durable();
        a.splice(
            0..0,
            args(&["--client-crl", "/a.crl", "--client-crl", "/b.crl"]),
        );
        let config = parse_args(&a).expect("parse");
        assert_eq!(
            config.client_crl_paths,
            vec!["/a.crl".to_string(), "/b.crl".to_string()]
        );
    }

    #[test]
    fn empty_client_crl_segment_errors() {
        // A trailing comma (or empty value) must not silently load zero CRLs and
        // quietly disable revocation — it is a clear error.
        let mut a = minimal();
        a.splice(0..0, args(&["--client-crl", "/a.crl,"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("empty path segment"), "got: {err}");
    }

    #[test]
    fn missing_client_crl_file_fails_closed() {
        // A configured-but-unreadable CRL path is a hard error, never a silently
        // skipped revocation check.
        let err =
            super::load_client_crls(&["/no/such/MCPS3839_MISSING.crl".to_string()]).unwrap_err();
        assert!(err.contains("MCPS3839_MISSING"), "got: {err}");
    }

    #[test]
    fn no_crl_paths_loads_empty_vec() {
        // The no-CRL path: empty input → empty vec (revocation disabled), no error.
        let crls = super::load_client_crls(&[]).expect("empty load");
        assert!(crls.is_empty());
    }

    // --- #4030 online OCSP flag parsing -------------------------------------

    #[test]
    fn default_has_online_ocsp_off_and_hard_fail() {
        let config = parse_args(&minimal_durable()).expect("parse");
        assert_eq!(
            config.client_ocsp,
            OcspKind::Off,
            "online OCSP is OFF by default (offline-CRL-only posture preserved)"
        );
        // Online OCSP ALWAYS hard-fails on an indeterminate result — no soft-fail knob.
        assert!(config.ocsp_responder_url.is_none());
    }

    #[test]
    fn parses_client_ocsp_require_and_knobs() {
        // `--ocsp-soft-fail` is a rejected qualifier (the hard-fail posture is
        // unconditional), so only the require mode + responder URL are exercised.
        let mut a = minimal_durable();
        a.splice(
            0..0,
            args(&[
                "--client-ocsp",
                "require",
                "--ocsp-responder-url",
                "http://ocsp.example.test/r",
            ]),
        );
        // `--client-ocsp require` fails closed at parse time in EVERY build: without
        // the feature the OCSP code is absent, and with it the code exists but the
        // async serving fleet never calls it. Announcing enforcement that does not
        // happen is the defect this refusal removes.
        let err = parse_args(&a).expect_err("--client-ocsp require must fail closed");
        assert!(err.contains("cannot be honored"), "got: {err}");
        assert!(
            err.contains("--client-crl"),
            "the error must name the working alternative; got: {err}"
        );
    }

    #[test]
    fn unknown_client_ocsp_value_errors() {
        let mut a = minimal();
        a.splice(0..0, args(&["--client-ocsp", "maybe"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("unknown --client-ocsp"), "got: {err}");
    }

    #[test]
    fn responder_url_without_require_errors() {
        // A dangling --ocsp-responder-url (no --client-ocsp require) must not
        // silently do nothing.
        let mut a = minimal();
        a.splice(0..0, args(&["--ocsp-responder-url", "http://x/r"]));
        let err = parse_args(&a).unwrap_err();
        assert!(
            err.contains("--ocsp-responder-url has no effect"),
            "got: {err}"
        );
    }

    #[test]
    fn empty_responder_url_errors() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&["--client-ocsp", "require", "--ocsp-responder-url", "   "]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("non-empty URL"), "got: {err}");
    }

    /// `--client-ocsp require` fails closed in EVERY build configuration — the check
    /// is unreachable from the async serving fleet whether or not the `online_ocsp`
    /// code is compiled in.
    #[test]
    fn client_ocsp_require_fails_closed_in_every_build() {
        let mut a = minimal();
        a.splice(0..0, args(&["--client-ocsp", "require"]));
        let err = parse_args(&a).unwrap_err();
        assert!(
            err.contains("cannot be honored") && err.contains("async fleet"),
            "require must fail closed in every build; got: {err}"
        );
    }

    #[cfg(feature = "online_ocsp")]
    #[test]
    fn client_ocsp_require_in_reverse_proxy_mode_errors() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--client-ocsp",
                "require",
                "--reverse-proxy-identity-header",
                "x-client-id",
                "--max-client-cert-lifetime",
                "none",
            ]),
        );
        // Refused — now for the stronger reason that the serving path performs no OCSP
        // check at all, which subsumes the reverse-proxy-mode objection.
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("cannot be honored"), "got: {err}");
    }

    #[test]
    fn loads_a_trust_file() {
        let key = SigningKey::from_seed_bytes(&[1u8; 32])
            .public_key()
            .to_b64url();
        let json = format!(
            r#"[{{"signer":"did:example:agent-1","key_id":"key-1","public_key":"{key}"}}]"#
        );
        let resolver = load_trust(json.as_bytes()).expect("load");
        assert!(resolver.resolve("did:example:agent-1", "key-1").is_ok());
        assert!(resolver.resolve("did:example:agent-1", "other").is_err());
    }

    #[test]
    fn trust_file_with_bad_key_errors() {
        let json = r#"[{"signer":"s","key_id":"k","public_key":"!!!not-base64"}]"#;
        assert!(load_trust(json.as_bytes()).is_err());
    }

    #[test]
    fn trust_file_with_duplicate_key_id_is_rejected() {
        // Audit LOW (ledger `54aadf7b6257f126`): two entries sharing (signer,key_id)
        // but DIFFERENT public_key must fail closed, not silently last-write-wins
        // (a key-substitution primitive via an appended entry).
        let k1 = SigningKey::from_seed_bytes(&[1u8; 32])
            .public_key()
            .to_b64url();
        let k2 = SigningKey::from_seed_bytes(&[2u8; 32])
            .public_key()
            .to_b64url();
        let json = format!(
            r#"[{{"signer":"s","key_id":"k","public_key":"{k1}"}},
                {{"signer":"s","key_id":"k","public_key":"{k2}"}}]"#
        );
        let err =
            load_trust(json.as_bytes()).expect_err("duplicate (signer,key_id) must be refused");
        assert!(err.contains("duplicate entry"), "got: {err}");
    }

    #[test]
    fn trust_file_duplicate_same_key_is_also_rejected() {
        // Uniform posture: even an exact-duplicate entry is a malformed file, not a
        // silently-tolerated redundancy.
        let k = SigningKey::from_seed_bytes(&[3u8; 32])
            .public_key()
            .to_b64url();
        let json = format!(
            r#"[{{"signer":"s","key_id":"k","public_key":"{k}"}},
                {{"signer":"s","key_id":"k","public_key":"{k}"}}]"#
        );
        assert!(load_trust(json.as_bytes()).is_err());
    }

    #[test]
    fn trust_file_same_signer_distinct_key_ids_is_fine() {
        // The dedup is on the (signer,key_id) PAIR — one signer legitimately holds
        // multiple key ids (rotation), which must still load.
        let k1 = SigningKey::from_seed_bytes(&[4u8; 32])
            .public_key()
            .to_b64url();
        let k2 = SigningKey::from_seed_bytes(&[5u8; 32])
            .public_key()
            .to_b64url();
        let json = format!(
            r#"[{{"signer":"s","key_id":"k1","public_key":"{k1}"}},
                {{"signer":"s","key_id":"k2","public_key":"{k2}"}}]"#
        );
        let resolver = load_trust(json.as_bytes()).expect("distinct key ids load");
        assert!(resolver.resolve("s", "k1").is_ok());
        assert!(resolver.resolve("s", "k2").is_ok());
    }

    // --- MCPS-3842 strict/production posture ("reject, not warn") ------------
    //
    // The strict/production posture is UNCONDITIONAL: the proxy always rejects an
    // insecure-posture config at parse time (there is no warn-only mode, and the
    // `--strict`/`--production` qualifiers are refused as redundant). These
    // black-box parser tests assert those hard refusals and the accepting cases.

    #[test]
    fn strict_is_always_on_for_a_safe_config() {
        // The bare in-memory replay default is a #90 violation, so a fully-safe
        // config declares a durable replay backend; it must then parse with no
        // unsafe-config violations (the proxy always runs maximal security).
        let config = parse_args(&minimal_durable()).expect("a fully-safe config must parse");
        assert!(
            unsafe_config_violations(&config).is_empty(),
            "a safe config must have no strict violations"
        );
    }

    // ADR-MCPS-020: strict/production rejects a shared store declared at a tier
    // weaker than REDIS_WAIT_QUORUM.
    #[test]
    fn strict_rejects_weak_replay_durability_tier() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--replay-cache",
                "shared",
                "--replay-redis-url",
                "redis://127.0.0.1:6379",
                "--replay-durability-tier",
                "redis-async",
            ]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--replay-durability-tier"), "got: {err}");
        assert!(err.contains("strict-production minimum"), "got: {err}");
    }

    #[test]
    fn strict_accepts_wait_quorum_replay_durability_tier() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--replay-cache",
                "shared",
                "--replay-redis-url",
                "redis://127.0.0.1:6379",
                "--replay-durability-tier",
                "redis-wait-quorum:2:500",
            ]),
        );
        let config = parse_args(&a).expect("wait-quorum tier must be strict-acceptable");
        assert!(
            unsafe_config_violations(&config)
                .iter()
                .all(|v| !v.contains("replay-durability-tier")),
            "wait-quorum must not be a replay-tier strict violation"
        );
    }

    // MCPS-79 (ADR-MCPS-049 clause 1): under --fleet a node-local FILE replay cache
    // is rejected — it is durable on ONE node but unshareable across verifiers, so a
    // peer would not see a replayed nonce. Contrast
    // `single_node_accepts_file_replay_cache`: the same file cache is valid WITHOUT
    // --fleet (single verifier). This is the orthogonality of the fleet dimension
    // and the (always-on) strict posture made executable.
    #[test]
    fn strict_fleet_rejects_file_replay_cache() {
        let mut a = minimal();
        a.splice(0..0, durable_replay());
        a.splice(0..0, args(&["--fleet"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--fleet"), "got: {err}");
        assert!(err.contains("node-local"), "got: {err}");
        assert!(err.contains("shared"), "got: {err}");
    }

    // MCPS-79: under --fleet the node-local in-memory cache is likewise rejected (it
    // is also rejected as non-durable, #90 — but the --fleet reason must be present
    // so the operator learns the cross-verifier property, not just the restart-
    // durability one).
    #[test]
    fn strict_fleet_rejects_memory_replay_cache() {
        let mut a = minimal(); // default replay backend is in-memory
        a.splice(0..0, args(&["--fleet"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--fleet"), "got: {err}");
        assert!(err.contains("node-local"), "got: {err}");
    }

    // MCPS-79: --fleet ACCEPTS a shared cache at a strict-production durability tier
    // — the one posture that maintains cross-verifier replay state. No fleet
    // violation must remain.
    #[test]
    fn strict_fleet_accepts_shared_wait_quorum() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--fleet",
                "--replay-cache",
                "shared",
                "--replay-redis-url",
                "redis://127.0.0.1:6379",
                "--replay-durability-tier",
                "redis-wait-quorum:2:500",
            ]),
        );
        let config = parse_args(&a).expect("--fleet + shared wait-quorum must parse");
        assert!(config.fleet);
        assert!(
            unsafe_config_violations(&config)
                .iter()
                .all(|v| !v.contains("--fleet")),
            "shared wait-quorum must not be a --fleet strict violation"
        );
    }

    // MCPS-79 (orthogonality): WITHOUT --fleet the deployment is single-node, so the
    // durable FILE cache (ADR-MCPS-014) remains valid — the node is the sole
    // verifier. The --fleet rejection must NOT fire here.
    #[test]
    fn single_node_accepts_file_replay_cache() {
        let config =
            parse_args(&minimal_durable()).expect("single-node must accept a durable file cache");
        assert!(!config.fleet);
        assert!(
            unsafe_config_violations(&config)
                .iter()
                .all(|v| !v.contains("--fleet")),
            "single-node must have no --fleet violation"
        );
    }

    // MCPS-84: a trust-epoch backend is only consumed by the Push tier; pairing it
    // with any other tier is a fail-closed misconfiguration (not silently ignored).
    #[test]
    fn trust_epoch_url_without_push_tier_is_rejected() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&["--trust-epoch-redis-url", "redis://127.0.0.1:6379"]),
        );
        // Default tier is bounded-cache, not push.
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--trust-epoch-redis-url"), "got: {err}");
        assert!(err.contains("push"), "got: {err}");
    }

    // MCPS-84: under --revocation-tier push the trust-epoch URL/key parse and land
    // on the config.
    #[test]
    fn trust_epoch_url_with_push_tier_parses() {
        let mut a = minimal_durable();
        a.splice(
            0..0,
            args(&[
                "--revocation-tier",
                "push:60",
                "--trust-epoch-redis-url",
                "redis://127.0.0.1:6379",
                "--trust-epoch-key",
                "mcp-re:trust:epoch",
                "--trust-reload-secs",
                "60",
            ]),
        );
        let config = parse_args(&a).expect("push + trust-epoch must parse");
        assert_eq!(
            config.trust_epoch_redis_url.as_deref(),
            Some("redis://127.0.0.1:6379")
        );
        assert_eq!(
            config.trust_epoch_key.as_deref(),
            Some("mcp-re:trust:epoch")
        );
    }

    // #90 (ADR-MCPS-014/020): the DEFAULT replay backend is the non-durable
    // in-memory cache, which loses admitted nonces on restart and re-opens a replay
    // window for still-fresh captured envelopes. Under --strict it is a hard parse
    // error directing the operator at a durable backend.
    #[test]
    fn strict_rejects_in_memory_replay_default() {
        // minimal() omits --replay-cache, so it defaults to the non-durable
        // in-memory backend — always a strict/production violation.
        let err = parse_args(&minimal()).unwrap_err();
        assert!(err.contains("--replay-cache memory"), "got: {err}");
        // The message must direct to BOTH durable options (single-node + horizontal).
        assert!(err.contains("--replay-cache file"), "got: {err}");
        assert!(err.contains("--replay-cache shared"), "got: {err}");
    }

    // #90: the durable single-node `file` backend is NOT a strict violation — a
    // proxy restart re-reads its admitted nonces from disk, so no restart window
    // re-opens. The minimal config with `--replay-cache file` must parse Ok with no
    // replay strict violation.
    #[test]
    fn strict_accepts_file_replay_backend() {
        let config = parse_args(&minimal_durable()).expect("durable file replay must parse");
        assert_eq!(config.replay, ReplayKind::File);
        assert!(
            unsafe_config_violations(&config)
                .iter()
                .all(|v| !v.contains("--replay-cache")),
            "a durable file replay must not be a replay strict violation"
        );
    }

    // #90: the horizontally-durable `shared` backend at an adequate tier is NOT a
    // replay strict violation either (the weaker-tier case is covered by
    // `strict_rejects_weak_replay_durability_tier`).
    #[test]
    fn strict_accepts_shared_replay_at_adequate_tier() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--replay-cache",
                "shared",
                "--replay-redis-url",
                "redis://127.0.0.1:6379",
                "--replay-durability-tier",
                "redis-wait-quorum:2:500",
            ]),
        );
        let config = parse_args(&a).expect("durable shared replay must parse");
        assert_eq!(config.replay, ReplayKind::Shared);
        assert!(
            unsafe_config_violations(&config)
                .iter()
                .all(|v| !v.contains("--replay-cache memory")),
            "a durable shared replay must not trip the in-memory replay violation"
        );
    }

    #[test]
    fn strict_rejects_disabled_cert_lifetime_none() {
        let mut a = minimal_durable();
        a.splice(0..0, args(&["--max-client-cert-lifetime", "none"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--max-client-cert-lifetime"), "got: {err}");
    }

    #[test]
    fn strict_rejects_disabled_cert_lifetime_zero() {
        // `0` parses to the same disabled (None) enforcement as `none`.
        let mut a = minimal_durable();
        a.splice(0..0, args(&["--max-client-cert-lifetime", "0"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--max-client-cert-lifetime"), "got: {err}");
    }

    // ADR-MCPS-023 §A1 (MCPS-57), conformance vector (a): a client-cert lifetime
    // ABOVE the 1h ceiling is a hard violation — Mode-A's revocation posture is
    // short-lived certs, so a longer-lived cert cannot be audited as
    // `short_lived_cert`.
    #[test]
    fn strict_rejects_over_ceiling_cert_lifetime() {
        let mut a = minimal_durable();
        a.splice(0..0, args(&["--max-client-cert-lifetime", "24h"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("exceeds the ceiling"), "got: {err}");
        assert!(err.contains("86400s"), "got: {err}");
        assert!(err.contains("short_lived_cert"), "got: {err}");
    }

    // ADR-MCPS-023 §A1: the boundary is inclusive — a lifetime EXACTLY at the 1h
    // ceiling (the default) is acceptable, so a default config is not self-rejecting.
    #[test]
    fn strict_accepts_cert_lifetime_at_ceiling() {
        let mut a = minimal_durable();
        a.splice(0..0, args(&["--max-client-cert-lifetime", "3600"]));
        let config = parse_args(&a).expect("a 1h lifetime must be strict-acceptable");
        assert!(
            unsafe_config_violations(&config)
                .iter()
                .all(|v| !v.contains("max-client-cert-lifetime")),
            "a lifetime at the ceiling must not be a strict violation"
        );
    }

    // ADR-MCPS-023 §A1: a lifetime just BELOW the ceiling is also acceptable.
    #[test]
    fn strict_accepts_cert_lifetime_below_ceiling() {
        let mut a = minimal_durable();
        a.splice(0..0, args(&["--max-client-cert-lifetime", "30m"]));
        let config = parse_args(&a).expect("a 30m lifetime must be strict-acceptable");
        assert!(
            unsafe_config_violations(&config)
                .iter()
                .all(|v| !v.contains("max-client-cert-lifetime")),
            "a lifetime below the ceiling must not be a strict violation"
        );
    }

    // SUPERSEDED by ADR-MCPS-023 §A1 (v0.9, MCPS-57): the earlier MCPS-3842 stance
    // treated a lifetime > 1h as a warning-only recommendation. That is reversed —
    // Mode-A's revocation posture IS the cert lifetime, so a lifetime above the
    // ceiling fails closed. A 2h lifetime is enforced but cannot be audited as
    // `short_lived_cert`, so it is rejected.
    #[test]
    fn strict_rejects_over_ceiling_lifetime_2h() {
        let mut a = minimal_durable();
        a.splice(0..0, args(&["--max-client-cert-lifetime", "2h"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("exceeds the ceiling"), "got: {err}");
        assert!(err.contains("7200s"), "got: {err}");
    }

    #[test]
    fn strict_rejects_cn_legacy_identity_source() {
        let mut a = minimal_durable();
        a.splice(0..0, args(&["--transport-identity-source", "cn_legacy"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("cn_legacy"), "got: {err}");
    }

    #[test]
    fn strict_reports_all_violations_at_once() {
        // The error aggregates every parse-time violation so the operator can fix
        // the whole posture in one pass, not one error per restart. The bare
        // in-memory replay default is itself a #90 violation and aggregates alongside
        // the cert-lifetime and cn_legacy violations.
        let mut a = minimal(); // in-memory replay default
        a.splice(
            0..0,
            args(&[
                "--max-client-cert-lifetime",
                "none",
                "--transport-identity-source",
                "cn_legacy",
            ]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--replay-cache memory"), "got: {err}");
        assert!(err.contains("--max-client-cert-lifetime"), "got: {err}");
        assert!(err.contains("cn_legacy"), "got: {err}");
    }

    // --- #4082 (MCP-RE-MED-1) additional strict/production posture rejections -----
    //
    // M10/M11/M22: the unconditional strict/production posture turns these
    // otherwise-spoofable/decoupled postures into HARD parse errors.

    // M10/M22 — reverse-proxy identity-header ingress is the documented
    // identity-spoofable posture; production refuses to enable it.
    #[test]
    fn strict_rejects_reverse_proxy_identity_header_ingress() {
        let mut a = minimal_durable();
        a.splice(
            0..0,
            args(&[
                "--reverse-proxy-identity-header",
                "x-forwarded-client-cert",
                // The local-cert lifetime is meaningless in reverse-proxy mode, so it
                // must be explicitly disabled (existing parse rule); that disabled
                // lifetime is itself a violation, but the reverse-proxy ingress
                // rejection is what we assert here.
                "--max-client-cert-lifetime",
                "none",
            ]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(
            err.contains("--reverse-proxy-identity-header"),
            "got: {err}"
        );
    }

    // M11 — `--transport-binding none` is no longer a selectable value (the only
    // accepted bindings enforce a channel↔signer binding), so it fails closed at
    // argument-parse time.
    #[test]
    fn strict_rejects_transport_binding_none() {
        let mut a = minimal_durable();
        a.splice(0..0, args(&["--transport-binding", "none"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("unknown --transport-binding"), "got: {err}");
        assert!(err.contains("none"), "got: {err}");
    }

    #[test]
    fn key_file_mode_predicate_flags_group_and_world_bits() {
        // The pure file-perm predicate used by main.rs's strict key-file check:
        // owner-only (0600) is safe; any group/world bit is insecure.
        assert!(
            !super::key_file_mode_is_insecure(0o600),
            "0600 owner-only is safe"
        );
        assert!(
            !super::key_file_mode_is_insecure(0o400),
            "0400 owner-read is safe"
        );
        assert!(
            super::key_file_mode_is_insecure(0o640),
            "group-readable is insecure"
        );
        assert!(
            super::key_file_mode_is_insecure(0o604),
            "world-readable is insecure"
        );
        assert!(
            super::key_file_mode_is_insecure(0o660),
            "group-writable is insecure"
        );
        assert!(
            super::key_file_mode_is_insecure(0o777),
            "world-everything is insecure"
        );
    }

    // ---- C053b: the fsGroup-owned mount posture -------------------------------

    #[test]
    fn the_strict_posture_is_unchanged_by_default() {
        // No opt-in: the 0600/0400 floor behaves exactly as before.
        assert_eq!(
            super::key_file_posture_violation(0o600, 1000, false, &[1000]),
            None
        );
        assert_eq!(
            super::key_file_posture_violation(0o400, 1000, false, &[1000]),
            None
        );
        assert!(super::key_file_posture_violation(0o440, 1000, false, &[1000]).is_some());
    }

    #[test]
    fn an_fsgroup_owned_mount_is_accepted_only_with_the_opt_in() {
        // The Kubernetes shape: mode 0440, owned by a supplementary group the process
        // is in. Refused by default, accepted when the operator asks for it.
        assert!(super::key_file_posture_violation(0o440, 2000, false, &[1000, 2000]).is_some());
        assert_eq!(
            super::key_file_posture_violation(0o440, 2000, true, &[1000, 2000]),
            None
        );
    }

    #[test]
    fn a_group_this_process_is_not_in_is_still_refused() {
        // "Group-readable" to a group the proxy has nothing to do with is strictly
        // worse than the posture being relaxed, so the opt-in does not reach it.
        assert!(super::key_file_posture_violation(0o440, 9999, true, &[1000, 2000]).is_some());
    }

    #[test]
    fn group_write_is_never_accepted() {
        // A peer process able to REPLACE the signing key is never a mount requirement.
        for mode in [0o460, 0o660, 0o620] {
            assert!(
                super::key_file_posture_violation(mode, 2000, true, &[2000]).is_some(),
                "{mode:o} is group-writable and must be refused even with the opt-in"
            );
        }
    }

    #[test]
    fn any_world_bit_is_never_accepted() {
        for mode in [0o444, 0o604, 0o441, 0o642] {
            assert!(
                super::key_file_posture_violation(mode, 2000, true, &[2000]).is_some(),
                "{mode:o} has a world bit and must be refused even with the opt-in"
            );
        }
    }

    #[test]
    fn tls_signing_exclusivity_rejects_both_and_admits_either_or_neither() {
        // ADR-MCPS-028 §G / issue #58: delegated XOR exported TLS signing.
        // Exported only — the current default path — is fine.
        assert!(super::validate_tls_signing_exclusivity(false, true).is_ok());
        // Delegated only — what #59–#61 will configure — is fine.
        assert!(super::validate_tls_signing_exclusivity(true, false).is_ok());
        // Neither set — degenerate, not contradictory — is fine (the require()
        // checks elsewhere catch a genuinely missing credential).
        assert!(super::validate_tls_signing_exclusivity(false, false).is_ok());
        // BOTH set — contradictory — fails closed.
        let err = super::validate_tls_signing_exclusivity(true, true)
            .expect_err("delegated AND exported TLS signing must be rejected");
        assert!(
            err.contains("delegated XOR exported"),
            "the rejection must name the XOR rule, got: {err}"
        );
    }

    /// The leading PKCS#11-source flags (no `--tls-key`, no TLS label, no inner
    /// plane). Tests append the #59 toggles and then an `--inner-http-url` inner.
    fn pkcs11_lead_no_tls_key() -> Vec<String> {
        args(&[
            "--bind",
            "127.0.0.1:8443",
            "--audience",
            "did:example:server-1",
            "--server-signer",
            "did:example:server-1",
            "--server-key-id",
            "server-key-1",
            "--key-source",
            "pkcs11",
            "--pkcs11-module",
            "/opt/pkcs11/libmock_pkcs11.so",
            "--pkcs11-pin-file",
            "/etc/mcp-re/pkcs11-pin",
            "--pkcs11-token-label",
            "mcp-re-test",
            "--pkcs11-key-label",
            "mcp-re-response-signing",
            "--signing-key-seed",
            "/unused-seed",
            "--tls-cert",
            "/cert",
            "--client-ca",
            "/ca",
            "--trust",
            "/trust.json",
            "--target-uri",
            "https://mcp.example.com/mcp",
            "--delegated-trust-epoch",
            "epoch-min",
            "--trust-domain",
            "mcp.example.com",
        ])
    }

    fn with_inner_http_url(mut a: Vec<String>) -> Vec<String> {
        a.push("--inner-http-url".to_string());
        a.push("http://127.0.0.1:8080/mcp".to_string());
        a
    }

    /// #59: with `--pkcs11-tls-key-label`, the TLS handshake is DELEGATED to the
    /// token, so `--tls-key` is NOT required (it must not be read from disk) — the
    /// config parses and carries the TLS label.
    #[test]
    fn pkcs11_tls_label_makes_tls_key_optional() {
        let mut a = pkcs11_lead_no_tls_key();
        a.push("--pkcs11-tls-key-label".to_string());
        a.push("mcp-re-tls".to_string());
        a.extend(durable_replay());
        let config = parse_args(&with_inner_http_url(a))
            .expect("delegated TLS path parses without --tls-key");
        assert_eq!(config.pkcs11_tls_key_label.as_deref(), Some("mcp-re-tls"));
        assert_eq!(config.key_source, super::KeySourceKind::Pkcs11);
    }

    /// #59 / #58: `--pkcs11-tls-key-label` (delegated) PLUS an exported `--tls-key`
    /// is contradictory and fails closed via the XOR exclusivity guard.
    #[test]
    fn pkcs11_tls_label_with_exported_tls_key_is_rejected() {
        let mut a = pkcs11_lead_no_tls_key();
        a.push("--pkcs11-tls-key-label".to_string());
        a.push("mcp-re-tls".to_string());
        a.push("--tls-key".to_string());
        a.push("/exported-key".to_string());
        let err = parse_args(&with_inner_http_url(a))
            .expect_err("delegated + exported TLS key must be rejected");
        assert!(
            err.contains("delegated XOR exported"),
            "the rejection must name the XOR rule, got: {err}"
        );
    }

    /// #59: the TLS-key label only has meaning for the PKCS#11 source. A dangling
    /// `--pkcs11-tls-key-label` on a file source would silently do nothing (a false
    /// belief the TLS key is token-resident), so it fails closed.
    #[test]
    fn pkcs11_tls_label_without_pkcs11_source_is_rejected() {
        let a = args(&[
            "--bind",
            "127.0.0.1:8443",
            "--audience",
            "did:example:server-1",
            "--server-signer",
            "did:example:server-1",
            "--server-key-id",
            "server-key-1",
            "--signing-key-seed",
            "/seed",
            "--tls-cert",
            "/cert",
            "--tls-key",
            "/key",
            "--client-ca",
            "/ca",
            "--trust",
            "/trust.json",
            "--pkcs11-tls-key-label",
            "mcp-re-tls",
            "--inner-http-url",
            "http://127.0.0.1:8080/mcp",
        ]);
        let err = parse_args(&a).expect_err("dangling TLS label must be rejected");
        assert!(
            err.contains("--pkcs11-tls-key-label has no effect without --key-source pkcs11"),
            "got: {err}"
        );
    }

    /// #59: without a TLS-key label the PKCS#11 source keeps the exported-TLS-key
    /// path, so `--tls-key` is STILL required (no silent fallback to a delegated
    /// path that was not requested).
    #[test]
    fn pkcs11_without_tls_label_still_requires_tls_key() {
        let err = parse_args(&with_inner_http_url(pkcs11_lead_no_tls_key()))
            .expect_err("non-delegated pkcs11 must still require --tls-key");
        assert!(err.contains("--tls-key"), "got: {err}");
    }

    // ---- ADR-MCPS-021 Axis 2: build_revocation_resolver wiring ----------------
    //
    // These prove the helper does not merely label the tier but CHANGES runtime
    // behavior: Tier 2 (Live) reflects a store revocation immediately (no caching),
    // while Tier 1 (BoundedCache) caches within T. Uses the same ScriptedResolver
    // test-double style as `trust_cache` / `live_trust`.

    use super::build_revocation_resolver;
    use crate::revocation_tier::RevocationTier;
    use crate::trust_cache::UnixClock;
    use mcp_re_core::TrustResolverError;
    use mcp_re_core::VerificationKey;
    use std::sync::atomic::AtomicI64;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering as AtomicOrdering;

    const SEED_A_REV: [u8; 32] = [1u8; 32];

    fn rev_key() -> VerificationKey {
        SigningKey::from_seed_bytes(&SEED_A_REV).public_key()
    }

    /// A resolver whose outcome the test flips, counting inner consultations to
    /// prove caching (or its absence). Mirrors the other modules' doubles.
    struct ScriptedRevResolver {
        outcome: Mutex<Result<VerificationKey, TrustResolverError>>,
        calls: AtomicUsize,
    }
    impl ScriptedRevResolver {
        fn new(initial: Result<VerificationKey, TrustResolverError>) -> Self {
            ScriptedRevResolver {
                outcome: Mutex::new(initial),
                calls: AtomicUsize::new(0),
            }
        }
        fn set(&self, outcome: Result<VerificationKey, TrustResolverError>) {
            *self.outcome.lock().unwrap() = outcome;
        }
        fn calls(&self) -> usize {
            self.calls.load(AtomicOrdering::SeqCst)
        }
    }
    impl TrustResolver for ScriptedRevResolver {
        fn resolve(
            &self,
            _signer: &str,
            _key_id: &str,
        ) -> Result<VerificationKey, TrustResolverError> {
            self.calls.fetch_add(1, AtomicOrdering::SeqCst);
            self.outcome.lock().unwrap().clone()
        }
    }

    /// Box a shared scripted resolver as the helper's `base`, keeping a handle.
    fn base_over(inner: Arc<ScriptedRevResolver>) -> Box<dyn TrustResolver + Send + Sync> {
        struct Shared(Arc<ScriptedRevResolver>);
        impl TrustResolver for Shared {
            fn resolve(
                &self,
                signer: &str,
                key_id: &str,
            ) -> Result<VerificationKey, TrustResolverError> {
                self.0.resolve(signer, key_id)
            }
        }
        Box::new(Shared(inner))
    }

    fn fixed_clock(start: i64) -> (UnixClock, Arc<AtomicI64>) {
        let now = Arc::new(AtomicI64::new(start));
        let handle = now.clone();
        let clock: UnixClock = Box::new(move || now.load(AtomicOrdering::SeqCst));
        (clock, handle)
    }

    #[test]
    fn live_tier_wrapping_reflects_a_store_revocation_immediately() {
        // Proves Tier 2 (Live) was actually APPLIED: the wrapped resolver consults
        // the inner store on every call, so a store-side revocation is rejected on
        // the next request with no T wait and no caching.
        let inner = Arc::new(ScriptedRevResolver::new(Ok(rev_key())));
        let (clock, _now) = fixed_clock(1000);
        let resolver =
            build_revocation_resolver(&RevocationTier::Live, base_over(inner.clone()), clock);

        resolver
            .resolve("did:host", "key-1")
            .expect("active resolves");
        // Store flips to Revoked; NO clock advance (Live has no propagation window).
        inner.set(Err(TrustResolverError::Revoked));
        assert_eq!(
            resolver.resolve("did:host", "key-1").unwrap_err(),
            TrustResolverError::Revoked,
            "Live wrapping reflects a store revocation immediately"
        );
        assert_eq!(
            inner.calls(),
            2,
            "Live consults the inner store every call (no positive caching)"
        );
    }

    #[test]
    fn bounded_cache_tier_wrapping_caches_within_t() {
        // Proves Tier 1 (BoundedCache) was actually APPLIED: within T a second
        // resolve is served from cache and the inner store is consulted only once
        // — the opposite of the Live behavior above, so the two tiers are
        // genuinely distinct at runtime.
        let inner = Arc::new(ScriptedRevResolver::new(Ok(rev_key())));
        let (clock, _now) = fixed_clock(1000);
        let resolver = build_revocation_resolver(
            &RevocationTier::BoundedCache { t_secs: 60 },
            base_over(inner.clone()),
            clock,
        );

        resolver
            .resolve("did:host", "key-1")
            .expect("active resolves");
        // A store revocation within T is NOT seen — the cached active entry holds.
        inner.set(Err(TrustResolverError::Revoked));
        resolver
            .resolve("did:host", "key-1")
            .expect("within T the cached active entry is served");
        assert_eq!(
            inner.calls(),
            1,
            "BoundedCache consults the inner store once within T (caching is in effect)"
        );
    }

    #[test]
    fn push_tier_wrapping_behaves_as_bounded_t_with_an_inert_channel() {
        // Tier 3 over the inert in-process channel (no networked event source ships)
        // behaves exactly as bounded-T: within T a second resolve is a cache hit; a
        // store revocation is not picked up until T elapses.
        let inner = Arc::new(ScriptedRevResolver::new(Ok(rev_key())));
        let (clock, now) = fixed_clock(1000);
        let resolver = build_revocation_resolver(
            &RevocationTier::Push { t_secs: 60 },
            base_over(inner.clone()),
            clock,
        );

        resolver
            .resolve("did:host", "key-1")
            .expect("active resolves");
        inner.set(Err(TrustResolverError::Revoked));
        // Within T: still a cache hit (the inert channel delivers no push).
        resolver
            .resolve("did:host", "key-1")
            .expect("within T the bounded-T fallback serves the cached entry");
        assert_eq!(
            inner.calls(),
            1,
            "inert-channel Tier 3 is bounded-T (cache hit within T)"
        );
        // Past T: the bounded window caps exposure and the revocation is picked up.
        now.store(1000 + 60, AtomicOrdering::SeqCst);
        assert_eq!(
            resolver.resolve("did:host", "key-1").unwrap_err(),
            TrustResolverError::Revoked,
            "past T the bounded fallback re-resolves and picks up the revocation"
        );
        assert_eq!(inner.calls(), 2);
    }

    // `build_lb_assertion_binding` is never reached on the CLI happy path (the
    // lb-assertion binding is refused at parse), so cover the pure builder directly by
    // mutating a parsed Config — the wiring + the fail-closed key parse.
    #[test]
    fn build_lb_assertion_binding_wires_keys_and_fails_closed() {
        let mut c = parse_args(&minimal_durable()).expect("parse");
        assert!(
            super::build_lb_assertion_binding(&c).expect("ok").is_none(),
            "no binding when the selection is not lb-assertion"
        );
        c.binding = BindingKind::LbAssertion;
        c.ingress_lb_keys = vec![("lb-1".to_string(), lb_pub_b64())];
        assert!(super::build_lb_assertion_binding(&c)
            .expect("build")
            .is_some());
        c.ingress_lb_keys = vec![("lb-x".to_string(), "not-a-key".to_string())];
        assert!(
            super::build_lb_assertion_binding(&c).is_err(),
            "a malformed LB key must fail closed"
        );
    }

    #[test]
    fn load_trust_rejects_malformed_entries() {
        assert!(load_trust(br#"{"not":"an array"}"#).is_err());
        assert!(load_trust(br#"[{"key_id":"k","public_key":"x"}]"#)
            .unwrap_err()
            .contains("signer"));
        assert!(load_trust(br#"[{"signer":"s","public_key":"x"}]"#)
            .unwrap_err()
            .contains("key_id"));
        assert!(load_trust(br#"[{"signer":"s","key_id":"k"}]"#)
            .unwrap_err()
            .contains("public_key"));
    }

    #[test]
    fn parse_rejects_bad_values_and_names_each_missing_required_flag() {
        for (flag, val) in [
            ("--client-crl-reload-secs", "abc"),
            ("--max-connections", "abc"),
            ("--max-body-bytes", "abc"),
            ("--max-clock-skew", "abc"),
            ("--request-deadline-secs", "abc"),
            ("--read-timeout-secs", "abc"),
        ] {
            let mut a = minimal_durable();
            a.splice(0..0, args(&[flag, val]));
            assert!(parse_args(&a).is_err(), "{flag} {val} must be rejected");
        }
        // `--authz off` is the explicit no-authz selection (the default value).
        let mut a = minimal_durable();
        a.splice(0..0, args(&["--authz", "off"]));
        assert_eq!(parse_args(&a).expect("parse").authz, AuthzKind::Off);
        // Dropping any required (flag, value) pair fails closed naming the flag.
        for miss in [
            "--audience",
            "--server-signer",
            "--server-key-id",
            "--tls-cert",
            "--tls-key",
            "--client-ca",
            "--trust",
        ] {
            let mut a = minimal_durable();
            let i = a
                .iter()
                .position(|x| x == miss)
                .expect("required flag present");
            a.drain(i..i + 2);
            let e = parse_args(&a).unwrap_err();
            assert!(e.contains(miss), "missing {miss} must be named; got: {e}");
        }
    }
}
