//! Serve orchestration for the `mcp-re-proxy` binary, in the LIBRARY so it is
//! testable in-process (the binary is a thin shim over [`run`]). Builds the key
//! source, TLS config, replay tier, actor resolver and per-core async fleet from a
//! parsed [`crate::cli::Config`], then serves until the caller flips `shutdown`.
#![allow(clippy::too_many_lines)]

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use crate::async_replay::AsyncReplayTier;
use crate::async_replay::InMemoryAsyncAtomicReplayStore;
use crate::async_serve::ServedHttpRequest;
use crate::cli;
use crate::cli::BindingKind;
use crate::cli::KeySourceKind;
use crate::client_revocation;
use crate::config_snapshot;
use crate::delegated_server_signer::TrustEpochAdvance;
use crate::http_inner::HttpInnerPool;
use crate::http_profile_dispatch::ProxyDispatchConfig;
use crate::startup_plan::ReplayPlan;
use crate::tls;
use crate::transport::ExactMatchBinding;
use crate::transport::TransportBindingPolicy;
use crate::HttpProfileProxy;
use crate::IdentityStrategy;
use crate::ReverseProxyMtlsProvider;
use crate::RevocationTier;
use crate::ServerOptions;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::ResolverOutcome;
use mcp_re_http_profile::SignerSlot;
use std::collections::HashMap;

/// How often the trust-epoch counter is polled, in seconds.
///
/// The Tier-3 guarantee is "flush within one poll interval of an advance", so this is
/// the revocation latency the push tier actually delivers. Kept well inside the
/// bounded-`T` fallback so the push tier is still the faster of the two.
const TRUST_EPOCH_POLL_SECS: u64 = 5;

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A wall-clock reading below this Unix-seconds threshold at startup is treated as a
/// host-clock fault (audit #94 F5). `now_unix()` clamps a pre-epoch SystemTime error
/// to 0, and a host whose clock is unset typically reads at/near the epoch; either
/// way every freshness check will fail closed. The threshold is 2000-01-01 UTC — far
/// below any plausible real deployment time, so a legitimate clock never trips it,
/// but a 0/epoch clock always does.
const EPOCH_CLOCK_FAULT_THRESHOLD_SECS: i64 = 946_684_800;

/// The production [`UnixClock`] the revocation-tier resolver wrapping uses to bound
/// the propagation window `T` (ADR-MCPS-021). Delegates to the trust-cache's
/// system clock so production and the unit-tested helper share one clock type.
fn trust_clock() -> crate::trust_cache::UnixClock {
    crate::trust_cache::system_clock()
}

/// Build the serving [`crate::ActorResolver`] — the trust seam the RFC 9421 PEP
/// consults for every signature it verifies (slot discipline, MCPRE-100).
///
/// The Response slot answers only for `response_kid`, from the root/issuer public key
/// held at build time: that key is the deployment's trust anchor, revoked by root
/// rotation rather than by a trust-store entry.
///
/// The Request slot resolves through `request_trust` — the ADR-MCPS-021
/// revocation-tier resolver — on EVERY request. `trust_store` supplies only the
/// `kid -> signer` identity coordinate; deliberately not the key, since caching the
/// key here would re-freeze trust at process start and silently bypass the tier. It
/// is read through the SNAPSHOT rather than a captured `HashMap` for the same reason:
/// a kid removed from the trust file has to leave the request-signer set at the same
/// instant it stops resolving, or the two disagree for a whole reload cadence.
/// Every non-active outcome (`Revoked`, `NotFound`, `MalformedKey`, `Unavailable`)
/// yields no actor, which the verifier surfaces as `actor_binding_failed`; an
/// operational failure is never softened into an allow.
pub fn build_actor_resolver(
    signers: crate::reloading_trust::SignerDirectory,
    request_trust: Arc<dyn mcp_re_core::TrustResolver + Send + Sync>,
    trust_domain: String,
    response_kid: String,
    server_identity: ActorIdentity,
    response_pub: mcp_re_core::VerificationKey,
) -> crate::ActorResolver {
    Box::new(move |kid: &str, slot: SignerSlot| match slot {
        SignerSlot::Response if kid == response_kid => {
            ResolverOutcome::Resolved(Box::new(ResolvedActor {
                identity: server_identity.clone(),
                verification_key: response_pub.clone(),
                slot,
            }))
        }
        SignerSlot::Request => {
            // An unknown kid is a definitive negative from a healthy resolver.
            let Some(signer) = signers.signer_for(kid) else {
                return ResolverOutcome::NotTrusted;
            };
            // C079: `.ok()?` used to throw this error away, so a store OUTAGE and an
            // unknown keyid became the same observation and the outage was reported as
            // `actor_binding_failed`. `mcp-re-core` has always modelled the difference
            // (`TrustResolverError::Unavailable`); it simply could not cross the seam.
            // Both still fail closed — only the reported reason changes.
            let key = match request_trust.resolve(&signer, kid) {
                Ok(key) => key,
                Err(mcp_re_core::TrustResolverError::Unavailable { .. }) => {
                    return ResolverOutcome::Unavailable
                }
                Err(_) => return ResolverOutcome::NotTrusted,
            };
            ResolverOutcome::Resolved(Box::new(ResolvedActor {
                identity: ActorIdentity {
                    role: "client".to_string(),
                    trust_domain: trust_domain.clone(),
                    subject: signer,
                    keyid: kid.to_string(),
                },
                verification_key: key,
                slot,
            }))
        }
        _ => ResolverOutcome::NotTrusted,
    })
}

/// Enforce the key-file-permission posture for a sensitive key file. The proxy
/// always runs the maximal-security posture, so a group/world-accessible key file
/// is a HARD error returned to the caller (startup refuses). Uses the pure
/// [`cli::key_file_mode_is_insecure`] predicate so it stays consistent with (and
/// testable alongside) the parse-time checks.
#[cfg(unix)]
fn check_key_file_perms(path: &str, allow_group_read: bool) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mode = meta.permissions().mode();
        if let Some(reason) =
            cli::key_file_posture_violation(mode, meta.gid(), allow_group_read, &process_gids())
        {
            return Err(format!(
                "mcp-re-proxy refuses unsafe configuration:\n  - key file {path} \
                 is {reason} (mode {:o}); restrict to 0600",
                mode & 0o777
            ));
        }
    }
    Ok(())
}

/// The groups this process belongs to: the effective gid plus its supplementary
/// groups. Under Kubernetes `fsGroup` the mounted Secret is owned by a supplementary
/// group, not the effective one, so checking only `getegid()` would refuse the very
/// mount model the relaxation exists for.
#[cfg(unix)]
fn process_gids() -> Vec<u32> {
    let mut gids = vec![unsafe { libc::getegid() } as u32];
    // SAFETY: the two-call idiom — ask for the count, then fill a buffer of that size.
    unsafe {
        let count = libc::getgroups(0, std::ptr::null_mut());
        if count > 0 {
            let mut buf = vec![0 as libc::gid_t; count as usize];
            if libc::getgroups(count, buf.as_mut_ptr()) >= 0 {
                gids.extend(buf);
            }
        }
    }
    gids
}
/// Every private-key file this config causes the proxy to READ from disk.
///
/// Pure, so the decision is testable on its own — the defect this replaces was not in
/// the permission predicate but in which files it was pointed at.
///
/// The rule follows the files, not the key-source name. The signing seed is read only
/// under `file` custody; a PKCS#11/KMS source never surrenders it, and those sources
/// thread the path only into the `FileKeySource` they use for TLS material. The TLS
/// server private key, by contrast, is read under EVERY custody mode unless TLS signing
/// is itself delegated — and `cli::parse_args` leaves `tls_key` empty in exactly that
/// delegated case, which is why emptiness is the right test rather than the mode.
///
/// Gating the whole check on `key_source == File` therefore skipped the one private key
/// that DOES land in the pod in precisely the modes advertised as "no key material ever
/// lands in the pod": a Secret mounted with Kubernetes' default 0644 booted silently.
fn key_files_read_from_disk(config: &cli::Config) -> Vec<&str> {
    let mut paths = Vec::new();
    if config.key_source == KeySourceKind::File && !config.signing_key_seed.is_empty() {
        paths.push(config.signing_key_seed.as_str());
    }
    if !config.tls_key.is_empty() {
        paths.push(config.tls_key.as_str());
    }
    // The PKCS#11 User PIN file is not a key, but it is the credential that unlocks the
    // token holding the signing and (optionally) TLS keys — so a group/world-readable PIN
    // file is as good as a readable key file, and belongs behind the same floor.
    if let Some(pin_file) = config.pkcs11_pin_file.as_deref() {
        if !pin_file.is_empty() {
            paths.push(pin_file);
        }
    }
    paths
}

/// No-op off unix: the mode bits this guard reads do not exist there. Kept in step with
/// the unix signature above — it had drifted to a second `strict` parameter no caller
/// passes, so this arm could not have compiled.
#[cfg(not(unix))]
fn check_key_file_perms(_path: &str, _allow_group_read: bool) -> Result<(), String> {
    Ok(())
}

/// Build every component from `config` and serve on the per-core async fleet until
/// `shutdown` is flipped (SIGTERM/SIGINT in the binary; a test flag in tests). The
/// binary's `main` is a thin shim over this; keeping it in the library makes the
/// whole deployed serving path in-process-testable.
///
/// The signature still takes a raw [`crate::cli::Config`], and validation happens HERE
/// rather than being the caller's job. `Config` has 76 public fields, so a caller that
/// builds one in code — an embedder, a harness, a test — used to reach the serving path
/// having run none of the parse-time safety guards. Validating at the boundary closes
/// that without breaking any existing caller: every guard now runs whichever way the
/// config was produced, and nothing past this point sees an unchecked `Config`.
pub fn run(
    config: crate::cli::Config,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<(), String> {
    let validated = crate::cli::ValidatedConfig::try_from(config)?;
    run_validated(&validated, shutdown)
}

/// The serving path proper. Reachable only with a [`crate::cli::ValidatedConfig`], which
/// is the whole point: there is no route into it that skips the guards.
fn run_validated(
    config: &crate::cli::ValidatedConfig,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<(), String> {
    // Every long-lived thread startup creates belongs to this set (ADR-MCPRE-056 §9).
    // It is declared before the first of them and dropped when this function returns by
    // ANY path, so the ~38 fallible expressions between here and `serve_fleet` each halt
    // and reclaim the workers already running on their way out. None of them says so:
    // that is the point of expressing the lifetime as ownership instead of as cleanup
    // nobody was going to write at 38 return points.
    let mut workers = crate::managed_worker::WorkerSet::new(Arc::clone(&shutdown));
    // Clock-fault diagnosis (audit #94 F5). `now_unix()` deliberately maps a
    // pre-epoch SystemTime error to 0 (fail CLOSED — every request then fails its
    // freshness check rather than admitting a stale one), but a clock that reads
    // at/near the Unix epoch would otherwise surface only as an unexplained flood of
    // freshness denials. Emit a ONE-TIME loud startup warning so a broken/unset host
    // clock is diagnosed at the source instead of masked. We do not refuse to start
    // (the fail-closed posture is already safe), but the operator is told why every
    // request will be denied.
    // Read the clock ONCE so the comparison and the reported value are consistent
    // (a second now_unix() call could read a different instant).
    let startup_now_unix = now_unix();
    if startup_now_unix < EPOCH_CLOCK_FAULT_THRESHOLD_SECS {
        eprintln!(
            "mcp-re-proxy: WARNING: the system clock reads at/near the Unix epoch ({} < {}s); this \
             almost certainly means the host clock is unset or broken. Freshness checks will \
             FAIL CLOSED (every request denied) until the clock is corrected — fix the host clock \
             (NTP/RTC) rather than treating the resulting denials as a load problem.",
            startup_now_unix,
            EPOCH_CLOCK_FAULT_THRESHOLD_SECS,
        );
    }

    // Security posture note. The hard guards (cn_legacy, memory/weak replay,
    // over-ceiling/disabled cert lifetime, reverse-proxy ingress, lb-assertion,
    // node-local replay under --fleet) are ALL rejected at parse time by
    // `cli::unsafe_config_violations` — the proxy never reaches here with them. Only
    // the env key source (a dev/CI-only build, `dev_env_key_source`) is worth a
    // runtime note, since that build deliberately permits it.
    if config.key_source == KeySourceKind::Env {
        eprintln!(
            "mcp-re-proxy: WARNING: --key-source env is a dev/CI-only build (dev_env_key_source); \
             env key material is visible to the process tree. Never use in production."
        );
    }
    // MCPS-3840 reverse-proxy ingress trust assumption — emit LOUDLY. When the
    // identity is read from a trusted forwarded header, mTLS is terminated by an
    // upstream proxy and the local client certificate is NOT consulted for
    // identity. This is only safe if the listening socket is reachable ONLY by
    // the trusted upstream; anyone who can reach the port could otherwise spoof
    // any identity by setting the header. (Strict ingress enforcement is #3842.)
    if let Some(header) = &config.reverse_proxy_identity_header {
        eprintln!(
            "mcp-re-proxy: WARNING: reverse-proxy identity mode is ENABLED (reading the trusted \
             header '{header}', format {:?}, identity field {:?}). mTLS is assumed terminated \
             UPSTREAM and the local client certificate is NOT used for identity. You are \
             asserting the listening socket {} is reachable ONLY by the trusted upstream \
             (loopback / private network / its own mTLS link) and that the upstream STRIPS any \
             client-supplied copy of '{header}' before setting its own. If the socket is \
             reachable by untrusted clients, they can SPOOF any identity.",
            config.reverse_proxy_header_format, config.identity_source, config.bind,
        );
    }
    // A group/world-readable key file is a HARD error (refuse startup). The other
    // guards are parse-time and already enforced inside `cli::parse_args`; this one is
    // filesystem-dependent so it lives here.
    for path in key_files_read_from_disk(config) {
        check_key_file_perms(path, config.allow_group_readable_key_files)?;
    }
    // A disabled (`none`/`0`) or over-ceiling `--max-client-cert-lifetime` is
    // rejected at parse time (`cli::unsafe_config_violations`), so by here it is
    // always a bounded lifetime within the ceiling — no runtime check needed.

    // Key material + trust.
    //
    // Issue #3838 (ADR-MCPS-014): the response-signing key is NOT extracted here.
    // We pull the TLS materials (still export accessors, by #3838 scope) and the
    // client-CA roots from the key source, then hand the SAME boxed source to the
    // proxy AS its response signer (`Box<dyn KeySource>: ResponseSigner`). The proxy
    // signs by delegation (`sign_response`), so a non-exporting HSM/KMS source would
    // never need to surrender its private key — there is deliberately no
    // `signing_key()` export call on the wiring path anymore.
    let key_source = cli::build_key_source(config).map_err(|e| e.to_string())?;
    let server_chain = key_source
        .tls_server_cert_chain()
        .map_err(|e| e.to_string())?;
    let client_ca = key_source.client_ca_roots().map_err(|e| e.to_string())?;
    // ADR-MCPS-028 §G / issue #58: TLS signing is DELEGATED xor EXPORTED. When the
    // source offers a delegated TLS signer the server private key never leaves the
    // device — `tls_server_key()` is never called. The exported key is read ONLY on the
    // non-delegated path. The CLI exclusivity guard (`cli::parse_args`) already rejected
    // a config that asks for both.
    //
    // The sum type is built HERE, where custody becomes known, so the exclusivity is a
    // property of the value rather than an agreement between two `Option`s that later
    // code has to re-derive.
    let tls_material = match key_source.tls_delegated_signer() {
        Some(signer) => TlsKeyMaterial::Delegated(signer),
        None => TlsKeyMaterial::Exported(key_source.tls_server_key().map_err(|e| e.to_string())?),
    };
    // ADR-MCPS-021 Axis 2: the base trust store the revocation tiers resolve against.
    //
    // It is a SNAPSHOT the reload task can swap, not a map deserialised once and
    // frozen for the process lifetime. Every tier describes itself in terms of "the
    // store" — Tier 2 consults it per verification, Tier 3 evicts and forces a
    // re-resolve against it — and none of those descriptions was a true statement
    // about the deployment while the store could not change: revoking a client
    // signing key meant editing the file and restarting every replica, so the
    // exposure window was unbounded while the startup line advertised near-zero.
    // The response kid is the deployment's own issuer key id; it is excluded from the
    // request-signer set so the root can never be presented as a client credential.
    let response_kid = config
        .delegated_issuer_kid
        .clone()
        .unwrap_or_else(|| config.server_key_id.clone());
    let trust_store = Arc::new(load_trust_snapshot(&config.trust_path, &response_kid)?);

    // ADR-MCPS-021 Axis 2: surface the DECLARED revocation tier and its honest
    // guarantee at startup. The proxy emits the tier's OWN guarantee string — never
    // a hardcoded stronger one — so it cannot surface a revocation window stronger
    // than the configured tier proves (the tier-claim ceiling). Tier 1
    // (bounded-cache) is the default when --revocation-tier is absent.
    // The tier's window is a claim about how fast a REVOKED key stops resolving, and
    // nothing resolves faster than `--trust` is re-read. The qualifier belongs on the
    // tier line itself: as a separate line further down it was routinely read as being
    // about something else, and the tier line was quoted on its own.
    eprintln!(
        "mcp-re-proxy: {} store-change-cadence={}",
        config.revocation_tier.startup_audit_line("trust-store"),
        store_change_cadence(config.trust_reload_secs)
    );
    // ADR-MCPS-021 Axis 2: APPLY the declared tier to the resolver so the runtime
    // behavior actually matches the surfaced guarantee (Tier 1 bounds cached active
    // trust to T; Tier 2 consults the store live every request; Tier 3 evicts on a
    // pushed event, else falls back to bounded T). Without this wrapping the tier
    // line above would be a claim the resolver does not enforce.
    // MCPS-84: connect the networked trust-epoch invalidation channel if one is
    // configured (only under --revocation-tier push; enforced at parse time).
    let push_channel = build_trust_epoch_channel(config, &mut workers)?;
    if let RevocationTier::Push { .. } = config.revocation_tier {
        if push_channel.is_none() {
            // Honesty (Tier 3): with no networked source wired, the in-process
            // reference channel is inert — Tier 3 runs at its bounded-`T` fallback
            // (already reflected in the tier's `guarantee()` string above), NOT an
            // active near-zero push channel. Configure --trust-epoch-redis-url to
            // activate the networked source (MCPS-84).
            eprintln!(
                "mcp-re-proxy: NOTE: revocation-tier PUSH has no networked event source (no \
                 --trust-epoch-redis-url), so it runs at its bounded-T fallback; set \
                 --trust-epoch-redis-url to activate the trust-epoch push source."
            );
        }
    }
    let resolver = cli::build_revocation_resolver_with_channel(
        &config.revocation_tier,
        Box::new(crate::reloading_trust::SharedTrustStore(Arc::clone(
            &trust_store,
        ))),
        trust_clock(),
        push_channel,
    );
    // Re-read `--trust` on a cadence so a key removed from the file stops resolving on
    // a RUNNING replica. Without it the tier wrappers above wrap an immutable map and
    // the guarantee printed a few lines up is not one the data plane can keep.
    // Whether the store behind the resolver is still changing. Only meaningful where a
    // reload is running: with `--trust-reload-secs` absent the store is frozen by
    // design and says so on the OFF line below, so there is no freshness to lose.
    let trust_freshness = Arc::new(TrustStoreFreshness::default());
    if let Some(interval_secs) = config.trust_reload_secs {
        spawn_trust_reload_task(
            &mut workers,
            Arc::clone(&trust_store),
            config.trust_path.clone(),
            response_kid.clone(),
            interval_secs,
            Arc::clone(&trust_freshness),
        );
        eprintln!(
            "mcp-re-proxy: trust store reload ACTIVE every {interval_secs}s: a key removed              from {} stops resolving within one cadence, with no restart.",
            config.trust_path
        );
    } else {
        eprintln!(
            "mcp-re-proxy: trust store reload OFF: --trust is read once at startup, so              revoking a request-signer key requires restarting every replica. The              revocation-tier guarantee above bounds CACHING, not the store itself. Set              --trust-reload-secs to bound it."
        );
    }

    // ADR-MCPRE-051 §3: the inner MCP server is reached over the ASYNC HTTP inner
    // plane — a stateless Streamable-HTTP backend fronted by the pooled hyper
    // client wired below. The proxy launches NO subprocess and carries no sandbox:
    // an unmodified local stdio MCP server is fronted by the out-of-TCB
    // `mcp-re-stdio-bridge` adapter and reached over HTTP like any other backend.
    if config.inner_http_urls.is_empty() {
        return Err(
            "the proxy serves over an async HTTP inner plane: pass --inner-http-url <url>. \
             To protect a local stdio MCP server, run it behind the mcp-re-stdio-bridge adapter \
             and point --inner-http-url at the bridge."
                .to_string(),
        );
    }

    // Build the RFC 9421 serving PEP (ADR-MCPRE-050 sole carrier). The trust file
    // supplies the ActorResolver: each trusted key_id resolves to a structured
    // ResolvedActor — client keys for the Request slot, the server key for the
    // Response slot (slot discipline, MCPRE-100).
    //
    // The Request slot resolves its verification key through the ADR-MCPS-021
    // revocation-tier resolver built above, so the tier whose guarantee is printed
    // at startup is the tier the data plane actually runs: a `Revoked`/`NotFound`
    // binding rejects the request, and an `Unavailable` fails closed rather than
    // serving a key. The trust file supplies only the kid -> signer identity
    // coordinate; the KEY comes from the resolver on every request.
    let resolver: Arc<dyn mcp_re_core::TrustResolver + Send + Sync> = Arc::from(resolver);
    // OUTSIDE the tier wrappers, so a bounded-cache hit cannot answer from a snapshot
    // the reload has stopped being able to refresh. Only where a reload is running: a
    // deployment without one has already been told its store cannot change at all.
    let resolver: Arc<dyn mcp_re_core::TrustResolver + Send + Sync> =
        if config.trust_reload_secs.is_some() {
            Arc::new(StaleFailsClosed {
                inner: resolver,
                freshness: Arc::clone(&trust_freshness),
            })
        } else {
            resolver
        };
    // Response-slot signing custody (ADR-MCPRE-052, MCPRE-122): delegated-signing is
    // the ONLY response mode. The ROOT key is the credential ISSUER only; the resolver
    // resolves the ROOT public key (by its issuer kid) for the Response slot, and NO
    // directly-held server key exists. The delegated key is never enrolled (authorized
    // by the credential alone). The root key source is only borrowed here (for its
    // public key); it is moved into the issuer at proxy build, so KMS-rooted delegated
    // signing works on the async serving path.
    let response_pub = key_source
        .response_public_key()
        .map_err(|e| e.to_string())?;
    let server_identity = ActorIdentity {
        role: "server".to_string(),
        trust_domain: config.trust_domain.clone(),
        subject: config.server_signer.clone(),
        keyid: response_kid.clone(),
    };
    let resolve_actor = build_actor_resolver(
        trust_store.signer_directory(),
        Arc::clone(&resolver),
        config.trust_domain.clone(),
        response_kid.clone(),
        server_identity.clone(),
        response_pub,
    );
    let expected_audience = AudienceTuple {
        audience_id: config.audience.clone(),
        target_uri: config.target_uri.clone(),
        route: config.route.clone(),
    };
    // The authoritative async replay tier (§4) + deployment durability posture,
    // selected below; default is the single-replica in-memory tier.
    // `mut` is load-bearing only under the durable-store features, whose match arms
    // reassign these below; without those features the bindings are never rewritten.
    #[cfg_attr(
        not(any(feature = "cpstore_etcd", feature = "redis_replay")),
        allow(unused_mut)
    )]
    let mut replay_async = AsyncReplayTier::new(
        Arc::new(InMemoryAsyncAtomicReplayStore::new()),
        config.max_clock_skew,
    );
    #[cfg_attr(
        not(any(feature = "cpstore_etcd", feature = "redis_replay")),
        allow(unused_mut)
    )]
    let mut dispatch_cfg = ProxyDispatchConfig {
        fleet_strict: false,
        tier: None,
    };
    let mut transport_binding: Option<Box<dyn TransportBindingPolicy + Send + Sync>> = None;
    // ADR-MCPRE-051 §4: select the AUTHORITATIVE async replay tier. The atomic
    // insert-if-absent is AWAITED on the per-core request path without blocking a
    // runtime worker. Memory (default) is single-replica; Shared selects a durable
    // networked store — etcd (CP/linearizable) or redis (horizontally scaled) —
    // both fail closed on any store error (an outage is never a fresh nonce).
    // `--replay-cache file` is not offered on the async fleet: a single file-backed
    // cache does not fit the per-core, share-nothing data plane (ADR-MCPRE-051 §1).
    // The redis ConnectionManager's reconnect task lives on a process-lifetime
    // control runtime (`control_rt`), distinct from the per-core serving
    // runtimes; it is held alive for the whole serve.
    // ONE process-lifetime control runtime for every networked control-plane client:
    // the redis replay ConnectionManager's reconnect task, the admission source and the
    // MRTR continuation store. Distinct from the per-core serving runtimes and held
    // alive for the whole serve. Created on demand by [`control_runtime`], so a seam
    // that needs it is never gated on some OTHER seam having created it first.
    // `mut` only bites where a networked control-plane client exists to build it.
    #[cfg_attr(not(feature = "redis_replay"), allow(unused_mut))]
    let mut control_rt: Option<tokio::runtime::Runtime> = None;
    // Which tier this deployment asked for is decided purely, from configuration alone;
    // the arms below only establish it. Every refusal the plan can raise is a statement
    // about the config; every refusal left here is a statement about the build or the
    // environment.
    let replay_plan = crate::startup_plan::ReplayPlan::from_config(config)?;
    match &replay_plan {
        ReplayPlan::Memory => {
            // Proxy::new already installed the in-memory async tier (single-replica).
        }
        ReplayPlan::Etcd { endpoint, tier } => {
            #[cfg(feature = "cpstore_etcd")]
            {
                eprintln!(
                    "mcp-re-proxy: replay tier = shared (CP/linearizable; async etcd backend)"
                );
                eprintln!("mcp-re-proxy: {}", tier.startup_audit_line("etcd"));
                let store = Arc::new(
                    crate::async_etcd_store::EtcdAsyncAtomicReplayStore::connect(endpoint),
                );
                replay_async =
                    crate::async_replay::AsyncReplayTier::new(store, config.max_clock_skew);
                dispatch_cfg = ProxyDispatchConfig {
                    fleet_strict: true,
                    tier: Some(tier.clone()),
                };
            }
            #[cfg(not(feature = "cpstore_etcd"))]
            {
                let _ = (endpoint, tier);
                return Err("--replay-durability-tier linearizable requires a build with the `cpstore_etcd` feature".to_string());
            }
        }
        ReplayPlan::Redis { url, tier } => {
            #[cfg(feature = "redis_replay")]
            {
                eprintln!(
                    "mcp-re-proxy: replay tier = shared (horizontally-scaled; async Redis backend)"
                );
                eprintln!("mcp-re-proxy: {}", tier.startup_audit_line("redis"));
                // The ConnectionManager's reconnect task runs on this dedicated
                // process-lifetime runtime, distinct from the per-core serving
                // runtimes; held alive by `control_rt` for the whole serve.
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(1)
                    .enable_all()
                    .build()
                    .map_err(|e| format!("build replay control runtime: {e}"))?;
                // The client-side response timeout is sized for the DECLARED WAIT
                // timeout before connecting: the library defaults to 500ms per
                // command, and `WAIT` is an ordinary command — so a declared
                // `redis-wait-quorum:2:2000` could never wait 2000ms, and any
                // replica ack slower than 500ms failed the request closed while the
                // startup line advertised the fuller window.
                let wait_timeout_ms = tier.wait_quorum_params().map(|(_, ms)| ms);
                let mut store = rt
                    .block_on(
                        crate::RedisAsyncAtomicReplayStore::connect_with_wait_timeout(
                            url,
                            crate::redis_store::system_clock(),
                            wait_timeout_ms,
                        ),
                    )
                    .map_err(|e| format!("connect redis async replay store: {e:?}"))?;
                // Apply the DECLARED durability tier to the store that actually
                // serves. `startup_audit_line` above promises "WAIT timeout or
                // insufficient acks fail closed" for REDIS_WAIT_QUORUM; without
                // this the store would run plain SET NX PX and the promise would
                // be audited but unenforced.
                if let Some((quorum, timeout_ms)) = tier.wait_quorum_params() {
                    store = store.with_wait_quorum(quorum, timeout_ms);
                }
                let store = Arc::new(store);
                replay_async =
                    crate::async_replay::AsyncReplayTier::new(store, config.max_clock_skew);
                dispatch_cfg = ProxyDispatchConfig {
                    fleet_strict: true,
                    tier: Some(tier.clone()),
                };
                control_rt = Some(rt);
            }
            #[cfg(not(feature = "redis_replay"))]
            {
                let _ = (url, tier);
                return Err("--replay-cache shared (redis) requires a build with the `redis_replay` feature".to_string());
            }
        }
    }
    // #78 (ADR-MCPS-020), OBJECT-LEVEL defense in depth beneath the CLI-flag gate:
    // the CLI's unsafe_config_violations rejects the `--replay-cache memory`
    // SELECTION, but the proxy's replay cache is a `Box<dyn ReplayCache>` that can
    // also be INJECTED (`with_replay_cache`). Assert the cache the proxy actually
    // holds self-declares a durable posture, so a volatile single-process reference
    // cache can never reach a production verify path even if it arrived by injection
    // rather than the default selection. mcp-re-core's `durability_class()` defaults
    // (fail closed) to the single-process reference, so an undeclared cache is
    // rejected here too.
    if replay_async.durability_class() == mcp_re_core::ReplayDurabilityClass::SingleProcessReference
    {
        return Err(
            "the configured replay cache self-declares the volatile single-process reference \
             posture (admitted nonces are lost on restart and invisible to peer verifiers); \
             a durable replay store is required — use --replay-cache file or --replay-cache \
             shared, or inject a cache that declares ReplayDurabilityClass::Durable"
                .into(),
        );
    }
    // Authorization policy enforcement is DEFERRED on the RFC 9421 serving path — the
    // authorization evaluator is not yet built on this carrier. A configured policy
    // fails closed rather than silently not enforce.
    if config.authz == cli::AuthzKind::Reference {
        return Err(
            "authorization policy enforcement is not yet wired on the RFC 9421 serving path \
             (the authorization evaluator is not yet built on this carrier); it must be rebuilt on \
             the HTTP-profile request evidence before an authz profile can be enabled"
                .to_string(),
        );
    }
    // Mode-A transport binding: bind the verified request actor to the mTLS peer.
    if config.binding == BindingKind::Exact {
        transport_binding = Some(Box::new(ExactMatchBinding::new()));
    }
    // Tier-3 LB assertion (Mode B) and Mode-C attested ingress bind the request hash
    // under the OWNER-SIGNED security boundary; re-binding them to the RFC 9421
    // request-evidence digest is pending owner authorization — fail closed rather than
    // silently drop the channel binding.
    if matches!(
        config.binding,
        BindingKind::LbAssertion | BindingKind::AttestedIngress
    ) {
        return Err(
            "Tier-3 LB / Mode-C attested-ingress transport binding is not yet supported on the \
             RFC 9421 serving path (owner-signed security-boundary rebinding pending); use \
             --binding exact (end-to-end mTLS) for the RFC 9421 carrier"
                .to_string(),
        );
    }

    // Offline client-cert CRLs (#3839). Loaded once at startup; a missing or
    // malformed CRL file fails closed here. OFFLINE revocation only — there is no
    // online OCSP / distribution-point fetching (deferred to a follow-up).
    let client_crls = cli::load_client_crls(&config.client_crl_paths)?;
    if !client_crls.is_empty() {
        eprintln!(
            "mcp-re-proxy: offline client-cert revocation enabled — {} CRL file(s), unknown status \
             DENIED (fail closed) (OFFLINE only; no online OCSP/CRL-DP fetching)",
            config.client_crl_paths.len(),
        );
        // ADR-MCPS-023 §A1 (MCPS-58): the verifier enforces CRL nextUpdate, so a
        // stale CRL fails every new handshake closed. Surface that at BOOT — refuse
        // to start on a stale CRL — and warn while a CRL is near expiry so a
        // refreshed CRL can be installed before the cutover ("restart before
        // nextUpdate"; the in-process hot-reloader is a v0.10 follow-up). A malformed
        // CRL is a hard startup error (fail closed).
        const CRL_NEAR_EXPIRY_WARN_SECS: i64 = 6 * 3600;
        for (i, crl) in client_crls.iter().enumerate() {
            match tls::crl_freshness(crl.as_ref(), startup_now_unix, CRL_NEAR_EXPIRY_WARN_SECS)
                .map_err(|e| e.to_string())?
            {
                tls::CrlFreshness::Fresh => {}
                tls::CrlFreshness::NearExpiry { next_update_unix } => eprintln!(
                    "mcp-re-proxy: WARNING: client CRL #{i} is near expiry (nextUpdate={next_update_unix}); \
                     install a refreshed CRL and restart before then, or new handshakes will fail closed."
                ),
                tls::CrlFreshness::Stale { next_update_unix } => {
                    let msg = format!(
                        "client CRL #{i} is STALE (nextUpdate={next_update_unix} <= now={startup_now_unix}): \
                         with CRL expiration enforced, every new client handshake fails closed. Install a \
                         CRL published within its nextUpdate window."
                    );
                    return Err(format!(
                        "mcp-re-proxy refuses to start with a stale client CRL: {msg}"
                    ));
                }
            }
        }
    }

    // ADR-MCPS-023 §A1 (MCPS-58): operator-visible revocation POSTURE DIAGNOSTIC.
    // This is a posture diagnostic, NOT a structured per-request audit guarantee —
    // the structured evidence vocabulary (including `delegated_attestor_crl`, which
    // does not exist yet) lands with Mode C attested ingress (MCPS-62). These lines
    // deliberately use the canonical ADR field names so that future audit surface
    // can reuse them verbatim. OCSP posture is per-request (no-AIA is a per-cert
    // fact, not a config-load one) and likewise belongs to the MCPS-62 surface, not
    // this startup line.
    {
        let exposure_window = match config.max_client_cert_lifetime {
            Some(d) => format!("{}s", d.as_secs()),
            None => "unbounded".to_string(),
        };
        // The exposure window above is only true because these two bounds hold: the
        // certificate is re-checked against the clock on EVERY request (not just at
        // the handshake), and a connection is closed at a bounded age so the peer must
        // re-handshake through the current CRL. Stated alongside the window it makes
        // honest.
        eprintln!(
            "mcp-re.revocation.posture connection_max_age={} per_request_cert_validity=enforced \
             per_request_crl_check={} tls_session_resumption=epoch-bound",
            match config.limits.max_connection_age {
                Some(d) => format!("{}s", d.as_secs()),
                None => "unbounded".to_string(),
            },
            // The claim the CRL lines below rest on. rustls consults the CRLs during
            // client authentication, which runs on a full handshake only, so without
            // this a revoked peer serves every later request on the connection it
            // already holds and the reload cadence below describes new connections
            // alone.
            if client_crls.is_empty() {
                "not_configured"
            } else {
                "enforced"
            }
        );
        if client_crls.is_empty() {
            let max_lifetime = match config.max_client_cert_lifetime {
                Some(d) => format!("{}s", d.as_secs()),
                None => "none".to_string(),
            };
            eprintln!(
                "mcp-re.revocation.posture revocation_mode=short_lived_cert dynamic_revocation=false \
                 exposure_window={exposure_window} max_client_cert_lifetime={max_lifetime}"
            );
        } else {
            for (i, crl) in client_crls.iter().enumerate() {
                let posture = tls::crl_posture(crl.as_ref()).map_err(|e| e.to_string())?;
                let next_update = posture
                    .next_update_unix
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "none".to_string());
                eprintln!(
                    "mcp-re.revocation.posture revocation_mode=static_crl_snapshot \
                     dynamic_revocation=false stale_crl_policy=fail_closed crl_index={i} \
                     crl_digest={} crl_this_update={} crl_next_update={} \
                     exposure_window={exposure_window}",
                    posture.crl_digest, posture.this_update_unix, next_update
                );
            }
        }
    }

    // MCPS-85 (ADR-MCPS-049 clause 3): under --fleet, state the PER-TIER
    // cross-replica revocation-lag bounds explicitly, derived from real config
    // (the two tiers have different cadences). Zero-window revocation is never
    // claimed on either.
    if config.fleet {
        let trust_bound = fleet_trust_bound(
            &config.revocation_tier,
            config.trust_epoch_redis_url.is_some(),
            config.trust_reload_secs,
        );
        let crl_bound = if client_crls.is_empty() {
            let window = config
                .max_client_cert_lifetime
                .map(|d| format!("{}s", d.as_secs()))
                .unwrap_or_else(|| "unbounded".to_string());
            format!("short-lived-cert only (exposure_window {window}); no client CRL")
        } else {
            match config.client_crl_reload_secs {
                // The reload cadence IS the bound, on open and new connections alike:
                // a republished index is consulted by the next request on a connection
                // the peer is already holding.
                Some(secs) => format!(
                    "bounded {secs}s (the --client-crl-reload-secs cadence), enforced per request \
                     on established connections as well as at the handshake"
                ),
                None => "the CRL nextUpdate / a restart (no --client-crl-reload-secs) — a fleet's \
                         CRL-rollout window"
                    .to_string(),
            }
        };
        eprintln!(
            "mcp-re-proxy: FLEET cross-replica revocation-lag bounds (ADR-MCPS-049 clause 3): \
             trust-key-status={trust_bound}; client-cert-crl={crl_bound}; zero-window revocation \
             NOT claimed"
        );
    }

    // TLS server. ADR-MCPS-028 §G / issue #58: on the delegated path rustls drives
    // the handshake signature through the device/KMS signer (TLS private key never
    // exported); the validated builder fails closed at construction if the leaf cert
    // is not Ed25519 or its key does not match the signer. Otherwise the exported-key
    // path is used verbatim.
    // ADR-MCPRE-051 §6 (MCPRE-116): capture the rebuild inputs BEFORE the match
    // consumes them, so the opt-in CRL hot-reload task can rebuild the verifier from a
    // refreshed `--client-crl` without a restart.
    //
    // BOTH custody paths are reloadable. The delegated path used to warn and keep a
    // static snapshot, which put the weakest revocation posture on the deployments
    // with the STRONGEST key custody: a client certificate revoked after startup kept
    // authenticating for the whole process lifetime, silently, on exactly the
    // configurations that took the most care with keys. The signer is an `Arc` and the
    // certificate material is immutable, so a rebuild needs nothing the exported path
    // does not also need.
    // The delegated-TLS custody paths sign the handshake through a KMS or a PKCS#11
    // token, synchronously, inside rustls' `Signer::sign` — so the serving runtime
    // shape has to account for a blocking signer (see `async_fleet`).
    let is_delegated_tls = tls_material.is_delegated();
    if is_delegated_tls {
        eprintln!(
            "mcp-re-proxy: TLS custody = DELEGATED: the handshake signature is a blocking \
             KMS/PKCS#11 call inside rustls' synchronous signer, so each core serves on a \
             small worker pool rather than the single-threaded share-nothing default. A \
             stalled signer then costs one worker instead of a whole core."
        );
    }
    // Cloned because the initial build below consumes the originals; the reload re-reads
    // only the CRLs, never these.
    let reload_chain = server_chain.clone();
    let reload_client_ca = client_ca.clone();
    let reload_crl_paths = config.client_crl_paths.clone();
    // The CRL verifier ALWAYS fails closed on an unknown revocation status — there
    // is no relax knob. `false` = deny-unknown, threaded to every verifier builder.
    let reload_allow_unknown = false;

    // The PER-REQUEST revocation index, built from the same CRL bytes the handshake
    // verifier is about to be given. Installed only when CRLs are configured: with
    // none, rustls performs no revocation checking, and installing an index would put
    // a check on the request path that the handshake does not perform.
    //
    // Without this, revocation reaches only NEW connections. rustls runs client
    // authentication on a full handshake alone, so a peer added to a reloaded CRL keeps
    // serving every request on the connection it already holds.
    let client_revocation = if client_crls.is_empty() {
        None
    } else {
        let index = client_revocation::ClientRevocationIndex::from_crl_ders(
            &client_crls
                .iter()
                .map(|crl| crl.as_ref().to_vec())
                .collect::<Vec<_>>(),
            reload_allow_unknown,
        )
        .map_err(|e| e.to_string())?;
        Some(Arc::new(client_revocation::SharedClientRevocation::new(
            index,
        )))
    };

    // The same construction a CRL reload performs, so the serving config a reload
    // installs cannot diverge from the one startup installed.
    let server_config = tls_material.rebuild(server_chain, client_ca, client_crls, false)?;
    // ADR-MCPRE-051 §6 (MCPRE-116): the serve loop reads the current config from a
    // versioned, atomically-swappable snapshot instead of a fixed `Arc`. With no
    // `--client-crl-reload-secs` the snapshot is never swapped, so behavior is
    // byte-identical to the static posture.
    let config_snapshot = Arc::new(config_snapshot::ServerConfigSnapshot::new(Arc::new(
        server_config,
    )));
    if let Some(reload_secs) = config.client_crl_reload_secs {
        if reload_crl_paths.is_empty() {
            eprintln!(
                "mcp-re-proxy: --client-crl-reload-secs set but no --client-crl configured; \
                 no CRL reload scheduled"
            );
        } else {
            let custody = tls_material.label();
            spawn_crl_reload_task(
                &mut workers,
                CrlReloadTask {
                    snapshot: Arc::clone(&config_snapshot),
                    server_chain: reload_chain,
                    material: tls_material,
                    client_ca: reload_client_ca,
                    crl_paths: reload_crl_paths,
                    allow_unknown_status: reload_allow_unknown,
                    interval_secs: reload_secs,
                    revocation: client_revocation.clone(),
                },
            );
            eprintln!(
                "mcp-re-proxy: in-process CRL hot-reload enabled (every {reload_secs}s, \
                 {custody} TLS custody; refreshed --client-crl honored without restart; \
                 failed reload keeps last-good)"
            );
        }
    }
    // Select the identity strategy (MCPS-3840): direct mTLS (default) extracts the
    // identity from the verified peer certificate; reverse-proxy mode reads it from
    // the trusted forwarded header and ignores the local client cert. These are
    // mutually exclusive on a connection (enforced at parse time, honoured here).
    // ADR-MCPS-023 Tier 3 (issue #71): under `--transport-binding lb-assertion` the
    // identity is NOT resolved at the connection seam — it is carried by the signed,
    // request-bound assertion header and verified post-verification inside the proxy.
    // The serve loop therefore selects the LbAssertion strategy so it extracts the
    // assertion header (failing closed on a duplicate) instead of reading a local
    // client cert or a forwarded identity header. The three strategies are mutually
    // exclusive; the CLI forbids combining lb-assertion with a reverse-proxy header.
    let identity_strategy = if config.binding == BindingKind::LbAssertion
        || config.binding == BindingKind::AttestedIngress
    {
        // Both the v1 LB-assertion (Mode B) and the v2 attested-ingress (Mode C)
        // paths carry identity in the signed assertion header — verified post-
        // verification inside the proxy — not at the connection seam. The serve loop
        // extracts the same `mcp-ingress-assertion` header (failing closed on a
        // duplicate) for both.
        IdentityStrategy::LbAssertion
    } else {
        match &config.reverse_proxy_identity_header {
            None => IdentityStrategy::DirectTls,
            Some(header) => IdentityStrategy::ReverseProxyHeader(ReverseProxyMtlsProvider::new(
                header.clone(),
                config.reverse_proxy_header_format,
                config.identity_source,
            )),
        }
    };
    // #4030 ONLINE OCSP client-cert revocation. Built only under the
    // `online_ocsp` feature; `parse_args` already fails closed for
    // `--client-ocsp require` in a build without the feature.
    #[cfg(feature = "online_ocsp")]
    let ocsp_checker = cli::build_ocsp_checker(config);
    #[cfg(feature = "online_ocsp")]
    if let Some(checker) = &ocsp_checker {
        eprintln!(
            "mcp-re-proxy: ONLINE OCSP client-cert revocation enabled (SHA-256 CertIDs; \
             responder URL {}; on indeterminate result: {}). The OCSP responder must answer \
             SHA-256 CertIDs.",
            config
                .ocsp_responder_url
                .as_deref()
                .map(|u| format!("override {u}"))
                .unwrap_or_else(|| "from each leaf's AIA".to_string()),
            if checker.soft_fail() {
                "ALLOW (soft-fail)"
            } else {
                "REJECT (hard-fail)"
            },
        );
    }
    let serve_options = ServerOptions {
        identity_policy: config.identity_source,
        identity_strategy,
        limits: config.limits.clone(),
        max_client_cert_lifetime: config.max_client_cert_lifetime,
        client_revocation: client_revocation.clone(),
        #[cfg(feature = "online_ocsp")]
        ocsp_checker,
        target_uri: config.target_uri.clone(),
        // The delegated-TLS custody paths sign the handshake through a KMS or a
        // PKCS#11 token, synchronously, inside rustls' `Signer::sign`.
        tls_signing_may_block: is_delegated_tls,
    };

    // ADR-MCPRE-051 §3: the async inner plane — a per-core pooled hyper client to
    // the stateless Streamable-HTTP inner backends. Forwarding is AWAITED, never
    // blocking a per-core runtime worker.
    let inner_timeout = config
        .limits
        .read_timeout
        .unwrap_or_else(|| Duration::from_secs(30));
    let pool = HttpInnerPool::from_url_strs(config.inner_http_urls.clone(), inner_timeout)?;
    // The pool is PROCESS-WIDE (one instance behind the `Arc` every core shares), so
    // its in-flight bound must not sit below the fleet's aggregate admission ceiling.
    // If it did, requests that passed every security gate would be answered with a
    // signed `inner server unavailable` at a capacity cliff no configured flag names —
    // and the shedding decision would move from the admission gate, where it is
    // deliberate, to the inner pool, where it is an accident of core count.
    let cores = crate::async_fleet::resolve_core_count(config.cores);
    let aggregate_ceiling = config
        .limits
        .max_in_flight_requests
        .map(|per_core| per_core.saturating_mul(cores))
        .or(config.max_in_flight_total);
    let pool = match aggregate_ceiling {
        Some(ceiling) if ceiling > crate::http_inner::DEFAULT_MAX_IN_FLIGHT => {
            eprintln!(
                "mcp-re-proxy: inner-plane in-flight bound raised to {ceiling} to stay at or \
                 above the fleet admission ceiling ({cores} cores); the admission gate sheds, \
                 not the inner pool."
            );
            pool.with_max_in_flight(ceiling)
        }
        _ => pool,
    };

    // ADR-MCPRE-050 + §5: assemble the RFC 9421 serving PEP with the async inner
    // plane, the authoritative replay tier, and the optional Mode-A channel binding.
    // Response-signature validity window: 300s. Delegated-signing is the only mode
    // (ADR-MCPRE-052): build the delegated signer + cold-path rotor from the ROOT key
    // source and fail closed at startup if the root cannot issue the first delegated
    // key. The KMS/HSM/file root is the credential ISSUER, invoked at issuance/rotation
    // only — never on the request path. `key_source` is moved in here; it was only
    // borrowed above (TLS materials, root public key).
    let mut proxy = {
        let crate::delegated_wiring::DelegatedSigningWiring {
            signer,
            mut rotor,
            overlap,
        } = crate::delegated_wiring::build_delegated_signing(config, key_source)?;
        // Resolve the shared trust epoch BEFORE the first key is minted, so the very
        // first credential carries the globally comparable `<base>#<counter>` label
        // rather than the bare base. Minting under the bare label is what let a
        // restarted replica appear unrevoked to verifiers pinned past an `INCR`.
        let epoch_watch = build_delegated_epoch_watch(config, rotor.trust_epoch().to_string());
        if let Some(watch) = epoch_watch.as_ref() {
            // FAIL CLOSED FOR MINTING: a configured kill switch whose state cannot be
            // read means we cannot produce an epoch verifiers can compare, so we must
            // not issue at all. Refusing to start is the honest outcome — the previous
            // behaviour was to start anyway with the switch wired to nothing.
            let label = watch.current_label().ok_or_else(|| {
                "delegated-signing: --trust-epoch-redis-url is configured but the shared trust \
                 epoch could NOT be read at startup, so no credential can carry a comparable \
                 epoch. Refusing to start rather than minting keys the operator's kill switch \
                 cannot revoke (fail closed, ADR-MCPRE-052 §7)."
                    .to_string()
            })?;
            eprintln!(
                "mcp-re-proxy: delegated trust-epoch watch ACTIVE; minting under {label:?}. An \
                 operator INCR moves every replica to the next label, so verifiers pinned to the \
                 prior accepted-epoch set reject fleet-wide — and a restarted replica resolves \
                 the SAME label as its peers."
            );
            rotor.set_trust_epoch_before_first_issue(label);
        }
        // Initial issuance MUST succeed before serving: the proxy never serves without
        // an active delegated key (fail closed, ADR-MCPRE-052 §6).
        rotor.rotate(startup_now_unix).map_err(|e| {
            format!(
                "delegated-signing: initial delegated key issuance FAILED at startup ({e:?}); \
                 the root issuer must be available before serving (fail closed, ADR-MCPRE-052 §6)"
            )
        })?;
        eprintln!(
            "mcp-re-proxy: response signing = DELEGATED (ADR-MCPRE-052): the root issuer is off \
             the request path; delegated key TTL {}s / overlap {overlap}s; issuer kid \
             {response_kid:?}. Initial delegated key issued.",
            config.delegated_ttl_secs,
        );
        // Cold-path rotation thread: rotate within the overlap window before each
        // key's exp so the KMS/root stays off the per-core serving runtimes. It also
        // watches the shared trust-epoch counter and re-issues under a new epoch on an
        // advance, so an operator `INCR` revokes the outstanding delegated keys across
        // the fleet (ADR-MCPRE-052 §7).
        spawn_delegated_rotation_task(
            &mut workers,
            rotor,
            Arc::clone(&signer),
            overlap,
            epoch_watch,
        );
        HttpProfileProxy::new_delegated(
            resolve_actor,
            expected_audience,
            replay_async,
            dispatch_cfg,
            Box::new(pool),
            300,
            signer,
        )
    };
    // §5.1/§13.1: attach the verifier-local acceptance policy so the operator's
    // `--max-clock-skew` governs the FRESHNESS GATE, not only replay retention.
    // `VerifierPolicy::new` is the validating constructor: a skew outside
    // `0..=MAX_CLOCK_SKEW_BOUND` refuses to build and startup fails closed rather
    // than serving a window the operator did not get. One value drives both the
    // acceptance window and the replay `retain_until`, so an admitted nonce is
    // retained for exactly as long as its signature can still be accepted.
    let mut verifier_policy =
        mcp_re_http_profile::VerifierPolicy::new(&["ed25519"], config.max_clock_skew).map_err(
            |_| {
                format!(
                    "--max-clock-skew {} is out of bounds: the RFC 9421 freshness gate accepts \
                     0..={} seconds (§5.1 bounded skew)",
                    config.max_clock_skew,
                    mcp_re_http_profile::VerifierPolicy::MAX_CLOCK_SKEW_BOUND,
                )
            },
        )?;
    // §4.1: the MCP transport/version contract is enforced only when the operator
    // declares the protocol versions this deployment serves. Absent the flag there
    // is no contract, so required-header presence and `Mcp-Name`/`params.name`
    // agreement are not asserted — declared explicitly rather than defaulted.
    if !config.mcp_protocol_versions.is_empty() {
        let versions: Vec<&str> = config
            .mcp_protocol_versions
            .iter()
            .map(String::as_str)
            .collect();
        eprintln!(
            "mcp-re-proxy: MCP transport contract ENFORCED for protocol version(s) {:?} \
             (required transport headers covered; Mcp-Name must equal params.name)",
            config.mcp_protocol_versions
        );
        verifier_policy = verifier_policy.with_mcp_transport(
            mcp_re_http_profile::McpTransportPolicy::mcp_2026_07_28(&versions),
        );
    }
    eprintln!(
        "mcp-re-proxy: freshness gate = created-{skew}s .. expires+{skew}s (RFC 9421 §5.1)",
        skew = config.max_clock_skew
    );
    proxy = proxy.with_verifier_policy(verifier_policy);
    if let Some(binding) = transport_binding {
        proxy = proxy.with_transport_binding(binding);
    }

    // ADR-MCPS-035: install the per-request security record. Stated at startup in
    // both directions — a deployment without a sink has NO per-request attribution,
    // and finding that out after an incident is too late.
    match config.audit_sink {
        cli::AuditSinkKind::Stderr => {
            proxy = proxy.with_audit_sink(Arc::new(crate::audit_sink::StderrAuditSink));
            eprintln!(
                "mcp-re-proxy: security audit record = STDERR (ADR-MCPS-035): one line per \
                 accepted / rejected / signed decision, carrying the verifier-resolved actor \
                 and the frozen mcp-re.* wire code."
            );
        }
        cli::AuditSinkKind::None => {
            proxy = proxy.with_audit_sink(Arc::new(crate::audit_sink::NoAuditSink));
            eprintln!(
                "mcp-re-proxy: security audit record = NONE: no per-request accepted/rejected \
                 record is emitted, so this deployment has no attribution surface for a later \
                 incident. Pass --audit-sink stderr to enable it."
            );
        }
    }

    // ADR-MCPRE-054: evidence retention. Stated at startup in both directions because
    // it changes what this deployment STORES about every call, and because a reader of
    // the posture line should never have to infer a data-retention decision.
    match &config.retained_evidence_dir {
        Some(dir) => {
            let retention = crate::transparency::EvidenceRetention::open(dir).map_err(|e| {
                // Fail at startup, not at the first served call: a deployment that
                // cannot open the store would otherwise refuse every request with
                // `evidence_retention_unavailable` while appearing to have started.
                format!("--retained-evidence-dir {dir}: {e}")
            })?;
            proxy = proxy.with_evidence_retention(Arc::new(retention));
            eprintln!(
                "mcp-re-proxy: evidence retention = ON at {dir} (ADR-MCPRE-054): the full \
                 request and response messages of every ACCEPTED call are retained (rejected \
                 requests are not), and a store failure refuses the exchange with \
                 mcp-re.evidence_retention_unavailable. The store has NO expiry or quota — \
                 a full volume is therefore a total outage. Put it on a dedicated volume \
                 with a retention policy and free-space alerting."
            );
        }
        None => eprintln!(
            "mcp-re-proxy: evidence retention = OFF: nothing is retained, so no SCITT \
             statement can later be issued about a call served here. Pass \
             --retained-evidence-dir <path> to enable it."
        ),
    }

    // #415 rev 2 §10: the verified-context carrier. Caller-seeded context is stripped
    // regardless; this decides only whether the PEP writes its OWN context in its
    // place, and `trusted` is an operator assertion about the inner channel that
    // nothing here can verify.
    if config.verified_context == cli::VerifiedContextKind::Trusted {
        proxy = proxy
            .with_verified_context_carrier(mcp_re_http_profile::VerifiedContextPolicy::Trusted);
        eprintln!(
            "mcp-re-proxy: verified-context carrier = TRUSTED (#415 §10): the PEP writes its \
             resolved actor into the forwarded body. The carrier is UNSIGNED — this asserts \
             that nothing but this proxy can reach the inner server, and nothing here can \
             check that."
        );
    }

    // ADR-MCPS-047: wire the MRTR continuation correlation store on the SAME shared
    // Redis the fleet uses for replay coherence, so a multi-round-trip continuation
    // opened on one replica is honoured on any other. Connected on the replay control
    // runtime (held alive for the whole serve). Present only when a shared redis URL
    // AND that runtime exist; single-store / in-memory replay deployments run without
    // cross-replica MRTR (an answer leg then fails closed on the continuation binding).
    #[cfg(feature = "redis_replay")]
    if let Some(url) = config.replay_redis_url.as_ref() {
        let rt = control_runtime(&mut control_rt)?;
        let store = rt
            .block_on(crate::redis_continuation_store::RedisContinuationStore::connect(url))
            .map_err(|e| format!("connect redis continuation store: {e}"))?;
        eprintln!(
            "mcp-re-proxy: MRTR continuation store = shared (async Redis backend, TTL {}s)",
            crate::http_profile_serve::DEFAULT_CONTINUATION_TTL_SECS
        );
        proxy = proxy.with_continuation_store(
            Arc::new(store),
            crate::http_profile_serve::DEFAULT_CONTINUATION_TTL_SECS,
        );
    } else {
        eprintln!("mcp-re-proxy: {}", CONTINUATION_STORE_OFF);
    }
    #[cfg(not(feature = "redis_replay"))]
    eprintln!("mcp-re-proxy: {}", CONTINUATION_STORE_OFF);

    // MCPRE-493: wire the §7 admission-currency gate. Without a source the assertion
    // and its binding are verified evidence that decides nothing — a call carrying a
    // fresh, correctly-bound assertion is served even after its workload has been
    // revoked, because currency is a comparison against state only the deployment can
    // supply. The CLI has already refused any combination that would leave the gate
    // enabled but toothless.
    #[cfg(feature = "redis_replay")]
    if config.admission != crate::cli::AdmissionKind::Off {
        let Some(url) = config.admission_redis_url.as_ref() else {
            return Err("--admission requires --admission-redis-url".to_string());
        };
        // The admission record is an INDEPENDENT endpoint; it has nothing to do with
        // which replay tier the deployment chose. Coupling it to the replay control
        // runtime made admission unimplementable on the CP/linearizable tier — the
        // operator supplied `--admission-redis-url`, was told the flag was missing, and
        // the natural resolution was to turn a security control off.
        let rt = control_runtime(&mut control_rt)?;
        let source = rt
            .block_on(crate::redis_admission_source::RedisAdmissionSource::connect(url))
            .map_err(|e| format!("connect redis admission source: {e}"))?;
        let kid = config
            .admission_authority_kid
            .clone()
            .ok_or("--admission-authority-kid is required")?;
        let key = mcp_re_core::VerificationKey::from_b64url(
            config
                .admission_authority_pubkey_b64url
                .as_deref()
                .ok_or("--admission-authority-pubkey is required")?,
        )
        .map_err(|e| format!("--admission-authority-pubkey is not a valid Ed25519 key: {e:?}"))?;
        let enforcement = match config.admission {
            crate::cli::AdmissionKind::Required => {
                crate::http_profile_serve::AdmissionEnforcement::Required
            }
            _ => crate::http_profile_serve::AdmissionEnforcement::Optional,
        };
        eprintln!(
            "mcp-re-proxy: admission currency = {} (authority {kid}, shared record over redis, \
             degraded {})",
            match enforcement {
                crate::http_profile_serve::AdmissionEnforcement::Required => "REQUIRED",
                crate::http_profile_serve::AdmissionEnforcement::Optional => "optional",
            },
            if config.admission_allow_degraded {
                format!("allowed within P={}s", config.admission_degraded_bound_secs)
            } else {
                "OFF (an unreachable authority fails closed)".to_string()
            },
        );
        proxy = proxy.with_admission(
            Arc::new(source),
            mcp_re_http_profile::AdmissionPolicy {
                max_assertion_age: 300,
                max_clock_skew: config.max_clock_skew,
                degraded_propagation_bound: config.admission_degraded_bound_secs,
                allow_degraded_mode: config.admission_allow_degraded,
            },
            enforcement,
            Arc::new(move |presented: &str| (presented == kid).then(|| key.clone())),
        );
    }
    #[cfg(not(feature = "redis_replay"))]
    if config.admission != crate::cli::AdmissionKind::Off {
        // Fail closed rather than serve with admission silently disabled: an operator
        // who asked for it must not get a proxy that quietly does not do it.
        return Err(
            "--admission requires a build with the `redis_replay` feature (the \
                    shared authoritative admission record)"
                .to_string(),
        );
    }

    // ADR-MCPRE-051 §1: serve on the per-core async fleet (SO_REUSEPORT + tokio),
    // the production data plane. Blocks until SIGTERM/SIGINT drains the fleet.
    // `control_rt` (if any) is handed in so the redis ConnectionManager's reconnect
    // task, the admission source and the continuation store stay alive for the whole
    // serve.
    serve_fleet(
        proxy,
        Arc::clone(&config_snapshot),
        serve_options,
        config,
        control_rt,
        shutdown,
    )
}

/// ADR-MCPRE-051 §1/§3 — serve on the per-core async fleet forwarding over the
/// pooled HTTP inner plane. Built when `--inner-http-url` is set; the sync stdio
/// serving path is used otherwise.
///
/// Consumes the fully-built `proxy` (adds the async replay tier + async HTTP inner
/// to it), binds one `SO_REUSEPORT` listener per core, and serves
/// `Proxy::handle_with_transport_async` on each core's own tokio runtime until a
/// SIGTERM/SIGINT drains the fleet within the bounded grace window.
///
/// The authoritative replay tier and async HTTP inner have already been wired into
/// `proxy` by the caller (`run`) from the `--replay-cache` / `--inner-http-url`
/// selection. `_control_rt` (when any networked control-plane client was wired) holds
/// the redis `ConnectionManager`'s reconnect runtime alive for the whole serve.
fn serve_fleet(
    proxy: HttpProfileProxy,
    config_snapshot: Arc<config_snapshot::ServerConfigSnapshot>,
    serve_options: crate::ServerOptions,
    config: &cli::Config,
    _control_rt: Option<tokio::runtime::Runtime>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) -> Result<(), String> {
    use std::net::ToSocketAddrs;

    // Resolve `--bind` to a concrete SocketAddr for the SO_REUSEPORT listeners.
    let addr = config
        .bind
        .to_socket_addrs()
        .map_err(|e| format!("resolve --bind {}: {e}", config.bind))?
        .next()
        .ok_or_else(|| format!("--bind {} resolved to no address", config.bind))?;

    let proxy = Arc::new(proxy);

    let fleet_cfg = crate::async_fleet::FleetConfig {
        addr,
        cores: config.cores, // 0 = auto (one worker per core); --cores pins it
        workers_per_shard: config.workers_per_shard,
        listen_backlog: crate::async_fleet::DEFAULT_LISTEN_BACKLOG,
        // MCPRE-114: the operator's fleet-global ceiling, divided evenly per core by
        // `async_fleet::apply_global_admission`. `None` = no global target.
        max_in_flight_total: config.max_in_flight_total,
    };
    // MCPRE-116: hand the fleet the SNAPSHOT, not a one-shot `load()`. The accept
    // loop re-reads it per connection, so the CRL hot-reload task's atomic swap is
    // observed by the next handshake instead of being written to a config nothing
    // reads again.
    let server_config = Arc::clone(&config_snapshot);
    let serve_options = Arc::new(serve_options);
    // The caller owns the shutdown flag (the binary wires it to SIGTERM/SIGINT; a
    // test flips it directly). We hand a clone to the fleet and poll the same flag.

    // One handler per core over the SHARED `Proxy` (Send + Sync, MCPRE-111); each
    // request awaits the async replay tier + async HTTP inner without blocking the
    // per-core runtime worker.
    let handler_proxy = Arc::clone(&proxy);
    let make_handler = move |_core: usize| {
        let proxy = Arc::clone(&handler_proxy);
        Arc::new(
            move |req: ServedHttpRequest| -> crate::async_serve::HandlerResponseFuture {
                let proxy = Arc::clone(&proxy);
                Box::pin(async move { proxy.handle(req, now_unix()).await })
            },
        )
    };

    let fleet = crate::async_fleet::serve_fleet(
        fleet_cfg,
        server_config,
        serve_options,
        make_handler,
        Arc::clone(&shutdown),
    )
    .map_err(|e| format!("start async fleet: {e}"))?;
    eprintln!(
        "mcp-re-proxy: async fleet serving on {} ({} per-core workers; HTTP inner backends {:?})",
        fleet.local_addr(),
        fleet.worker_count(),
        config.inner_http_urls,
    );

    // Block until the caller flips `shutdown`, then drain the fleet (bounded).
    while !shutdown.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(50));
    }
    eprintln!("mcp-re-proxy: shutdown signal received; draining async fleet");
    fleet.shutdown_and_join();
    eprintln!("mcp-re-proxy: async fleet drained, exiting cleanly");
    Ok(())
}

/// ADR-MCPRE-051 §6 (MCPRE-116): the in-process CRL hot-reload task. Every
/// `interval_secs` it re-reads the `--client-crl` files and rebuilds the direct-TLS
/// verifier from the SAME immutable server key material, atomically swapping the
/// result into `snapshot`. A read/parse/build failure keeps the last-good config
/// (which still fails closed once its CRL passes `nextUpdate`), so a bad reload
/// never widens what is accepted. The task observes `SHUTDOWN` between naps so it
/// exits promptly on a rolling deploy. Spawned only when `--client-crl-reload-secs`
/// is set with a non-empty `--client-crl` on the direct-TLS path.
/// The TLS server key the verifier is rebuilt around, under either custody.
///
/// A CRL reload re-reads only the CRLs; this is carried verbatim across the rebuild.
/// Both variants exist so the reload does not depend on which custody the deployment
/// chose — a revocation control that works only on the weaker custody is the wrong way
/// round.
enum TlsKeyMaterial {
    /// The exported private key read from disk.
    Exported(rustls_pki_types::PrivateKeyDer<'static>),
    /// A non-exporting device/KMS signer (PKCS#11, AWS KMS, Cloud KMS).
    Delegated(Arc<dyn crate::delegated_tls::RawEd25519TlsSigner>),
}

impl TlsKeyMaterial {
    /// Whether the handshake signature goes through a non-exporting device/KMS.
    ///
    /// The serving runtime shape depends on this: a delegated signer blocks inside
    /// rustls' synchronous `Signer::sign`, so each core needs a worker pool rather than
    /// the single-threaded share-nothing default.
    fn is_delegated(&self) -> bool {
        matches!(self, TlsKeyMaterial::Delegated(_))
    }

    /// The custody word for the operator-facing startup line.
    fn label(&self) -> &'static str {
        match self {
            TlsKeyMaterial::Exported(_) => "exported-key",
            TlsKeyMaterial::Delegated(_) => "delegated",
        }
    }

    /// Rebuild the serving config around `crls`, under whichever custody applies.
    fn rebuild(
        &self,
        server_chain: Vec<rustls_pki_types::CertificateDer<'static>>,
        client_ca: Vec<rustls_pki_types::CertificateDer<'static>>,
        crls: Vec<rustls_pki_types::CertificateRevocationListDer<'static>>,
        allow_unknown_status: bool,
    ) -> Result<rustls::ServerConfig, String> {
        match self {
            TlsKeyMaterial::Exported(key) => {
                tls::RustlsDirectProvider::build_server_config_with_crls(
                    server_chain,
                    key.clone_key(),
                    client_ca,
                    crls,
                    allow_unknown_status,
                )
                .map_err(|e| e.to_string())
            }
            TlsKeyMaterial::Delegated(signer) => tls::build_server_config_delegated_validated(
                server_chain,
                Arc::clone(signer),
                client_ca,
                crls,
                allow_unknown_status,
            )
            .map_err(|e| e.to_string()),
        }
    }
}

struct CrlReloadTask {
    snapshot: Arc<config_snapshot::ServerConfigSnapshot>,
    /// The immutable server key material the verifier is rebuilt from; a reload
    /// re-reads only the CRLs, never these.
    server_chain: Vec<rustls_pki_types::CertificateDer<'static>>,
    material: TlsKeyMaterial,
    client_ca: Vec<rustls_pki_types::CertificateDer<'static>>,
    crl_paths: Vec<String>,
    allow_unknown_status: bool,
    interval_secs: u64,
    /// The per-request revocation index, republished from the same re-read bytes as
    /// the rebuilt verifier. Rebuilding only the verifier would leave the reload
    /// reaching new connections alone — which is the gap the per-request check exists
    /// to close.
    revocation: Option<Arc<client_revocation::SharedClientRevocation>>,
}

/// Read `--trust` and build the snapshot the revocation tiers resolve against.
///
/// Two things come out of one read so they can never disagree: the
/// [`InMemoryTrustResolver`](mcp_re_core::InMemoryTrustResolver) that answers
/// `resolve`, and the `kid -> signer` map the actor seam uses as the identity
/// coordinate. `response_kid` is excluded from the request-signer map: the
/// deployment's own issuer key must never be presentable as a client credential.
fn load_trust_snapshot(
    trust_path: &str,
    response_kid: &str,
) -> Result<crate::reloading_trust::ReloadingTrustStore, String> {
    let (resolver, signers) = read_trust_file(trust_path, response_kid)?;
    Ok(crate::reloading_trust::ReloadingTrustStore::new(
        resolver, signers,
    ))
}

/// The file read shared by startup and every reload.
fn read_trust_file(
    trust_path: &str,
    response_kid: &str,
) -> Result<(mcp_re_core::InMemoryTrustResolver, HashMap<String, String>), String> {
    let bytes = std::fs::read(trust_path).map_err(|e| format!("{trust_path}: {e}"))?;
    let resolver = cli::load_trust(&bytes)?;
    // Slot-scoped: only entries this file enrols for the REQUEST slot become client
    // request signers. A key carried here for another purpose is not one.
    let signers = cli::load_trust_request_signers(&bytes, response_kid)?;
    Ok((resolver, signers))
}

/// The `--fleet` per-tier cross-replica revocation-lag bound, derived from real config.
///
/// This is the one operator-facing line whose stated purpose is to bound revocation lag
/// HONESTLY, so each clause has to name a mechanism that exists. Two floors sit under
/// every tier's number:
///
///   * the trust epoch is read by a BACKGROUND POLLER on a
///     [`TRUST_EPOCH_POLL_SECS`] cadence, never on the request path, so a push-tier
///     flush lands within one poll interval of an advance — not "on the next request
///     after an epoch advance", which is a mechanism the data plane no longer has;
///   * a key removed from `--trust` cannot stop resolving faster than the file is
///     re-read, whatever the tier does with its cache.
fn fleet_trust_bound(
    tier: &RevocationTier,
    epoch_source_configured: bool,
    trust_reload_secs: Option<u64>,
) -> String {
    let reload_floor = match trust_reload_secs {
        Some(secs) => format!("--trust re-read every {secs}s"),
        None => "--trust read once at startup (no --trust-reload-secs), so the store itself \
                 changes only on a restart"
            .to_string(),
    };
    match (tier, epoch_source_configured) {
        (RevocationTier::Push { t_secs }, true) => format!(
            "cache flush within one {TRUST_EPOCH_POLL_SECS}s trust-epoch poll interval of an \
             advance while the source is healthy, bounded {t_secs}s on a source read-outage \
             (fail-closed), over {reload_floor}"
        ),
        (RevocationTier::Push { t_secs }, false) => format!(
            "bounded {t_secs}s (no --trust-epoch-redis-url; the push channel is inert), over \
             {reload_floor}"
        ),
        (RevocationTier::BoundedCache { t_secs }, _) => {
            format!("bounded {t_secs}s, over {reload_floor}")
        }
        (RevocationTier::Live, _) => {
            format!("per-request live re-resolution (no positive cache), over {reload_floor}")
        }
    }
}

/// The posture line for a deployment with no cross-replica MRTR continuation store.
///
/// Every other optional seam prints its OFF posture; this one printed nothing, so an
/// operator on the CP/linearizable replay tier — the tier the claim matrix presents as
/// strongest — silently lost every human-approval / multi-round-trip flow. The failure
/// is closed but reads on the wire as a client or attack signal, which is exactly what
/// the startup posture exists to prevent.
const CONTINUATION_STORE_OFF: &str = "MRTR continuation store = OFF (no --replay-redis-url): \
     multi-round-trip flows are SINGLE-REPLICA only. A client that receives an \
     `input_required` reply from one replica and answers on another is refused \
     (mcp-re.continuation_binding_failed). Set --replay-redis-url for the shared store.";

/// The process-lifetime control runtime, built on first use.
///
/// Every networked control-plane client shares it — the redis replay reconnect task,
/// the admission source, the MRTR continuation store. Building it lazily is what keeps
/// them independent: an admission source is its OWN endpoint and must not be gated on
/// the replay tier having happened to create a runtime.
#[cfg_attr(not(feature = "redis_replay"), allow(dead_code))]
fn control_runtime(
    slot: &mut Option<tokio::runtime::Runtime>,
) -> Result<&tokio::runtime::Runtime, String> {
    if slot.is_none() {
        *slot = Some(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .map_err(|e| format!("build control runtime: {e}"))?,
        );
    }
    Ok(slot.as_ref().expect("just created"))
}

/// The qualifier carried on the revocation-tier startup line: how fast the trust STORE
/// itself can change.
///
/// Every tier's window is a claim about how quickly a key removed from `--trust` stops
/// resolving, and nothing resolves faster than the file is re-read. The default tier
/// (`bounded-cache`) is accepted without a cadence — unlike `live`/`push`, whose claims
/// are refused outright without one — so its "enforced fleet-wide within T" line is the
/// one an operator gets by omission. The correction therefore rides on the SAME line as
/// the claim: as a separate line further down it was read as being about something else,
/// and the tier line was quoted on its own.
fn store_change_cadence(trust_reload_secs: Option<u64>) -> String {
    match trust_reload_secs {
        Some(secs) => format!("{secs}s (--trust re-read on that cadence)"),
        None => "NONE: --trust is read once at startup, so the window above bounds CACHING \
                 only — the store itself changes only when every replica restarts"
            .to_string(),
    }
}

/// How many consecutive failed `--trust` re-reads are absorbed before the resolver
/// fails closed.
///
/// Keeping the last-good store across a blip is deliberate: a truncated file caught
/// mid-write must not empty the trust map. But "keep last-good" with no bound restores
/// exactly the unbounded revocation window the reload exists to close — the replica
/// keeps honouring a key the operator removed, indefinitely, while its startup line
/// promises a one-cadence window. Five consecutive failures is far longer than a
/// ConfigMap remount or an editor's save and short enough that an incident-time
/// revocation is not silently ignored.
const TRUST_RELOAD_FAILURE_BUDGET: u32 = 5;

/// Whether the trust store is still fresh enough to answer.
///
/// Set by [`spawn_trust_reload_task`] when the file has been unreadable for
/// [`TRUST_RELOAD_FAILURE_BUDGET`] consecutive cadences, or when the reload thread has
/// died. Read by the resolver wrapper below on every verification, which is what makes
/// it a real fail-closed rather than a log line.
#[derive(Debug, Default)]
struct TrustStoreFreshness {
    stale: std::sync::atomic::AtomicBool,
}

impl TrustStoreFreshness {
    fn mark_stale(&self) {
        self.stale.store(true, Ordering::SeqCst);
    }

    fn mark_fresh(&self) {
        self.stale.store(false, Ordering::SeqCst);
    }

    fn is_stale(&self) -> bool {
        self.stale.load(Ordering::Relaxed)
    }
}

/// The request-trust resolver, refusing to answer at all once the store behind it has
/// stopped changing.
///
/// `Unavailable` and not `NotFound`: a frozen store still HOLDS the revoked key, so
/// answering from it is the one outcome that must not happen, and reporting the outage
/// as an unknown keyid would send the operator hunting a client bug. The verifier maps
/// this to `mcp-re.trust_resolver_unavailable`, which is what a stale store actually is.
struct StaleFailsClosed {
    inner: Arc<dyn mcp_re_core::TrustResolver + Send + Sync>,
    freshness: Arc<TrustStoreFreshness>,
}

impl mcp_re_core::TrustResolver for StaleFailsClosed {
    fn resolve(
        &self,
        signer: &str,
        key_id: &str,
    ) -> Result<mcp_re_core::VerificationKey, mcp_re_core::TrustResolverError> {
        if self.freshness.is_stale() {
            return Err(mcp_re_core::TrustResolverError::Unavailable {
                details: "the trust store has not been re-read successfully for several \
                          cadences; a key revoked in --trust would still resolve from the \
                          frozen snapshot, so verification fails closed until a reload \
                          succeeds"
                    .to_string(),
            });
        }
        self.inner.resolve(signer, key_id)
    }
}

/// Re-read `--trust` on a cadence and swap the snapshot atomically.
///
/// The same shape as [`spawn_crl_reload_task`], and for the same reason: a
/// revocation mechanism that needs a restart is not one an operator can use during an
/// incident. A FAILED read keeps the last-good store — a truncated file caught
/// mid-write must not empty the trust map, because an empty map rejects every request
/// and would turn an editor's save into a fleet-wide outage.
///
/// That tolerance is BOUNDED. Unlike a CRL, an `InMemoryTrustResolver` carries no
/// expiry, so nothing makes a frozen snapshot stop being honoured on its own; after
/// [`TRUST_RELOAD_FAILURE_BUDGET`] consecutive failures the resolver fails closed
/// instead. SUPERVISED for the same reason as the rotation owner: nothing joins this
/// thread, so a panic (a poisoned lock, a closed stderr) would otherwise end reloading
/// for the process lifetime while every surface still read healthy.
fn spawn_trust_reload_task(
    workers: &mut crate::managed_worker::WorkerSet,
    store: Arc<crate::reloading_trust::ReloadingTrustStore>,
    trust_path: String,
    response_kid: String,
    interval_secs: u64,
    freshness: Arc<TrustStoreFreshness>,
) {
    let halt = workers.halt();
    workers.spawn("trust store reload", move || {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            trust_reload_loop(
                &store,
                &trust_path,
                &response_kid,
                interval_secs,
                &freshness,
                &halt,
            );
        }));
        if outcome.is_err() {
            freshness.mark_stale();
            eprintln!(
                "mcp-re-proxy: FATAL: the trust store reload thread PANICKED. --trust is no \
                 longer being re-read, so a key revoked in it would keep resolving from the \
                 frozen snapshot; request verification now fails closed \
                 (trust_resolver_unavailable) rather than serving a store that cannot change. \
                 This replica cannot recover on its own — restart it."
            );
        }
    });
}

/// The reload loop proper. Split out so the supervisor above can catch a panic from
/// anywhere inside it.
fn trust_reload_loop(
    store: &crate::reloading_trust::ReloadingTrustStore,
    trust_path: &str,
    response_kid: &str,
    interval_secs: u64,
    freshness: &TrustStoreFreshness,
    halt: &crate::managed_worker::Halt,
) {
    let mut consecutive_failures: u32 = 0;
    loop {
        // Naps in small increments, so a halt is observed within one increment rather
        // than after a whole reload interval.
        if halt.sleep(Duration::from_secs(interval_secs)) {
            return;
        }
        match read_trust_file(trust_path, response_kid) {
            Ok((resolver, signers)) => {
                let enrolled = signers.len();
                let recovered = consecutive_failures > 0;
                consecutive_failures = 0;
                store.store(resolver, signers);
                freshness.mark_fresh();
                if recovered {
                    eprintln!(
                        "mcp-re-proxy: trust store reload RECOVERED; {enrolled} request-signer \
                         key(s) live, verification is serving again"
                    );
                } else {
                    eprintln!(
                        "mcp-re-proxy: trust store reloaded; {enrolled} request-signer key(s) live"
                    );
                }
            }
            Err(reason) => {
                consecutive_failures = consecutive_failures.saturating_add(1);
                if consecutive_failures >= TRUST_RELOAD_FAILURE_BUDGET {
                    freshness.mark_stale();
                    eprintln!(
                        "mcp-re-proxy: trust store reload FAILED {consecutive_failures}x in a row \
                         ({reason}); the snapshot is now too old to carry the declared revocation \
                         window, so request verification FAILS CLOSED \
                         (trust_resolver_unavailable) until a reload succeeds. Fix the --trust \
                         mount at {trust_path}."
                    );
                } else {
                    eprintln!(
                        "mcp-re-proxy: WARNING: trust store reload FAILED \
                         ({consecutive_failures}/{TRUST_RELOAD_FAILURE_BUDGET}), keeping last-good \
                         store: {reason}. At {TRUST_RELOAD_FAILURE_BUDGET} consecutive failures \
                         verification fails closed."
                    );
                }
            }
        }
    }
}

/// SUPERVISED like the trust reload and the rotation owner: nothing joins this thread,
/// and a panic in it would silently stop CRL reloading for the process lifetime.
///
/// Unlike the trust store, a stale CRL index bounds ITSELF — a CRL past its `nextUpdate`
/// covers nothing, so its issuer's certificates become `Unknown` and are refused. A
/// failed reload therefore never widens what is accepted, and the escalation here is a
/// loud operator signal rather than a second fail-closed transition.
fn spawn_crl_reload_task(workers: &mut crate::managed_worker::WorkerSet, task: CrlReloadTask) {
    let halt = workers.halt();
    workers.spawn("client CRL reload", move || {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crl_reload_loop(task, &halt);
        }));
        if outcome.is_err() {
            eprintln!(
                "mcp-re-proxy: FATAL: the client-CRL reload thread PANICKED. --client-crl is no \
                 longer being re-read, so a newly revoked client certificate reaches this replica \
                 only when its CRL passes nextUpdate (after which that issuer's certificates are \
                 refused outright). This replica cannot recover on its own — restart it."
            );
        }
    });
}

/// The CRL reload loop proper. Split out so the supervisor above can catch a panic.
fn crl_reload_loop(task: CrlReloadTask, halt: &crate::managed_worker::Halt) {
    let CrlReloadTask {
        snapshot,
        server_chain,
        material,
        client_ca,
        crl_paths,
        allow_unknown_status,
        interval_secs,
        revocation,
    } = task;
    {
        let mut consecutive_failures: u32 = 0;
        loop {
            // Naps in small increments, so a halt is observed within one increment
            // rather than after a whole reload interval.
            if halt.sleep(Duration::from_secs(interval_secs)) {
                return;
            }
            let outcome = config_snapshot::reload_once(&snapshot, || {
                let crls = cli::load_client_crls(&crl_paths)?;
                // Build the per-request index from the SAME bytes, BEFORE the verifier
                // is rebuilt, so a malformed CRL keeps last-good on both rather than
                // swapping one and failing the other.
                let index = client_revocation::ClientRevocationIndex::from_crl_ders(
                    &crls
                        .iter()
                        .map(|crl| crl.as_ref().to_vec())
                        .collect::<Vec<_>>(),
                    allow_unknown_status,
                )
                .map_err(|e| e.to_string())?;
                let rebuilt = material.rebuild(
                    server_chain.clone(),
                    client_ca.clone(),
                    crls,
                    allow_unknown_status,
                )?;
                if let Some(revocation) = revocation.as_ref() {
                    revocation.store(index);
                }
                Ok(Arc::new(rebuilt))
            });
            match outcome {
                config_snapshot::ReloadOutcome::Swapped => {
                    let recovered = consecutive_failures > 0;
                    consecutive_failures = 0;
                    if recovered {
                        eprintln!(
                            "mcp-re-proxy: client CRL reload RECOVERED; new verifier and \
                             per-request index are live"
                        );
                    } else {
                        eprintln!("mcp-re-proxy: client CRL reloaded; new verifier is live");
                    }
                }
                config_snapshot::ReloadOutcome::KeptLastGood { reason } => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    eprintln!(
                        "mcp-re-proxy: WARNING: client CRL reload FAILED {consecutive_failures}x \
                         in a row, keeping last-good config: {reason}. Newly revoked certificates \
                         are NOT reaching this replica; when the last-good CRL passes its \
                         nextUpdate its issuer's certificates are refused outright."
                    );
                }
            }
        }
    }
}

/// ADR-MCPRE-052 §4/§6 + ADR-MCPRE-051 §5 (MCPRE-122): the cold-path delegated-key
/// rotation thread. A single owner drives the rotor OFF the per-core serving runtimes,
/// so the root issuer's blocking KMS/HSM calls never touch the request path. It wakes
/// within the rotation-overlap window before the current key's `exp`, mints a
/// successor, and republishes the hot-path snapshot; the fleet keeps signing off the
/// current key until then (no gap). If issuance fails while the current key is still
/// valid, serving continues until that key expires and THEN fails closed
/// (ADR-MCPRE-052 §6) — never a stale-key extension or a direct-root fallback. The
/// thread observes its halt between naps so it exits promptly on a rolling deploy.
fn spawn_delegated_rotation_task(
    workers: &mut crate::managed_worker::WorkerSet,
    mut rotor: crate::delegated_wiring::ProdDelegatedRotor,
    signer: Arc<crate::delegated_server_signer::DelegatedServerSigner>,
    overlap: i64,
    epoch_watch: Option<DelegatedEpochWatch>,
) {
    let halt = workers.halt();
    workers.spawn("delegated key rotation", move || {
        // SUPERVISION (C040). This thread is the ONLY thing that mints delegated keys, and
        // its `JoinHandle` is dropped, so nothing joins it. Left bare, a panic on any
        // reachable `.expect()` (the CSPRNG draw, the two custody invariants) would end all
        // rotation for the process lifetime while every health surface still read steady
        // state: `DelegatedRotationMetrics.consecutive_failures` is only written BY this
        // thread, so a dead thread leaves it at 0 and the replica appears healthy right up
        // until the current key's `exp`, then 503s with no attributable cause.
        //
        // So the loop runs inside `catch_unwind` and a panic is converted into the
        // strongest honest signal available: RETIRE the snapshot, which makes the hot path
        // fail closed IMMEDIATELY (`delegated_signing_unavailable`) rather than at `exp`,
        // and record a failure so the metric stops reading healthy. The thread does not
        // resume — after a panic the rotor's state is not known good, and continuing to
        // mint from it would be worse than refusing.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            rotation_loop(&mut rotor, &signer, overlap, epoch_watch.as_ref(), &halt)
        }));
        if outcome.is_err() {
            signer.retire();
            signer.metrics().record_failure();
            eprintln!(
                "mcp-re-proxy: FATAL: the delegated rotation thread PANICKED. Delegated key \
                 rotation has stopped for the lifetime of this process and the current \
                 snapshot has been retired, so response signing now fails closed \
                 (delegated_signing_unavailable) immediately rather than at the key's exp. \
                 This replica cannot recover on its own — restart it."
            );
        }
    });
}

/// The rotation loop proper. Split out of [`spawn_delegated_rotation_task`] so the
/// supervisor above can catch a panic from anywhere inside it.
fn rotation_loop(
    rotor: &mut crate::delegated_wiring::ProdDelegatedRotor,
    signer: &Arc<crate::delegated_server_signer::DelegatedServerSigner>,
    overlap: i64,
    epoch_watch: Option<&DelegatedEpochWatch>,
    halt: &crate::managed_worker::Halt,
) {
    use crate::delegated_server_signer::rotation_backoff;
    {
        // Failures since the last success drive the backoff schedule; 0 in steady state.
        let mut consecutive_failures: u32 = 0;
        // The epoch this node is currently minting under (starts at the configured
        // baseline label from the startup issuance). An advance of the shared counter
        // moves it; verifiers pinned to the old label then reject across replicas.
        let mut last_label = rotor.trust_epoch().to_string();
        loop {
            if halt.requested() {
                return;
            }
            // In steady state, sleep until the overlap window opens (`exp - overlap`) so
            // a successor is minted while the predecessor is still valid. While retrying
            // after a failure we skip this wait and go straight to the backoff-then-retry
            // below. With no current key (startup edge / post-retirement) rotate at once.
            // The wait ALSO breaks early when the shared trust epoch advances, so
            // cross-replica revocation is bounded by the ~500ms epoch poll, not a full TTL.
            if consecutive_failures == 0 {
                let wake_at = match signer.current(now_unix()) {
                    Some(a) => (a.exp - overlap).max(now_unix()),
                    None => now_unix(),
                };
                let mut ticks = 0u32;
                while now_unix() < wake_at {
                    if halt.requested() {
                        return;
                    }
                    // Poll the shared trust epoch ~every 500ms (10 * 50ms).
                    if ticks.is_multiple_of(10) {
                        if let Some(watch) = epoch_watch.as_ref() {
                            if matches!(watch.current_label(), Some(l) if l != last_label) {
                                break;
                            }
                        }
                    }
                    ticks += 1;
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
            if halt.requested() {
                return;
            }
            // Trust-epoch advance takes priority over the scheduled rotation: swap to
            // the new epoch NOW so verifiers pinned to the prior accepted-epoch set
            // reject on the next request (cross-replica, since every replica reads the
            // same counter). ADR-MCPRE-052 §7.
            if let Some(watch) = epoch_watch.as_ref() {
                let resolved = watch.current_label();
                if resolved.is_none() {
                    // FAIL CLOSED FOR MINTING: the shared epoch is unreadable (outage)
                    // or went backwards (refused, never rebased). Either way we cannot
                    // produce a comparable epoch, so we must not issue. The current key
                    // keeps serving until its `exp`, after which the hot path fails
                    // closed on its own — no stale-epoch minting, no rebase. Back off
                    // and retry; the reader reconnects on the next read.
                    consecutive_failures = signer.metrics().record_failure();
                    let ttl = signer.seconds_to_expiry(now_unix());
                    let backoff = rotation_backoff(consecutive_failures, ttl, rotation_jitter());
                    eprintln!(
                        "mcp-re-proxy: WARNING: shared trust epoch unreadable or regressed; \
                         NOT minting (a credential without a comparable epoch is unrevokable). \
                         Current key serves until exp then fails closed. \
                         consecutive_failures {}, time-to-expiry {}s. Retrying in {}ms.",
                        consecutive_failures,
                        ttl.unwrap_or(0),
                        backoff.as_millis(),
                    );
                    if halt.sleep(backoff) {
                        return;
                    }
                    continue;
                }
                if let Some(label) = resolved {
                    if label != last_label {
                        match rotor.advance_trust_epoch(label.clone(), now_unix()) {
                            Ok(TrustEpochAdvance::Advanced) => {
                                consecutive_failures = 0;
                                last_label = label;
                                signer.metrics().record_success(now_unix());
                                eprintln!(
                                    "mcp-re-proxy: trust epoch advanced -> {last_label}: delegated \
                                     keys re-issued under the new epoch. This replica no longer \
                                     mints under the prior epoch. Credentials already issued under \
                                     it stay VERIFIABLE until verifiers are pointed at the new \
                                     epoch — update the verifiers' accepted epochs to complete the \
                                     revocation (delegation_trust_epoch_stale)."
                                );
                                continue;
                            }
                            // The root declined and the PRIOR-epoch key is still valid.
                            // `last_label` is deliberately left where it was, so the
                            // next pass re-enters this arm and retries; advancing it
                            // here would report a revocation that never happened and
                            // never look at it again.
                            Ok(TrustEpochAdvance::Declined) => {
                                consecutive_failures = signer.metrics().record_failure();
                                let ttl = signer.seconds_to_expiry(now_unix());
                                let backoff =
                                    rotation_backoff(consecutive_failures, ttl, rotation_jitter());
                                eprintln!(
                                    "mcp-re-proxy: WARNING: trust epoch advance to {label} NOT \
                                     APPLIED (root issuer declined); this replica is STILL MINTING \
                                     under the prior epoch on its current key, until that key's \
                                     exp ({}s) and then FAILS CLOSED. The break-glass revocation \
                                     is not yet in force here. consecutive_failures {}. Retrying \
                                     in {}ms.",
                                    ttl.unwrap_or(0),
                                    consecutive_failures,
                                    backoff.as_millis(),
                                );
                                if halt.sleep(backoff) {
                                    return;
                                }
                                continue;
                            }
                            Err(_) => {
                                consecutive_failures = signer.metrics().record_failure();
                                let ttl = signer.seconds_to_expiry(now_unix());
                                let backoff =
                                    rotation_backoff(consecutive_failures, ttl, rotation_jitter());
                                eprintln!(
                                    "mcp-re-proxy: WARNING: re-issue on trust-epoch advance FAILED \
                                     (root issuer unavailable); consecutive_failures {}. Retrying in {}ms.",
                                    consecutive_failures,
                                    backoff.as_millis(),
                                );
                                if halt.sleep(backoff) {
                                    return;
                                }
                                continue;
                            }
                        }
                    }
                }
            }
            // The delegated kid BEFORE the attempt, so silent no-progress is detectable.
            // `ensure_active` returns Ok when successor issuance FAILED but the current
            // key is still valid (custody.rs: the `!current_valid` guard is skipped and
            // the fallthrough `Some(a) if now < a.exp => Ok(())` wins). That is the
            // PRIMARY failure mode — a root outage during the overlap window, exactly
            // what the overlap exists to absorb — and taking it as success would reset
            // `consecutive_failures`, collapse `wake_at` to now (we are already past
            // `exp - overlap`), and re-enter this arm immediately: a tight retry loop
            // against the root KMS/HSM, minting a fresh keypair every pass, for the
            // whole overlap window. The backoff below must cover it.
            let before_kid = signer.current(now_unix()).map(|a| a.delegated_kid.clone());
            match rotor.rotate(now_unix()) {
                Ok(()) if !rotation_made_progress(signer, &before_kid, overlap) => {
                    consecutive_failures = signer.metrics().record_failure();
                    let ttl = signer.seconds_to_expiry(now_unix());
                    let backoff = rotation_backoff(consecutive_failures, ttl, rotation_jitter());
                    eprintln!(
                        "mcp-re-proxy: WARNING: delegated successor issuance FAILED (root issuer \
                         unavailable) but the current key is still valid; consecutive_failures {}, \
                         time-to-expiry {}s. Serving continues on the current key until its exp, \
                         then FAILS CLOSED (ADR-MCPRE-052 §6). Retrying in {}ms.",
                        consecutive_failures,
                        ttl.unwrap_or(0),
                        backoff.as_millis(),
                    );
                    if halt.sleep(backoff) {
                        return;
                    }
                }
                Ok(()) => {
                    consecutive_failures = 0;
                    signer.metrics().record_success(now_unix());
                    if let Some(ev) = rotor.audit().last() {
                        let ttl = signer.seconds_to_expiry(now_unix()).unwrap_or(0);
                        eprintln!(
                            "mcp-re-proxy: delegated key {} (kid {}, exp {}); time-to-expiry {}s; \
                             rotations_ok {}",
                            ev.event_type,
                            ev.delegated_kid,
                            ev.exp,
                            ttl,
                            signer.metrics().rotations_ok(),
                        );
                    }
                }
                Err(_) => {
                    consecutive_failures = signer.metrics().record_failure();
                    let ttl = signer.seconds_to_expiry(now_unix());
                    // Bounded jittered exponential backoff, capped by the current key's
                    // remaining validity (retry inside the overlap window) and a 30s
                    // ceiling once expired. OS CSPRNG jitter decorrelates a fleet.
                    let backoff = rotation_backoff(consecutive_failures, ttl, rotation_jitter());
                    eprintln!(
                        "mcp-re-proxy: WARNING: delegated key issuance FAILED (root issuer \
                         unavailable); consecutive_failures {}, time-to-expiry {}s. Serving \
                         continues only until the current delegated key expires, then FAILS CLOSED \
                         (ADR-MCPRE-052 §6) — no stale-key extension, no direct-root fallback. \
                         Retrying in {}ms.",
                        consecutive_failures,
                        ttl.unwrap_or(0),
                        backoff.as_millis(),
                    );
                    // Interruptible backoff so a persistent root outage does not hot-spin;
                    // the hot path keeps signing off the current key until its exp.
                    if halt.sleep(backoff) {
                        return;
                    }
                }
            }
        }
    }
}

/// Did the rotation attempt actually mint a successor?
///
/// `DelegatedSigningCustody::ensure_active` reports `Ok(())` in two very different
/// situations: a successor was issued, or issuance failed while the current key is
/// still valid (so the fleet keeps signing and the caller is expected to retry).
/// Only the first is progress. Without this distinction the retry loop treats a root
/// outage during the overlap window as steady state and spins on the root issuer.
///
/// Progress means the published delegated kid changed. When nothing is published at
/// all there is nothing to keep serving on, and the `Err` arm already handles that;
/// when the attempt was not yet due (we are outside the overlap window) an unchanged
/// kid is expected and not a failure.
fn rotation_made_progress(
    signer: &crate::delegated_server_signer::DelegatedServerSigner,
    before_kid: &Option<String>,
    overlap: i64,
) -> bool {
    let now = now_unix();
    let Some(active) = signer.current(now) else {
        // Nothing published: not progress, but also nothing to back off protecting.
        return false;
    };
    if active.delegated_kid != *before_kid.as_deref().unwrap_or("") {
        return true;
    }
    // Same kid. Only a rotation that was DUE and did not happen is a failure.
    now < active.exp - overlap
}

/// A fresh random u64 from the OS CSPRNG for backoff jitter. On the (astronomically
/// unlikely) CSPRNG failure, fall back to 0 (no jitter) rather than panicking the
/// rotation thread — the backoff still bounds the retry rate, only its dither is lost.
fn rotation_jitter() -> u64 {
    let mut b = [0u8; 8];
    match getrandom::fill(&mut b) {
        Ok(()) => u64::from_le_bytes(b),
        Err(_) => 0,
    }
}

/// MCPS-84 (ADR-MCPS-049 W2): build the networked trust-epoch invalidation channel
/// for the ADR-021 Push tier when `--trust-epoch-redis-url` is configured. Under
/// the `redis_replay` feature this connects the Redis trust-epoch source; without
/// it, a configured URL fails closed (a networked backend was requested but not
/// compiled in). Returns `None` when no URL is set (Push runs inert / bounded-`T`).
#[cfg(feature = "redis_replay")]
fn build_trust_epoch_channel(
    config: &cli::Config,
    workers: &mut crate::managed_worker::WorkerSet,
) -> Result<Option<Box<dyn crate::InvalidationChannel + Send + Sync>>, String> {
    match &config.trust_epoch_redis_url {
        Some(url) => {
            let key = config
                .trust_epoch_key
                .as_deref()
                .unwrap_or(crate::trust_epoch::DEFAULT_TRUST_EPOCH_KEY);
            let source = std::sync::Arc::new(
                crate::trust_epoch::redis_trust_epoch_source(url, key)
                    .map_err(|e| format!("trust-epoch source: {e}"))?,
            );
            // The epoch read is a blocking network round trip behind ONE connection
            // mutex, and the resolver that would trigger it runs before signature
            // verification on every request. Polled from a dedicated thread instead,
            // so the request path costs a mutex acquisition and the whole per-core
            // fleet is not serialized on one Redis connection.
            let halt = workers.halt();
            workers.spawn(
                "trust epoch poll",
                crate::trust_epoch::trust_epoch_poller_body(
                    std::sync::Arc::clone(&source),
                    TRUST_EPOCH_POLL_SECS,
                    move || halt.requested(),
                ),
            );
            eprintln!(
                "mcp-re-proxy: revocation-tier PUSH: networked trust-epoch source ACTIVE (redis, \
                 epoch key {key:?}, polled every {TRUST_EPOCH_POLL_SECS}s off the request path); \
                 the trust cache flushes within one poll interval of an epoch advance and \
                 reverts to the bounded-T guarantee on a read outage."
            );
            Ok(Some(Box::new(crate::trust_epoch::SharedEpochChannel(
                source,
            ))))
        }
        None => Ok(None),
    }
}

#[cfg(not(feature = "redis_replay"))]
fn build_trust_epoch_channel(
    config: &cli::Config,
    _workers: &mut crate::managed_worker::WorkerSet,
) -> Result<Option<Box<dyn crate::InvalidationChannel + Send + Sync>>, String> {
    if config.trust_epoch_redis_url.is_some() {
        return Err(
            "--trust-epoch-redis-url requires a build with the `redis_replay` feature".to_string(),
        );
    }
    Ok(None)
}

/// The shared trust-epoch counter, watched by the delegated-rotation owner so an
/// operator's `INCR <trust-epoch-key>` invalidates the outstanding epoch of delegated
/// response keys across the fleet (ADR-MCPRE-052 §7). The RESPONSE-side counterpart to
/// [`build_trust_epoch_channel`], which flushes the REQUEST-trust cache on the same
/// advance. Read-only; a read error leaves the epoch unchanged (never advance on a
/// transient blip).
///
/// What an advance does and does not do: it stops this fleet MINTING under the prior
/// epoch. It does not reach credentials already issued under it — no verifier reads the
/// counter, so `accepted_epochs` is static verifier configuration and a leaked
/// credential stays verifiable until the verifiers are pointed at the new epoch
/// (docs/spec/delegated-required-validation-matrix.md §C.1, "Operational consequence").
/// The counter is therefore also a fleet availability dependency: anyone who can write
/// the shared key can advance it and make every replica mint a label the currently
/// configured verifiers reject.
///
/// The emitted label is ALWAYS `<base>#<counter>` — never the bare base label. That is
/// what makes an operator `INCR` survive a replica restart: the label is derived purely
/// from shared state, so every replica at counter `N` mints `<base>#N` regardless of
/// when it started. The previous design compared the counter against a baseline read at
/// *this process's* startup and emitted the bare base label while they matched, so a
/// replica restarting after an `INCR` adopted the advanced value as its own baseline,
/// never observed an advance, and kept minting an epoch verifiers still accepted — the
/// kill switch was process-relative rather than durable.
///
/// `high_water` makes the emitted epoch monotone WITHIN a process: a read that goes
/// backwards (store reset, failover to a stale replica, a reconnect landing on the
/// wrong instance) is refused rather than rebased, so reconnection can never re-mint
/// under an epoch a verifier has already stopped accepting. Across a restart the shared
/// counter is the only authority, by construction — a store that loses its counter is a
/// trust-store failure, not something a replica can detect locally.
struct DelegatedEpochWatch {
    reader: Box<dyn crate::trust_epoch::EpochReader>,
    base_label: String,
    high_water: std::sync::Mutex<Option<i64>>,
}

impl DelegatedEpochWatch {
    /// The label to mint under, or `None` when the shared epoch cannot be established.
    ///
    /// `None` is FAIL CLOSED FOR MINTING: the caller must not issue a credential,
    /// because it cannot produce an epoch verifiers can compare. It does not retire the
    /// current key — the fleet keeps signing off it until its `exp` and the hot path
    /// then fails closed on its own (ADR-MCPRE-052 §6). Crucially it is also not treated
    /// as "no change": a blip must never be read as an advance, nor as permission to
    /// mint under a stale label.
    fn current_label(&self) -> Option<String> {
        let counter = self.reader.read_epoch().ok()?;
        let mut hw = self.high_water.lock().ok()?;
        if matches!(*hw, Some(prev) if counter < prev) {
            // Regression. Refuse rather than rebase: minting under the lower epoch
            // would resurrect credentials the fleet's verifiers already reject.
            return None;
        }
        *hw = Some(counter);
        Some(format!("{}#{}", self.base_label, counter))
    }
}

/// Build the delegated-signing trust-epoch watcher from `--trust-epoch-redis-url`.
/// `None` when no source is configured — the epoch is then whatever
/// `--delegated-trust-epoch` fixed it to, with no cross-replica revocation signal (the
/// honest bounded behaviour for a single-node deployment).
///
/// When a URL IS configured the watcher is always returned: the reader connects lazily
/// and re-establishes after any failure, so a store that is briefly unreachable at boot
/// no longer leaves this replica permanently without the operator's kill switch. The
/// caller resolves the initial label and fails closed if it cannot.
#[cfg(feature = "redis_replay")]
fn build_delegated_epoch_watch(
    config: &cli::Config,
    base_label: String,
) -> Option<DelegatedEpochWatch> {
    let url = config.trust_epoch_redis_url.as_ref()?;
    let key = config
        .trust_epoch_key
        .as_deref()
        .unwrap_or(crate::trust_epoch::DEFAULT_TRUST_EPOCH_KEY);
    match crate::trust_epoch::RedisEpochReader::connect_lazy(url, key) {
        Ok(reader) => Some(DelegatedEpochWatch {
            reader: Box::new(reader),
            base_label,
            high_water: std::sync::Mutex::new(None),
        }),
        Err(e) => {
            // Only a malformed URL reaches here (`Client::open` parses, it does not
            // connect), so this is a configuration error, not an outage.
            eprintln!(
                "mcp-re-proxy: --trust-epoch-redis-url is not a usable Redis URL ({}); \
                 delegated trust-epoch revocation cannot be wired.",
                e.0
            );
            None
        }
    }
}

#[cfg(not(feature = "redis_replay"))]
fn build_delegated_epoch_watch(
    _config: &cli::Config,
    _base_label: String,
) -> Option<DelegatedEpochWatch> {
    None
}

#[cfg(all(test, unix))]
mod key_file_perm_tests {
    use super::check_key_file_perms;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    /// A key file at `mode`, named per-process so concurrent test binaries do not
    /// collide. Mirrors the temp-file idiom the rest of this crate's tests use
    /// (`std::env::temp_dir()` + pid) rather than adding a dev-dependency.
    struct KeyFile(String);

    impl KeyFile {
        fn at(mode: u32, name: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("mcp_re_perm_{}_{name}", std::process::id()));
            let mut f = std::fs::File::create(&path).expect("create");
            f.write_all(b"key-material").expect("write");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
            KeyFile(path.to_string_lossy().into_owned())
        }
        fn path(&self) -> &str {
            &self.0
        }
    }

    impl Drop for KeyFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// A parsed `Config` for `source`, built through the REAL parser so the test cannot
    /// drift from what the CLI actually produces. An empty `tls_key` is how the parser
    /// represents delegated TLS, so it is passed through rather than defaulted.
    fn config_with(
        source: crate::cli::KeySourceKind,
        seed: &str,
        tls_key: &str,
    ) -> crate::cli::Config {
        use crate::cli::KeySourceKind;
        let (name, mut extra): (&str, Vec<&str>) = match source {
            KeySourceKind::File => ("file", vec![]),
            KeySourceKind::Env => ("env", vec![]), // unreachable outside dev_env_key_source
            KeySourceKind::Pkcs11 => (
                "pkcs11",
                vec![
                    "--pkcs11-module",
                    "/m.so",
                    "--pkcs11-token-label",
                    "t",
                    "--pkcs11-key-label",
                    "k",
                    "--pkcs11-pin-file",
                    "/etc/mcp-re/pin",
                ],
            ),
            KeySourceKind::AwsKms => (
                "aws-kms",
                vec![
                    "--aws-kms-region",
                    "us-east-1",
                    "--aws-kms-key-id",
                    "alias/k",
                ],
            ),
            KeySourceKind::GcpKms => (
                "gcp-kms",
                vec![
                    "--gcp-kms-key-version",
                    "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
                ],
            ),
        };
        let mut argv: Vec<&str> = vec![
            "--bind",
            "127.0.0.1:8443",
            "--audience",
            "did:example:server-1",
            "--server-signer",
            "did:example:server-1",
            "--server-key-id",
            "server-key-1",
            "--tls-cert",
            "/cert",
            "--client-ca",
            "/ca",
            "--trust",
            "/trust.json",
            "--inner-http-url",
            "http://127.0.0.1:8080/mcp",
            "--target-uri",
            "https://mcp.example.com/mcp",
            "--delegated-trust-epoch",
            "epoch-min",
            "--replay-cache",
            "file",
            "--replay-path",
            "/replay",
            "--key-source",
            name,
            "--trust-domain",
            "mcp.example.com",
        ];
        argv.append(&mut extra);
        if !seed.is_empty() {
            argv.extend_from_slice(&["--signing-key-seed", seed]);
        }
        // An empty `tls_key` means delegated TLS; the parser only leaves it empty when a
        // delegated TLS custody is configured, so express that rather than omitting it.
        if tls_key.is_empty() {
            argv.extend_from_slice(&[
                "--gcp-kms-tls-key-version",
                "projects/p/locations/l/keyRings/r/cryptoKeys/tls/cryptoKeyVersions/1",
            ]);
        } else {
            argv.extend_from_slice(&["--tls-key", tls_key]);
        }
        let owned: Vec<String> = argv.into_iter().map(str::to_string).collect();
        crate::cli::parse_args(&owned)
            .unwrap_or_else(|e| panic!("{source:?} config must parse: {e}"))
    }

    /// C048: the PKCS#11 PIN file unlocks the token holding the signing keys, so it must
    /// be among the files the startup permission check covers — otherwise the credential
    /// protecting the keys sits behind a weaker floor than the keys themselves.
    #[test]
    fn the_pkcs11_pin_file_is_permission_checked() {
        use crate::app::key_files_read_from_disk;
        use crate::cli::KeySourceKind;

        let config = config_with(KeySourceKind::Pkcs11, "", "/tls.key");
        let files = key_files_read_from_disk(&config);
        assert!(
            files.contains(&"/etc/mcp-re/pin"),
            "the PIN file must be checked; got {files:?}"
        );
        // And it is NOT claimed for a source that reads no PIN.
        let file_custody = config_with(KeySourceKind::File, "/seed", "/tls.key");
        assert!(
            !key_files_read_from_disk(&file_custody)
                .iter()
                .any(|p| p.contains("pin")),
            "file custody reads no PIN file"
        );
    }

    /// 0644 is world-readable, not merely group-readable — the refusal now says which,
    /// because "restrict to 0600" is more actionable when it names the actual bit.
    #[test]
    fn a_world_readable_key_file_is_refused() {
        let f = KeyFile::at(0o644, "world.key");
        let err = check_key_file_perms(f.path(), false).expect_err("0644 must be refused");
        assert!(err.contains("world-accessible"), "got: {err}");
    }

    /// C053b: group-readable is refused by DEFAULT — the opt-in is what changes it, and
    /// the default posture is exactly what it was.
    #[test]
    fn a_group_readable_key_file_is_refused_without_the_opt_in() {
        let f = KeyFile::at(0o640, "group.key");
        let err = check_key_file_perms(f.path(), false).expect_err("0640 must be refused");
        assert!(err.contains("group-accessible"), "got: {err}");
        assert!(
            err.contains("--allow-group-readable-key-files"),
            "the refusal must name the opt-in that exists for the fsGroup mount model: {err}"
        );
    }

    /// With the opt-in, a group-readable file whose group this process is actually in
    /// is accepted — the file the test harness creates is owned by our own gid.
    #[test]
    fn a_group_readable_key_file_owned_by_our_group_is_accepted_with_the_opt_in() {
        let f = KeyFile::at(0o640, "fsgroup.key");
        check_key_file_perms(f.path(), true).expect("an fsGroup-shaped mount is accepted");
    }

    /// The opt-in does not reach group-WRITE: a peer able to replace the signing key is
    /// never a mount-model requirement.
    #[test]
    fn group_write_is_refused_even_with_the_opt_in() {
        let f = KeyFile::at(0o660, "groupwrite.key");
        let err = check_key_file_perms(f.path(), true).expect_err("0660 must be refused");
        assert!(err.contains("group-writable"), "got: {err}");
    }

    #[test]
    fn an_owner_only_key_file_is_accepted() {
        let f = KeyFile::at(0o600, "owner.key");
        check_key_file_perms(f.path(), false).expect("0600 is the required posture");
    }

    /// The load-bearing property, on the pure predicate `run` actually uses: the TLS
    /// server key is read from disk under EVERY custody mode unless TLS signing is
    /// itself delegated — including the KMS modes advertised as "no key material ever
    /// lands in the pod" — so it must always be among the files checked.
    #[test]
    fn the_tls_key_is_checked_under_every_custody_mode() {
        use crate::app::key_files_read_from_disk;
        use crate::cli::KeySourceKind;

        // `Env` is omitted: it is rejected by the parser outside a
        // `dev_env_key_source` build, so it cannot be constructed here.
        for source in [
            KeySourceKind::File,
            KeySourceKind::Pkcs11,
            KeySourceKind::AwsKms,
            KeySourceKind::GcpKms,
        ] {
            let config = config_with(source, "/seed", "/tls.key");
            let checked = key_files_read_from_disk(&config);
            assert!(
                checked.contains(&"/tls.key"),
                "{source:?}: the TLS key lands on disk and must be permission-checked"
            );
            // The SEED is read only where custody is file-based.
            assert_eq!(
                checked.contains(&"/seed"),
                source == KeySourceKind::File,
                "{source:?}: the seed is checked iff it is actually read"
            );
        }
    }

    /// Delegated TLS leaves `tls_key` empty — that emptiness is how the wiring says "no
    /// key file is read", so nothing must be checked for it.
    #[test]
    fn a_delegated_tls_key_contributes_no_file_to_check() {
        use crate::app::key_files_read_from_disk;
        use crate::cli::KeySourceKind;

        let config = config_with(KeySourceKind::GcpKms, "", "");
        assert!(
            key_files_read_from_disk(&config).is_empty(),
            "delegated TLS + KMS custody reads no private key from disk"
        );
    }

    /// Delegated TLS leaves `tls_key` EMPTY (see `cli::parse_args`), which is how the
    /// wiring expresses "no key file is read" — and an empty path must not be treated as
    /// a key file to check.
    #[test]
    fn an_absent_key_file_is_not_an_error() {
        check_key_file_perms("", false).expect("no file configured is not a violation");
        check_key_file_perms("/nonexistent/path/tls.key", false)
            .expect("a missing file is reported by the loader, not by this guard");
    }
}

#[cfg(test)]
mod rotation_progress_tests {
    use super::rotation_made_progress;
    use crate::delegated_server_signer::DelegatedServerSigner;
    use mcp_re_core::SigningKey;
    use mcp_re_http_profile::ActiveDelegatedKey;
    use mcp_re_http_profile::ActorIdentity;
    use std::sync::Arc;

    const OVERLAP: i64 = 60;

    fn key(kid: &str, exp: i64) -> ActiveDelegatedKey {
        ActiveDelegatedKey {
            key: Arc::new(SigningKey::from_seed_bytes(&[7u8; 32])),
            delegated_kid: kid.to_string(),
            server_signer: ActorIdentity {
                role: "server".into(),
                trust_domain: "example.com".into(),
                subject: "did:example:server".into(),
                keyid: kid.to_string(),
            },
            credential: "cred".into(),
            nbf: 0,
            exp,
        }
    }

    /// The defect this guards: `ensure_active` reports `Ok(())` both when a successor
    /// was minted AND when issuance failed while the current key is still valid. Taking
    /// the second as success reset `consecutive_failures`, collapsed the steady-state
    /// wake time to now (we are already past `exp - overlap`), and re-entered the
    /// rotate arm immediately — a tight loop against the root KMS/HSM, minting a fresh
    /// keypair each pass, for the entire overlap window.
    #[test]
    fn unchanged_kid_inside_the_overlap_window_is_not_progress() {
        let signer = DelegatedServerSigner::new();
        let now = crate::app::now_unix();
        // Published key is inside its overlap window: a rotation is DUE.
        signer.publish(key("K1", now + OVERLAP - 1));
        let before = Some("K1".to_string());
        assert!(
            !rotation_made_progress(&signer, &before, OVERLAP),
            "a due rotation that did not change the kid means issuance failed"
        );
    }

    #[test]
    fn a_new_kid_is_progress() {
        let signer = DelegatedServerSigner::new();
        let now = crate::app::now_unix();
        signer.publish(key("K2", now + 300));
        let before = Some("K1".to_string());
        assert!(rotation_made_progress(&signer, &before, OVERLAP));
    }

    /// Outside the overlap window an unchanged kid is expected, not a failure — the
    /// backoff must not engage in steady state.
    #[test]
    fn unchanged_kid_outside_the_overlap_window_is_not_a_failure() {
        let signer = DelegatedServerSigner::new();
        let now = crate::app::now_unix();
        signer.publish(key("K1", now + 10 * OVERLAP));
        let before = Some("K1".to_string());
        assert!(rotation_made_progress(&signer, &before, OVERLAP));
    }

    /// Nothing published: the `Err` arm owns that case; report no progress.
    #[test]
    fn nothing_published_is_not_progress() {
        let signer = DelegatedServerSigner::new();
        assert!(!rotation_made_progress(&signer, &None, OVERLAP));
    }
}

#[cfg(test)]
mod trust_epoch_watch_tests {
    use super::DelegatedEpochWatch;
    use crate::trust_epoch::EpochReadError;
    use crate::trust_epoch::EpochReader;
    use std::sync::atomic::AtomicI64;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::sync::Mutex;

    const BASE: &str = "epoch-min";

    /// A shared counter standing in for the Redis key, plus a switch that makes reads
    /// fail so an outage can be simulated deterministically.
    struct SharedCounter {
        value: AtomicI64,
        down: Mutex<bool>,
        reads: AtomicUsize,
    }

    impl SharedCounter {
        fn new(v: i64) -> Arc<Self> {
            Arc::new(SharedCounter {
                value: AtomicI64::new(v),
                down: Mutex::new(false),
                reads: AtomicUsize::new(0),
            })
        }
        fn incr(&self) {
            self.value.fetch_add(1, Ordering::SeqCst);
        }
        fn set(&self, v: i64) {
            self.value.store(v, Ordering::SeqCst);
        }
        fn set_down(&self, down: bool) {
            *self.down.lock().expect("down lock") = down;
        }
        fn reads(&self) -> usize {
            self.reads.load(Ordering::SeqCst)
        }
    }

    struct CounterReader(Arc<SharedCounter>);

    impl EpochReader for CounterReader {
        fn read_epoch(&self) -> Result<i64, EpochReadError> {
            self.0.reads.fetch_add(1, Ordering::SeqCst);
            if *self.0.down.lock().expect("down lock") {
                return Err(EpochReadError("epoch store unreachable".into()));
            }
            Ok(self.0.value.load(Ordering::SeqCst))
        }
    }

    /// Start a replica's watch over the shared counter. Constructing a NEW watch over
    /// the SAME counter is exactly what a restart looks like: no carried-over state.
    fn replica(counter: &Arc<SharedCounter>) -> DelegatedEpochWatch {
        DelegatedEpochWatch {
            reader: Box::new(CounterReader(Arc::clone(counter))),
            base_label: BASE.to_string(),
            high_water: Mutex::new(None),
        }
    }

    /// The label is derived purely from shared state, so it is globally comparable.
    #[test]
    fn label_is_always_base_hash_counter_never_the_bare_base() {
        let counter = SharedCounter::new(0);
        let w = replica(&counter);
        assert_eq!(w.current_label().as_deref(), Some("epoch-min#0"));
        counter.incr();
        assert_eq!(w.current_label().as_deref(), Some("epoch-min#1"));
    }

    /// Every replica at the same counter mints the same label, whenever it started.
    #[test]
    fn all_replicas_agree_regardless_of_start_time() {
        let counter = SharedCounter::new(4);
        let a = replica(&counter);
        assert_eq!(a.current_label().as_deref(), Some("epoch-min#4"));
        // B joins the fleet later.
        let b = replica(&counter);
        assert_eq!(b.current_label(), a.current_label());
    }

    /// THE INVARIANT (C007). An operator INCR must stay effective across a restart: the
    /// restarted replica must NOT reinterpret the current counter as a fresh local
    /// baseline and resume minting a label verifiers treat as unrevoked.
    #[test]
    fn an_increment_survives_a_replica_restart() {
        let counter = SharedCounter::new(7);
        let long_lived = replica(&counter);
        let before = long_lived.current_label().expect("readable");
        assert_eq!(before, "epoch-min#7");

        // Operator revokes the fleet.
        counter.incr();
        let after_incr = long_lived.current_label().expect("readable");
        assert_eq!(after_incr, "epoch-min#8");
        assert_ne!(after_incr, before, "the INCR must change the minted label");

        // A replica restarts: brand-new watch, no memory of the pre-INCR value.
        let restarted = replica(&counter);
        let after_restart = restarted.current_label().expect("readable");

        assert_eq!(
            after_restart, after_incr,
            "a restarted replica must resolve the SAME post-INCR label as its peers"
        );
        assert_ne!(
            after_restart, before,
            "a restart must NOT resurrect the pre-INCR epoch — that is the revocation \
             being defeated by a restart"
        );
    }

    /// An outage is fail-closed FOR MINTING: no label, so the caller must not issue.
    /// It is not silently treated as "unchanged", which would keep minting blind.
    #[test]
    fn an_outage_yields_no_label_so_minting_stops() {
        let counter = SharedCounter::new(3);
        let w = replica(&counter);
        assert!(w.current_label().is_some());
        counter.set_down(true);
        assert!(
            w.current_label().is_none(),
            "an unreadable epoch must fail closed for minting"
        );
    }

    /// Reconnect after an outage resumes at the CURRENT shared value — including an
    /// INCR that happened while this replica could not read.
    #[test]
    fn reconnect_after_an_outage_resumes_and_sees_missed_increments() {
        let counter = SharedCounter::new(1);
        let w = replica(&counter);
        assert_eq!(w.current_label().as_deref(), Some("epoch-min#1"));

        counter.set_down(true);
        assert!(w.current_label().is_none());
        // The operator revokes DURING the outage.
        counter.incr();
        counter.incr();
        assert!(w.current_label().is_none(), "still down");

        counter.set_down(false);
        assert_eq!(
            w.current_label().as_deref(),
            Some("epoch-min#3"),
            "a reconnect must observe increments missed during the outage"
        );
        assert!(
            counter.reads() >= 4,
            "each attempt re-reads; no cached verdict"
        );
    }

    /// Reconnection must not reset, rebase or otherwise weaken an already-issued
    /// revocation: a counter that goes BACKWARDS (store reset, failover to a stale
    /// replica, reconnect to the wrong instance) is refused, never adopted.
    #[test]
    fn a_regressed_counter_is_refused_not_rebased() {
        let counter = SharedCounter::new(9);
        let w = replica(&counter);
        assert_eq!(w.current_label().as_deref(), Some("epoch-min#9"));

        counter.set(2); // store rolled back
        assert!(
            w.current_label().is_none(),
            "minting under a lower epoch would resurrect credentials verifiers reject"
        );
        // Still refused on retry — it is not a transient blip that clears itself.
        assert!(w.current_label().is_none());

        // Recovery to at-or-above the high-water mark resumes minting.
        counter.set(9);
        assert_eq!(w.current_label().as_deref(), Some("epoch-min#9"));
        counter.set(11);
        assert_eq!(w.current_label().as_deref(), Some("epoch-min#11"));
    }

    /// Issuance continues normally across the whole sequence the operator cares about:
    /// steady state -> INCR -> outage -> reconnect -> restart.
    #[test]
    fn full_sequence_increment_outage_restart_reconnect_continued_issuance() {
        let counter = SharedCounter::new(0);
        let mut minted: Vec<String> = Vec::new();
        let w = replica(&counter);

        minted.push(w.current_label().expect("steady state"));
        counter.incr();
        minted.push(w.current_label().expect("after incr"));

        counter.set_down(true);
        assert!(w.current_label().is_none(), "no minting during the outage");
        counter.set_down(false);
        minted.push(w.current_label().expect("after reconnect"));

        // Restart: fresh watch, same shared counter.
        let w2 = replica(&counter);
        minted.push(w2.current_label().expect("after restart"));
        counter.incr();
        minted.push(
            w2.current_label()
                .expect("issuance continues after restart"),
        );

        assert_eq!(
            minted,
            vec![
                "epoch-min#0".to_string(),
                "epoch-min#1".to_string(),
                "epoch-min#1".to_string(),
                "epoch-min#1".to_string(),
                "epoch-min#2".to_string(),
            ],
            "labels track the shared counter only — never a per-process baseline"
        );
    }
}

#[cfg(test)]
mod store_cadence_tests {
    use super::fleet_trust_bound;
    use super::store_change_cadence;
    use super::TrustStoreFreshness;
    use crate::revocation_tier::RevocationTier;
    use std::sync::Arc;

    /// R7-C126: the `--fleet` push-tier line must not claim a mechanism that was
    /// removed. The epoch is read by a 5s background poller, never on the request path,
    /// so "flush on the next request after an epoch advance" was a guarantee the data
    /// plane could not keep — an operator sizing a revocation SLO from it got a number
    /// short by up to the poll interval.
    #[test]
    fn the_push_tier_bound_states_the_poll_interval_not_the_next_request() {
        let line = fleet_trust_bound(&RevocationTier::Push { t_secs: 90 }, true, Some(30));
        assert!(
            !line.contains("next request"),
            "the per-request flush no longer exists: {line}"
        );
        assert!(
            line.contains(&format!(
                "{}s trust-epoch poll interval",
                super::TRUST_EPOCH_POLL_SECS
            )),
            "the honest bound is one poll interval: {line}"
        );
        assert!(
            line.contains("90s"),
            "the outage fallback is still named: {line}"
        );
    }

    /// A push tier with no networked source is inert, and says so rather than quoting
    /// the healthy-source number.
    #[test]
    fn a_push_tier_without_a_source_reports_the_fallback_only() {
        let line = fleet_trust_bound(&RevocationTier::Push { t_secs: 90 }, false, Some(30));
        assert!(line.contains("inert"), "got: {line}");
        assert!(
            !line.contains("poll interval"),
            "no source means no poll to bound anything: {line}"
        );
    }

    /// Every tier's number sits over the same floor: nothing resolves faster than the
    /// store is re-read.
    #[test]
    fn every_tier_names_the_reload_floor_under_its_number() {
        for tier in [
            RevocationTier::Live,
            RevocationTier::BoundedCache { t_secs: 60 },
            RevocationTier::Push { t_secs: 60 },
        ] {
            let with_reload = fleet_trust_bound(&tier, true, Some(15));
            assert!(
                with_reload.contains("--trust re-read every 15s"),
                "tier {tier:?}: {with_reload}"
            );
            let frozen = fleet_trust_bound(&tier, true, None);
            assert!(
                frozen.contains("only on a restart"),
                "tier {tier:?}: a frozen store must be named on the same line: {frozen}"
            );
        }
    }

    /// R7-C129: `bounded-cache` is the tier a deployment gets by omission, and it is
    /// accepted with no `--trust-reload-secs` while still printing "revocation enforced
    /// fleet-wide within T". Without a reload the base store is frozen for the process
    /// lifetime, so the qualifier has to be ON that line — not a separate one further
    /// down that an operator quoting the tier line never reads.
    #[test]
    fn a_tier_with_no_reload_cadence_says_the_store_cannot_change() {
        let line = store_change_cadence(None);
        assert!(line.contains("NONE"), "got: {line}");
        assert!(
            line.contains("CACHING"),
            "the line must say what the tier's window actually bounds: {line}"
        );
        assert!(
            line.contains("restart"),
            "and what changing the store actually costs: {line}"
        );
    }

    /// With a cadence the same line names it, so the tier window and the store window
    /// are read together.
    #[test]
    fn a_configured_cadence_is_named_on_the_tier_line() {
        let line = store_change_cadence(Some(30));
        assert!(line.starts_with("30s"), "got: {line}");
        assert!(line.contains("--trust"), "got: {line}");
    }

    /// R7-C072/C104: keep-last-good must be BOUNDED. A trust file that becomes
    /// permanently unreadable otherwise restores the unbounded revocation window the
    /// reload exists to close, silently — an `InMemoryTrustResolver` carries no expiry,
    /// so nothing makes a frozen snapshot stop being honoured on its own.
    ///
    /// The bound has to be a state the RESOLVER reads, not a warning on stderr: a log
    /// line changes nothing about which keys keep verifying.
    #[test]
    fn a_frozen_store_stops_answering_instead_of_serving_the_revoked_key() {
        use mcp_re_core::TrustResolver;

        struct AlwaysResolves;
        impl TrustResolver for AlwaysResolves {
            fn resolve(
                &self,
                _signer: &str,
                _key_id: &str,
            ) -> Result<mcp_re_core::VerificationKey, mcp_re_core::TrustResolverError> {
                Ok(mcp_re_core::SigningKey::from_seed_bytes(&[9u8; 32]).public_key())
            }
        }

        let freshness = Arc::new(TrustStoreFreshness::default());
        let resolver = super::StaleFailsClosed {
            inner: Arc::new(AlwaysResolves),
            freshness: Arc::clone(&freshness),
        };

        assert!(
            resolver.resolve("signer-a", "kid-a").is_ok(),
            "a fresh store answers normally"
        );

        // The reload has failed its budget: the snapshot behind this resolver can no
        // longer be trusted to reflect a revocation.
        freshness.mark_stale();
        assert!(
            matches!(
                resolver.resolve("signer-a", "kid-a"),
                Err(mcp_re_core::TrustResolverError::Unavailable { .. })
            ),
            "a frozen store still HOLDS the revoked key, so answering from it is the \
             one outcome that must not happen — and it must be reported as an outage, \
             not as an unknown keyid"
        );

        freshness.mark_fresh();
        assert!(
            resolver.resolve("signer-a", "kid-a").is_ok(),
            "a recovered reload serves again"
        );
    }
}
