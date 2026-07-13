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

use crate::config_snapshot;
use crate::cli;
use crate::cli::BindingKind;
use crate::cli::KeySourceKind;
use crate::cli::ReplayKind;
use crate::http_inner::HttpInnerPool;
use crate::HttpProfileProxy;
use crate::async_replay::AsyncReplayTier;
use crate::async_replay::InMemoryAsyncAtomicReplayStore;
use crate::http_profile_dispatch::ProxyDispatchConfig;
use crate::transport::TransportBindingPolicy;
use crate::async_serve::ServedHttpRequest;
use mcp_re_core::VerificationKey;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use std::collections::HashMap;
use crate::tls;
use crate::transport::ExactMatchBinding;
use crate::ReplayDurabilityTier;
use crate::IdentityStrategy;
use crate::RevocationTier;
use crate::ReverseProxyMtlsProvider;
use crate::ServerOptions;

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

/// Enforce the key-file-permission posture for a sensitive key file. The proxy
/// always runs the maximal-security posture, so a group/world-accessible key file
/// is a HARD error returned to the caller (startup refuses). Uses the pure
/// [`cli::key_file_mode_is_insecure`] predicate so it stays consistent with (and
/// testable alongside) the parse-time checks.
#[cfg(unix)]
fn check_key_file_perms(path: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mode = meta.permissions().mode();
        if cli::key_file_mode_is_insecure(mode) {
            return Err(format!(
                "mcp-re-proxy refuses unsafe configuration:\n  - key file {path} \
                 is group/world-accessible (mode {:o}); restrict to 0600",
                mode & 0o777
            ));
        }
    }
    Ok(())
}
#[cfg(not(unix))]
fn check_key_file_perms(_path: &str, _strict: bool) -> Result<(), String> {
    Ok(())
}

/// Build every component from `config` and serve on the per-core async fleet until
/// `shutdown` is flipped (SIGTERM/SIGINT in the binary; a test flag in tests). The
/// binary's `main` is a thin shim over this; keeping it in the library makes the
/// whole deployed serving path in-process-testable.
pub fn run(
    config: crate::cli::Config,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<(), String> {

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
            config.reverse_proxy_header_format,
            config.identity_source,
            config.bind,
        );
    }
    if config.key_source == KeySourceKind::File {
        // A group/world-readable key file is a HARD error (refuse startup). The other
        // guards are parse-time and already enforced inside `cli::parse_args`; this
        // one is filesystem-dependent so it lives here.
        check_key_file_perms(&config.signing_key_seed)?;
        check_key_file_perms(&config.tls_key)?;
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
    let key_source = cli::build_key_source(&config).map_err(|e| e.to_string())?;
    let server_chain = key_source.tls_server_cert_chain().map_err(|e| e.to_string())?;
    let client_ca = key_source.client_ca_roots().map_err(|e| e.to_string())?;
    // ADR-MCPS-028 §G / issue #58: TLS signing is DELEGATED xor EXPORTED. When the
    // source offers a delegated TLS signer the server private key never leaves the
    // device — we never call `tls_server_key()`. The exported key is loaded ONLY on
    // the non-delegated path. The CLI exclusivity guard (`cli::parse_args`) already
    // rejected a config that asks for both.
    let tls_delegated_signer = key_source.tls_delegated_signer();
    let server_key = match &tls_delegated_signer {
        Some(_) => None,
        None => Some(key_source.tls_server_key().map_err(|e| e.to_string())?),
    };
    let trust_bytes = std::fs::read(&config.trust_path)
        .map_err(|e| format!("{}: {e}", config.trust_path))?;
    let base_resolver = cli::load_trust(&trust_bytes)?;

    // ADR-MCPS-021 Axis 2: surface the DECLARED revocation tier and its honest
    // guarantee at startup. The proxy emits the tier's OWN guarantee string — never
    // a hardcoded stronger one — so it cannot surface a revocation window stronger
    // than the configured tier proves (the tier-claim ceiling). Tier 1
    // (bounded-cache) is the default when --revocation-tier is absent.
    eprintln!(
        "mcp-re-proxy: {}",
        config.revocation_tier.startup_audit_line("trust-store")
    );
    // ADR-MCPS-021 Axis 2: APPLY the declared tier to the resolver so the runtime
    // behavior actually matches the surfaced guarantee (Tier 1 bounds cached active
    // trust to T; Tier 2 consults the store live every request; Tier 3 evicts on a
    // pushed event, else falls back to bounded T). Without this wrapping the tier
    // line above would be a claim the resolver does not enforce.
    // MCPS-84: connect the networked trust-epoch invalidation channel if one is
    // configured (only under --revocation-tier push; enforced at parse time).
    let push_channel = build_trust_epoch_channel(&config)?;
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
        Box::new(base_resolver),
        trust_clock(),
        push_channel,
    );

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
    // Response slot (slot discipline, MCPRE-100). `_resolver`/`key_source` stay for
    // the TLS path; the object response-signer seam is gone.
    let _ = &resolver;
    let trust_entries = cli::load_trust_entries(&trust_bytes)?;
    // Response-slot signing custody (ADR-MCPRE-052, MCPRE-122): delegated-signing is
    // the ONLY response mode. The ROOT key is the credential ISSUER only; the resolver
    // resolves the ROOT public key (by its issuer kid) for the Response slot, and NO
    // directly-held server key exists. The delegated key is never enrolled (authorized
    // by the credential alone). The root key source is only borrowed here (for its
    // public key); it is moved into the issuer at proxy build, so KMS-rooted delegated
    // signing works on the async serving path.
    let response_kid = config
        .delegated_issuer_kid
        .clone()
        .unwrap_or_else(|| config.server_key_id.clone());
    let response_pub = key_source.response_public_key().map_err(|e| e.to_string())?;
    let server_identity = ActorIdentity {
        role: "server".to_string(),
        trust_domain: config.trust_domain.clone(),
        subject: config.server_signer.clone(),
        keyid: response_kid.clone(),
    };
    let mut client_map: HashMap<String, (String, VerificationKey)> = HashMap::new();
    for (signer, key_id, key) in trust_entries {
        if key_id != response_kid {
            client_map.insert(key_id, (signer, key));
        }
    }
    let skid = response_kid.clone();
    let sident = server_identity.clone();
    let td = config.trust_domain.clone();
    let resolve_actor: crate::ActorResolver =
        Box::new(move |kid: &str, slot: SignerSlot| match slot {
            SignerSlot::Response if kid == skid => Some(ResolvedActor {
                identity: sident.clone(),
                verification_key: response_pub.clone(),
                slot,
            }),
            SignerSlot::Request => client_map.get(kid).map(|(signer, key)| ResolvedActor {
                identity: ActorIdentity {
                    role: "client".to_string(),
                    trust_domain: td.clone(),
                    subject: signer.clone(),
                    keyid: kid.to_string(),
                },
                verification_key: key.clone(),
                slot,
            }),
            _ => None,
        });
    let expected_audience = AudienceTuple {
        audience_id: config.audience.clone(),
        target_uri: config.target_uri.clone(),
        route: config.route.clone(),
    };
    // The authoritative async replay tier (§4) + deployment durability posture,
    // selected below; default is the single-replica in-memory tier.
    let mut replay_async =
        AsyncReplayTier::new(Arc::new(InMemoryAsyncAtomicReplayStore::new()), config.max_clock_skew);
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
    // control runtime (`replay_control_rt`), distinct from the per-core serving
    // runtimes; it is held alive for the whole serve.
    let replay_control_rt: Option<tokio::runtime::Runtime>;
    match config.replay {
        ReplayKind::Memory => {
            // Proxy::new already installed the in-memory async tier (single-replica).
            replay_control_rt = None;
        }
        ReplayKind::File => {
            return Err(
                "--replay-cache file is not supported on the async serving path: a single \
                 file-backed cache does not fit the per-core share-nothing data plane. Use \
                 --replay-cache shared (redis/etcd) for durable cross-replica replay, or \
                 --replay-cache memory for single-replica development."
                    .to_string(),
            );
        }
        ReplayKind::Shared => {
            let tier_kind = config
                .replay_durability_tier
                .as_ref()
                .ok_or("--replay-cache shared requires --replay-durability-tier")?;
            if matches!(tier_kind, ReplayDurabilityTier::Linearizable) {
                let endpoint = config.cpstore_etcd_endpoint.clone().ok_or(
                    "--replay-durability-tier linearizable requires --cpstore-etcd-endpoint",
                )?;
                #[cfg(feature = "cpstore_etcd")]
                {
                    eprintln!(
                        "mcp-re-proxy: replay tier = shared (CP/linearizable; async etcd backend)"
                    );
                    eprintln!("mcp-re-proxy: {}", tier_kind.startup_audit_line("etcd"));
                    let store = Arc::new(
                        crate::async_etcd_store::EtcdAsyncAtomicReplayStore::connect(
                            &endpoint,
                        ),
                    );
                    replay_async = crate::async_replay::AsyncReplayTier::new(
                        store,
                        config.max_clock_skew,
                    );
                    dispatch_cfg = ProxyDispatchConfig {
                        fleet_strict: true,
                        tier: config.replay_durability_tier.clone(),
                    };
                    replay_control_rt = None;
                }
                #[cfg(not(feature = "cpstore_etcd"))]
                {
                    let _ = endpoint;
                    return Err("--replay-durability-tier linearizable requires a build with the `cpstore_etcd` feature".to_string());
                }
            } else {
                let url = config
                    .replay_redis_url
                    .clone()
                    .ok_or("--replay-cache shared requires --replay-redis-url")?;
                #[cfg(feature = "redis_replay")]
                {
                    eprintln!(
                        "mcp-re-proxy: replay tier = shared (horizontally-scaled; async Redis backend)"
                    );
                    eprintln!("mcp-re-proxy: {}", tier_kind.startup_audit_line("redis"));
                    // The ConnectionManager's reconnect task runs on this dedicated
                    // process-lifetime runtime, distinct from the per-core serving
                    // runtimes; held alive by `replay_control_rt` for the whole serve.
                    let rt = tokio::runtime::Builder::new_multi_thread()
                        .worker_threads(1)
                        .enable_all()
                        .build()
                        .map_err(|e| format!("build replay control runtime: {e}"))?;
                    let store = Arc::new(
                        rt.block_on(crate::RedisAsyncAtomicReplayStore::connect(&url))
                            .map_err(|e| format!("connect redis async replay store: {e:?}"))?,
                    );
                    replay_async = crate::async_replay::AsyncReplayTier::new(
                        store,
                        config.max_clock_skew,
                    );
                    dispatch_cfg = ProxyDispatchConfig {
                        fleet_strict: true,
                        tier: config.replay_durability_tier.clone(),
                    };
                    replay_control_rt = Some(rt);
                }
                #[cfg(not(feature = "redis_replay"))]
                {
                    let _ = url;
                    return Err("--replay-cache shared (redis) requires a build with the `redis_replay` feature".to_string());
                }
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
    if replay_async.durability_class()
        == mcp_re_core::ReplayDurabilityClass::SingleProcessReference
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
        let trust_bound = match (&config.revocation_tier, config.trust_epoch_redis_url.is_some()) {
            (RevocationTier::Push { t_secs }, true) => format!(
                "near-zero when the trust-epoch source is healthy (flush on the next request after \
                 an epoch advance), bounded {t_secs}s on a source read-outage (fail-closed)"
            ),
            (RevocationTier::Push { t_secs }, false) => {
                format!("bounded {t_secs}s (no --trust-epoch-redis-url; the push channel is inert)")
            }
            (RevocationTier::BoundedCache { t_secs }, _) => format!("bounded {t_secs}s"),
            (RevocationTier::Live, _) => {
                "per-request live re-resolution (no positive cache)".to_string()
            }
        };
        let crl_bound = if client_crls.is_empty() {
            let window = config
                .max_client_cert_lifetime
                .map(|d| format!("{}s", d.as_secs()))
                .unwrap_or_else(|| "unbounded".to_string());
            format!("short-lived-cert only (exposure_window {window}); no client CRL")
        } else {
            "the CRL nextUpdate / in-process reload cadence (reload needs a restart until \
             MCPS-66) — a fleet's CRL-rollout window"
                .to_string()
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
    // ADR-MCPRE-051 §6 (MCPRE-116): capture the direct-TLS rebuild inputs BEFORE the
    // match consumes them, so the opt-in CRL hot-reload task can rebuild the verifier
    // from a refreshed `--client-crl` without a restart. Only the direct
    // (exported-key) path is reloadable in this increment; delegated-TLS reload is a
    // tracked follow-up.
    let is_delegated_tls = tls_delegated_signer.is_some();
    let reload_chain = server_chain.clone();
    let reload_client_ca = client_ca.clone();
    let reload_key = server_key.as_ref().map(|k| k.clone_key());
    let reload_crl_paths = config.client_crl_paths.clone();
    // The CRL verifier ALWAYS fails closed on an unknown revocation status — there
    // is no relax knob. `false` = deny-unknown, threaded to every verifier builder.
    let reload_allow_unknown = false;

    let server_config = match tls_delegated_signer {
        Some(signer) => tls::build_server_config_delegated_validated(
            server_chain,
            signer,
            client_ca,
            client_crls,
            false,
        )
        .map_err(|e| e.to_string())?,
        None => {
            let server_key = server_key.ok_or_else(|| {
                "internal error: exported TLS key missing on the non-delegated path".to_string()
            })?;
            tls::RustlsDirectProvider::build_server_config_with_crls(
                server_chain,
                server_key,
                client_ca,
                client_crls,
                false,
            )
            .map_err(|e| e.to_string())?
        }
    };
    // ADR-MCPRE-051 §6 (MCPRE-116): the serve loop reads the current config from a
    // versioned, atomically-swappable snapshot instead of a fixed `Arc`. With no
    // `--client-crl-reload-secs` the snapshot is never swapped, so behavior is
    // byte-identical to the static posture.
    let config_snapshot = Arc::new(config_snapshot::ServerConfigSnapshot::new(Arc::new(server_config)));
    if let Some(reload_secs) = config.client_crl_reload_secs {
        if reload_crl_paths.is_empty() {
            eprintln!(
                "mcp-re-proxy: --client-crl-reload-secs set but no --client-crl configured; \
                 no CRL reload scheduled"
            );
        } else if is_delegated_tls {
            eprintln!(
                "mcp-re-proxy: --client-crl-reload-secs is not yet supported on the \
                 delegated-TLS path; retaining the static CRL snapshot (follow-up)"
            );
        } else if let Some(reload_key) = reload_key {
            spawn_crl_reload_task(
                Arc::clone(&config_snapshot),
                reload_chain,
                reload_key,
                reload_client_ca,
                reload_crl_paths,
                reload_allow_unknown,
                reload_secs,
                Arc::clone(&shutdown),
            );
            eprintln!(
                "mcp-re-proxy: in-process CRL hot-reload enabled (every {reload_secs}s; \
                 refreshed --client-crl honored without restart; failed reload keeps last-good)"
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
    let ocsp_checker = cli::build_ocsp_checker(&config);
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
            if checker.soft_fail() { "ALLOW (soft-fail)" } else { "REJECT (hard-fail)" },
        );
    }
    let serve_options = ServerOptions {
        identity_policy: config.identity_source,
        identity_strategy,
        limits: config.limits.clone(),
        max_client_cert_lifetime: config.max_client_cert_lifetime,
        #[cfg(feature = "online_ocsp")]
        ocsp_checker,
        target_uri: config.target_uri.clone(),
    };

    // ADR-MCPRE-051 §3: the async inner plane — a per-core pooled hyper client to
    // the stateless Streamable-HTTP inner backends. Forwarding is AWAITED, never
    // blocking a per-core runtime worker.
    let inner_timeout = config
        .limits
        .read_timeout
        .unwrap_or_else(|| Duration::from_secs(30));
    let pool = HttpInnerPool::from_url_strs(config.inner_http_urls.clone(), inner_timeout)?;

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
        } = crate::delegated_wiring::build_delegated_signing(&config, key_source)?;
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
        // key's exp so the KMS/root stays off the per-core serving runtimes.
        spawn_delegated_rotation_task(rotor, Arc::clone(&signer), overlap, Arc::clone(&shutdown));
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
    if let Some(binding) = transport_binding {
        proxy = proxy.with_transport_binding(binding);
    }

    // ADR-MCPRE-051 §1: serve on the per-core async fleet (SO_REUSEPORT + tokio),
    // the production data plane. Blocks until SIGTERM/SIGINT drains the fleet.
    // `replay_control_rt` (if any) is handed in so the redis ConnectionManager's
    // reconnect task stays alive for the whole serve.
    serve_fleet(
        proxy,
        Arc::clone(&config_snapshot),
        serve_options,
        &config,
        replay_control_rt,
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
/// selection. `_replay_control_rt` (if a durable redis tier is configured) holds
/// the redis `ConnectionManager`'s reconnect runtime alive for the whole serve.
fn serve_fleet(
    proxy: HttpProfileProxy,
    config_snapshot: Arc<config_snapshot::ServerConfigSnapshot>,
    serve_options: crate::ServerOptions,
    config: &cli::Config,
    _replay_control_rt: Option<tokio::runtime::Runtime>,
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
        listen_backlog: crate::async_fleet::DEFAULT_LISTEN_BACKLOG,
        max_in_flight_total: None,
    };
    let server_config = config_snapshot.load();
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
fn spawn_crl_reload_task(
    snapshot: Arc<config_snapshot::ServerConfigSnapshot>,
    server_chain: Vec<rustls_pki_types::CertificateDer<'static>>,
    server_key: rustls_pki_types::PrivateKeyDer<'static>,
    client_ca: Vec<rustls_pki_types::CertificateDer<'static>>,
    crl_paths: Vec<String>,
    allow_unknown_status: bool,
    interval_secs: u64,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) {
    std::thread::spawn(move || {
        // Nap in small increments so a shutdown signal is observed within one
        // increment rather than after a whole reload interval.
        let ticks = interval_secs.saturating_mul(20); // 20 * 50ms = 1s
        loop {
            for _ in 0..ticks {
                if shutdown.load(Ordering::SeqCst) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let outcome = config_snapshot::reload_once(&snapshot, || {
                let crls = cli::load_client_crls(&crl_paths)?;
                let rebuilt = tls::RustlsDirectProvider::build_server_config_with_crls(
                    server_chain.clone(),
                    server_key.clone_key(),
                    client_ca.clone(),
                    crls,
                    allow_unknown_status,
                )
                .map_err(|e| e.to_string())?;
                Ok(Arc::new(rebuilt))
            });
            match outcome {
                config_snapshot::ReloadOutcome::Swapped => {
                    eprintln!("mcp-re-proxy: client CRL reloaded; new verifier is live");
                }
                config_snapshot::ReloadOutcome::KeptLastGood { reason } => {
                    eprintln!(
                        "mcp-re-proxy: client CRL reload FAILED, keeping last-good config: {reason}"
                    );
                }
            }
        }
    });
}

/// ADR-MCPRE-052 §4/§6 + ADR-MCPRE-051 §5 (MCPRE-122): the cold-path delegated-key
/// rotation thread. A single owner drives the rotor OFF the per-core serving runtimes,
/// so the root issuer's blocking KMS/HSM calls never touch the request path. It wakes
/// within the rotation-overlap window before the current key's `exp`, mints a
/// successor, and republishes the hot-path snapshot; the fleet keeps signing off the
/// current key until then (no gap). If issuance fails while the current key is still
/// valid, serving continues until that key expires and THEN fails closed
/// (ADR-MCPRE-052 §6) — never a stale-key extension or a direct-root fallback. The
/// thread observes `shutdown` between naps so it exits promptly on a rolling deploy.
fn spawn_delegated_rotation_task(
    mut rotor: crate::delegated_wiring::ProdDelegatedRotor,
    signer: Arc<crate::delegated_server_signer::DelegatedServerSigner>,
    overlap: i64,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) {
    use crate::delegated_server_signer::rotation_backoff;
    std::thread::spawn(move || {
        // Failures since the last success drive the backoff schedule; 0 in steady state.
        let mut consecutive_failures: u32 = 0;
        loop {
            if shutdown.load(Ordering::SeqCst) {
                return;
            }
            // In steady state, sleep until the overlap window opens (`exp - overlap`) so
            // a successor is minted while the predecessor is still valid. While retrying
            // after a failure we skip this wait and go straight to the backoff-then-retry
            // below. With no current key (startup edge / post-retirement) rotate at once.
            if consecutive_failures == 0 {
                let wake_at = match signer.current(now_unix()) {
                    Some(a) => (a.exp - overlap).max(now_unix()),
                    None => now_unix(),
                };
                while now_unix() < wake_at {
                    if shutdown.load(Ordering::SeqCst) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
            if shutdown.load(Ordering::SeqCst) {
                return;
            }
            match rotor.rotate(now_unix()) {
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
                    if interruptible_sleep(backoff, &shutdown) {
                        return;
                    }
                }
            }
        }
    });
}

/// Sleep `dur` in small increments, returning `true` as soon as `shutdown` is observed
/// (so a rolling deploy is not delayed by a long backoff nap). `false` if the full
/// duration elapsed.
fn interruptible_sleep(dur: Duration, shutdown: &std::sync::atomic::AtomicBool) -> bool {
    let step = Duration::from_millis(50);
    let mut slept = Duration::ZERO;
    while slept < dur {
        if shutdown.load(Ordering::SeqCst) {
            return true;
        }
        std::thread::sleep(step);
        slept += step;
    }
    false
}

/// A fresh random u64 from the OS CSPRNG for backoff jitter. On the (astronomically
/// unlikely) CSPRNG failure, fall back to 0 (no jitter) rather than panicking the
/// rotation thread — the backoff still bounds the retry rate, only its dither is lost.
fn rotation_jitter() -> u64 {
    let mut b = [0u8; 8];
    match getrandom::getrandom(&mut b) {
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
) -> Result<Option<Box<dyn crate::InvalidationChannel + Send + Sync>>, String> {
    match &config.trust_epoch_redis_url {
        Some(url) => {
            let key = config
                .trust_epoch_key
                .as_deref()
                .unwrap_or(crate::trust_epoch::DEFAULT_TRUST_EPOCH_KEY);
            let source = crate::trust_epoch::redis_trust_epoch_source(url, key)
                .map_err(|e| format!("trust-epoch source: {e}"))?;
            eprintln!(
                "mcp-re-proxy: revocation-tier PUSH: networked trust-epoch source ACTIVE (redis, \
                 epoch key {key:?}); the trust cache flushes on an epoch advance and reverts to \
                 the bounded-T guarantee on a read outage."
            );
            Ok(Some(Box::new(source)))
        }
        None => Ok(None),
    }
}

#[cfg(not(feature = "redis_replay"))]
fn build_trust_epoch_channel(
    config: &cli::Config,
) -> Result<Option<Box<dyn crate::InvalidationChannel + Send + Sync>>, String> {
    if config.trust_epoch_redis_url.is_some() {
        return Err(
            "--trust-epoch-redis-url requires a build with the `redis_replay` feature".to_string(),
        );
    }
    Ok(None)
}
