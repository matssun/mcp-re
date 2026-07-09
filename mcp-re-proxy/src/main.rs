//! The production `mcp-re-proxy` CLI (MCPS-029, ADR-MCPS-014; folds in MCPS-018).
//!
//! Terminates TLS, verifies the mTLS client certificate, verifies the MCP-RE
//! object signature, optionally evaluates authorization (Phase 5) and transport
//! binding (Phase 6), then forwards verified requests to a stateless HTTP inner
//! MCP backend and signs the response. Serves on the per-core async fleet
//! (ADR-MCPRE-051 §1: SO_REUSEPORT + one tokio runtime per core); the authoritative
//! replay tier and the inner round-trip are AWAITED, never blocking a worker. All
//! wiring/parsing logic lives in `cli` (and is unit-tested there); this shell
//! parses, builds, and runs.

use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use mcp_re_policy::InMemoryRevocationSource;
use mcp_re_policy::PolicyEvaluator;
use mcp_re_policy::ReferenceProfile;
use mcp_re_policy::REFERENCE_PROFILE_ID;
use mcp_re_proxy::config_snapshot;
use mcp_re_proxy::cli;
use mcp_re_proxy::cli::AuthzKind;
use mcp_re_proxy::cli::BindingKind;
use mcp_re_proxy::cli::KeySourceKind;
use mcp_re_proxy::cli::ReplayKind;
use mcp_re_proxy::http_inner::HttpInnerPool;
use mcp_re_proxy::tls;
use mcp_re_proxy::transport::ExactMatchBinding;
use mcp_re_proxy::IdentityPolicy;
use mcp_re_proxy::ReplayDurabilityTier;
use mcp_re_proxy::IdentityStrategy;
use mcp_re_proxy::Proxy;
use mcp_re_proxy::RevocationTier;
use mcp_re_proxy::ReverseProxyMtlsProvider;
use mcp_re_proxy::ServerOptions;

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
fn trust_clock() -> mcp_re_proxy::trust_cache::UnixClock {
    mcp_re_proxy::trust_cache::system_clock()
}

/// Enforce the key-file-permission posture for a sensitive key file. In the
/// default (warn-only) posture a group/world-accessible key file produces a
/// WARNING; under `--strict`/`--production` (MCPS-3842, "reject, not warn") the
/// same condition is a HARD error returned to the caller so startup refuses. The
/// warn-vs-reject decision uses the pure [`cli::key_file_mode_is_insecure`]
/// predicate so it stays consistent with (and testable alongside) the
/// parse-time strict checks.
#[cfg(unix)]
fn check_key_file_perms(path: &str, strict: bool) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mode = meta.permissions().mode();
        if cli::key_file_mode_is_insecure(mode) {
            if strict {
                return Err(format!(
                    "--strict/--production refuses unsafe configuration:\n  - key file {path} \
                     is group/world-accessible (mode {:o}); restrict to 0600",
                    mode & 0o777
                ));
            }
            eprintln!(
                "mcp-re-proxy: WARNING: key file {path} is group/world-accessible (mode {:o}); \
                 restrict to 0600",
                mode & 0o777
            );
        }
    }
    Ok(())
}
#[cfg(not(unix))]
fn check_key_file_perms(_path: &str, _strict: bool) -> Result<(), String> {
    Ok(())
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let config = cli::parse_args(&args)?;

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

    // Security posture warnings (config already enforced the hard guards).
    if config.identity_source == IdentityPolicy::CnLegacy {
        eprintln!(
            "mcp-re-proxy: WARNING: --transport-identity-source cn_legacy is deprecated; \
             prefer uri_san or dns_san"
        );
    }
    if config.key_source == KeySourceKind::Env {
        eprintln!(
            "mcp-re-proxy: WARNING: --key-source env is dev/CI-only; env key material is visible \
             to the process tree. Use --key-source file in production."
        );
    }
    // Audit LOW (ledger `4307bd95f2296d67`): the default in-memory replay cache is
    // volatile — admitted nonces are lost on restart, reopening a replay window for
    // the freshness interval across a bounce. `--strict` REJECTS it outright (below);
    // a NON-strict operator otherwise gets no signal, so warn unconditionally here,
    // mirroring the other non-strict posture warnings. (The `--fleet` warning below
    // covers the orthogonal cross-verifier concern.)
    if config.replay == ReplayKind::Memory && !config.strict {
        eprintln!(
            "mcp-re-proxy: WARNING: --replay-cache memory is volatile (single-process reference): \
             admitted nonces are held only in memory, so a restart reopens a replay window for \
             the freshness interval. Use --replay-cache file (single-node durable) or \
             --replay-cache shared (fleet) in production; --strict refuses this cache."
        );
    }
    // MCPS-79 (ADR-MCPS-049): `--fleet` declares horizontally-scaled topology but
    // is orthogonal to the security posture. The node-local-replay REJECTION is a
    // hard guard only under `--strict --fleet` (see `cli::strict_violations`);
    // `--fleet` alone cannot fail closed without also asserting `--strict`. Warn
    // so the operator does not mistake `--fleet` alone for the production
    // guarantee, and point specifically at a node-local cache if one is selected.
    if config.fleet && !config.strict {
        let node_local = matches!(config.replay, ReplayKind::Memory | ReplayKind::File);
        eprintln!(
            "mcp-re-proxy: WARNING: --fleet was given WITHOUT --strict; the horizontally-scaled \
             replay guarantee is NOT enforced (node-local replay caches are rejected only under \
             --strict --fleet).{} The production posture for a multi-verifier deployment is \
             --strict --fleet with --replay-cache shared and a quorum durability tier.",
            if node_local {
                format!(
                    " The selected --replay-cache {} is node-local: a request replayed to a peer \
                     verifier during the acceptance window would NOT be detected as a replay.",
                    match config.replay {
                        ReplayKind::Memory => "memory",
                        ReplayKind::File => "file",
                        ReplayKind::Shared => "",
                    }
                )
            } else {
                String::new()
            }
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
        // MCPS-3842: under strict/production a group/world-readable key file is a
        // HARD error (refuse startup), not a warning. The other strict checks are
        // parse-time and already enforced inside `cli::parse_args`; this one is
        // filesystem-dependent so it lives here.
        check_key_file_perms(&config.signing_key_seed, config.strict)?;
        check_key_file_perms(&config.tls_key, config.strict)?;
    }
    match config.max_client_cert_lifetime {
        None => eprintln!(
            "mcp-re-proxy: WARNING: client-certificate lifetime enforcement is DISABLED; with no \
             online revocation a compromised client cert is usable until expiry. Set \
             --max-client-cert-lifetime (default 1h)."
        ),
        // ADR-MCPS-023 §A1 (v0.9, MCPS-57): under --strict a lifetime above the 1h
        // ceiling is REJECTED at parse time (see `cli::strict_violations`), so this
        // arm is reached only in non-strict mode. There it stays a warning: the cert
        // is still enforced, but is too long-lived to be audited as
        // `short_lived_cert`. (Supersedes the earlier MCPS-3842 warning-only stance.)
        Some(d) if d.as_secs() > 3600 => eprintln!(
            "mcp-re-proxy: WARNING: --max-client-cert-lifetime {}s exceeds the 1h ceiling for the \
             short-lived-cert revocation posture; under --strict this is rejected.",
            d.as_secs()
        ),
        Some(_) => {}
    }

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

    // Build the proxy (PEP). The MCPS-036 lifecycle sink receives the proxy-level
    // events (inner_request_forwarded / inner_response_signed) on the async path.
    let log_sink: Arc<dyn mcp_re_proxy::InnerLogSink + Send + Sync> =
        Arc::new(mcp_re_proxy::StderrLogSink);
    let mut proxy = Proxy::new(
        key_source,
        config.server_signer.clone(),
        config.server_key_id.clone(),
        resolver,
        config.audience.clone(),
        config.max_clock_skew,
    )
    .with_expected_version_policy(config.expected_version_policy)
    .with_log_sink(Arc::clone(&log_sink));
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
                        mcp_re_proxy::async_etcd_store::EtcdAsyncAtomicReplayStore::connect(
                            &endpoint,
                        ),
                    );
                    proxy = proxy.with_async_replay_tier(
                        mcp_re_proxy::async_replay::AsyncReplayTier::new(
                            store,
                            config.max_clock_skew,
                        ),
                    );
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
                        rt.block_on(mcp_re_proxy::RedisAsyncAtomicReplayStore::connect(&url))
                            .map_err(|e| format!("connect redis async replay store: {e:?}"))?,
                    );
                    proxy = proxy.with_async_replay_tier(
                        mcp_re_proxy::async_replay::AsyncReplayTier::new(
                            store,
                            config.max_clock_skew,
                        ),
                    );
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
    // the CLI's strict_violations rejects the `--replay-cache memory` SELECTION,
    // but the proxy's replay cache is a `Box<dyn ReplayCache>` that can also be
    // INJECTED (`with_replay_cache`). Assert the cache the proxy actually holds
    // self-declares a durable posture under strict/production, so a volatile
    // single-process reference cache can never reach a production verify path even
    // if it arrived by injection rather than the default selection. mcp-re-core's
    // `durability_class()` defaults (fail closed) to the single-process reference,
    // so an undeclared cache is rejected here too.
    if config.strict
        && proxy.replay_durability_class()
            == mcp_re_core::ReplayDurabilityClass::SingleProcessReference
    {
        return Err(
            "strict/production: the configured replay cache self-declares the volatile \
             single-process reference posture (admitted nonces are lost on restart and \
             invisible to peer verifiers); a durable replay store is required — use \
             --replay-cache file or --replay-cache shared, or inject a cache that declares \
             ReplayDurabilityClass::Durable"
                .into(),
        );
    }
    if config.authz == AuthzKind::Reference {
        let mut evaluator = PolicyEvaluator::new();
        evaluator.register(Box::new(ReferenceProfile::new()));
        // ADR-MCPS-013: surface the ACTIVE authorization profile and its non-production
        // posture at startup so an operator can never silently treat the reference
        // (conformance) profile as the production authority. Reaching here required the
        // explicit `--allow-reference-authz` acknowledgement (parse-time guard) and is
        // refused under --strict/--production.
        eprintln!(
            "mcp-re-proxy: authorization = ENABLED, active profile '{}' (ACKNOWLEDGED non-production \
             via --allow-reference-authz). The reference profile is a real, signature-verifying, \
             fully-bound profile but is a CONFORMANCE/reference implementation, NOT the long-term \
             recommendation (ADR-MCPS-013; Biscuit is the intended production profile). It is \
             refused under --strict/--production.",
            REFERENCE_PROFILE_ID,
        );
        // ADR-MCPS-013 policy-layer revocation. `parse_args` has already failed
        // closed unless a deny-list was supplied or --allow-empty-revocation was
        // EXPLICITLY given, so reaching here with an empty list is an acknowledged
        // posture — surfaced loudly at startup so it can never be a silent illusion.
        let revoked = cli::load_revocation_list(&config.revocation_list_paths)?;
        let revoked_count = revoked.len();
        let mut revocation = InMemoryRevocationSource::new();
        for id in revoked {
            revocation.revoke(id);
        }
        if revoked_count == 0 {
            eprintln!(
                "mcp-re-proxy: WARNING: policy revocation deny-list is EMPTY \
                 (--allow-empty-revocation) — no authorization grant can be revoked this run"
            );
        } else {
            eprintln!(
                "mcp-re-proxy: policy revocation enabled — {revoked_count} revoked grant id(s) \
                 loaded (OFFLINE static list; restart to update)"
            );
        }
        proxy = proxy.with_policy_enforcement(evaluator, Box::new(revocation));
    }
    if config.binding == BindingKind::Exact {
        proxy = proxy.with_transport_binding(Box::new(ExactMatchBinding::new()));
    }
    // ADR-MCPS-023 Tier 3 (issue #71): LB-signed, request-bound ingress assertion.
    // The verified transport identity comes from a cryptographically-verified
    // assertion bound to THIS request's hash (checked post-verification, inside the
    // proxy), then binds to the request signer through the SAME ExactMatchBinding
    // the direct-TLS path uses. `parse_args` already required at least one trusted
    // `--ingress-lb-key`. Honestly downgraded — NOT end_to_end_mtls.
    if config.binding == BindingKind::LbAssertion {
        let lb_assertion = cli::build_lb_assertion_binding(&config)?
            .ok_or("internal error: lb-assertion binding selected but no verifier built")?;
        eprintln!(
            "mcp-re-proxy: transport binding = LB-signed request-bound ingress assertion \
             ({} trusted LB key(s), guarantee '{}', identity field {:?}, header '{}'). This is \
             request-bound INGRESS assertion, NOT end-to-end client-node mTLS: the LB terminates \
             the client's mTLS and re-asserts identity; the node verifies the LB signature + the \
             request-hash binding, not the client's own key.",
            config.ingress_lb_keys.len(),
            mcp_re_proxy::LbAssertionBinding::GUARANTEE,
            config.identity_source,
            tls::MCP_INGRESS_ASSERTION_HEADER,
        );
        proxy = proxy
            .with_transport_binding(Box::new(ExactMatchBinding::new()))
            .with_lb_assertion(lb_assertion);
    }
    // ADR-MCPS-023 §C (v0.10) Mode C: attested ingress. A controlled ingress
    // attestor signs a request-bound `mcp-re/lb-ingress-assertion/v2` assertion the
    // node verifies over the pinned attestor→node channel; the verified delegated
    // client identity binds to the request signer through the SAME ExactMatchBinding
    // the direct-TLS path uses. `parse_args` already required the attestor keys, ≥1
    // ingress identity, the audience, and the `--ingress-pinned-mtls` acknowledgement.
    // Strict-ADMITTED and explicit — but attested delegation, NOT end_to_end_mtls.
    if config.binding == BindingKind::AttestedIngress {
        let attested = cli::build_attested_ingress_binding(&config)?
            .ok_or("internal error: attested-ingress selected but no verifier built")?;
        let audience = config.ingress_audience.as_deref().unwrap_or("<unset>");
        eprintln!(
            "mcp-re-proxy: transport binding = attested ingress (Mode C) \
             ({} trusted attestor key(s), {} trusted ingress identity(ies), guarantee '{}', \
             audience '{audience}', identity field {:?}, header '{}'). This is ATTESTED \
             DELEGATION, NOT end-to-end client-node mTLS: the load balancer witnesses \
             proof-of-possession and stays in the trusted computing base; the node verifies \
             the attestor signature + the request-hash binding over the pinned attestor-node \
             channel, not the client's own key.",
            config.ingress_attestor_keys.len(),
            config.ingress_identities.len(),
            mcp_re_proxy::LbAssertionV2Binding::GUARANTEE,
            config.identity_source,
            tls::MCP_INGRESS_ASSERTION_HEADER,
        );
        // ADR-MCPS-023 §C2: record the THREE trust facts, never fewer, as an
        // operator posture diagnostic (canonical audit field names; the structured
        // per-request surface lands with MCPS-62). `delegated_client_identity` is
        // asserted per request (its value rides the v2 assertion); the other two are
        // configured facts. Emitting all three prevents a later auditor from
        // mistaking Mode C for end-to-end mTLS or for a single-component attestor.
        eprintln!(
            "mcp-re.ingress.posture binding=attested_ingress \
             delegated_client_identity=per_request_asserted \
             ingress_internal_hop=lb_to_attestor_trusted_pop_stays_with_lb \
             backend_channel_binding=pinned_mtls trusted_ingress_identities={}",
            config.ingress_identities.len(),
        );
        // ADR-MCPS-023 §A1 revocation vocabulary: Mode C delivers dynamic mid-life
        // revocation via the attestor's CRL (keyed on the client cert serial); the
        // node treats the attestor's revocation_result as an opaque asserted fact.
        eprintln!(
            "mcp-re.revocation.posture revocation_mode=delegated_attestor_crl \
             dynamic_revocation=true"
        );
        proxy = proxy
            .with_transport_binding(Box::new(ExactMatchBinding::new()))
            .with_attested_ingress(attested);
    }

    // Offline client-cert CRLs (#3839). Loaded once at startup; a missing or
    // malformed CRL file fails closed here. OFFLINE revocation only — there is no
    // online OCSP / distribution-point fetching (deferred to a follow-up).
    let client_crls = cli::load_client_crls(&config.client_crl_paths)?;
    if !client_crls.is_empty() {
        eprintln!(
            "mcp-re-proxy: offline client-cert revocation enabled — {} CRL file(s), unknown status \
             {} (OFFLINE only; no online OCSP/CRL-DP fetching)",
            config.client_crl_paths.len(),
            if config.crl_allow_unknown_status { "ALLOWED (relaxed)" } else { "DENIED (fail closed)" },
        );
        // ADR-MCPS-023 §A1 (MCPS-58): the verifier now enforces CRL nextUpdate, so
        // a stale CRL fails every new handshake closed. Surface that at BOOT — under
        // strict refuse to start; otherwise warn loudly — and warn while a CRL is
        // near expiry so a refreshed CRL can be installed before the cutover
        // ("restart before nextUpdate"; the in-process hot-reloader is a v0.10
        // follow-up). A malformed CRL is a hard startup error (fail closed).
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
                    if config.strict {
                        return Err(format!(
                            "--strict/--production refuses to start with a stale client CRL: {msg}"
                        ));
                    }
                    eprintln!("mcp-re-proxy: WARNING: {msg}");
                }
            }
        }
    } else if config.crl_allow_unknown_status {
        eprintln!(
            "mcp-re-proxy: WARNING: --crl-allow-unknown-status has no effect without --client-crl"
        );
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
    let reload_allow_unknown = config.crl_allow_unknown_status;

    let server_config = match tls_delegated_signer {
        Some(signer) => tls::build_server_config_delegated_validated(
            server_chain,
            signer,
            client_ca,
            client_crls,
            config.crl_allow_unknown_status,
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
                config.crl_allow_unknown_status,
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
    };

    // ADR-MCPRE-051 §3: the async inner plane — a per-core pooled hyper client to
    // the stateless Streamable-HTTP inner backends. Forwarding is AWAITED, never
    // blocking a per-core runtime worker.
    let inner_timeout = config
        .limits
        .read_timeout
        .unwrap_or_else(|| Duration::from_secs(30));
    let pool = HttpInnerPool::from_url_strs(config.inner_http_urls.clone(), inner_timeout)?;
    let proxy = proxy.with_async_inner(Box::new(pool));

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
    proxy: Proxy,
    config_snapshot: Arc<config_snapshot::ServerConfigSnapshot>,
    serve_options: mcp_re_proxy::ServerOptions,
    config: &cli::Config,
    _replay_control_rt: Option<tokio::runtime::Runtime>,
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

    let fleet_cfg = mcp_re_proxy::async_fleet::FleetConfig {
        addr,
        cores: config.cores, // 0 = auto (one worker per core); --cores pins it
        listen_backlog: mcp_re_proxy::async_fleet::DEFAULT_LISTEN_BACKLOG,
        max_in_flight_total: None,
    };
    let server_config = config_snapshot.load();
    let serve_options = Arc::new(serve_options);
    let shutdown = Arc::new(AtomicBool::new(false));

    // SIGTERM/SIGINT graceful drain, same handler as the sync path.
    install_shutdown_handlers();

    // One handler per core over the SHARED `Proxy` (Send + Sync, MCPRE-111); each
    // request awaits the async replay tier + async HTTP inner without blocking the
    // per-core runtime worker.
    let handler_proxy = Arc::clone(&proxy);
    let make_handler = move |_core: usize| {
        let proxy = Arc::clone(&handler_proxy);
        Arc::new(
            move |body: Vec<u8>,
                  identity: Option<mcp_re_proxy::transport::TransportIdentity>,
                  assertion: Option<String>|
                  -> mcp_re_proxy::async_serve::HandlerResponseFuture {
                let proxy = Arc::clone(&proxy);
                Box::pin(async move {
                    proxy
                        .handle_with_transport_async(
                            &body,
                            now_unix(),
                            identity.as_ref(),
                            assertion.as_deref(),
                        )
                        .await
                })
            },
        )
    };

    let fleet = mcp_re_proxy::async_fleet::serve_fleet(
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

    // Block until a shutdown signal, then drain the fleet (bounded) and exit clean.
    while !SHUTDOWN.load(Ordering::SeqCst) {
        std::thread::sleep(SHUTDOWN_POLL_INTERVAL);
    }
    eprintln!("mcp-re-proxy: shutdown signal received; draining async fleet");
    shutdown.store(true, Ordering::SeqCst);
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
) {
    std::thread::spawn(move || {
        // Nap in small increments so a shutdown signal is observed within one
        // increment rather than after a whole reload interval.
        let ticks = interval_secs.saturating_mul(20); // 20 * 50ms = 1s
        loop {
            for _ in 0..ticks {
                if SHUTDOWN.load(Ordering::SeqCst) {
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

/// MCPS-88 (ADR-MCPS-049 W3): set on SIGTERM/SIGINT so the serve loop stops
/// accepting NEW connections and returns for a clean exit. Graceful drain in the
/// single-threaded inline model is exact: at most one request is ever in flight
/// (on this same thread), and it always runs to completion — bounded by the
/// existing per-request read/response deadlines (`ServerLimits`) — before the loop
/// re-checks this flag. There is therefore no queue to drain and no in-flight
/// request to abandon.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// How long the loop naps between `accept()` polls when no connection is pending,
/// bounding how late a shutdown signal is observed under an idle listener.
const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Async-signal-safe handler: a lone atomic store (on the async-signal-safe list).
extern "C" fn handle_shutdown_signal(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

/// Install the graceful-shutdown handler for SIGTERM (k8s rollout / `docker stop`)
/// and SIGINT (Ctrl-C). Best-effort: a failure to install leaves the previous
/// (default-terminate) disposition, which is still safe — just not graceful.
fn install_shutdown_handlers() {
    // SAFETY: `sigaction` with a zeroed struct and a static `extern "C"` handler
    // that only performs an atomic store. No `SA_RESTART`, so a signal interrupts
    // the poll nap promptly.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handle_shutdown_signal as *const () as libc::sighandler_t;
        libc::sigemptyset(&mut action.sa_mask);
        action.sa_flags = 0;
        libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut());
        libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut());
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
) -> Result<Option<Box<dyn mcp_re_proxy::InvalidationChannel + Send + Sync>>, String> {
    match &config.trust_epoch_redis_url {
        Some(url) => {
            let key = config
                .trust_epoch_key
                .as_deref()
                .unwrap_or(mcp_re_proxy::trust_epoch::DEFAULT_TRUST_EPOCH_KEY);
            let source = mcp_re_proxy::trust_epoch::redis_trust_epoch_source(url, key)
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
) -> Result<Option<Box<dyn mcp_re_proxy::InvalidationChannel + Send + Sync>>, String> {
    if config.trust_epoch_redis_url.is_some() {
        return Err(
            "--trust-epoch-redis-url requires a build with the `redis_replay` feature".to_string(),
        );
    }
    Ok(None)
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mcp-re-proxy: {e}");
            ExitCode::FAILURE
        }
    }
}
