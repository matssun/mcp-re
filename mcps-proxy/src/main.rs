//! The production `mcps-proxy` CLI (MCPS-029, ADR-MCPS-014; folds in MCPS-018).
//!
//! Terminates TLS, verifies the mTLS client certificate, verifies the MCP-S
//! object signature, optionally evaluates authorization (Phase 5) and transport
//! binding (Phase 6), then forwards verified requests to an inner MCP server
//! subprocess and signs the response. Blocking single-threaded serve loop (no
//! async). All wiring/parsing logic lives in `cli` (and is unit-tested there);
//! this shell parses, builds, and runs.

use std::io;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use mcps_policy::InMemoryRevocationSource;
use mcps_policy::PolicyEvaluator;
use mcps_policy::ReferenceProfile;
use mcps_policy::REFERENCE_PROFILE_ID;
use mcps_proxy::cli;
use mcps_proxy::cli::AuthzKind;
use mcps_proxy::cli::BindingKind;
use mcps_proxy::cli::InnerModeKind;
use mcps_proxy::cli::KeySourceKind;
use mcps_proxy::cli::ReplayKind;
use mcps_proxy::tls;
use mcps_proxy::transport::ExactMatchBinding;
use mcps_proxy::DurableReplayCache;
use mcps_proxy::IdentityPolicy;
use mcps_proxy::ReplayDurabilityTier;
use mcps_proxy::IdentityStrategy;
use mcps_proxy::InnerServer;
use mcps_proxy::PersistentSubprocessInner;
use mcps_proxy::Proxy;
use mcps_proxy::RevocationTier;
use mcps_proxy::ReverseProxyMtlsProvider;
use mcps_proxy::ServerOptions;

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
fn trust_clock() -> mcps_proxy::trust_cache::UnixClock {
    mcps_proxy::trust_cache::system_clock()
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
                "mcps-proxy: WARNING: key file {path} is group/world-accessible (mode {:o}); \
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
            "mcps-proxy: WARNING: the system clock reads at/near the Unix epoch ({} < {}s); this \
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
            "mcps-proxy: WARNING: --transport-identity-source cn_legacy is deprecated; \
             prefer uri_san or dns_san"
        );
    }
    if config.key_source == KeySourceKind::Env {
        eprintln!(
            "mcps-proxy: WARNING: --key-source env is dev/CI-only; env key material is visible \
             to the process tree. Use --key-source file in production."
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
            "mcps-proxy: WARNING: --fleet was given WITHOUT --strict; the horizontally-scaled \
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
            "mcps-proxy: WARNING: reverse-proxy identity mode is ENABLED (reading the trusted \
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
            "mcps-proxy: WARNING: client-certificate lifetime enforcement is DISABLED; with no \
             online revocation a compromised client cert is usable until expiry. Set \
             --max-client-cert-lifetime (default 1h)."
        ),
        // ADR-MCPS-023 §A1 (v0.9, MCPS-57): under --strict a lifetime above the 1h
        // ceiling is REJECTED at parse time (see `cli::strict_violations`), so this
        // arm is reached only in non-strict mode. There it stays a warning: the cert
        // is still enforced, but is too long-lived to be audited as
        // `short_lived_cert`. (Supersedes the earlier MCPS-3842 warning-only stance.)
        Some(d) if d.as_secs() > 3600 => eprintln!(
            "mcps-proxy: WARNING: --max-client-cert-lifetime {}s exceeds the 1h ceiling for the \
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
        "mcps-proxy: {}",
        config.revocation_tier.startup_audit_line("trust-store")
    );
    // MCPS-83 (ADR-MCPS-049 clause 2): surface the declared inner-session posture so
    // the routing consequence is auditable at startup. Verification is unaffected;
    // this only tells an operator/LB whether sticky routing is required.
    eprintln!(
        "mcps-proxy: {}",
        config.inner_session.startup_audit_line()
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
                "mcps-proxy: NOTE: revocation-tier PUSH has no networked event source (no \
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

    // Inner-server environment minimization (MCPS-035, ADR-MCPS-016). By default
    // the child environment is cleared and only the explicit allowlist is passed,
    // closing the full-inheritance leak (env-loaded key material is not visible to
    // the inner server unless explicitly allowlisted). Full inheritance is opt-in
    // and loudly warned.
    if config.inner_launch.inherit_env {
        eprintln!(
            "mcps-proxy: WARNING: --inherit-env true passes the proxy's ENTIRE environment to the \
             inner server, including any env-loaded key material (e.g. an env-backed KeySource). \
             This re-opens the full-inheritance leak; prefer --inherit-env false (default) with \
             explicit --inner-env / --inner-env-allow."
        );
    }

    // Inner-server working-dir + output hygiene (MCPS-036, ADR-MCPS-016). The
    // inner server launches in a CONTROLLED working directory (the explicit
    // --inner-working-dir, else the system temp dir — never silently the proxy's
    // cwd). This is a controlled STARTING directory, NOT a filesystem sandbox:
    // the inner server can still chdir and open any path its OS credentials
    // allow. Its stderr is captured separately into a bounded log; bounded is not
    // secrets-safe.
    eprintln!(
        "mcps-proxy: inner working dir = {} (controlled start dir, NOT a filesystem sandbox); \
         inner stderr captured to a bounded log ({} bytes / {} lines), never forwarded as MCP content; \
         inner stdout per-read timeout = {:?} (always bounded, no disable — never-hang posture)",
        config.inner_launch.effective_working_dir(),
        config.inner_launch.stderr_cap_bytes,
        config.inner_launch.stderr_cap_lines,
        config.inner_launch.inner_read_timeout,
    );

    // Inner-server resource hardening (MCPS-037, ADR-MCPS-016). Unix `setrlimit`
    // ceilings applied to the inner subprocess before exec. This is RESOURCE
    // HARDENING, NOT SANDBOXING: it bounds resource abuse (fds, CPU, memory,
    // core/file size), not access — the inner server can still reach any file or
    // socket its OS credentials permit. A configured limit is never silently
    // dropped: on Unix a setrlimit the kernel refuses fails the spawn; on a
    // non-Unix platform a configured limit is a hard startup error unless
    // best-effort is opted in.
    {
        let r = &config.inner_launch.rlimits;
        if r.any_configured() {
            eprintln!(
                "mcps-proxy: inner resource limits (RESOURCE HARDENING, NOT a sandbox): \
                 nofile={:?} cpu_s={:?} as_bytes={:?} data_bytes={:?} core_bytes={:?} \
                 fsize_bytes={:?} best_effort={}",
                r.nofile, r.cpu_seconds, r.address_space_bytes, r.data_bytes, r.core_bytes,
                r.fsize_bytes, r.best_effort,
            );
        }
        if r.best_effort && r.any_configured() {
            eprintln!(
                "mcps-proxy: WARNING: --inner-rlimit-best-effort true — a resource limit that \
                 cannot be applied will be downgraded to a logged no-op instead of failing \
                 closed. Prefer the default strict posture in production."
            );
        }
    }

    // Inner-server OS sandbox profile (#3865, ADR-MCPS-016). This is the PROFILE +
    // fail-closed platform gate, NOT enforcement. With --inner-sandbox off
    // (default) there is NO fs/network containment: the inner server can still
    // reach any file or socket its OS credentials permit — the working-dir /
    // rlimit hardening above is not a sandbox. With --inner-sandbox enforce the
    // proxy REFUSES to start unless a kernel backend (Linux Landlock/seccomp) can
    // actually enforce containment; no such backend ships in this build yet, so
    // enforce currently fails closed on every platform (the inner server is never
    // spawned unsandboxed while having been asked to sandbox it). The gate fires
    // inside SubprocessInner / PersistentSubprocessInner construction below.
    {
        let s = &config.inner_launch.sandbox;
        if s.is_enforced() {
            eprintln!(
                "mcps-proxy: inner sandbox = ENFORCE requested (fs read-allow={:?}, \
                 fs write-allow={:?}, net={:?}); kernel enforcement backend is a follow-up and \
                 ships on no platform yet, so startup will FAIL CLOSED (see #3865).",
                s.fs_allow_read, s.fs_allow_write, s.network,
            );
        } else {
            eprintln!(
                "mcps-proxy: inner sandbox = off (NO fs/network containment; the inner server can \
                 still reach any file or socket its OS credentials permit — this is not a sandbox)"
            );
        }
    }

    // Build the proxy (PEP).
    let log_sink: Arc<dyn mcps_proxy::InnerLogSink + Send + Sync> =
        Arc::new(mcps_proxy::StderrLogSink);
    // Select the inner-server process model (MCPS-066). One-shot (default) spawns
    // the inner command per request; persistent spawns it ONCE, performs the MCP
    // initialize handshake, and forwards many requests over the same long-lived
    // process — the only way to front a genuinely long-lived MCP server.
    let inner: Box<dyn InnerServer> = match config.inner_mode {
        InnerModeKind::OneShot => Box::new(cli::SubprocessInner::with_log_sink(
            &config.inner_command,
            config.inner_launch.clone(),
            Arc::clone(&log_sink),
        )?),
        InnerModeKind::Persistent => {
            eprintln!(
                "mcps-proxy: inner process model = persistent (spawn-once + initialize handshake; \
                 long-lived inner serves many requests over one process)"
            );
            Box::new(PersistentSubprocessInner::with_log_sink(
                &config.inner_command,
                config.inner_launch.clone(),
                Arc::clone(&log_sink),
            )?)
        }
    };
    let mut proxy = Proxy::new(
        key_source,
        config.server_signer.clone(),
        config.server_key_id.clone(),
        resolver,
        config.audience.clone(),
        config.max_clock_skew,
        inner,
    )
    .with_expected_version_policy(config.expected_version_policy)
    .with_log_sink(Arc::clone(&log_sink));
    if config.replay == ReplayKind::File {
        let path = config
            .replay_path
            .clone()
            .ok_or("--replay-cache file requires --replay-path")?;
        let cache = DurableReplayCache::open(&path, config.max_clock_skew)
            .map_err(|e| format!("replay cache {path}: {e}"))?;
        proxy = proxy.with_replay_cache(Box::new(cache));
    }
    if config.replay == ReplayKind::Shared {
        // Issue #3837 / #69: shared, server-side-atomic cache for horizontally-
        // scaled replay safety. The DECLARED durability tier selects the backend
        // (ADR-MCPS-020): LINEARIZABLE → the CP / etcd store (issue #69),
        // every other tier → the Redis store (issue #4028). Either backend FAILS
        // CLOSED if its adapter feature is not compiled in this build, never
        // silently degrading to a non-shared / weaker cache.
        let tier = config
            .replay_durability_tier
            .as_ref()
            .ok_or("--replay-cache shared requires --replay-durability-tier")?;
        let cache = if matches!(tier, ReplayDurabilityTier::Linearizable) {
            // CP / LINEARIZABLE: etcd endpoint required (parse_args already
            // enforced its presence for this tier — fail closed otherwise).
            let endpoint = config
                .cpstore_etcd_endpoint
                .clone()
                .ok_or("--replay-durability-tier linearizable requires --cpstore-etcd-endpoint")?;
            let backend = if cfg!(feature = "cpstore_etcd") {
                "etcd"
            } else {
                "none"
            };
            eprintln!(
                "mcps-proxy: replay cache = shared (CP/linearizable; {backend} backend, issue #69)"
            );
            eprintln!("mcps-proxy: {}", tier.startup_audit_line(backend));
            cli::build_cpstore_replay_cache(
                &endpoint,
                config.max_clock_skew,
                config.limits.read_timeout,
                config.limits.write_timeout,
            )?
        } else {
            // Redis tiers (REDIS_ASYNC / REDIS_WAIT_QUORUM / SINGLE_STORE_FAIL_CLOSED).
            let url = config
                .replay_redis_url
                .clone()
                .ok_or("--replay-cache shared requires --replay-redis-url")?;
            let backend = if cfg!(feature = "redis_replay") {
                "redis"
            } else {
                "none"
            };
            eprintln!(
                "mcps-proxy: replay cache = shared (horizontally-scaled replay safety; \
                 Redis backend, issue #4028)"
            );
            eprintln!("mcps-proxy: {}", tier.startup_audit_line(backend));
            cli::build_shared_replay_cache(
                &url,
                config.max_clock_skew,
                config.limits.read_timeout,
                config.limits.write_timeout,
                tier,
            )?
        };
        proxy = proxy.with_replay_cache(cache);
    }
    // #78 (ADR-MCPS-020), OBJECT-LEVEL defense in depth beneath the CLI-flag gate:
    // the CLI's strict_violations rejects the `--replay-cache memory` SELECTION,
    // but the proxy's replay cache is a `Box<dyn ReplayCache>` that can also be
    // INJECTED (`with_replay_cache`). Assert the cache the proxy actually holds
    // self-declares a durable posture under strict/production, so a volatile
    // single-process reference cache can never reach a production verify path even
    // if it arrived by injection rather than the default selection. mcps-core's
    // `durability_class()` defaults (fail closed) to the single-process reference,
    // so an undeclared cache is rejected here too.
    if config.strict
        && proxy.replay_durability_class()
            == mcps_core::ReplayDurabilityClass::SingleProcessReference
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
            "mcps-proxy: authorization = ENABLED, active profile '{}' (ACKNOWLEDGED non-production \
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
                "mcps-proxy: WARNING: policy revocation deny-list is EMPTY \
                 (--allow-empty-revocation) — no authorization grant can be revoked this run"
            );
        } else {
            eprintln!(
                "mcps-proxy: policy revocation enabled — {revoked_count} revoked grant id(s) \
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
            "mcps-proxy: transport binding = LB-signed request-bound ingress assertion \
             ({} trusted LB key(s), guarantee '{}', identity field {:?}, header '{}'). This is \
             request-bound INGRESS assertion, NOT end-to-end client-node mTLS: the LB terminates \
             the client's mTLS and re-asserts identity; the node verifies the LB signature + the \
             request-hash binding, not the client's own key.",
            config.ingress_lb_keys.len(),
            mcps_proxy::LbAssertionBinding::GUARANTEE,
            config.identity_source,
            tls::MCP_INGRESS_ASSERTION_HEADER,
        );
        proxy = proxy
            .with_transport_binding(Box::new(ExactMatchBinding::new()))
            .with_lb_assertion(lb_assertion);
    }
    // ADR-MCPS-023 §C (v0.10) Mode C: attested ingress. A controlled ingress
    // attestor signs a request-bound `mcps/lb-ingress-assertion/v2` assertion the
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
            "mcps-proxy: transport binding = attested ingress (Mode C) \
             ({} trusted attestor key(s), {} trusted ingress identity(ies), guarantee '{}', \
             audience '{audience}', identity field {:?}, header '{}'). This is ATTESTED \
             DELEGATION, NOT end-to-end client-node mTLS: the load balancer witnesses \
             proof-of-possession and stays in the trusted computing base; the node verifies \
             the attestor signature + the request-hash binding over the pinned attestor-node \
             channel, not the client's own key.",
            config.ingress_attestor_keys.len(),
            config.ingress_identities.len(),
            mcps_proxy::LbAssertionV2Binding::GUARANTEE,
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
            "mcps.ingress.posture binding=attested_ingress \
             delegated_client_identity=per_request_asserted \
             ingress_internal_hop=lb_to_attestor_trusted_pop_stays_with_lb \
             backend_channel_binding=pinned_mtls trusted_ingress_identities={}",
            config.ingress_identities.len(),
        );
        // ADR-MCPS-023 §A1 revocation vocabulary: Mode C delivers dynamic mid-life
        // revocation via the attestor's CRL (keyed on the client cert serial); the
        // node treats the attestor's revocation_result as an opaque asserted fact.
        eprintln!(
            "mcps.revocation.posture revocation_mode=delegated_attestor_crl \
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
            "mcps-proxy: offline client-cert revocation enabled — {} CRL file(s), unknown status \
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
                    "mcps-proxy: WARNING: client CRL #{i} is near expiry (nextUpdate={next_update_unix}); \
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
                    eprintln!("mcps-proxy: WARNING: {msg}");
                }
            }
        }
    } else if config.crl_allow_unknown_status {
        eprintln!(
            "mcps-proxy: WARNING: --crl-allow-unknown-status has no effect without --client-crl"
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
                "mcps.revocation.posture revocation_mode=short_lived_cert dynamic_revocation=false \
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
                    "mcps.revocation.posture revocation_mode=static_crl_snapshot \
                     dynamic_revocation=false stale_crl_policy=fail_closed crl_index={i} \
                     crl_digest={} crl_this_update={} crl_next_update={} \
                     exposure_window={exposure_window}",
                    posture.crl_digest, posture.this_update_unix, next_update
                );
            }
        }
    }

    // TLS server. ADR-MCPS-028 §G / issue #58: on the delegated path rustls drives
    // the handshake signature through the device/KMS signer (TLS private key never
    // exported); the validated builder fails closed at construction if the leaf cert
    // is not Ed25519 or its key does not match the signer. Otherwise the exported-key
    // path is used verbatim.
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
    let server_config = Arc::new(server_config);
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
            "mcps-proxy: ONLINE OCSP client-cert revocation enabled (SHA-256 CertIDs; \
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
    let listener = std::net::TcpListener::bind(&config.bind)
        .map_err(|e| format!("bind {}: {e}", config.bind))?;
    // Report the OS-RESOLVED address, not the requested one: when `--bind` asks
    // for port 0 the kernel assigns an ephemeral port, and a caller (e.g. a test
    // harness) that lets the proxy pick the port avoids the bind-after-free-port
    // TOCTOU race. For a fixed `--bind` port this prints the same address.
    let local_addr = listener
        .local_addr()
        .map_err(|e| format!("local_addr after bind {}: {e}", config.bind))?;
    eprintln!("mcps-proxy: listening on {} (PEP; inner = {:?})", local_addr, config.inner_command);

    // MCPS-88 (ADR-MCPS-049 W3): graceful shutdown for fleet rollouts. Install the
    // SIGTERM/SIGINT handler and make the listener non-blocking so the loop polls
    // between connections and observes a shutdown signal within
    // `SHUTDOWN_POLL_INTERVAL` even when idle. `serve_once_with_assertion` forces
    // each ACCEPTED connection socket back to blocking, so the per-connection read/
    // response phase is unchanged.
    install_shutdown_handlers();
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("set_nonblocking on listener {}: {e}", config.bind))?;

    // Single-threaded serve loop: the Proxy's replay cache is single-threaded
    // interior state, so connections are handled one at a time. Runs until a
    // shutdown signal is observed, then returns for a clean (exit 0) drain.
    while !SHUTDOWN.load(Ordering::SeqCst) {
        let config_arc = Arc::clone(&server_config);
        match tls::serve_once_with_assertion(
            &listener,
            config_arc,
            &serve_options,
            |request, identity, assertion| {
                proxy.handle_with_transport(request, now_unix(), identity.as_ref(), assertion)
            },
        ) {
            Ok(_) => {}
            // No connection is pending on the non-blocking listener: nap briefly so
            // a shutdown signal is observed promptly, then re-check the loop guard.
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(SHUTDOWN_POLL_INTERVAL);
            }
            // A single rejected/aborted connection (e.g. failed mTLS) must not
            // bring the server down — log and keep serving.
            Err(e) => eprintln!("mcps-proxy: connection error: {e}"),
        }
    }
    // Reached only via SIGTERM/SIGINT. Any in-flight request already completed
    // above (inline, on this thread); dropping `proxy` here tears down a persistent
    // inner child. Exit 0 so an orchestrator reads the rollout as a clean stop.
    eprintln!("mcps-proxy: shutdown signal received; stopped accepting, drained, exiting cleanly");
    Ok(())
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
) -> Result<Option<Box<dyn mcps_proxy::InvalidationChannel + Send + Sync>>, String> {
    match &config.trust_epoch_redis_url {
        Some(url) => {
            let key = config
                .trust_epoch_key
                .as_deref()
                .unwrap_or(mcps_proxy::trust_epoch::DEFAULT_TRUST_EPOCH_KEY);
            let source = mcps_proxy::trust_epoch::redis_trust_epoch_source(url, key)
                .map_err(|e| format!("trust-epoch source: {e}"))?;
            eprintln!(
                "mcps-proxy: revocation-tier PUSH: networked trust-epoch source ACTIVE (redis, \
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
) -> Result<Option<Box<dyn mcps_proxy::InvalidationChannel + Send + Sync>>, String> {
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
            eprintln!("mcps-proxy: {e}");
            ExitCode::FAILURE
        }
    }
}
