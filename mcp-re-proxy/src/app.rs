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

use crate::async_serve::ServedHttpRequest;
use crate::cli;
use crate::cli::BindingKind;
use crate::cli::KeySourceKind;
use crate::client_revocation;
use crate::config_snapshot;
use crate::http_inner::HttpInnerPool;
use crate::tls;
use crate::transport::ExactMatchBinding;
use crate::transport::TransportBindingPolicy;
use crate::HttpProfileProxy;
use crate::IdentityStrategy;
use crate::ReverseProxyMtlsProvider;
use crate::ServerOptions;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::ResolverOutcome;
use mcp_re_http_profile::SignerSlot;

pub(crate) fn now_unix() -> i64 {
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
    // Trust (ADR-MCPRE-056 §8). The plane owns the store, the freshness flag and the
    // workers that refresh them; what comes back is two narrow live handles.
    //
    // `response_kid` names the root issuer the delegated credential chains to
    // (ADR-MCPRE-052). Derived once, in the plan, and handed to BOTH planes: trust must
    // not enroll it as a request signer, and signing mints under it. Two derivations
    // could disagree about which key that is.
    let response_kid = crate::startup_plan::response_issuer_kid(config);
    let trust =
        crate::trust_plane::TrustPlane::materialize(config, &response_kid, Arc::clone(&shutdown))?;
    let resolver = trust.resolver();
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
        trust.signers(),
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
    let mut transport_binding: Option<Box<dyn TransportBindingPolicy + Send + Sync>> = None;
    // ADR-MCPRE-051 §4: the AUTHORITATIVE async replay tier. The atomic
    // insert-if-absent is AWAITED on the per-core request path without blocking a
    // runtime worker. Shared selects a durable networked store — etcd (CP/linearizable)
    // or redis (horizontally scaled) — both fail closed on any store error (an outage is
    // never a fresh nonce).
    //
    // Which tier this deployment asked for is decided PURELY, from configuration alone;
    // `replay_plane` only establishes it. Every refusal the plan can raise is a statement
    // about the config; every refusal materialization raises is a statement about the
    // build or the environment.
    let replay_plan = crate::startup_plan::ReplayPlan::from_config(config)?;
    // ONE process-lifetime control runtime for every networked control-plane client:
    // the redis replay ConnectionManager's reconnect task, the admission source and the
    // MRTR continuation store. Distinct from the per-core serving runtimes and held
    // alive for the whole serve.
    //
    // Whether it exists is decided by the PLANS, aggregated across every capability that
    // can need one — not by whichever seam reaches for it first. Deriving it from replay
    // once made admission unimplementable on the CP/linearizable tier.
    let control_rt = crate::control_runtime::ControlRuntime::start(
        crate::startup_plan::control_runtime_requirement(config, &replay_plan),
    )?;
    // The redis store's reconnect machinery binds to the runtime it is CREATED in, so the
    // substrate must outlive every USE of the tier — discharged by draining the fleet
    // before anything is reclaimed, not by drop order. See `replay_plane`.
    let crate::replay_plane::MaterializedReplay {
        tier: replay_async,
        dispatch: dispatch_cfg,
    } = crate::replay_plane::materialize(&replay_plan, config.max_clock_skew, control_rt.as_ref())?;
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
        let trust_bound = crate::trust_plane::fleet_trust_bound(
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

    // Response-signing custody (ADR-MCPRE-056 §8; ADR-MCPRE-052). The plane owns the
    // root issuer, the delegated snapshot and the worker that maintains it; what comes
    // back is the signer alone. `key_source` is MOVED in here — it was only borrowed
    // above, for TLS material and the response public key.
    //
    // The plane must outlive the proxy that signs with it, and it does: both are locals
    // of this function, and `serve_fleet` returns before either is dropped.
    let signing = crate::signing_plane::SigningPlane::materialize(
        config,
        key_source,
        &response_kid,
        startup_now_unix,
        Arc::clone(&shutdown),
    )?;
    // ADR-MCPRE-050 + §5: assemble the RFC 9421 serving PEP with the async inner plane,
    // the authoritative replay tier, and the optional Mode-A channel binding.
    // Response-signature validity window: 300s.
    let mut proxy = HttpProfileProxy::new_delegated(
        resolve_actor,
        expected_audience,
        replay_async,
        dispatch_cfg,
        Box::new(pool),
        300,
        signing.signer(),
    );
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
    // opened on one replica is honoured on any other. Connected on the shared control
    // runtime (held alive for the whole serve). Present only when a shared redis URL
    // exists.
    //
    // ABSENCE IS ANNOUNCED HERE, WHILE ADMISSION BELOW REFUSES TO START. The two look
    // inconsistent until the difference is named: admission is an EXPLICITLY REQUESTED
    // capability, so a build that cannot provide it must fail closed rather than serve a
    // proxy that quietly does not enforce it. Cross-replica MRTR is OPPORTUNISTIC — no
    // flag asks for it; it appears when a shared Redis happens to be configured. Refusing
    // startup for its absence would make every single-store deployment unstartable, and
    // it is safe not to, because the dependent leg fails closed on its own: an answer
    // without a correlated continuation is rejected at the binding
    // (`mcp-re.continuation_binding_failed`), not admitted unbound.
    //
    // The rule, for the next capability that has to choose: explicitly requested and
    // unavailable => refuse startup; opportunistic and unavailable => announce the
    // absence, and verify the dependent leg still fails closed without it.
    #[cfg(feature = "redis_replay")]
    if let Some(url) = config.replay_redis_url.as_ref() {
        let rt = control_rt
            .as_ref()
            .expect("the plan declared the continuation store needs the control runtime")
            .handle();
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
        let rt = control_rt
            .as_ref()
            .expect("the plan declared the admission source needs the control runtime")
            .handle();
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
///
/// # Drain before reclaim
///
/// `fleet.shutdown_and_join()` returns before any drop here runs, so no request can be
/// using the replay tier or the continuation store when the control runtime goes. THAT is
/// what makes the teardown safe — not the order in which `proxy` and `_control_rt` are
/// dropped, which is currently a consequence of parameter declaration order and would be
/// a fragile thing to depend on. A later owner holding both in one struct inherits the
/// same obligation: drain, then reclaim.
fn serve_fleet(
    proxy: HttpProfileProxy,
    config_snapshot: Arc<config_snapshot::ServerConfigSnapshot>,
    serve_options: crate::ServerOptions,
    config: &cli::Config,
    _control_rt: Option<crate::control_runtime::ControlRuntime>,
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
