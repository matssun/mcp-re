//! Serve orchestration for the `mcp-re-proxy` binary, in the LIBRARY so it is
//! testable in-process (the binary is a thin shim over [`run`]).
//!
//! The composition root. It establishes the planes that own the runtime's resources
//! (ADR-MCPRE-056 §8), assembles the RFC 9421 serving PEP over them, hands the whole graph
//! to [`crate::materialized_runtime::MaterializedRuntime`], and serves until the caller
//! flips `shutdown`. It decides as little as possible: what it branches on is either a
//! named rule in [`crate::startup_plan`] or a plane's own answer.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use crate::async_serve::ServedHttpRequest;
use crate::cli;
use crate::cli::BindingKind;
use crate::cli::KeySourceKind;
use crate::clock::now_unix;
use crate::config_snapshot;
use crate::config_state::CustodyState;
use crate::config_state::TlsCustodyState;
use crate::http_inner::HttpInnerPool;
use crate::startup_posture::PostureLog;
use crate::startup_posture::Seam;
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

/// Whether a startup clock reading costs more than a warning, and why.
///
/// A faulted clock is tolerable where it only feeds per-request freshness: every request
/// then fails closed, which is safe. It is NOT tolerable where the same reading is the
/// reference time for a BOOT-TIME refusal. `startup_now_unix` is what the TLS plane
/// compares each client CRL's `nextUpdate` against, and nothing is ever `Stale` relative
/// to a clock reading zero — so with CRLs configured the refusal that exists to keep an
/// expired CRL out of the serving path cannot fire, while the revocation-posture transcript
/// still advertises the CRL as enforced.
///
/// Pure, so the decision is assertable without a broken host clock: it takes the reading
/// and how many CRLs the deployment configured, and returns the refusal.
fn faulted_clock_refusal(startup_now_unix: i64, configured_crls: usize) -> Option<String> {
    if configured_crls == 0 || !crate::startup_plan::host_clock_is_faulted(startup_now_unix) {
        return None;
    }
    Some(format!(
        "mcp-re-proxy refuses to start: the system clock reads at/near the Unix epoch \
         ({startup_now_unix} < {}s), so the boot-time client-CRL freshness refusal cannot be \
         performed — every CRL compares as fresh against a zero clock, and the \
         {configured_crls} configured CRL(s) would be advertised as enforced while an \
         arbitrarily expired one was loaded. Fix the host clock (NTP/RTC) before starting.",
        crate::startup_plan::EPOCH_CLOCK_FAULT_THRESHOLD_SECS,
    ))
}

/// Enforce the key-file-permission posture for a sensitive key file. The proxy
/// always runs the maximal-security posture, so a group/world-accessible key file
/// is a HARD error returned to the caller (startup refuses). Uses the pure
/// [`cli::key_file_posture_violation`] predicate so it stays consistent with (and
/// testable alongside) the parse-time checks.
///
/// A `stat` that fails for any reason other than "there is no such file" is itself a
/// refusal. The posture of a file the proxy is about to READ is either established or it
/// is not, and treating an unreadable `stat` as compliance is how a world-readable signing
/// seed on a networked or overlay mount (EIO, ESTALE, EACCES on the directory) boots
/// silently. `NotFound` is the one error that is not a fail-open: there is no file whose
/// permissions could be wrong, the loader resolves the same path a moment later, and it
/// reports the absence with the diagnostic that names what was missing.
#[cfg(unix)]
fn check_key_file_perms(path: &str, allow_group_read: bool) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(format!(
                "mcp-re-proxy refuses unsafe configuration:\n  - key file {path} cannot be \
                 stat'ed ({e}), so its permission posture cannot be established; it is read \
                 by the proxy regardless, and starting would mean serving with a key file \
                 that may be group- or world-readable"
            ))
        }
    };
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
fn key_files_read_from_disk<'a>(
    custody: &'a CustodyState,
    tls_custody: &'a TlsCustodyState,
) -> Vec<&'a str> {
    // Under `EnvSeed` NOTHING is on disk: every locator this deployment carries names an
    // environment variable, including the TLS ones. The old field test compared
    // `key_source == File` for the seed but not for `--tls-key`, so an env-var NAME was
    // stat'ed as a path — harmless only because a missing file passes the check. Phrasing
    // the projection over the state removes the case instead of adding a condition for it.
    let CustodyState::EnvSeed { .. } = custody else {
        let mut paths = Vec::new();
        match custody {
            // The signing seed, where the deployment keeps one on disk.
            CustodyState::FileSeed { seed_path } => paths.push(seed_path.as_str()),
            // The PKCS#11 User PIN file is not a key, but it is the credential that
            // unlocks the token holding the signing and (optionally) TLS keys — so a
            // group/world-readable PIN file is as good as a readable key file, and belongs
            // behind the same floor.
            CustodyState::Pkcs11 { pin_file, .. } => paths.push(pin_file.as_str()),
            // The KMS states keep the signing key in KMS; neither holds a local secret.
            CustodyState::AwsKms { .. } | CustodyState::GcpKms { .. } => {}
            CustodyState::EnvSeed { .. } => unreachable!("the let-else above took this arm"),
        }
        // And the handshake key, only where custody EXPORTS one. Delegated custody keeps
        // it on the device, and X2b has already refused a file copy beside it.
        if let TlsCustodyState::Exported { key_path } = tls_custody {
            paths.push(key_path.as_str());
        }
        return paths;
    };
    Vec::new()
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
    // Whether the audit stream is this process's stderr has to be read BEFORE the config
    // is consumed, and it decides only whether the drain is REPORTED — the drain itself is
    // unconditional, because a sink installed by an embedder past this seam would still
    // have left records in the same global queue.
    let audits_to_stderr = config.audit_sink == crate::cli::AuditSinkKind::Stderr;
    // The drain is placed around the WHOLE of the run rather than after `serve` returns, so
    // that every route out of this function passes through it: a clean drain, a serve that
    // failed, and a startup refused at the boundary. A teardown obligation discharged on
    // one of three exits is the shape the rest of this round keeps finding.
    let outcome = crate::cli::ValidatedConfig::try_from(config)
        .and_then(|validated| run_validated(&validated, shutdown));
    drain_audit_stream(audits_to_stderr);
    outcome
}

/// How long shutdown waits for the audit writer to write out what it was already handed.
///
/// Bounded because the writer owns a file descriptor the proxy does not control: a log
/// collector applying backpressure, a full volume or a stalled pipe reader must cost a
/// bounded shutdown delay and a stated uncertainty, never a process that will not exit.
const AUDIT_FLUSH_TIMEOUT: Duration = Duration::from_secs(2);

/// Discharge the audit writer's teardown obligation, and SAY which of the two things
/// happened.
///
/// [`crate::audit_sink::flush_stderr_audit`] exists because the writer thread is detached
/// and cannot be joined: without this call a process that exits with records still queued
/// loses them, and a shutdown under load loses precisely the decisions taken last.
///
/// The two outcomes are reported as different facts on purpose. "Drained" means every
/// record handed to the writer reached stderr. A timeout does NOT mean records were lost —
/// it means nobody can say either way, because the acknowledgement that would have settled
/// it never came. Collapsing those two into one "shutdown complete" line would destroy
/// exactly the distinction an audit stream exists to preserve, so the timeout line states
/// the uncertainty as uncertainty rather than as either outcome.
///
/// A timeout is deliberately NOT turned into a non-zero result. The serving outcome is
/// what the caller asked about, and reporting a clean shutdown as failed because a log
/// collector was slow would make an observability fault look like a serving fault — the
/// inversion the sink's own "audit must never fail a request" rule rejects on the hot path.
fn drain_audit_stream(report: bool) {
    let drained = crate::audit_sink::flush_stderr_audit(AUDIT_FLUSH_TIMEOUT);
    if let Some(line) = audit_drain_line(drained, report) {
        eprintln!("{line}");
    }
}

/// What shutdown says about the audit drain, or `None` when this deployment does not write
/// its audit stream to stderr and so has nothing to say about it.
///
/// Separated from the drain itself so the one property that matters here — that the two
/// outcomes never read as the same fact — is assertable without stalling a log collector.
fn audit_drain_line(drained: bool, report: bool) -> Option<String> {
    if !report {
        return None;
    }
    Some(if drained {
        "mcp-re-proxy: audit stream drained at shutdown: every record handed to the audit \
         writer reached stderr"
            .to_string()
    } else {
        format!(
            "mcp-re-proxy: WARNING: the audit stream did NOT acknowledge its drain within {}s. \
             This is NOT a report that records were lost and NOT a clean shutdown of the audit \
             stream: whether the decisions recorded last reached stderr is UNKNOWN. Their seq \
             numbers are the gap to look for, and the writer's backing channel (a stalled log \
             collector, a full volume) is what to check.",
            AUDIT_FLUSH_TIMEOUT.as_secs()
        )
    })
}

/// The serving path proper. Reachable only with a [`crate::cli::ValidatedConfig`], which
/// is the whole point: there is no route into it that skips the guards.
// The composition root is long ON PURPOSE (§12): its length is the assembly it performs,
// and shortening it by moving statements into helpers would hide ordering and ownership
// where a reader cannot see them. The allowance is on this function alone rather than on
// the module, so anything else here that grows past the threshold is still reported.
#[allow(clippy::too_many_lines)]
fn run_validated(
    config: &crate::cli::ValidatedConfig,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<(), String> {
    let values = config.config();
    // Clock-fault diagnosis (audit #94 F5). `now_unix()` deliberately maps a
    // pre-epoch SystemTime error to 0 (fail CLOSED — every request then fails its
    // freshness check rather than admitting a stale one), but a clock that reads
    // at/near the Unix epoch would otherwise surface only as an unexplained flood of
    // freshness denials. Emit a ONE-TIME loud startup warning so a broken/unset host
    // clock is diagnosed at the source instead of masked. Where the reading only feeds
    // per-request freshness the posture is already safe, so that case warns rather than
    // refuses and the operator is told why every request will be denied.
    //
    // It is NOT safe where the same reading is the reference time for a BOOT-TIME refusal.
    // `startup_now_unix` is handed to the TLS plane, which refuses to start on a client CRL
    // whose `nextUpdate` has passed — a comparison against a clock reading zero declares
    // every CRL fresh, so the one check that stops an arbitrarily expired CRL from reaching
    // the serving path silently does not fire while the revocation-posture transcript still
    // advertises the CRL as enforced. A fail-closed default cannot be inferred from a
    // fail-closed neighbour: this one is refused.
    //
    // Read the clock ONCE so the comparison, the reported value and every plane handed
    // `startup_now_unix` below agree on one instant. Whether that reading is a FAULT is
    // the plan's rule; reading the clock and deciding what it costs is this function's.
    let startup_now_unix = now_unix();
    if let Some(refusal) = faulted_clock_refusal(startup_now_unix, values.client_crl_paths.len()) {
        return Err(refusal);
    }
    if crate::startup_plan::host_clock_is_faulted(startup_now_unix) {
        eprintln!(
            "mcp-re-proxy: WARNING: the system clock reads at/near the Unix epoch ({} < {}s); this \
             almost certainly means the host clock is unset or broken. Freshness checks will \
             FAIL CLOSED (every request denied) until the clock is corrected — fix the host clock \
             (NTP/RTC) rather than treating the resulting denials as a load problem.",
            startup_now_unix,
            crate::startup_plan::EPOCH_CLOCK_FAULT_THRESHOLD_SECS,
        );
    }

    // Security posture note. The hard guards (cn_legacy, memory/weak replay,
    // over-ceiling/disabled cert lifetime, reverse-proxy ingress, lb-assertion,
    // node-local replay under --fleet) are ALL rejected at parse time by
    // `cli::unsafe_config_violations` — the proxy never reaches here with them. Only
    // the env key source (a dev/CI-only build, `dev_env_key_source`) is worth a
    // runtime note, since that build deliberately permits it.
    if values.key_source == KeySourceKind::Env {
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
    if let Some(header) = &values.reverse_proxy_identity_header {
        eprintln!(
            "mcp-re-proxy: WARNING: reverse-proxy identity mode is ENABLED (reading the trusted \
             header '{header}', format {:?}, identity field {:?}). mTLS is assumed terminated \
             UPSTREAM and the local client certificate is NOT used for identity. You are \
             asserting the listening socket {} is reachable ONLY by the trusted upstream \
             (loopback / private network / its own mTLS link) and that the upstream STRIPS any \
             client-supplied copy of '{header}' before setting its own. If the socket is \
             reachable by untrusted clients, they can SPOOF any identity.",
            values.reverse_proxy_header_format, values.identity_source, values.bind,
        );
    }
    // A group/world-readable key file is a HARD error (refuse startup). The other
    // guards are parse-time and already enforced inside `cli::parse_args`; this one is
    // filesystem-dependent so it lives here.
    for path in key_files_read_from_disk(config.state().custody(), config.state().tls_custody()) {
        check_key_file_perms(path, values.allow_group_readable_key_files)?;
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
    let key_source = cli::build_key_source(
        config.state().custody(),
        config.state().tls_custody(),
        &values.tls_cert,
        &values.client_ca,
    )
    .map_err(|e| e.to_string())?;
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
        Some(signer) => crate::tls_plane::TlsKeyMaterial::Delegated(signer),
        None => crate::tls_plane::TlsKeyMaterial::Exported(
            key_source.tls_server_key().map_err(|e| e.to_string())?,
        ),
    };
    // ADR-MCPRE-056 §9: there is no shared worker set here any more. EVERY long-lived
    // thread startup creates belongs to the plane that owns the resource it maintains, so
    // the ~38 fallible expressions between here and `serve_fleet` each halt and reclaim
    // whatever is already running on their way out — and each plane also gets to say what
    // its own resource means once it stops. None of those expressions says so: that is
    // the point of expressing the lifetime as ownership instead of as cleanup nobody was
    // going to write at 38 return points.
    // Trust (ADR-MCPRE-056 §8). The plane owns the store, the freshness flag and the
    // workers that refresh them; what comes back is two narrow live handles.
    //
    // `response_kid` names the root issuer the delegated credential chains to
    // (ADR-MCPRE-052). Derived once, in the plan, and handed to BOTH planes: trust must
    // not enroll it as a request signer, and signing mints under it. Two derivations
    // could disagree about which key that is.
    let response_kid = crate::startup_plan::response_issuer_kid(config);
    // The shared trust-epoch mechanism, interpreted ONCE and handed to both consumers
    // (CF-09). Trust flushes its cache on an advance; delegated signing mints under the
    // resulting label. Each used to read the configuration for itself.
    let trust_epoch = crate::startup_plan::TrustEpochPlan::from_validated(config);
    let trust_plan =
        crate::startup_plan::TrustPlan::from_validated(config, response_kid.clone(), trust_epoch);
    // Transport custody and the offline client-cert revocation posture, both already
    // classified by layer A (ADR-MCPRE-056 §8).
    let tls_plan = crate::startup_plan::TlsPlan::from_validated(config);
    // Response-signing custody. The SECOND consumer of both shared decisions, and it
    // receives them the same way the first did — from here, not from its sibling.
    let signing_plan = crate::startup_plan::SigningPlan::from_validated(
        config,
        response_kid.clone(),
        trust_plan.epoch.clone(),
    );

    // ADR-MCPRE-057 §3 — the lifecycle becomes a value here.
    //
    // `PlanBuilt` is applied at THIS line because everything above it is pure and the
    // next statement is the first effect this process performs. That boundary is real but
    // not yet tidy: some pure planning (`ReplayPlan::from_config`, the inner-plane
    // ceiling) still runs below, INSIDE `Materializing`. The state machine tolerates it —
    // planning during materialization is untidy, not illegal — and ADR-MCPRE-058 §17A
    // step 5 is where the two stop interleaving. Instrumenting what is here, rather than
    // reordering to make the model look clean, is deliberate: a state machine that
    // required its own preconditions to be manufactured would be describing an
    // architecture that does not exist.
    let mut lifecycle = crate::runtime_state::RuntimeLifecycle::new();
    // Holding a `ValidatedConfig` IS the proof: there is no route to this function that
    // skips the boundary.
    lifecycle.apply(crate::runtime_state::RuntimeEvent::ValidationSucceeded)?;
    lifecycle.apply(crate::runtime_state::RuntimeEvent::PlanBuilt)?;

    // ADR-MCPRE-057 §9 — from here every teardown-bearing resource is owned the moment it
    // is acquired. `begin` applies `MaterializationStarted`, so entering the state and
    // entering the owner are one act; a failure at any `?` below drops the builder, which
    // reclaims what was installed in the documented order instead of unwinding locals in
    // reverse declaration order (F3).
    let mut building = crate::materializing_runtime::MaterializingRuntime::begin(lifecycle)?;

    building.install_trust(crate::trust_plane::TrustPlane::materialize(
        &trust_plan,
        Arc::clone(&shutdown),
    )?);
    let resolver = building.trust().resolver();
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
        trust_domain: values.trust_domain.clone(),
        subject: values.server_signer.clone(),
        keyid: response_kid.clone(),
    };
    let resolve_actor = build_actor_resolver(
        building.trust().signers(),
        Arc::clone(&resolver),
        values.trust_domain.clone(),
        response_kid.clone(),
        server_identity.clone(),
        response_pub,
    );
    let expected_audience = AudienceTuple {
        audience_id: values.audience.clone(),
        target_uri: values.target_uri.clone(),
        route: values.route.clone(),
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
    let replay_plan = crate::startup_plan::ReplayPlan::from_validated(config);
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
    } = crate::replay_plane::materialize(&replay_plan, values.max_clock_skew, control_rt.as_ref())?;
    // Mode-A transport binding: bind the verified request actor to the mTLS peer.
    if values.binding == BindingKind::Exact {
        transport_binding = Some(Box::new(ExactMatchBinding::new()));
    }

    // Materialized HERE, not where `tls_material` is built, so the CRL load and its
    // stale-CRL refusal keep the position they had before the extraction: after the trust
    // posture, before the revocation posture. A deployment with both a stale CRL and an
    // unreadable trust file must still see the same diagnostic first.
    // Transport custody (ADR-MCPRE-056 §8). The plane owns the serving TLS config, the
    // per-request revocation index and the CRL reload worker; `tls_material` is MOVED in
    // so no second copy of the key material can drift from the one a reload rebuilds.
    building.install_tls(crate::tls_plane::TlsPlane::materialize(
        &tls_plan,
        tls_material,
        server_chain,
        client_ca,
        startup_now_unix,
        Arc::clone(&shutdown),
    )?);
    let is_delegated_tls = building.tls().is_delegated();
    let client_revocation = building.tls().revocation();
    let config_snapshot = building.tls().snapshot();

    // ADR-MCPS-023 §A1 (MCPS-58): the operator-visible revocation posture. Rendered by
    // the plane that parsed the CRLs, so what an operator is told is assertable in a test
    // rather than only readable in a transcript.
    for line in crate::tls_plane::revocation_posture_lines(&tls_plan, building.tls().crls()) {
        eprintln!("{line}");
    }

    // MCPS-85 (ADR-MCPS-049 clause 3): under --fleet, state the PER-TIER
    // cross-replica revocation-lag bounds explicitly, derived from real config
    // (the two tiers have different cadences). Zero-window revocation is never
    // claimed on either.
    if values.fleet {
        let trust_bound = crate::trust_plane::fleet_trust_bound(&trust_plan);
        let crl_bound = crate::tls_plane::fleet_crl_bound(&tls_plan);
        eprintln!(
            "mcp-re-proxy: FLEET cross-replica revocation-lag bounds (ADR-MCPS-049 clause 3): \
             trust-key-status={trust_bound}; client-cert-crl={crl_bound}; zero-window revocation \
             NOT claimed"
        );
    }

    // The delegated-TLS custody paths sign the handshake through a KMS or a PKCS#11
    // token, synchronously, inside rustls' `Signer::sign` — so the serving runtime
    // shape has to account for a blocking signer (see `async_fleet`).
    if is_delegated_tls {
        eprintln!(
            "mcp-re-proxy: TLS custody = DELEGATED: the handshake signature is a blocking \
             KMS/PKCS#11 call inside rustls' synchronous signer, so each core serves on a \
             small worker pool rather than the single-threaded share-nothing default. A \
             stalled signer then costs one worker instead of a whole core."
        );
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
    let identity_strategy = if values.binding == BindingKind::LbAssertion
        || values.binding == BindingKind::AttestedIngress
    {
        // Both the v1 LB-assertion (Mode B) and the v2 attested-ingress (Mode C)
        // paths carry identity in the signed assertion header — verified post-
        // verification inside the proxy — not at the connection seam. The serve loop
        // extracts the same `mcp-ingress-assertion` header (failing closed on a
        // duplicate) for both.
        IdentityStrategy::LbAssertion
    } else {
        match &values.reverse_proxy_identity_header {
            None => IdentityStrategy::DirectTls,
            Some(header) => IdentityStrategy::ReverseProxyHeader(ReverseProxyMtlsProvider::new(
                header.clone(),
                values.reverse_proxy_header_format,
                values.identity_source,
            )),
        }
    };
    // ADR-MCPRE-056 §5.4: from here on, every optional capability states its posture in
    // BOTH directions through `posture`. `assert_complete` below refuses to start — in
    // every build profile — if any seam is left silent.
    let mut posture = PostureLog::new();

    // #4030 ONLINE OCSP client-cert revocation. Attached to `ServerOptions` below rather
    // than to the PEP, because revocation is decided during the TLS handshake.
    let (ocsp_checker, ocsp_state) = crate::serving_capabilities::online_ocsp().into_parts();
    posture.declare(Seam::OnlineOcspClientRevocation, ocsp_state);
    // A build without the backend still DECLARES the seam above — that is the point of
    // `Seam::ALL` not varying by `cfg` — but there is no checker type in it to carry, so
    // the artifact is uninhabited and goes nowhere.
    #[cfg(not(feature = "online_ocsp"))]
    let _ = ocsp_checker;
    let serve_options = ServerOptions {
        identity_policy: values.identity_source,
        identity_strategy,
        limits: values.limits.clone(),
        max_client_cert_lifetime: values.max_client_cert_lifetime,
        client_revocation: client_revocation.clone(),
        #[cfg(feature = "online_ocsp")]
        ocsp_checker,
        target_uri: values.target_uri.clone(),
        // The delegated-TLS custody paths sign the handshake through a KMS or a
        // PKCS#11 token, synchronously, inside rustls' `Signer::sign`.
        tls_signing_may_block: is_delegated_tls,
    };

    // ADR-MCPRE-051 §3: the async inner plane — a per-core pooled hyper client to
    // the stateless Streamable-HTTP inner backends. Forwarding is AWAITED, never
    // blocking a per-core runtime worker.
    let inner_timeout = values
        .limits
        .read_timeout
        .unwrap_or_else(|| Duration::from_secs(30));
    let pool = HttpInnerPool::from_url_strs(values.inner_http_urls.clone(), inner_timeout)?;
    // Named where the pool that forwards to them is BUILT. Reporting them from the fleet
    // instead would mean carrying the URLs through serving purely to print them, and the
    // fleet does not forward — it accepts.
    eprintln!(
        "mcp-re-proxy: HTTP inner backends {:?}",
        values.inner_http_urls
    );
    // The pool is PROCESS-WIDE (one instance behind the `Arc` every core shares), so
    // its in-flight bound must not sit below the fleet's aggregate admission ceiling.
    // If it did, requests that passed every security gate would be answered with a
    // signed `inner server unavailable` at a capacity cliff no configured flag names —
    // and the shedding decision would move from the admission gate, where it is
    // deliberate, to the inner pool, where it is an accident of core count.
    // The RULE is pure and lives in the plan; the core count is the environment reading it
    // needs, and the wiring is this function's business.
    let cores = crate::async_fleet::resolve_core_count(values.cores);
    let ceiling = crate::startup_plan::inner_plane_ceiling(
        values.limits.max_in_flight_requests,
        values.max_in_flight_total,
        cores,
    );
    let pool = match crate::startup_plan::inner_plane_raise(
        ceiling,
        crate::http_inner::DEFAULT_MAX_IN_FLIGHT,
    ) {
        Some(raised) => {
            eprintln!(
                "mcp-re-proxy: inner-plane in-flight bound raised to {raised} to stay at or \
                 above the fleet admission ceiling ({cores} cores); the admission gate sheds, \
                 not the inner pool."
            );
            pool.with_max_in_flight(raised)
        }
        None => pool,
    };

    // Response-signing custody (ADR-MCPRE-056 §8; ADR-MCPRE-052). The plane owns the
    // root issuer, the delegated snapshot and the worker that maintains it; what comes
    // back is the signer alone. `key_source` is MOVED in here — it was only borrowed
    // above, for TLS material and the response public key.
    //
    // The plane must outlive the proxy that signs with it, and it does: both are locals
    // of this function, and `serve_fleet` returns before either is dropped.
    building.install_signing(crate::signing_plane::SigningPlane::materialize(
        &signing_plan,
        key_source,
        startup_now_unix,
        Arc::clone(&shutdown),
    )?);
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
        building.signing().signer(),
    );
    // §5.1/§13.1: attach the verifier-local acceptance policy so the operator's
    // `--max-clock-skew` governs the FRESHNESS GATE, not only replay retention.
    // `VerifierPolicy::new` is the validating constructor: a skew outside
    // `0..=MAX_CLOCK_SKEW_BOUND` refuses to build and startup fails closed rather
    // than serving a window the operator did not get. One value drives both the
    // acceptance window and the replay `retain_until`, so an admitted nonce is
    // retained for exactly as long as its signature can still be accepted.
    let mut verifier_policy =
        mcp_re_http_profile::VerifierPolicy::new(&["ed25519"], values.max_clock_skew).map_err(
            |_| {
                format!(
                    "--max-clock-skew {} is out of bounds: the RFC 9421 freshness gate accepts \
                     0..={} seconds (§5.1 bounded skew)",
                    values.max_clock_skew,
                    mcp_re_http_profile::VerifierPolicy::MAX_CLOCK_SKEW_BOUND,
                )
            },
        )?;
    let (mcp_transport, transport_state) = crate::serving_capabilities::mcp_transport_contract(
        config.state().mcp_transport_contract(),
    )
    .into_parts();
    if let Some(policy) = mcp_transport {
        verifier_policy = verifier_policy.with_mcp_transport(policy);
    }
    posture.declare(Seam::McpTransportContract, transport_state);
    eprintln!(
        "mcp-re-proxy: freshness gate = created-{skew}s .. expires+{skew}s (RFC 9421 §5.1)",
        skew = values.max_clock_skew
    );
    proxy = proxy.with_verifier_policy(verifier_policy);
    if let Some(binding) = transport_binding {
        proxy = proxy.with_transport_binding(binding);
    }

    // ADR-MCPS-035: the per-request security record. Both arms install a sink — the OFF
    // state is a real `NoAuditSink` — so this one is a pair rather than an `Established`.
    let (audit_sink, audit_state) =
        crate::serving_capabilities::security_audit_record(config.state().audit());
    proxy = proxy.with_audit_sink(audit_sink);
    posture.declare(Seam::SecurityAuditRecord, audit_state);

    // ADR-MCPRE-054: evidence retention. Opening the store is effectful and refuses
    // startup, which is why this is the one capability here that can return an error.
    let (retention, retention_state) =
        crate::serving_capabilities::evidence_retention(config.state().retention())?.into_parts();
    if let Some(retention) = retention {
        proxy = proxy.with_evidence_retention(Arc::new(retention));
    }
    posture.declare(Seam::EvidenceRetention, retention_state);

    let (verified_context, verified_context_state) =
        crate::serving_capabilities::verified_context_carrier(config.state().verified_context())
            .into_parts();
    if let Some(policy) = verified_context {
        proxy = proxy.with_verified_context_carrier(policy);
    }
    posture.declare(Seam::VerifiedContextCarrier, verified_context_state);

    // ADR-MCPS-047: the shared MRTR continuation correlation store, and MCPRE-493 §7:
    // the admission-currency gate. Both connect over the SAME shared control runtime the
    // fleet uses, and both are established in `serving_capabilities`, which is also where
    // the rule they DIFFER on is written down: absence is announced for the continuation
    // store and refuses startup for admission, because one is opportunistic and the other
    // was explicitly requested.
    let (continuation_store, continuation_state) =
        crate::serving_capabilities::mrtr_continuation_store(
            &crate::startup_plan::ContinuationControlPlan::from_validated(config),
            control_rt.as_ref(),
        )?
        .into_parts();
    if let Some(store) = continuation_store {
        proxy = proxy.with_continuation_store(
            store,
            crate::http_profile_serve::DEFAULT_CONTINUATION_TTL_SECS,
        );
    }
    posture.declare(Seam::MrtrContinuationStore, continuation_state);

    let (admission, admission_state) = crate::serving_capabilities::admission_currency(
        config.state().admission(),
        values.max_clock_skew,
        control_rt.as_ref(),
    )?
    .into_parts();
    if let Some(gate) = admission {
        proxy = proxy.with_admission(
            gate.source,
            gate.policy,
            gate.enforcement,
            gate.resolve_authority,
        );
    }
    posture.declare(Seam::AdmissionCurrency, admission_state);

    // Every optional capability has now stated its posture. Serving with an incomplete
    // one is refused in EVERY build profile (ADR-MCPRE-056 §5.4): the transcript is this
    // deployment's statement of which security controls are running, and an operator must
    // not read a list that silently omits an entry.
    posture.assert_complete()?;

    // ADR-MCPRE-051 §1: serve on the per-core async fleet (SO_REUSEPORT + tokio), the
    // production data plane. Blocks until SIGTERM/SIGINT drains the fleet.
    //
    // ADR-MCPRE-056 §10: every resource with a teardown obligation goes to one owner —
    // the three planes, the proxy, and the control runtime the proxy's networked clients
    // are bound to. The order they come apart in is stated and enforced there, rather
    // than being whatever order these locals happen to be declared in.
    // The last two teardown-bearing resources join the owner, and `finish` assembles.
    //
    // `MaterializationSucceeded` is applied INSIDE `finish`, after every required
    // resource has been taken — so a `Materialized` lifecycle cannot exist over an
    // incomplete graph. That is the equivalence ADR-MCPRE-057 §9 asks for: the lifecycle
    // state and the ownership state are the same fact, not two facts kept in step by
    // convention.
    // Composed BEFORE the runtime exists. `--bind` resolution can fail, and a failure
    // after `finish` would drop a materialized runtime instead of tearing it down in the
    // order it owns — the one thing that type is for.
    let fleet_cfg = fleet_config(values)?;

    building.install_proxy(proxy);
    building.install_control(control_rt);
    let (runtime, lifecycle) = building.finish()?;

    runtime.serve(
        Arc::clone(&config_snapshot),
        Arc::new(serve_options),
        fleet_cfg,
        shutdown,
        lifecycle,
    )
}

/// The serving topology this deployment asked for, with `--bind` resolved.
///
/// The fleet's whole input. Composed here rather than inside serving because resolving a
/// bind locator is a name lookup — an environment reading — and because it is the last
/// place that legitimately holds the deployment request: what serving needs is a topology,
/// and handing it the request instead would give it every other field as well.
fn fleet_config(values: &cli::Config) -> Result<crate::async_fleet::FleetConfig, String> {
    use std::net::ToSocketAddrs;

    let addr = values
        .bind
        .to_socket_addrs()
        .map_err(|e| format!("resolve --bind {}: {e}", values.bind))?
        .next()
        .ok_or_else(|| format!("--bind {} resolved to no address", values.bind))?;

    Ok(crate::async_fleet::FleetConfig {
        addr,
        cores: values.cores, // 0 = auto (one worker per core); --cores pins it
        workers_per_shard: values.workers_per_shard,
        listen_backlog: crate::async_fleet::DEFAULT_LISTEN_BACKLOG,
        // MCPRE-114: the operator's fleet-global target, divided evenly per core by
        // `async_fleet::apply_global_admission`. `None` = no global target.
        max_in_flight_total: values.max_in_flight_total,
    })
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
/// `proxy` by the caller.
///
/// # This function owns no teardown obligation
///
/// It borrows the proxy through an `Arc` and returns once `fleet.shutdown_and_join()` has
/// returned, which is the DRAIN: no request can be in flight afterwards. Everything that
/// must then happen in a particular order — each plane's post-owner transition, and
/// reclaiming the control runtime the proxy's networked clients are bound to — belongs to
/// [`crate::materialized_runtime::MaterializedRuntime`], which calls this and then tears
/// down. Keeping the drain here and the ordering there is deliberate: this function's
/// contract is "no request is running when I return", and that is all a caller should
/// have to know to sequence anything after it.
pub(crate) fn serve_fleet(
    proxy: Arc<HttpProfileProxy>,
    config_snapshot: Arc<config_snapshot::ServerConfigSnapshot>,
    serve_options: Arc<crate::ServerOptions>,
    fleet_cfg: crate::async_fleet::FleetConfig,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) -> Result<(), String> {
    // MCPRE-116: hand the fleet the SNAPSHOT, not a one-shot `load()`. The accept
    // loop re-reads it per connection, so the CRL hot-reload task's atomic swap is
    // observed by the next handshake instead of being written to a config nothing
    // reads again.
    let server_config = Arc::clone(&config_snapshot);
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
        "mcp-re-proxy: async fleet serving on {} ({} per-core workers)",
        fleet.local_addr(),
        fleet.worker_count(),
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

#[cfg(all(test, unix))]
mod tests {
    use super::check_key_file_perms;
    use super::faulted_clock_refusal;
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
            "shared",
            "--replay-redis-url",
            "redis://127.0.0.1:6379",
            "--replay-durability-tier",
            "redis-wait-quorum:1:100",
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

    /// The two custody states the disk projection is a function of.
    ///
    /// Classified rather than hand-built, so these tests measure what the validation
    /// boundary actually recognises for the fixture above.
    fn custody_states(
        config: &crate::cli::Config,
    ) -> (
        crate::config_state::CustodyState,
        crate::config_state::TlsCustodyState,
    ) {
        let (custody, violations) = crate::config_state::custody::classify_and_validate(config);
        assert!(violations.is_empty(), "fixture refused: {violations:?}");
        let (tls_custody, violations) =
            crate::config_state::tls_custody::classify_and_validate(config);
        assert!(violations.is_empty(), "fixture refused: {violations:?}");
        (
            custody.expect("the fixture names a custody state"),
            tls_custody.expect("the fixture names a TLS custody state"),
        )
    }

    /// C048: the PKCS#11 PIN file unlocks the token holding the signing keys, so it must
    /// be among the files the startup permission check covers — otherwise the credential
    /// protecting the keys sits behind a weaker floor than the keys themselves.
    #[test]
    fn the_pkcs11_pin_file_is_permission_checked() {
        use crate::app::key_files_read_from_disk;
        use crate::cli::KeySourceKind;

        let config = config_with(KeySourceKind::Pkcs11, "", "/tls.key");
        let (custody, tls_custody) = custody_states(&config);
        let files = key_files_read_from_disk(&custody, &tls_custody);
        assert!(
            files.contains(&"/etc/mcp-re/pin"),
            "the PIN file must be checked; got {files:?}"
        );
        // And it is NOT claimed for a source that reads no PIN.
        let file_config = config_with(KeySourceKind::File, "/seed", "/tls.key");
        let (custody, tls_custody) = custody_states(&file_config);
        assert!(
            !key_files_read_from_disk(&custody, &tls_custody)
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
            let (custody, tls_custody) = custody_states(&config);
            let checked = key_files_read_from_disk(&custody, &tls_custody);
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
        let (custody, tls_custody) = custody_states(&config);
        assert!(
            key_files_read_from_disk(&custody, &tls_custody).is_empty(),
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

    /// C077: a `stat` that fails for a reason OTHER than absence must refuse.
    ///
    /// The file exists and is about to be read; only its posture is unknowable. Treating
    /// that as compliance is a fail-open — on a networked or overlay Secret mount an EIO
    /// or ESTALE would start the proxy over a world-readable signing seed with no
    /// diagnostic at all.
    ///
    /// The broken implementation this catches: `if let Ok(meta) = metadata(path)` with no
    /// error arm, which is what this guard did.
    #[test]
    fn a_key_file_whose_posture_cannot_be_established_is_refused() {
        let dir = std::env::temp_dir().join(format!("mcp_re_perm_dir_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create dir");
        let key = dir.join("tls.key");
        std::fs::write(&key, b"key-material").expect("write");
        // No search permission on the directory: the file is still there and still
        // openable by anything holding a descriptor, but `stat` on the path fails EACCES.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).expect("chmod");

        let result = check_key_file_perms(&key.to_string_lossy(), false);

        // Restore before asserting so a failure does not leave an unremovable directory.
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::remove_dir_all(&dir);

        let err = result.expect_err("an unestablishable key-file posture must refuse startup");
        assert!(
            err.contains("cannot be stat'ed"),
            "the refusal must say the posture could not be established, got: {err}"
        );
    }

    /// R8-C123 (G10's finding, this group's call site): a record handed to the audit
    /// writer immediately before teardown must still reach stderr.
    ///
    /// The writer thread is DETACHED, so nothing joins it: at process exit whatever it
    /// had not yet written is gone, and a shutdown under load loses precisely the
    /// decisions taken last. That is the did-it-get-recorded-or-not collapse — the
    /// records are neither present nor reported missing, because the drop counter only
    /// counts what the QUEUE refused, not what the process exited on top of.
    /// `flush_stderr_audit` exists to close it and, until this call site, had no
    /// production caller at all.
    ///
    /// # Why a child process
    ///
    /// The property is "observable AFTER teardown", and teardown means the process is
    /// gone. Asserting it in-process would only assert that a background thread got
    /// around to the write — which it would, given any pause, with or without the flush.
    /// So the scenario runs in a child that enqueues a batch and then `exit`s the instant
    /// `app::run` returns: no destructors, no grace, the detached writer killed where it
    /// stands. With the drain in place every record is on stderr before `run` returns;
    /// without it the tail of the batch dies with the child, which is what the parent
    /// checks by looking for the LAST sequence number rather than any of them.
    #[test]
    fn a_record_enqueued_immediately_before_teardown_still_reaches_stderr() {
        use crate::audit_sink::AuditSink;
        use mcp_re_core::audit::AuditEvent;

        const BATCH: u64 = 2000;
        const CHILD_MARKER: &str = "MCP_RE_AUDIT_FLUSH_TEARDOWN_CHILD";
        const TEST_NAME: &str = "app::tests::\
                                 a_record_enqueued_immediately_before_teardown_still_reaches_stderr";

        if std::env::var_os(CHILD_MARKER).is_some() {
            // A config the validation boundary refuses, so `run` returns without opening a
            // socket. The route out does not matter — the drain is on all of them.
            let mut config = config_with(crate::cli::KeySourceKind::File, "/seed", "/tls.key");
            config.target_uri = String::new();

            // Attributed records, so the unattributed ceiling cannot drop any of them and
            // an absent seq means "lost at exit" rather than "refused by the queue".
            for i in 0..BATCH {
                crate::audit_sink::StderrAuditSink.record(&crate::audit_sink::AuditRecord {
                    event: AuditEvent::request_accepted(),
                    actor_id: Some("teardown-actor".to_string()),
                    status: 200,
                    at_unix: i as i64,
                });
            }
            let _ = super::run(
                config,
                std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            );
            // No unwinding, no flush of anything else: whatever the writer has not written
            // by now is lost, which is the condition under test.
            std::process::exit(0);
        }

        let child = std::process::Command::new(
            std::env::current_exe().expect("the test binary re-invokes itself"),
        )
        .args(["--exact", TEST_NAME, "--nocapture"])
        .env(CHILD_MARKER, "1")
        .output()
        .expect("the child scenario runs");
        let stderr = String::from_utf8_lossy(&child.stderr);
        // `--exact` with a name nothing matches selects ZERO tests and exits 0, so the
        // scenario would silently not run and the drain assertion below would fail with a
        // message about flushing. `TEST_NAME` is a literal that no compiler check keeps in
        // step with this module's path, so confirm the child actually ran the scenario.
        // The child `exit`s before libtest prints its summary — that is the point of the
        // scenario — so the evidence it ran is the line libtest prints on the way IN.
        let ran = String::from_utf8_lossy(&child.stdout);
        assert!(
            ran.contains("running 1 test"),
            "the child ran no test: {TEST_NAME:?} matches nothing in this binary. Fix the \
             name before reading anything into the drain assertion.\n{ran}"
        );

        let last = format!("audit seq={} ", BATCH - 1);
        assert!(
            stderr.contains(&last),
            "the record enqueued last before teardown never reached stderr: no {last:?} in \
             the child's output. The audit writer is detached, so an unflushed queue dies \
             with the process and the decisions taken last are neither recorded nor \
             reported missing."
        );
        // The first record is the control: it proves the child really did emit the batch,
        // so a missing tail above is a lost drain rather than a scenario that never ran.
        assert!(
            stderr.contains("audit seq=0 "),
            "the child emitted no audit records at all, so the assertion above proved \
             nothing: {stderr}"
        );
        assert!(
            stderr.contains("audit stream drained at shutdown"),
            "shutdown must STATE which of the two audit outcomes happened, and this run \
             drained: {stderr}"
        );
    }

    /// R8-C123, second half: a drain that TIMED OUT must never read as a drain that
    /// completed.
    ///
    /// The bounded wait exists so a stalled log collector cannot hold the process open,
    /// which means the timeout is a reachable outcome in production and not an error path.
    /// What it must not become is a quiet one: "the queue was drained" and "nobody can say
    /// whether the queue was drained" are different facts about the audit stream, and an
    /// operator reading the shutdown transcript has to be able to tell which they got.
    ///
    /// The broken implementation this catches: reporting both as one shutdown-complete
    /// line, or reporting only the success and leaving the timeout silent.
    #[test]
    fn a_timed_out_audit_drain_never_reads_as_a_completed_one() {
        let drained = super::audit_drain_line(true, true).expect("stderr audit states its drain");
        let timed_out =
            super::audit_drain_line(false, true).expect("a timeout is stated, not swallowed");

        assert_ne!(drained, timed_out);
        assert!(
            !drained.contains("WARNING") && drained.contains("drained"),
            "a completed drain must read as one: {drained}"
        );
        assert!(
            timed_out.contains("WARNING") && timed_out.contains("UNKNOWN"),
            "a timeout must state the uncertainty AS uncertainty — not as loss, and not as \
             a clean shutdown: {timed_out}"
        );
        assert!(
            !timed_out.contains("drained at shutdown"),
            "the timeout line must not carry the completed line's claim: {timed_out}"
        );
        // A deployment whose audit goes nowhere says nothing about a stream it does not
        // write; without this control the two assertions above would also hold for a
        // function that always spoke.
        assert!(super::audit_drain_line(true, false).is_none());
        assert!(super::audit_drain_line(false, false).is_none());
    }

    /// C117: a faulted host clock is only a warning while it costs nothing but
    /// per-request fail-closed denials. With client CRLs configured it costs the
    /// boot-time stale-CRL refusal — nothing is `Stale` against a zero clock — so the
    /// deployment would load an arbitrarily expired CRL and still print that revocation
    /// is enforced. That case refuses.
    ///
    /// The broken implementation this catches: warning unconditionally, and handing the
    /// same faulted reading to `TlsPlane::materialize` as the CRL freshness reference.
    #[test]
    fn a_faulted_clock_refuses_only_when_it_disables_the_crl_refusal() {
        use crate::startup_plan::EPOCH_CLOCK_FAULT_THRESHOLD_SECS;

        let refusal = faulted_clock_refusal(0, 1).expect("a faulted clock plus CRLs must refuse");
        assert!(
            refusal.contains("CRL") && refusal.contains("clock"),
            "the refusal must name both halves of why it fired: {refusal}"
        );
        assert!(
            faulted_clock_refusal(EPOCH_CLOCK_FAULT_THRESHOLD_SECS - 1, 2).is_some(),
            "anything below the fault threshold disables the same refusal"
        );
        // The two negative controls. Without them a guard that refused unconditionally
        // would satisfy the assertions above.
        assert!(
            faulted_clock_refusal(0, 0).is_none(),
            "with no CRL configured there is no boot-time refusal to disable; the \
             per-request posture is already fail-closed and warns"
        );
        assert!(
            faulted_clock_refusal(EPOCH_CLOCK_FAULT_THRESHOLD_SECS, 3).is_none(),
            "a sane clock must not be refused however many CRLs are configured"
        );
    }

    /// The fleet's input is the serving TOPOLOGY. Each field is carried across unchanged —
    /// no normalization happens here, because `0` means "auto" to `resolve_topology` and a
    /// value substituted at this point would hide which of the two decided.
    #[test]
    fn the_fleet_config_carries_the_topology_and_resolves_the_bind() {
        let config = config_with(crate::cli::KeySourceKind::File, "/seed", "/key");
        let fleet = super::fleet_config(&config).expect("the fixture binds a literal address");

        assert_eq!(fleet.addr, "127.0.0.1:8443".parse().expect("literal"));
        assert_eq!(fleet.cores, config.cores);
        assert_eq!(fleet.workers_per_shard, config.workers_per_shard);
        assert_eq!(fleet.max_in_flight_total, config.max_in_flight_total);
        assert_eq!(
            fleet.listen_backlog,
            crate::async_fleet::DEFAULT_LISTEN_BACKLOG
        );
    }

    /// A bind that resolves to nothing is refused BEFORE the runtime is assembled, so the
    /// failure cannot drop a materialized runtime instead of tearing it down in order.
    ///
    /// The refusal names the flag: a bare address-parse error tells an operator nothing
    /// about which of several address-shaped settings was rejected.
    #[test]
    fn an_unresolvable_bind_is_refused_and_names_the_flag() {
        let mut config = config_with(crate::cli::KeySourceKind::File, "/seed", "/key");
        config.bind = "missing-a-port".to_string();

        let refusal = super::fleet_config(&config).expect_err("no port, no socket address");
        assert!(
            refusal.contains("--bind") && refusal.contains("missing-a-port"),
            "the refusal must name the flag and the value: {refusal}"
        );
    }
}
