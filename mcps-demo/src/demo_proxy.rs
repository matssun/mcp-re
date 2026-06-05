//! Demo proxy wiring (MCPS-047, MCPS-EPIC-P6 Child Issue 3).
//!
//! This is the demo-specific glue that points the EXISTING `mcps-proxy`
//! [`Proxy`](mcps_proxy::Proxy) at the EXISTING `mcps-demo-fileserver` binary as
//! its inner stdio subprocess. It reinvents nothing: the launch hardening
//! (controlled working directory, minimized/allowlisted environment, bounded
//! separately-captured stderr, `setrlimit` resource ceilings) lives in
//! `mcps-proxy`'s [`InnerLaunchConfig`](mcps_proxy::InnerLaunchConfig) /
//! [`SubprocessInner`](mcps_proxy::cli::SubprocessInner); the verify →
//! strip-caller-`.verified` → inject-sidecar-verified-context → sign path lives
//! in `mcps-proxy`'s `Proxy`. This module only assembles them for the demo.
//!
//! The inner binary path and the demo-root directory are RESOLVED BY THE CALLER
//! (the integration test resolves them from Bazel runfiles); nothing here
//! hardcodes a path. The proxy's verification/signing identities are likewise
//! injected so the demo wiring is deterministic and testable.

use mcps_core::SigningKey;
use mcps_core::TrustResolver;
use mcps_proxy::cli::SubprocessInner;
use mcps_proxy::InnerLaunchConfig;
use mcps_proxy::InnerLogSink;
use mcps_proxy::Proxy;
use mcps_proxy::RLimits;
use std::sync::Arc;

/// The inputs that locate and identify a demo proxy instance.
///
/// `inner_binary` and `demo_root` are absolute paths the caller resolves (the
/// test resolves them from Bazel runfiles — see the crate's integration test).
/// The remaining fields are the proxy's verification + response-signing
/// identities, injected so the wiring carries no ambient configuration.
pub struct DemoProxyConfig {
    /// Absolute path to the `mcps-demo-fileserver` binary the proxy launches as
    /// its inner stdio subprocess.
    pub inner_binary: String,
    /// Absolute path to the committed `demo_root/` fixture. Used BOTH as the
    /// inner server's `--demo-root` argument AND as its controlled working
    /// directory, so the inner server never silently inherits the proxy's cwd.
    pub demo_root: String,
    /// The proxy's response-signing key.
    pub server_signing_key: SigningKey,
    /// The proxy's signer identity (the `server_signer` / response `verifier`).
    pub server_signer: String,
    /// The key id advertised in signed responses.
    pub server_key_id: String,
    /// The expected audience the inbound request must target.
    pub audience: String,
    /// Maximum clock skew tolerated during verification (seconds).
    pub max_clock_skew_secs: i64,
}

/// Build the hardened inner-launch policy the demo uses (MCPS-035/036/037).
///
/// * environment is MINIMIZED — cleared then nothing allowlisted (the demo
///   fileserver needs no env), so env-loaded key material is never visible to
///   the inner server;
/// * the inner server runs in an EXPLICIT working directory (`demo_root`),
///   never the proxy's cwd;
/// * stderr is captured separately into a bounded log (default caps) and never
///   merged into the stdout protocol stream;
/// * `setrlimit` resource ceilings are applied where supported (the secure
///   default already disables core dumps; the demo additionally caps open file
///   descriptors and single-file write size as a coarse abuse bound).
pub fn demo_inner_launch(demo_root: &str) -> InnerLaunchConfig {
    InnerLaunchConfig {
        // MCPS-035: clear the environment, allowlist nothing — the fileserver
        // reads no env. inherit_env stays false (the secure default).
        inherit_env: false,
        explicit_env: Vec::new(),
        allow_env_names: Vec::new(),
        // MCPS-036: explicit controlled working directory.
        working_dir: Some(demo_root.to_string()),
        // MCPS-037: resource ceilings where supported. Core dumps are already
        // disabled by RLimits::new(); add a coarse fd + single-file-size bound.
        rlimits: RLimits {
            nofile: Some(256),
            fsize_bytes: Some(8 * 1024 * 1024),
            ..RLimits::new()
        },
        // Bounded-stderr caps default (MCPS-036) from InnerLaunchConfig::new().
        ..InnerLaunchConfig::new()
    }
}

/// The `[cmd, arg, ...]` vector launching the demo fileserver pointed at
/// `demo_root` via its required `--demo-root` flag.
pub fn demo_inner_command(inner_binary: &str, demo_root: &str) -> Vec<String> {
    vec![
        inner_binary.to_string(),
        "--demo-root".to_string(),
        demo_root.to_string(),
    ]
}

/// Assemble a demo [`Proxy`] that launches the real `mcps-demo-fileserver` as
/// its inner stdio subprocess under the hardened launch policy above, resolving
/// inbound signers through `resolver`.
///
/// The returned proxy drives the production serving path: every inbound request
/// is verified, any caller-supplied `.verified` block is stripped, a fresh
/// sidecar-owned verified context is injected, the request is forwarded to the
/// inner subprocess, and the inner result is signed. The `log_sink` receives the
/// inner lifecycle events (spawn/exit/stderr) AND the two proxy-level events.
///
/// Fails closed (`Err`) if the launch policy cannot be honored against the real
/// process environment / filesystem (e.g. `demo_root` is not a directory) —
/// surfaced at construction, never silently at serve time.
pub fn build_demo_proxy(
    config: DemoProxyConfig,
    resolver: Box<dyn TrustResolver>,
    log_sink: Arc<dyn InnerLogSink + Send + Sync>,
) -> Result<Proxy, String> {
    let launch = demo_inner_launch(&config.demo_root);
    let command = demo_inner_command(&config.inner_binary, &config.demo_root);
    let inner = SubprocessInner::with_log_sink(&command, launch, Arc::clone(&log_sink))?;
    let proxy = Proxy::new(
        config.server_signing_key,
        config.server_signer,
        config.server_key_id,
        resolver,
        config.audience,
        config.max_clock_skew_secs,
        Box::new(inner),
    )
    .with_log_sink(log_sink);
    Ok(proxy)
}
