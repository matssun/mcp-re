// SPDX-License-Identifier: Apache-2.0
//! Everything between the command line and the serving loop.
//!
//! Two questions are asked of the invocation and nothing else — which configuration, and
//! whether to serve. The parser is deliberately this small: every argument this binary
//! accepts is one more thing that can change what gets signed under the operator's identity.
//!
//! The other half is what *running* means. The anchor refresher is started
//! UNCONDITIONALLY and held for the process lifetime, because it is not only how a
//! published revocation reaches a running client — it is the ONLY place anchors are
//! WITHDRAWN once the manifest in force has passed its own `expires_at`, and nothing on the
//! request path consults that expiry. A client without it verifies for as long as it runs
//! under a trust picture whose governing document has lapsed, which is exactly the state the
//! manifest loader''s expiry check exists to refuse. `validate()` bounds
//! `trust.reload_secs`, so the cadence is also a ceiling on that window.

use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use mcp_re_client::anchors::AnchorRefresher;
use mcp_re_client::config::ClientConfig;

use crate::USAGE;

/// Set on SIGTERM/SIGINT so the accept loop stops taking new local connections.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_shutdown_signal(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

/// Install the graceful-shutdown handler. Best effort: a failure leaves the default
/// terminate disposition, which is still safe — just not graceful.
fn install_shutdown_handlers() {
    // SAFETY: `sigaction` with a zeroed struct and a static `extern "C"` handler that
    // performs only an atomic store (on the async-signal-safe list).
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handle_shutdown_signal as *const () as libc::sighandler_t;
        libc::sigemptyset(&mut action.sa_mask);
        action.sa_flags = 0;
        libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut());
        libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut());
    }
}

/// The floor posture for the startup banner.
///
/// `bootstrap_version` is reported rather than elided. It is the only part of a durable
/// floor an attacker cannot reach by unlinking the directory and the only part an
/// ephemeral volume cannot lose, and it defaults to 0 — so "durable" on its own names
/// the storage an operator chose while saying nothing about whether any of it is
/// actually beyond reach. On the common sidecar deployment, where the floor directory
/// is an emptyDir, a bootstrap of 0 means a restart resets the floor to whatever the
/// What the command line asked for.
///
/// Two questions and nothing else: which configuration, and whether to serve. The parser is
/// deliberately this small — every argument this binary accepts is one more thing that can
/// change what gets signed under the operator's identity.
pub(crate) struct Invocation {
    pub(crate) config_path: String,
    pub(crate) check_only: bool,
}

/// Read the command line, or say what to print and with which status.
///
/// `Err(code)` covers both terminals that are not serving: `--help` printed the usage and
/// succeeded, a bad argument printed a diagnosis and failed. Neither is a value the rest of
/// startup could act on, which is why they leave here rather than being carried.
pub(crate) fn parse_invocation(args: &[String]) -> Result<Invocation, ExitCode> {
    let mut config_path: Option<String> = None;
    let mut check_only = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--config" => {
                index += 1;
                match args.get(index) {
                    Some(path) => config_path = Some(path.clone()),
                    None => {
                        eprintln!("--config needs a path");
                        return Err(ExitCode::FAILURE);
                    }
                }
            }
            "--check" => check_only = true,
            "--help" | "-h" => {
                println!("{USAGE}");
                return Err(ExitCode::SUCCESS);
            }
            other => {
                eprintln!("unknown argument {other:?}\n\n{USAGE}");
                return Err(ExitCode::FAILURE);
            }
        }
        index += 1;
    }
    let Some(config_path) = config_path else {
        eprintln!("--config is required\n\n{USAGE}");
        return Err(ExitCode::FAILURE);
    };
    Ok(Invocation {
        config_path,
        check_only,
    })
}

/// Wall-clock unix seconds.
pub(crate) fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Serve until a shutdown signal is observed.
///
/// The anchor refresher is started UNCONDITIONALLY and held for the process lifetime. It is
/// not only how a published revocation reaches a running client — it is the only place
/// anchors are WITHDRAWN once the manifest in force has passed its own `expires_at`, and
/// nothing on the request path consults that expiry. A client without it verifies for as
/// long as it runs under a trust picture whose governing document has lapsed, which is
/// exactly the state the manifest loader's expiry check exists to refuse. `validate()`
/// bounds `trust.reload_secs`, so the cadence is also a ceiling on that window.
pub(crate) fn serve_until_shutdown(
    config: &ClientConfig,
    built: mcp_re_client::BuiltClient,
    listener: std::net::TcpListener,
) -> ExitCode {
    let _refresher = AnchorRefresher::start(
        built.loader,
        Arc::clone(&built.snapshot),
        built.manifest_expires_at,
        Duration::from_secs(config.trust.reload_secs),
        now_unix,
    );
    install_shutdown_handlers();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_loop = Arc::clone(&stop);
    std::thread::spawn(move || {
        while !SHUTDOWN.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(100));
        }
        stop_loop.store(true, Ordering::Relaxed);
    });

    eprintln!("mcp-re-client: serving plain MCP on {}", config.local.bind);
    mcp_re_client::serve::serve(listener, built.context, stop);
    ExitCode::SUCCESS
}
