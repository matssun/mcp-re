// SPDX-License-Identifier: Apache-2.0
//! The `mcp-re-client` CLI: parse, build, verify the trust picture, serve.
//!
//! All wiring lives in the library (and is unit-tested there); this shell reads the
//! configuration, performs the fail-closed startup load, starts the anchor refresher,
//! and runs the local listener until a signal.

use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use mcp_re_client::anchors::AnchorRefresher;
use mcp_re_client::config::ClientConfig;

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

const USAGE: &str = "\
mcp-re-client — the MCP-RE client-side ambassador

  --config <path>   the JSON configuration document (required)
  --check           load the configuration and the trust anchors, then exit
  --help            this text

The local listener speaks PLAIN MCP. It binds loopback unless the configuration
declares local.allow_non_loopback, because anything that reaches it gets requests
signed under this client's identity.";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
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
                        return ExitCode::FAILURE;
                    }
                }
            }
            "--check" => check_only = true,
            "--help" | "-h" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unknown argument {other:?}\n\n{USAGE}");
                return ExitCode::FAILURE;
            }
        }
        index += 1;
    }
    let Some(config_path) = config_path else {
        eprintln!("--config is required\n\n{USAGE}");
        return ExitCode::FAILURE;
    };

    let config = match ClientConfig::read(std::path::Path::new(&config_path)) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    // The startup load is fail-closed: a client that cannot establish which roots it
    // trusts has no basis to verify anything.
    let built = match mcp_re_client::build(&config, now) {
        Ok(built) => built,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };

    let floor = match built.loader.floor_version() {
        Ok(floor) => floor.to_string(),
        Err(_) => "unreadable".to_owned(),
    };
    eprintln!(
        "mcp-re-client: trust-anchor manifest v{} accepted (floor={}, {}), \
         manifest_expires_at={}",
        built.manifest_version,
        floor,
        match &config.trust.floor {
            mcp_re_client::config::FloorConfig::Durable { dir, .. } =>
                format!("durable at {}", dir.display()),
            mcp_re_client::config::FloorConfig::Ephemeral { .. } =>
                "EPHEMERAL — no rollback protection across a restart".to_owned(),
        },
        built.manifest_expires_at
    );

    if check_only {
        eprintln!("mcp-re-client: configuration and trust anchors load; not serving (--check)");
        return ExitCode::SUCCESS;
    }

    let listener = match mcp_re_client::serve::bind(config.local.bind) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("bind {}: {error}", config.local.bind);
            return ExitCode::FAILURE;
        }
    };

    // Held for the process lifetime; dropping it stops and joins the refresh thread.
    let _refresher = (config.trust.reload_secs > 0).then(|| {
        AnchorRefresher::start(
            built.loader,
            Arc::clone(&built.snapshot),
            built.manifest_expires_at,
            Duration::from_secs(config.trust.reload_secs),
            || {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0)
            },
        )
    });
    if config.trust.reload_secs == 0 {
        eprintln!(
            "mcp-re-client: trust.reload_secs is 0 — a published revocation reaches this \
             client only on restart"
        );
    }

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
