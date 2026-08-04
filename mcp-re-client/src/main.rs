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

/// The floor posture for the startup banner.
///
/// `bootstrap_version` is reported rather than elided. It is the only part of a durable
/// floor an attacker cannot reach by unlinking the directory and the only part an
/// ephemeral volume cannot lose, and it defaults to 0 — so "durable" on its own names
/// the storage an operator chose while saying nothing about whether any of it is
/// actually beyond reach. On the common sidecar deployment, where the floor directory
/// is an emptyDir, a bootstrap of 0 means a restart resets the floor to whatever the
/// (now empty) directory says and an older signed manifest is accepted again.
fn floor_posture(floor: &mcp_re_client::config::FloorConfig) -> String {
    use mcp_re_client::config::FloorConfig;
    // The ceiling is reported the same way and for the same reason: absent, the floor is
    // undefended against a writer who pins it at u64::MAX and refuses every later
    // manifest, and an operator reading the posture line should see that.
    let ceiling = |c: &Option<u64>| match c {
        Some(c) => format!(", ceiling_version={c}"),
        None => ", NO ceiling_version — unbounded upward".to_owned(),
    };
    match floor {
        FloorConfig::Durable {
            dir,
            bootstrap_version: 0,
            ceiling_version,
        } => format!(
            "durable at {} with NO bootstrap_version — a restart over lost storage resets \
             the floor to 0{}",
            dir.display(),
            ceiling(ceiling_version),
        ),
        FloorConfig::Durable {
            dir,
            bootstrap_version,
            ceiling_version,
        } => format!(
            "durable at {} (bootstrap_version={bootstrap_version}{})",
            dir.display(),
            ceiling(ceiling_version),
        ),
        FloorConfig::Ephemeral { bootstrap_version } => format!(
            "EPHEMERAL — no rollback protection across a restart \
             (bootstrap_version={bootstrap_version})"
        ),
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
         manifest_expires_at={}, trust.reload_secs={}",
        built.manifest_version,
        floor,
        floor_posture(&config.trust.floor),
        built.manifest_expires_at,
        config.trust.reload_secs
    );

    if check_only {
        eprintln!("mcp-re-client: configuration and trust anchors load; not serving (--check)");
        return ExitCode::SUCCESS;
    }

    let listener = match mcp_re_client::serve::bind(&config.local) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("bind {}: {error}", config.local.bind);
            return ExitCode::FAILURE;
        }
    };

    // Held for the process lifetime; dropping it stops and joins the refresh thread.
    //
    // Started unconditionally. This thread is not only how a published revocation
    // reaches a running client — it is the only place anchors are WITHDRAWN once the
    // manifest in force has passed its own `expires_at`, and nothing on the request
    // path consults that expiry. A client without it verifies for as long as it runs
    // under a trust picture whose governing document has lapsed, which is exactly the
    // state the manifest loader's expiry check exists to refuse. `validate()` bounds
    // `trust.reload_secs` so the cadence is also a ceiling on that window.
    let _refresher = AnchorRefresher::start(
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

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_re_client::config::FloorConfig;

    /// The posture line has to distinguish a durable floor with an operator-declared
    /// minimum from one that is purely whatever the directory says. Reporting both as
    /// "durable at <dir>" tells an operator the durability they selected is in force
    /// when, on an ephemeral volume with bootstrap 0, none of it is.
    #[test]
    fn the_posture_line_reports_the_bootstrap_the_floor_actually_has() {
        let unbootstrapped = floor_posture(&FloorConfig::Durable {
            dir: "/var/lib/mcp-re/floor".into(),
            bootstrap_version: 0,
            ceiling_version: None,
        });
        assert!(
            unbootstrapped.contains("NO bootstrap_version"),
            "unexpected: {unbootstrapped}"
        );
        let bootstrapped = floor_posture(&FloorConfig::Durable {
            dir: "/var/lib/mcp-re/floor".into(),
            bootstrap_version: 7,
            ceiling_version: None,
        });
        assert!(
            bootstrapped.contains("bootstrap_version=7"),
            "unexpected: {bootstrapped}"
        );
        let ephemeral = floor_posture(&FloorConfig::Ephemeral {
            bootstrap_version: 3,
        });
        assert!(
            ephemeral.contains("EPHEMERAL") && ephemeral.contains("bootstrap_version=3"),
            "unexpected: {ephemeral}"
        );
    }

    /// An absent ceiling is a real posture, not a neutral default: the floor is then
    /// undefended against a writer who pins it at `u64::MAX` and refuses every later
    /// manifest. The line has to say so, for the same reason it says so about the
    /// bootstrap.
    #[test]
    fn the_posture_line_reports_whether_the_floor_is_bounded_upward() {
        let unbounded = floor_posture(&FloorConfig::Durable {
            dir: "/var/lib/mcp-re/floor".into(),
            bootstrap_version: 7,
            ceiling_version: None,
        });
        assert!(
            unbounded.contains("NO ceiling_version"),
            "unexpected: {unbounded}"
        );
        let bounded = floor_posture(&FloorConfig::Durable {
            dir: "/var/lib/mcp-re/floor".into(),
            bootstrap_version: 7,
            ceiling_version: Some(500),
        });
        assert!(
            bounded.contains("ceiling_version=500") && !bounded.contains("NO ceiling_version"),
            "unexpected: {bounded}"
        );
    }
}
