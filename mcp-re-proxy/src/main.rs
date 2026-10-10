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
use std::sync::OnceLock;

/// MCPS-88 (ADR-MCPS-049 W3): flipped by SIGTERM/SIGINT. `app::run` then stops
/// the per-core async fleet from accepting and drains it via `shutdown_and_join`
/// (bounded; THM-0104) before returning. Initialised by
/// `install_shutdown_handlers` before any handler is installed.
static SHUTDOWN: OnceLock<Arc<AtomicBool>> = OnceLock::new();

/// Async-signal-safe handler: `OnceLock::get` on an initialised cell is an atomic
/// acquire load plus a reference (no lock, no allocation), followed by a lone
/// atomic store.
extern "C" fn handle_shutdown_signal(_sig: libc::c_int) {
    if let Some(flag) = SHUTDOWN.get() {
        flag.store(true, Ordering::SeqCst);
    }
}

/// Install the graceful-shutdown handler for SIGTERM (k8s rollout / `docker stop`)
/// and SIGINT (Ctrl-C), returning the flag the handler flips. The flag is
/// published before either `sigaction` call. Best-effort: a failure to install
/// leaves the previous (default-terminate) disposition, which is still safe — just
/// not graceful.
fn install_shutdown_handlers() -> Arc<AtomicBool> {
    let flag = Arc::clone(SHUTDOWN.get_or_init(|| Arc::new(AtomicBool::new(false))));
    // SAFETY: `sigaction` with a zeroed struct and a static `extern "C"` handler
    // that only reads an initialised `OnceLock` and performs an atomic store. No
    // `SA_RESTART`.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handle_shutdown_signal as *const () as libc::sighandler_t;
        libc::sigemptyset(&mut action.sa_mask);
        action.sa_flags = 0;
        libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut());
        libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut());
    }
    flag
}

fn main() -> ExitCode {
    let shutdown = install_shutdown_handlers();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(("trust-epoch", rest)) = args.split_first().map(|(c, r)| (c.as_str(), r)) {
        return match mcp_re_proxy::trust_epoch::advance::run_command(rest) {
            Ok(line) => {
                println!("{line}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("mcp-re-proxy trust-epoch: {e}");
                ExitCode::FAILURE
            }
        };
    }
    let result = mcp_re_proxy::cli::parse_args(&args)
        .and_then(|config| mcp_re_proxy::app::run(config, shutdown));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mcp-re-proxy: {e}");
            ExitCode::FAILURE
        }
    }
}
