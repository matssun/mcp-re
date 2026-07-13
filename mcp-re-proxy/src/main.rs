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

/// MCPS-88 (ADR-MCPS-049 W3): set on SIGTERM/SIGINT so the serve loop stops
/// accepting NEW connections and returns for a clean exit. Graceful drain in the
/// single-threaded inline model is exact: at most one request is ever in flight
/// (on this same thread), and it always runs to completion — bounded by the
/// existing per-request read/response deadlines (`ServerLimits`) — before the loop
/// re-checks this flag. There is therefore no queue to drain and no in-flight
/// request to abandon.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

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

fn main() -> ExitCode {
    // Bridge the async-signal-safe global flag (flipped by the SIGTERM/SIGINT
    // handler) to the Arc the library serve loop watches, so shutdown stays signal-
    // driven in the binary while `app::run` takes an ordinary flag (testable).
    let shutdown = Arc::new(AtomicBool::new(false));
    install_shutdown_handlers();
    let bridge = Arc::clone(&shutdown);
    std::thread::spawn(move || loop {
        if SHUTDOWN.load(Ordering::SeqCst) {
            bridge.store(true, Ordering::SeqCst);
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    });
    let args: Vec<String> = std::env::args().skip(1).collect();
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
