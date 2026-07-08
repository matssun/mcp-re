//! ADR-MCPRE-051 (Phase B) — the OUT-OF-TCB `stdio`↔HTTP adapter.
//!
//! # Why this binary exists
//!
//! MCP-RE's proxy (the PEP) is a cryptographic trust boundary: it verifies signed
//! requests, enforces replay, and SIGNS responses. The high-throughput serving
//! architecture (ADR-MCPRE-051) makes its sole inner plane a *stateless HTTP*
//! client — a keep-alive connection pool to inner MCP backends — so the async
//! front end's concurrency becomes throughput. The PEP no longer launches, nor
//! sandboxes, nor speaks `stdio` to a subprocess: that entire ~3k-line surface
//! (subprocess lifecycle, environment allow-listing, Landlock fs rulesets,
//! seccomp-bpf egress filters, `setrlimit`) is the single most dangerous and
//! most platform-specific code in the system, and it has been REMOVED from the
//! signing PEP's Trusted Computing Base.
//!
//! But the large existing population of MCP servers speaks `stdio` only (launched
//! as a subprocess, JSON-RPC over the child's stdin/stdout). This bridge lets the
//! PEP protect them WITHOUT re-admitting that surface into the TCB: it fronts one
//! unmodified local `stdio` MCP server behind a plain HTTP endpoint. The PEP's
//! HTTP inner plane POSTs an already-verified, stripped, verified-context-injected
//! JSON-RPC request here; this bridge relays it to the sandboxed child over
//! `stdio` and returns the child's JSON-RPC response as the HTTP body.
//!
//! ```text
//!   client ──mTLS──▶  mcp-re-proxy (PEP, signs)  ──HTTP──▶  THIS BRIDGE  ──stdio──▶  unmodified MCP server
//!                     └ cryptographic TCB ─────┘            └ subprocess + sandbox live HERE, outside the TCB ┘
//! ```
//!
//! A compromise of this bridge cannot forge a signature or defeat replay — those
//! guarantees live entirely in the PEP. The bridge's own job (contain the child)
//! is a separate, relocatable concern, which is exactly why it belongs out here.
//!
//! # Phase status
//!
//! Phase A (this commit) proves the topology and reuses the hardened subprocess
//! inner from `mcp-re-proxy` (`SubprocessInner` / `PersistentSubprocessInner` +
//! `InnerLaunchConfig` + the Landlock/seccomp `SandboxProfile` + `RLimits`). The
//! secure launch defaults apply (empty environment, controlled working directory,
//! bounded stderr, resource ceilings). The full `--inner-*` sandbox/env/rlimit
//! flag surface, and the physical MOVE of those modules into this crate (cutting
//! the reverse dependency on `mcp-re-proxy`), are the next commits of this phase.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::Full;
use http_body_util::Limited;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::Method;
use hyper::Request;
use hyper::Response;
use hyper::StatusCode;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;

use mcp_re_stdio_bridge::inner_launch::InnerLaunchConfig;
use mcp_re_stdio_bridge::persistent_inner::PersistentSubprocessInner;
use mcp_re_stdio_bridge::subprocess_inner::InnerServer;
use mcp_re_stdio_bridge::subprocess_inner::SubprocessInner;

/// A cap on the request body the bridge reads into memory, so a broken/hostile
/// PEP (or, more realistically, a misconfiguration) cannot exhaust the bridge.
/// Generous relative to real MCP requests; mirrors the PEP's inner-response cap.
const MAX_REQUEST_BYTES: usize = 32 * 1024 * 1024;

/// Which subprocess inner to run: spawn-per-request or a single long-lived child.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InnerMode {
    /// Spawn the inner command fresh for each request (stateless).
    OneShot,
    /// Spawn the inner command ONCE and keep the MCP session alive across
    /// requests (stateful servers). Requests are serialized over the one child.
    Persistent,
}

/// Parsed bridge configuration.
struct BridgeArgs {
    /// HTTP address the bridge listens on for the PEP's inner-plane POSTs.
    listen: SocketAddr,
    /// The inner MCP server command + argv (everything after `--`).
    inner_command: Vec<String>,
    /// One-shot vs persistent subprocess inner.
    inner_mode: InnerMode,
    /// Explicit controlled working directory for the child (`--inner-working-dir`).
    /// `None` selects the hardened default (see [`InnerLaunchConfig`]).
    inner_working_dir: Option<String>,
}

impl BridgeArgs {
    /// Hand-rolled parse (matching the repo's flag-parsing style). Everything
    /// AFTER a `--` separator is the inner command + its argv, verbatim.
    ///
    /// `--listen ADDR` (required), `--inner-mode oneshot|persistent`
    /// (default `oneshot`), `--inner-working-dir DIR` (optional).
    fn parse(argv: &[String]) -> Result<Self, String> {
        let mut listen: Option<SocketAddr> = None;
        let mut inner_mode = InnerMode::OneShot;
        let mut inner_working_dir: Option<String> = None;
        let mut inner_command: Vec<String> = Vec::new();

        let mut i = 0;
        while i < argv.len() {
            match argv[i].as_str() {
                "--" => {
                    inner_command = argv[i + 1..].to_vec();
                    break;
                }
                "--listen" => {
                    let v = argv
                        .get(i + 1)
                        .ok_or_else(|| "--listen requires an ADDR argument".to_string())?;
                    listen = Some(
                        v.parse::<SocketAddr>()
                            .map_err(|e| format!("invalid --listen address '{v}': {e}"))?,
                    );
                    i += 2;
                }
                "--inner-mode" => {
                    let v = argv
                        .get(i + 1)
                        .ok_or_else(|| "--inner-mode requires oneshot|persistent".to_string())?;
                    inner_mode = match v.as_str() {
                        "oneshot" => InnerMode::OneShot,
                        "persistent" => InnerMode::Persistent,
                        other => {
                            return Err(format!(
                                "invalid --inner-mode '{other}' (expected oneshot|persistent)"
                            ))
                        }
                    };
                    i += 2;
                }
                "--inner-working-dir" => {
                    let v = argv
                        .get(i + 1)
                        .ok_or_else(|| "--inner-working-dir requires a DIR argument".to_string())?;
                    inner_working_dir = Some(v.clone());
                    i += 2;
                }
                other => {
                    return Err(format!(
                        "unknown argument '{other}' (put the inner command after a '--' separator)"
                    ));
                }
            }
        }

        let listen = listen.ok_or_else(|| "missing required --listen ADDR".to_string())?;
        if inner_command.is_empty() {
            return Err(
                "missing inner command: pass it after a '--' separator, e.g. \
                 `mcp-re-stdio-bridge --listen 127.0.0.1:8080 -- /path/to/server --flag`"
                    .to_string(),
            );
        }
        Ok(BridgeArgs {
            listen,
            inner_command,
            inner_mode,
            inner_working_dir,
        })
    }
}

/// Build the hardened [`InnerLaunchConfig`] from the parsed args. Phase A applies
/// the secure defaults (empty env, controlled working dir, bounded stderr,
/// resource ceilings, sandbox off) and honours `--inner-working-dir`. The full
/// sandbox/env/rlimit flag surface ports in the next commit of this phase.
fn build_launch(args: &BridgeArgs) -> InnerLaunchConfig {
    let mut launch = InnerLaunchConfig::default();
    if let Some(dir) = &args.inner_working_dir {
        launch.working_dir = Some(dir.clone());
    }
    launch
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = match BridgeArgs::parse(&argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("mcp-re-stdio-bridge: {e}");
            std::process::exit(2);
        }
    };

    let launch = build_launch(&args);
    // Build the concrete, sandboxed subprocess inner. Both variants implement the
    // sync `InnerServer` seam and are `Send + Sync` (shared across connections;
    // the persistent variant serializes over its single child internally).
    let inner: Arc<dyn InnerServer + Send + Sync> = match args.inner_mode {
        InnerMode::OneShot => match SubprocessInner::new(&args.inner_command, launch) {
            Ok(s) => Arc::new(s),
            Err(e) => {
                eprintln!("mcp-re-stdio-bridge: failed to configure one-shot inner: {e}");
                std::process::exit(1);
            }
        },
        InnerMode::Persistent => match PersistentSubprocessInner::new(&args.inner_command, launch) {
            Ok(s) => Arc::new(s),
            Err(e) => {
                eprintln!("mcp-re-stdio-bridge: failed to start persistent inner: {e}");
                std::process::exit(1);
            }
        },
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("mcp-re-stdio-bridge: failed to build tokio runtime: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = runtime.block_on(serve(args.listen, inner)) {
        eprintln!("mcp-re-stdio-bridge: serve error: {e}");
        std::process::exit(1);
    }
}

/// Accept loop: bind `listen`, then serve each connection with the auto (HTTP/1
/// + HTTP/2) protocol builder, routing every request through [`handle`].
async fn serve(listen: SocketAddr, inner: Arc<dyn InnerServer + Send + Sync>) -> Result<(), String> {
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|e| format!("bind {listen}: {e}"))?;
    let bound = listener
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?;
    eprintln!("mcp-re-stdio-bridge: listening on http://{bound} (stdio inner, out of the PEP TCB)");

    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(pair) => pair,
            // A single accept error must not tear the bridge down.
            Err(_) => continue,
        };
        let inner = Arc::clone(&inner);
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req| {
                let inner = Arc::clone(&inner);
                async move { handle(req, inner).await }
            });
            // Serve the connection; a per-connection error is logged, not fatal.
            let _ = auto::Builder::new(TokioExecutor::new())
                .serve_connection(io, service)
                .await;
        });
    }
}

/// Handle one HTTP request: a `POST` of a JSON-RPC body is relayed to the stdio
/// child; the child's JSON-RPC response becomes the body. Anything else is a
/// `405`. The dispatch is blocking subprocess I/O, so it runs on a blocking
/// thread and never stalls a runtime worker.
async fn handle(
    req: Request<Incoming>,
    inner: Arc<dyn InnerServer + Send + Sync>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    if req.method() != Method::POST {
        return Ok(status_only(StatusCode::METHOD_NOT_ALLOWED));
    }

    // Read the (capped) request body. Over-cap or transport error ⇒ 400.
    let limited = Limited::new(req.into_body(), MAX_REQUEST_BYTES);
    let body = match limited.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return Ok(status_only(StatusCode::BAD_REQUEST)),
    };

    // Subprocess pipe I/O is blocking: keep it off the async workers.
    let response = match tokio::task::spawn_blocking(move || inner.dispatch(&body)).await {
        Ok(bytes) => bytes,
        // A panic in the blocking dispatch ⇒ 502 (the PEP fails that inner call closed).
        Err(_) => return Ok(status_only(StatusCode::BAD_GATEWAY)),
    };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(response)))
        .expect("static response build never fails"))
}

/// A body-less response carrying just `status`.
fn status_only(status: StatusCode) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::new()))
        .expect("static response build never fails")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_listen_and_inner_command_after_separator() {
        let a = v(&["--listen", "127.0.0.1:8080", "--", "/bin/server", "--flag"]);
        let parsed = BridgeArgs::parse(&a).expect("parse");
        assert_eq!(parsed.listen, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(parsed.inner_command, vec!["/bin/server", "--flag"]);
        assert_eq!(parsed.inner_mode, InnerMode::OneShot);
    }

    #[test]
    fn parses_persistent_mode_and_working_dir() {
        let a = v(&[
            "--listen",
            "127.0.0.1:0",
            "--inner-mode",
            "persistent",
            "--inner-working-dir",
            "/srv/run",
            "--",
            "server",
        ]);
        let parsed = BridgeArgs::parse(&a).expect("parse");
        assert_eq!(parsed.inner_mode, InnerMode::Persistent);
        assert_eq!(parsed.inner_working_dir.as_deref(), Some("/srv/run"));
    }

    #[test]
    fn missing_listen_fails_closed() {
        let a = v(&["--", "server"]);
        assert!(BridgeArgs::parse(&a).is_err());
    }

    #[test]
    fn missing_inner_command_fails_closed() {
        let a = v(&["--listen", "127.0.0.1:8080"]);
        assert!(BridgeArgs::parse(&a).is_err());
    }

    #[test]
    fn empty_inner_command_after_separator_fails_closed() {
        let a = v(&["--listen", "127.0.0.1:8080", "--"]);
        assert!(BridgeArgs::parse(&a).is_err());
    }

    #[test]
    fn unknown_flag_before_separator_fails_closed() {
        let a = v(&["--listen", "127.0.0.1:8080", "--bogus", "--", "server"]);
        assert!(BridgeArgs::parse(&a).is_err());
    }

    #[test]
    fn invalid_inner_mode_fails_closed() {
        let a = v(&["--listen", "127.0.0.1:8080", "--inner-mode", "weird", "--", "server"]);
        assert!(BridgeArgs::parse(&a).is_err());
    }
}
