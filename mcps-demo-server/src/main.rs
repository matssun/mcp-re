//! `mcps-demo-server` binary entrypoint (MCPS-062).
//!
//! Runs the demo server as a plain, LONG-LIVED stdio MCP server: reads
//! newline-delimited JSON-RPC requests from stdin and writes one response line
//! per request to stdout, staying alive across MANY requests until stdin EOF
//! (or a modelled `shutdown`). The in-memory item set is seeded deterministically
//! (defaulting to `alpha,beta,gamma`); repeat `--seed <ITEM>` to override it.
//! Arg parsing is std-only (no clap), consistent with the sibling stdio servers.
//!
//! ## Received-request log (MCPS-068, #3965)
//! For anti-gaming tests of "deny-before-dispatch / inner not reached", the
//! server can record every `tools/call` it ACTUALLY executes to an append-only
//! file: one JSON line `{"id":<json-rpc id>,"tool":"<name>"}` per served call.
//! Enable it with `--received-log <PATH>` or the `MCPS_DEMO_SERVER_RECEIVED_LOG`
//! env var (the flag wins). It is OFF by default, so ordinary runs (and the
//! existing one-shot/persistent proxy paths) are entirely unaffected.
//!
//! Usage:
//!   mcps-demo-server [--seed <ITEM>]... [--received-log <PATH>]

use std::io::BufReader;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use mcps_demo_server::serve_stdio;
use mcps_demo_server::DemoServer;

/// Env var fallback for the received-request log path (the `--received-log` flag
/// takes precedence when both are present).
const RECEIVED_LOG_ENV: &str = "MCPS_DEMO_SERVER_RECEIVED_LOG";

/// The default deterministic seed item set when no `--seed` is supplied.
fn default_seed() -> Vec<String> {
    vec!["alpha".to_string(), "beta".to_string(), "gamma".to_string()]
}

/// The parsed CLI: the seed item set plus an optional received-log path.
struct CliArgs {
    seed: Vec<String>,
    received_log: Option<PathBuf>,
}

fn parse_args(argv: &[String]) -> Result<CliArgs, String> {
    let mut iter = argv.iter();
    let mut seed: Vec<String> = Vec::new();
    let mut received_log: Option<PathBuf> = None;
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--seed" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--seed requires a value".to_string())?;
                seed.push(value.clone());
            }
            "--received-log" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--received-log requires a value".to_string())?;
                received_log = Some(PathBuf::from(value));
            }
            other => return Err(format!("unknown argument '{other}'")),
        }
    }
    if seed.is_empty() {
        seed = default_seed();
    }
    // Env var is the fallback; an explicit flag wins.
    if received_log.is_none() {
        if let Ok(path) = std::env::var(RECEIVED_LOG_ENV) {
            if !path.is_empty() {
                received_log = Some(PathBuf::from(path));
            }
        }
    }
    Ok(CliArgs { seed, received_log })
}

fn run() -> Result<(), String> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = parse_args(&argv)?;

    let mut server = DemoServer::new(args.seed);
    if let Some(path) = args.received_log {
        server = server
            .with_received_log(&path)
            .map_err(|e| format!("open received-log '{}': {e}", path.display()))?;
    }
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    serve_stdio(&server, BufReader::new(stdin.lock()), &mut stdout)
        .map_err(|e| format!("stdio serve loop failed: {e}"))?;
    stdout.flush().map_err(|e| format!("flush stdout: {e}"))?;
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("mcps-demo-server: {err}");
            ExitCode::FAILURE
        }
    }
}
