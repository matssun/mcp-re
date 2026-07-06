//! `mcp-re-stdio-server` — a documented MCP-RE server over stdio (MCPS-012/017).
//!
//! Reads newline-delimited JSON-RPC requests from stdin and writes one signed
//! MCP-RE response (or JSON-RPC error object) line per request to stdout.
//!
//! Usage:
//!   mcp-re-stdio-server --now-unix <SECONDS> [--mode native|proxy]
//!
//! `--now-unix` pins the verification clock so frozen conformance vectors verify
//! deterministically. `--mode` selects the native echo server (default) or the
//! sidecar proxy fronting an unmodified inner echo (MCPS-017 parity). Arg
//! parsing is std-only (no clap), consistent with the object CLI.

use std::io::BufReader;
use std::io::Write;
use std::process::ExitCode;

use mcp_re_conformance::build_server;
use mcp_re_conformance::serve_stdio;
use mcp_re_conformance::ServerKind;

struct Args {
    now_unix: i64,
    kind: ServerKind,
}

fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut iter = argv.iter();
    let mut now_unix: Option<i64> = None;
    let mut kind = ServerKind::Native;
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--now-unix" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--now-unix requires a value".to_string())?;
                now_unix = Some(
                    value
                        .parse::<i64>()
                        .map_err(|e| format!("--now-unix not an integer: {e}"))?,
                );
            }
            "--mode" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--mode requires a value".to_string())?;
                kind = ServerKind::from_mode(value)
                    .ok_or_else(|| format!("--mode must be native|proxy, got '{value}'"))?;
            }
            other => return Err(format!("unknown argument '{other}'")),
        }
    }
    let now_unix = now_unix.ok_or_else(|| {
        "usage: mcp-re-stdio-server --now-unix <SECONDS> [--mode native|proxy]".to_string()
    })?;
    Ok(Args { now_unix, kind })
}

fn run() -> Result<(), String> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = parse_args(&argv)?;

    let server = build_server(args.kind);
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    serve_stdio(
        server.as_ref(),
        args.now_unix,
        BufReader::new(stdin.lock()),
        &mut stdout,
    )
    .map_err(|e| format!("stdio serve loop failed: {e}"))?;
    stdout.flush().map_err(|e| format!("flush stdout: {e}"))?;
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("mcp-re-stdio-server: {err}");
            ExitCode::FAILURE
        }
    }
}
