//! `mcps-demo-fileserver` binary entrypoint (MCPS-045).
//!
//! Runs the demo fileserver as a plain stdio MCP server: reads newline-delimited
//! JSON-RPC requests from stdin and writes one response line per request to
//! stdout. The demo root is selected with `--demo-root <DIR>` (required). Arg
//! parsing is std-only (no clap), consistent with the sibling stdio servers.
//!
//! Usage:
//!   mcps-demo-fileserver --demo-root <DIR>

use std::io::BufReader;
use std::io::Write;
use std::process::ExitCode;

use mcps_demo_fileserver::serve_stdio;
use mcps_demo_fileserver::FileServer;

fn parse_demo_root(argv: &[String]) -> Result<String, String> {
    let mut iter = argv.iter();
    let mut demo_root: Option<String> = None;
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--demo-root" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--demo-root requires a value".to_string())?;
                demo_root = Some(value.clone());
            }
            other => return Err(format!("unknown argument '{other}'")),
        }
    }
    demo_root.ok_or_else(|| "usage: mcps-demo-fileserver --demo-root <DIR>".to_string())
}

fn run() -> Result<(), String> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let demo_root = parse_demo_root(&argv)?;

    let server = FileServer::new(demo_root);
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
            eprintln!("mcps-demo-fileserver: {err}");
            ExitCode::FAILURE
        }
    }
}
