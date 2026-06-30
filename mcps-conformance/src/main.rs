//! MCP-S conformance CLI (MCPS-010).
//!
//! Usage:
//!   mcps-conformance object [--vectors-dir DIR] [--profile core] [--json]
//!
//! Runs the in-process object suite (committed vectors directly against
//! `mcps-core`) and prints the report (human by default, JSON with `--json`).
//! Exits non-zero if any case fails. Arg parsing is std-only — no clap.

use std::path::PathBuf;
use std::process::ExitCode;

use mcps_conformance::load_from_dir;
use mcps_conformance::run_suite;
use mcps_conformance::ObjectTarget;

/// Default vectors directory for local `cargo run` (workspace-relative). The
/// bazel TEST target does NOT use this path — it embeds the vectors at compile
/// time (see `tests/object_suite_test.rs`).
const DEFAULT_VECTORS_DIR: &str = "../mcps-core/tests/vectors";

struct Args {
    vectors_dir: PathBuf,
    json: bool,
}

fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut iter = argv.iter();
    let subcommand = iter.next().ok_or_else(|| {
        "usage: mcps-conformance object [--vectors-dir DIR] [--profile core] [--json]".to_string()
    })?;
    if subcommand != "object" {
        return Err(format!(
            "unknown subcommand '{subcommand}' (only 'object' is implemented in MCPS-010)"
        ));
    }

    let mut vectors_dir = PathBuf::from(DEFAULT_VECTORS_DIR);
    let mut json = false;

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--json" => json = true,
            "--vectors-dir" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--vectors-dir requires a value".to_string())?;
                vectors_dir = PathBuf::from(value);
            }
            "--profile" => {
                // Accepted for forward-compat; only the core profile exists.
                let value = iter
                    .next()
                    .ok_or_else(|| "--profile requires a value".to_string())?;
                if value != "core" {
                    return Err(format!("unsupported profile '{value}' (only 'core')"));
                }
            }
            other => return Err(format!("unknown argument '{other}'")),
        }
    }

    Ok(Args { vectors_dir, json })
}

fn run() -> Result<bool, String> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = parse_args(&argv)?;

    let cases = load_from_dir(&args.vectors_dir)?;
    let report = run_suite(&ObjectTarget::new(), &cases);

    if args.json {
        println!("{}", report.to_json_string()?);
    } else {
        print!("{}", report.to_human_string());
    }
    Ok(report.all_passed())
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(err) => {
            eprintln!("mcps-conformance: {err}");
            ExitCode::FAILURE
        }
    }
}
