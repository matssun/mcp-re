// SPDX-License-Identifier: Apache-2.0
//! The `mcp-re-client` CLI: parse, build, verify the trust picture, serve.
//!
//! All wiring lives in the library (and is unit-tested there); this shell reads the
//! configuration, performs the fail-closed startup load, starts the anchor refresher,
//! and runs the local listener until a signal.

use std::process::ExitCode;

use mcp_re_client::config::ClientConfig;

/// Everything between the command line and the serving loop: what was asked for, and what
/// running until shutdown means.
mod startup;

use startup::now_unix;
use startup::parse_invocation;
use startup::serve_until_shutdown;

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
    let invocation = match parse_invocation(&args) {
        Ok(invocation) => invocation,
        Err(code) => return code,
    };
    let config = match ClientConfig::read(std::path::Path::new(&invocation.config_path)) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    // The startup load is fail-closed: a client that cannot establish which roots it
    // trusts has no basis to verify anything.
    let built = match mcp_re_client::build(&config, now_unix()) {
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
    if invocation.check_only {
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
    serve_until_shutdown(&config, built, listener)
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
