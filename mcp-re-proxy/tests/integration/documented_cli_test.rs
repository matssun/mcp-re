// SPDX-License-Identifier: Apache-2.0
//! The command line the sidecar guide teaches must be one the proxy will start with.
//!
//! `docs/sidecar-deployment-guide.md` is the guide for the shipped HTTP-profile sidecar.
//! Its worked example is what an operator copies, and it had drifted into a configuration
//! that could not start in five separate ways at once. Three refused values —
//! `--authz reference`, `--revocation-list`, `--replay-cache file` — and two required
//! flags absent: `--delegated-trust-epoch`, and `--target-uri`, which this test found on
//! its first run. None of that failed anything. The operator would have met it as a proxy
//! that refuses to boot, with no reason to suspect the document.
//!
//! # Why this runs the real parser
//!
//! Three ways a documented command line can be wrong: a flag that no longer exists, a
//! flag whose VALUE is refused, and a required flag that is missing.
//! `scripts/proxy_flag_doc_gate.py` catches the first by comparing spellings against
//! `cli.rs`, cheaply and across every document, and it cannot see the other two — checking
//! them syntactically would mean restating `unsafe_config_violations` in a second language
//! with no compiler between the copies.
//!
//! `cli::parse_args` followed by `ValidatedDeployment::try_from` is not a restatement of the
//! rule; it IS the rule, and it covers all three at once. Neither reads the filesystem, so
//! the guide's `/etc/mcp-re/...` paths need not exist for this to be a real check.
//!
//! # What it does not cover
//!
//! Only what the guide presents as a complete invocation. An excerpt — the Mode-C
//! cookbook's, say, which trails off in `...` and carries a `<placeholder>` — is not a
//! command line, and asserting it parses would mean inventing the parts the author left
//! out. Startup steps after validation (key files, TLS material, the trust store, opening
//! the replay tier) are equally out of scope: this asserts the configuration is
//! ADMISSIBLE, not that the deployment behind it exists.

use mcp_re_proxy::cli;

/// The guide, read from disk (runfiles under Bazel, workspace path under Cargo) rather
/// than `include_str!`-ed, so it is the committed document that is checked.
fn guide() -> String {
    let path = mcp_re_test_paths::resolve_runfile("MCP_RE_SIDECAR_GUIDE");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Every complete `mcp_re_proxy_cli` invocation in `markdown`, as argv.
///
/// Shell continuations are joined so a multi-line invocation is one command; a leading
/// `bazel run //target:mcp_re_proxy_cli --` is dropped along with anything before it, so
/// what remains is the proxy's own argv.
fn documented_invocations(markdown: &str) -> Vec<Vec<String>> {
    const LAUNCH: &str = "mcp_re_proxy_cli";
    let mut found = Vec::new();
    let mut in_fence = false;
    let mut block = String::new();
    for line in markdown.lines() {
        if line.trim_start().starts_with("```") {
            if in_fence {
                found.extend(invocations_in_block(&block, LAUNCH));
                block.clear();
            }
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            block.push_str(line);
            block.push('\n');
        }
    }
    found
}

fn invocations_in_block(block: &str, launch: &str) -> Vec<Vec<String>> {
    // Join `\`-continued lines into one logical command.
    let joined = block.replace("\\\n", " ");
    joined
        .lines()
        .filter_map(|command| {
            let start = command.find(launch)? + launch.len();
            let mut argv: Vec<String> = command[start..]
                .split_whitespace()
                .map(str::to_string)
                .collect();
            // Drop the launcher's own flags and the `--` that ends them.
            if let Some(sep) = argv.iter().position(|a| a == "--") {
                argv.drain(..=sep);
            }
            Some(argv)
        })
        .filter(|argv| !argv.is_empty())
        .collect()
}

/// The guide's worked example must parse AND pass the unsafe-configuration boundary.
///
/// Both halves matter and they fail differently. `parse_args` rejects a flag that no
/// longer exists or a value outside its enum; `ValidatedDeployment::try_from` is what refuses
/// an admissible-looking value the deployment may not use. The guide's example carried
/// defects of both kinds.
#[test]
fn the_sidecar_guides_worked_example_is_a_configuration_the_proxy_will_start_with() {
    let markdown = guide();
    let invocations = documented_invocations(&markdown);
    assert!(
        !invocations.is_empty(),
        "no `mcp_re_proxy_cli` invocation found in the sidecar guide. Either the worked \
         example was removed — in which case delete this test deliberately rather than \
         leaving it passing over nothing — or the way it is written changed and the \
         extraction above no longer sees it."
    );

    for argv in invocations {
        let rendered = argv.join(" ");
        let config = cli::parse_args(&argv).unwrap_or_else(|e| {
            panic!(
                "the sidecar guide documents a command line the parser rejects:\n  \
                 {rendered}\n\nparse_args said: {e}\n\nFix the guide, not this test."
            )
        });
        mcp_re_proxy::config_state::validation::ValidatedDeployment::try_from(config).unwrap_or_else(|e| {
            panic!(
                "the sidecar guide documents a command line that PARSES but is refused \
                 before serving:\n  {rendered}\n\nvalidation said: {e}\n\nFix the guide, \
                 not this test."
            )
        });
    }
}

/// The extraction must actually see a proxy invocation, and must ignore other commands.
///
/// Without this, a change to how the guide writes its example would silently reduce the
/// test above to asserting nothing — the failure mode the empty-check guards against, but
/// only if the extraction is known to work in the first place.
#[test]
fn the_extraction_finds_a_proxy_invocation_and_skips_other_commands() {
    let markdown = "\
```sh
cargo test -p mcp-re-proxy --features x
bazel run //mcp-re-proxy:mcp_re_proxy_cli -- \\
  --bind 127.0.0.1:8600 \\
  --audience did:example:server-1
helm upgrade mcp-re-proxy ./chart --set foo=bar
```
";
    let found = documented_invocations(markdown);
    assert_eq!(
        found.len(),
        1,
        "expected exactly one invocation, got {found:?}"
    );
    assert_eq!(
        found[0],
        vec![
            "--bind",
            "127.0.0.1:8600",
            "--audience",
            "did:example:server-1"
        ],
        "the launcher's own arguments must not be read as the proxy's"
    );
}
