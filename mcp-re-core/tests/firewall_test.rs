// SPDX-License-Identifier: Apache-2.0
//! The `mcp-re-core` purity firewall (ADR-MCPS-011/012; ADR-MCPRE-051
//! "Compliance and Enforcement").
//!
//! `mcp-re-core` is the embeddable security core: pure, synchronous, per-request
//! Ed25519 signature verification + freshness, with **no networking, no async
//! runtime, and no filesystem access**. ADR-MCPRE-051 admits the async stack
//! (`tokio`/`hyper`/`tokio-rustls`) into the *proxy serving path* ONLY, and keeps
//! this core clean — "the firewall test is updated: `mcp-re-core` MUST remain pure
//! (no networking/async/fs); the proxy serving path MAY use the async stack."
//!
//! This guard encodes exactly that split. It is scoped to `mcp-re-core`'s own
//! declared dependencies; the proxy is deliberately NOT guarded here — its use of
//! the async stack is the sanctioned carve-out, not a violation. The sibling guard
//! `mcp_re_host_carries_no_networking_or_async_dependencies` enforces the same
//! discipline for `mcp-re-host`.
//!
//! The manifest and BUILD file are baked in at COMPILE time (`include_str!` +
//! `compile_data` in BUILD.bazel), so the guard runs fully inside the bazel test
//! sandbox with no runfiles wiring, and identically under `cargo test`.

const CARGO_TOML: &str = include_str!("../Cargo.toml");
const BUILD_BAZEL: &str = include_str!("../BUILD.bazel");

/// Networking / async crate substrings that must NEVER appear in `mcp-re-core`'s
/// declared dependencies. Matching is on whole crate-name tokens (see
/// [`name_tokens`]) so an innocuous substring (e.g. "core", "rand") cannot
/// false-positive. This is the ADR-MCPRE-051 async stack plus the broader
/// networking/async family the pure core must never pull in.
const FORBIDDEN_ASYNC_NETWORKING_CRATES: &[&str] = &[
    // Async runtimes / reactors.
    "tokio",
    "tokio-util",
    "async-std",
    "async_std",
    "smol",
    "mio",
    "futures",
    "futures-util",
    "futures-executor",
    // HTTP / RPC / web.
    "reqwest",
    "hyper",
    "hyper-util",
    "axum",
    "actix",
    "actix-web",
    "warp",
    "tower",
    "tower-http",
    "tonic",
    // TLS / transport security.
    "rustls",
    "tokio-rustls",
    "native-tls",
    "openssl",
    // Wire protocols / sockets / DNS / websockets.
    "h2",
    "h3",
    "quinn",
    "socket2",
    "trust-dns",
    "tungstenite",
    "tokio-tungstenite",
];

/// Filesystem-access crates the pure core must never pull in. `std::fs`/`std::net`
/// cannot be dep-scanned, but the crates that make fs/network access ergonomic
/// (watchers, mmap, temp dirs, path walking) are a reliable proxy — none belongs
/// in a networking/async/fs-free verification core.
const FORBIDDEN_FS_CRATES: &[&str] = &[
    "notify",
    "memmap",
    "memmap2",
    "walkdir",
    "tempfile",
    "fs-err",
    "fs_err",
];

/// Higher MCP-RE crates. `mcp-re-core` is the BASE of the stack — it must depend on
/// nothing else in the workspace; every other crate depends on it, never the
/// reverse. Both the hyphenated Cargo name and the underscored Bazel target name
/// are listed so a dependency in either manifest is caught.
const FORBIDDEN_UPSTACK_CRATES: &[&str] = &[
    "mcp-re-proxy",
    "mcp_re_proxy",
    "mcp-re-http-profile",
    "mcp_re_http_profile",
    "mcp-re-transport",
    "mcp_re_transport",
    "mcp-re-host",
    "mcp_re_host",
    "mcp-re-policy",
    "mcp_re_policy",
    "mcp-re-client-core",
    "mcp_re_client_core",
];

/// Strip `#` line comments (TOML and Starlark both use them). Dependency
/// declarations never live in a comment, but prose comments legitimately NAME
/// forbidden crates (e.g. this crate's manifest says "no tokio/reqwest/axum") —
/// tokenizing those would self-poison the guard with false positives. We cut each
/// line at its first `#`; no dependency line in these manifests contains one.
fn strip_line_comments(text: &str) -> String {
    text.lines()
        .map(|line| match line.find('#') {
            Some(idx) => &line[..idx],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Split text into crate-name tokens (alphanumerics plus `-` / `_`), lowercased.
/// A forbidden crate is flagged only on a WHOLE-token match, so `getrandom` or
/// `serde_json` can never trip a substring like "rand" or "async".
fn name_tokens(text: &str) -> std::collections::BTreeSet<String> {
    let mut tokens = std::collections::BTreeSet::new();
    let mut current = String::new();
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            current.push(ch.to_ascii_lowercase());
        } else if !current.is_empty() {
            tokens.insert(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        tokens.insert(current);
    }
    tokens
}

#[test]
fn mcp_re_core_stays_pure_no_networking_async_fs_or_upstack_dependencies() {
    // Guard inputs are non-empty (a renamed/empty file cannot silently pass).
    assert!(
        CARGO_TOML.contains("[dependencies]"),
        "Cargo.toml has a [dependencies] section"
    );
    assert!(
        BUILD_BAZEL.contains("nt_rust_library"),
        "BUILD.bazel declares the library"
    );

    let cargo_tokens = name_tokens(&strip_line_comments(CARGO_TOML));
    let build_tokens = name_tokens(&strip_line_comments(BUILD_BAZEL));

    let mut offenders: Vec<String> = Vec::new();
    let all_forbidden = FORBIDDEN_ASYNC_NETWORKING_CRATES
        .iter()
        .chain(FORBIDDEN_FS_CRATES)
        .chain(FORBIDDEN_UPSTACK_CRATES);
    for forbidden in all_forbidden {
        let token = forbidden.to_ascii_lowercase();
        if cargo_tokens.contains(&token) {
            offenders.push(format!("{forbidden} (Cargo.toml)"));
        }
        if build_tokens.contains(&token) {
            offenders.push(format!("{forbidden} (BUILD.bazel)"));
        }
    }

    assert!(
        offenders.is_empty(),
        "mcp-re-core MUST stay pure (ADR-MCPS-011/012; ADR-MCPRE-051): forbidden \
         networking/async/fs/up-stack crate(s) found in its dependency declarations: \
         {offenders:?}. The async stack (tokio/hyper/tokio-rustls) is admitted into the \
         PROXY serving path only, never into the verification core."
    );

    // Positive sanity: the legitimate pure-crypto/serialization deps ARE present,
    // proving the tokenizer actually parsed the dependency declarations (a guard
    // that parses nothing would vacuously pass).
    assert!(cargo_tokens.contains("serde_json"), "serde_json dep present");
    assert!(
        cargo_tokens.contains("ed25519-dalek"),
        "ed25519-dalek dep present"
    );
    assert!(cargo_tokens.contains("sha2"), "sha2 dep present");
    assert!(cargo_tokens.contains("base64"), "base64 dep present");
}
