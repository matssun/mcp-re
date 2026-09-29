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
//! This guard encodes exactly that split. It is scoped to what `mcp-re-core`
//! links — the crates in its dependency closure, direct and transitive — read off
//! the build graph by the `mcp_re_core_dependency_closure` genquery; the proxy is
//! deliberately NOT guarded here — its use of the async stack is the sanctioned
//! carve-out, not a violation.
//!
//! The closure is a runfile of this test, so the test reruns whenever the graph it
//! describes changes.

fn dependency_closure() -> String {
    let path = mcp_re_test_paths::resolve_runfile("MCP_RE_CORE_DEPENDENCY_CLOSURE");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"))
}

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
    "notify", "memmap", "memmap2", "walkdir", "tempfile", "fs-err", "fs_err",
];

/// Higher MCP-RE crates, by Bazel package. `mcp-re-core` is the BASE of the stack —
/// it must depend on nothing else in the workspace; every other crate depends on it,
/// never the reverse.
const FORBIDDEN_UPSTACK_CRATES: &[&str] = &[
    "mcp-re-proxy",
    "mcp-re-http-profile",
    "mcp-re-transport",
    "mcp-re-host",
    "mcp-re-policy",
    "mcp-re-client-core",
];

/// The crate a closure label names, spelled with hyphens: the hub repository's
/// `<crate>-<version>` for a third-party crate (`…crates_mcp_re__ed25519-dalek-3.0.0//:…`),
/// the package for a first-party one (`//mcp-re-core:mcp_re_core`).
fn crate_of(label: &str) -> Option<String> {
    if let Some(package) = label.strip_prefix("//") {
        return package.split(':').next().map(str::to_string);
    }
    let repo = label.split("//").next()?;
    let (_, crate_and_version) = repo.rsplit_once("__")?;
    // The version starts at the first `-` followed by a digit; a pre-release suffix
    // (`1.0.0-rc.1`) has further hyphens after it.
    let split = crate_and_version
        .match_indices('-')
        .map(|(at, _)| at)
        .find(|&at| crate_and_version[at + 1..].starts_with(|c: char| c.is_ascii_digit()))?;
    Some(crate_and_version[..split].replace('_', "-"))
}

/// Every crate the closure names, hyphenated and lowercased. Matching is on WHOLE
/// crate names, so `getrandom` or `serde_json` can never trip a substring like
/// "rand" or "async".
fn closure_crates(closure: &str) -> std::collections::BTreeSet<String> {
    closure
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(crate_of)
        .map(|name| name.to_ascii_lowercase())
        .collect()
}

#[test]
fn mcp_re_core_stays_pure_no_networking_async_fs_or_upstack_dependencies() {
    let crates = closure_crates(&dependency_closure());

    // Positive sanity: the legitimate pure-crypto/serialization deps ARE present,
    // proving the reader actually parsed the closure (a guard that parses nothing
    // would vacuously pass), and the closure is transitive: `curve25519-dalek` is
    // reached only through `ed25519-dalek`.
    for present in [
        "mcp-re-core",
        "serde-json",
        "ed25519-dalek",
        "sha2",
        "base64",
        "curve25519-dalek",
    ] {
        assert!(
            crates.contains(present),
            "{present} is not in mcp-re-core's dependency closure {crates:?}"
        );
    }

    let offenders: Vec<&str> = FORBIDDEN_ASYNC_NETWORKING_CRATES
        .iter()
        .chain(FORBIDDEN_FS_CRATES)
        .chain(FORBIDDEN_UPSTACK_CRATES)
        .copied()
        .filter(|forbidden| crates.contains(&forbidden.replace('_', "-").to_ascii_lowercase()))
        .collect();

    assert!(
        offenders.is_empty(),
        "mcp-re-core MUST stay pure (ADR-MCPS-011/012; ADR-MCPRE-051): forbidden \
         networking/async/fs/up-stack crate(s) in the crates it links: {offenders:?}. \
         The async stack (tokio/hyper/tokio-rustls) is admitted into the PROXY serving \
         path only, never into the verification core."
    );
}
