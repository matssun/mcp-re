//! Multi-process positive-path E2E over real mTLS (MCPS-056, Phase 6.6, epic
//! #3948) — the keystone hermetic test.
//!
//! This proves the FULL real-process topology, not an in-process server:
//!
//! ```text
//! this test process: DemoHostClient (HostSession) signs + mcp-re-transport mTLS POST
//!    │  real mTLS socket (127.0.0.1:<ephemeral>)
//!    ▼
//! mcp_re_proxy_cli  (SEPARATE OS process spawned here: mTLS terminate + verify,
//!    │             Core verify, freshness, durable replay, transport-binding EXACT,
//!    │             Phase-5 authz=reference, strip caller .verified / inject sidecar
//!    │             verified context, sign response)
//!    │  stdio, one subprocess per request
//!    ▼
//! mcp_re_demo_fileserver_bin  (the ordinary inner MCP server; list_files over demo_root/)
//! ```
//!
//! It exercises matrix **P1**: ONE authorized `list_files` on the `reports/`
//! fixture subdirectory succeeds end to end; the signed response verifies against
//! the request hash the `HostSession` STORED at sign time; the mTLS client
//! identity (the client cert's URI SAN) EQUALS the request signer, so the proxy's
//! `--transport-binding exact` is SATISFIED — not bypassed; and the returned
//! fixture entries prove the inner fileserver actually executed.
//!
//! All security material comes from the shared [`DemoFixtures`] (#3942) and is
//! materialized to files for the proxy's path-based flags. The proxy binary, the
//! inner fileserver binary, and the committed `demo_root/` fixture are delivered
//! via Bazel runfiles (`data` deps) and resolved via the `$(rlocationpath ...)`
//! env vars — no hardcoded path, no cargo. The proxy subprocess is killed on test
//! end via a Drop guard, and readiness is a TCP port probe (no sleep-only sync),
//! matching `mcp-re-proxy/tests/full_stack_test.rs`.

use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use mcp_re_demo::run_positive_e2e;
use mcp_re_demo::DemoFixtureFiles;
use mcp_re_demo::DemoFixtures;
use mcp_re_demo::E2E_PATH;

const SKEW_SECS: i64 = 300;
const REQUEST_LIFETIME_SECS: i64 = 600;

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Resolve a runfiles-relative path delivered via an `$(rlocationpath ...)` env
/// var against the runfiles roots, returning the first candidate that exists.
fn resolve_runfile(env_key: &str) -> PathBuf {
    mcp_re_test_paths::resolve_runfile(env_key)
}

fn proxy_cli() -> PathBuf {
    resolve_runfile("MCP_RE_PROXY_CLI")
}
fn inner_binary() -> String {
    resolve_runfile("INNER_FILESERVER_BIN")
        .to_string_lossy()
        .into_owned()
}
fn demo_root() -> String {
    resolve_runfile("DEMO_ROOT_README")
        .parent()
        .expect("readme.txt has a parent")
        .to_string_lossy()
        .into_owned()
}

/// Parse the proxy's OS-resolved listen address from its startup marker
/// `mcp-re-proxy: listening on <addr> (PEP; …)`. Requires the trailing space so a
/// partially-captured line never yields a truncated address.
fn parse_listening_addr(stderr: &str) -> Option<SocketAddr> {
    let marker = "mcp-re-proxy: listening on ";
    let start = stderr.find(marker)? + marker.len();
    let rest = &stderr[start..];
    let end = rest.find(' ')?;
    rest[..end].parse().ok()
}

/// A spawned `mcp_re_proxy_cli` OS process, killed (and reaped) on drop.
struct ProxyProcess {
    child: std::process::Child,
    addr: SocketAddr,
    // Held for the lifetime of the proxy so the path-based fixture files (and the
    // durable replay-cache dir) outlive it; dropped (cleaned up) after the proxy.
    _files: DemoFixtureFiles,
    _replay_dir: PathBuf,
}

impl Drop for ProxyProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self._replay_dir);
    }
}

/// Spawn the real `mcp_re_proxy_cli` as its OWN process with the full P1 flag set
/// (mTLS, `--authz reference`, `--replay-cache file`, `--transport-binding
/// exact`, inner = the demo fileserver pointed at `demo_root`), then poll the
/// port until it accepts. Panics if it never starts listening.
fn spawn_proxy(fixtures: &DemoFixtures) -> ProxyProcess {
    let files = fixtures.write_files().expect("materialize fixture files");
    let cli = proxy_cli();
    let inner = inner_binary();
    let root = demo_root();

    // Let the PROXY pick the port (bind :0, read it back from the startup
    // marker) — deletes the free_port() bind-after-free TOCTOU (MCPS-087).
    let bind = "127.0.0.1:0".to_string();

    // A private durable replay-cache file (P1 uses `--replay-cache file`).
    let replay_dir = std::env::temp_dir().join(format!("mcp_re_e2e_replay_{}", std::process::id()));
    std::fs::create_dir_all(&replay_dir).expect("mkdir replay dir");
    let replay_path = replay_dir.join("replay.json");

    let mut child = Command::new(&cli)
        .args([
            "--bind",
            &bind,
            "--audience",
            fixtures.audience(),
            "--server-signer",
            fixtures.server_signer(),
            "--server-key-id",
            fixtures.server_key_id(),
            "--max-clock-skew",
            &SKEW_SECS.to_string(),
            "--key-source",
            "file",
            "--signing-key-seed",
            &files.signing_seed_path().to_string_lossy(),
            "--tls-cert",
            &files.server_cert_path().to_string_lossy(),
            "--tls-key",
            &files.server_key_path().to_string_lossy(),
            "--client-ca",
            &files.client_ca_path().to_string_lossy(),
            "--trust",
            &files.trust_path().to_string_lossy(),
            "--replay-cache",
            "file",
            "--replay-path",
            &replay_path.to_string_lossy(),
            "--transport-binding",
            "exact",
            "--transport-identity-source",
            "uri_san",
            "--authz",
            "reference",
            "--allow-reference-authz",
            "--allow-empty-revocation",
            // Generous client-cert lifetime ceiling so the bounded (~15y) fixture
            // client cert passes; lifetime ENFORCEMENT (T4) is full_stack_test's job.
            "--max-client-cert-lifetime",
            "175200h",
            // The inner stdio server: the demo fileserver pointed at the demo root.
            // `--inner-command` consumes the remainder of argv.
            "--inner-working-dir",
            &root,
            "--inner-command",
            &inner,
            "--demo-root",
            &root,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        // stderr PIPED + drained: readiness is gated on the proxy's startup
        // marker (so we never open a connection-consuming probe), and a spawn
        // failure surfaces the captured diagnostic in the panic below. The drain
        // thread runs detached to EOF so the pipe never backs up.
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mcp_re_proxy_cli");

    let stderr = Arc::new(Mutex::new(String::new()));
    let mut pipe = child.stderr.take().expect("piped stderr");
    let sink = Arc::clone(&stderr);
    std::thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        loop {
            match pipe.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    if let Ok(mut buf) = sink.lock() {
                        buf.push_str(&String::from_utf8_lossy(&chunk[..n]));
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Readiness without a connection-consuming probe: wait for the proxy's
    // startup marker (printed after bind) and read the OS-resolved address from
    // it; fail fast if the proxy exits before listening. See MCPS-087.
    let mut addr: Option<SocketAddr> = None;
    for _ in 0..1200 {
        if let Some(parsed) = stderr.lock().ok().and_then(|buf| parse_listening_addr(&buf)) {
            addr = Some(parsed);
            break;
        }
        if let Ok(Some(status)) = child.try_wait() {
            let captured = stderr.lock().map(|b| b.clone()).unwrap_or_default();
            panic!("mcp_re_proxy_cli exited before listening (status {status}):\n{captured}");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let addr = addr.expect("mcp_re_proxy_cli did not report a listening address within budget");

    ProxyProcess {
        child,
        addr,
        _files: files,
        _replay_dir: replay_dir,
    }
}

/// P1 — the authorized multi-process positive path over real mTLS.
#[test]
fn positive_path_multi_process_mtls_round_trip() {
    let fixtures = DemoFixtures::generate_default();
    let proxy = spawn_proxy(&fixtures);

    let outcome = run_positive_e2e(
        &fixtures,
        proxy.addr,
        now_unix(),
        SKEW_SECS,
        REQUEST_LIFETIME_SECS,
    )
    .expect("authorized P1 multi-process mTLS round trip must succeed");

    // The signed response verified against the STORED request hash (the runner
    // returns the stored hash only on a successful bind), and the response was
    // signed by the proxy's configured server signer.
    assert_eq!(
        outcome.server_signer,
        fixtures.server_signer(),
        "the verified response must be signed by the proxy's server signer"
    );
    assert!(
        !outcome.request_hash.is_empty(),
        "a verified round trip carries the bound request hash"
    );

    // The mTLS client identity == the request signer: the proxy ran with
    // `--transport-binding exact`, so a verified (non-error) response is only
    // possible because the binding was SATISFIED, not bypassed.
    assert_eq!(
        outcome.signer,
        fixtures.signer(),
        "the request signer (== the mTLS client cert URI SAN) drove the call"
    );

    // The inner fileserver actually executed: the committed `reports/` fixture
    // entries (q1.txt, q2.txt) came back through the proxy.
    assert!(
        outcome.entries.iter().any(|n| n == "q1.txt"),
        "expected the reports/ fixture entry q1.txt; got {:?}",
        outcome.entries
    );
    assert!(
        outcome.entries.iter().any(|n| n == "q2.txt"),
        "expected the reports/ fixture entry q2.txt; got {:?}",
        outcome.entries
    );
    assert_eq!(E2E_PATH, "reports");
}
