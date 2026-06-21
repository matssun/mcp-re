//! Runnable multi-process mTLS positive-path demonstration (MCPS-056, Phase 6.6,
//! epic #3948).
//!
//! The human-facing counterpart to the hermetic `demo_e2e_test`: it stands up the
//! SAME full real-process topology and drives the authorized happy path (matrix
//! P1), then prints a clear success line.
//!
//! ```text
//! this process: DemoHostClient (HostSession) signs + mcps-transport mTLS POST
//!    │  real mTLS socket
//!    ▼
//! mcps_proxy_cli  (SEPARATE OS process spawned here: mTLS, Core verify, freshness,
//!    │             durable replay, transport-binding EXACT, Phase-5 authz=reference,
//!    │             strip/inject, sign response)
//!    │  stdio, one subprocess per request
//!    ▼
//! mcps_demo_fileserver_bin  (the ordinary inner MCP server; list_files over demo_root/)
//! ```
//!
//! Run it with (from `components/mcps`):
//!
//! ```sh
//! bazel run //mcps-demo:demo_e2e
//! ```
//!
//! Because `bazel run` has no test fixtures, this bin GENERATES the security
//! material at runtime via [`DemoFixtures`] and materializes the proxy's path-
//! based flags with `write_files`. The proxy binary, the inner fileserver binary,
//! and the committed `demo_root/` fixture are delivered via Bazel runfiles; the
//! bin resolves them from the `$(rlocationpath ...)` env vars the BUILD target
//! stamps — nothing is hardcoded.
//!
//! It fails LOUDLY (non-zero exit, clear message) on any error; the libraries it
//! drives never panic on bad input — they fail closed with a typed error which
//! this bin surfaces.

use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Command;
use std::process::ExitCode;
use std::process::Stdio;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use mcps_demo::run_positive_e2e;
use mcps_demo::DemoFixtureFiles;
use mcps_demo::DemoFixtures;

const SKEW_SECS: i64 = 300;
const REQUEST_LIFETIME_SECS: i64 = 600;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("demo_e2e FAILED: {err}");
            ExitCode::FAILURE
        }
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn run() -> Result<(), String> {
    // 1. Generate the full, internally-consistent demo material at runtime.
    let fixtures = DemoFixtures::generate_default();

    // 2. Spawn the real proxy CLI as a SEPARATE OS process and wait for readiness.
    let proxy = spawn_proxy(&fixtures)?;
    println!(
        "proxy-up addr={} inner=mcps_demo_fileserver_bin authz=reference replay=file binding=exact",
        proxy.addr
    );

    // 3. Drive the authorized P1 flow over the real mTLS socket.
    let outcome = run_positive_e2e(
        &fixtures,
        proxy.addr,
        now_unix(),
        SKEW_SECS,
        REQUEST_LIFETIME_SECS,
    )
    .map_err(|e| format!("{e}"))?;

    // 4. Report the verified result.
    println!(
        "response-verified signer={} audience={} request_hash={} authorization_hash={} \
         server_signer={} tool=list_files path=reports entries={:?}",
        outcome.signer,
        outcome.audience,
        outcome.request_hash,
        outcome.authorization_hash,
        outcome.server_signer,
        outcome.entries,
    );
    println!(
        "OK: authorized list_files round-tripped client -> mcps_proxy_cli (separate process, \
         real mTLS) -> mcps_demo_fileserver_bin -> client; transport-binding exact satisfied \
         (mTLS identity == request signer)"
    );
    Ok(())
}

/// Resolve a runfiles-relative path delivered via an `$(rlocationpath ...)` env
/// var. Under `bazel run` no runfiles env var is set but the cwd is the runfiles
/// `_main` dir, so try the cwd and its parent before the bare relative path.
fn resolve_runfile(env_key: &str) -> Result<PathBuf, String> {
    let rel = std::env::var(env_key)
        .map_err(|_| format!("{env_key} must be set by the BUILD target (run via `bazel run`)"))?;
    let mut candidates: Vec<PathBuf> = Vec::new();
    for root_key in ["TEST_SRCDIR", "RUNFILES_DIR"] {
        if let Ok(root) = std::env::var(root_key) {
            candidates.push(PathBuf::from(&root).join(&rel));
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join(&rel));
        if let Some(parent) = cwd.parent() {
            candidates.push(parent.join(&rel));
        }
    }
    candidates.push(PathBuf::from(&rel));
    candidates
        .into_iter()
        .find(|c| c.exists())
        .ok_or_else(|| format!("cannot locate runfile via {env_key}='{rel}'"))
}

/// A spawned `mcps_proxy_cli` OS process, killed (and reaped) on drop.
struct ProxyProcess {
    child: std::process::Child,
    addr: SocketAddr,
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

fn free_port() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind ephemeral: {e}"))?;
    Ok(listener.local_addr().map_err(|e| format!("addr: {e}"))?.port())
}

/// Spawn the real `mcps_proxy_cli` with the full P1 flag set wrapping the demo
/// fileserver, then poll the port until it accepts.
fn spawn_proxy(fixtures: &DemoFixtures) -> Result<ProxyProcess, String> {
    let files = fixtures
        .write_files()
        .map_err(|e| format!("materialize fixture files: {e}"))?;
    let cli = resolve_runfile("MCPS_PROXY_CLI")?;
    let inner = resolve_runfile("INNER_FILESERVER_BIN")?
        .to_string_lossy()
        .into_owned();
    let root = resolve_runfile("DEMO_ROOT_README")?
        .parent()
        .ok_or("readme.txt has no parent")?
        .to_string_lossy()
        .into_owned();

    let port = free_port()?;
    let bind = format!("127.0.0.1:{port}");
    let addr: SocketAddr = bind.parse().map_err(|e| format!("addr: {e}"))?;

    let replay_dir = std::env::temp_dir().join(format!("mcps_e2e_replay_{}", std::process::id()));
    std::fs::create_dir_all(&replay_dir).map_err(|e| format!("mkdir replay dir: {e}"))?;
    let replay_path = replay_dir.join("replay.json");

    let child = Command::new(&cli)
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
            "--max-client-cert-lifetime",
            "175200h",
            "--inner-working-dir",
            &root,
            "--inner-command",
            &inner,
            "--demo-root",
            &root,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn mcps_proxy_cli: {e}"))?;

    let mut up = false;
    for _ in 0..400 {
        if TcpStream::connect(addr).is_ok() {
            up = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    if !up {
        return Err(format!("mcps_proxy_cli did not start listening on {addr}"));
    }

    Ok(ProxyProcess {
        child,
        addr,
        _files: files,
        _replay_dir: replay_dir,
    })
}
