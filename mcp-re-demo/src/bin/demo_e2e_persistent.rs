//! Runnable multi-process mTLS demonstration over the LONG-LIVED
//! `mcp-re-demo-server` (MCPS-066, MCP-RE-EPIC-P6.6B).
//!
//! The human-facing counterpart to `demo_e2e_persistent_test`: it stands up the
//! SAME full real-process topology with a PERSISTENT inner and drives several
//! authorized tool calls over one session plus one authorization-denied call,
//! then prints a clear success line.
//!
//! ```text
//! this process: DemoHostClient (HostSession) signs + mcp-re-transport mTLS POST
//!    │  real mTLS socket
//!    ▼
//! mcp_re_proxy_cli --inner-mode persistent  (SEPARATE OS process: mTLS, Core verify,
//!    │             freshness, durable replay, transport-binding EXACT, Phase-5
//!    │             authz=reference, sign response)
//!    │  ONE persistent stdio child, spawned + initialized ONCE
//!    ▼
//! mcp_re_demo_server_bin  (the long-lived MCP server; echo / list_items / reset_items)
//! ```
//!
//! Run it with (from `components/mcp-re`):
//!
//! ```sh
//! bazel run //mcp-re-demo:demo_e2e_persistent
//! ```
//!
//! Because `bazel run` has no test fixtures, this bin GENERATES the security
//! material at runtime via [`DemoFixtures`] and materializes the proxy's path-
//! based flags with `write_files`. The proxy binary and the demo-server binary
//! are delivered via Bazel runfiles; the bin resolves them from the
//! `$(rlocationpath ...)` env vars the BUILD target stamps — nothing is hardcoded.
//!
//! It fails LOUDLY (non-zero exit, clear message) on any error; the libraries it
//! drives never panic on bad input — they fail closed with a typed error which
//! this bin surfaces.

use std::io::Read;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Command;
use std::process::ExitCode;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use mcp_re_demo::assemble_assertions;
use mcp_re_demo::run_persistent_e2e;
use mcp_re_demo::server_response_public_key;
use mcp_re_demo::DemoFixtureFiles;
use mcp_re_demo::DemoFixtures;
use mcp_re_demo::PersistentE2eEvidence;

const SKEW_SECS: i64 = 300;
const REQUEST_LIFETIME_SECS: i64 = 600;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("demo_e2e_persistent FAILED: {err}");
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

    // 2. Spawn the real proxy CLI (persistent inner mode) and wait for readiness.
    let proxy = spawn_proxy(&fixtures)?;
    println!(
        "proxy-up addr={} inner=mcp_re_demo_server_bin inner_mode=persistent authz=reference \
         replay=file binding=exact",
        proxy.addr
    );

    // 3. Drive several authorized calls + one denied call over the mTLS socket.
    let outcome = run_persistent_e2e(
        &fixtures,
        proxy.addr,
        now_unix(),
        SKEW_SECS,
        REQUEST_LIFETIME_SECS,
    )
    .map_err(|e| format!("{e}"))?;

    // 4. Report each verified authorized round trip.
    for (i, call) in outcome.authorized.iter().enumerate() {
        println!(
            "authorized-call#{i} tool={} signer={} request_hash={} server_signer={} result={}",
            call.tool, call.signer, call.request_hash, call.server_signer, call.result,
        );
    }
    println!(
        "denied-call tool=reset_items reason={} (rejected before dispatch; persistent inner never forwarded)",
        outcome.denied_reason,
    );

    // 5. Assemble the MACHINE-CHECKED evidence from INDEPENDENT signals: the
    //    proxy's spawn-lifecycle stderr (spawn count), the inner server's own
    //    received-log (#3965 — which ids actually reached the inner), and a
    //    direct public-key verification of each response signature.
    let assertions = assemble_assertions(
        &outcome,
        &proxy.stderr_snapshot(),
        &proxy.inner_received_log(),
        &server_response_public_key(&fixtures),
    );
    let all_pass = assertions.all_pass();
    let evidence = PersistentE2eEvidence::from_assertions(assertions);

    // 6. Emit the evidence object as a single machine-readable JSON line.
    let rendered = serde_json::to_string(&evidence.to_json())
        .map_err(|e| format!("serialize evidence: {e}"))?;
    println!("{rendered}");

    if !all_pass {
        return Err(format!("evidence assertions did not all pass: {rendered}"));
    }
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

/// A spawned `mcp_re_proxy_cli` OS process, killed (and reaped — with its
/// persistent inner child) on drop. Its diagnostic stderr is drained into a
/// shared buffer (the `inner_spawned` lifecycle channel — the independent spawn-
/// count oracle), and the inner server writes its received-log under the same
/// temp dir (the independent "what actually reached the inner" oracle, #3965).
struct ProxyProcess {
    child: std::process::Child,
    addr: SocketAddr,
    stderr: Arc<Mutex<String>>,
    received_log_path: PathBuf,
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

impl ProxyProcess {
    /// The proxy's captured diagnostic stderr (the `inner_spawned` lifecycle log).
    fn stderr_snapshot(&self) -> String {
        self.stderr.lock().map(|s| s.clone()).unwrap_or_default()
    }

    /// The inner server's received-log content (#3965), empty if unwritten.
    fn inner_received_log(&self) -> String {
        std::fs::read_to_string(&self.received_log_path).unwrap_or_default()
    }
}

fn free_port() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind ephemeral: {e}"))?;
    Ok(listener.local_addr().map_err(|e| format!("addr: {e}"))?.port())
}

/// Spawn the real `mcp_re_proxy_cli --inner-mode persistent` wrapping the demo
/// server, then poll the port until it accepts.
fn spawn_proxy(fixtures: &DemoFixtures) -> Result<ProxyProcess, String> {
    let files = fixtures
        .write_files()
        .map_err(|e| format!("materialize fixture files: {e}"))?;
    let cli = resolve_runfile("MCP_RE_PROXY_CLI")?;
    let inner = resolve_runfile("DEMO_SERVER_BIN")?
        .to_string_lossy()
        .into_owned();
    let working_dir = std::env::temp_dir().to_string_lossy().into_owned();

    let port = free_port()?;
    let bind = format!("127.0.0.1:{port}");
    let addr: SocketAddr = bind.parse().map_err(|e| format!("addr: {e}"))?;

    let replay_dir = std::env::temp_dir().join(format!("mcp_re_persist_replay_{}", std::process::id()));
    std::fs::create_dir_all(&replay_dir).map_err(|e| format!("mkdir replay dir: {e}"))?;
    let replay_path = replay_dir.join("replay.json");
    // The inner server's received-log (#3965): the proxy forwards these trailing
    // args verbatim to the inner (`--inner-command` consumes the remainder of
    // argv), so the long-lived inner records every tools/call it ACTUALLY runs.
    let received_log_path = replay_dir.join("inner_received.log");

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
            "--max-client-cert-lifetime",
            "175200h",
            "--inner-mode",
            "persistent",
            "--inner-working-dir",
            &working_dir,
            // `--inner-command` consumes the remainder of argv: the inner binary
            // plus its OWN `--received-log` flag, so the long-lived inner records
            // every tools/call it actually serves.
            "--inner-command",
            &inner,
            "--received-log",
            &received_log_path.to_string_lossy(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn mcp_re_proxy_cli: {e}"))?;

    // Drain the proxy's stderr into a shared buffer: it emits `inner_spawned`
    // here the instant it launches the persistent inner — the independent
    // spawn-count oracle.
    let stderr = Arc::new(Mutex::new(String::new()));
    if let Some(mut pipe) = child.stderr.take() {
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
    }

    let mut up = false;
    for _ in 0..400 {
        if TcpStream::connect(addr).is_ok() {
            up = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    if !up {
        return Err(format!("mcp_re_proxy_cli did not start listening on {addr}"));
    }

    Ok(ProxyProcess {
        child,
        addr,
        stderr,
        received_log_path,
        _files: files,
        _replay_dir: replay_dir,
    })
}
