//! Multi-process DEPLOYMENT-POSTURE proofs over the REAL `mcps_proxy_cli` binary
//! (MCPS-059, Phase 6.6, epic #3948) — the C1/C2 scenarios of the test plan.
//!
//! These two cases are STARTUP / DURABILITY posture, not request-path security:
//!
//!   * C1 — env-keysource refusal. The production binary treats environment-
//!     variable key material as dev/CI-only. Two layers gate it: (a) `parse_args`
//!     refuses `--key-source env` unless `--allow-env-keysource` is passed; and
//!     (b) MCPS-076 (audit gap G-3) gates `EnvKeySource` itself behind the
//!     NON-DEFAULT `dev_env_key_source` cargo feature, so the PRODUCTION
//!     `mcps_proxy_cli` (built without that feature) FAILS CLOSED on env key
//!     material EVEN WITH the runtime opt-in. We prove both: WITHOUT the opt-in the
//!     parse-time gate fires (naming `--allow-env-keysource`); WITH the opt-in the
//!     compile-time gate fires (naming the `dev_env_key_source` feature rebuild).
//!     Either way: non-zero exit, refusal diagnostic, and NO listening socket. The
//!     POSITIVE control that an env key source can actually load lives in the
//!     feature-built `//mcps-proxy:dev_env_key_source_test`. This is the anchor for
//!     the Phase 7 #3842 strict-mode work.
//!
//!   * C2 — replay durability across a proxy RESTART. With `--replay-cache file
//!     --replay-path <p>` a valid request succeeds against a first proxy process;
//!     we then STOP that process, START a NEW proxy process pointing at the SAME
//!     `--replay-path`, and replay the IDENTICAL signed bytes. The durable cache
//!     survives the restart, so the replay is still `replay_detected`. (The
//!     across-CONNECTION case is `demo_negative_e2e_test` A3; this is the
//!     across-PROCESS case.)
//!
//! Reuses the shared [`DemoFixtures`] (#3942) material, the `mcps-transport`
//! verifying client, and the `mcps-host` HostSession, exactly like the positive
//! (#3943) and negative (#3944) multi-process harnesses. The proxy binary, inner
//! fileserver binary, and `demo_root/` fixture are delivered via Bazel runfiles
//! (`data` deps) and resolved via `$(rlocationpath ...)` — no hardcoded path, no
//! cargo. Every spawned proxy is killed + reaped on Drop; readiness is a TCP port
//! probe; the C1 "never listens" case bounds its wait and asserts the process
//! EXITED rather than waiting forever.

use std::io::Read;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use mcps_core::McpsError;
use mcps_core::SigningKey;
use mcps_demo::mint_demo_grant;
use mcps_demo::DemoFixtureFiles;
use mcps_demo::DemoFixtures;
use mcps_demo::DemoGrant;
use mcps_demo::DemoGrantSpec;
use mcps_demo::DemoHostClient;
use mcps_demo::E2E_ON_BEHALF_OF;
use mcps_demo::E2E_PATH;
use mcps_demo::E2E_TOOL;
use mcps_host::HostSigner;
use mcps_host::SystemClock;
use mcps_host::SystemNonceSource;
use mcps_transport::ClientTlsConfig;
use mcps_transport::MtlsClient;
use serde_json::json;
use serde_json::Value;

const SKEW_SECS: i64 = 300;
const REQUEST_LIFETIME_SECS: i64 = 600;

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Runfiles resolution (identical scheme to the positive/negative harnesses).
// ---------------------------------------------------------------------------

fn resolve_runfile(env_key: &str) -> PathBuf {
    mcps_test_paths::resolve_runfile(env_key)
}

fn proxy_cli() -> PathBuf {
    resolve_runfile("MCPS_PROXY_CLI")
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
/// `mcps-proxy: listening on <addr> (PEP; …)`. Requires the trailing space so a
/// partially-captured line never yields a truncated address.
fn parse_listening_addr(stderr: &str) -> Option<SocketAddr> {
    let marker = "mcps-proxy: listening on ";
    let start = stderr.find(marker)? + marker.len();
    let rest = &stderr[start..];
    let end = rest.find(' ')?;
    rest[..end].parse().ok()
}

/// Drain a child's piped stderr on a dedicated thread into a shared buffer (so a
/// full pipe never deadlocks the child and the diagnostic is assertable).
fn drain_stderr(child: &mut std::process::Child) -> Arc<Mutex<String>> {
    let buf = Arc::new(Mutex::new(String::new()));
    let mut pipe = child.stderr.take().expect("piped stderr");
    let sink = Arc::clone(&buf);
    std::thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        loop {
            match pipe.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    if let Ok(mut s) = sink.lock() {
                        s.push_str(&String::from_utf8_lossy(&chunk[..n]));
                    }
                }
                Err(_) => break,
            }
        }
    });
    buf
}

// ===========================================================================
// C1 — env keysource without the opt-in must FAIL CLOSED at startup.
// ===========================================================================

/// A spawned env-keysource proxy child plus the temp dir holding its (real)
/// trust file. The dir is removed on drop, AFTER the child (so the proxy never
/// reads a half-deleted trust file). The child is NOT auto-killed here — the C1
/// tests own its lifecycle (one expects it to exit, one kills it explicitly).
struct EnvKeysourceProxy {
    child: std::process::Child,
    _trust_dir: PathBuf,
}

impl Drop for EnvKeysourceProxy {
    fn drop(&mut self) {
        // Best-effort: ensure no zombie, then drop the trust dir.
        let _ = self.child.try_wait();
        let _ = std::fs::remove_dir_all(&self._trust_dir);
    }
}

/// Spawn the real proxy with `--key-source env` (key material supplied via the
/// named environment variables) and `extra` flags appended. The seed/cert/key/CA
/// values are env VAR NAMES (env keysource semantics); their values are set in
/// the child's environment from the fixture material so the ONLY thing that
/// changes between the negative and positive C1 runs is whether
/// `--allow-env-keysource` is present. `--trust` points at a REAL fixture
/// trust.json on disk (it is not key material and not part of the KeySource), so
/// the positive control proceeds past trust loading to the actual bind.
fn spawn_env_keysource_proxy(
    fixtures: &DemoFixtures,
    bind: &str,
    inner: &str,
    root: &str,
    extra: &[&str],
) -> EnvKeysourceProxy {
    // Env VAR NAMES the proxy will read (env keysource: the flag VALUES are names).
    const SEED_VAR: &str = "MCPS_C1_SIGNING_SEED";
    const CERT_VAR: &str = "MCPS_C1_TLS_CERT";
    const KEY_VAR: &str = "MCPS_C1_TLS_KEY";
    const CA_VAR: &str = "MCPS_C1_CLIENT_CA";

    // A REAL trust.json on disk (trust is not key material; it stays a file even
    // under --key-source env). Owned by the returned guard so it outlives the
    // proxy and is cleaned up after it.
    let trust_dir = std::env::temp_dir().join(format!(
        "mcps_c1_trust_{}_{}",
        std::process::id(),
        now_unix(),
    ));
    std::fs::create_dir_all(&trust_dir).expect("mkdir trust dir");
    let trust_path = trust_dir.join("trust.json");
    std::fs::write(&trust_path, fixtures.trust_json()).expect("write trust.json");

    let mut args: Vec<String> = vec![
        "--bind".into(),
        bind.into(),
        "--audience".into(),
        fixtures.audience().into(),
        "--server-signer".into(),
        fixtures.server_signer().into(),
        "--server-key-id".into(),
        fixtures.server_key_id().into(),
        "--max-clock-skew".into(),
        SKEW_SECS.to_string(),
        "--key-source".into(),
        "env".into(),
        "--signing-key-seed".into(),
        SEED_VAR.into(),
        "--tls-cert".into(),
        CERT_VAR.into(),
        "--tls-key".into(),
        KEY_VAR.into(),
        "--client-ca".into(),
        CA_VAR.into(),
        "--trust".into(),
        trust_path.to_string_lossy().into_owned(),
    ];
    for f in extra {
        args.push((*f).into());
    }
    // The inner command consumes the remainder of argv.
    args.extend([
        "--inner-working-dir".into(),
        root.into(),
        "--inner-command".into(),
        inner.into(),
        "--demo-root".into(),
        root.into(),
    ]);

    let child = Command::new(proxy_cli())
        .args(&args)
        // env keysource: the secret material lives in the child's environment.
        .env(SEED_VAR, fixtures.signing_seed_b64url())
        .env(CERT_VAR, fixtures.server_cert_pem())
        .env(KEY_VAR, fixtures.server_key_pem())
        .env(CA_VAR, fixtures.client_ca_pem())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mcps_proxy_cli");

    EnvKeysourceProxy {
        child,
        _trust_dir: trust_dir,
    }
}

/// C1 negative — `--key-source env` WITHOUT `--allow-env-keysource` must fail
/// closed: the process exits non-zero, its diagnostic names the refusal, and it
/// NEVER opens the listening socket.
#[test]
fn c1_env_keysource_without_opt_in_fails_closed_no_listener() {
    let fixtures = DemoFixtures::generate_default();
    let inner = inner_binary();
    let root = demo_root();

    // No --allow-env-keysource: the production CLI must refuse env key material.
    // Bind :0 is irrelevant here (the refusal happens before bind); pass it so no
    // free_port() is involved.
    let mut proxy = spawn_env_keysource_proxy(&fixtures, "127.0.0.1:0", &inner, &root, &[]);
    let stderr = drain_stderr(&mut proxy.child);

    // The refusal is in argument parsing (before bind), so the process exits
    // promptly — wait for exit. We do NOT probe a port for "is it listening?": a
    // free_port could be occupied by an unrelated concurrent listener and give a
    // false positive (MCPS-087). The "never listened" claim is proven race-free
    // below by the ABSENCE of the proxy's post-bind startup marker.
    let mut status = None;
    for _ in 0..1200 {
        match proxy.child.try_wait().expect("try_wait") {
            Some(s) => {
                status = Some(s);
                break;
            }
            None => std::thread::sleep(Duration::from_millis(25)),
        }
    }
    // Reap regardless so no zombie outlives the test.
    let status = match status {
        Some(s) => s,
        None => {
            let _ = proxy.child.kill();
            proxy.child.wait().expect("wait")
        }
    };

    assert!(
        !status.success(),
        "env keysource without --allow-env-keysource must exit non-zero; got {status:?}"
    );
    let diag = stderr.lock().expect("stderr lock").clone();
    assert!(
        diag.contains("--allow-env-keysource"),
        "the refusal diagnostic must name the required opt-in; got: {diag:?}"
    );
    assert!(
        !diag.contains("mcps-proxy: listening on"),
        "a refused proxy must NEVER open a listening socket; got: {diag:?}"
    );
}

/// C1 compile-time gate (MCPS-076, audit gap G-3) — the env key source is now
/// gated behind the NON-DEFAULT `dev_env_key_source` cargo feature, so the
/// PRODUCTION `mcps_proxy_cli` binary (built without that feature) FAILS CLOSED on
/// `--key-source env` EVEN WITH the runtime `--allow-env-keysource` opt-in: the
/// process exits non-zero, the diagnostic names the required feature rebuild, and
/// it NEVER opens the listening socket. This is the stronger posture that
/// supersedes the old "runtime opt-in starts listening" control — in a production
/// build there is no runtime path to an env key source at all.
///
/// The POSITIVE control that an env key source CAN load lives in the
/// feature-built unit test `//mcps-proxy:dev_env_key_source_test`
/// (`env_source_signs_and_removes_var_after_read`), not in the production binary.
#[test]
fn c1_env_keysource_fails_closed_even_with_opt_in_in_production_build() {
    let fixtures = DemoFixtures::generate_default();
    let inner = inner_binary();
    let root = demo_root();

    // Even WITH the runtime opt-in, the production binary refuses env key material
    // because EnvKeySource is not compiled in (dev_env_key_source is off). Bind :0
    // is irrelevant (the refusal happens before bind); pass it so no free_port()
    // is involved.
    let mut proxy = spawn_env_keysource_proxy(
        &fixtures,
        "127.0.0.1:0",
        &inner,
        &root,
        &["--allow-env-keysource"],
    );
    let stderr = drain_stderr(&mut proxy.child);

    // The refusal is at key-source CONSTRUCTION (before bind), so the process
    // exits promptly — wait for exit (no port probe; see MCPS-087). The "never
    // listened" claim is proven race-free below by the ABSENCE of the proxy's
    // post-bind startup marker.
    let mut status = None;
    for _ in 0..1200 {
        match proxy.child.try_wait().expect("try_wait") {
            Some(s) => {
                status = Some(s);
                break;
            }
            None => std::thread::sleep(Duration::from_millis(25)),
        }
    }
    let status = match status {
        Some(s) => s,
        None => {
            let _ = proxy.child.kill();
            proxy.child.wait().expect("wait")
        }
    };

    assert!(
        !status.success(),
        "env keysource must fail closed in a production build even with \
         --allow-env-keysource; got {status:?}"
    );
    let diag = stderr.lock().expect("stderr lock").clone();
    assert!(
        diag.contains("dev_env_key_source"),
        "the refusal diagnostic must name the required dev_env_key_source feature \
         rebuild; got: {diag:?}"
    );
    assert!(
        !diag.contains("mcps-proxy: listening on"),
        "a refused proxy must NEVER open a listening socket; got: {diag:?}"
    );
}

// ===========================================================================
// C2 — replay durability across a full proxy RESTART (same durable replay file).
// ===========================================================================

/// A spawned `mcps_proxy_cli` OS process bound to an EXPLICIT durable replay
/// path (the caller owns the path so it can outlive a restart). Killed + reaped
/// on drop; the replay file is NOT removed here (the caller manages it).
struct DurableProxy {
    child: std::process::Child,
    addr: SocketAddr,
    _files: DemoFixtureFiles,
}

impl Drop for DurableProxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn the full P1 proxy (mTLS, `--authz reference`, `--transport-binding
/// exact`) with `--replay-cache file --replay-path <replay_path>`, then poll the
/// port until it accepts. Each call mints fresh fixture FILES but points at the
/// caller's shared `replay_path`, so two successive spawns share the durable
/// cache.
fn spawn_durable_proxy(fixtures: &DemoFixtures, replay_path: &Path) -> DurableProxy {
    let files = fixtures.write_files().expect("materialize fixture files");
    let inner = inner_binary();
    let root = demo_root();

    // Let the PROXY pick the port (bind :0, read it back from the startup
    // marker) — deletes the free_port() bind-after-free TOCTOU (MCPS-087). The
    // refusal cases above are unaffected (they exit before bind), so free_port
    // stays for those.
    let bind = "127.0.0.1:0".to_string();

    let mut child = Command::new(proxy_cli())
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
        // stderr PIPED + drained: readiness gates on the proxy's startup marker
        // (no connection-consuming probe) and a spawn failure surfaces the
        // captured diagnostic in the panic below. See MCPS-087.
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mcps_proxy_cli");

    let stderr = drain_stderr(&mut child);

    let mut addr: Option<SocketAddr> = None;
    for _ in 0..1200 {
        if let Some(parsed) = stderr.lock().ok().and_then(|buf| parse_listening_addr(&buf)) {
            addr = Some(parsed);
            break;
        }
        if let Ok(Some(status)) = child.try_wait() {
            let captured = stderr.lock().map(|b| b.clone()).unwrap_or_default();
            panic!("mcps_proxy_cli exited before listening (status {status}):\n{captured}");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let addr = addr.expect("mcps_proxy_cli did not report a listening address within budget");

    DurableProxy {
        child,
        addr,
        _files: files,
    }
}

fn signer_key(fixtures: &DemoFixtures) -> SigningKey {
    SigningKey::from_seed_bytes(&fixtures.signer_seed())
}

fn mtls_client(fixtures: &DemoFixtures) -> MtlsClient {
    let tls = ClientTlsConfig::from_pem(
        fixtures.client_cert_pem().as_bytes(),
        fixtures.client_key_pem().as_bytes(),
        fixtures.server_ca_pem().as_bytes(),
    )
    .expect("client TLS config from fixture PEM");
    MtlsClient::new(tls, fixtures.server_name()).expect("verifying mTLS client")
}

fn build_grant(fixtures: &DemoFixtures, now: i64) -> DemoGrant {
    let spec = DemoGrantSpec {
        issuer: fixtures.signer().to_string(),
        grantee: fixtures.signer().to_string(),
        subject: E2E_ON_BEHALF_OF.to_string(),
        audience: fixtures.audience().to_string(),
        allowed_path: E2E_PATH.to_string(),
        not_before: mcps_core::unix_to_rfc3339_utc(now - SKEW_SECS),
        expires_at: mcps_core::unix_to_rfc3339_utc(now + REQUEST_LIFETIME_SECS),
        revocation_id: "demo-c2-restart".to_string(),
    };
    mint_demo_grant(&spec, &signer_key(fixtures), fixtures.signer_key_id()).expect("mint demo grant")
}

fn list_files_params(grant: &DemoGrant) -> serde_json::Map<String, Value> {
    let mut params = serde_json::Map::new();
    params.insert("name".to_string(), Value::String(E2E_TOOL.to_string()));
    params.insert("arguments".to_string(), json!({ "path": E2E_PATH }));
    let mut meta = serde_json::Map::new();
    meta.insert(DemoGrant::meta_key().to_string(), grant.authorization_block());
    params.insert("_meta".to_string(), Value::Object(meta));
    params
}

/// Parse the JSON-RPC denial reason (`error.message`) from a proxy response;
/// `None` for a success.
fn denial_reason(response: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(response).expect("parse response");
    let error = value.get("error")?;
    Some(error["message"].as_str().expect("error.message").to_string())
}

/// C2 — a valid request accepted by a FIRST proxy process is still
/// `replay_detected` when replayed against a SECOND proxy process that shares the
/// SAME durable `--replay-path`. Proves the file-backed replay cache survives a
/// full restart (the in-process / across-connection cases are covered elsewhere;
/// this is the across-PROCESS guarantee).
#[test]
fn c2_replay_detected_after_proxy_restart_with_shared_durable_cache() {
    let fixtures = DemoFixtures::generate_default();
    let client = mtls_client(&fixtures);
    let now = now_unix();
    let grant = build_grant(&fixtures, now);
    let auth_hash = grant.authorization_hash().expect("authorization_hash");

    // ONE signed request, reused byte-for-byte across the restart so the durable
    // cache must recognise it the second time.
    let mut cl = DemoHostClient::with_defaults(
        HostSigner::new(
            signer_key(&fixtures),
            fixtures.signer().to_string(),
            fixtures.signer_key_id().to_string(),
        ),
        SystemClock,
        SystemNonceSource,
    );
    let id = Value::String("req-c2-restart".to_string());
    let signed = cl
        .sign_request(
            &id,
            "tools/call",
            list_files_params(&grant),
            E2E_ON_BEHALF_OF,
            fixtures.audience(),
            &auth_hash,
        )
        .expect("client signs the authorized list_files");

    // A durable replay file the caller owns, so it OUTLIVES the first proxy and
    // is read by the second. Removed at the end of the test.
    let replay_dir = std::env::temp_dir().join(format!(
        "mcps_c2_replay_{}_{}",
        std::process::id(),
        now
    ));
    std::fs::create_dir_all(&replay_dir).expect("mkdir replay dir");
    let replay_path = replay_dir.join("replay.json");

    // 1. First proxy process: the request is fresh and SUCCEEDS, recording the
    //    nonce in the durable cache on disk.
    {
        let proxy = spawn_durable_proxy(&fixtures, &replay_path);
        let first = client
            .round_trip(proxy.addr, &signed)
            .expect("first mTLS round trip");
        assert!(
            denial_reason(&first).is_none(),
            "the first send to a fresh durable cache must succeed: {:?}",
            denial_reason(&first)
        );
        // proxy dropped here → STOP the first process. The durable file remains.
    }

    // The durable cache file must exist on disk after the first proxy recorded
    // the accepted request and exited — that is what the restart reads back.
    assert!(
        replay_path.exists(),
        "the durable replay cache file must persist on disk across the restart"
    );

    // 2. A NEW proxy process pointing at the SAME --replay-path. Replaying the
    //    IDENTICAL signed bytes must now be rejected: the durable cache survived
    //    the restart.
    {
        let proxy = spawn_durable_proxy(&fixtures, &replay_path);
        let replayed = client
            .round_trip(proxy.addr, &signed)
            .expect("replay mTLS round trip");
        assert_eq!(
            denial_reason(&replayed).as_deref(),
            Some(McpsError::ReplayDetected.wire_code()),
            "after a full proxy restart the durable cache must still detect the replay"
        );
    }

    let _ = std::fs::remove_dir_all(&replay_dir);
}
