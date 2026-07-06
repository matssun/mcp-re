//! Multi-process mTLS E2E over the LONG-LIVED `mcp-re-demo-server` (MCPS-066,
//! MCP-RE-EPIC-P6.6B).
//!
//! This proves the FULL real-process topology against a PERSISTENT inner — the
//! keystone of P6.6B:
//!
//! ```text
//! this test process: DemoHostClient (HostSession) signs + mcp-re-transport mTLS POST
//!    │  real mTLS socket (127.0.0.1:<ephemeral>)
//!    ▼
//! mcp_re_proxy_cli --inner-mode persistent  (SEPARATE OS process: mTLS terminate +
//!    │             verify, Core verify, freshness, durable replay, transport-
//!    │             binding EXACT, Phase-5 authz=reference, sign response)
//!    │  ONE persistent stdio child, spawned + initialized ONCE
//!    ▼
//! mcp_re_demo_server_bin  (the long-lived MCP server; echo / list_items / reset_items)
//! ```
//!
//! It drives, over ONE verifying mTLS client and ONE persistent inner session:
//!   * THREE authorized `tools/call`s (echo, list_items, echo) — each signed
//!     response verifies against the request hash the `HostSession` STORED at
//!     sign time, proving the persistent inner served all three over one process;
//!   * ONE authorization-denied admin `reset_items` (covered by no grant) —
//!     rejected with `mcp-re.authorization_scope_denied`, after which a fourth
//!     authorized call (implicitly, the flow already proved the session survives
//!     via the third call sequencing) would still succeed.
//!
//! The persistent inner is spawned ONCE: the proxy's `--inner-mode persistent`
//! performs the MCP initialize handshake at startup and forwards every authorized
//! call over the same long-lived child. All security material comes from the
//! shared [`DemoFixtures`] and is materialized to files for the proxy's path-
//! based flags. The proxy binary and the demo-server binary are delivered via
//! Bazel runfiles (`data` deps) and resolved via the `$(rlocationpath ...)` env
//! vars — no hardcoded path, no cargo. The proxy subprocess (and its persistent
//! child) are killed + reaped on test end via a Drop guard, and readiness is a
//! TCP port probe (no sleep-only sync), matching `demo_e2e_test.rs`.

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

use mcp_re_demo::assemble_assertions;
use mcp_re_demo::independently_verify_response;
use mcp_re_demo::inner_received_id;
use mcp_re_demo::run_persistent_e2e;
use mcp_re_demo::server_response_public_key;
use mcp_re_demo::DemoFixtureFiles;
use mcp_re_demo::DemoFixtures;
use mcp_re_demo::PersistentE2eEvidence;
use mcp_re_demo::PERSISTENT_DENIED_ID;
use mcp_re_demo::PERSISTENT_ECHO_1_ID;
use mcp_re_demo::PERSISTENT_ECHO_2_ID;
use mcp_re_demo::PERSISTENT_LIST_ID;
use mcp_re_demo::TOOL_ECHO;
use mcp_re_demo::TOOL_LIST_ITEMS;

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
fn demo_server_binary() -> String {
    resolve_runfile("DEMO_SERVER_BIN")
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

/// A spawned `mcp_re_proxy_cli` OS process, killed (and reaped — together with its
/// persistent inner child, which exits on the proxy's death / stdin EOF) on drop.
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
    /// The proxy's captured diagnostic stderr (the `inner_spawned` lifecycle log)
    /// — the INDEPENDENT spawn-count oracle.
    fn stderr_snapshot(&self) -> String {
        self.stderr.lock().map(|s| s.clone()).unwrap_or_default()
    }

    /// The inner server's received-log content (#3965) — the INDEPENDENT "what
    /// actually reached the inner" oracle. Empty if the inner wrote nothing.
    fn inner_received_log(&self) -> String {
        std::fs::read_to_string(&self.received_log_path).unwrap_or_default()
    }
}

/// Spawn the real `mcp_re_proxy_cli --inner-mode persistent` as its OWN process
/// with the full flag set (mTLS, `--authz reference`, durable `--replay-cache
/// file`, `--transport-binding exact`, inner = the long-lived demo server), then
/// poll the port until it accepts. Panics if it never starts listening.
fn spawn_persistent_proxy(fixtures: &DemoFixtures) -> ProxyProcess {
    let files = fixtures.write_files().expect("materialize fixture files");
    let cli = proxy_cli();
    let inner = demo_server_binary();
    // The persistent inner spawns the demo server in a controlled working dir;
    // the demo server reads/writes nothing on disk, so the system temp dir is a
    // valid controlled start dir.
    let working_dir = std::env::temp_dir().to_string_lossy().into_owned();

    // Let the PROXY pick the port (bind :0, read it back from the startup
    // marker) — deletes the free_port() bind-after-free TOCTOU (MCPS-087).
    let bind = "127.0.0.1:0".to_string();

    let replay_dir = std::env::temp_dir().join(format!("mcp_re_persist_replay_{}", std::process::id()));
    std::fs::create_dir_all(&replay_dir).expect("mkdir replay dir");
    let replay_path = replay_dir.join("replay.json");
    // The inner server's received-log (#3965): the proxy forwards these trailing
    // args verbatim to the inner, so the long-lived inner records every tools/call
    // it ACTUALLY runs. This is the anti-gaming oracle for "denied never reached".
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
            // THE knob under test: front a long-lived inner with the persistent
            // process model (spawn-once + initialize handshake).
            "--inner-mode",
            "persistent",
            "--inner-working-dir",
            &working_dir,
            // `--inner-command` consumes the remainder of argv: the inner binary
            // plus its OWN `--received-log` flag (#3965), so the long-lived inner
            // records every tools/call it actually serves to a file the test reads.
            "--inner-command",
            &inner,
            "--received-log",
            &received_log_path.to_string_lossy(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        // stderr PIPED + drained: the proxy emits `inner_spawned` here the instant
        // it launches the persistent inner — the independent spawn-count oracle.
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mcp_re_proxy_cli --inner-mode persistent");

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
        stderr,
        received_log_path,
        _files: files,
        _replay_dir: replay_dir,
    }
}

/// The MCPS-066 proof: several authorized tool calls + one denied admin call,
/// over ONE persistent inner, across the real multi-process mTLS path.
#[test]
fn persistent_multi_call_multi_process_mtls() {
    let fixtures = DemoFixtures::generate_default();
    let proxy = spawn_persistent_proxy(&fixtures);

    let outcome = run_persistent_e2e(
        &fixtures,
        proxy.addr,
        now_unix(),
        SKEW_SECS,
        REQUEST_LIFETIME_SECS,
    )
    .expect("the persistent multi-process mTLS flow must succeed");

    // THREE (>= 3) authorized calls round-tripped + verified over ONE inner.
    assert_eq!(
        outcome.authorized.len(),
        3,
        "expected three authorized round trips over the one persistent session",
    );

    // Every authorized response was signed by the proxy's server signer and bound
    // to the request hash the session stored at sign time (a verified, non-empty
    // hash is only produced on a successful bind). The signer == the mTLS client
    // identity, so `--transport-binding exact` was SATISFIED, not bypassed.
    for call in &outcome.authorized {
        assert_eq!(
            call.server_signer,
            fixtures.server_signer(),
            "every verified response must be signed by the proxy's server signer",
        );
        assert!(
            !call.request_hash.is_empty(),
            "a verified round trip carries the bound request hash",
        );
        assert_eq!(
            call.signer,
            fixtures.signer(),
            "the request signer (== the mTLS client cert URI SAN) drove the call",
        );
    }

    // Tool-specific proof the LONG-LIVED inner actually executed each call:
    //   call 1: echo "hello-persistent" -> text echoed back;
    //   call 2: list_items -> the seed item set (alpha/beta/gamma);
    //   call 3: echo "still-alive" (AFTER list_items, same process) -> echoed.
    let echo_1 = &outcome.authorized[0];
    assert_eq!(echo_1.tool, TOOL_ECHO);
    assert_eq!(
        echo_1.result["content"][0]["text"].as_str(),
        Some("hello-persistent"),
        "echo must round-trip its message over the persistent inner",
    );

    let list = &outcome.authorized[1];
    assert_eq!(list.tool, TOOL_LIST_ITEMS);
    let items: Vec<String> = list.result["structuredContent"]["items"]
        .as_array()
        .expect("list_items returns an items array")
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    assert!(
        items.iter().any(|i| i == "alpha"),
        "list_items returned the seeded item set; got {items:?}",
    );

    let echo_2 = &outcome.authorized[2];
    assert_eq!(echo_2.tool, TOOL_ECHO);
    assert_eq!(
        echo_2.result["content"][0]["text"].as_str(),
        Some("still-alive"),
        "a later echo on the SAME persistent session still succeeds (session survives)",
    );

    // The admin reset_items call was DENIED before dispatch with the frozen
    // scope-denied reason — it was never forwarded to the persistent inner.
    assert_eq!(
        outcome.denied_reason, "mcp-re.authorization_scope_denied",
        "admin reset_items (no grant) must be scope-denied before dispatch",
    );

    // Real process boundary: the proxy is a separate spawned OS process.
    assert!(
        proxy.child.id() > 0,
        "the proxy ran as a separate OS process",
    );

    // -----------------------------------------------------------------------
    // #3966 — MACHINE-CHECKED, externally-observable evidence. Every fact below
    // is sourced from a signal INDEPENDENT of the flow's own return: the proxy's
    // spawn lifecycle stderr, the inner server's received-log (#3965), and a
    // direct public-key signature check. The test FAILS if any fact is false.
    // -----------------------------------------------------------------------
    let proxy_stderr = proxy.stderr_snapshot();
    let received_log = proxy.inner_received_log();
    let server_pubkey = server_response_public_key(&fixtures);

    // (a) inner_spawn_count == 1 — from the proxy's spawn lifecycle (one
    //     persistent inner, spawned ONCE), NOT a printed claim.
    let inner_spawns = proxy_stderr.matches("inner_spawned").count();
    assert_eq!(
        inner_spawns, 1,
        "the persistent inner must be spawned exactly once; proxy stderr:\n{proxy_stderr}",
    );

    // (b) The DENIED request's id is ABSENT from the inner's OWN received-log:
    //     the proxy rejected it before dispatch, so the long-lived inner never
    //     saw it. This is the anti-gaming oracle — the inner's record, not the
    //     proxy's `inner_request_forwarded` claim.
    assert!(
        !inner_received_id(&received_log, PERSISTENT_DENIED_ID),
        "the scope-denied id must NOT appear in the inner's received-log; log:\n{received_log}",
    );
    // The THREE authorized ids ARE present in the inner's received-log (the inner
    // actually ran them), and the post-denial echo proves the session survived.
    for authorized_id in [PERSISTENT_ECHO_1_ID, PERSISTENT_LIST_ID, PERSISTENT_ECHO_2_ID] {
        assert!(
            inner_received_id(&received_log, authorized_id),
            "authorized id {authorized_id} must appear in the inner's received-log; log:\n{received_log}",
        );
    }

    // (c) INDEPENDENT crypto: verify each authorized response signature with the
    //     server PUBLIC KEY directly (not via HostSession), binding to the
    //     request hash the session actually stored for the request it sent.
    for call in &outcome.authorized {
        assert!(
            independently_verify_response(&call.response_bytes, &server_pubkey, &call.request_hash),
            "response for {} must verify independently against the server public key \
             and bind to the stored request hash",
            call.id,
        );
        // ANTI-GAMING (negative control): the SAME signed bytes must FAIL the
        // independent check when bound to a WRONG request hash — the binding is
        // load-bearing, not decorative.
        assert!(
            !independently_verify_response(&call.response_bytes, &server_pubkey, "sha256:wrong"),
            "response for {} must NOT verify against a wrong request hash",
            call.id,
        );
    }

    // (d) The assembled evidence object: every machine-checked fact holds, and the
    //     overall result is "pass". A future change that silently breaks a control
    //     flips a fact false here, not merely a printed line.
    let assertions =
        assemble_assertions(&outcome, &proxy_stderr, &received_log, &server_pubkey);
    assert_eq!(assertions.inner_spawn_count, 1, "evidence: one persistent inner");
    assert_eq!(assertions.authorized_calls, 3, "evidence: three authorized calls");
    assert_eq!(assertions.denied_before_dispatch, 1, "evidence: one pre-dispatch denial");
    assert!(!assertions.denied_reached_inner, "evidence: denied call never reached the inner");
    assert!(assertions.response_hash_verified, "evidence: every response verified independently");
    assert!(assertions.proxy_process_started, "evidence: proxy emitted its post-bind startup marker");
    assert!(assertions.mtls_verified, "evidence: a round trip returned over the verifying mTLS client");
    assert!(
        assertions.session_survived_after_denial,
        "evidence: the persistent session served an authorized call after the denial",
    );
    assert!(assertions.all_pass(), "evidence: ALL externally-observable facts hold");

    let evidence = PersistentE2eEvidence::from_assertions(assertions);
    let json = evidence.to_json();
    assert_eq!(json["result"].as_str(), Some("pass"), "evidence result must be pass");
    assert_eq!(
        json["demo"].as_str(),
        Some("demo_e2e_persistent"),
        "evidence names the demo",
    );
    // The evidence object is well-formed and machine-readable.
    assert!(
        serde_json::to_string(&json).is_ok(),
        "evidence object must serialize to JSON",
    );
}
