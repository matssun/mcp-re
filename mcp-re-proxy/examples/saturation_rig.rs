// SPDX-License-Identifier: Apache-2.0
//! Saturation rig orchestrator — the instrument that can measure the proxy's own ceiling.
//!
//! The ADR-MCPRE-051 §7 harness cannot, and this is not a criticism of it: it is a
//! REGRESSION DETECTOR, deliberately cold and deliberately self-contained, and its numbers
//! are only meaningful relative to an anchor measured the same way. It stays untouched.
//!
//! What it cannot answer is "how fast is the proxy", because it co-locates a
//! thread-per-connection client that signs on the hot path with the proxy and the backend
//! in one process. Throughput measured that way was flat at ~10.4k rps across 1-8 proxy
//! cores AND 128-1024 connections — a ceiling that moves with neither cores nor offered
//! load is the harness, not the subject.
//!
//! This rig separates every tier into its own process so each one's CPU is attributable,
//! and it refuses to report a throughput number it cannot show is the proxy's:
//!
//! * proxy — a spawned `mcp-re-proxy` with `--cores K`, the swept variable;
//! * backend — its own process, worker count set well above the proxy's;
//! * generators — M separate processes, async, corpus pre-signed before the clock starts.
//!
//! # The saturation proof
//!
//! Every sweep point runs at M and M+1 generators. If throughput RISES when a generator
//! is added, the client was the limit and the number is discarded as a floor. Only a point
//! where adding load does not add throughput is reported as the proxy's. This is the check
//! whose absence made every previous number unsafe, so it is not optional here.
//!
//! # Liveness (`--smoke`)
//!
//! `--smoke` is not a measurement and never prints a throughput number. It stands the same
//! three tiers up with the same fixtures, the same admission posture and the same replay
//! tier, sends a tiny fixed load, and asserts that the requests were SERVED: zero failures,
//! a non-zero rate, and backend CPU that moved. It exists because the instrument once sat
//! for eleven days constructing a request the serving path refused at the channel-binding
//! stage — 100% refused, no backend dispatch, and every ordinary gate green, because
//! nothing on the merge path ever asked the rig to send one request.
//!
//! # Honest limits
//!
//! macOS has no usable CPU affinity for user processes, so tiers share the machine's
//! scheduler and "the proxy got K cores" means "the proxy was configured for K per-core
//! workers", not that the OS reserved them. On a single box the generators still compete
//! for CPU; the M/M+1 check is what detects when that has begun to bind, and per-process
//! CPU is reported so the reader can see it rather than trust it.

use std::io::BufRead;
use std::io::BufReader;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use mcp_re_core::SigningKey;
use rcgen::BasicConstraints;
use rcgen::CertificateParams;
use rcgen::DnType;
use rcgen::ExtendedKeyUsagePurpose;
use rcgen::IsCa;
use rcgen::KeyPair;
use rcgen::KeyUsagePurpose;
use rcgen::SanType;
use serde_json::json;
use serde_json::Value;

const SERVER: &str = "did:example:server-1";
const SERVER_KEY_ID: &str = "server-key-1";
const AUDIENCE: &str = "did:example:server-1";
const TRUST_DOMAIN: &str = "example.org";
const SUBJECT_A: &str = "did:example:agent-1";
const SIGNER_A_KEY_ID: &str = "key-a";
const TARGET_URI: &str = "https://localhost/";
/// The client leaf's URI SAN. It is the request actor's SUBJECT, because that is the
/// operand the serving path binds the channel to: `bind_request_to_peer` compares the
/// peer identity extracted from the leaf against `VerifiedRequestSubject`, which is
/// `ResolvedActor::identity.subject` and nothing else. Any other encoding of the actor
/// is refused `mcp-re.transport_binding_failed` before the request reaches the backend,
/// and the rig then measures nothing at all — which is what `--smoke` exists to catch.
const CLIENT_ACTOR_ID: &str = SUBJECT_A;
const MAX_CLIENT_CERT_LIFETIME_SECS: u64 = 3600;

fn tmp(name: &str) -> PathBuf {
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("mcp_re_sat_{}_{seq}_{name}", std::process::id()))
}

struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
    params: CertificateParams,
}

impl Ca {
    fn issuer(&self) -> rcgen::Issuer<'_, &KeyPair> {
        rcgen::Issuer::from_params(&self.params, &self.key)
    }
}

fn make_ca() -> Ca {
    let key = KeyPair::generate().expect("ca key");
    let mut params = CertificateParams::new(Vec::new()).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params
        .distinguished_name
        .push(DnType::CommonName, "mcp-re-sat-ca");
    let cert = params.self_signed(&key).expect("self-signed");
    Ca { cert, key, params }
}

fn make_leaf(ca: &Ca, sans: Vec<SanType>, client_auth: bool) -> (rcgen::Certificate, KeyPair) {
    let key = KeyPair::generate().expect("leaf key");
    let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
    params.subject_alt_names = sans;
    if client_auth {
        // Minted INSIDE the proxy's enforced ceiling: the serving path rejects a client
        // certificate whose span exceeds --max-client-cert-lifetime.
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::seconds(60);
        params.not_after = now + time::Duration::seconds(MAX_CLIENT_CERT_LIFETIME_SECS as i64)
            - time::Duration::seconds(120);
    }
    params.extended_key_usages = vec![if client_auth {
        ExtendedKeyUsagePurpose::ClientAuth
    } else {
        ExtendedKeyUsagePurpose::ServerAuth
    }];
    let cert = params.signed_by(&key, &ca.issuer()).expect("leaf signed");
    (cert, key)
}

struct Material {
    seed: PathBuf,
    server_cert: PathBuf,
    server_key: PathBuf,
    client_ca: PathBuf,
    trust: PathBuf,
    client_leaf_der: PathBuf,
    client_key_der: PathBuf,
}

fn write_material() -> Material {
    let server_ca = make_ca();
    let (server_leaf, server_leaf_key) = make_leaf(
        &server_ca,
        vec![SanType::DnsName("localhost".try_into().expect("dns"))],
        false,
    );
    let client_ca = make_ca();
    let (client_leaf, client_leaf_key) = make_leaf(
        &client_ca,
        vec![SanType::URI(CLIENT_ACTOR_ID.try_into().expect("uri san"))],
        true,
    );

    let m = Material {
        seed: tmp("seed"),
        server_cert: tmp("server_cert.pem"),
        server_key: tmp("server_key.pem"),
        client_ca: tmp("client_ca.pem"),
        trust: tmp("trust.json"),
        client_leaf_der: tmp("client_leaf.der"),
        client_key_der: tmp("client_key.der"),
    };

    let signer = SigningKey::from_seed_bytes(&[1u8; 32]);
    std::fs::write(&m.seed, b64url(&[2u8; 32])).expect("seed");
    std::fs::write(&m.server_cert, server_leaf.pem()).expect("server cert");
    std::fs::write(&m.server_key, server_leaf_key.serialize_pem()).expect("server key");
    std::fs::write(&m.client_ca, client_ca.cert.pem()).expect("client ca");
    // DER for the generator, so it needs no PEM parser.
    std::fs::write(&m.client_leaf_der, client_leaf.der().as_ref()).expect("client leaf der");
    std::fs::write(&m.client_key_der, client_leaf_key.serialize_der()).expect("client key der");

    // The proxy refuses to start on a group/world-readable key.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for p in [&m.seed, &m.server_key] {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        }
    }

    let trust = json!([{
        "signer": SUBJECT_A,
        "key_id": SIGNER_A_KEY_ID,
        "public_key": signer.public_key().to_b64url(),
    }]);
    std::fs::write(&m.trust, serde_json::to_vec(&trust).expect("trust json")).expect("trust");
    m
}

fn b64url(bytes: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        for i in 0..(c.len() + 1) {
            out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

/// A child that is killed when the rig drops, so a panic mid-sweep cannot leave a proxy
/// or a backend holding a port.
struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        // Under a profiling wrapper the direct child is the profiler, and SIGKILL
        // discards the capture it has not written yet. SIGTERM the grandchild instead.
        if std::env::var("MCP_RE_PROFILE_WRAPPER").is_ok() {
            let _ = Command::new("pkill")
                .args(["-TERM", "-P", &self.0.id().to_string()])
                .status();
            let _ = self.0.wait();
            return;
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Total CPU-seconds a process has consumed, via `ps`. Sampled before and after a run so
/// each tier's share is reported rather than assumed.
fn cpu_secs(pid: u32) -> f64 {
    let out = Command::new("ps")
        .args(["-o", "time=", "-p", &pid.to_string()])
        .output();
    let Ok(out) = out else { return 0.0 };
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    // formats: MM:SS.ss or HH:MM:SS
    let parts: Vec<f64> = text
        .split(':')
        .filter_map(|p| p.trim().parse::<f64>().ok())
        .collect();
    match parts.len() {
        2 => parts[0] * 60.0 + parts[1],
        3 => parts[0] * 3600.0 + parts[1] * 60.0 + parts[2],
        _ => 0.0,
    }
}

/// Poll a set of PIDs until `stop` is set, keeping the highest CPU reading seen for
/// each. Sampling AFTER a short-lived child exits returns nothing — `ps` cannot report a
/// process that is gone — which is why the first version of this reported 0.0 for every
/// generator and could not rule the client out.
fn sample_cpu(pids: Vec<u32>, stop: Arc<AtomicBool>) -> std::thread::JoinHandle<f64> {
    std::thread::spawn(move || {
        let mut peak = vec![0.0f64; pids.len()];
        while !stop.load(Ordering::Relaxed) {
            for (i, pid) in pids.iter().enumerate() {
                let c = cpu_secs(*pid);
                if c > peak[i] {
                    peak[i] = c;
                }
            }
            std::thread::sleep(Duration::from_millis(150));
        }
        peak.iter().sum()
    })
}

fn spawn_backend(exe: &str, workers: usize) -> (Proc, String) {
    let mut child = Command::new(exe)
        .args(["--workers", &workers.to_string(), "--bind", "127.0.0.1:0"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn backend");
    let stdout = child.stdout.take().expect("backend stdout");
    let mut line = String::new();
    BufReader::new(stdout)
        .read_line(&mut line)
        .expect("backend addr line");
    let addr = line
        .rsplit(' ')
        .next()
        .expect("addr token")
        .trim()
        .to_string();
    (Proc(child), addr)
}

#[allow(clippy::too_many_arguments)]
fn spawn_proxy(
    cli: &str,
    m: &Material,
    cores: usize,
    redis: &str,
    inner: &str,
    tier: &str,
    max_connections: usize,
    max_in_flight: usize,
) -> (Proc, String) {
    let lifetime = MAX_CLIENT_CERT_LIFETIME_SECS.to_string();
    let cores_s = cores.to_string();
    // The second topology axis. Read from the environment rather than a flag so
    // `runtime_topology_sweep.sh` can drive it without every rig caller growing an
    // argument it does not use.
    let workers_s = std::env::var("MCP_RE_SAT_WORKERS_PER_SHARD").unwrap_or_else(|_| "0".into());
    let maxconn_s = max_connections.to_string();
    let inflight_s = max_in_flight.to_string();
    let inner_url = format!("http://{inner}/mcp");
    let mut child = Command::new(cli)
        .args([
            "--bind",
            "127.0.0.1:0",
            "--audience",
            AUDIENCE,
            "--server-signer",
            SERVER,
            "--server-key-id",
            SERVER_KEY_ID,
            "--delegated-trust-epoch",
            "epoch-1",
            "--key-source",
            "file",
            "--signing-key-seed",
            &m.seed.to_string_lossy(),
            "--tls-cert",
            &m.server_cert.to_string_lossy(),
            "--tls-key",
            &m.server_key.to_string_lossy(),
            "--client-ca",
            &m.client_ca.to_string_lossy(),
            "--trust",
            &m.trust.to_string_lossy(),
            "--target-uri",
            TARGET_URI,
            "--trust-domain",
            TRUST_DOMAIN,
            "--transport-binding",
            "exact",
            "--transport-identity-source",
            "uri_san",
            "--max-client-cert-lifetime",
            &lifetime,
            "--replay-redis-url",
            redis,
            "--replay-durability-tier",
            tier,
            "--cores",
            &cores_s,
            "--workers-per-shard",
            &workers_s,
            // Headroom, so a shed connection never masquerades as a throughput ceiling.
            // The rig measures how fast the proxy serves, not where it starts refusing —
            // that is admission control and it has its own tests.
            "--max-connections",
            &maxconn_s,
            "--max-in-flight",
            &inflight_s,
            "--inner-http-url",
            &inner_url,
        ])
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn proxy");

    let stderr = child.stderr.take().expect("proxy stderr");
    let mut reader = BufReader::new(stderr);
    let mut addr = None;
    let mut seen: Vec<String> = Vec::new();
    for _ in 0..400 {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        if let Some(rest) = line.split("async fleet serving on ").nth(1) {
            // FIRST token only: the line continues with the core count and posture, and
            // trimming the whole tail yields a "host:port ..." that fails to parse.
            addr = rest.split_whitespace().next().map(str::to_string);
            if addr.is_some() {
                break;
            }
        }
        seen.push(line.trim_end().to_string());
    }
    // Drain the rest so a full pipe never blocks the proxy mid-measurement.
    std::thread::spawn(move || {
        let mut sink = String::new();
        while reader.read_line(&mut sink).unwrap_or(0) > 0 {
            sink.clear();
        }
    });
    let addr = addr.unwrap_or_else(|| {
        panic!(
            "proxy never reported a serving address; its stderr was:\n{}",
            seen.join("\n")
        )
    });
    (Proc(child), addr)
}

/// One measurement: M generator processes against the proxy, aggregated.
fn run_generators(
    gen_exe: &str,
    m: &Material,
    target: &str,
    generators: usize,
    connections: usize,
    requests: usize,
    mode: &str,
) -> (f64, u64, u64, usize, f64) {
    let mut kids = Vec::new();
    let mut outs = Vec::new();
    for g in 0..generators {
        let out = tmp(&format!("gen{g}.json"));
        let child = Command::new(gen_exe)
            .args([
                "--target",
                target,
                "--connections",
                &connections.to_string(),
                "--requests",
                &requests.to_string(),
                "--mode",
                mode,
                "--client-cert",
                &m.client_leaf_der.to_string_lossy(),
                "--client-key",
                &m.client_key_der.to_string_lossy(),
                "--id",
                &format!("g{g}"),
                "--out",
                &out.to_string_lossy(),
            ])
            .stdout(Stdio::null())
            .spawn()
            .expect("spawn generator");
        kids.push(child);
        outs.push(out);
    }
    // Sample WHILE they run; a dead process reports nothing.
    let stop = Arc::new(AtomicBool::new(false));
    let sampler = sample_cpu(kids.iter().map(|k| k.id()).collect(), Arc::clone(&stop));
    for mut k in kids {
        let _ = k.wait();
    }
    stop.store(true, Ordering::Relaxed);
    let gen_cpu = sampler.join().unwrap_or(0.0);

    let (mut ok, mut failed) = (0usize, 0usize);
    let (mut p50, mut p99) = (0u64, 0u64);
    let (mut first_start, mut last_end) = (u64::MAX, 0u64);
    for o in &outs {
        let Ok(text) = std::fs::read_to_string(o) else {
            continue;
        };
        let v: Value = serde_json::from_str(&text).expect("gen report");
        ok += v["successes"].as_u64().unwrap_or(0) as usize;
        first_start = first_start.min(v["start_ms"].as_u64().unwrap_or(u64::MAX));
        last_end = last_end.max(v["end_ms"].as_u64().unwrap_or(0));
        failed += v["failures"].as_u64().unwrap_or(0) as usize;
        p50 = p50.max(v["latency_us"]["p50"].as_u64().unwrap_or(0));
        p99 = p99.max(v["latency_us"]["p99"].as_u64().unwrap_or(0));
        if let Some(e) = v["first_error"].as_str() {
            // Surfaced immediately: a rig that prints "N failures" and swallows the
            // reason is the thing that wasted the afternoon.
            eprintln!("  generator error: {e}");
        }
        let _ = std::fs::remove_file(o);
    }
    // TRUE aggregate: all successes over the union of the generators' windows.
    let span = (last_end.saturating_sub(first_start)) as f64 / 1000.0;
    let rps = if span > 0.0 { ok as f64 / span } else { 0.0 };
    (rps, p50, p99, failed, gen_cpu)
}

/// The liveness parameters. Small enough to run on every pull request, large enough that
/// the backend's CPU is measurable rather than rounded away by `ps`.
const SMOKE_CONNECTIONS: usize = 8;
const SMOKE_REQUESTS: usize = 2000;

/// Prove the instrument can still construct a request this proxy admits, and that a
/// positive request reaches the backend. Returns the process exit status.
///
/// The three assertions are independent, and each one alone has been the whole failure:
/// a refused corpus shows up as failures, a generator that never started shows up as a
/// zero rate, and a reply the proxy produced without dispatching would show up as an
/// unmoved backend clock.
fn run_smoke(
    proxy_cli: &str,
    gen_exe: &str,
    m: &Material,
    redis: &str,
    backend_addr: &str,
    backend_pid: u32,
    tier: &str,
) -> i32 {
    let headroom = (SMOKE_CONNECTIONS * 4).max(64);
    let (proxy, target) = spawn_proxy(
        proxy_cli,
        m,
        1,
        redis,
        backend_addr,
        tier,
        headroom,
        headroom,
    );
    std::thread::sleep(Duration::from_millis(300));
    let b0 = cpu_secs(backend_pid);
    let (rps, _p50, _p99, failed, _gcpu) = run_generators(
        gen_exe,
        m,
        &target,
        1,
        SMOKE_CONNECTIONS,
        SMOKE_REQUESTS,
        "keepalive",
    );
    let b1 = cpu_secs(backend_pid);
    drop(proxy);

    let backend_cpu = b1 - b0;
    println!(
        "smoke: attempted={SMOKE_REQUESTS} failures={failed} rate={rps:.0}/s backend_cpu={backend_cpu:.2}s"
    );
    let mut bad = Vec::new();
    if failed > 0 {
        bad.push(format!(
            "{failed}/{SMOKE_REQUESTS} requests were refused — the reason is printed \
             above as `generator error:` and carries the proxy's wire code"
        ));
    }
    if rps <= 0.0 {
        bad.push("no request completed at all".to_string());
    }
    if backend_cpu <= 0.0 {
        bad.push(
            "the backend's CPU clock did not move — nothing was dispatched to it, so \
             whatever the proxy replied did not come from the inner server"
                .to_string(),
        );
    }
    if bad.is_empty() {
        println!("smoke: PASS — the saturation instrument constructs a request this proxy serves.");
        return 0;
    }
    eprintln!("\nsaturation rig LIVENESS FAILED:");
    for b in &bad {
        eprintln!("  * {b}");
    }
    eprintln!(
        "\nThe instrument, not necessarily the proxy, is what this proves broken: the rig \n\
         builds its own fixtures and signs its own corpus, so a serving-path change that \n\
         moves an admission operand leaves it refused at 100% while every other lane stays \n\
         green. Fix the rig to match the production request, never the proxy to accept the \n\
         rig's."
    );
    1
}

fn main() {
    let mut cores_sweep = vec![1usize, 2, 4, 8];
    let mut generators = 2usize;
    let mut connections = 256usize;
    let mut requests = 40000usize;
    let mut mode = "keepalive".to_string();
    let mut backend_workers = 6usize;
    // Escalation bounds. `--saturation-pct` is the gain below which one more generator
    // is judged to have bought nothing.
    let mut max_generators = 8usize;
    let mut saturation_pct = 5.0f64;
    // Escalation proves saturation but leaves each row at a different offered load, so
    // the core sweep stops being a curve. `--fixed-generators` pins every point to one
    // count; the M/M+1 probe still runs so a row that is client-bound is still flagged.
    let mut fixed_generators: Option<usize> = None;
    // The liveness mode. Not a measurement: it asserts that the instrument still works
    // and reports no throughput, so it can run on the merge path without claiming one.
    let mut smoke = false;
    // Must match the replica count actually running: `redis-wait-quorum` requires a
    // POSITIVE quorum, so a lone Redis cannot serve this rig at all. The default matches
    // the §7 lane, so the admission path measured here is the one the gate runs.
    let tier = std::env::var("MCP_RE_SAT_REPLAY_TIER")
        .unwrap_or_else(|_| "redis-wait-quorum:2:2000".to_string());
    let redis = std::env::var("MCP_RE_SAT_REDIS_URL")
        .expect("MCP_RE_SAT_REDIS_URL is required (the per-core plane refuses node-local replay)");

    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut val = || it.next().expect("flag needs a value");
        match flag.as_str() {
            "--cores" => {
                cores_sweep = val()
                    .split(',')
                    .map(|s| s.parse().expect("cores"))
                    .collect()
            }
            "--generators" => generators = val().parse().expect("generators"),
            "--connections" => connections = val().parse().expect("connections"),
            "--requests" => requests = val().parse().expect("requests"),
            "--mode" => mode = val(),
            "--backend-workers" => backend_workers = val().parse().expect("backend workers"),
            "--max-generators" => max_generators = val().parse().expect("max generators"),
            "--saturation-pct" => saturation_pct = val().parse().expect("saturation pct"),
            "--fixed-generators" => {
                fixed_generators = Some(val().parse().expect("fixed generators"))
            }
            "--smoke" => smoke = true,
            other => panic!("unknown flag {other}"),
        }
    }

    let dir =
        std::env::var("CARGO_BIN_EXE_DIR").unwrap_or_else(|_| "target/release/examples".into());
    let gen_exe = format!("{dir}/saturation_loadgen");
    let backend_exe = format!("{dir}/saturation_backend");
    let proxy_cli =
        std::env::var("MCP_RE_PROXY_CLI").unwrap_or_else(|_| "target/release/mcp-re-proxy".into());
    for p in [&gen_exe, &backend_exe, &proxy_cli] {
        assert!(
            std::path::Path::new(p).exists(),
            "missing binary {p} — build with: cargo build --release -p mcp-re-proxy \
             --features async_serve,redis_replay --bins --examples"
        );
    }

    let m = write_material();
    let (backend, backend_addr) = spawn_backend(&backend_exe, backend_workers);
    let backend_pid = backend.0.id();

    println!("replay tier {tier}");
    if smoke {
        let rc = run_smoke(
            &proxy_cli,
            &gen_exe,
            &m,
            &redis,
            &backend_addr,
            backend_pid,
            &tier,
        );
        drop(backend);
        std::process::exit(rc);
    }
    println!("saturation rig — mode={mode} connections/gen={connections} requests/gen={requests}");
    println!("backend on {backend_addr} ({backend_workers} workers)\n");
    println!(
        "{:>5} {:>4} {:>11} {:>11} {:>9} {:>9} {:>8} {:>9} {:>9}",
        "cores", "gens", "rps", "last_gain", "verdict", "p50_us", "fail", "proxy_cpu", "gen_cpu"
    );

    let mut results = Vec::new();
    for cores in &cores_sweep {
        let headroom = (max_generators * connections * 2).max(1024);
        let (proxy, target) = spawn_proxy(
            &proxy_cli,
            &m,
            *cores,
            &redis,
            &backend_addr,
            &tier,
            headroom,
            headroom,
        );
        let proxy_pid = proxy.0.id();
        std::thread::sleep(Duration::from_millis(300));

        let p0 = cpu_secs(proxy_pid);
        let b0 = cpu_secs(backend_pid);

        // ESCALATE until the client stops being the limit. Testing only M and M+1 tells
        // you the point is a floor but not where the ceiling is; adding generators until
        // throughput stops responding is what turns a floor into a measurement.
        let mut gens = fixed_generators.unwrap_or(generators);
        let (mut rps, mut p50, _p99_0, mut fail, mut gcpu) =
            run_generators(&gen_exe, &m, &target, gens, connections, requests, &mode);
        let mut verdict = "CLIENT";
        let mut gain = f64::NAN;
        if let Some(n) = fixed_generators {
            // One probe at N+1 purely to classify the row; the reported number stays the
            // pinned-N one so the curve remains comparable.
            let (probe, _, _, _, _) =
                run_generators(&gen_exe, &m, &target, n + 1, connections, requests, &mode);
            gain = (probe - rps) / rps.max(1.0) * 100.0;
            verdict = if gain > saturation_pct {
                "CLIENT"
            } else {
                "PROXY"
            };
        }
        while gens < max_generators && fixed_generators.is_none() {
            let (rps_next, p50_n, _p99_n, fail_n, gcpu_n) = run_generators(
                &gen_exe,
                &m,
                &target,
                gens + 1,
                connections,
                requests,
                &mode,
            );
            gain = (rps_next - rps) / rps.max(1.0) * 100.0;
            if gain <= saturation_pct {
                // The extra generator bought nothing: the proxy is the limit, and the
                // HIGHER of the two is the honest number.
                if rps_next > rps {
                    rps = rps_next;
                    p50 = p50_n;
                    fail = fail_n;
                    gcpu = gcpu_n;
                    gens += 1;
                }
                verdict = "PROXY";
                break;
            }
            gens += 1;
            rps = rps_next;
            p50 = p50_n;
            fail = fail_n;
            gcpu = gcpu_n;
        }
        let p2 = cpu_secs(proxy_pid);
        let b1 = cpu_secs(backend_pid);

        let attempted = gens * requests;
        let fail_pct = fail as f64 / attempted.max(1) as f64 * 100.0;
        // A throughput figure computed over a run that dropped requests is not a
        // measurement of anything; say so in the row rather than in a footnote.
        let verdict = if fail_pct > 0.5 { "INVALID" } else { verdict };
        println!(
            "{cores:>5} {gens:>4} {rps:>11.1} {:>11} {verdict:>9} {p50:>9} {fail:>8} {:>9.1} {gcpu:>9.1}",
            if gain.is_nan() { "-".to_string() } else { format!("{gain:+.1}%") },
            p2 - p0
        );
        results.push(json!({
            "cores": cores, "generators": gens,
            "rps": rps, "last_gain_pct": if gain.is_nan() { Value::Null } else { json!(gain) },
            "saturated": verdict == "PROXY",
            "failure_pct": fail_pct,
            "p50_us": p50, "failures": fail,
            "proxy_cpu_secs": p2 - p0, "backend_cpu_secs": b1 - b0,
            "generator_cpu_secs": gcpu,
        }));
        drop(proxy);
        std::thread::sleep(Duration::from_millis(200));
    }

    let report = json!({
        "schema": "mcp-re-saturation-rig/v1",
        "mode": mode, "connections_per_generator": connections,
        "requests_per_generator": requests, "backend_workers": backend_workers,
        "note": "NOT comparable to the ADR-MCPRE-051 §7 anchor — different client, different question.",
        "points": results,
    });
    let path = std::env::var("MCP_RE_SAT_OUT").unwrap_or_else(|_| "target/saturation.json".into());
    std::fs::write(&path, serde_json::to_string_pretty(&report).expect("json")).expect("write");
    println!("\nwrote {path}");
    println!("verdict CLIENT = adding a generator raised throughput >5%; that row is a FLOOR, not the proxy's ceiling.");
}
