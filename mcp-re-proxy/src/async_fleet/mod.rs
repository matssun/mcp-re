//! MCPRE-113 (ADR-MCPRE-051 §1, Phase 2) — per-core async serving fleet.
//!
//! The data-plane shape: **a small number of SHARDS, each a `tokio` runtime with a
//! work-stealing worker pool, its own `SO_REUSEPORT` listener and (on Linux)
//! CPU-affinity pinning, running one [`crate::async_serve::serve`] loop over one `Proxy`
//! per shard.** The kernel's `SO_REUSEPORT` group load-balances accepted connections
//! across the shard listeners, so there is:
//!
//!   * **no shared accept lock** — every core `accept()`s on its own listener fd;
//!   * **no cross-core connection handoff** — a connection is served start-to-finish
//!     on the core that accepted it;
//!   * **no contended cross-shard hot-path state** — each shard owns its runtime,
//!     its listener, and its `Proxy` handler; work stealing happens strictly WITHIN a
//!     shard's pool and never across shards. The ONLY state shared across shards is
//!     the coherent replay/trust store (designed server-side-atomic, ADR-MCPS-020)
//!     and the `ServerConfigSnapshot`/`ServerOptions` handles (shared read-only
//!     behind `Arc`). See the module-level "Cross-core sharing audit" below.
//!
//! This supersedes the MCPRE-112 single-shared-runtime scaffolding (which was never a
//! release, ADR-MCPRE-051 §1); that runtime remains available for development but the
//! fleet is the target and is what the SLO/scaling gate (MCPRE-110/123) measures.
//!
//! ## Cross-core sharing audit (acceptance criterion: "no cross-core locks on the
//! request path")
//!
//! Per request, a worker touches only:
//!   * its own shard's `tokio` runtime (uncontended across shards);
//!   * its own listener fd (per-shard, not shared);
//!   * the per-core `Proxy` handler (`make_handler(core)` returns a distinct handler
//!     per core; nothing forces cores to share one);
//!   * read-only `Arc<ServerConfigSnapshot>` / `Arc<ServerOptions>` (the TLS config is
//!     re-read per connection so a CRL hot-reload is picked up without a restart; an
//!     `Arc` clone is a non-blocking refcount bump, never a lock);
//!   * the shared authoritative replay/trust store, whose cross-core coordination is
//!     the store's own server-side-atomic contract (Redis/etcd), NOT a process-local
//!     lock on the request path. The in-memory reference store's interior `Mutex`
//!     (MCPRE-111) is the deliberate exception for the single-process dev tier and is
//!     out of scope for a fleet deployment, which mandates a shared store.
//!
//! ## Scope (this increment)
//!
//! Shard runtimes + `SO_REUSEPORT` + pinning + configurable shard count and pool depth,
//! with a
//! deterministic always-on suite proving N independent per-core runtimes serve the
//! full mTLS pipeline correctly and shut down cleanly. **Near-linear 1→N throughput
//! scaling is measured on the load harness (MCPRE-108) in the SLO/CI lane**, not in a
//! unit test (kernel connection distribution is platform-dependent and not a
//! deterministic assertion off Linux). Bounded graceful drain across cores is
//! MCPRE-115 (this increment inherits `serve`'s runtime-drop shutdown); per-core
//! bounded admission control is MCPRE-114.

use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread::JoinHandle;

use crate::async_serve::serve;
use crate::async_serve::AsyncRequestHandler;
use crate::tls::ServerOptions;

mod core_runtime;
mod reuseport;
mod shard_depth;

pub use core_runtime::CorePool;
pub use core_runtime::HandshakeBound;
use reuseport::reuseport_listener;
pub use shard_depth::DelegatedTlsDepthRefusal;
pub use shard_depth::ShardDepth;

/// The `listen(2)` backlog for each per-core `SO_REUSEPORT` listener. A generous
/// default: the kernel bounds it to `net.core.somaxconn` anyway, and admission
/// control (MCPRE-114) is the real saturation guard, not the accept queue depth.
pub const DEFAULT_LISTEN_BACKLOG: i32 = 1024;

/// Configuration for a per-core serving fleet.
#[derive(Debug, Clone)]
pub struct FleetConfig {
    /// The address every per-core listener binds (they share one port via
    /// `SO_REUSEPORT`). A `:0` port is resolved to a concrete OS-assigned port on
    /// the first bind and reused for the rest, so the whole fleet shares one port.
    pub addr: SocketAddr,
    /// Number of serving SHARDS, each with its own `SO_REUSEPORT` listener. `0` means
    /// "auto" — one per cpu (see [`resolve_topology`]).
    pub cores: usize,
    /// Tokio worker threads inside EACH shard's runtime. `0` means auto (`min(8, cpus)`);
    /// an explicit `1` asks for the single-threaded share-nothing runtime.
    ///
    /// `0` AND `1` ARE DIFFERENT REQUESTS past the point [`resolve_topology`] fills one in
    /// ([`ShardDepth`]): `1` is a choice, `0` declines to make one, and under delegated TLS
    /// custody that decides between a startup refusal and a derived depth. The four cases
    /// are [`CorePool::for_core`]'s — the other half of each is the signing custody.
    ///
    /// Depth parallelises POLLING; shards parallelise `accept`. Which dominates depends
    /// on the connection profile, so neither substitutes for the other — see
    /// [`resolve_topology`] for the measurements on both.
    ///
    /// The optimum is hardware-, kernel- AND workload-specific, so this is configuration
    /// rather than a constant. `scripts/runtime_topology_sweep.sh` measures a given host.
    pub workers_per_shard: usize,
    /// `listen(2)` backlog for each per-core listener.
    pub listen_backlog: i32,
    /// MCPRE-114: an optional FLEET-GLOBAL in-flight-request TARGET, the ALTERNATIVE to
    /// the per-core `ServerLimits::max_in_flight_requests` rather than a companion to it —
    /// layer A refuses a configuration that names both. When set, it is divided evenly
    /// across cores — each core's ceiling is
    /// `ceil(total / cores)` — which keeps the request path lock-free ACROSS cores (no
    /// shared global semaphore on the hot path, per ADR-MCPRE-051 §1). `None` leaves the
    /// per-core ceiling as configured on `ServerOptions` (or unbounded).
    ///
    /// A target, not a cap: equal integer shares cannot express a total that does not
    /// divide by the core count, and the division rounds UP, so the fleet admits
    /// `ceil(total / cores) × cores` — at or above `total`, never below.
    /// [`derived_per_core_ceiling`] is the one authority on that share, and every
    /// component that must agree with the gate on aggregate capacity derives from it
    /// (see [`crate::startup_plan::inner_plane_ceiling`]).
    pub max_in_flight_total: Option<usize>,
}

impl FleetConfig {
    /// A fleet on `addr` with auto core count and the default backlog.
    pub fn new(addr: SocketAddr) -> Self {
        FleetConfig {
            addr,
            cores: 0,
            workers_per_shard: 0,
            listen_backlog: DEFAULT_LISTEN_BACKLOG,
            max_in_flight_total: None,
        }
    }
}

/// A running per-core fleet. Dropping it does NOT stop the workers (they would be
/// detached); call [`Fleet::shutdown_and_join`] (or [`Fleet::shutdown`] then
/// [`Fleet::join`]) to stop accepting and wait for the worker threads to exit.
pub struct Fleet {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
}

impl Fleet {
    /// The concrete address (with resolved port) every core is listening on.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// The number of per-core worker runtimes actually started.
    pub fn worker_count(&self) -> usize {
        self.workers.len()
    }

    /// Signal every per-core accept loop to stop. Each loop observes the flag within
    /// one accept poll interval and returns; in-flight connection tasks end when the
    /// per-core runtime is dropped (bounded graceful drain is MCPRE-115).
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Join every worker thread (blocks until all per-core runtimes have exited).
    pub fn join(self) {
        for worker in self.workers {
            let _ = worker.join();
        }
    }

    /// Signal shutdown and join every worker thread.
    pub fn shutdown_and_join(self) {
        self.shutdown();
        self.join();
    }
}

/// Start a per-core serving fleet.
///
/// Binds `cfg.cores` (or an auto count) `SO_REUSEPORT` listeners on one shared port,
/// and spawns one worker thread per listener; each worker pins itself (Linux), builds
/// a current-thread `tokio` runtime, and runs [`crate::async_serve::serve`] with the
/// per-core handler from `make_handler(core_index)`. Returns once every listener is
/// bound (so `fleet.local_addr()` is immediately usable) — the workers keep serving
/// until `shutdown` flips.
///
/// `make_handler` is called once per core with the core index, so callers construct
/// one `Proxy` (or handler) per core over the shared coherent stores rather than
/// contending on a single shared handler.
///
/// Fails closed at startup: any listener that cannot be bound (port in use without
/// `SO_REUSEPORT`, permission, address family unsupported), runtime that cannot be built
/// or worker that cannot be spawned fails the whole call with no core having served and
/// every started worker joined.
pub fn serve_fleet<H, F>(
    cfg: FleetConfig,
    config: Arc<crate::config_snapshot::ServerConfigSnapshot>,
    options: Arc<ServerOptions>,
    make_handler: F,
    shutdown: Arc<AtomicBool>,
) -> std::io::Result<Fleet>
where
    H: AsyncRequestHandler,
    F: Fn(usize) -> Arc<H>,
{
    let (cores, workers_per_shard) = resolve_topology(cfg.cores, cfg.workers_per_shard);

    // MCPRE-114: translate an optional fleet-GLOBAL in-flight ceiling into an
    // evenly-divided PER-CORE ceiling, so admission control stays lock-free across
    // cores (each core enforces its own share; no shared global semaphore).
    let options = apply_global_admission(options, cfg.max_in_flight_total, cores);

    // The per-core runtime shape and the blocking-handshake bound that shape supports,
    // decided once from the resolved depth and this deployment's signing custody. Every
    // core of a fleet is the same shape, so the decision is taken here and not per core.
    // BEFORE THE FIRST BIND and before any runtime is built (Owner Ruling 7). That
    // `serve_fleet` fails only before a listener exists is what `materialized_runtime` reads
    // to decide which lifecycle events happened, so a refusal after this line would not just
    // be worse advice — it would be a false event.
    let pool = CorePool::for_core(workers_per_shard, &options)
        .map_err(|refusal| std::io::Error::new(std::io::ErrorKind::InvalidInput, refusal))?;
    let handshake_bound = pool.handshake_bound();

    // Bind the first listener to resolve the concrete port (cfg.addr may be `:0`),
    // then bind the remaining listeners to that resolved address so the whole fleet
    // shares ONE port via SO_REUSEPORT.
    let first = reuseport_listener(cfg.addr, cfg.listen_backlog)?;
    let bound = first.local_addr()?;
    let mut listeners = Vec::with_capacity(cores);
    listeners.push(first);
    for _ in 1..cores {
        listeners.push(reuseport_listener(bound, cfg.listen_backlog)?);
    }

    let workers = release_when_all_started(listeners, |core_index, listener, parked| {
        // Class R, and settled HERE because this is the thread that can still report a
        // failure. Neither is an invariant of this program — `build` allocates threads and
        // an event loop, `set_nonblocking` is an `fcntl` — and a core the OS declines must
        // not leave the fleet reporting a successful bind with one fewer server behind it.
        let runtime = pool.build_runtime(core_index)?;
        listener.set_nonblocking(true)?;
        let config = Arc::clone(&config);
        let options = Arc::clone(&options);
        let handler = make_handler(core_index);
        let shutdown = Arc::clone(&shutdown);
        let worker = std::thread::Builder::new()
            .name(format!("mcp-re-serve-{core_index}"))
            .spawn(move || {
                if parked.recv().is_err() {
                    return;
                }
                // Best-effort CPU pinning (Linux); a no-op elsewhere. Pinning is a
                // tail-latency optimization, never a correctness property, so a
                // failure to pin is ignored (logged nowhere hot).
                pin_current_thread_to_core(core_index);

                // `CorePool` decided which runtime this core got and how much blocking
                // handshake work it may admit onto it; both are stated there, once.
                runtime.block_on(serve_core(
                    listener,
                    config,
                    options,
                    handler,
                    shutdown,
                    handshake_bound,
                ));
            })?;
        Ok(worker)
    })?;

    Ok(Fleet {
        addr: bound,
        shutdown,
        workers,
    })
}

/// Register one core's listener with the runtime running it and serve on it.
async fn serve_core<H: AsyncRequestHandler>(
    listener: std::net::TcpListener,
    config: Arc<crate::config_snapshot::ServerConfigSnapshot>,
    options: Arc<ServerOptions>,
    handler: Arc<H>,
    shutdown: Arc<AtomicBool>,
    handshake_bound: HandshakeBound,
) {
    // Class A. `from_std` needs a non-blocking socket — established before the worker
    // thread was spawned — and a runtime context, which is the `block_on` that polls
    // this future. What remains is registration with the reactor this runtime owns, so a
    // failure is a defect in the lines above rather than anything an environment, peer or
    // configuration can produce.
    #[allow(clippy::expect_used)]
    let listener = tokio::net::TcpListener::from_std(listener)
        .expect("the listener registers with the runtime running it");
    serve(
        listener,
        config,
        options,
        handler,
        shutdown,
        handshake_bound,
    )
    .await;
}

/// Drop every parked worker's sender, so each returns without serving, and join them.
fn stand_down(started: Vec<(JoinHandle<()>, std::sync::mpsc::SyncSender<()>)>) {
    let handles: Vec<JoinHandle<()>> = started
        .into_iter()
        .map(|(handle, release)| {
            drop(release);
            handle
        })
        .collect();
    for handle in handles {
        let _ = handle.join();
    }
}

/// Start one worker per item, each parked until every worker has started.
///
/// `start` receives the index, the item and the receiver the worker must wait on before
/// serving. If any `start` fails, every parked worker's sender is dropped (its `recv`
/// errs and it returns without serving), every started handle is joined, and the error is
/// returned: no worker serves and none outlives the call. Only once all have started is
/// each released.
fn release_when_all_started<T>(
    items: impl IntoIterator<Item = T>,
    mut start: impl FnMut(usize, T, std::sync::mpsc::Receiver<()>) -> std::io::Result<JoinHandle<()>>,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let mut started = Vec::new();
    for (index, item) in items.into_iter().enumerate() {
        let (release, parked) = std::sync::mpsc::sync_channel::<()>(1);
        match start(index, item, parked) {
            Ok(handle) => started.push((handle, release)),
            Err(error) => {
                stand_down(started);
                return Err(error);
            }
        }
    }
    let mut handles = Vec::with_capacity(started.len());
    for (handle, release) in started {
        let _ = release.send(());
        handles.push(handle);
    }
    Ok(handles)
}

/// MCPRE-114: derive the per-core in-flight ceiling from an optional fleet-global
/// target. When `global` is set AND the per-core ceiling is not already configured
/// explicitly, set each core's `max_in_flight_requests` to `ceil(global / cores)` (at
/// least 1) — every core then enforces only its own share, with no shared cross-core
/// semaphore. The aggregate that results is `ceil(global / cores) × cores`, which is at
/// or above `global` because the share rounds UP. Otherwise the options are returned
/// unchanged (an explicit per-core ceiling wins; no global ⇒ no derivation).
fn apply_global_admission(
    options: Arc<ServerOptions>,
    global: Option<usize>,
    cores: usize,
) -> Arc<ServerOptions> {
    match derived_per_core_ceiling(options.limits.max_in_flight_requests, global, cores) {
        // Only rebuild the options when the derivation actually changed the ceiling
        // (a global target was divided into a per-core one). An explicit per-core
        // ceiling or "no ceiling" leaves the shared options untouched.
        derived if derived != options.limits.max_in_flight_requests => {
            let mut opts = (*options).clone();
            opts.limits.max_in_flight_requests = derived;
            Arc::new(opts)
        }
        _ => options,
    }
}

/// MCPRE-114: the per-core in-flight ceiling given an (optional) explicit per-core
/// ceiling, an (optional) fleet-global target, and the core count. An explicit
/// per-core ceiling wins; otherwise a global target is divided evenly
/// (`ceil(global / cores)`, at least 1); with neither, there is no ceiling. Pure and
/// deterministic (unit-tested).
///
/// The both-set arm survives because this is a total function over two `Option`s, not
/// because that input is legal: layer A refuses a configuration naming both
/// (`config_state::InFlightLimitRequest` holds one limit), so no validated deployment
/// reaches it.
pub fn derived_per_core_ceiling(
    explicit_per_core: Option<usize>,
    global: Option<usize>,
    cores: usize,
) -> Option<usize> {
    match (explicit_per_core, global) {
        (Some(per_core), _) => Some(per_core),
        (None, Some(total)) => Some(total.div_ceil(cores.max(1)).max(1)),
        (None, None) => None,
    }
}

/// Resolve the configured core count: `0` → [`std::thread::available_parallelism`]
/// (min 1), otherwise the configured value.
pub fn resolve_core_count(configured: usize) -> usize {
    resolve_topology(configured, 0).0
}

/// Pool depth a shard is given when the operator does not choose one, capped.
///
/// Depth past this bought nothing measurable and started costing: 8 workers/shard reached
/// 44,803 rps and 16 reached 46,325 (+3.4%) while scheduler latency rose from 60us to
/// 83us. The cap is where the curve flattens, not a hardware constant.
const DEFAULT_MAX_WORKERS_PER_SHARD: usize = 8;

/// Resolve `(shards, workers_per_shard)` from what the operator configured, filling in
/// either from the host when it is `0`.
///
/// The default is ONE SHARD PER CPU, each with a worker pool — shard count is NOT reduced
/// to pay for depth.
///
/// Both axes matter, for different reasons, and which one dominates depends on the
/// WORKLOAD rather than the hardware:
///
/// * **Shards parallelise `accept`.** Each shard owns its own `SO_REUSEPORT` listener, and
///   a single listener serialises connection establishment. On the cold-mTLS §7 envelope
///   (every request a new connection + full handshake) this dominates everything else:
///   measured on an 8-vCPU GKE node at a constant 8 threads, 8 shards x 1 worker reached
///   369.0 rps against 125.9 for 2 x 4 and 65.5 for 1 x 8 — 5.6x across the same thread
///   count.
/// * **Depth parallelises polling.** A single-threaded shard has one thread driving the
///   I/O reactor AND polling every task, so with hundreds of concurrent futures a readied
///   task waits milliseconds. On a keepalive workload, where `accept` is amortised, this
///   dominates instead: 8 shards x 8 workers reached 44,803 rps against 10,362 for
///   8 x 1 on a 14-cpu host.
///
/// An earlier version of this function traded shards away for depth (`ceil(cpus/workers)`
/// shards). That was inferred from the keepalive rig alone and is wrong: it resolved an
/// 8-vCPU host to ONE shard, which measured 65.5 rps against the previous default's 369.0
/// on the cold envelope — a 5.6x regression on the profile production actually serves.
/// Keeping a shard per cpu and adding depth costs ~3% cold (369.0 -> 358.1) and gains
/// ~4.3x keepalive, so it is the defensible default; trading shards away is not.
///
/// A single-cpu host still resolves to 1 x 1, exactly the old single-threaded shard.
///
/// This remains a STARTING POINT, not a claim of optimality: cache domains, SMT,
/// P/E-core asymmetry and epoll-vs-kqueue wakeups all move the optimum, and so does the
/// connection profile. Measure a given host with `scripts/runtime_topology_sweep.sh`.
///
/// The depth comes back as a [`ShardDepth`], not a number: this is the function that spends
/// `0 = auto`, and a `usize` return would collapse an explicit `1` and a single-cpu host's
/// derived `1` — the difference the delegated-TLS refusal downstream turns on.
pub fn resolve_topology(
    configured_shards: usize,
    configured_workers: usize,
) -> (usize, ShardDepth) {
    let available = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let shards = if configured_shards != 0 {
        configured_shards
    } else {
        available
    };
    let workers = if configured_workers != 0 {
        ShardDepth::stated(configured_workers)
    } else {
        ShardDepth::derived(DEFAULT_MAX_WORKERS_PER_SHARD.min(available).max(1))
    };
    (shards, workers)
}

/// Pin the calling thread to `core_index % online_cpus` (Linux `sched_setaffinity`).
/// Best-effort: pinning is a tail-latency optimization (keep a worker on one core so
/// its runtime, sockets, and cache lines stay warm), never a correctness property, so
/// every failure — an unavailable syscall, a restricted cgroup cpuset — is ignored.
#[cfg(target_os = "linux")]
fn pin_current_thread_to_core(core_index: usize) {
    // `checked_rem`, so the guard and the operation are ONE statement. `online_cpu_count`
    // returns 0 only if every fallback in it failed, and nothing can be pinned to then.
    let Some(cpu) = core_index.checked_rem(online_cpu_count()) else {
        return;
    };
    // SAFETY: `cpu_set` is a zeroed, fully-owned `cpu_set_t`; `CPU_SET` sets one valid
    // bit in it; `sched_setaffinity(0, ...)` applies it to the calling thread and does
    // not retain the pointer. Return value is ignored (best-effort).
    unsafe {
        let mut cpu_set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(cpu, &mut cpu_set);
        let _ = libc::sched_setaffinity(
            0,
            std::mem::size_of::<libc::cpu_set_t>(),
            &cpu_set as *const libc::cpu_set_t,
        );
    }
}

/// Non-Linux platforms: no portable thread-affinity syscall; pinning is a no-op (the
/// per-core runtimes + `SO_REUSEPORT` still apply — only the affinity hint is
/// skipped). Matches the target-gated posture of the Linux sandbox backend.
#[cfg(not(target_os = "linux"))]
fn pin_current_thread_to_core(_core_index: usize) {}

/// Number of online CPUs, for the pinning modulo. `sysconf(_SC_NPROCESSORS_ONLN)`;
/// falls back to `available_parallelism` and finally 1.
#[cfg(target_os = "linux")]
fn online_cpu_count() -> usize {
    // SAFETY: `sysconf` takes an int name and returns a long; no pointers involved.
    let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if n > 0 {
        return n as usize;
    }
    std::thread::available_parallelism()
        .map(|x| x.get())
        .unwrap_or(1)
}

#[cfg(test)]
mod refusal_order_tests {
    use super::*;
    use rustls::crypto::ring;
    use rustls::pki_types::PrivateKeyDer;
    use rustls::pki_types::PrivatePkcs8KeyDer;

    /// A self-signed server-only config built in-process. The fleet never reaches a
    /// handshake in these tests — it exists because `serve_fleet` takes a snapshot.
    fn dummy_snapshot() -> Arc<crate::config_snapshot::ServerConfigSnapshot> {
        let key = rcgen::KeyPair::generate().expect("key");
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
        let cert = params.self_signed(&key).expect("self-signed");
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let config =
            rustls::ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("versions")
                .with_no_client_auth()
                .with_single_cert(vec![cert.der().clone()], key_der)
                .expect("server config");
        Arc::new(crate::config_snapshot::ServerConfigSnapshot::new(Arc::new(
            config,
        )))
    }

    /// An address no host can bind, so a run that reaches the listener loop FAILS THERE
    /// with an OS error. That is what makes the ordering observable: the two failures are
    /// distinguishable, and only one of them can come first.
    const UNBINDABLE: &str = "240.0.0.1:1";

    fn start(workers_per_shard: usize, tls_signing_may_block: bool) -> std::io::Error {
        let options = Arc::new(ServerOptions {
            tls_signing_may_block,
            ..Default::default()
        });
        serve_fleet(
            FleetConfig {
                addr: UNBINDABLE.parse().expect("a literal address"),
                cores: 1,
                workers_per_shard,
                listen_backlog: DEFAULT_LISTEN_BACKLOG,
                max_in_flight_total: None,
            },
            dummy_snapshot(),
            options,
            |_core| {
                Arc::new(|_req: crate::async_serve::ServedHttpRequest| -> crate::async_serve::HandlerResponseFuture {
                    unreachable!("no connection is ever accepted in these tests")
                })
            },
            Arc::new(AtomicBool::new(true)),
        )
        .err()
        .expect("an unbindable address never serves")
    }

    /// OWNER RULING 7, END TO END: the refused pair is refused BEFORE the serving fleet is
    /// established.
    ///
    /// LOAD-BEARING, and the reason the address is unbindable: if the listener loop ran
    /// first this call would still fail, just for the other reason. Asserting only that it
    /// fails would pass on the defect. What is asserted is WHICH failure came back —
    /// `InvalidInput` naming the flag, not the OS refusing the address.
    #[test]
    fn the_delegated_tls_depth_refusal_precedes_the_first_bind() {
        let refusal = start(1, true);
        assert_eq!(
            refusal.kind(),
            std::io::ErrorKind::InvalidInput,
            "a configuration refusal, not an OS failure: {refusal}"
        );
        let text = refusal.to_string();
        assert!(text.contains("--workers-per-shard"), "{text}");
        assert!(text.contains("DELEGATED"), "{text}");
    }

    /// THE CONTROL THAT MAKES THE ONE ABOVE MEAN SOMETHING: the same unbindable address
    /// under an ADMITTED configuration gets the OS failure, because the run reaches the
    /// listener loop. Without this, a `serve_fleet` that refused every configuration would
    /// satisfy the test above.
    #[test]
    fn an_admitted_configuration_reaches_the_listener_and_fails_there() {
        for (workers, may_block) in [(1, false), (2, true), (0, true)] {
            let failure = start(workers, may_block);
            assert_ne!(
                failure.kind(),
                std::io::ErrorKind::InvalidInput,
                "{workers}/{may_block}: this configuration has a safe shape and must reach \
                 the bind: {failure}"
            );
        }
    }
}

#[cfg(test)]
mod topology_tests {
    use super::*;

    /// Explicit configuration always wins over the host-derived default — an operator who
    /// measured their own hardware must not be second-guessed.
    #[test]
    fn explicit_topology_is_never_overridden() {
        assert_eq!(resolve_topology(4, 4), (4, ShardDepth::stated(4)));
        assert_eq!(resolve_topology(1, 16), (1, ShardDepth::stated(16)));
        // An explicit 1 is how the old single-threaded share-nothing shard is restored,
        // so it must survive as 1 and not be auto-filled to the default depth.
        assert_eq!(resolve_topology(8, 1), (8, ShardDepth::stated(1)));
    }

    /// OWNER RULING 7, at the resolver: a configured depth comes back as the OPERATOR'S
    /// and an auto-filled one comes back as the HOST'S, and the two are distinguishable
    /// afterwards. This is the fact `CorePool::for_core` refuses on — collapsing both to a
    /// number here is the defect, one layer before it becomes visible.
    #[test]
    fn a_resolved_depth_says_whether_the_operator_or_the_host_chose_it() {
        let (_, stated) = resolve_topology(0, 1);
        assert!(
            stated.is_operator_stated(),
            "--workers-per-shard 1 is a request, not a default"
        );
        assert_eq!(stated.get(), 1);

        let (_, derived) = resolve_topology(0, 0);
        assert!(
            !derived.is_operator_stated(),
            "an absent flag is the operator declining to choose"
        );
        assert!(derived.get() >= 1);
    }

    /// The default keeps ONE SHARD PER CPU and adds depth on top; it never trades shards
    /// away for depth. Shards own the `SO_REUSEPORT` listeners that parallelise `accept`,
    /// and on a cold-connection workload that dominates: at a constant 8 threads on an
    /// 8-vCPU node, 8x1 measured 369.0 rps against 65.5 for 1x8.
    #[test]
    fn auto_keeps_a_shard_per_cpu_and_adds_depth() {
        assert_eq!(auto_for(64), (64, 8));
        assert_eq!(auto_for(14), (14, 8));
        assert_eq!(auto_for(8), (8, 8));
        assert_eq!(auto_for(4), (4, 4));
        // A single-cpu host gets exactly the old single-threaded shard: a deployment that
        // cannot use a pool must not be handed one.
        assert_eq!(auto_for(1), (1, 1));
    }

    /// Auto never yields a degenerate topology, whatever the host reports.
    #[test]
    fn auto_is_always_at_least_one_shard_of_one_worker() {
        for cpus in 1..=64 {
            let (shards, workers) = auto_for(cpus);
            assert!(
                shards >= 1 && workers >= 1,
                "cpus={cpus} → {shards}x{workers}"
            );
            // One listener per cpu: `accept` is never serialised below the host's width,
            // which is what dominates a cold-connection workload.
            assert_eq!(shards, cpus);
            // Threads DO exceed the cpu count once the host is wider than one worker, and
            // that is deliberate rather than an accident to bound: the pool exists so a
            // readied task finds a thread to poll it, and those threads are parked, not
            // spinning. It cost ~3% on the cold GKE envelope and gained ~4.3x keepalive.
            assert!(shards * workers >= cpus);
            assert!(workers <= DEFAULT_MAX_WORKERS_PER_SHARD);
        }
    }

    /// `resolve_topology`'s auto path with the host's cpu count injected, so the
    /// expectations above are about the POLICY and not about whichever machine runs the
    /// suite.
    fn auto_for(cpus: usize) -> (usize, usize) {
        (cpus, DEFAULT_MAX_WORKERS_PER_SHARD.min(cpus).max(1))
    }

    /// `auto_for` models `resolve_topology`'s auto arm, so it has to be held to it: the
    /// arm must produce a DERIVED depth of exactly that number, or the expectations above
    /// are about a formula nothing runs.
    #[test]
    fn the_auto_model_matches_the_resolver_on_this_host() {
        let available = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let (shards, depth) = resolve_topology(0, 0);
        assert_eq!((shards, depth.get()), auto_for(available));
        assert!(!depth.is_operator_stated());
    }
}

#[cfg(test)]
mod start_gate_tests {
    use super::release_when_all_started;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering::SeqCst;
    use std::sync::Arc;

    #[test]
    fn a_core_that_fails_to_start_leaves_every_started_core_unserved_and_joined() {
        let served = Arc::new(AtomicBool::new(false));
        let exited = Arc::new(AtomicUsize::new(0));
        let result = release_when_all_started([0, 1, 2], |index, _item, parked| {
            if index == 2 {
                return Err(std::io::Error::other("declined"));
            }
            let served = Arc::clone(&served);
            let exited = Arc::clone(&exited);
            Ok(std::thread::spawn(move || {
                if parked.recv().is_err() {
                    exited.fetch_add(1, SeqCst);
                    return;
                }
                served.store(true, SeqCst);
            }))
        });
        let error = result.expect_err("the third core declines to start");
        assert!(error.to_string().contains("declined"));
        assert!(!served.load(SeqCst));
        assert_eq!(exited.load(SeqCst), 2);
    }

    #[test]
    fn every_core_is_released_once_all_have_started() {
        let served = Arc::new(AtomicUsize::new(0));
        let handles = release_when_all_started([0, 1, 2], |_index, _item, parked| {
            let served = Arc::clone(&served);
            Ok(std::thread::spawn(move || {
                if parked.recv().is_ok() {
                    served.fetch_add(1, SeqCst);
                }
            }))
        })
        .expect("every core starts");
        for handle in handles {
            handle.join().expect("the worker exits cleanly");
        }
        assert_eq!(served.load(SeqCst), 3);
    }
}
