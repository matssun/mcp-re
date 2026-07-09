//! MCPRE-113 (ADR-MCPRE-051 §1, Phase 2) — per-core async serving fleet.
//!
//! The target data-plane shape: **one worker thread per core, each a current-thread
//! `tokio` runtime with its own `SO_REUSEPORT` listener and (on Linux) CPU-affinity
//! pinning, running one [`crate::async_serve::serve`] loop over one `Proxy` per
//! core.** The kernel's `SO_REUSEPORT` group load-balances accepted connections
//! across the per-core listeners, so there is:
//!
//!   * **no shared accept lock** — every core `accept()`s on its own listener fd;
//!   * **no cross-core connection handoff** — a connection is served start-to-finish
//!     on the core that accepted it;
//!   * **no contended cross-core hot-path state** — each worker owns its runtime,
//!     its listener, and its `Proxy` handler; the ONLY state shared across cores is
//!     the coherent replay/trust store (designed server-side-atomic, ADR-MCPS-020)
//!     and the immutable `ServerConfig`/`ServerOptions` snapshots (shared read-only
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
//!   * its own `tokio` current-thread runtime (thread-local, uncontended);
//!   * its own listener fd (per-core, not shared);
//!   * the per-core `Proxy` handler (`make_handler(core)` returns a distinct handler
//!     per core; nothing forces cores to share one);
//!   * read-only `Arc<ServerConfig>` / `Arc<ServerOptions>` (immutable snapshots — an
//!     `Arc` clone is a non-blocking refcount bump, never a lock);
//!   * the shared authoritative replay/trust store, whose cross-core coordination is
//!     the store's own server-side-atomic contract (Redis/etcd), NOT a process-local
//!     lock on the request path. The in-memory reference store's interior `Mutex`
//!     (MCPRE-111) is the deliberate exception for the single-process dev tier and is
//!     out of scope for a fleet deployment, which mandates a shared store.
//!
//! ## Scope (this increment)
//!
//! Per-core runtimes + `SO_REUSEPORT` + pinning + configurable core count, with a
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

use rustls::ServerConfig;

use crate::async_serve::serve;
use crate::async_serve::AsyncRequestHandler;
use crate::tls::ServerOptions;

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
    /// Number of per-core worker runtimes. `0` means "auto" —
    /// [`std::thread::available_parallelism`] (falling back to 1 if unavailable).
    pub cores: usize,
    /// `listen(2)` backlog for each per-core listener.
    pub listen_backlog: i32,
    /// MCPRE-114: an optional FLEET-GLOBAL in-flight-request ceiling. When set (and
    /// the per-core `ServerLimits::max_in_flight_requests` is not already set
    /// explicitly), it is divided evenly across cores — each core's ceiling is
    /// `ceil(total / cores)` — so the aggregate in-flight stays under `total` while
    /// the request path remains lock-free ACROSS cores (no shared global semaphore on
    /// the hot path, per ADR-MCPRE-051 §1). `None` leaves the per-core ceiling as
    /// configured on `ServerOptions` (or unbounded).
    pub max_in_flight_total: Option<usize>,
}

impl FleetConfig {
    /// A fleet on `addr` with auto core count and the default backlog.
    pub fn new(addr: SocketAddr) -> Self {
        FleetConfig {
            addr,
            cores: 0,
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
/// Fails closed at startup: if any listener cannot be bound (port in use without
/// `SO_REUSEPORT`, permission, address family unsupported) the whole fleet fails to
/// start and no worker is spawned.
pub fn serve_fleet<H, F>(
    cfg: FleetConfig,
    config: Arc<ServerConfig>,
    options: Arc<ServerOptions>,
    make_handler: F,
    shutdown: Arc<AtomicBool>,
) -> std::io::Result<Fleet>
where
    H: AsyncRequestHandler,
    F: Fn(usize) -> Arc<H>,
{
    let cores = resolve_core_count(cfg.cores);

    // MCPRE-114: translate an optional fleet-GLOBAL in-flight ceiling into an
    // evenly-divided PER-CORE ceiling, so admission control stays lock-free across
    // cores (each core enforces its own share; no shared global semaphore).
    let options = apply_global_admission(options, cfg.max_in_flight_total, cores);

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

    let mut workers = Vec::with_capacity(cores);
    for (core_index, listener) in listeners.into_iter().enumerate() {
        let config = Arc::clone(&config);
        let options = Arc::clone(&options);
        let handler = make_handler(core_index);
        let shutdown = Arc::clone(&shutdown);
        let worker = std::thread::Builder::new()
            .name(format!("mcp-re-serve-{core_index}"))
            .spawn(move || {
                // Best-effort CPU pinning (Linux); a no-op elsewhere. Pinning is a
                // tail-latency optimization, never a correctness property, so a
                // failure to pin is ignored (logged nowhere hot).
                pin_current_thread_to_core(core_index);

                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("per-core tokio runtime builds");
                runtime.block_on(async move {
                    // `from_std` requires a non-blocking socket and a runtime
                    // context (both satisfied here).
                    listener
                        .set_nonblocking(true)
                        .expect("listener set_nonblocking");
                    let listener = tokio::net::TcpListener::from_std(listener)
                        .expect("tokio listener from std");
                    serve(listener, config, options, handler, shutdown).await;
                });
            })?;
        workers.push(worker);
    }

    Ok(Fleet {
        addr: bound,
        shutdown,
        workers,
    })
}

/// MCPRE-114: derive the per-core in-flight ceiling from an optional fleet-global
/// target. When `global` is set AND the per-core ceiling is not already configured
/// explicitly, set each core's `max_in_flight_requests` to `ceil(global / cores)` (at
/// least 1) — so the aggregate stays under `global` while every core enforces only
/// its own share (no shared cross-core semaphore). Otherwise the options are returned
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
/// per-core ceiling always wins; otherwise a global target is divided evenly
/// (`ceil(global / cores)`, at least 1); with neither, there is no ceiling. Pure and
/// deterministic (unit-tested).
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
fn resolve_core_count(configured: usize) -> usize {
    if configured != 0 {
        return configured;
    }
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// Create a `SO_REUSEPORT` (+ `SO_REUSEADDR`) TCP listener bound to `addr` and put it
/// in listening state. `SO_REUSEPORT` must be set BEFORE `bind`, which `std::net`
/// does not expose — hence the raw socket construction. On Linux the kernel then
/// load-balances accepted connections across every listener in the port's
/// `SO_REUSEPORT` group (one per core).
#[cfg(unix)]
fn reuseport_listener(addr: SocketAddr, backlog: i32) -> std::io::Result<std::net::TcpListener> {
    use std::os::fd::FromRawFd;
    use std::os::fd::OwnedFd;

    let family = match addr {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };

    // SAFETY: `socket(2)` with a valid family/type returns a new fd or -1. We wrap a
    // successful fd in an `OwnedFd` IMMEDIATELY so every early return below closes it
    // (RAII), and hand ownership to `TcpListener` only on the success path.
    let owned = unsafe {
        let fd = libc::socket(family, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        OwnedFd::from_raw_fd(fd)
    };
    let fd = {
        use std::os::fd::AsRawFd;
        owned.as_raw_fd()
    };

    set_sockopt(fd, libc::SO_REUSEADDR)?;
    set_sockopt(fd, libc::SO_REUSEPORT)?;

    // Build the bind sockaddr for the address family and bind + listen. On any error
    // `owned` drops and closes the fd.
    bind_and_listen(fd, addr, backlog)?;

    Ok(std::net::TcpListener::from(owned))
}

/// Non-Unix platforms have no `SO_REUSEPORT`; the per-core fleet is a Unix
/// (Linux-production) data plane. Fail closed rather than silently binding a single
/// non-shared listener.
#[cfg(not(unix))]
fn reuseport_listener(_addr: SocketAddr, _backlog: i32) -> std::io::Result<std::net::TcpListener> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "SO_REUSEPORT per-core fleet is only supported on Unix",
    ))
}

/// Set a boolean `SOL_SOCKET` option to 1 on `fd`, failing closed on error.
#[cfg(unix)]
fn set_sockopt(fd: std::os::fd::RawFd, option: libc::c_int) -> std::io::Result<()> {
    let one: libc::c_int = 1;
    // SAFETY: `fd` is a valid open socket; `&one` points to a `c_int` of the declared
    // length. `setsockopt` reads that many bytes and does not retain the pointer.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            &one as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// `bind(2)` + `listen(2)` `fd` to `addr`, constructing the family-appropriate
/// sockaddr. Ports and IPv4 addresses go on the wire in network byte order.
#[cfg(unix)]
fn bind_and_listen(fd: std::os::fd::RawFd, addr: SocketAddr, backlog: i32) -> std::io::Result<()> {
    let rc = match addr {
        SocketAddr::V4(v4) => {
            let sockaddr = libc::sockaddr_in {
                #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
                sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                // `octets()` is already network-order bytes; `from_ne_bytes` keeps
                // that in-memory byte layout, which is what `s_addr` (network order)
                // expects.
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: `fd` is a valid socket; the sockaddr pointer + length describe a
            // fully-initialized `sockaddr_in`. `bind` copies it and does not retain
            // the pointer.
            unsafe {
                libc::bind(
                    fd,
                    &sockaddr as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            }
        }
        SocketAddr::V6(v6) => {
            let sockaddr = libc::sockaddr_in6 {
                #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
                sin6_len: std::mem::size_of::<libc::sockaddr_in6>() as u8,
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            // SAFETY: as above for the IPv6 sockaddr.
            unsafe {
                libc::bind(
                    fd,
                    &sockaddr as *const libc::sockaddr_in6 as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            }
        }
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }

    // SAFETY: `fd` is a valid bound socket.
    let rc = unsafe { libc::listen(fd, backlog) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Pin the calling thread to `core_index % online_cpus` (Linux `sched_setaffinity`).
/// Best-effort: pinning is a tail-latency optimization (keep a worker on one core so
/// its runtime, sockets, and cache lines stay warm), never a correctness property, so
/// every failure — an unavailable syscall, a restricted cgroup cpuset — is ignored.
#[cfg(target_os = "linux")]
fn pin_current_thread_to_core(core_index: usize) {
    let online = online_cpu_count();
    if online == 0 {
        return;
    }
    let cpu = core_index % online;
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
