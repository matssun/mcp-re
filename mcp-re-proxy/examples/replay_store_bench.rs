// SPDX-License-Identifier: Apache-2.0
//! Measure the replay store's OWN throughput, with no proxy in the picture.
//!
//! The saturation rig measures the proxy, and every ceiling it found survived removing
//! proxy cores, backend workers, connections and pool size — which says the bound is
//! somewhere all of those share. The replay store's round trip is one such place, and it
//! is the only real network I/O on the request path.
//!
//! Redis's own numbers, taken with `redis-benchmark` INSIDE the container, are 202k
//! `SET NX PX`/s and 238k `WAIT 2 2000`/s. If this binary — the same client code the
//! proxy runs, from the host, across whatever forwards the published port — reports a
//! number in that range, the store is exonerated and the ceiling is elsewhere in the
//! proxy. If it reports something near the proxy's own ceiling, the store path IS the
//! ceiling, and the split between `--wait-quorum` on and off says whether replication
//! acknowledgement or plain transport is responsible.
//!
//! Usage:
//!   replay_store_bench --url redis://127.0.0.1:PORT --concurrency 512 --requests 200000
//!                      [--wait-quorum 2 --wait-timeout-ms 2000]

use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use mcp_re_proxy::async_replay::AsyncAtomicReplayStore;
use mcp_re_proxy::async_replay::ReplayInsert;
use mcp_re_proxy::redis_store::system_clock;
use mcp_re_proxy::RedisAsyncAtomicReplayStore;

const ACTOR: &str = "did:example:bench-signer";

fn main() {
    let mut url = "redis://127.0.0.1:6379".to_string();
    let mut concurrency = 512usize;
    let mut requests = 200_000usize;
    let mut pool = RedisAsyncAtomicReplayStore::DEFAULT_POOL_SIZE;
    let mut wait_quorum: Option<u32> = None;
    let mut wait_timeout_ms = 2000u64;
    // Reproduce the PROXY's topology: build the connections on a small dedicated control
    // runtime (`app.rs` does this so the reconnect task never lands on a serving core),
    // then drive them from a different runtime. redis-rs spawns each connection's
    // multiplexer driver on whatever runtime is ambient at construction, so this puts a
    // cross-runtime thread wakeup on both legs of every command. Without the flag,
    // callers and drivers share one runtime, which is the arrangement that measured 421k.
    let mut split_runtime = false;
    let mut control_workers = 1usize;
    // The proxy's per-core serving runtimes are `new_current_thread()` (ADR-MCPRE-051 §1
    // share-nothing, `async_fleet.rs`), not the multi-worker runtime this bench used by
    // default. That is a materially different wakeup path: a multi-worker runtime has
    // sibling workers that can pick up a readied task, while a current-thread runtime has
    // exactly one thread which parks in kqueue and must be woken by the kernel before
    // anything can be polled. Every previous bench run hid that difference.
    let mut caller_current_thread = false;
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut val = || it.next().expect("flag needs a value");
        match flag.as_str() {
            "--url" => url = val(),
            "--concurrency" => concurrency = val().parse().expect("concurrency"),
            "--requests" => requests = val().parse().expect("requests"),
            "--pool" => pool = val().parse().expect("pool"),
            "--wait-quorum" => wait_quorum = Some(val().parse().expect("quorum")),
            "--wait-timeout-ms" => wait_timeout_ms = val().parse().expect("timeout"),
            "--split-runtime" => split_runtime = true,
            "--control-workers" => control_workers = val().parse().expect("control workers"),
            "--caller-current-thread" => caller_current_thread = true,
            other => panic!("unknown flag {other}"),
        }
    }

    // Worker threads well above the store's needs: this binary must not be the limit it
    // is looking for. `--caller-current-thread` instead reproduces one of the proxy's
    // per-core serving runtimes exactly.
    let rt = if caller_current_thread {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
    } else {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(8)
            .enable_all()
            .build()
            .expect("runtime")
    };

    let connect = |url: String| async move {
        let mut store = RedisAsyncAtomicReplayStore::connect_pooled(
            &url,
            system_clock(),
            wait_quorum.map(|_| wait_timeout_ms),
            pool,
        )
        .await
        .expect("connect redis");
        if let Some(quorum) = wait_quorum {
            store = store.with_wait_quorum(quorum, wait_timeout_ms);
        }
        Arc::new(store)
    };

    // Held for the whole run: dropping the control runtime would take the connection
    // drivers with it, so a `let _ =` here would measure a store with no I/O behind it.
    let control_rt = split_runtime.then(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(control_workers)
            .enable_all()
            .build()
            .expect("control runtime")
    });
    let store = match &control_rt {
        Some(control) => control.block_on(connect(url.clone())),
        None => rt.block_on(connect(url.clone())),
    };

    rt.block_on(async move {
        // Every key is distinct, so every insert is a genuine `Fresh` write and (with a
        // quorum) a genuine replication wait — a benchmark of `Replay` hits would skip
        // the write path entirely and measure nothing of interest.
        let now = system_clock()();
        let expires = now + 3600;
        let done = Arc::new(AtomicU64::new(0));
        let per_task = requests / concurrency.max(1);

        let started = Instant::now();
        let mut handles = Vec::with_capacity(concurrency);
        for task in 0..concurrency {
            let store = Arc::clone(&store);
            let done = Arc::clone(&done);
            handles.push(tokio::spawn(async move {
                for i in 0..per_task {
                    let key = format!("bench:{task}:{i}");
                    if store
                        .atomic_insert_if_absent(ReplayInsert::new(&key, ACTOR, expires, 0))
                        .await
                        .is_ok()
                    {
                        done.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
        }
        for h in handles {
            let _ = h.await;
        }
        let elapsed = started.elapsed();

        let ok = done.load(Ordering::Relaxed);
        let rps = ok as f64 / elapsed.as_secs_f64();
        let mean_us = elapsed.as_secs_f64() * 1e6 * concurrency as f64 / ok.max(1) as f64;
        let tier = match wait_quorum {
            Some(q) => format!("SET NX PX + WAIT {q} {wait_timeout_ms}"),
            None => "SET NX PX only".to_string(),
        };
        let caller = if caller_current_thread {
            "current_thread"
        } else {
            "multi_thread(8)"
        };
        let topology = if split_runtime {
            format!("caller={caller} split-control({control_workers})")
        } else {
            format!("caller={caller} one-runtime")
        };
        println!(
            "{tier} [{topology}]: pool={pool} concurrency={concurrency} ok={ok} \
             elapsed={:.2}s rps={rps:.0} mean_latency={mean_us:.0}us",
            elapsed.as_secs_f64()
        );
    });
}
