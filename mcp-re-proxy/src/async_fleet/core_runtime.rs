// SPDX-License-Identifier: Apache-2.0
//! WHICH tokio runtime one serving core gets, and why it is not always the same one.
//!
//! One current-thread runtime per core is the share-nothing default (ADR-MCPRE-051 §1): no
//! work stealing, no cross-core hot-path state. Delegated TLS custody breaks the assumption
//! that runtime holds, so the choice is a decision with a security consequence rather than
//! a tuning knob, and it is made here where the reasoning can be stated once.
//!
//! Building it is FALLIBLE and the failure is reported: `build` allocates threads and an
//! event loop, so a core the operating system declines must not leave the fleet reporting a
//! successful bind with one fewer server behind it.

use super::DELEGATED_TLS_WORKERS_PER_CORE;

/// One core's tokio runtime.
///
/// One current-thread runtime per core is the share-nothing default (ADR-MCPRE-051 §1):
/// no work stealing, no cross-core hot-path state.
///
/// DELEGATED TLS custody breaks the assumption that runtime holds. The handshake signature
/// is produced by rustls' SYNCHRONOUS `Signer::sign`, which on that path is a blocking KMS
/// round trip or a PKCS#11 `C_Sign`. On a current-thread runtime one such call freezes the
/// core outright — its accept loop, its keep-alive connections and every in-flight signed
/// request — for the duration, and no timer can preempt it because the future never
/// yields. Any peer opening connections triggers it, so it is a trivially-reachable DoS.
///
/// Those deployments get a small worker pool per core instead, so a stalled signature costs
/// one worker rather than a whole core. The share-nothing default is unchanged for the
/// exported-key path, where signing is in-memory and never blocks. A configured pool depth
/// gives the shard a work-stealing runtime; see `FleetConfig::workers_per_shard` for why
/// depth beats shard count.
pub(super) fn build_core_runtime(
    core_index: usize,
    workers_per_shard: usize,
    options: &crate::tls::ServerOptions,
) -> std::io::Result<tokio::runtime::Runtime> {
    let pooled = if workers_per_shard > 1 {
        Some(workers_per_shard)
    } else if options.tls_signing_may_block {
        Some(DELEGATED_TLS_WORKERS_PER_CORE)
    } else {
        None
    };
    match pooled {
        Some(threads) => tokio::runtime::Builder::new_multi_thread()
            .worker_threads(threads)
            .thread_name(format!("mcp-re-serve-{core_index}-w"))
            .enable_all()
            .build(),
        None => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build(),
    }
}
