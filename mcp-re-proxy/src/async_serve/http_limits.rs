// SPDX-License-Identifier: Apache-2.0
//! The operator's limits, as bounds on the wire.
//!
//! Separate from [`super::connection`] because it answers a different question. That module
//! decides who is on the other end and for how long; this one decides what the HTTP layer
//! will accept from them, and it is the same answer on every connection.
//!
//! Every value here was parsed and validated already — this is where each one stops being a
//! number in a struct. `--max-header-bytes` is the cautionary case: it was parsed,
//! validated, and then read by NOTHING on this path, so the only bound in force was hyper's
//! internal default and an operator tightening the limit got a silent no-op.

use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioTimer;
use hyper_util::server::conn::auto;

use crate::tls::ServerOptions;

use super::MIN_HYPER_BUF_BYTES;

/// hyper configured from the operator's limits.
///
/// Every one of these was parsed and validated already; this is where each becomes a bound
/// on the wire rather than a number in a struct. `--max-header-bytes` in particular was
/// read by nothing on this path, so an operator tightening it got a silent no-op.
pub(super) fn http_builder(options: &ServerOptions) -> auto::Builder<TokioExecutor> {
    let header_read_timeout = options
        .limits
        .request_deadline
        .or(options.limits.read_timeout);
    let stream_ceiling = options.limits.max_in_flight_requests;
    let max_header_bytes = options.limits.max_header_bytes;
    let write_timeout = options.limits.write_timeout;
    let mut builder = auto::Builder::new(TokioExecutor::new());
    // Bound the HTTP/1 header read so a slow-loris trickling header bytes cannot
    // hold a keep-alive connection between requests (the per-request analogue of
    // the blocking `request_deadline` over the header block).
    if let Some(read_timeout) = header_read_timeout {
        // `header_read_timeout` needs a `Timer` on the connection or hyper panics
        // when it arms the deadline; supply the tokio timer.
        builder
            .http1()
            .timer(TokioTimer::new())
            .header_read_timeout(read_timeout);
    }
    // Cap HTTP/2 concurrent streams to the same per-core in-flight ceiling. Without a
    // cap, ONE connection holding a valid client certificate can open unbounded
    // concurrent streams; each is a request that buffers up to `max_body_bytes`, so the
    // in-flight semaphore sheds them with a 503 only AFTER hyper has accepted the
    // stream. Capping at the connection level applies the same bound one layer earlier,
    // at the multiplexer. Left unset when no ceiling is configured (unbounded, the
    // historical behavior).
    if let Some(ceiling) = stream_ceiling {
        builder.http2().max_concurrent_streams(ceiling as u32);
    }
    // Apply the operator's `--max-header-bytes` on BOTH protocols. It was previously
    // parsed, validated, and then read by nothing on this path, so the only bound was
    // hyper's internal default — an operator tightening the limit got a silent no-op.
    // `max_buf_size` has a hyper-enforced 8 KiB floor, so clamp rather than pass a
    // smaller value straight through and panic.
    builder
        .http1()
        .max_buf_size(max_header_bytes.max(MIN_HYPER_BUF_BYTES));
    builder
        .http2()
        .max_header_list_size(max_header_bytes.min(u32::MAX as usize) as u32);
    // `--write-timeout-secs` is refused at parse time when it is 0, on the stated
    // grounds that it is a slow-loris defence — so it has to actually bound something
    // here. HTTP/2 has no per-write deadline in hyper; the keep-alive PING probe is
    // the equivalent liveness bound, and it closes a connection whose peer has stopped
    // reading. HTTP/1's write side is covered by the connection-age bound below.
    if let Some(write_timeout) = write_timeout {
        builder
            .http2()
            .timer(TokioTimer::new())
            .keep_alive_interval(Some(write_timeout))
            .keep_alive_timeout(write_timeout);
    }
    builder
}
