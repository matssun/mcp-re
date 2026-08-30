// SPDX-License-Identifier: Apache-2.0
//! The three NUMBERS that bound retention durability, and why each is the number it is.
//!
//! Together because they are one argument, not three settings. The reservation ceiling is
//! what an admission decision is taken against; the queue capacity is twice it, and the
//! factor is load-bearing rather than slack; the batch bound is how many queued jobs one
//! directory barrier may cover. Change any one in isolation and the argument that `complete`
//! is never refused for capacity stops holding.

/// Process-global ceiling on calls that hold a retention reservation at once.
///
/// A backstop, not the primary admission control — the per-core in-flight ceiling is
/// that. Its job is to bound the write queue: a reservation contributes at most one
/// queued job at any instant, so `K` reservations bound the queue at `K` jobs. Exceeding
/// it is refused BEFORE dispatch, which is the one place refusing is still free and
/// genuinely retry-safe.
pub(super) const MAX_RESERVATIONS: usize = 1024;

/// The write queue's capacity for a given reservation ceiling.
///
/// Twice the ceiling, and the factor of two is load-bearing rather than slack. A
/// reservation holds its permit until it is dropped, which can happen while its
/// completion job is still queued; the permit it releases can then admit a successor
/// whose reserve job is queued alongside it. One transient extra slot per reservation is
/// the most that window can produce, so at `2K` the send can never find the channel
/// full — and `complete` is therefore never refused for capacity, which is the whole
/// point of taking the admission decision before dispatch.
pub(super) const fn write_queue_capacity(max_reservations: usize) -> usize {
    // Saturating: a ceiling that cannot be doubled is not one this process can hold
    // reservations against, so the queue is as large as `usize` allows.
    max_reservations.saturating_mul(2)
}

/// How many queued jobs one directory barrier may cover.
///
/// A directory `fsync` has no per-entry granularity, so one call after B renames is
/// exactly as durable as B calls after one rename each. Bounding the batch bounds the
/// latency the last job in it waits, not its durability.
pub(super) const MAX_WRITE_BATCH: usize = 64;
