// SPDX-License-Identifier: Apache-2.0
//! The three NUMBERS that bound retention durability, and why each is the number it is.
//!
//! Together because they are one argument, not three settings. The reservation ceiling is
//! what an admission decision is taken against; the queue capacity is twice it, and the
//! factor is EXACTLY TIGHT rather than slack; the batch bound is how many queued jobs one
//! directory barrier may cover. Change any one in isolation and the argument that `complete`
//! is never refused for capacity stops holding.

/// Process-global ceiling on calls that hold a retention reservation at once.
///
/// A backstop, not the primary admission control — the per-core in-flight ceiling is
/// that. Its job is to bound the write queue: a reservation contributes at most TWO
/// queued jobs at any instant — see [`write_queue_capacity`] for the census — so `K`
/// reservations bound the queue at `2K`. Exceeding it is refused BEFORE dispatch, which is
/// the one place refusing is still free and genuinely retry-safe.
pub(super) const MAX_RESERVATIONS: usize = 1024;

/// The write queue's capacity for a given reservation ceiling.
///
/// Twice the ceiling, and the factor of two is EXACTLY TIGHT — not one slot of slack.
///
/// # The census, per permit
///
/// Two jobs can be outstanding at once and never three, and the two are not the pair the
/// obvious reading suggests.
///
/// **One AWAITED job at a time.** `reserve`, `commit_to_dispatch` and `complete` each
/// `submit`, and `submit` awaits the writer's acknowledgement — which the writer sends
/// only after it has dequeued the job, acted and crossed the barrier. A caller cannot be
/// in two of those at once.
///
/// It is the JOB that holds the slot, not the parked caller. A request future dropped at
/// its `await` — what hyper does to every in-flight service future when a connection goes
/// — leaves its job in the queue, and a slot released there would admit a successor
/// alongside an orphan that nothing is counting any more. Repeated often enough that is
/// not a tight bound but no bound at all, so
/// [`WriteJob::accounted`](super::durable_job::WriteJob::accounted) carries the permit and
/// the writer returns it as it acknowledges.
///
/// **Plus at most one UN-AWAITED rescind.** `commit_to_dispatch` takes the
/// [`ReservedBeforeDispatch`](super::ReservedBeforeDispatch) BY VALUE, so the guard drops
/// as that call returns and its `Drop` `try_send`s a `Rescind` that nobody awaits. That
/// rescind is therefore still in the channel while the following `complete` sends — which
/// is the real pair, and the one a census counting only awaited work misses.
///
/// **And no third.** The permit is `Arc`-shared — with
/// [`DispatchCommitted`](super::DispatchCommitted) and with the awaited job itself — and
/// released only when the last holder is gone, so no successor can be admitted while any
/// part of a commitment is outstanding: the successor's `reserve` can only coexist with
/// the predecessor's rescind, never with its completion as well. The FIFO acknowledgement
/// is what keeps the awaited half at one.
///
/// So at `2K` the send can never find the channel full, and `complete` is never refused
/// for capacity — which is the whole point of taking the admission decision before
/// dispatch. At `2K` exactly; a census that read the factor as slack could take it to `K`
/// and lose the property.
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
