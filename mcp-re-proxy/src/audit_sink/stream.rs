// SPDX-License-Identifier: Apache-2.0
//! Which run of the process an audit line belongs to, and where in that run it sits.
//!
//! A `seq` alone numbers one process's stream and starts again at 0 in the next one, so
//! two runs' records interleave numerically in a collector that keeps both. The position of
//! a record is therefore the pair `(run, seq)`: `seq` is ordered only within its run, and
//! the run is what a reader partitions on. A run whose stream has a start line and no
//! terminal line ended with an unknown tail.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

/// The identity of one process's audit stream: 128 bits from the OS CSPRNG, drawn once.
///
/// Nothing already on the audit line identifies a run. `at=` is wall-clock time, which
/// two runs can share and an operator can set. The process id is reused, and is the same
/// value in every container. The delegated key id rotates within a run and the trust
/// epoch spans the fleet, so neither marks one process. Hence a fresh random value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct AuditIncarnation([u8; 16]);

impl AuditIncarnation {
    /// A fresh incarnation. `None` when the OS CSPRNG fails, which refuses startup.
    fn draw() -> Option<Self> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).ok()?;
        Some(AuditIncarnation(bytes))
    }
}

impl std::fmt::Display for AuditIncarnation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

/// Where one record sits: its run and its number within that run.
///
/// There is no ordering between positions. Two positions of one run compare by their
/// `seq`, which [`AuditPosition::seq_within`] hands out only for the run asked about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct AuditPosition {
    run: AuditIncarnation,
    seq: u64,
}

impl AuditPosition {
    /// The run this position belongs to.
    pub(super) fn run(&self) -> AuditIncarnation {
        self.run
    }

    /// The number of this position within `run`, or `None` when it belongs to another run:
    /// a `seq` from one run says nothing about order in another.
    pub(super) fn seq_within(&self, run: &AuditIncarnation) -> Option<u64> {
        (self.run == *run).then_some(self.seq)
    }
}

/// The allocator of one run's positions.
#[derive(Debug)]
pub(super) struct AuditPositions {
    run: AuditIncarnation,
    next: AtomicU64,
}

impl AuditPositions {
    /// A run's allocator, starting at `seq = 0`.
    fn starting(run: AuditIncarnation) -> Self {
        AuditPositions {
            run,
            next: AtomicU64::new(0),
        }
    }

    /// The run this allocator numbers.
    pub(super) fn run(&self) -> AuditIncarnation {
        self.run
    }

    /// The next position of this run. Assigned before the hand-off, so a record the
    /// writer never received still took its number and leaves a hole.
    pub(super) fn next(&self) -> AuditPosition {
        AuditPosition {
            run: self.run,
            seq: self.next.fetch_add(1, Ordering::Relaxed),
        }
    }
}

/// This process's stream: one stderr, one writer, one run.
pub(super) static STREAM: OnceLock<AuditPositions> = OnceLock::new();

/// The run allocator in `cell`, drawing the run on first use, and whether this call drew
/// it. `None` when the CSPRNG fails; a later call draws again.
pub(super) fn open(
    cell: &'static OnceLock<AuditPositions>,
) -> Option<(&'static AuditPositions, bool)> {
    open_drawing(cell, AuditIncarnation::draw)
}

/// [`open`] with the run drawn by `draw`. There is no other run to fall back to: a failed
/// draw leaves `cell` empty and opens nothing.
fn open_drawing(
    cell: &'static OnceLock<AuditPositions>,
    draw: fn() -> Option<AuditIncarnation>,
) -> Option<(&'static AuditPositions, bool)> {
    if let Some(stream) = cell.get() {
        return Some((stream, false));
    }
    let drawn = AuditPositions::starting(draw()?);
    let mut won = false;
    let stream = cell.get_or_init(|| {
        won = true;
        drawn
    });
    Some((stream, won))
}

/// ` run=<hex>` for a stream-level line, or nothing when no stream was opened in this
/// process — in which case it has no record to speak of.
pub(super) fn run_suffix() -> String {
    STREAM
        .get()
        .map(|stream| format!(" run={}", stream.run))
        .unwrap_or_default()
}

/// The line that opens a run's stream, before its first record.
pub(super) fn start_line(run: &AuditIncarnation) -> String {
    format!("mcp-re-proxy: audit stream started run={run}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run() -> AuditIncarnation {
        AuditIncarnation::draw().expect("the OS CSPRNG yields an incarnation")
    }

    #[test]
    fn each_record_of_a_run_takes_the_next_number() {
        let positions = AuditPositions::starting(run());
        let first = positions.next();
        let second = positions.next();
        assert_eq!(first.seq_within(&positions.run), Some(0));
        assert_eq!(second.seq_within(&positions.run), Some(1));
    }

    /// A restart: two runs number their records from 0, and the run is what tells their
    /// equal numbers apart.
    #[test]
    fn two_runs_with_the_same_numbers_stay_distinguishable() {
        let (before, after) = (
            AuditPositions::starting(run()),
            AuditPositions::starting(run()),
        );
        let (a, b) = (before.next(), after.next());
        assert_ne!(a.run(), b.run(), "two draws name two runs");
        assert_ne!(a, b, "equal seq in different runs is not the same position");
        assert_eq!(a.seq_within(&a.run()), b.seq_within(&b.run()));
    }

    #[test]
    fn a_position_has_no_number_in_another_run() {
        let (mine, other) = (AuditPositions::starting(run()), run());
        let position = mine.next();
        assert_eq!(position.seq_within(&other), None);
        assert_eq!(position.seq_within(&position.run()), Some(0));
    }

    #[test]
    fn a_run_renders_as_32_hex_digits() {
        let rendered = run().to_string();
        assert_eq!(rendered.len(), 32, "{rendered}");
        assert!(
            rendered.chars().all(|c| c.is_ascii_hexdigit()),
            "{rendered}"
        );
    }

    /// A CSPRNG failure opens no stream and leaves no run behind to number records under;
    /// the next successful draw opens it.
    #[test]
    fn a_failed_draw_opens_nothing() {
        let cell = Box::leak(Box::new(OnceLock::new()));
        assert!(open_drawing(cell, || None).is_none());
        assert!(cell.get().is_none(), "a failed draw must not leave a run");
        let (_, drew) = open_drawing(cell, AuditIncarnation::draw)
            .expect("the OS CSPRNG yields an incarnation");
        assert!(drew, "the first successful draw opens the stream");
    }

    #[test]
    fn the_process_stream_is_drawn_once() {
        let (first, _) = open(&STREAM).expect("the OS CSPRNG yields an incarnation");
        let (again, drew) = open(&STREAM).expect("an opened stream is returned");
        assert!(std::ptr::eq(first, again));
        assert!(!drew, "a second call must not draw a second run");
        assert_eq!(run_suffix(), format!(" run={}", first.run));
        assert_eq!(
            start_line(&first.run),
            format!("mcp-re-proxy: audit stream started run={}", first.run)
        );
    }
}
