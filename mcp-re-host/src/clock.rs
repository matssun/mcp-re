//! Injected wall-clock abstraction for the host session (MCPS-033, ADR-MCPS-015).
//!
//! The host — unlike pure `mcp-re-core` — is allowed to read time, but it reads it
//! through an injected [`Clock`] so signing is deterministic under test. Core
//! itself never reads the clock (ADR-MCPS-006 "push timestamps to callers"); the
//! session is exactly such a caller, stamping `issued_at`/`expires_at` from the
//! injected clock and formatting them with `mcp_re_core::unix_to_rfc3339_utc`.

/// A source of the current time as Unix seconds (UTC).
///
/// Implemented in production by [`SystemClock`] (reads the OS clock) and in tests
/// by [`FixedClock`] (returns a frozen value), so session output is reproducible.
pub trait Clock {
    /// The current time as whole Unix seconds (UTC).
    fn now_unix(&self) -> i64;
}

/// Production clock: reads the OS wall clock via `std::time::SystemTime`.
///
/// A clock set before the Unix epoch yields a negative second count; this is the
/// faithful reading and is left to the freshness check at the verifier to reject.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl SystemClock {
    /// Construct the production clock.
    pub fn new() -> Self {
        SystemClock
    }
}

impl Clock for SystemClock {
    fn now_unix(&self) -> i64 {
        match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(delta) => delta.as_secs() as i64,
            // Clock set before the epoch: report the (negative) offset faithfully
            // rather than fabricate a value. The verifier's freshness window then
            // rejects it — fail closed at the boundary, not by inventing time.
            Err(err) => pre_epoch_seconds(err.duration().as_secs()),
        }
    }
}

/// Deterministic test clock: always returns a fixed Unix-second value.
///
/// A TEST fixture, reused as an injectable clock by integration tests (and the
/// deterministic demo binaries) in this and dependent crates. It is compiled
/// only under `cfg(test)` or the explicit `test-fixtures` cargo feature — an
/// *enforced* boundary, so a default (production) build of `mcp-re-host` does not
/// compile or export `FixedClock` at all. That fixture therefore cannot be used
/// to pin a `HostSession` to a frozen clock unless `test-fixtures` is enabled.
/// (This scopes only this fixture; a consumer remains free to provide its own
/// [`Clock`] implementation.)
#[cfg(any(test, feature = "test-fixtures"))]
#[derive(Debug, Clone, Copy)]
pub struct FixedClock {
    now_unix: i64,
}

#[cfg(any(test, feature = "test-fixtures"))]
impl FixedClock {
    /// Construct a clock frozen at `now_unix` (whole Unix seconds, UTC).
    pub fn new(now_unix: i64) -> Self {
        FixedClock { now_unix }
    }
}

#[cfg(any(test, feature = "test-fixtures"))]
impl Clock for FixedClock {
    fn now_unix(&self) -> i64 {
        self.now_unix
    }
}
/// The seconds an instant BEFORE the epoch reports, as a signed count.
///
/// Extracted from [`SystemClock::now_unix`] because it is the security-bearing arithmetic
/// on that boundary and the boundary itself cannot be reached from a test: a
/// `SystemTimeError` is not constructible, so a control over `now_unix` could never exercise
/// the pre-epoch arm at all.
///
/// `i64::MIN` is the answer for every magnitude `i64` cannot hold: it is the
/// most-before-the-epoch instant the type has, and every freshness window rejects it. What
/// must never happen is a fabricated plausible time — and above all, not a FUTURE one.
///
/// The conversion is `try_from` rather than an `as` cast, and that is the whole content of
/// this function. `(2^63 + 1) as i64` wraps to `i64::MIN + 1`, whose negation is `i64::MAX`:
/// a clock set unrepresentably far before the epoch would have reported the furthest instant
/// in the FUTURE, which every freshness window accepts. The magnitude is therefore refused
/// before it is negated, not after.
fn pre_epoch_seconds(secs: u64) -> i64 {
    i64::try_from(secs).map_or(i64::MIN, |magnitude| {
        magnitude.checked_neg().unwrap_or(i64::MIN)
    })
}

#[cfg(test)]
mod tests {
    use super::pre_epoch_seconds;
    use super::Clock;
    use super::FixedClock;
    use super::SystemClock;

    /// A clock set before the epoch reports a NEGATIVE count, which every freshness window
    /// rejects. The alternative — clamping to zero, or wrapping — fabricates a plausible
    /// time, and a fabricated timestamp is accepted rather than refused.
    #[test]
    fn a_pre_epoch_instant_is_reported_negative_never_fabricated() {
        assert_eq!(pre_epoch_seconds(1), -1);
        assert_eq!(pre_epoch_seconds(1_000_000_000), -1_000_000_000);
        assert!(
            pre_epoch_seconds(1) < 0,
            "a pre-epoch instant must not read as a time at or after the epoch"
        );
    }

    /// The exact instant the epoch: zero, and not a negative sentinel.
    #[test]
    fn the_epoch_itself_is_zero() {
        assert_eq!(pre_epoch_seconds(0), 0);
    }

    /// The overflow boundary, which is the reason this function exists — and which an `as`
    /// cast got WRONG until this control was written. `(2^63 + 1) as i64` wraps to
    /// `i64::MIN + 1`, and negating that yields `i64::MAX`: a clock set unrepresentably far
    /// before the epoch reported the furthest instant in the FUTURE, which every freshness
    /// window accepts. The answer must be the most-before-the-epoch instant, never a wrap.
    #[test]
    fn a_magnitude_past_the_i64_boundary_saturates_before_the_epoch_never_after_it() {
        for magnitude in [
            (1u64 << 63) - 1,
            1u64 << 63,
            (1u64 << 63) + 1,
            u64::MAX - 1,
            u64::MAX,
        ] {
            let reported = pre_epoch_seconds(magnitude);
            assert!(
                reported <= -(i64::MAX - 1),
                "magnitude {magnitude} must report an instant at the very start of the \
                 representable range, not {reported}"
            );
            assert!(
                reported < 0,
                "a magnitude that cannot be represented must never wrap into a future time"
            );
        }
    }

    /// The production clock reads the OS clock rather than returning a constant. Weak by
    /// construction — it cannot assert a specific instant — but it does refuse the two
    /// shapes that would matter: a frozen value, and a value before this code was written.
    #[test]
    fn the_production_clock_reads_a_real_time() {
        // 2020-01-01T00:00:00Z. A clock reporting earlier than this on a machine running
        // this test is not reading the OS clock.
        const AFTER: i64 = 1_577_836_800;
        let clock = SystemClock::new();
        assert!(
            clock.now_unix() > AFTER,
            "the production clock is not reading the OS wall clock"
        );
    }

    /// The fixture is frozen, which is what makes signing reproducible under test.
    #[test]
    fn the_fixture_clock_is_frozen_at_its_value() {
        let clock = FixedClock::new(1_700_000_000);
        assert_eq!(clock.now_unix(), 1_700_000_000);
        assert_eq!(clock.now_unix(), 1_700_000_000, "and does not advance");
    }
}
