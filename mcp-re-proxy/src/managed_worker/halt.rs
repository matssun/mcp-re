// SPDX-License-Identifier: Apache-2.0
//! The STOP SIGNAL a managed worker observes, and the bounded nap it observes it through.
//!
//! One authority, and the nap belongs to it rather than being a convenience beside it: a
//! worker that slept its whole reload or rotation cadence would observe a stop only at the
//! end of it, so how long a worker may sleep IS how promptly the fleet shuts down. Both
//! halt sources sit here for the same reason — a deployment-wide stop and an owner's own
//! stop are raised independently and must be observable as one question.

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

/// A stop signal with two independent sources.
///
/// A worker asks only whether it should stop, never why. That is the point of the type:
/// a reload loop has no business distinguishing "SIGTERM arrived" from "the plane I
/// belong to failed to finish materializing" — both mean stop, and coupling worker bodies
/// to deployment-global state is what made the original threads impossible to own.
///
/// The signal is MONOTONIC. Once [`Halt::requested`] has observed either source raised,
/// it stays raised for the life of that `Halt` and every clone of it, even if the
/// underlying flag is later cleared. A worker that has begun winding down must not be
/// able to see the world become healthy again half way through.
#[derive(Clone)]
pub struct Halt {
    deployment: Arc<AtomicBool>,
    owner: Arc<AtomicBool>,
    latched: Arc<AtomicBool>,
}

impl Halt {
    /// Whether this worker should stop now.
    ///
    /// Stays true once raised, including after the owning set is gone — the worker's own
    /// clone keeps the flags alive — so a straggler that wakes late exits rather than
    /// resuming its loop.
    pub fn requested(&self) -> bool {
        if self.latched.load(Ordering::SeqCst) {
            return true;
        }
        if self.deployment.load(Ordering::SeqCst) || self.owner.load(Ordering::SeqCst) {
            // Latch, so the answer cannot revert. `deployment` is owned by the CALLER of
            // `run`, which makes "raised" something this type observes rather than
            // controls; without the latch a caller that reset its flag could restart a
            // worker that had already decided to stop.
            self.latched.store(true, Ordering::SeqCst);
            return true;
        }
        false
    }

    /// Sleep up to `total`, waking early if a halt is requested. Returns `true` if it
    /// was cut short, so a caller can `return` without re-reading the flag.
    ///
    /// Naps in small increments rather than sleeping the whole interval, so a stop is
    /// observed within one increment instead of after a full reload or rotation cadence.
    pub fn sleep(&self, total: Duration) -> bool {
        const TICK: Duration = Duration::from_millis(50);
        // Class R: an interval that cannot be turned into an instant is not a nap this
        // worker can bound, so the caller proceeds to its next cycle instead.
        let Some(deadline) = Instant::now().checked_add(total) else {
            return self.requested();
        };
        loop {
            if self.requested() {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            // `saturating_duration_since`, so the remaining time does not depend on the
            // comparison above staying where it is.
            std::thread::sleep(TICK.min(deadline.saturating_duration_since(now)));
        }
    }

    /// A halt over one set's three sources. The fields stay private: a `Halt` is only
    /// meaningful as the set's own projection of them, and this is the seam the set uses.
    pub(super) fn over(
        deployment: Arc<AtomicBool>,
        owner: Arc<AtomicBool>,
        latched: Arc<AtomicBool>,
    ) -> Halt {
        Halt {
            deployment,
            owner,
            latched,
        }
    }

    /// A halt over caller-supplied sources, so each can be raised independently.
    #[cfg(test)]
    pub(super) fn from_parts(deployment: Arc<AtomicBool>, owner: Arc<AtomicBool>) -> Halt {
        Halt {
            deployment,
            owner,
            latched: Arc::new(AtomicBool::new(false)),
        }
    }

    /// A halt with no owning set, raised only by the deployment flag.
    #[cfg(test)]
    pub(super) fn detached(deployment: Arc<AtomicBool>) -> Halt {
        Halt::from_parts(deployment, Arc::new(AtomicBool::new(false)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flag() -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(false))
    }

    /// Each source raises the halt on its own. Asserted directly, with the other source
    /// held down, so neither case can pass by accident of the other being set.
    #[test]
    fn either_source_alone_raises_the_halt() {
        // Deployment stopping, owner intact.
        let deployment = flag();
        let owner = flag();
        let halt = Halt::from_parts(Arc::clone(&deployment), Arc::clone(&owner));
        assert!(!halt.requested());
        deployment.store(true, Ordering::SeqCst);
        assert!(halt.requested(), "the deployment halt must raise it");
        assert!(
            !owner.load(Ordering::SeqCst),
            "the owner source is untouched"
        );

        // Owner disappearing, deployment intact — the case a single shared flag could
        // not express without telling the process that SIGTERM had arrived.
        let deployment = flag();
        let owner = flag();
        let halt = Halt::from_parts(Arc::clone(&deployment), Arc::clone(&owner));
        assert!(!halt.requested());
        owner.store(true, Ordering::SeqCst);
        assert!(halt.requested(), "the structural halt must raise it");
        assert!(
            !deployment.load(Ordering::SeqCst),
            "the deployment source is untouched"
        );
    }

    /// The halt is a monotonic lifecycle signal, not a boolean convenience: a worker
    /// that has begun winding down must never see the world become healthy again.
    ///
    /// `deployment` belongs to the caller of `run`, so "raised" is something this type
    /// observes rather than controls; the latch is what makes the observation stick.
    #[test]
    fn a_raised_halt_never_becomes_unraised() {
        for clear_source in [true, false] {
            let deployment = flag();
            let owner = flag();
            let halt = Halt::from_parts(Arc::clone(&deployment), Arc::clone(&owner));
            let source = if clear_source { &deployment } else { &owner };

            source.store(true, Ordering::SeqCst);
            assert!(halt.requested());
            source.store(false, Ordering::SeqCst);

            assert!(
                halt.requested(),
                "a halt observed as raised must stay raised"
            );
            assert!(
                halt.clone().requested(),
                "and must stay raised for every clone, including ones taken afterwards"
            );
            assert!(
                halt.sleep(Duration::from_secs(30)),
                "and must keep cutting sleeps short"
            );
        }
    }
}
