// SPDX-License-Identifier: Apache-2.0
//! WHICH revocation index a request reads.
//!
//! The cell a reload publishes into and the serving path reads from. What the index it yields
//! ANSWERS is [`super::ClientRevocationIndex`]'s; this decides only which one is in force.

use std::sync::Arc;
use std::sync::RwLock;

use super::ClientRevocationIndex;

/// The index behind an atomic swap, so a reloaded CRL reaches requests already being
/// served on OPEN connections.
///
/// Same shape and same reason as the reloading trust store: the read path clones an
/// `Arc` under a short read lock, so a request in flight never blocks on the reloader
/// and keeps the index it captured.
#[derive(Debug)]
pub struct SharedClientRevocation {
    current: RwLock<Arc<ClientRevocationIndex>>,
}

impl SharedClientRevocation {
    /// Seed the snapshot with the index built from the CRLs read at startup.
    pub fn new(index: ClientRevocationIndex) -> Self {
        SharedClientRevocation {
            current: RwLock::new(Arc::new(index)),
        }
    }

    /// The index in force right now.
    pub fn load(&self) -> Arc<ClientRevocationIndex> {
        match self.current.read() {
            Ok(guard) => Arc::clone(&guard),
            // A poisoned lock still yields the last value: a request must not panic
            // because a reloader paniced mid-swap, and the last-good index is the
            // fail-closed-correct answer — it still carries every revocation it knew.
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }

    /// Publish a rebuilt index. Requests already in flight keep the one they captured.
    pub fn store(&self, index: ClientRevocationIndex) {
        match self.current.write() {
            Ok(mut guard) => *guard = Arc::new(index),
            Err(poisoned) => *poisoned.into_inner() = Arc::new(index),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::coord;
    use super::super::tests::index;
    use super::super::tests::ISSUER;
    use super::super::RevocationVerdict;
    use super::*;

    #[test]
    fn the_snapshot_swaps_atomically() {
        let shared = SharedClientRevocation::new(index(&[], 9_000));
        assert!(shared.load().admits(&coord(ISSUER, b"\x01\x02\x03"), 1_000));
        shared.store(index(&[b"\x01\x02\x03"], 9_000));
        assert!(
            !shared.load().admits(&coord(ISSUER, b"\x01\x02\x03"), 1_000),
            "a reloaded CRL must reach a request being served on an already-open connection"
        );
    }

    /// The recovery arms run in exactly the situation nobody rehearses: a reload worker
    /// that panicked mid-swap. A `load` that answered with a default index instead of the
    /// last-good one would silently disable revocation process-wide.
    #[test]
    fn a_poisoned_lock_still_yields_the_last_good_index_and_still_accepts_a_swap() {
        let shared = Arc::new(SharedClientRevocation::new(index(
            &[b"\x01\x02\x03"],
            9_000,
        )));

        let poisoner = Arc::clone(&shared);
        let outcome = std::thread::spawn(move || {
            let _guard = poisoner.current.write().expect("write lock");
            panic!("reload worker panicked mid-swap");
        })
        .join();
        assert!(outcome.is_err(), "the worker must have panicked");
        assert!(shared.current.is_poisoned(), "the lock must be poisoned");

        assert!(
            !shared.load().admits(&coord(ISSUER, b"\x01\x02\x03"), 1_000),
            "a poisoned lock must still yield the last-good index, which still carries \
             every revocation it knew"
        );
        assert_eq!(
            shared.load().verdict(&coord(ISSUER, b"\x09"), 1_000),
            RevocationVerdict::Good,
            "and it must be the last-good index, not an empty or default one"
        );

        shared.store(index(&[], 9_000));
        assert!(
            shared.load().admits(&coord(ISSUER, b"\x01\x02\x03"), 1_000),
            "a later reload must still be able to publish through a poisoned lock"
        );
    }
}
