// SPDX-License-Identifier: Apache-2.0
//! WHICH revocation index a request reads, and WHO may change it.
//!
//! The cell a reload publishes into and the serving path reads from, as two handles: a read
//! handle that can only `load`, and a publisher that is the only way to write. What the index
//! it yields ANSWERS is [`super::ClientRevocationIndex`]'s; this decides only which one is in
//! force and who can replace it.

use std::sync::Arc;
use std::sync::RwLock;

use super::ClientRevocationIndex;

/// The cell itself: the index behind an atomic swap, shared by exactly one read handle and
/// one publisher.
///
/// Same shape and same reason as the reloading trust store: the read path clones an `Arc`
/// under a short read lock, so a request in flight never blocks on the reloader and keeps
/// the index it captured.
#[derive(Debug)]
struct Cell {
    current: RwLock<Arc<ClientRevocationIndex>>,
}

/// The READ handle on the index in force — what the serving path holds.
///
/// It can only [`load`](Self::load). There is no way to write through it, so holding one,
/// however widely it is passed, is not the power to change what revocation says.
#[derive(Debug)]
pub struct SharedClientRevocation {
    cell: Arc<Cell>,
}

/// The one capability to publish a rebuilt index into a cell, so a reloaded CRL reaches
/// requests already being served on OPEN connections.
///
/// Not `Clone`, and the cell's read handle cannot mint one: [`SharedClientRevocation::establish`]
/// returns the pair together, and whoever receives the publisher is the only writer of that
/// cell. In production that is the TLS plane's reload worker, which takes the publisher when
/// the plane is established and hands out only the read handle; anything else that holds the
/// plane's `Arc<SharedClientRevocation>` can read the index and cannot replace it.
#[derive(Debug)]
pub struct ClientRevocationPublisher {
    cell: Arc<Cell>,
}

impl SharedClientRevocation {
    /// Seed a cell with the index built from the CRLs read at startup, and return its read
    /// handle together with the one capability to publish into it.
    pub fn establish(index: ClientRevocationIndex) -> (Self, ClientRevocationPublisher) {
        let cell = Arc::new(Cell {
            current: RwLock::new(Arc::new(index)),
        });
        (
            SharedClientRevocation {
                cell: Arc::clone(&cell),
            },
            ClientRevocationPublisher { cell },
        )
    }

    /// The index in force right now.
    pub fn load(&self) -> Arc<ClientRevocationIndex> {
        match self.cell.current.read() {
            Ok(guard) => Arc::clone(&guard),
            // A poisoned lock still yields the last value: a request must not panic
            // because a reloader paniced mid-swap, and the last-good index is the
            // fail-closed-correct answer — it still carries every revocation it knew.
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }
}

impl ClientRevocationPublisher {
    /// Publish a rebuilt index. Requests already in flight keep the one they captured.
    pub fn publish(&self, index: ClientRevocationIndex) {
        match self.cell.current.write() {
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
        let (shared, publisher) = SharedClientRevocation::establish(index(&[], 9_000));
        assert!(shared.load().admits(&coord(ISSUER, b"\x01\x02\x03"), 1_000));
        publisher.publish(index(&[b"\x01\x02\x03"], 9_000));
        assert!(
            !shared.load().admits(&coord(ISSUER, b"\x01\x02\x03"), 1_000),
            "a reloaded CRL must reach a request being served on an already-open connection"
        );
    }

    /// The write capability belongs to ONE cell. A publisher that was established for another
    /// cell moves nothing here, which is what lets the plane hold its own publisher and hand
    /// out the read handle without handing out the power to rewrite what it reads.
    #[test]
    fn a_publisher_moves_only_the_cell_it_was_established_with() {
        let (mine, _mine_publisher) = SharedClientRevocation::establish(index(&[], 9_000));
        let (_other, other_publisher) = SharedClientRevocation::establish(index(&[], 9_000));
        other_publisher.publish(index(&[b"\x01\x02\x03"], 9_000));
        assert!(
            mine.load().admits(&coord(ISSUER, b"\x01\x02\x03"), 1_000),
            "another cell's publisher does not revoke through this one"
        );
    }

    /// The recovery arms run in exactly the situation nobody rehearses: a reload worker
    /// that panicked mid-swap. A `load` that answered with a default index instead of the
    /// last-good one would silently disable revocation process-wide.
    #[test]
    fn a_poisoned_lock_still_yields_the_last_good_index_and_still_accepts_a_swap() {
        let (shared, publisher) =
            SharedClientRevocation::establish(index(&[b"\x01\x02\x03"], 9_000));

        let poisoner = Arc::clone(&publisher.cell);
        let outcome = std::thread::spawn(move || {
            let _guard = poisoner.current.write().expect("write lock");
            panic!("reload worker panicked mid-swap");
        })
        .join();
        assert!(outcome.is_err(), "the worker must have panicked");
        assert!(
            shared.cell.current.is_poisoned(),
            "the lock must be poisoned"
        );

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

        publisher.publish(index(&[], 9_000));
        assert!(
            shared.load().admits(&coord(ISSUER, b"\x01\x02\x03"), 1_000),
            "a later reload must still be able to publish through a poisoned lock"
        );
    }
}
