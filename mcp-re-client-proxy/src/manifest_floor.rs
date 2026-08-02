// SPDX-License-Identifier: Apache-2.0
//! A DURABLE rollback floor for the signed trust-anchor manifest (ADR-MCPRE-052).
//!
//! [`mcp_re_client_core::load_signed_manifest`] rejects a manifest whose version is
//! below `min_version` — but `min_version` is an argument, and the accepted version is
//! handed back for "the caller to record". Nothing recorded it, so the floor was 0 on
//! every start and an attacker who could serve an old manifest could roll the trust
//! picture back: un-revoke a root, re-widen a closed overlap window, resurrect an
//! issuer the org had withdrawn. Rollback protection that resets on restart is not
//! rollback protection.
//!
//! ## Monotonic BY CONSTRUCTION, not by comparison
//!
//! The floor is a DIRECTORY holding one empty marker file per accepted version, and
//! the floor is the maximum of those names. Recording version `v` creates `v`;
//! reading takes the max.
//!
//! The obvious design — a single file holding the number, read, compared, rewritten —
//! is a read-modify-write with no atomicity, and the module's own documented topology
//! is multi-writer ("a sidecar updater, a second client"). Two writers that both read
//! floor 5 and then persist 10 and 7 leave the floor at 7: a superseded manifest that
//! un-revokes a withdrawn root becomes acceptable again. Writing through one fixed
//! `<path>.tmp` made it worse — every writer truncates the same inode and writes from
//! its own offset, so `100` and `7` can publish as `700`, which rejects every
//! legitimate manifest until an operator repairs the file by hand.
//!
//! A max over a set that only ever GROWS has neither failure. Two writers create
//! different names and never collide; a late writer recording a lower version cannot
//! lower the maximum; and there is no lock to leak if a process dies mid-update.
//!
//! Each marker is created, `sync_all`ed and followed by a directory fsync, the same
//! durability discipline as the replay store: without the fsync a power loss can lose
//! the marker, and the next start reads a stale floor.
//!
//! ## Deleting the floor is not a way to lower it
//!
//! An empty directory reads as 0 — the honest meaning of "this verifier has never
//! accepted a manifest". But unlink on a directory is a CHEAPER capability than
//! corrupting a file, and an ephemeral client sidecar loses the volume on every
//! restart, so "0 after deletion" would hand back the whole rollback window for free.
//!
//! [`FileManifestFloor::with_bootstrap`] is the answer: an operator-declared minimum
//! the floor can never read below, whatever the filesystem says. It costs one config
//! value and it is the only part of this that an attacker cannot reach.

use std::fs::File;
use std::io;
use std::path::Path;
use std::path::PathBuf;

use mcp_re_client_core::ManifestVersionFloor;
use mcp_re_client_core::TrustManifestError;

/// A directory-backed [`ManifestVersionFloor`].
///
/// An ABSENT or empty directory reads as the bootstrap minimum (0 unless one is
/// declared). Any entry whose name is not a `u64` is NOT ignored: it is an unknown
/// floor, and the load fails closed with [`TrustManifestError::FloorUnreadable`],
/// because silently skipping unreadable entries would make writing junk into the
/// directory a way to lower the floor.
#[derive(Debug, Clone)]
pub struct FileManifestFloor {
    dir: PathBuf,
    /// The operator-declared minimum. The effective floor is never below it, so
    /// deleting the directory — or losing it with an ephemeral volume — cannot
    /// re-open the rollback window past this point.
    bootstrap: u64,
}

impl FileManifestFloor {
    /// Open (or create) the floor directory at `path`, with no declared minimum.
    ///
    /// Deleting the directory then resets the floor to 0. Prefer
    /// [`with_bootstrap`](Self::with_bootstrap) anywhere the storage is not both
    /// persistent and better-protected than the manifest itself.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, TrustManifestError> {
        Self::with_bootstrap(path, 0)
    }

    /// Open the floor with an operator-declared minimum version.
    ///
    /// `bootstrap` is a floor under the floor: whatever the directory says, no
    /// manifest below this version is ever accepted. It is what makes the durable
    /// floor safe on ephemeral storage, where "the file is gone" and "nothing has
    /// been accepted yet" are indistinguishable to the code and very different in
    /// fact.
    pub fn with_bootstrap(
        path: impl Into<PathBuf>,
        bootstrap: u64,
    ) -> Result<Self, TrustManifestError> {
        let dir = path.into();
        std::fs::create_dir_all(&dir)
            .map_err(|_| TrustManifestError::FloorNotPersisted("create trust-anchor floor dir"))?;
        let floor = FileManifestFloor { dir, bootstrap };
        // Prove it is readable now rather than at the first verification.
        floor.min_version()?;
        Ok(floor)
    }

    /// The directory this floor persists to.
    pub fn path(&self) -> &Path {
        &self.dir
    }
}

impl ManifestVersionFloor for FileManifestFloor {
    fn min_version(&self) -> Result<u64, TrustManifestError> {
        // Re-read every time rather than cache: another process (a sidecar updater, a
        // second client) may have raised the floor since this handle was opened, and
        // the higher value is the safe one to enforce.
        Ok(read_floor(&self.dir)?.max(self.bootstrap))
    }

    fn record(&mut self, version: u64) -> Result<(), TrustManifestError> {
        if version <= self.min_version()? {
            // Nothing to do — and no write, so re-applying the current manifest does
            // not churn the directory. Not an error: a concurrent writer may
            // legitimately have got there first.
            return Ok(());
        }
        persist(&self.dir, version)
            .map_err(|_| TrustManifestError::FloorNotPersisted("write trust-anchor floor"))?;
        // Best-effort tidy-up. Removing markers strictly BELOW the new maximum cannot
        // lower it, so a failure here is not a correctness problem — it only leaves
        // entries behind.
        prune_below(&self.dir, version);
        Ok(())
    }
}

/// The maximum recorded version in `dir`; 0 when the directory is absent or empty.
fn read_floor(dir: &Path) -> Result<u64, TrustManifestError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(_) => {
            return Err(TrustManifestError::FloorUnreadable(
                "read trust-anchor floor",
            ))
        }
    };
    let mut max = 0u64;
    for entry in entries {
        let entry = entry
            .map_err(|_| TrustManifestError::FloorUnreadable("read trust-anchor floor entry"))?;
        let name = entry.file_name();
        let name = name.to_str().ok_or(TrustManifestError::FloorUnreadable(
            "trust-anchor floor entry is not UTF-8",
        ))?;
        let version = name.parse::<u64>().map_err(|_| {
            TrustManifestError::FloorUnreadable("trust-anchor floor entry is not a u64")
        })?;
        max = max.max(version);
    }
    Ok(max)
}

/// Durably record `version`: create its marker, fsync it, fsync the directory.
///
/// An ALREADY-EXISTING marker is success, not a failure: it means a concurrent writer
/// recorded the same version, which is exactly the outcome asked for.
fn persist(dir: &Path, version: u64) -> io::Result<()> {
    let marker = dir.join(version.to_string());
    match File::create_new(&marker) {
        Ok(file) => file.sync_all()?,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Ok(()),
        Err(e) => return Err(e),
    }
    File::open(dir)?.sync_all()?;
    Ok(())
}

/// Remove markers strictly below `keep`. Best effort by design — the floor is the
/// maximum, so a marker that survives changes nothing.
fn prune_below(dir: &Path, keep: u64) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if let Some(v) = name.to_str().and_then(|n| n.parse::<u64>().ok()) {
            if v < keep {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique scratch directory per test. No `tempfile` dependency in this crate,
    /// and the pid keeps concurrent `cargo test` runs from colliding.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("mcp-re-floor-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            Scratch(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_missing_floor_is_zero() {
        let scratch = Scratch::new("missing");
        let floor = FileManifestFloor::open(&scratch.0).expect("open");
        assert_eq!(
            floor.min_version().unwrap(),
            0,
            "never accepted a manifest yet"
        );
    }

    #[test]
    fn a_recorded_version_survives_reopen() {
        // The whole point: the floor outlives the process that recorded it.
        let scratch = Scratch::new("survives");
        {
            let mut floor = FileManifestFloor::open(&scratch.0).expect("open");
            floor.record(7).expect("record");
        }
        let reopened = FileManifestFloor::open(&scratch.0).expect("reopen");
        assert_eq!(reopened.min_version().unwrap(), 7, "the floor is durable");
    }

    #[test]
    fn the_floor_is_monotonic() {
        let scratch = Scratch::new("monotonic");
        let mut floor = FileManifestFloor::open(&scratch.0).expect("open");
        floor.record(9).expect("record 9");
        floor
            .record(4)
            .expect("recording a lower version is a no-op, not an error");
        assert_eq!(floor.min_version().unwrap(), 9, "the floor never goes down");
        floor
            .record(9)
            .expect("re-recording the same version is a no-op");
        assert_eq!(floor.min_version().unwrap(), 9);
    }

    /// The interleaving a read-compare-write floor could not survive: a writer that
    /// decided on a LOWER version while another was publishing a higher one. Here it
    /// is a create of a different name, so the maximum is untouched — the property
    /// holds by construction rather than by the two writers' relative timing.
    #[test]
    fn a_late_lower_write_cannot_walk_the_floor_back() {
        let scratch = Scratch::new("interleaved");
        FileManifestFloor::open(&scratch.0).expect("open");
        // Both writers act as though the floor were still 5.
        persist(&scratch.0, 10).expect("writer A records 10");
        persist(&scratch.0, 7).expect("writer B records 7, having read the older floor");
        assert_eq!(
            read_floor(&scratch.0).unwrap(),
            10,
            "the later, lower write must not become the floor"
        );
    }

    #[test]
    fn a_corrupt_floor_entry_fails_closed_instead_of_being_skipped() {
        // Deleting the floor means "nothing accepted yet" and is allowed. Writing junk
        // into it must not be a cheaper way to say the same thing — skipping entries it
        // cannot parse would make littering the directory a way to lower the maximum.
        let scratch = Scratch::new("corrupt");
        let mut floor = FileManifestFloor::open(&scratch.0).expect("open");
        floor.record(12).expect("record");
        std::fs::write(scratch.0.join("not-a-number"), b"").expect("write garbage");
        assert_eq!(
            FileManifestFloor::open(&scratch.0).err(),
            Some(TrustManifestError::FloorUnreadable(
                "trust-anchor floor entry is not a u64"
            )),
        );
    }

    /// Deleting the floor is a cheaper capability than corrupting it, and an ephemeral
    /// client sidecar loses its volume on every restart. The declared bootstrap is the
    /// part of the floor an attacker cannot reach.
    #[test]
    fn the_bootstrap_minimum_survives_deleting_the_whole_floor() {
        let scratch = Scratch::new("bootstrap");
        {
            let mut floor = FileManifestFloor::with_bootstrap(&scratch.0, 4).expect("open");
            floor.record(9).expect("record 9");
            assert_eq!(floor.min_version().unwrap(), 9);
        }
        std::fs::remove_dir_all(&scratch.0).expect("an attacker unlinks the floor");
        let reopened = FileManifestFloor::with_bootstrap(&scratch.0, 4).expect("reopen");
        assert_eq!(
            reopened.min_version().unwrap(),
            4,
            "the durable floor is gone, but no manifest below the declared minimum is \
             acceptable"
        );
        // Without a bootstrap the same deletion does reset to 0 — which is why the
        // bootstrap exists, and why this asymmetry is worth pinning.
        let bare = FileManifestFloor::open(&scratch.0).expect("reopen bare");
        assert_eq!(bare.min_version().unwrap(), 0);
    }

    #[test]
    fn a_floor_raised_by_another_writer_is_honoured() {
        // Two handles on one directory. The second writer's higher floor must be
        // enforced by the first handle too — it re-reads rather than trusting a cache,
        // so a sidecar that fetched a newer manifest cannot be undercut.
        let scratch = Scratch::new("concurrent");
        let mut first = FileManifestFloor::open(&scratch.0).expect("open first");
        first.record(2).expect("record 2");
        let mut second = FileManifestFloor::open(&scratch.0).expect("open second");
        second.record(11).expect("record 11");
        assert_eq!(
            first.min_version().unwrap(),
            11,
            "the first handle sees the floor the second writer raised"
        );
        // And it will not walk it back.
        first.record(5).expect("no-op");
        assert_eq!(
            FileManifestFloor::open(&scratch.0)
                .unwrap()
                .min_version()
                .unwrap(),
            11
        );
    }

    /// Markers below the maximum are pruned so the directory does not grow without
    /// bound — and pruning below the max cannot change the max.
    #[test]
    fn superseded_markers_are_pruned() {
        let scratch = Scratch::new("prune");
        let mut floor = FileManifestFloor::open(&scratch.0).expect("open");
        floor.record(1).expect("record 1");
        floor.record(2).expect("record 2");
        floor.record(3).expect("record 3");
        let entries: Vec<_> = std::fs::read_dir(&scratch.0)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries, vec!["3".to_owned()]);
        assert_eq!(floor.min_version().unwrap(), 3);
    }
}
