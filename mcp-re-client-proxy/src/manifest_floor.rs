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
//!
//! ## What the floor directory's integrity buys, and what it does not
//!
//! Everything above defends the floor DOWNWARD. Upward the markers are unauthenticated
//! by construction, so a writer of the directory can create `18446744073709551615` and
//! pin the floor at `u64::MAX`, after which every manifest — including a break-glass
//! revocation — is refused as `Stale`. This is the same shape as the TUF fast-forward
//! attack, and it is a denial of service reachable by whoever holds the cheapest write
//! capability in the deployment.
//!
//! [`FileManifestFloor::with_bounds`] declares a CEILING, and the ceiling
//! [`fail-stops`](mcp_re_client_core::TrustManifestError::FloorAboveCeiling) — it never
//! clamps. `min(stored_floor, ceiling)` would be worse than no ceiling: it lowers a
//! floor on the say-so of the storage that just proved untrustworthy, re-opening the
//! rollback window silently and letting the attacker pick which versions come back by
//! choosing how far to overshoot. A floor above its ceiling means the storage and the
//! trust domain that bounds it disagree, and neither one may be preferred; the client
//! stops and says so.
//!
//! The ceiling is worth exactly the trust domain it comes from. Read from a config file
//! the floor-directory writer can also edit, it adds nothing — it must be no more
//! writable than the org keys themselves.
//!
//! What this does NOT do is preserve availability. A malicious fast-forward still stops
//! the client; it stops it LOUDLY, at a named error an operator can act on, instead of
//! silently withdrawing every anchor once the loaded manifest expires. Closing the
//! finding underneath needs the floor to stop being state the constrained actor can
//! write at all — authenticated, anti-replay, atomically updated storage outside the
//! writer's authority. Until then the floor directory must be permissioned no more
//! widely than the trust store itself; the bootstrap bounds what a directory-writer can
//! take away, and the ceiling bounds what it can add.

use std::fs::File;
use std::io;
use std::path::Path;
use std::path::PathBuf;

use mcp_re_client_core::ManifestVersionFloor;
use mcp_re_client_core::TrustManifestError;

/// A directory-backed [`ManifestVersionFloor`].
///
/// An ABSENT or empty directory reads as the bootstrap minimum (0 unless one is
/// declared). Entries that are not marker names are ignored — they are not versions
/// this floor recorded, and they cannot lower the maximum the real markers set — while
/// a directory that cannot be READ at all fails closed with
/// [`TrustManifestError::FloorUnreadable`], because "we do not know what we have
/// accepted" and "we have accepted nothing" are opposite statements.
#[derive(Debug, Clone)]
pub struct FileManifestFloor {
    dir: PathBuf,
    /// The operator-declared minimum. The effective floor is never below it, so
    /// deleting the directory — or losing it with an ephemeral volume — cannot
    /// re-open the rollback window past this point.
    bootstrap: u64,
    /// The operator-declared maximum the STORED floor may reach. `None` leaves the
    /// directory unbounded upward. A stored floor above it is a fail-stop, never a
    /// clamp — see the module docs.
    ceiling: Option<u64>,
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
        Self::with_bounds(path, bootstrap, None)
    }

    /// Open the floor with an operator-declared minimum AND maximum.
    ///
    /// `ceiling` bounds what a writer of the floor directory can ADD. Exceeding it is
    /// [`TrustManifestError::FloorAboveCeiling`] — the client stops rather than serving
    /// under a floor it cannot reconcile, and rather than clamping down to a value the
    /// untrusted storage effectively chose. It is only worth the trust domain it comes
    /// from: a ceiling the floor-directory writer can also edit bounds nothing.
    ///
    /// A `bootstrap` above the `ceiling` is that same contradiction declared in one
    /// place, so it is refused here rather than at the first verification.
    pub fn with_bounds(
        path: impl Into<PathBuf>,
        bootstrap: u64,
        ceiling: Option<u64>,
    ) -> Result<Self, TrustManifestError> {
        if let Some(ceiling) = ceiling {
            if bootstrap > ceiling {
                return Err(TrustManifestError::FloorAboveCeiling {
                    floor: bootstrap,
                    ceiling,
                });
            }
        }
        let dir = path.into();
        std::fs::create_dir_all(&dir)
            .map_err(|_| TrustManifestError::FloorNotPersisted("create trust-anchor floor dir"))?;
        let floor = FileManifestFloor {
            dir,
            bootstrap,
            ceiling,
        };
        // Prove it is readable — and within its declared bounds — now rather than at the
        // first verification.
        floor.min_version()?;
        Ok(floor)
    }

    /// The directory this floor persists to.
    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// The declared ceiling, if any.
    pub fn ceiling(&self) -> Option<u64> {
        self.ceiling
    }

    /// Fail-stop when `value` is above the declared ceiling.
    ///
    /// The comparison is `>`, not `>=`: a floor exactly AT the ceiling is the highest
    /// state the operator said could exist, which is consistent, not contradictory.
    fn check_ceiling(&self, value: u64) -> Result<(), TrustManifestError> {
        match self.ceiling {
            Some(ceiling) if value > ceiling => Err(TrustManifestError::FloorAboveCeiling {
                floor: value,
                ceiling,
            }),
            _ => Ok(()),
        }
    }
}

impl ManifestVersionFloor for FileManifestFloor {
    fn min_version(&self) -> Result<u64, TrustManifestError> {
        // Re-read every time rather than cache: another process (a sidecar updater, a
        // second client) may have raised the floor since this handle was opened, and
        // the higher value is the safe one to enforce.
        let durable = read_floor(&self.dir)?;
        self.check_ceiling(durable)?;
        Ok(durable.max(self.bootstrap))
    }

    fn record(&mut self, version: u64) -> Result<(), TrustManifestError> {
        let durable = read_floor(&self.dir)?;
        self.check_ceiling(durable)?;
        // A validly signed manifest whose version is above the ceiling means the
        // operator's ceiling is stale, not that the manifest is bad. Recording it anyway
        // would push the stored floor past the bound and brick every later read, so the
        // inconsistency is reported at the one call that would create it.
        self.check_ceiling(version)?;
        if durable > version {
            // Another writer raised the floor ABOVE this version between the load's
            // floor read and this call. The accepted manifest passed a floor that no
            // longer holds, so reporting success here would hand back anchors from a
            // document the floor has since refused — the rollback this module exists to
            // make impossible, reached through a race instead of a replay. The caller
            // treats the error as "these anchors are not usable" and keeps what it had.
            return Err(TrustManifestError::FloorNotPersisted(
                "trust-anchor floor was raised past this version concurrently",
            ));
        }
        if durable == version {
            // Already recorded — the marker exists, so no marker is created. Not an
            // error: a concurrent writer recording the same version is exactly the
            // outcome asked for.
            //
            // It still goes through `persist`, which is what makes the directory entry
            // DURABLE. The trait requires the floor to be durable before `record`
            // returns Ok, and the marker seen here may be one another process created
            // and has not fsynced: returning early reported a durability this process
            // never established, and a power loss in that window loses the marker, so
            // the next start reads the older floor and a superseded manifest — one that
            // has not yet revoked a compromised root — becomes acceptable again.
            persist(&self.dir, version)
                .map_err(|_| TrustManifestError::FloorNotPersisted("fsync trust-anchor floor"))?;
            return Ok(());
        }
        // Deliberately compared against the DURABLE floor alone, not against
        // `min_version()`. Folding the bootstrap in here meant no accepted version at or
        // below it was ever written down, so the durable half of the floor silently
        // stopped working for the deployments that declared one: a second process on the
        // same volume — or the same one after the bootstrap is lowered — read 0 and
        // accepted a replayed manifest. The bootstrap belongs to the ACCEPT decision;
        // the directory records what was accepted.
        persist(&self.dir, version)
            .map_err(|_| TrustManifestError::FloorNotPersisted("write trust-anchor floor"))?;
        // Best-effort tidy-up. Removing markers strictly BELOW the new maximum cannot
        // lower it, so a failure here is not a correctness problem — it only leaves
        // entries behind.
        prune_below(&self.dir, version);
        Ok(())
    }
}

/// The maximum recorded version in `dir`; 0 when the directory is absent or holds no
/// marker.
///
/// An entry that is not a marker name is NOT a floor this function failed to read: the
/// only writer of this directory is [`persist`], which creates decimal `u64` names and
/// nothing else, so a name that is not one never encoded an accepted version and
/// ignoring it cannot put the maximum below what the real markers say. Treating it as
/// unreadable instead made one stray file a permanent brick — `lost+found` on an ext4
/// PVC, `.DS_Store` on a dev volume, or a single attacker-written byte — that stopped
/// the client from starting and, once the loaded manifest expired, made a running one
/// withdraw every anchor. The threat it was meant to answer, littering the directory to
/// LOWER the floor, does not exist: adding entries cannot remove the marker that sets
/// the maximum, and removing it is the unlink case the declared bootstrap answers.
///
/// A genuine I/O failure — the directory cannot be read, or an entry cannot be
/// enumerated — is still fatal: then the floor really is unknown.
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
        if let Some(version) = marker_version(&entry.file_name()) {
            max = max.max(version);
        }
    }
    Ok(max)
}

/// The version a directory entry name records, or `None` when the name is not one
/// [`persist`] could have written.
fn marker_version(name: &std::ffi::OsStr) -> Option<u64> {
    let name = name.to_str()?;
    // `u64::from_str` also accepts a leading `+`, and a leading zero would let one
    // version be spelled many ways; a marker is exactly the digits `to_string` emits.
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if name.len() > 1 && name.starts_with('0') {
        return None;
    }
    name.parse::<u64>().ok()
}

/// Durably record `version`: create its marker, fsync it, fsync the directory.
///
/// An ALREADY-EXISTING marker is success, not a failure: it means a concurrent writer
/// recorded the same version, which is exactly the outcome asked for. It still gets the
/// directory fsync, because the caller reads `Ok` as "this version can never be
/// accepted again" and the entry the OTHER writer created may not be durable yet —
/// returning early there reported durability this process had not established, and a
/// power loss in that window loses the marker and re-opens the rollback window on the
/// next start.
fn persist(dir: &Path, version: u64) -> io::Result<()> {
    let marker = dir.join(version.to_string());
    match File::create_new(&marker) {
        Ok(file) => file.sync_all()?,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
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
        // Only entries this module wrote. Anything else is not a floor and not this
        // module's to delete.
        if let Some(v) = marker_version(&entry.file_name()) {
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
            .expect_err("a version the floor has already passed is not recordable");
        assert_eq!(floor.min_version().unwrap(), 9, "the floor never goes down");
        floor
            .record(9)
            .expect("re-recording the same version is a no-op");
        assert_eq!(floor.min_version().unwrap(), 9);
    }

    /// The equal-version arm must still ESTABLISH durability, not merely observe a
    /// marker.
    ///
    /// `record` reports "this version can never be accepted again", and in the module's
    /// own multi-writer topology the marker it sees may be one another process created
    /// and has not fsynced. Short-circuiting there claimed a durability this process
    /// never established; a power loss in that window loses the marker, the next start
    /// reads the older floor, and a superseded manifest — one that has not yet revoked a
    /// compromised root — is acceptable again.
    ///
    /// Driven through the one equal-version case whose durability step can be made to
    /// fail deterministically: the floor directory is gone, so there is nothing to fsync
    /// and nothing durable to report.
    #[test]
    fn an_equal_version_record_still_establishes_durability() {
        let scratch = Scratch::new("equal-durable");
        let mut floor = FileManifestFloor::open(&scratch.0).expect("open");
        // A marker another writer created, never routed through this handle.
        persist(&scratch.0, 5).expect("the sidecar records 5");
        floor
            .record(5)
            .expect("re-recording a version the volume already carries is not an error");
        assert_eq!(floor.min_version().unwrap(), 5);

        // The volume went away. `read_floor` reports 0, so recording 0 takes the
        // equal-version arm — and there is no directory to make anything durable in.
        std::fs::remove_dir_all(&scratch.0).expect("the floor directory disappears");
        assert_eq!(floor.min_version().unwrap(), 0);
        assert_eq!(
            floor.record(0).err(),
            Some(TrustManifestError::FloorNotPersisted(
                "fsync trust-anchor floor"
            )),
            "Ok here reports a durability nothing established",
        );
    }

    /// The load reads the floor, verifies against that snapshot, and only then records.
    /// If another writer raises the floor inside that window, the version this process
    /// accepted no longer clears it — and `record` reporting a silent `Ok` is what let
    /// the caller go on to serve under a trust picture the floor had already refused.
    #[test]
    fn a_concurrent_raise_makes_the_accepted_version_unrecordable() {
        let scratch = Scratch::new("raced");
        let mut floor = FileManifestFloor::open(&scratch.0).expect("open");
        // The load read floor 0 and verified manifest v6. Meanwhile a sidecar accepted
        // v10 — the manifest that revoked a root.
        persist(&scratch.0, 10).expect("the sidecar records 10");
        assert_eq!(
            floor.record(6).err(),
            Some(TrustManifestError::FloorNotPersisted(
                "trust-anchor floor was raised past this version concurrently"
            )),
            "v6 must not be handed back as usable once the floor has passed it",
        );
        assert_eq!(floor.min_version().unwrap(), 10);
    }

    /// The durable directory must record what was ACCEPTED, whatever this process's
    /// bootstrap happens to be. Folding the bootstrap into the record decision meant a
    /// client with a declared minimum wrote nothing at or below it, so the volume it
    /// shares with the next process said 0 and a replayed manifest was acceptable
    /// again — the rollback the floor exists to refuse, through the option documented
    /// as the safe one.
    #[test]
    fn a_declared_bootstrap_does_not_suppress_the_durable_record() {
        let scratch = Scratch::new("bootstrap-record");
        {
            let mut floor = FileManifestFloor::with_bootstrap(&scratch.0, 100).expect("open");
            floor.record(100).expect("record the accepted version");
        }
        // A second process on the same volume, with no bootstrap of its own.
        let other = FileManifestFloor::open(&scratch.0).expect("reopen without a bootstrap");
        assert_eq!(
            other.min_version().unwrap(),
            100,
            "the accepted version is on the shared volume, not only in one process's config",
        );
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

    /// A non-marker entry is not a floor. `lost+found` on an ext4 PVC, `.DS_Store` on a
    /// dev volume, or one attacker-written byte must not brick the client: failing
    /// closed on them stopped it from starting and made a running one withdraw every
    /// anchor as soon as its manifest expired. Littering cannot lower the maximum —
    /// only deleting the marker can, and that is the unlink case the bootstrap answers.
    #[test]
    fn a_non_marker_entry_is_ignored_and_does_not_lower_the_floor() {
        let scratch = Scratch::new("junk");
        let mut floor = FileManifestFloor::open(&scratch.0).expect("open");
        floor.record(12).expect("record");
        std::fs::write(scratch.0.join("not-a-number"), b"").expect("write garbage");
        std::fs::write(scratch.0.join(".DS_Store"), b"x").expect("write a dev artefact");
        std::fs::write(scratch.0.join("99x"), b"").expect("write a near-miss name");
        std::fs::write(scratch.0.join("0099"), b"").expect("write a padded near-miss");
        std::fs::create_dir(scratch.0.join("lost+found")).expect("an ext4 mount root");

        let reopened = FileManifestFloor::open(&scratch.0).expect("the floor is still readable");
        assert_eq!(
            reopened.min_version().unwrap(),
            12,
            "the recorded maximum stands; junk neither raises nor lowers it",
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
        first
            .record(5)
            .expect_err("a version the shared floor has passed is refused, not silently ok");
        assert_eq!(
            FileManifestFloor::open(&scratch.0)
                .unwrap()
                .min_version()
                .unwrap(),
            11
        );
    }

    /// `record` reports "durable" to a caller that treats it as "this version can never
    /// be accepted again", so the losing writer of a concurrent create still owes the
    /// directory fsync that makes the WINNER's entry durable. Observed through the only
    /// failure that separates the two paths: a directory that cannot be opened for the
    /// fsync.
    #[cfg(unix)]
    #[test]
    fn an_already_existing_marker_still_syncs_the_directory() {
        use std::os::unix::fs::PermissionsExt;

        let scratch = Scratch::new("dirsync");
        std::fs::create_dir_all(&scratch.0).expect("create");
        persist(&scratch.0, 5).expect("the winning writer creates the marker");

        // Write + traverse, but NOT read: `create_new` still reports AlreadyExists,
        // while opening the directory for the fsync is denied.
        std::fs::set_permissions(&scratch.0, std::fs::Permissions::from_mode(0o333))
            .expect("chmod");
        let enforced = std::fs::read_dir(&scratch.0).is_err();
        let outcome = persist(&scratch.0, 5);
        std::fs::set_permissions(&scratch.0, std::fs::Permissions::from_mode(0o755))
            .expect("restore");

        if enforced {
            assert!(
                outcome.is_err(),
                "the already-exists path must not report durability it never established",
            );
        }
    }

    /// The fast-forward: one marker named `u64::MAX` pins the floor so high that every
    /// future manifest — including a break-glass revocation — is refused as `Stale`.
    /// With a ceiling declared, the client stops at a named error instead.
    #[test]
    fn a_fast_forwarded_floor_fails_stop_against_the_ceiling() {
        let scratch = Scratch::new("ceiling-fastforward");
        let floor = FileManifestFloor::with_bounds(&scratch.0, 0, Some(50)).expect("open");
        persist(&scratch.0, u64::MAX).expect("an attacker writes the highest marker there is");
        assert_eq!(
            floor.min_version().err(),
            Some(TrustManifestError::FloorAboveCeiling {
                floor: u64::MAX,
                ceiling: 50,
            }),
            "a floor above its ceiling is reported, not reconciled",
        );
    }

    /// The negative control for the whole design. `min(stored, ceiling)` would answer 50
    /// here and go on serving — accepting every manifest between 51 and 90 that the real
    /// floor had already passed, chosen by the same writer that overshot. The ONLY
    /// acceptable answer is the error.
    #[test]
    fn the_ceiling_never_clamps_the_floor_downward() {
        let scratch = Scratch::new("ceiling-no-clamp");
        let floor = FileManifestFloor::with_bounds(&scratch.0, 0, Some(50)).expect("open");
        persist(&scratch.0, 90).expect("the stored floor overshoots the ceiling");
        let outcome = floor.min_version();
        assert!(
            outcome.is_err(),
            "clamping to {:?} would re-admit versions 51..=90 the floor had passed",
            outcome,
        );
        assert_eq!(
            outcome.err(),
            Some(TrustManifestError::FloorAboveCeiling {
                floor: 90,
                ceiling: 50
            }),
        );
    }

    /// A ceiling bounds the storage, not ordinary operation: everything at or below it
    /// behaves exactly as it did before the ceiling existed.
    #[test]
    fn a_floor_within_its_ceiling_is_untouched() {
        let scratch = Scratch::new("ceiling-within");
        let mut floor = FileManifestFloor::with_bounds(&scratch.0, 2, Some(50)).expect("open");
        assert_eq!(
            floor.min_version().unwrap(),
            2,
            "the bootstrap still applies"
        );
        floor
            .record(50)
            .expect("a version AT the ceiling is consistent, not contradictory");
        assert_eq!(floor.min_version().unwrap(), 50);
    }

    /// A signed manifest above the ceiling means the operator's ceiling is stale. It is
    /// refused at the call that would otherwise write an unreadable floor — recording it
    /// would brick every later read, turning one stale config value into an outage that
    /// needs manual repair of the directory.
    #[test]
    fn recording_above_the_ceiling_is_refused_before_it_bricks_the_floor() {
        let scratch = Scratch::new("ceiling-record");
        let mut floor = FileManifestFloor::with_bounds(&scratch.0, 0, Some(50)).expect("open");
        assert_eq!(
            floor.record(51).err(),
            Some(TrustManifestError::FloorAboveCeiling {
                floor: 51,
                ceiling: 50
            }),
        );
        assert_eq!(
            read_floor(&scratch.0).unwrap(),
            0,
            "nothing was persisted, so the floor is still readable",
        );
    }

    /// The same contradiction declared in one place: an operator who sets a bootstrap
    /// above the ceiling has written two mutually exclusive statements, and the process
    /// should not start.
    #[test]
    fn a_bootstrap_above_the_ceiling_is_refused_at_construction() {
        let scratch = Scratch::new("ceiling-bootstrap");
        assert_eq!(
            FileManifestFloor::with_bounds(&scratch.0, 60, Some(50)).err(),
            Some(TrustManifestError::FloorAboveCeiling {
                floor: 60,
                ceiling: 50
            }),
        );
    }

    /// No ceiling is the old behaviour exactly — the fast-forward is undefended, which
    /// is the honest posture for a deployment that has not declared a bound.
    #[test]
    fn without_a_ceiling_the_floor_is_unbounded_upward() {
        let scratch = Scratch::new("ceiling-absent");
        let floor = FileManifestFloor::open(&scratch.0).expect("open");
        persist(&scratch.0, u64::MAX).expect("write the fast-forward marker");
        assert_eq!(
            floor.min_version().unwrap(),
            u64::MAX,
            "undefended, and visibly so",
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
