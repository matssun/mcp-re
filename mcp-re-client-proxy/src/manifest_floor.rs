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
//! This is the floor, on disk, with the same durability discipline as the replay store:
//! temp file → `sync_all` → atomic rename → fsync the directory. Each step matters for
//! a different failure. Without the pre-rename fsync a power loss can publish a renamed
//! file with unflushed contents; without the directory fsync the rename itself can be
//! lost. Either way the next start reads a stale floor and re-accepts a superseded
//! manifest — which is exactly the event this file exists to make impossible.
//!
//! The floor is monotonic: [`ManifestVersionFloor::record`] never lowers it, so a
//! concurrent writer that already raised it cannot be walked back, and re-applying the
//! current manifest is a no-op rather than a rewrite.

use std::fs::File;
use std::io;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use mcp_re_client_core::ManifestVersionFloor;
use mcp_re_client_core::TrustManifestError;

/// A file-backed [`ManifestVersionFloor`].
///
/// A MISSING file reads as floor 0 — the honest meaning of "this verifier has never
/// accepted a manifest". Any other read error (permissions, a truncated or non-numeric
/// file, a directory in the way) is NOT floor 0: it is an unknown floor, and the load
/// fails closed with [`TrustManifestError::FloorUnreadable`]. Treating a corrupt floor
/// as zero would let deleting one file re-open the rollback window.
#[derive(Debug, Clone)]
pub struct FileManifestFloor {
    path: PathBuf,
    /// Mirrors the on-disk value so a `record` that does not raise the floor performs
    /// no write at all. Seeded on construction, and only ever advanced after a
    /// successful durable write — never ahead of the file.
    cached: u64,
}

impl FileManifestFloor {
    /// Open (or adopt) the floor file at `path`, reading the current value.
    ///
    /// Fails closed if the file exists but cannot be read or parsed, rather than
    /// starting from 0 — see the type docs.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, TrustManifestError> {
        let path = path.into();
        let cached = read_floor(&path)?;
        Ok(FileManifestFloor { path, cached })
    }

    /// The path this floor persists to.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl ManifestVersionFloor for FileManifestFloor {
    fn min_version(&self) -> Result<u64, TrustManifestError> {
        // Re-read rather than trust the cache: another process (a sidecar updater, a
        // second client) may have raised the floor since this handle was opened, and
        // the higher value is the safe one to enforce.
        let on_disk = read_floor(&self.path)?;
        Ok(on_disk.max(self.cached))
    }

    fn record(&mut self, version: u64) -> Result<(), TrustManifestError> {
        let current = self.min_version()?;
        if version <= current {
            // Monotonic: a lower or equal version leaves the floor alone. Not an error —
            // a concurrent writer may legitimately have got there first.
            self.cached = current;
            return Ok(());
        }
        persist(&self.path, version)
            .map_err(|_| TrustManifestError::FloorNotPersisted("write trust-anchor floor"))?;
        self.cached = version;
        Ok(())
    }
}

/// Read the floor from `path`. A missing file is 0; anything else unreadable fails closed.
fn read_floor(path: &Path) -> Result<u64, TrustManifestError> {
    match std::fs::read_to_string(path) {
        Ok(text) => text
            .trim()
            .parse::<u64>()
            .map_err(|_| TrustManifestError::FloorUnreadable("trust-anchor floor is not a u64")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(_) => Err(TrustManifestError::FloorUnreadable("read trust-anchor floor")),
    }
}

/// Write `version` to `path` durably: temp file → fsync → rename → fsync the directory.
fn persist(path: &Path, version: u64) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut file = File::create(&tmp)?;
        file.write_all(version.to_string().as_bytes())?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    let dir = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    File::open(dir)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique scratch path per test. No `tempfile` dependency in this crate, and the
    /// pid keeps concurrent `cargo test` runs from colliding.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!("mcp-re-floor-{name}-{}", std::process::id()));
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_file(path.with_extension("tmp"));
            Scratch(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            let _ = std::fs::remove_file(self.0.with_extension("tmp"));
        }
    }

    #[test]
    fn a_missing_file_is_floor_zero() {
        let scratch = Scratch::new("missing");
        let floor = FileManifestFloor::open(&scratch.0).expect("open");
        assert_eq!(floor.min_version().unwrap(), 0, "never accepted a manifest yet");
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
        floor.record(4).expect("recording a lower version is a no-op, not an error");
        assert_eq!(floor.min_version().unwrap(), 9, "the floor never goes down");
        floor.record(9).expect("re-recording the same version is a no-op");
        assert_eq!(floor.min_version().unwrap(), 9);
    }

    #[test]
    fn a_corrupt_floor_fails_closed_instead_of_reading_as_zero() {
        // Deleting the file means "nothing accepted yet" and is allowed. CORRUPTING it
        // must not be a cheaper way to say the same thing, or the rollback window opens
        // by tampering with one file.
        let scratch = Scratch::new("corrupt");
        std::fs::write(&scratch.0, b"not-a-number").expect("write garbage");
        assert_eq!(
            FileManifestFloor::open(&scratch.0).err(),
            Some(TrustManifestError::FloorUnreadable("trust-anchor floor is not a u64")),
        );
    }

    #[test]
    fn no_tmp_sibling_is_left_behind() {
        // The temp file is an implementation detail of the atomic write; a leftover one
        // would be read by nothing but is a sign the rename did not happen.
        let scratch = Scratch::new("no-tmp");
        let mut floor = FileManifestFloor::open(&scratch.0).expect("open");
        floor.record(3).expect("record");
        assert!(scratch.0.exists(), "the floor file exists");
        assert!(
            !scratch.0.with_extension("tmp").exists(),
            "the temp file was renamed, not left alongside"
        );
    }

    #[test]
    fn a_floor_raised_by_another_writer_is_honoured() {
        // Two handles on one file. The second writer's higher floor must be enforced by
        // the first handle too — it re-reads rather than trusting its own cache, so a
        // sidecar that fetched a newer manifest cannot be undercut.
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
        assert_eq!(FileManifestFloor::open(&scratch.0).unwrap().min_version().unwrap(), 11);
    }
}
