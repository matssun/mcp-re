// SPDX-License-Identifier: Apache-2.0
//! WHICH bytes this archive holds.
//!
//! One fact: **the object named by a digest, or nothing** — and it is the same object on
//! the way out as it was on the way in, or it is refused. Nothing here decides whether an
//! absence is fatal, what a record means, or whether this process may write more of them.
//!
//! # Reading takes no write authority, and the type says so
//!
//! [`FsRetainedArchive::open_read_only`] opens an existing directory and nothing more: it
//! creates nothing, writes no probe, and starts no thread. So it works against a read-only
//! mount, a `0555` directory or a filesystem snapshot — the ordinary ways an archive is
//! handed to somebody who is meant to audit it and not to add to it.
//!
//! It does check that the path exists and is a directory, because a mistyped archive path
//! must refuse where an operator is looking rather than report every hop of every chain
//! missing.
//!
//! # What it deliberately does not do
//!
//! It does not warn about a loose directory mode. That warning belongs to the half that
//! CREATES the store ([`super::FsRetainedEvidenceStore::open`]), where the deployment
//! choosing the mode is the party being told. A reader has been handed a directory; it is
//! not its place to grade the custody of somebody else's archive, and a warning printed by
//! every audit run would train an operator to ignore it.

use std::path::Path;
use std::path::PathBuf;

use mcp_re_http_profile::scitt::EvidenceDigest;

/// A read view of a retained-evidence directory: one file per object, named by digest.
pub struct FsRetainedArchive {
    root: PathBuf,
}

impl FsRetainedArchive {
    /// Open an EXISTING archive directory for reading only.
    ///
    /// No `create_dir_all`, no writability probe, no writer thread — an archive on a
    /// read-only mount or a snapshot opens here and a write-side open would refuse it.
    pub fn open_read_only(root: impl AsRef<Path>) -> std::io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        if !std::fs::metadata(&root)?.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotADirectory,
                "retained-evidence archive is not a directory",
            ));
        }
        Ok(FsRetainedArchive { root })
    }

    /// A read view over a root the WRITE half has already created and proved.
    ///
    /// `pub(super)`: the write half is the only legitimate producer of an archive whose
    /// root has not been separately checked to exist, because creating it is what it just
    /// did. Anything outside this module goes through
    /// [`FsRetainedArchive::open_read_only`], which establishes that for itself.
    pub(super) fn over_created_root(root: PathBuf) -> Self {
        FsRetainedArchive { root }
    }

    /// The directory every object and marker lives in.
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    /// The path for a digest — the ONE derivation of an object's name from its digest.
    ///
    /// base64url is used for the digest everywhere in this profile, and it contains `-`
    /// and `_` but never `/`, `.` or NUL — so it is already a safe single path segment.
    /// The check is kept anyway: a filename derived from a value that arrived from
    /// outside is exactly where path traversal gets in, and "the encoding cannot produce
    /// a separator" is a property of the encoder, not of the string in hand.
    ///
    /// `pub(crate)` because the WRITE path needs the final name of an object it is about
    /// to stage, and a second copy of this rule is how the read and write halves would come
    /// to disagree about which names are legal.
    pub(crate) fn object_path(&self, digest: &EvidenceDigest) -> std::io::Result<PathBuf> {
        let name = digest.as_str();
        let safe = !name.is_empty()
            && name.len() <= 64
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !safe {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "evidence digest is not a base64url token",
            ));
        }
        Ok(self.root.join(name))
    }

    /// The bytes for `digest`, or `None` if this archive does not hold them.
    ///
    /// Absence is `None` rather than an error: an archive legitimately does not hold every
    /// object in existence, and the caller — not the archive — decides whether a missing
    /// object is fatal for the verification it is attempting.
    pub fn get(&self, digest: &EvidenceDigest) -> std::io::Result<Option<Vec<u8>>> {
        let path = self.object_path(digest)?;
        match std::fs::read(&path) {
            Ok(bytes) => {
                // Re-address what came back. The file could have been replaced on disk
                // by something outside this store, and returning bytes that do not hash
                // to the requested digest would break the one property a
                // content-addressed store has.
                if EvidenceDigest::of(&bytes) != *digest {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "retained evidence does not hash to the digest it is stored under",
                    ));
                }
                Ok(Some(bytes))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::fixtures::TempDir;
    use super::super::FsRetainedEvidenceStore;
    use mcp_re_http_profile::scitt::RetainedEvidenceStore;

    /// The property the whole split rests on: an archive nobody may write to still reads.
    #[test]
    #[cfg(unix)]
    fn a_read_only_directory_opens_for_reading_and_serves_its_objects() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new();
        let root = dir.path().join("archive");
        let digest = {
            let mut store = FsRetainedEvidenceStore::open(&root).expect("open for writing");
            store.put(b"a retained hop").expect("put")
        };
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o555)).expect("chmod");

        let opened = FsRetainedArchive::open_read_only(&root);
        let write_open = FsRetainedEvidenceStore::open(&root);
        let read_back = opened.as_ref().map(|a| a.get(&digest));

        // Restore before asserting, so the temp dir can be removed either way.
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        assert!(
            write_open.is_err(),
            "the write half must still refuse a directory it cannot write"
        );
        assert!(opened.is_ok(), "the read half must not need write authority");
        assert_eq!(
            read_back.expect("opened").expect("get").as_deref(),
            Some(b"a retained hop".as_slice())
        );
    }

    /// Opening for reading creates nothing. An archive is somebody else's directory.
    #[test]
    fn opening_for_reading_does_not_create_the_directory() {
        let dir = TempDir::new();
        let absent = dir.path().join("never-created");
        assert!(FsRetainedArchive::open_read_only(&absent).is_err());
        assert!(!absent.exists(), "a read-only open must create nothing");
    }

    /// A path that is not a directory refuses at open, where an operator is looking —
    /// rather than reporting every hop of the chain missing.
    #[test]
    fn a_path_that_is_not_a_directory_is_refused_at_open() {
        let dir = TempDir::new();
        let file = dir.path().join("not-a-dir");
        std::fs::write(&file, b"x").expect("write");
        assert!(FsRetainedArchive::open_read_only(&file).is_err());
    }

    /// The re-addressing check lives HERE, so it runs for a reader that never had write
    /// authority — the case an auditor is.
    #[test]
    fn bytes_replaced_on_disk_are_refused_by_the_read_view() {
        let dir = TempDir::new();
        let root = dir.path().join("archive");
        let digest = {
            let mut store = FsRetainedEvidenceStore::open(&root).expect("open");
            store.put(b"authentic").expect("put")
        };
        std::fs::write(root.join(digest.as_str()), b"swapped").expect("tamper");
        let archive = FsRetainedArchive::open_read_only(&root).expect("open read-only");
        assert!(
            archive.get(&digest).is_err(),
            "bytes that do not hash to the requested digest are not this object"
        );
    }

    /// A digest that is not a base64url token never reaches the filesystem.
    #[test]
    fn a_non_token_digest_cannot_escape_the_root() {
        let dir = TempDir::new();
        let root = dir.path().join("archive");
        let _store = FsRetainedEvidenceStore::open(&root).expect("open");
        let archive = FsRetainedArchive::open_read_only(&root).expect("open read-only");
        let traversal: EvidenceDigest =
            serde_json::from_str("\"../../etc/passwd\"").expect("deserialize");
        assert!(archive.get(&traversal).is_err());
    }
}
