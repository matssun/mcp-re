// SPDX-License-Identifier: Apache-2.0
//! The WRITE half of a retained-evidence directory.
//!
//! One fact: **this process may add objects to this archive, and an acknowledged object is
//! on disk under its own name.** Retrieval is not here — the store HOLDS a
//! [`FsRetainedArchive`] and reads through it, so the re-addressing rule that makes a name
//! determine its bytes exists exactly once and a writer's `get` is the same `get` an
//! auditor runs.

use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use mcp_re_http_profile::scitt::EvidenceDigest;
use mcp_re_http_profile::scitt::RetainedEvidenceStore;

use super::private_file::create_root;
use super::private_file::open_private;
use super::private_file::unique_suffix;
use super::FsRetainedArchive;

/// A retained-evidence store over a directory, one file per object named by digest.
pub struct FsRetainedEvidenceStore {
    archive: FsRetainedArchive,
}

impl FsRetainedEvidenceStore {
    /// Open (creating if absent) a store rooted at `root`, PROVING it is writable.
    ///
    /// `create_dir_all` alone returns `Ok(())` for any existing directory whatever its
    /// mode and whatever its mount says, so it establishes nothing about a read-only
    /// volume, a `0555` directory or a mismatched `fsGroup` — the ordinary Kubernetes
    /// failures. A replica that starts on one of those refuses every call it then
    /// accepts. So a probe object is created, written, made durable and removed here:
    /// the failure surfaces where an operator is looking, at startup.
    ///
    /// This is a startup gate, not a guarantee about any later write — nothing can give
    /// that, which is why the serving path takes a durable reservation before the
    /// backend runs instead of trusting a probe.
    ///
    /// A process that only READS the archive must not come through here: opening for
    /// reading is [`FsRetainedArchive::open_read_only`], which takes no write authority
    /// and works against a read-only mount or a snapshot.
    pub fn open(root: impl AsRef<Path>) -> std::io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        create_root(&root)?;
        let store = FsRetainedEvidenceStore {
            archive: FsRetainedArchive::over_created_root(root),
        };
        store.probe_writable()?;
        Ok(store)
    }

    /// Create, write, make durable and remove one probe object.
    fn probe_writable(&self) -> std::io::Result<()> {
        let probe = self
            .archive
            .root()
            .join(format!(".writable.{}", unique_suffix()));
        let outcome = (|| {
            let mut file = open_private(&probe)?;
            file.write_all(b"mcp-re retained-evidence writability probe\n")?;
            file.sync_all()
        })();
        let _ = std::fs::remove_file(&probe);
        outcome
    }

    /// Write `bytes` to `path` durably EXCEPT for the directory entry.
    ///
    /// Unique temp name, write, `fsync` the file, rename. The caller must call
    /// [`FsRetainedEvidenceStore::sync_root`] before treating `path` as durable —
    /// splitting the barrier out is what lets one directory `fsync` cover a whole batch
    /// of renames, which is the only reduction the filesystem ordering law permits (a
    /// directory `fsync` has no per-entry granularity, so N renames followed by one
    /// `fsync` are exactly as durable as N `fsync`-per-rename pairs).
    ///
    /// `path` MUST be directly under the archive root, or the barrier the caller takes is
    /// over the wrong directory.
    pub fn stage_at(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        // Unique PER WRITE. A name that is only unique per process is not: the pid is
        // constant for the process lifetime and is 1 in a container, so crash residue
        // under that name makes every future write of the same object fail
        // `AlreadyExists` forever, and two replicas sharing one volume collide live.
        // A leftover temp under a name nothing will ever choose again is inert.
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(format!(".tmp.{}", unique_suffix()));
        let tmp = PathBuf::from(tmp);
        let staged = (|| {
            let mut file = open_private(&tmp)?;
            file.write_all(bytes)?;
            // Durability barrier before the rename: without it a power loss can publish
            // the renamed name with unflushed contents, and a reader then gets bytes
            // that do not hash to the digest they asked for — the one property a
            // content-addressed store has.
            //
            // `sync_all`, not `sync_data`: `fdatasync` is only obliged to flush the
            // metadata needed to read the data back, and the 0600 mode is not in that
            // set. These records carry covered credential headers.
            file.sync_all()?;
            drop(file);
            std::fs::rename(&tmp, path)
        })();
        if staged.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        staged
    }

    /// Stage `evidence` under its digest. See [`FsRetainedEvidenceStore::stage_at`] for
    /// the missing barrier.
    ///
    /// The final name is written unconditionally rather than skipped when it exists. A
    /// pre-existing file is NOT proof the object is there: a truncated or substituted
    /// file at that path would be reported as successfully retained, and the exchange
    /// served as accountable, with the loss discovered only when an auditor's `get`
    /// re-addresses it. Rewriting cannot lose data — the rename is atomic, so an
    /// interrupted rewrite leaves whatever was there untouched.
    pub fn stage(&self, evidence: &[u8]) -> std::io::Result<EvidenceDigest> {
        let digest = EvidenceDigest::of(evidence);
        let path = self.archive.object_path(&digest)?;
        self.stage_at(&path, evidence)?;
        Ok(digest)
    }

    /// The directory barrier: makes every rename staged into the root so far durable.
    pub fn sync_root(&self) -> std::io::Result<()> {
        std::fs::File::open(self.archive.root())?.sync_all()
    }
}

impl RetainedEvidenceStore for FsRetainedEvidenceStore {
    type Error = std::io::Error;

    /// One object, fully durable on return: stage it, then take the directory barrier
    /// immediately. The serving path uses [`FsRetainedEvidenceStore::stage`] plus a
    /// shared [`FsRetainedEvidenceStore::sync_root`] instead, so a batch of writes pays
    /// one directory barrier rather than one each.
    fn put(&mut self, evidence: &[u8]) -> Result<EvidenceDigest, Self::Error> {
        let digest = self.stage(evidence)?;
        // Without this the rename itself can be lost.
        self.sync_root()?;
        Ok(digest)
    }

    /// Through the archive, so the re-addressing check has exactly one implementation.
    fn get(&self, digest: &EvidenceDigest) -> Result<Option<Vec<u8>>, Self::Error> {
        self.archive.get(digest)
    }
}

#[cfg(test)]
mod tests {
    use super::super::fixtures::TempDir;
    use super::*;

    fn store() -> (TempDir, FsRetainedEvidenceStore) {
        let dir = TempDir::new();
        let store = FsRetainedEvidenceStore::open(dir.path()).expect("open");
        (dir, store)
    }

    #[test]
    fn retained_bytes_come_back_under_their_digest() {
        let (_dir, mut store) = store();
        let digest = store.put(b"request signature base").expect("put");
        assert_eq!(
            store.get(&digest).expect("get").as_deref(),
            Some(b"request signature base".as_slice())
        );
    }

    /// A missing object is `None`, not an error: the caller decides whether the absence
    /// is fatal for the verification it is attempting.
    #[test]
    fn a_missing_object_is_absent_rather_than_an_error() {
        let (_dir, store) = store();
        let never = EvidenceDigest::of(b"never retained");
        assert_eq!(store.get(&never).expect("get"), None);
    }

    /// Modified evidence is a different object, and the old digest still names the old
    /// bytes. Content addressing means a store cannot be used to substitute evidence.
    #[test]
    fn modified_evidence_gets_a_different_digest() {
        let (_dir, mut store) = store();
        let original = store.put(b"evidence").expect("put");
        let modified = store.put(b"evidenc3").expect("put");
        assert_ne!(original, modified);
        assert_eq!(
            store.get(&original).expect("get").as_deref(),
            Some(b"evidence".as_slice()),
            "the original digest still names the original bytes"
        );
    }

    /// Retaining the same bytes twice is idempotent — the digest is the same and no
    /// second copy appears.
    #[test]
    fn retaining_the_same_bytes_twice_is_idempotent() {
        let (dir, mut store) = store();
        let first = store.put(b"same").expect("put");
        let second = store.put(b"same").expect("put");
        assert_eq!(first, second);
        let files = std::fs::read_dir(dir.path()).expect("read dir").count();
        assert_eq!(files, 1, "one object, not two copies");
    }

    /// R7-C069/C070/C115: `create_dir_all` succeeds on an existing directory whatever
    /// its mode, so the startup gate proved nothing. Opening must fail where a write
    /// would fail — otherwise the replica reports ready and then refuses every call.
    #[test]
    #[cfg(unix)]
    fn opening_an_unwritable_directory_fails_at_open() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new();
        let root = dir.path().join("readonly");
        std::fs::create_dir_all(&root).expect("create");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o555)).expect("chmod");

        let opened = FsRetainedEvidenceStore::open(&root);

        // Restore before asserting, so the temp dir can be removed either way.
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        assert!(
            opened.is_err(),
            "an existing but unwritable store directory must stop the process at \
             startup, not refuse every request afterwards"
        );
    }

    /// And the store it does open leaves no probe behind.
    #[test]
    fn the_writability_probe_leaves_nothing_in_the_store() {
        let dir = TempDir::new();
        let root = dir.path().join("fresh");
        let _store = FsRetainedEvidenceStore::open(&root).expect("open");
        assert_eq!(
            std::fs::read_dir(&root).expect("read dir").count(),
            0,
            "the probe is removed; a store that has retained nothing is empty"
        );
    }

    /// R7-C075/C076: the store root is owner-only. Its objects are 0600 but a
    /// world-searchable directory still exposes them on a shared mount, and they carry
    /// the covered `authorization`/`dpop` headers verbatim.
    #[test]
    #[cfg(unix)]
    fn a_created_store_root_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new();
        let root = dir.path().join("private");
        let _store = FsRetainedEvidenceStore::open(&root).expect("open");
        let mode = std::fs::metadata(&root).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "mode was {:o}", mode & 0o777);
    }

    /// R7-C077: a pre-existing file at the digest path is not evidence that the object
    /// is there. Reporting success for a truncated one serves the exchange as
    /// accountable while the record is unreadable.
    #[test]
    fn a_truncated_object_is_rewritten_rather_than_reported_as_retained() {
        let (dir, mut store) = store();
        let digest = store.put(b"the whole record").expect("put");
        std::fs::write(dir.path().join(digest.as_str()), b"trunc").expect("truncate");

        let again = store.put(b"the whole record").expect("put again");

        assert_eq!(again, digest);
        assert_eq!(
            store.get(&digest).expect("get").as_deref(),
            Some(b"the whole record".as_slice()),
            "put must not report success for bytes that are not the object"
        );
    }

    /// R7-C078: crash residue under a temp name must not poison the object forever. The
    /// old name was `<digest>.tmp.<pid>` and the open is `create_new`, so a leftover
    /// made every future write of those bytes fail `AlreadyExists` — a permanent 503 for
    /// that exact call shape.
    #[test]
    fn temp_residue_from_an_interrupted_write_does_not_block_a_later_put() {
        let (dir, mut store) = store();
        let digest = EvidenceDigest::of(b"interrupted");
        let path = dir.path().join(digest.as_str());
        // Every temp name the old scheme could have produced for this object.
        for suffix in ["tmp.1", &format!("tmp.{}", std::process::id())] {
            std::fs::write(path.with_extension(suffix), b"residue").expect("residue");
        }

        let put = store
            .put(b"interrupted")
            .expect("residue must not block the write");

        assert_eq!(put, digest);
        assert_eq!(
            store.get(&digest).expect("get").as_deref(),
            Some(b"interrupted".as_slice())
        );
    }

    /// Two writes of the same object never choose the same temp name, so concurrent
    /// writers cannot truncate each other's inode.
    #[test]
    fn staging_the_same_object_concurrently_leaves_one_object_and_no_residue() {
        let (dir, store) = store();
        let store = std::sync::Arc::new(store);
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let store = std::sync::Arc::clone(&store);
                std::thread::spawn(move || store.stage(b"contended").expect("stage"))
            })
            .collect();
        let digests: Vec<_> = threads
            .into_iter()
            .map(|t| t.join().expect("join"))
            .collect();
        store.sync_root().expect("barrier");

        assert!(digests.windows(2).all(|w| w[0] == w[1]));
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec![digests[0].as_str().to_owned()]);
    }
}
