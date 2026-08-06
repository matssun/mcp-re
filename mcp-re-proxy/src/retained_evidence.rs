// SPDX-License-Identifier: Apache-2.0
//! Filesystem-backed retained-evidence store (MCPRE-501 slice 3).
//!
//! The SCITT commitment (`mcp-re-http-profile::scitt`) names evidence it does not
//! carry: the receipt is small and portable, the request/response bytes stay retained.
//! `mcp-re-http-profile` is pure — no fs — so it declares the
//! [`RetainedEvidenceStore`] interface and this module supplies the implementation.
//!
//! **Scope, stated so nobody mistakes it for a platform.** This is an immutable
//! content-addressed object store, sufficient for the SCITT vertical: `put` and `get`
//! over SHA-256-named blobs. It is not an evidence-retention product — no lifecycle, no
//! expiry, no index, no query. Those belong to whatever retention policy a deployment
//! has, and inventing them here to close an interoperability issue would be building
//! the wrong thing.
//!
//! The interface is the seam that keeps an object-store implementation possible later:
//! nothing in the SCITT path knows a filesystem is behind it.

use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use mcp_re_http_profile::scitt::EvidenceDigest;
use mcp_re_http_profile::scitt::RetainedEvidenceStore;

/// A retained-evidence store over a directory, one file per object named by digest.
pub struct FsRetainedEvidenceStore {
    root: PathBuf,
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
    pub fn open(root: impl AsRef<Path>) -> std::io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        create_root(&root)?;
        let store = FsRetainedEvidenceStore { root };
        store.probe_writable()?;
        Ok(store)
    }

    /// The directory every object and marker lives in.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Create, write, make durable and remove one probe object.
    fn probe_writable(&self) -> std::io::Result<()> {
        let probe = self.root.join(format!(".writable.{}", unique_suffix()));
        let outcome = (|| {
            let mut file = open_private(&probe)?;
            file.write_all(b"mcp-re retained-evidence writability probe\n")?;
            file.sync_all()
        })();
        let _ = std::fs::remove_file(&probe);
        outcome
    }

    /// The path for a digest.
    ///
    /// base64url is used for the digest everywhere in this profile, and it contains `-`
    /// and `_` but never `/`, `.` or NUL — so it is already a safe single path segment.
    /// The check is kept anyway: a filename derived from a value that arrived from
    /// outside is exactly where path traversal gets in, and "the encoding cannot produce
    /// a separator" is a property of the encoder, not of the string in hand.
    fn path_for(&self, digest: &EvidenceDigest) -> std::io::Result<PathBuf> {
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

    /// Write `bytes` to `path` durably EXCEPT for the directory entry.
    ///
    /// Unique temp name, write, `fsync` the file, rename. The caller must call
    /// [`FsRetainedEvidenceStore::sync_root`] before treating `path` as durable —
    /// splitting the barrier out is what lets one directory `fsync` cover a whole batch
    /// of renames, which is the only reduction the filesystem ordering law permits (a
    /// directory `fsync` has no per-entry granularity, so N renames followed by one
    /// `fsync` are exactly as durable as N `fsync`-per-rename pairs).
    ///
    /// `path` MUST be directly under [`FsRetainedEvidenceStore::root`], or the barrier
    /// the caller takes is over the wrong directory.
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
        let path = self.path_for(&digest)?;
        self.stage_at(&path, evidence)?;
        Ok(digest)
    }

    /// The directory barrier: makes every rename staged into the root so far durable.
    pub fn sync_root(&self) -> std::io::Result<()> {
        std::fs::File::open(&self.root)?.sync_all()
    }
}

/// Create the store root readable, writable and searchable by the OWNER ONLY.
///
/// A retained record contains the request's covered headers verbatim, and this profile
/// requires `authorization` and `dpop` to be covered when present — so the store holds
/// live bearer tokens and DPoP proofs. The object files are 0600; a directory created at
/// the ambient umask would still let anyone with search access enumerate and stat them,
/// and on a shared mount that is the whole exposure.
#[cfg(unix)]
fn create_root(root: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    use std::os::unix::fs::PermissionsExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(root)?;
    // An existing directory keeps the mode its operator gave it — silently tightening a
    // path a sidecar or an auditor may share is not this module's call. It is stated
    // instead, because "the store holds credentials" is not inferable from the flag.
    let mode = std::fs::metadata(root)?.permissions().mode();
    if mode & 0o077 != 0 {
        eprintln!(
            "mcp-re-proxy: retained-evidence store {} is mode {:o}: readable or writable \
             beyond its owner. Retained records contain the covered request headers \
             verbatim, which for this profile includes `authorization` and `dpop` — live \
             bearer tokens and DPoP proofs. Restrict it to 0700.",
            root.display(),
            mode & 0o7777
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn create_root(root: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(root)
}

/// A suffix no other write in this process, or any concurrent one, will choose again.
///
/// pid alone is not unique per write and is not unique across restarts in a container
/// (always 1); the clock alone can repeat under a coarse timer; the counter alone
/// repeats across processes. All three together do not.
fn unique_suffix() -> String {
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!(
        "{}.{nanos}.{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

/// Create `path` readable and writable by the OWNER ONLY.
///
/// Retained evidence is the request and response signature bases of real calls —
/// enough to reconstruct who asked for what — and the store wrote them at whatever
/// the process umask happened to allow, typically world-readable. Every other
/// sensitive file this proxy touches is permission-checked; this one was not.
#[cfg(unix)]
fn open_private(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_private(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
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

    fn get(&self, digest: &EvidenceDigest) -> Result<Option<Vec<u8>>, Self::Error> {
        let path = self.path_for(digest)?;
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

    /// A unique temporary directory that removes itself. The workspace carries no
    /// `tempfile` dependency and this is not a reason to add one.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            use std::sync::atomic::AtomicU32;
            use std::sync::atomic::Ordering;
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let path = std::env::temp_dir().join(format!(
                "mcp-re-retained-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).expect("temp dir");
            TempDir(path)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

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

    /// A file swapped underneath the store is refused rather than returned. The one
    /// property a content-addressed store has is that the name determines the bytes.
    #[test]
    fn bytes_replaced_on_disk_are_refused_not_returned() {
        let (dir, mut store) = store();
        let digest = store.put(b"authentic").expect("put");
        std::fs::write(dir.path().join(digest.as_str()), b"swapped").expect("tamper");
        assert!(
            store.get(&digest).is_err(),
            "bytes that do not hash to the requested digest are not this object"
        );
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

    /// A digest that is not a base64url token never reaches the filesystem.
    #[test]
    fn a_non_token_digest_cannot_escape_the_root() {
        let (_dir, store) = store();
        let traversal: EvidenceDigest =
            serde_json::from_str("\"../../etc/passwd\"").expect("deserialize");
        assert!(store.get(&traversal).is_err());
    }
}
