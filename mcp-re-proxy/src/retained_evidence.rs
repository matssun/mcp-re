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

use std::path::Path;
use std::path::PathBuf;

use mcp_re_http_profile::scitt::EvidenceDigest;
use mcp_re_http_profile::scitt::RetainedEvidenceStore;

/// A retained-evidence store over a directory, one file per object named by digest.
pub struct FsRetainedEvidenceStore {
    root: PathBuf,
}

impl FsRetainedEvidenceStore {
    /// Open (creating if absent) a store rooted at `root`.
    pub fn open(root: impl AsRef<Path>) -> std::io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root)?;
        Ok(FsRetainedEvidenceStore { root })
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
}

impl RetainedEvidenceStore for FsRetainedEvidenceStore {
    type Error = std::io::Error;

    fn put(&mut self, evidence: &[u8]) -> Result<EvidenceDigest, Self::Error> {
        let digest = EvidenceDigest::of(evidence);
        let path = self.path_for(&digest)?;
        // Already retained: the bytes cannot differ, because the name is their digest.
        // Rewriting would be a no-op that could still lose data if it were interrupted.
        if path.exists() {
            return Ok(digest);
        }
        // Write to a temporary name and rename, so a crash mid-write cannot leave a
        // SHORT file under a digest that promises the full content. A reader would
        // otherwise get bytes that do not hash to the name they asked for.
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, evidence)?;
        std::fs::rename(&tmp, &path)?;
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

    /// A digest that is not a base64url token never reaches the filesystem.
    #[test]
    fn a_non_token_digest_cannot_escape_the_root() {
        let (_dir, store) = store();
        let traversal: EvidenceDigest =
            serde_json::from_str("\"../../etc/passwd\"").expect("deserialize");
        assert!(store.get(&traversal).is_err());
    }
}
