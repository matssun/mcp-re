// SPDX-License-Identifier: Apache-2.0
//! Filesystem-backed retained-evidence store (MCPRE-501 slice 3).
//!
//! The SCITT commitment (`mcp-re-http-profile::scitt`) names evidence it does not
//! carry: the receipt is small and portable, the request/response bytes stay retained.
//! `mcp-re-http-profile` is pure — no fs — so it declares the
//! [`mcp_re_http_profile::scitt::RetainedEvidenceStore`] interface and this module
//! supplies the implementation.
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
//!
//! ## Two authorities, and the reason the boundary is where it is
//!
//! ```text
//! FsRetainedArchive        WHICH bytes this directory holds — retrieval, and the
//!                          re-addressing that makes a name determine its bytes
//! FsRetainedEvidenceStore  the WRITE half: proving the root writable, staging an object
//!                          durably, and the directory barrier that publishes a batch
//! ```
//!
//! Opening for WRITING proves the directory writable by writing (see
//! [`FsRetainedEvidenceStore::open`]); opening for READING proves nothing of the sort,
//! because a reader needs nothing of the sort. That is not an accommodation for the
//! auditor — it is the observation that *which bytes are here* and *may this process
//! become answerable for more of them* are different facts with different consumers, and
//! that the reading half was only ever coupled to the writing half by there being one
//! constructor (MCPRE-179).
//!
//! The store HOLDS an archive rather than reimplementing retrieval, so the re-addressing
//! check exists exactly once and the write path's `get` is the same `get` an auditor runs.

/// WHICH bytes this archive holds: retrieval, and the re-addressing that guards it.
mod archive;

/// WHAT it takes to create a file here: owner-only, under a name nothing will reuse.
mod private_file;

/// The write half: proving the root writable, staging durably, and the batch barrier.
mod store;

pub use archive::FsRetainedArchive;
pub use store::FsRetainedEvidenceStore;

#[cfg(test)]
mod fixtures {
    //! A temporary directory shared by this module's owners.
    //!
    //! Inline rather than a file, for the reason the registration subtree's are:
    //! `scripts/module_size_gate.py` reads FILES and cannot see a `#[cfg(test)]` on a
    //! `mod` line, so a fixture file would be counted as production code.
    //!
    //! The workspace carries no `tempfile` dependency and this is not a reason to add one.

    use std::path::Path;
    use std::path::PathBuf;

    /// A unique temporary directory that removes itself.
    pub(super) struct TempDir(PathBuf);

    impl TempDir {
        pub(super) fn new() -> Self {
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

        pub(super) fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            // A test may have left a directory unwritable to exercise a refusal; the
            // removal has to survive that or the temp root grows every run.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
            }
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
