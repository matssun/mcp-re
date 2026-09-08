// SPDX-License-Identifier: Apache-2.0
//! Creating a file in a retained-evidence archive.
//!
//! One fact: **what it takes for this half to bring a file into existence here** — it is
//! readable by its owner and nobody else, and it is under a name no other write will ever
//! choose. Both are properties of the single act of creating one, which is why they have
//! one owner and exactly one primitive.
//!
//! It is a separate owner because the reason is separate from anything else the write half
//! does. A retained record holds the covered request headers verbatim, and this profile
//! requires `authorization` and `dpop` to be covered when present — so every artefact in
//! this directory, the probe and the temporaries included, is credential material. Three
//! of the round-7 findings (C075, C076, C078) were about this act and nothing else.

use std::path::Path;

/// Create the store root readable, writable and searchable by the OWNER ONLY.
///
/// A retained record contains the request's covered headers verbatim, and this profile
/// requires `authorization` and `dpop` to be covered when present — so the store holds
/// live bearer tokens and DPoP proofs. The object files are 0600; a directory created at
/// the ambient umask would still let anyone with search access enumerate and stat them,
/// and on a shared mount that is the whole exposure.
#[cfg(unix)]
pub(super) fn create_root(root: &Path) -> std::io::Result<()> {
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
pub(super) fn create_root(root: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(root)
}

/// A suffix no other write in this process, or any concurrent one, will choose again.
///
/// pid alone is not unique per write and is not unique across restarts in a container
/// (always 1); the clock alone can repeat under a coarse timer; the counter alone
/// repeats across processes. All three together do not.
pub(super) fn unique_suffix() -> String {
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
pub(super) fn open_private(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
pub(super) fn open_private(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

#[cfg(test)]
mod tests {
    use super::super::fixtures::TempDir;
    use super::*;

    /// A created file is owner-only. Every artefact here is credential material.
    #[test]
    #[cfg(unix)]
    fn a_created_file_is_readable_by_its_owner_and_nobody_else() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new();
        let path = dir.path().join("artefact");
        drop(open_private(&path).expect("create"));
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
    }

    /// `create_new`, so an existing path is refused rather than truncated: a temp name
    /// collision must fail the write, never silently overwrite another writer's inode.
    #[test]
    fn creating_over_an_existing_path_is_refused() {
        let dir = TempDir::new();
        let path = dir.path().join("taken");
        drop(open_private(&path).expect("create"));
        assert!(open_private(&path).is_err());
    }

    /// The suffix is unique PER WRITE, not per process — crash residue under a name
    /// something will choose again poisons that object forever (R7-C078).
    #[test]
    fn no_two_suffixes_are_the_same() {
        let suffixes: std::collections::HashSet<String> =
            (0..1_000).map(|_| unique_suffix()).collect();
        assert_eq!(suffixes.len(), 1_000);
    }

    /// The root is created owner-only even when the ambient umask is looser.
    #[test]
    #[cfg(unix)]
    fn a_created_root_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new();
        let root = dir.path().join("nested/root");
        create_root(&root).expect("create");
        let mode = std::fs::metadata(&root).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "mode was {:o}", mode & 0o777);
    }
}
