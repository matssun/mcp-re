// SPDX-License-Identifier: Apache-2.0
//! The one way an audit artifact reaches disk.
//!
//! One fact: **a path holds either its previous bytes or the new bytes, never a truncated
//! mixture.** The artifact is the operator's durable, portable record, so nothing here
//! truncates it in place: the new bytes are staged beside it and renamed over it.

use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

/// Replace the file at `path` with `bytes`: stage `path` + ".partial" in the same
/// directory, write and sync it, rename it over `path`, and on any failure remove the
/// staging file and leave `path` as it was.
pub(super) fn replace_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut staging = path.as_os_str().to_owned();
    staging.push(".partial");
    let staging = PathBuf::from(staging);
    let staged = stage_and_rename(&staging, path, bytes);
    if staged.is_err() {
        let _ = std::fs::remove_file(&staging);
    }
    staged
}

fn stage_and_rename(staging: &Path, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = std::fs::File::create(staging)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(staging, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("auditor-file-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    #[test]
    fn a_failed_replace_leaves_the_previous_artifact_whole() {
        let dir = scratch("failed");
        let out = dir.join("artifact.json");
        std::fs::write(&out, b"ORIGINAL").expect("seed");
        std::fs::create_dir(dir.join("artifact.json.partial")).expect("block staging");

        assert!(replace_atomically(&out, b"NEW").is_err());
        assert_eq!(std::fs::read(&out).expect("read"), b"ORIGINAL");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_replace_leaves_no_staging_file() {
        let dir = scratch("clean");
        let out = dir.join("artifact.json");

        replace_atomically(&out, b"NEW").expect("replace");
        assert_eq!(std::fs::read(&out).expect("read"), b"NEW");
        assert!(!dir.join("artifact.json.partial").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
