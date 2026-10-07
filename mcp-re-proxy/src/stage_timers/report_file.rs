// SPDX-License-Identifier: Apache-2.0
//! The stage-timer report file: one the diagnostic created, and only that one.
//!
//! The destination is named by the environment, so writing it must not be a way to replace
//! a file the process can reach for another reason, such as its evidence archive or an
//! audit log. The first write creates the file with `create_new`, which refuses a path that
//! already exists and does not follow a symlink placed there; every later snapshot is
//! written through the handle that creation returned, never through the name again.

use std::fs::File;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::sync::Mutex;
use std::sync::OnceLock;

/// The report file, or `None` when creating it was refused.
static FILE: OnceLock<Option<Mutex<File>>> = OnceLock::new();

/// Replace the report's contents with `body`. When the path already existed nothing is
/// ever written to it, and the refusal is reported once on stderr.
pub(super) fn rewrite(path: &str, body: &str) {
    let Some(cell) = FILE.get_or_init(|| create(path)) else {
        return;
    };
    let Ok(mut file) = cell.lock() else {
        return;
    };
    let _ = overwrite(&mut file, body);
}

/// Create the report file, refusing any existing path.
fn create(path: &str) -> Option<Mutex<File>> {
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(file) => Some(Mutex::new(file)),
        Err(e) => {
            eprintln!("mcp-re: stage timers: not writing {path}: {e}");
            None
        }
    }
}

/// Truncate `file` and write `body` from its start.
fn overwrite(file: &mut File, body: &str) -> std::io::Result<()> {
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(body.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("mcp-re-stage-timers-{name}-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        path
    }

    /// An existing file is never opened for writing, so its bytes survive.
    #[test]
    fn an_existing_file_is_refused_and_left_intact() {
        let path = scratch("existing");
        std::fs::write(&path, b"evidence").expect("seed");
        assert!(create(path.to_str().expect("utf-8")).is_none());
        assert_eq!(std::fs::read(&path).expect("read"), b"evidence");
        std::fs::remove_file(&path).expect("cleanup");
    }

    /// A symlink at the path is refused rather than followed to its target.
    #[cfg(unix)]
    #[test]
    fn a_symlink_at_the_path_is_refused_and_its_target_left_intact() {
        let target = scratch("target");
        let link = scratch("link");
        std::fs::write(&target, b"evidence").expect("seed");
        std::os::unix::fs::symlink(&target, &link).expect("link");
        assert!(create(link.to_str().expect("utf-8")).is_none());
        assert_eq!(std::fs::read(&target).expect("read"), b"evidence");
        std::fs::remove_file(&link).expect("cleanup");
        std::fs::remove_file(&target).expect("cleanup");
    }

    /// A fresh path is created, and a shorter snapshot replaces a longer one whole.
    #[test]
    fn a_created_file_is_rewritten_through_its_handle() {
        let path = scratch("fresh");
        let cell = create(path.to_str().expect("utf-8")).expect("created");
        let mut file = cell.lock().expect("lock");
        overwrite(&mut file, "stage,count\nlonger,1\n").expect("first");
        overwrite(&mut file, "stage\n").expect("second");
        drop(file);
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "stage\n");
        std::fs::remove_file(&path).expect("cleanup");
    }
}
