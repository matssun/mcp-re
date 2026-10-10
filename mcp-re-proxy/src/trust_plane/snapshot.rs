// SPDX-License-Identifier: Apache-2.0
//! What a `--trust` document BECOMES.
//!
//! One fact, and it is a correspondence rather than a lifecycle: **two products come out of
//! one read, so they can never disagree.** The resolver that answers `resolve` and the
//! `kid -> signer` map the actor seam reads as an identity coordinate are built together
//! from the same bytes; built separately they could describe different trust pictures while
//! both looking current.
//!
//! Separate from [`reload`](super::reload), which owns *how often the read happens and when
//! to stop trusting a stale one*. This module is called by both the first read at
//! materialization and every re-read after it, and it must give the same answer to both.
//!
//! `response_kid` is excluded from the request-signer map here rather than at either caller:
//! the deployment's own issuer key must never be presentable as a client credential, and a
//! rule enforced at the read is one neither caller can forget.

use std::collections::HashMap;
use std::io::Read;

/// The most `--trust` bytes this process will read into memory.
///
/// The document is read WHOLE, and not only at startup: [`read_trust_file`] is the read
/// [`supervise_trust_reload`](super::reload::supervise_trust_reload) performs on its
/// configured cadence, inside a live serving process. Unbounded there, a path that has
/// grown, been swapped for a large file, or been pointed at a device is loaded in full on
/// every tick.
///
/// A megabyte is far more than any real enrolment — an entry is a signer, a key id and a
/// base64 Ed25519 public key, so on the order of 250 bytes, and this admits thousands of
/// them. It bounds the READ. It is not a policy about how many keys a deployment may
/// enrol, and a deployment that needs more should be told so by this refusal rather than
/// by a process that grew until it was killed.
const MAX_TRUST_DOCUMENT_BYTES: u64 = 1024 * 1024;

/// Read `--trust` and build the snapshot the revocation tiers resolve against.
///
/// Two things come out of one read so they can never disagree: the
/// [`InMemoryTrustResolver`](mcp_re_core::InMemoryTrustResolver) that answers
/// `resolve`, and the `kid -> signer` map the actor seam uses as the identity
/// coordinate. `response_kid` is excluded from the request-signer map: the
/// deployment's own issuer key must never be presentable as a client credential.
pub(in crate::trust_plane) fn load_trust_snapshot(
    trust_path: &str,
    response_kid: &str,
) -> Result<crate::reloading_trust::ReloadingTrustStore, String> {
    let (resolver, signers) = read_trust_file(trust_path, response_kid)?;
    Ok(crate::reloading_trust::ReloadingTrustStore::new(
        resolver, signers,
    ))
}
/// The file read shared by startup and every reload.
pub(super) fn read_trust_file(
    trust_path: &str,
    response_kid: &str,
) -> Result<(mcp_re_core::InMemoryTrustResolver, HashMap<String, String>), String> {
    let bytes = read_bounded(trust_path)?;
    let document = crate::trust_document::TrustDocument::parse(&bytes)?;
    // Slot-scoped: only entries this file enrols for the REQUEST slot become client
    // request signers. A key carried here for another purpose is not one.
    Ok((document.resolver(), document.request_signers(response_kid)))
}

/// Why a `--trust` file's write posture is refused, or `None` when only this process or
/// root can change it.
///
/// The document decides which keys may sign requests, so whoever can write it holds that
/// authority. Read access is not restricted — it carries public keys. Pure, so the rule is
/// testable without a filesystem; the caller supplies the `fstat` of the open handle.
fn write_posture_violation(mode: u32, file_uid: u32, process_euid: u32) -> Option<&'static str> {
    if crate::config_state::foreign_owner(file_uid, process_euid) {
        return Some(crate::config_state::FOREIGN_OWNER);
    }
    if mode & 0o002 != 0 {
        return Some("world-writable");
    }
    if mode & 0o020 != 0 {
        return Some("group-writable");
    }
    None
}

/// Open `trust_path` ONCE and refuse a write posture that lets anyone but this process or
/// root change it, deciding on the opened handle.
///
/// The posture checked is the `fstat` of the handle the bytes are then read from, so a name
/// retargeted between a check and a read cannot substitute another file: the one open is
/// the only resolution of the name. That open follows symlinks, as a ConfigMap mount's
/// `..data` farm requires, and the posture is the resolved target's. The containing
/// directory's posture is not examined.
#[cfg(unix)]
fn open_checked(trust_path: &str) -> Result<std::fs::File, String> {
    use std::os::unix::fs::MetadataExt;
    let file = std::fs::File::open(trust_path).map_err(|e| format!("{trust_path}: {e}"))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("{trust_path}: its write posture cannot be established ({e})"))?;
    // SAFETY: `geteuid` takes no arguments, touches no memory and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if let Some(reason) = write_posture_violation(meta.mode(), meta.uid(), euid) {
        return Err(format!(
            "{trust_path}: trust document is {reason} (mode {:o}) and was refused: whoever \
             can write --trust decides which keys may sign requests. Restrict it to 0644 or \
             tighter, owned by this process's uid or root.",
            meta.mode() & 0o777
        ));
    }
    Ok(file)
}

/// REFUSES off unix: the mode bits and owner do not exist there, so the write posture
/// cannot be established, the same situation the key-file check refuses on.
#[cfg(not(unix))]
fn open_checked(trust_path: &str) -> Result<std::fs::File, String> {
    Err(format!(
        "{trust_path}: the trust document's write posture cannot be established on this \
         target, so it is refused"
    ))
}

/// Read at most [`MAX_TRUST_DOCUMENT_BYTES`] from the posture-checked handle, and REFUSE
/// rather than truncate.
///
/// One byte past the cap is read deliberately, so an oversized document is answered as
/// "larger than the bound" and never as a parse failure over a document cut in half. Those
/// are different things for an operator to do about, and only the first names the cap.
fn read_bounded(trust_path: &str) -> Result<Vec<u8>, String> {
    let file = open_checked(trust_path)?;
    let mut bytes = Vec::new();
    file.take(MAX_TRUST_DOCUMENT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{trust_path}: {e}"))?;
    if bytes.len() as u64 > MAX_TRUST_DOCUMENT_BYTES {
        return Err(format!(
            "{trust_path}: trust document exceeds the {MAX_TRUST_DOCUMENT_BYTES}-byte read \
             bound and was refused rather than read into memory. This read also runs on the \
             --trust reload cadence, inside the serving process."
        ));
    }
    Ok(bytes)
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::read_bounded;
    use super::write_posture_violation;
    use super::MAX_TRUST_DOCUMENT_BYTES;

    /// A file of `len` bytes at a path unique to this test.
    fn file_of(tag: &str, len: usize) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "mcp_re_trust_bound_{tag}_{}.json",
            std::process::id()
        ));
        std::fs::write(&path, vec![b'x'; len]).expect("write");
        set_mode(&path, 0o644);
        path
    }

    fn set_mode(path: &std::path::Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
    }

    /// Only this process or root may be able to change the document: a foreign owner, a
    /// group-write bit and a world-write bit are each refused, and read bits are not.
    #[test]
    fn the_write_posture_admits_only_this_process_or_root_as_writer() {
        let me = 1000;
        assert_eq!(write_posture_violation(0o644, me, me), None);
        assert_eq!(write_posture_violation(0o644, 0, me), None);
        assert_eq!(write_posture_violation(0o444, me, me), None);
        assert!(write_posture_violation(0o644, 4242, me)
            .is_some_and(|r| r.contains("neither this process's effective uid nor root")));
        assert_eq!(
            write_posture_violation(0o664, me, me),
            Some("group-writable")
        );
        assert_eq!(
            write_posture_violation(0o646, me, me),
            Some("world-writable")
        );
        assert_eq!(
            write_posture_violation(0o666, 0, me),
            Some("world-writable")
        );
    }

    /// The posture is decided on the handle the bytes are read from: a group-writable file
    /// is refused at the read, and the same file restricted to 0644 is read.
    #[test]
    fn a_group_writable_trust_file_is_refused_at_the_read() {
        let path = file_of("posture", 8);
        set_mode(&path, 0o664);
        let err = read_bounded(path.to_str().expect("utf-8 path")).expect_err("refused");
        assert!(
            err.contains("group-writable") && err.contains("--trust"),
            "{err}"
        );
        set_mode(&path, 0o644);
        assert_eq!(
            read_bounded(path.to_str().expect("utf-8 path"))
                .expect("read")
                .len(),
            8
        );
        std::fs::remove_file(&path).ok();
    }

    /// The bound is on the READ, so a document one byte past it is refused whole rather
    /// than handed to the parser truncated — and the refusal names the cap, because an
    /// operator whose enrolment outgrew it has something to do about that and nothing to
    /// do about "expected value at line 1".
    #[test]
    fn a_document_past_the_read_bound_is_refused_and_says_so() {
        let cap = usize::try_from(MAX_TRUST_DOCUMENT_BYTES).expect("cap fits a usize");
        let path = file_of("over", cap + 1);
        let err = read_bounded(path.to_str().expect("utf-8 path")).expect_err("refused");
        assert!(
            err.contains("exceeds") && err.contains(&MAX_TRUST_DOCUMENT_BYTES.to_string()),
            "the refusal must name the bound: {err}"
        );
        std::fs::remove_file(&path).ok();
    }

    /// And the bound is not a narrowing: a document AT the cap is read in full.
    #[test]
    fn a_document_at_the_read_bound_is_read_whole() {
        let cap = usize::try_from(MAX_TRUST_DOCUMENT_BYTES).expect("cap fits a usize");
        let path = file_of("at", cap);
        let bytes = read_bounded(path.to_str().expect("utf-8 path")).expect("read");
        assert_eq!(bytes.len(), cap);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_missing_trust_file_names_the_path_it_could_not_read() {
        let err = read_bounded("/nonexistent/mcp-re-trust.json").expect_err("refused");
        assert!(err.starts_with("/nonexistent/mcp-re-trust.json: "), "{err}");
    }
}
