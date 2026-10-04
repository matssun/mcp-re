// SPDX-License-Identifier: Apache-2.0
//! One key file, opened once: the object whose posture was checked is the object whose
//! bytes are consumed.
//!
//! One fact: **possession of a [`CheckedKeyFile`] means the access policy was applied to
//! the filesystem object its bytes were read from.**
//!
//! # Same object, not same name
//!
//! Checking a pathname and then reading the pathname are two resolutions of the name, and
//! anything able to replace or retarget it between them makes the checked object and the
//! consumed object different files. So the name is resolved ONCE: [`observe`] opens it,
//! `fstat`s the open handle, applies the policy to that metadata, and reads the key
//! material from the same handle. Nothing downstream holds the path to reopen — the value
//! carries the bytes, and the path only for diagnostics.
//!
//! Symlinks are followed by that one open, as any open follows them: a Kubernetes projected
//! Secret is a symlink farm (`..data/`), and the posture checked is the resolved target's,
//! because the handle `fstat` reads is the target's.
//!
//! # The authority split this file sits on the far side of
//!
//! `config_state::KeyFileAccessPolicy` is the PURE owner: given a posture, is it legal for
//! this deployment? It does not touch a filesystem and cannot. This role is the
//! environmental half: observe the real object, read the real process group set, hand both
//! to the policy, and keep what was read only if the policy admits it.
//!
//! # Every way of not knowing is a refusal
//!
//! An open or `fstat` that fails for any reason other than "there is no such file" is a
//! refusal. The posture of a file the proxy is about to READ is either established or it
//! is not, and treating an unobservable file as compliant is how a world-readable signing
//! seed on a networked or overlay mount (EIO, ESTALE, EACCES on the directory) boots
//! silently. `NotFound` is the one error that is not a fail-open: there is no file whose
//! permissions could be wrong, and no material either — the consumer that needed it
//! reports the absence and names the file.

use std::fmt;

use zeroize::Zeroizing;

use crate::config_state::KeyFileAccessPolicy;

/// Key material read from the very object the access policy admitted.
///
/// Sealed: the fields are private to this module and [`observe`] is the only producer, so
/// there is no constructor taking bytes, no `Default`, no `Clone` and no serialization.
/// The bytes are [`Zeroizing`] and scrubbed on drop; `Debug` names the path only.
pub struct CheckedKeyFile {
    path: String,
    bytes: Zeroizing<Vec<u8>>,
}

impl CheckedKeyFile {
    /// Open, check and read one key file under `policy`, refusing a missing one.
    ///
    /// The single-file form of the custody check, for a consumer that names its key file
    /// directly rather than through a deployment's custody states. It is the same route
    /// [`admit_key_files`](super::admit_key_files) takes for every covered file.
    pub fn open(path: &str, policy: KeyFileAccessPolicy) -> Result<Self, String> {
        observe(path, policy)?.ok_or_else(|| format!("key file {path} does not exist"))
    }

    /// The configured path the material was read through. Diagnostics only: the file is
    /// never reopened by it.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Surrender the material to the one consumer that parses it.
    ///
    /// `pub(crate)`: the consumers are the file-backed key source (`crate::key_source`)
    /// and the PKCS#11 PIN reader (`capability_materialization::key_source`), which live in
    /// different subtrees. The bytes stay [`Zeroizing`] across the handover.
    pub(crate) fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        self.bytes
    }
}

impl fmt::Debug for CheckedKeyFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CheckedKeyFile")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

/// Open `path` once, apply `policy` to the opened object, and read it — or refuse.
///
/// `Ok(None)` means there is no such file. `Ok(Some(_))` means the posture was OBSERVED on
/// the handle and found legal, and the bytes are that handle's.
#[cfg(unix)]
pub(super) fn observe(
    path: &str,
    policy: KeyFileAccessPolicy,
) -> Result<Option<CheckedKeyFile>, String> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    let unobservable = |e: std::io::Error| {
        format!(
            "mcp-re-proxy refuses unsafe configuration:\n  - key file {path} cannot be \
             opened and inspected ({e}), so its permission posture cannot be established; \
             starting would mean serving with a key file that may be group- or world-readable"
        )
    };
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(unobservable(e)),
    };
    let meta = file.metadata().map_err(unobservable)?;
    let mode = meta.permissions().mode();
    let gids = super::process_groups::process_gids();
    // SAFETY: `geteuid` takes no arguments, touches no memory and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if let Some(reason) = policy.violation(mode, meta.uid(), meta.gid(), euid, &gids) {
        return Err(format!(
            "mcp-re-proxy refuses unsafe configuration:\n  - key file {path} \
             is {reason} (mode {:o}); restrict to 0600",
            mode & 0o777
        ));
    }
    // Sized from the SAME `fstat` so the read does not reallocate: a grown `Vec` leaves the
    // earlier, unscrubbed buffer behind, which `Zeroizing` never sees.
    let capacity = usize::try_from(meta.len()).unwrap_or(0).saturating_add(1);
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
    // `fs::read(path)` — the form this lint asks for — resolves the name a second time,
    // which is the gap this function exists to close: the bytes must come from the handle
    // whose metadata was just checked.
    #[allow(clippy::verbose_file_reads)]
    let read = file.read_to_end(&mut bytes);
    read.map_err(unobservable)?;
    Ok(Some(CheckedKeyFile {
        path: path.to_owned(),
        bytes,
    }))
}

/// REFUSES off unix — it does not silently succeed (r12 R12-621).
///
/// The mode bits do not exist on a non-unix target, so such a build cannot tell a 0600 key
/// file from a world-readable one. That is the SAME situation as the unobservable file the
/// unix arm refuses on, and a permanent inability is not a weaker case than a transient
/// one.
///
/// NO EXECUTABLE CONTROL, stated rather than left to be looked for: every lane here is
/// unix, so nothing compiles this arm, and adding a target to assert a refusal would be a
/// lane invented for a test. It mirrors the unix arm's own refusal deliberately.
#[cfg(not(unix))]
pub(super) fn observe(
    path: &str,
    _policy: KeyFileAccessPolicy,
) -> Result<Option<CheckedKeyFile>, String> {
    Err(format!(
        "mcp-re-proxy refuses unsafe configuration:\n  - key file {path} cannot have its \
         permission posture established on this target (the mode bits do not exist); it is \
         read by the proxy regardless, and starting would mean serving with a key file that \
         may be group- or world-readable"
    ))
}

#[cfg(all(test, unix))]
mod tests {
    use super::observe;
    use super::CheckedKeyFile;
    use crate::config_state::KeyFileAccessPolicy;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    /// A key file at `mode`, named per-process so concurrent test binaries do not
    /// collide. Mirrors the temp-file idiom the rest of this crate's tests use
    /// (`std::env::temp_dir()` + pid) rather than adding a dev-dependency.
    struct KeyFile(String);

    impl KeyFile {
        fn at(mode: u32, name: &str) -> Self {
            Self::with(mode, name, b"key-material")
        }
        fn with(mode: u32, name: &str, content: &[u8]) -> Self {
            let path =
                std::env::temp_dir().join(format!("mcp_re_perm_{}_{name}", std::process::id()));
            let mut f = std::fs::File::create(&path).expect("create");
            f.write_all(content).expect("write");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
            KeyFile(path.to_string_lossy().into_owned())
        }
        fn path(&self) -> &str {
            &self.0
        }
    }

    impl Drop for KeyFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn material(checked: CheckedKeyFile) -> Vec<u8> {
        checked.into_bytes().to_vec()
    }

    /// 0644 is world-readable, not merely group-readable — the refusal says which,
    /// because "restrict to 0600" is more actionable when it names the actual bit.
    #[test]
    fn a_world_readable_key_file_is_refused() {
        let f = KeyFile::at(0o644, "world.key");
        let err =
            observe(f.path(), KeyFileAccessPolicy::OwnerOnly).expect_err("0644 must be refused");
        assert!(err.contains("world-accessible"), "got: {err}");
    }

    /// C053b: group-readable is refused by DEFAULT — the opt-in is what changes it.
    #[test]
    fn a_group_readable_key_file_is_refused_without_the_opt_in() {
        let f = KeyFile::at(0o640, "group.key");
        let err =
            observe(f.path(), KeyFileAccessPolicy::OwnerOnly).expect_err("0640 must be refused");
        assert!(err.contains("group-accessible"), "got: {err}");
        assert!(
            err.contains("--allow-group-readable-key-files"),
            "the refusal must name the opt-in that exists for the fsGroup mount model: {err}"
        );
    }

    /// With the opt-in, a group-readable file whose group this process is actually in
    /// is accepted — the file the test harness creates is owned by our own gid.
    #[test]
    fn a_group_readable_key_file_owned_by_our_group_is_accepted_with_the_opt_in() {
        let f = KeyFile::at(0o640, "fsgroup.key");
        observe(
            f.path(),
            KeyFileAccessPolicy::GroupReadableUnderProcessGroup,
        )
        .expect("an fsGroup-shaped mount is accepted")
        .expect("the file exists");
    }

    /// The opt-in does not reach group-WRITE: a peer able to replace the signing key is
    /// never a mount-model requirement.
    #[test]
    fn group_write_is_refused_even_with_the_opt_in() {
        let f = KeyFile::at(0o660, "groupwrite.key");
        let err = observe(
            f.path(),
            KeyFileAccessPolicy::GroupReadableUnderProcessGroup,
        )
        .expect_err("0660 must be refused");
        assert!(err.contains("group-writable"), "got: {err}");
    }

    /// THE POSITIVE CONTROL, and it carries the bytes: an admitted file yields exactly
    /// its own content.
    #[test]
    fn an_owner_only_key_file_is_accepted() {
        let f = KeyFile::at(0o600, "owner.key");
        let checked = observe(f.path(), KeyFileAccessPolicy::OwnerOnly)
            .expect("0600 is the required posture")
            .expect("the file exists");
        assert_eq!(checked.path(), f.path());
        assert_eq!(material(checked), b"key-material");
    }

    /// Absence is not a refusal here — there is no posture to be wrong and no material to
    /// hand over — and the single-file form turns it into one, naming the file.
    #[test]
    fn an_absent_key_file_is_not_an_error() {
        assert!(
            observe("/nonexistent/path/tls.key", KeyFileAccessPolicy::OwnerOnly)
                .expect("a missing file is reported by its consumer, not by this guard")
                .is_none()
        );
        let err = CheckedKeyFile::open("/nonexistent/path/tls.key", KeyFileAccessPolicy::OwnerOnly)
            .expect_err("a consumer naming its file needs the file");
        assert!(err.contains("/nonexistent/path/tls.key"), "{err}");
    }

    /// C077: an open or `fstat` that fails for a reason OTHER than absence must refuse.
    ///
    /// The broken implementation this catches: treating every error as `Ok(None)`, which
    /// starts the proxy with no diagnostic over a file whose posture nobody saw.
    #[test]
    fn a_key_file_whose_posture_cannot_be_established_is_refused() {
        let dir = std::env::temp_dir().join(format!("mcp_re_perm_dir_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create dir");
        let key = dir.join("tls.key");
        std::fs::write(&key, b"key-material").expect("write");
        // No search permission on the directory: the file is still there, but resolving
        // the path through the directory fails EACCES.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).expect("chmod");

        let result = observe(&key.to_string_lossy(), KeyFileAccessPolicy::OwnerOnly);

        // Restore before asserting so a failure does not leave an unremovable directory.
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::remove_dir_all(&dir);

        let err = result.expect_err("an unestablishable key-file posture must refuse startup");
        assert!(
            err.contains("cannot be opened and inspected"),
            "the refusal must say the posture could not be established, got: {err}"
        );
    }

    /// R12-630/R12-634, THE SAME-OBJECT CLAIM, exercised as the attack: the path is
    /// checked, then REPLACED with a different file before anything is loaded. The value
    /// still yields the admitted object's bytes, because nothing reopens the name.
    ///
    /// The replacement is world-readable on purpose. A loader that re-resolved the path
    /// would consume bytes whose posture was never checked — the exact gap — and this
    /// assertion is what goes red.
    #[test]
    fn the_checked_object_is_the_consumed_object_when_the_path_is_replaced() {
        let original = KeyFile::with(0o600, "toctou.key", b"checked-material");
        let checked = observe(original.path(), KeyFileAccessPolicy::OwnerOnly)
            .expect("the original is legal")
            .expect("the original exists");

        let intruder = KeyFile::with(0o644, "toctou.intruder", b"replacement-material");
        std::fs::rename(intruder.path(), original.path()).expect("replace the checked path");

        assert_eq!(material(checked), b"checked-material");
    }

    /// Symlinks stay supported, and the posture checked is the RESOLVED target's: a link
    /// to a protected target is admitted, its target's bytes are read, and retargeting the
    /// link afterwards changes nothing already admitted. A link to a world-readable target
    /// is refused although the link itself is 0777 — `fstat` reads the target.
    ///
    /// This is the projected-Secret shape (`..data/` symlinks) that the fsGroup relaxation
    /// exists for; refusing it would refuse the mount model.
    #[test]
    fn a_symlink_is_followed_and_its_resolved_target_is_checked_and_read() {
        let target = KeyFile::with(0o600, "link.target", b"target-material");
        let open_target = KeyFile::with(0o644, "link.open", b"open-material");
        let link =
            std::env::temp_dir().join(format!("mcp_re_perm_{}_link.key", std::process::id()));
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(target.path(), &link).expect("symlink");
        let link_path = link.to_string_lossy().into_owned();

        let checked = observe(&link_path, KeyFileAccessPolicy::OwnerOnly)
            .expect("a link to a 0600 target is legal")
            .expect("the target exists");

        std::fs::remove_file(&link).expect("unlink");
        std::os::unix::fs::symlink(open_target.path(), &link).expect("retarget");
        let refused = observe(&link_path, KeyFileAccessPolicy::OwnerOnly);
        let _ = std::fs::remove_file(&link);

        assert_eq!(material(checked), b"target-material");
        assert!(
            refused
                .expect_err("the resolved target is world-readable")
                .contains("world-accessible"),
            "the posture checked is the target's, not the link's"
        );
    }
}
