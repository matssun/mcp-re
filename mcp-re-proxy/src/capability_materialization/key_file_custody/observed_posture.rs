// SPDX-License-Identifier: Apache-2.0
//! Observing the real key-file object and applying the policy to what was observed.
//!
//! One fact: **a file whose permission posture this build could not establish is a
//! refusal, never a pass.**
//!
//! # The authority split this file sits on the far side of
//!
//! `config_state::KeyFileAccessPolicy` is the PURE owner: given a posture, is it legal for
//! this deployment? It does not touch a filesystem and cannot. This role is the
//! environmental half: `stat` the real object, read the real process group set, hand both
//! to the policy, and return the policy's verdict. It does not see
//! `--allow-group-readable-key-files` and could not re-derive the rule from it if it did —
//! the rule is three conditions and a boolean is one term in it.
//!
//! # Every way of not knowing is a refusal
//!
//! A `stat` that fails for any reason other than "there is no such file" is itself a
//! refusal. The posture of a file the proxy is about to READ is either established or it
//! is not, and treating an unreadable `stat` as compliance is how a world-readable signing
//! seed on a networked or overlay mount (EIO, ESTALE, EACCES on the directory) boots
//! silently. `NotFound` is the one error that is not a fail-open: there is no file whose
//! permissions could be wrong, the loader resolves the same path a moment later, and it
//! reports the absence with the diagnostic that names what was missing.
//!
//! The same reasoning decides the non-unix arm, and it used to decide it the other way —
//! see [`admit`]'s `not(unix)` form.

use crate::config_state::KeyFileAccessPolicy;

/// Admit one key file, or refuse with the policy's reason.
///
/// `Ok(())` means the posture was OBSERVED and found legal — not that the check was
/// skipped, which is the distinction the two arms below exist to keep.
#[cfg(unix)]
pub(super) fn admit(path: &str, policy: KeyFileAccessPolicy) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(format!(
                "mcp-re-proxy refuses unsafe configuration:\n  - key file {path} cannot be \
                 stat'ed ({e}), so its permission posture cannot be established; it is read \
                 by the proxy regardless, and starting would mean serving with a key file \
                 that may be group- or world-readable"
            ))
        }
    };
    let mode = meta.permissions().mode();
    let gids = super::process_groups::process_gids();
    if let Some(reason) = policy.violation(mode, meta.gid(), &gids) {
        return Err(format!(
            "mcp-re-proxy refuses unsafe configuration:\n  - key file {path} \
             is {reason} (mode {:o}); restrict to 0600",
            mode & 0o777
        ));
    }
    Ok(())
}

/// REFUSES off unix — it does not silently succeed (r12 R12-621).
///
/// The mode bits do not exist on a non-unix target, so such a build cannot tell a 0600 key
/// file from a world-readable one. That is the SAME situation as the `stat` failure the
/// unix arm refuses on, and a permanent inability is not a weaker case than a transient
/// one. Returning `Ok(())` made the guarantee "a group- or world-readable key file refuses
/// startup" quietly target-conditional, on a target set nobody had written down — no
/// `assumptions.toml` entry records that production targets are unix-only.
///
/// NO EXECUTABLE CONTROL, stated rather than left to be looked for: every lane here is
/// unix, so nothing compiles this arm, and adding a target to assert a refusal would be a
/// lane invented for a test. It mirrors the unix arm's own refusal deliberately.
#[cfg(not(unix))]
pub(super) fn admit(path: &str, _policy: KeyFileAccessPolicy) -> Result<(), String> {
    Err(format!(
        "mcp-re-proxy refuses unsafe configuration:\n  - key file {path} cannot have its \
         permission posture established on this target (the mode bits do not exist); it is \
         read by the proxy regardless, and starting would mean serving with a key file that \
         may be group- or world-readable"
    ))
}

#[cfg(all(test, unix))]
mod tests {
    use super::admit;
    use crate::config_state::KeyFileAccessPolicy;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    /// A key file at `mode`, named per-process so concurrent test binaries do not
    /// collide. Mirrors the temp-file idiom the rest of this crate's tests use
    /// (`std::env::temp_dir()` + pid) rather than adding a dev-dependency.
    struct KeyFile(String);

    impl KeyFile {
        fn at(mode: u32, name: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("mcp_re_perm_{}_{name}", std::process::id()));
            let mut f = std::fs::File::create(&path).expect("create");
            f.write_all(b"key-material").expect("write");
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

    /// 0644 is world-readable, not merely group-readable — the refusal now says which,
    /// because "restrict to 0600" is more actionable when it names the actual bit.
    #[test]
    fn a_world_readable_key_file_is_refused() {
        let f = KeyFile::at(0o644, "world.key");
        let err =
            admit(f.path(), KeyFileAccessPolicy::OwnerOnly).expect_err("0644 must be refused");
        assert!(err.contains("world-accessible"), "got: {err}");
    }

    /// C053b: group-readable is refused by DEFAULT — the opt-in is what changes it, and
    /// the default posture is exactly what it was.
    #[test]
    fn a_group_readable_key_file_is_refused_without_the_opt_in() {
        let f = KeyFile::at(0o640, "group.key");
        let err =
            admit(f.path(), KeyFileAccessPolicy::OwnerOnly).expect_err("0640 must be refused");
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
        admit(
            f.path(),
            KeyFileAccessPolicy::GroupReadableUnderProcessGroup,
        )
        .expect("an fsGroup-shaped mount is accepted");
    }

    /// The opt-in does not reach group-WRITE: a peer able to replace the signing key is
    /// never a mount-model requirement.
    #[test]
    fn group_write_is_refused_even_with_the_opt_in() {
        let f = KeyFile::at(0o660, "groupwrite.key");
        let err = admit(
            f.path(),
            KeyFileAccessPolicy::GroupReadableUnderProcessGroup,
        )
        .expect_err("0660 must be refused");
        assert!(err.contains("group-writable"), "got: {err}");
    }

    #[test]
    fn an_owner_only_key_file_is_accepted() {
        let f = KeyFile::at(0o600, "owner.key");
        admit(f.path(), KeyFileAccessPolicy::OwnerOnly).expect("0600 is the required posture");
    }

    /// Delegated TLS leaves `tls_key` EMPTY (see `cli::parse_args`), which is how the
    /// wiring expresses "no key file is read" — and an empty path must not be treated as
    /// a key file to check.
    #[test]
    fn an_absent_key_file_is_not_an_error() {
        admit("", KeyFileAccessPolicy::OwnerOnly).expect("no file configured is not a violation");
        admit("/nonexistent/path/tls.key", KeyFileAccessPolicy::OwnerOnly)
            .expect("a missing file is reported by the loader, not by this guard");
    }

    /// C077: a `stat` that fails for a reason OTHER than absence must refuse.
    ///
    /// The file exists and is about to be read; only its posture is unknowable. Treating
    /// that as compliance is a fail-open — on a networked or overlay Secret mount an EIO
    /// or ESTALE would start the proxy over a world-readable signing seed with no
    /// diagnostic at all.
    ///
    /// The broken implementation this catches: `if let Ok(meta) = metadata(path)` with no
    /// error arm, which is what this guard did.
    #[test]
    fn a_key_file_whose_posture_cannot_be_established_is_refused() {
        let dir = std::env::temp_dir().join(format!("mcp_re_perm_dir_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create dir");
        let key = dir.join("tls.key");
        std::fs::write(&key, b"key-material").expect("write");
        // No search permission on the directory: the file is still there and still
        // openable by anything holding a descriptor, but `stat` on the path fails EACCES.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).expect("chmod");

        let result = admit(&key.to_string_lossy(), KeyFileAccessPolicy::OwnerOnly);

        // Restore before asserting so a failure does not leave an unremovable directory.
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::remove_dir_all(&dir);

        let err = result.expect_err("an unestablishable key-file posture must refuse startup");
        assert!(
            err.contains("cannot be stat'ed"),
            "the refusal must say the posture could not be established, got: {err}"
        );
    }
}
