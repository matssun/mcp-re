// SPDX-License-Identifier: Apache-2.0
//! Which filesystem postures this process accepts for the files it trusts: a key file it
//! reads, and a shared object it maps and executes ([`executable_path_violation`]).
//!
//! `--allow-group-readable-key-files` is not a preference. It decides whether a signing
//! key readable by a Unix group is a refusal or an accepted deployment, so it belongs to
//! the rule that decides it rather than travelling to the composition root as a `bool` the
//! root hands to a predicate.
//!
//! The difference is what a consumer receives. A boolean is a term in someone else's
//! rule — the caller still has to know that group read is conditional on the process's
//! supplementary groups, that group WRITE is never acceptable, and that any world bit is
//! fatal. A [`KeyFileAccessPolicy`] answers the question instead: given a mode, a file
//! owner uid, a file group, the process's effective uid and its groups, is this posture
//! refused, and why. The containing directory's posture is NOT examined by this rule.
//!
//! # Why the relaxed posture exists
//!
//! The strict rule is `0600`/`0400` and nothing else. That is correct on a normal host and
//! IMPOSSIBLE under the Kubernetes model a non-root pod needs: a Secret mounted for a
//! non-root uid is owned by the pod's `fsGroup` and delivered mode `0440`, so strict
//! refuses to start exactly the deployment that stopped running as root (C053b).
//!
//! Group read is therefore acceptable under three conditions, never fewer: the operator
//! asked for it explicitly, the file's group is one this process is actually in, and there
//! is no group write and no world bit at all.
//!
//! # A known asymmetry, deliberately left alone
//!
//! The PKCS#11 PIN file is held to the STRICT rule
//! ([`mode_is_insecure`]) whichever policy this resolves, so an
//! fsGroup-mounted PIN at `0440` is refused while an fsGroup-mounted signing key at `0440`
//! is accepted. Refusing more is not a fail-open, so it is recorded here rather than
//! quietly relaxed: loosening a secret-file check is an owner decision, not a consistency
//! cleanup.

use crate::deployment_request::DeploymentRequest;

/// Which key-file permission postures this deployment accepts.
///
/// Both variants are legal deployments, so this is not sealed against construction — there
/// is no illegal inhabitant to exclude. What it owns is the RULE: consumers ask it whether
/// a posture is refused instead of receiving the flag and re-deriving the rule around it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyFileAccessPolicy {
    /// The default and the strict posture: the owner alone, `0600`/`0400`.
    #[default]
    OwnerOnly,
    /// Group READ is accepted, but only for a group this process is a member of, and only
    /// with no group write and no world bit. The `fsGroup`-mounted-Secret posture.
    GroupReadableUnderProcessGroup,
}

/// Whether a file is owned by a uid that is neither this process's effective uid nor root.
///
/// Such an owner can rewrite or `chmod` the file whatever its mode bits say, so the bits
/// alone never establish who controls its contents. Root stays admitted: an `fsGroup`
/// Secret and a ConfigMap mount are root-owned. One rule for every file this process
/// trusts the contents of — key material here, the `--trust` document in
/// `trust_plane::snapshot`.
pub fn foreign_owner(file_uid: u32, process_euid: u32) -> bool {
    file_uid != process_euid && file_uid != 0
}

/// The refusal [`foreign_owner`] names.
pub const FOREIGN_OWNER: &str =
    "owned by a uid that is neither this process's effective uid nor root";

impl KeyFileAccessPolicy {
    /// Why this key file's posture is refused, or `None` when it is acceptable.
    ///
    /// Pure, so the rule is black-box testable without touching a filesystem — the caller
    /// supplies the `stat` results (mode, owner uid, group), the process's effective uid
    /// and its groups. The file must be owned by that uid or by root (an fsGroup-mounted
    /// Secret is root-owned). The containing directory's posture is NOT examined here.
    ///
    /// The order of the clauses is the order of severity, and each is separate on purpose:
    /// a world bit and a group-write bit are refused under BOTH policies, so relaxing the
    /// posture can never be read as relaxing those.
    pub fn violation(
        &self,
        mode: u32,
        file_uid: u32,
        file_gid: u32,
        process_euid: u32,
        process_gids: &[u32],
    ) -> Option<&'static str> {
        if foreign_owner(file_uid, process_euid) {
            return Some(FOREIGN_OWNER);
        }
        if mode & 0o007 != 0 {
            return Some("world-accessible");
        }
        if mode & 0o020 != 0 {
            return Some("group-writable");
        }
        if mode & 0o050 == 0 {
            return None;
        }
        match self {
            KeyFileAccessPolicy::OwnerOnly => Some(
                "group-accessible (pass --allow-group-readable-key-files if this is an \
                 fsGroup-owned mount)",
            ),
            KeyFileAccessPolicy::GroupReadableUnderProcessGroup => {
                if process_gids.contains(&file_gid) {
                    None
                } else {
                    Some("group-accessible to a group this process is not a member of")
                }
            }
        }
    }
}

/// Resolve the policy. Infallible: both postures are legal deployments, and the illegal
/// combination — a relaxed policy with a world-readable file — is not representable here
/// because it is a fact about a file, decided by [`KeyFileAccessPolicy::violation`].
pub fn classify(config: &DeploymentRequest) -> KeyFileAccessPolicy {
    if config.allow_group_readable_key_files {
        KeyFileAccessPolicy::GroupReadableUnderProcessGroup
    } else {
        KeyFileAccessPolicy::OwnerOnly
    }
}

/// Whether a Unix file mode is group- or world-accessible (MCPS-3842).
///
/// A sensitive key file must be restricted to the owner (mode `0600`); any group or world
/// permission bit set is an insecure posture. A pure predicate, so the warn-vs-reject
/// decision is black-box testable without touching the filesystem.
///
/// It lives with the POLICY rather than with either caller. ADR-MCPRE-067 Phase 8 moved it
/// out of `cli.rs`, where it sat beside argument parsing while both of its readers — the
/// startup permission check and the PKCS#11 PIN reader — are elsewhere.
pub fn mode_is_insecure(mode: u32) -> bool {
    mode & 0o077 != 0
}

/// Why `path` is unfit for this process to LOAD EXECUTABLE CODE from, or `None` when it is
/// fit. Two named predicates rather than one with a flag, because the two floors differ.
///
/// [`mode_is_insecure`] governs a file that is READ: disclosure is the whole harm, so any
/// group or world bit at all is refused and `0600` is the only posture left. This governs a
/// file that is MAPPED AND EXECUTED, where the capability that matters is REPLACEMENT, not
/// disclosure — a distro PKCS#11 module is root-owned `0644` under `0755` directories and is
/// a legitimate deployment, while one anybody may overwrite is arbitrary code inside this
/// process. So the refusal is a group or world WRITE bit, on the file and on every directory
/// above it: a writable directory lets an attacker unlink the file and put their own in its
/// place, which the file's own mode says nothing about.
///
/// The path is resolved before the modes are read, so what is examined is the file that
/// would actually be mapped rather than a symlink standing in front of it.
#[cfg(unix)]
pub fn executable_path_violation(path: &str) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;
    let resolved = match std::fs::canonicalize(path) {
        Ok(resolved) => resolved,
        Err(e) => return Some(format!("{path} cannot be resolved: {e}")),
    };
    for component in resolved.ancestors() {
        let mode = match std::fs::symlink_metadata(component) {
            Ok(meta) => meta.permissions().mode(),
            Err(e) => return Some(format!("{} cannot be read: {e}", component.display())),
        };
        if mode & 0o022 != 0 {
            return Some(format!(
                "{} is group/world-writable (mode {:o}), so its contents can be replaced",
                component.display(),
                mode & 0o7777
            ));
        }
    }
    None
}

/// The non-Unix form. There is no mode to read, so there is no floor to apply — stated as
/// its own arm rather than left implicit, mirroring how `read_pkcs11_pin` scopes its own
/// permission check to `unix`.
#[cfg(not(unix))]
pub fn executable_path_violation(_path: &str) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const STRICT: KeyFileAccessPolicy = KeyFileAccessPolicy::OwnerOnly;
    const RELAXED: KeyFileAccessPolicy = KeyFileAccessPolicy::GroupReadableUnderProcessGroup;

    /// The owner-only posture accepts exactly the two owner-only modes.
    #[test]
    fn owner_only_accepts_0600_and_0400_and_nothing_else() {
        assert_eq!(STRICT.violation(0o600, 1000, 1000, 1000, &[1000]), None);
        assert_eq!(STRICT.violation(0o400, 1000, 1000, 1000, &[1000]), None);
        assert!(STRICT.violation(0o440, 1000, 1000, 1000, &[1000]).is_some());
        assert!(STRICT.violation(0o604, 1000, 1000, 1000, &[1000]).is_some());
        assert!(STRICT.violation(0o660, 1000, 1000, 1000, &[1000]).is_some());
        assert!(STRICT.violation(0o777, 1000, 1000, 1000, &[1000]).is_some());
    }

    /// The relaxed posture is the fsGroup mount, and only that.
    #[test]
    fn group_read_is_accepted_only_for_a_group_this_process_is_in() {
        assert_eq!(
            RELAXED.violation(0o440, 1000, 2000, 1000, &[1000, 2000]),
            None
        );
        assert!(
            RELAXED
                .violation(0o440, 1000, 9999, 1000, &[1000, 2000])
                .is_some(),
            "a group the process is not in grants a stranger, which is worse than strict"
        );
    }

    /// Neither policy accepts a world bit or a group-write bit.
    ///
    /// This is the property that makes the relaxed posture a NARROWING of who may read
    /// rather than a general loosening: an operator who passes the flag has not also
    /// accepted a key another process can replace.
    #[test]
    fn no_policy_accepts_world_access_or_group_write() {
        for mode in [
            0o004, 0o002, 0o001, 0o441, 0o444, 0o604, 0o642, 0o666, 0o777,
        ] {
            assert!(
                RELAXED.violation(mode, 1000, 2000, 1000, &[2000]).is_some(),
                "world bit accepted at {mode:o}"
            );
            assert!(STRICT.violation(mode, 1000, 2000, 1000, &[2000]).is_some());
        }
        for mode in [0o020, 0o060, 0o460, 0o620, 0o660] {
            assert!(
                RELAXED.violation(mode, 1000, 2000, 1000, &[2000]).is_some(),
                "group write accepted at {mode:o}"
            );
            assert!(STRICT.violation(mode, 1000, 2000, 1000, &[2000]).is_some());
        }
    }

    #[test]
    fn a_key_file_owned_by_another_uid_is_refused_under_both_policies() {
        assert!(STRICT.violation(0o600, 1001, 1000, 1000, &[1000]).is_some());
        assert!(RELAXED
            .violation(0o440, 1001, 2000, 1000, &[1000, 2000])
            .is_some());
    }

    #[test]
    fn a_root_owned_fsgroup_secret_is_still_admitted() {
        assert_eq!(RELAXED.violation(0o440, 0, 2000, 1000, &[1000, 2000]), None);
        assert_eq!(STRICT.violation(0o400, 0, 0, 1000, &[1000]), None);
    }

    /// The flag decides the policy, and absence is the strict one.
    #[test]
    fn the_default_deployment_is_owner_only() {
        let config = crate::config_state::test_support::legal_config();
        assert_eq!(classify(&config), KeyFileAccessPolicy::OwnerOnly);

        let mut relaxed = crate::config_state::test_support::legal_config();
        relaxed.allow_group_readable_key_files = true;
        assert_eq!(
            classify(&relaxed),
            KeyFileAccessPolicy::GroupReadableUnderProcessGroup
        );
    }

    /// The POSITIVE control for the executable floor, and the one that decides whether the
    /// floor is usable at all: a normal `0644` file under `0755` directories — the shape of
    /// `/usr/lib/softhsm/libsofthsm2.so` and of the in-tree mock module the PKCS#11 e2e lane
    /// builds — must still load. A floor that refuses every real module is a capability
    /// loss, not a fix.
    /// `/bin/sh` is the reference case: a root-owned executable under root-owned `0755`
    /// directories, which is the posture of `/usr/lib/softhsm/libsofthsm2.so` and of
    /// every packaged PKCS#11 module.
    #[cfg(unix)]
    #[test]
    fn a_packaged_system_library_posture_is_still_loadable() {
        // Several candidates so a sandboxed lane that does not expose `/bin` still
        // measures the property rather than self-skipping; `/` exists everywhere.
        let reference = ["/bin/sh", "/bin", "/usr/lib", "/"]
            .into_iter()
            .find(|p| std::fs::metadata(p).is_ok())
            .expect("a POSIX host exposes at least one of /bin/sh, /bin, /usr/lib, /");
        assert_eq!(
            executable_path_violation(reference),
            None,
            "{reference} is root-owned under 0755 system directories, which is the \
             ordinary module posture"
        );
    }

    /// The same control without depending on any system path: a `0644` file this test
    /// creates inside a `0700` directory it creates is never the component refused.
    #[cfg(unix)]
    #[test]
    fn a_0644_module_in_an_owner_only_directory_is_not_the_refused_component() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("mcp-re-mod-ok-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).expect("create dir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod dir");
        let path = dir.join("libmodule.so");
        std::fs::write(&path, b"not really a library").expect("write module");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("chmod 0644");
        // A shared temp root above it may itself be world-writable (`/tmp` is 1777), and
        // that is a true refusal about `/tmp`. What must never happen is a refusal of the
        // 0644 file or of the 0700 directory holding it.
        if let Some(why) = executable_path_violation(path.to_str().expect("utf-8")) {
            assert!(
                !why.contains("mcp-re-mod-ok-"),
                "a 0644 file in a 0700 directory must not be refused: {why}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A file anyone may overwrite is arbitrary code in this process.
    #[cfg(unix)]
    #[test]
    fn a_world_writable_module_file_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("mcp-re-mod-w-{}", std::process::id()));
        std::fs::write(&path, b"not really a library").expect("write module");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))
            .expect("chmod 0666");
        let why = executable_path_violation(path.to_str().expect("utf-8"))
            .expect("a world-writable module file is refused");
        assert!(
            why.contains("group/world-writable") && why.contains("mcp-re-mod-w-"),
            "the refusal must name the offending file: {why}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// The directory clause, which is the half a mode check on the file alone cannot have:
    /// the file is `0644` and unimpeachable, and it is still replaceable by anyone who can
    /// unlink it out of its parent.
    #[cfg(unix)]
    #[test]
    fn a_module_in_a_group_writable_directory_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("mcp-re-mod-d-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).expect("create dir");
        let path = dir.join("libmodule.so");
        std::fs::write(&path, b"not really a library").expect("write module");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("chmod 0644");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).expect("chmod dir");
        let why = executable_path_violation(path.to_str().expect("utf-8"))
            .expect("a module in a writable directory is refused");
        assert!(
            why.contains("group/world-writable") && why.contains("mcp-re-mod-d-"),
            "the refusal must name the offending DIRECTORY, not the file: {why}"
        );
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The GROUP-write half of the floor, on its own.
    ///
    /// The world-writable cases above are caught by the `0o002` bit alone, so they say
    /// nothing about `0o020`. This is also the posture a build host with `umask 002`
    /// produces — directories `0775`, files `0664` — which is the likeliest way a real
    /// deployment meets this refusal, and it was the half no test reached.
    #[cfg(unix)]
    #[test]
    fn group_write_alone_is_refused_on_the_directory_and_on_the_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("mcp-re-mod-g-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).expect("create dir");
        let path = dir.join("libmodule.so");
        std::fs::write(&path, b"not really a library").expect("write module");

        // umask 002: the file is 0664, the directory 0775. Neither carries a world-write
        // bit, so only the 0o020 half of the mask can refuse either one.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664))
            .expect("chmod 0664");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).expect("chmod dir");
        let why = executable_path_violation(path.to_str().expect("utf-8"))
            .expect("a group-writable module file is refused");
        assert!(
            why.contains("libmodule.so") && why.contains("664"),
            "the refusal must name the group-writable FILE and its mode: {why}"
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("chmod 0644");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o775)).expect("chmod dir");
        let why = executable_path_violation(path.to_str().expect("utf-8"))
            .expect("a module in a group-writable directory is refused");
        assert!(
            why.contains("mcp-re-mod-g-") && why.contains("775"),
            "the refusal must name the group-writable DIRECTORY and its mode: {why}"
        );

        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The WORLD-write half of the floor, on its own.
    ///
    /// Sibling of the group-only case above, and it exists for the same reason: every
    /// other fixture here carries BOTH bits, so either one alone would catch them all and
    /// neither half would be pinned. `0o606` and `0o757` are world-writable and NOT
    /// group-writable, so only the `0o002` half of the mask can refuse them.
    #[cfg(unix)]
    #[test]
    fn world_write_alone_is_refused_on_the_directory_and_on_the_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("mcp-re-mod-wonly-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).expect("create dir");
        let path = dir.join("libmodule.so");
        std::fs::write(&path, b"not really a library").expect("write module");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o606))
            .expect("chmod 0606");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).expect("chmod dir");
        let why = executable_path_violation(path.to_str().expect("utf-8"))
            .expect("a world-writable module file is refused");
        assert!(
            why.contains("libmodule.so") && why.contains("606"),
            "the refusal must name the world-writable FILE and its mode: {why}"
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("chmod 0644");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o757)).expect("chmod dir");
        let why = executable_path_violation(path.to_str().expect("utf-8"))
            .expect("a module in a world-writable directory is refused");
        assert!(
            why.contains("mcp-re-mod-wonly-") && why.contains("757"),
            "the refusal must name the world-writable DIRECTORY and its mode: {why}"
        );

        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A path that names nothing is refused rather than passed to `dlopen` to fail there.
    #[cfg(unix)]
    #[test]
    fn a_module_path_that_resolves_to_nothing_is_refused() {
        let missing = std::env::temp_dir().join(format!("mcp-re-absent-{}", std::process::id()));
        let why = executable_path_violation(missing.to_str().expect("utf-8"))
            .expect("an unresolvable module path is refused");
        assert!(
            why.contains("cannot be resolved"),
            "expected a resolution refusal, got: {why}"
        );
    }

    #[test]
    fn key_file_mode_predicate_flags_group_and_world_bits() {
        // The pure file-perm predicate used by main.rs's strict key-file check:
        // owner-only (0600) is safe; any group/world bit is insecure.
        assert!(!mode_is_insecure(0o600), "0600 owner-only is safe");
        assert!(!mode_is_insecure(0o400), "0400 owner-read is safe");
        assert!(mode_is_insecure(0o640), "group-readable is insecure");
        assert!(mode_is_insecure(0o604), "world-readable is insecure");
        assert!(mode_is_insecure(0o660), "group-writable is insecure");
        assert!(mode_is_insecure(0o777), "world-everything is insecure");
    }
}
