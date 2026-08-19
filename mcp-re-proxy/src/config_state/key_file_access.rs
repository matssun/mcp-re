// SPDX-License-Identifier: Apache-2.0
//! Which filesystem postures a key file may be in, as one owned decision.
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
//! group and the process's groups, is this posture refused, and why.
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
//! ([`crate::cli::key_file_mode_is_insecure`]) whichever policy this resolves, so an
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

impl KeyFileAccessPolicy {
    /// Why this key file's posture is refused, or `None` when it is acceptable.
    ///
    /// Pure, so the rule is black-box testable without touching a filesystem — the caller
    /// supplies the `stat` results and the process's supplementary groups.
    ///
    /// The order of the clauses is the order of severity, and each is separate on purpose:
    /// a world bit and a group-write bit are refused under BOTH policies, so relaxing the
    /// posture can never be read as relaxing those.
    pub fn violation(
        &self,
        mode: u32,
        file_gid: u32,
        process_gids: &[u32],
    ) -> Option<&'static str> {
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

#[cfg(test)]
mod tests {
    use super::*;

    const STRICT: KeyFileAccessPolicy = KeyFileAccessPolicy::OwnerOnly;
    const RELAXED: KeyFileAccessPolicy = KeyFileAccessPolicy::GroupReadableUnderProcessGroup;

    /// The owner-only posture accepts exactly the two owner-only modes.
    #[test]
    fn owner_only_accepts_0600_and_0400_and_nothing_else() {
        assert_eq!(STRICT.violation(0o600, 1000, &[1000]), None);
        assert_eq!(STRICT.violation(0o400, 1000, &[1000]), None);
        assert!(STRICT.violation(0o440, 1000, &[1000]).is_some());
        assert!(STRICT.violation(0o604, 1000, &[1000]).is_some());
        assert!(STRICT.violation(0o660, 1000, &[1000]).is_some());
        assert!(STRICT.violation(0o777, 1000, &[1000]).is_some());
    }

    /// The relaxed posture is the fsGroup mount, and only that.
    #[test]
    fn group_read_is_accepted_only_for_a_group_this_process_is_in() {
        assert_eq!(RELAXED.violation(0o440, 2000, &[1000, 2000]), None);
        assert!(
            RELAXED.violation(0o440, 9999, &[1000, 2000]).is_some(),
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
                RELAXED.violation(mode, 2000, &[2000]).is_some(),
                "world bit accepted at {mode:o}"
            );
            assert!(STRICT.violation(mode, 2000, &[2000]).is_some());
        }
        for mode in [0o020, 0o060, 0o460, 0o620, 0o660] {
            assert!(
                RELAXED.violation(mode, 2000, &[2000]).is_some(),
                "group write accepted at {mode:o}"
            );
            assert!(STRICT.violation(mode, 2000, &[2000]).is_some());
        }
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
}
