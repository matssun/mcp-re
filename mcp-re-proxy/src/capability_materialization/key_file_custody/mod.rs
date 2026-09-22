// SPDX-License-Identifier: Apache-2.0
//! The environmental half of key-file custody: observe the real objects, apply the policy,
//! and yield an earned result.
//!
//! One fact: **every private-key file this deployment will read had its permission posture
//! OBSERVED and found legal.**
//!
//! # The authority split
//!
//! `config_state::key_file_access` is the PURE policy owner and stays there: given a
//! posture, is it legal for this deployment? It touches no filesystem and reads no process
//! state, which is what makes it decidable from configuration alone.
//!
//! This subtree is the other half, and it is a MATERIALIZATION concern because it is the
//! only part that needs the world: `stat` the real object, read the real process group
//! set, hand both to the policy. That is the direction this layer's parent already
//! documents — a materializer takes a classified state and fails because the environment
//! does, never because it re-decided legality.
//!
//! # Why it is here and not in `app.rs`
//!
//! It was in `app.rs`, which meant the composition root inspected filesystem modes,
//! reconstructed group-access decisions and maintained its own list of which files custody
//! puts on disk. Three semantic roles in the file whose job is to compose them. The
//! composition root is now a consumer: it names the deployment's two custody states and
//! receives [`AdmittedKeyFiles`] or a refusal.
//!
//! # The three subordinate roles
//!
//! - [`covered_files`] — WHICH files this deployment causes to be read. Pure, and the
//!   scope the floor is enforced over.
//! - [`process_groups`] — the PROCESS half of the environment: which groups this process
//!   is in, as the `fsGroup` relaxation is checked against.
//! - [`observed_posture`] — the FILE half, plus applying the policy to what was observed.
//!
//! They are separate because they fail differently and are falsifiable separately: a file
//! can be absent or unstat'able, a group set cannot, and the scope can be wrong while both
//! observations are right — which is exactly the defect r12 R12-620 found.

mod covered_files;
mod observed_posture;
mod process_groups;

use crate::config_state::ChannelCredentialCustodyState;
use crate::config_state::CustodyState;
use crate::config_state::KeyFileAccessPolicy;

/// Evidence that every key file this deployment reads was admitted by the policy.
///
/// The representation is private and [`admit_key_files`] is the only producer, so holding
/// one means the observation happened — there is no constructor, no `Default` and no field
/// to fill in. It carries the admitted paths because the scope is part of the claim: "every
/// file was checked" is only meaningful beside WHICH files those were.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedKeyFiles {
    paths: Vec<String>,
}

impl AdmittedKeyFiles {
    /// The files whose posture was observed and found legal, in the order checked.
    ///
    /// For diagnostics and controls. A consumer that wants to READ one of these still
    /// opens it itself — this type is evidence about a posture, not a file handle, and
    /// claiming otherwise would be the TOCTOU gap r12 R12-634 already records.
    pub fn paths(&self) -> &[String] {
        &self.paths
    }
}

/// Observe and admit every key file this deployment will read, or return the policy's
/// refusal.
///
/// The composition root's whole interface to key-file custody. It names the two custody
/// states and the policy; it does not learn which files those imply, what a mode means, or
/// which groups this process is in.
pub fn admit_key_files(
    custody: &CustodyState,
    channel_credential_custody: &ChannelCredentialCustodyState,
    policy: KeyFileAccessPolicy,
) -> Result<AdmittedKeyFiles, String> {
    let covered = covered_files::key_files_read_from_disk(custody, channel_credential_custody);
    let mut paths = Vec::with_capacity(covered.len());
    for path in covered {
        observed_posture::admit(path, policy)?;
        paths.push(path.to_owned());
    }
    Ok(AdmittedKeyFiles { paths })
}

#[cfg(all(test, unix))]
mod tests {
    use super::admit_key_files;
    use crate::config_state::test_support::config_with;
    use crate::config_state::test_support::custody_states;
    use crate::config_state::KeyFileAccessPolicy;

    /// The product names the SCOPE it walked, which is what makes "every key file was
    /// admitted" a claim rather than a mood: the sentence is only meaningful beside which
    /// files those were.
    #[test]
    fn the_admitted_product_names_the_scope_it_walked() {
        let config = config_with("pkcs11", "", "/tls.key");
        let (custody, channel) = custody_states(&config);
        let admitted = admit_key_files(&custody, &channel, KeyFileAccessPolicy::OwnerOnly)
            .expect("no file exists at either path, so no posture is illegal");
        assert_eq!(admitted.paths(), ["/etc/mcp-re/pin", "/tls.key"]);
    }

    /// ONE illegal key file refuses the whole admission — the walk stops rather than
    /// collecting a partial product. A deployment with a world-readable key does not start,
    /// so there is no "admitted except for that one" to represent.
    #[test]
    fn one_illegal_key_file_refuses_the_whole_admission() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("mcp_re_admit_{}.key", std::process::id()));
        let mut f = std::fs::File::create(&path).expect("create");
        f.write_all(b"key-material").expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");

        let config = config_with("file", &path.to_string_lossy(), "/tls.key");
        let (custody, channel) = custody_states(&config);
        let refusal = admit_key_files(&custody, &channel, KeyFileAccessPolicy::OwnerOnly)
            .expect_err("a world-readable seed refuses the admission");
        assert!(refusal.contains("world-accessible"), "{refusal}");
        assert!(
            refusal.contains("mcp_re_admit_"),
            "the refusal names WHICH file: {refusal}"
        );
        let _ = std::fs::remove_file(&path);
    }
}
