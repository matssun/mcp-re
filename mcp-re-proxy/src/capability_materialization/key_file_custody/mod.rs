// SPDX-License-Identifier: Apache-2.0
//! The environmental half of key-file custody: observe the real objects, apply the policy,
//! and yield an earned result.
//!
//! One fact: **every private-key file this deployment reads was read from the object whose
//! permission posture was OBSERVED and found legal.**
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
//! receives [`AdmittedKeyFiles`] or a refusal, and hands the admission to the key-source
//! materializer, which takes each file's material from it rather than reopening a path.
//!
//! # The three subordinate roles
//!
//! - [`covered_files`] — WHICH files this deployment causes to be read. Pure, and the
//!   scope the floor is enforced over.
//! - [`process_groups`] — the PROCESS half of the environment: which groups this process
//!   is in, as the `fsGroup` relaxation is checked against.
//! - [`checked_key_file`] — the FILE half: open once, apply the policy to the opened
//!   object, and read that object — the same-object rule (r12 R12-630, R12-634).
//!
//! They are separate because they fail differently and are falsifiable separately: a file
//! can be absent or unstat'able, a group set cannot, and the scope can be wrong while both
//! observations are right — which is exactly the defect r12 R12-620 found.

mod checked_key_file;
mod covered_files;
mod process_groups;

pub use checked_key_file::CheckedKeyFile;

use crate::config_state::ChannelCredentialCustodyState;
use crate::config_state::CustodyState;
use crate::config_state::KeyFileAccessPolicy;
use crate::key_source::KeyError;

/// Every key file this deployment reads, admitted, with the material read from it.
///
/// The representation is private and [`admit_key_files`] is the only producer, so holding
/// one means every covered file was opened, checked and read — there is no constructor, no
/// `Default` and no field to fill in. It carries the custody states it was admitted FOR,
/// because the key-source materializer builds from exactly those: a key source cannot be
/// built from states whose files were never admitted.
#[derive(Debug)]
pub struct AdmittedKeyFiles<'a> {
    custody: &'a CustodyState,
    channel_credential_custody: &'a ChannelCredentialCustodyState,
    files: Vec<(String, Option<CheckedKeyFile>)>,
}

impl<'a> AdmittedKeyFiles<'a> {
    /// The files whose posture was observed and found legal, in the order checked. The
    /// scope is part of the claim: "every file was checked" means something only beside
    /// WHICH files those were.
    pub fn paths(&self) -> Vec<&str> {
        self.files.iter().map(|(path, _)| path.as_str()).collect()
    }

    /// The response-signing custody state these files were admitted for.
    pub(in crate::capability_materialization) fn custody(&self) -> &'a CustodyState {
        self.custody
    }

    /// The channel-credential custody state these files were admitted for.
    pub(in crate::capability_materialization) fn channel_credential_custody(
        &self,
    ) -> &'a ChannelCredentialCustodyState {
        self.channel_credential_custody
    }

    /// The material admitted at `path`, surrendered once.
    ///
    /// A path this admission never covered is a refusal, not a read: material exists here
    /// only for files the custody check walked. An absent file is reported now, by the
    /// consumer that needed it, naming it.
    pub(in crate::capability_materialization) fn take(
        &mut self,
        path: &str,
    ) -> Result<CheckedKeyFile, KeyError> {
        let slot = self
            .files
            .iter_mut()
            .find(|(covered, _)| covered == path)
            .ok_or_else(|| {
                KeyError::NotFound(format!("{path}: not a key file the custody check admitted"))
            })?;
        slot.1
            .take()
            .ok_or_else(|| KeyError::NotFound(format!("{path}: no such file")))
    }
}

/// Open, check and read every key file this deployment will use, or return the policy's
/// refusal.
///
/// The composition root's whole interface to key-file custody. It names the two custody
/// states and the policy; it does not learn which files those imply, what a mode means, or
/// which groups this process is in.
pub fn admit_key_files<'a>(
    custody: &'a CustodyState,
    channel_credential_custody: &'a ChannelCredentialCustodyState,
    policy: KeyFileAccessPolicy,
) -> Result<AdmittedKeyFiles<'a>, String> {
    let covered = covered_files::key_files_read_from_disk(custody, channel_credential_custody);
    let mut files = Vec::with_capacity(covered.len());
    for path in covered {
        let material = checked_key_file::observe(path, policy)?;
        files.push((path.to_owned(), material));
    }
    Ok(AdmittedKeyFiles {
        custody,
        channel_credential_custody,
        files,
    })
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

    /// The admission is the material's only route onward, and it hands each file over
    /// ONCE: the walked seed yields exactly the bytes that were checked, a second request
    /// for it is refused, an absent walked file is reported by name, and a path the walk
    /// never covered yields nothing — material exists here only for what custody observed.
    #[test]
    fn the_admission_surrenders_each_walked_file_once_and_nothing_else() {
        use crate::key_source::KeyError;
        use std::os::unix::fs::PermissionsExt;
        let seed = std::env::temp_dir().join(format!("mcp_re_take_{}.seed", std::process::id()));
        std::fs::write(&seed, b"seed-material").expect("write");
        std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let seed_path = seed.to_string_lossy().into_owned();

        let config = config_with("file", &seed_path, "/nonexistent/tls.key");
        let (custody, channel) = custody_states(&config);
        let mut admitted = admit_key_files(&custody, &channel, KeyFileAccessPolicy::OwnerOnly)
            .expect("the seed is legal and the TLS key is absent");
        let _ = std::fs::remove_file(&seed);

        let taken = admitted.take(&seed_path).expect("the walked seed");
        assert_eq!(&taken.into_bytes()[..], b"seed-material");
        assert!(matches!(
            admitted.take(&seed_path),
            Err(KeyError::NotFound(_))
        ));
        let absent = admitted.take("/nonexistent/tls.key").expect_err("absent");
        assert!(
            absent.to_string().contains("/nonexistent/tls.key"),
            "{absent}"
        );
        let unwalked = admitted.take("/etc/passwd").expect_err("never walked");
        assert!(
            unwalked.to_string().contains("not a key file"),
            "{unwalked}"
        );
    }

    /// R12-630/R12-634 END TO END, through the real loader: the seed is admitted, its path
    /// is then REPLACED by a different, world-readable seed, and only then is the key source
    /// built. It signs with the admitted seed — the loader consumed the checked object, not
    /// whatever the name resolves to now.
    #[test]
    fn the_loader_consumes_the_admitted_seed_when_the_path_is_replaced() {
        use crate::key_source::ResponseSigner;
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let seed = dir.join(format!("mcp_re_load_{pid}.seed"));
        let tls = dir.join(format!("mcp_re_load_{pid}.tls"));
        let intruder = dir.join(format!("mcp_re_load_{pid}.intruder"));
        let write = |path: &std::path::Path, content: &[u8], mode: u32| {
            std::fs::write(path, content).expect("write");
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
        };
        write(
            &seed,
            mcp_re_core::b64url_encode(&[1u8; 32]).as_bytes(),
            0o600,
        );
        let tls_pem = rcgen::KeyPair::generate().expect("key").serialize_pem();
        write(&tls, tls_pem.as_bytes(), 0o600);
        write(
            &intruder,
            mcp_re_core::b64url_encode(&[2u8; 32]).as_bytes(),
            0o644,
        );

        let config = config_with("file", &seed.to_string_lossy(), &tls.to_string_lossy());
        let (custody, channel) = custody_states(&config);
        let admitted = admit_key_files(&custody, &channel, KeyFileAccessPolicy::OwnerOnly)
            .expect("both files are owner-only");
        std::fs::rename(&intruder, &seed).expect("replace the admitted seed's path");

        let built = crate::capability_materialization::build_key_source(
            admitted,
            "/nonexistent/cert",
            "/nonexistent/ca",
        );
        let _ = std::fs::remove_file(&seed);
        let _ = std::fs::remove_file(&tls);
        let source = built
            .expect("built from admitted material")
            .into_key_source();
        assert_eq!(
            source.response_public_key().expect("a key").to_b64url(),
            mcp_re_core::SigningKey::from_seed_bytes(&[1u8; 32])
                .public_key()
                .to_b64url(),
            "the source must sign with the seed that was checked, not the replacement"
        );
    }
}
