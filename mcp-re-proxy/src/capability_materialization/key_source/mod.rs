// SPDX-License-Identifier: Apache-2.0
//! Opening the key source a validated custody state names.
//!
//! One module per mechanism, and a dispatch that is only a dispatch. The five arms used to
//! be one 210-line function whose AWS branch alone was 80 lines of KMS-client assembly; a
//! reader looking for what PKCS#11 does had to scroll past what IRSA does.
//!
//! **Each arm appears twice, once per build.** Whether this executable HAS a backend is
//! layer B and is decided here, not at the configuration boundary: `--key-source pkcs11` is
//! a coherent request in a build without the feature, and refusing it is a statement about
//! the executable rather than about the request (CF-05).

mod aws;
mod file;
mod gcp;
mod pin;
mod pkcs11;
mod role_identity;
mod role_separation;

pub use role_separation::MaterializedSigningRoles;

use super::key_file_custody::{AdmittedKeyFiles, CheckedKeyFile};
use crate::config_state::{CustodyMaterial, CustodyState};
use crate::key_source::{KeyError, KeySource};

/// The channel material every custody consumes, whatever holds the response-signing key.
///
/// `cert` and `client_ca` belong to no custody machine — every state consumes them, and
/// shared use is not semantic ownership. Under every state they are filesystem paths.
///
/// `key` is a LOCATOR, present only where custody exports the channel key. Every arm takes
/// the key's material from the admission with [`exported_tls_key`], and no arm reopens it
/// as a path.
#[derive(Debug, Clone, Copy)]
pub(super) struct ChannelMaterial<'a> {
    /// The credential chain this node presents.
    pub(super) cert: &'a str,
    /// The exported channel-key locator, `None` where custody keeps it on a device.
    pub(super) key: Option<&'a str>,
    /// The anchors peer credentials are verified against.
    pub(super) client_ca: &'a str,
}

/// The exported channel key as the custody check read it, or `None` where custody keeps
/// it on a device.
///
/// Called by each file-backed arm, AFTER the arm has established that this build has its
/// backend: which executable this is outranks which file is missing.
pub(super) fn exported_tls_key(
    admitted: &mut AdmittedKeyFiles<'_>,
    material: ChannelMaterial<'_>,
) -> Result<Option<CheckedKeyFile>, KeyError> {
    match material.key {
        None => Ok(None),
        Some(path) => admitted.take(path).map(Some),
    }
}

/// Build the key source the admitted custody names.
///
/// Takes the ADMISSION, not the custody states: it carries the states it was admitted for
/// and the material read from every key file they cover, so a key source cannot be built
/// over files the custody check never read, and every key byte it holds came from the
/// object that check observed (r12 R12-630, R12-634).
pub fn build_key_source(
    mut admitted: AdmittedKeyFiles<'_>,
    tls_cert: &str,
    client_ca: &str,
) -> Result<MaterializedSigningRoles, KeyError> {
    let custody = admitted.custody();
    let channel = admitted.channel_credential_custody().material();
    let material = ChannelMaterial {
        cert: tls_cert,
        key: channel.exported_key_path(),
        client_ca,
    };
    let source = open_source(custody, channel, material, &mut admitted)?;
    // The relation between what the two custody machines materialized. Neither can see the
    // other's key, so neither can own it; and it is asked HERE because the decisive fact —
    // which key each role actually resolved to — exists only once both are open.
    MaterializedSigningRoles::establish(source)
}

/// Open the key source the classified custody names.
///
/// The dispatch, and nothing else. Separate from [`build_key_source`] so that the role
/// relation above cannot be reached without a source, and a source cannot leave this module
/// without the relation.
fn open_source(
    custody: &CustodyState,
    channel: crate::config_state::ChannelKeyMaterial<'_>,
    material: ChannelMaterial<'_>,
    admitted: &mut AdmittedKeyFiles<'_>,
) -> Result<Box<dyn KeySource + Send + Sync>, KeyError> {
    match custody.material() {
        CustodyMaterial::FileSeed { seed_path } => file::open(admitted, seed_path, material),
        CustodyMaterial::Pkcs11 {
            module,
            pin_file,
            token_label,
            key_label,
        } => pkcs11::open(
            module,
            admitted,
            pin_file,
            token_label,
            key_label,
            channel,
            material,
        ),
        CustodyMaterial::AwsKms {
            region,
            key_id,
            endpoint,
            credentials,
        } => aws::open(
            admitted,
            region,
            key_id,
            endpoint,
            credentials,
            channel,
            material,
        ),
        CustodyMaterial::GcpKms {
            key_version,
            endpoint,
            use_metadata,
        } => gcp::open(
            admitted,
            key_version,
            endpoint,
            use_metadata,
            channel,
            material,
        ),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::{exported_tls_key, ChannelMaterial};
    use crate::capability_materialization::key_file_custody::admit_key_files;
    use crate::config_state::test_support::{config_with, custody_states};
    use crate::config_state::KeyFileAccessPolicy;
    use crate::key_source::KeyError;

    /// The exported channel key is surrendered by the admission only when custody names
    /// one: `None` takes nothing, and a named key is yielded once.
    #[test]
    fn the_exported_channel_key_is_taken_from_the_admission_only_when_custody_exports_one() {
        use std::os::unix::fs::PermissionsExt;
        let tls =
            std::env::temp_dir().join(format!("mcp_re_exported_tls_{}.key", std::process::id()));
        std::fs::write(&tls, b"tls-key-material").expect("write");
        std::fs::set_permissions(&tls, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let tls_path = tls.to_string_lossy().into_owned();

        let config = config_with("file", "/nonexistent/mcp_re_seed", &tls_path);
        let (custody, channel) = custody_states(&config);
        let mut admitted = admit_key_files(&custody, &channel, KeyFileAccessPolicy::OwnerOnly)
            .expect("the exported key is legal and the seed is absent");
        let _ = std::fs::remove_file(&tls);

        let device = ChannelMaterial {
            cert: "/c",
            key: None,
            client_ca: "/ca",
        };
        assert!(matches!(exported_tls_key(&mut admitted, device), Ok(None)));

        let exported = ChannelMaterial {
            key: Some(&tls_path),
            ..device
        };
        let file = exported_tls_key(&mut admitted, exported)
            .expect("the walked key")
            .expect("custody exports a key");
        assert_eq!(&file.into_bytes()[..], b"tls-key-material");
        assert!(matches!(
            exported_tls_key(&mut admitted, exported),
            Err(KeyError::NotFound(_))
        ));
    }
}
