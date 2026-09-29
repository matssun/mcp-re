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
mod env;
mod file;
mod gcp;
mod pin;
mod pkcs11;
mod role_identity;
mod role_separation;

pub use pin::read_pkcs11_pin;
pub use role_separation::MaterializedSigningRoles;

use super::key_file_custody::{AdmittedKeyFiles, CheckedKeyFile};
use crate::config_state::{CustodyMaterial, CustodyState};
use crate::key_source::{KeyError, KeySource};

/// The channel material every custody consumes, whatever holds the response-signing key.
///
/// `tls_cert` and `client_ca` belong to no custody machine — all five states consume them,
/// and shared use is not semantic ownership. They are STRINGS WHOSE INTERPRETATION THE
/// CUSTODY STATE DECIDES: filesystem paths under every state but
/// [`CustodyMaterial::EnvSeed`], where they name environment variables. The same is true of
/// the exported channel-key locator carried by the exported channel-custody state.
///
/// `key` is a LOCATOR. The environment arm reads it as a variable name; every file-backed
/// arm takes the key's material from the admission with [`exported_tls_key`] instead, and
/// no arm reopens it as a path.
#[derive(Debug, Clone, Copy)]
pub(super) struct ChannelMaterial<'a> {
    /// The credential chain this node presents.
    pub(super) cert: &'a str,
    /// The exported channel-key locator, empty where custody keeps it on a device.
    pub(super) key: &'a str,
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
    if material.key.is_empty() {
        return Ok(None);
    }
    admitted.take(material.key).map(Some)
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
        key: channel.exported_key_path().unwrap_or(""),
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
        CustodyMaterial::EnvSeed { env_var } => env::open(env_var, material),
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
