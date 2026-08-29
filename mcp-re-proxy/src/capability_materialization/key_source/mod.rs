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

pub use pin::read_pkcs11_pin;

use crate::config_state::{ChannelCredentialCustodyState, CustodyMaterial, CustodyState};
use crate::key_source::{KeyError, KeySource};

/// The channel material every custody consumes, whatever holds the response-signing key.
///
/// `tls_cert` and `client_ca` belong to no custody machine — all five states consume them,
/// and shared use is not semantic ownership. They are STRINGS WHOSE INTERPRETATION THE
/// CUSTODY STATE DECIDES: filesystem paths under every state but
/// [`CustodyMaterial::EnvSeed`], where they name environment variables. The same is true of
/// the exported channel-key locator carried by the exported channel-custody state.
#[derive(Debug, Clone, Copy)]
pub(super) struct ChannelMaterial<'a> {
    /// The credential chain this node presents.
    pub(super) cert: &'a str,
    /// The exported channel key, empty where custody keeps it on a device.
    pub(super) key: &'a str,
    /// The anchors peer credentials are verified against.
    pub(super) client_ca: &'a str,
}

/// Build the key source the classified custody names.
///
/// A dispatch and nothing else: the state carries every value each mechanism requires, so
/// there is nothing to unwrap here and no arm for material that went missing.
pub fn build_key_source(
    custody: &CustodyState,
    channel_credential_custody: &ChannelCredentialCustodyState,
    tls_cert: &str,
    client_ca: &str,
) -> Result<Box<dyn KeySource + Send + Sync>, KeyError> {
    let channel = channel_credential_custody.material();
    let material = ChannelMaterial {
        cert: tls_cert,
        key: channel.exported_key_path().unwrap_or(""),
        client_ca,
    };
    match custody.material() {
        CustodyMaterial::FileSeed { seed_path } => file::open(seed_path, material),
        CustodyMaterial::EnvSeed { env_var } => env::open(env_var, material),
        CustodyMaterial::Pkcs11 {
            module,
            pin_file,
            token_label,
            key_label,
        } => pkcs11::open(module, pin_file, token_label, key_label, channel, material),
        CustodyMaterial::AwsKms {
            region,
            key_id,
            endpoint,
            credentials,
        } => aws::open(region, key_id, endpoint, credentials, channel, material),
        CustodyMaterial::GcpKms {
            key_version,
            endpoint,
            use_metadata,
        } => gcp::open(key_version, endpoint, use_metadata, channel, material),
    }
}
