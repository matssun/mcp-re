// SPDX-License-Identifier: Apache-2.0
//! The PKCS#11 token-backed key source (#4034).

#[cfg(feature = "pkcs11_keysource")]
use super::read_pkcs11_pin;
use super::ChannelMaterial;
use crate::config_state::ChannelKeyMaterial;
use crate::key_source::{KeyError, KeySource};

/// Open a source whose signing key lives on a token.
///
/// The state carries all four values, so there is nothing to unwrap and no arm for
/// material that went missing.
#[cfg(feature = "pkcs11_keysource")]
pub(super) fn open(
    module: &str,
    pin_file: &str,
    token_label: &str,
    key_label: &str,
    channel: ChannelKeyMaterial<'_>,
    material: ChannelMaterial<'_>,
) -> Result<Box<dyn KeySource + Send + Sync>, KeyError> {
    // Read the User PIN here, at the one point it is used, so it exists for as short a
    // window as possible and never lands in `DeploymentRequest` (which is `Debug` and
    // freely cloned). The file must be no more readable than a key file: it unlocks the
    // token holding the signing keys.
    let pin = read_pkcs11_pin(pin_file)?;
    // #59: an optional SECOND token object holds the Ed25519 channel key. When present,
    // `open` builds the delegated handshake signer and the proxy never reads an exported
    // key from disk — a custody the request cannot even state alongside this one.
    Ok(Box::new(crate::pkcs11_keysource::Pkcs11KeySource::open(
        module,
        pin.expose(),
        token_label,
        key_label,
        material.cert,
        material.key,
        material.client_ca,
        channel.pkcs11_key_label(),
    )?))
}

/// Default build: the PKCS#11 backend is not compiled, so this FAILS CLOSED here (mirrors
/// the env-keysource gate). The flag still PARSES so the message is precise; no
/// token-backed key is built.
#[cfg(not(feature = "pkcs11_keysource"))]
pub(super) fn open(
    _module: &str,
    _pin_file: &str,
    _token_label: &str,
    _key_label: &str,
    _channel: ChannelKeyMaterial<'_>,
    _material: ChannelMaterial<'_>,
) -> Result<Box<dyn KeySource + Send + Sync>, KeyError> {
    Err(KeyError::NotFound(
        "pkcs11 key source requires the pkcs11_keysource feature (build with \
         --features pkcs11_keysource); not available in this build"
            .to_string(),
    ))
}
