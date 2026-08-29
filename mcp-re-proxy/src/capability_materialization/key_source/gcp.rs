// SPDX-License-Identifier: Apache-2.0
//! The GCP Cloud KMS key source (ADR-MCPS-028 §C).

use super::ChannelMaterial;
use crate::config_state::ChannelKeyMaterial;
use crate::key_source::{KeyError, KeySource};

/// Open a source whose signing key is a Cloud KMS key version, with channel material from
/// files.
#[cfg(feature = "gcp_kms_keysource")]
pub(super) fn open(
    key_version: &str,
    endpoint: Option<&str>,
    use_metadata: bool,
    channel: ChannelKeyMaterial<'_>,
    material: ChannelMaterial<'_>,
) -> Result<Box<dyn KeySource + Send + Sync>, KeyError> {
    let signing = backend(key_version, endpoint, use_metadata)?;
    let tls =
        crate::key_source::FileKeySource::tls_only(material.cert, material.key, material.client_ca);
    // #61: the GCP counterpart of #60 — a SECOND, DISTINCT key version custodies the
    // channel key, and the proxy never reads an exported key from disk.
    let Some(channel_key_version) = channel.gcp_key_version() else {
        return Ok(Box::new(crate::kms_keysource::KmsKeySource::new(
            Box::new(signing),
            tls,
        )));
    };
    let channel_signer = backend(channel_key_version, endpoint, use_metadata)?;
    Ok(Box::new(
        crate::kms_keysource::KmsKeySource::new_with_delegated_tls(
            Box::new(signing),
            tls,
            std::sync::Arc::new(channel_signer),
        ),
    ))
}

/// One Cloud KMS backend, at the named key version.
#[cfg(feature = "gcp_kms_keysource")]
fn backend(
    key_version: &str,
    endpoint: Option<&str>,
    use_metadata: bool,
) -> Result<crate::gcp_kms_keysource::GcpKmsEd25519Backend, KeyError> {
    let config = crate::gcp_kms_keysource::GcpKmsConfig {
        key_version_name: key_version.to_string(),
        endpoint: endpoint.map(str::to_string),
    };
    crate::gcp_kms_keysource::GcpKmsEd25519Backend::new(&config, use_metadata)
}

/// Default build: the Cloud KMS backend is not compiled, so this FAILS CLOSED here.
#[cfg(not(feature = "gcp_kms_keysource"))]
pub(super) fn open(
    _key_version: &str,
    _endpoint: Option<&str>,
    _use_metadata: bool,
    _channel: ChannelKeyMaterial<'_>,
    _material: ChannelMaterial<'_>,
) -> Result<Box<dyn KeySource + Send + Sync>, KeyError> {
    Err(KeyError::NotFound(
        "gcp-kms key source requires the gcp_kms_keysource feature (build with \
         --features gcp_kms_keysource); not available in this build"
            .to_string(),
    ))
}
