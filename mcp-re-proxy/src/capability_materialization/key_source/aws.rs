// SPDX-License-Identifier: Apache-2.0
//! The AWS KMS key source (ADR-MCPS-028 §B). The response-signing key never leaves KMS.

use super::ChannelMaterial;
#[cfg(feature = "aws_kms_keysource")]
use crate::config_state::AwsCredentialMode;
use crate::config_state::ChannelKeyMaterial;
use crate::key_source::{KeyError, KeySource};

/// Open a source whose signing key is a KMS key, with channel material from files.
#[cfg(feature = "aws_kms_keysource")]
pub(super) fn open(
    region: &str,
    key_id: &str,
    endpoint: Option<&str>,
    credentials: &AwsCredentialMode,
    channel: ChannelKeyMaterial<'_>,
    material: ChannelMaterial<'_>,
) -> Result<Box<dyn KeySource + Send + Sync>, KeyError> {
    let signing = backend(region, key_id, endpoint, credentials)?;
    let tls =
        crate::key_source::FileKeySource::tls_only(material.cert, material.key, material.client_ca);
    // #60: a configured channel key id custodies the channel key in a SECOND, DISTINCT KMS
    // key, independent of the object-signing one. It takes the SAME credential path as the
    // signing key, so a deployment cannot end up with one KMS principal reached through
    // IRSA and the other through static keys.
    let Some(channel_key_id) = channel.aws_key_id() else {
        return Ok(Box::new(crate::kms_keysource::KmsKeySource::new(
            Box::new(signing),
            tls,
        )));
    };
    let channel_signer = backend(region, channel_key_id, endpoint, credentials)?;
    Ok(Box::new(
        crate::kms_keysource::KmsKeySource::new_with_delegated_tls(
            Box::new(signing),
            tls,
            std::sync::Arc::new(channel_signer),
        ),
    ))
}

/// One KMS backend, under the one credential posture this deployment chose.
///
/// IRSA or the static env pair — never both, never a fallback between them. A deployment
/// that asked for web identity and cannot mint through it must fail, not quietly sign with
/// whatever keys are in the process environment. The posture is a tagged value, so there is
/// no pair of flags here to combine wrongly.
#[cfg(feature = "aws_kms_keysource")]
fn backend(
    region: &str,
    key_id: &str,
    endpoint: Option<&str>,
    credentials: &AwsCredentialMode,
) -> Result<crate::aws_kms_keysource::AwsKmsEd25519Backend, KeyError> {
    let config = crate::aws_kms_keysource::AwsKmsConfig {
        region: region.to_string(),
        key_id: key_id.to_string(),
        endpoint: endpoint.map(str::to_string),
    };
    Ok(match credentials {
        AwsCredentialMode::WebIdentity { sts_endpoint } => {
            crate::aws_kms_keysource::AwsKmsEd25519Backend::from_web_identity(
                &config,
                sts_endpoint.clone(),
            )?
        }
        AwsCredentialMode::StaticEnv => {
            crate::aws_kms_keysource::AwsKmsEd25519Backend::from_env(&config)?
        }
    })
}

/// Default build: the AWS KMS backend is not compiled, so this FAILS CLOSED here (mirrors
/// the pkcs11 gate). The flag still PARSES.
#[cfg(not(feature = "aws_kms_keysource"))]
pub(super) fn open(
    _region: &str,
    _key_id: &str,
    _endpoint: Option<&str>,
    _credentials: &crate::config_state::AwsCredentialMode,
    _channel: ChannelKeyMaterial<'_>,
    _material: ChannelMaterial<'_>,
) -> Result<Box<dyn KeySource + Send + Sync>, KeyError> {
    Err(KeyError::NotFound(
        "aws-kms key source requires the aws_kms_keysource feature (build with \
         --features aws_kms_keysource); not available in this build"
            .to_string(),
    ))
}
