// SPDX-License-Identifier: Apache-2.0
//! The environment-seed key source — development and CI only.

use super::ChannelMaterial;
use crate::key_source::{KeyError, KeySource};

/// Open a source whose signing key is a seed in the process environment.
#[cfg(feature = "dev_env_key_source")]
pub(super) fn open(
    env_var: &str,
    material: ChannelMaterial<'_>,
) -> Result<Box<dyn KeySource + Send + Sync>, KeyError> {
    Ok(Box::new(crate::key_source::EnvKeySource {
        signing_key_seed_var: env_var.to_string(),
        tls_cert_var: material.cert.to_string(),
        tls_key_var: material.key.to_string(),
        client_ca_var: material.client_ca.to_string(),
    }))
}

/// Default build: the environment source is not compiled, so it FAILS CLOSED here. The
/// flag still PARSES, so the message is precise rather than a typo report.
#[cfg(not(feature = "dev_env_key_source"))]
pub(super) fn open(
    _env_var: &str,
    _material: ChannelMaterial<'_>,
) -> Result<Box<dyn KeySource + Send + Sync>, KeyError> {
    Err(KeyError::NotFound(
        "env key source is development-only; rebuild with \
         --features dev_env_key_source (production must use --key-source file)"
            .to_string(),
    ))
}
