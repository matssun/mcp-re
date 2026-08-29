// SPDX-License-Identifier: Apache-2.0
//! The file-seed key source.

use super::ChannelMaterial;
use crate::key_source::{FileKeySource, KeyError, KeySource};

/// Open a source whose signing key is a 32-byte seed on disk.
///
/// Always available: reading a file needs no backend, which is why this arm has no
/// build-gated twin.
pub(super) fn open(
    seed_path: &str,
    material: ChannelMaterial<'_>,
) -> Result<Box<dyn KeySource + Send + Sync>, KeyError> {
    Ok(Box::new(FileKeySource {
        signing_key_seed_path: seed_path.to_string(),
        tls_cert_path: material.cert.to_string(),
        tls_key_path: material.key.to_string(),
        client_ca_path: material.client_ca.to_string(),
    }))
}
