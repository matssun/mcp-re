// SPDX-License-Identifier: Apache-2.0
//! The file-seed key source.

use super::{exported_tls_key, ChannelMaterial};
use crate::capability_materialization::key_file_custody::AdmittedKeyFiles;
use crate::key_source::{FileKeySource, KeyError, KeySource};

/// Open a source whose signing key is the admitted 32-byte seed file.
///
/// Always available: reading a file needs no backend, which is why this arm has no
/// build-gated twin.
pub(super) fn open(
    admitted: &mut AdmittedKeyFiles<'_>,
    seed_path: &str,
    material: ChannelMaterial<'_>,
) -> Result<Box<dyn KeySource + Send + Sync>, KeyError> {
    let seed = admitted.take(seed_path)?;
    let tls_key = exported_tls_key(admitted, material)?;
    Ok(Box::new(FileKeySource::from_checked(
        seed,
        material.cert,
        tls_key,
        material.client_ca,
    )?))
}
