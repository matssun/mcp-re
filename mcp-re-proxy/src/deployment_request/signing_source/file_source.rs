// SPDX-License-Identifier: Apache-2.0
//! The mechanism payload for a signing key read from a file on disk.

/// Where a file-backed signing key is read from.
///
/// The parent [`SigningSourceRequest`](super::SigningSourceRequest) variant already says
/// the mechanism is a file, so the field is `seed_path` and not `file_seed_path`
/// (ADR-MCPRE-067 §16.2).
///
/// The seed is 32 bytes, Base64URL-no-pad. Private key material under this mechanism is
/// readable by this process, which is what
/// [`PrivateKeyExposure`](crate::config_state::PrivateKeyExposure) states about it — the
/// consumer of that fact never learns it was a file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileSigningSourceRequest {
    /// Path to the Base64URL-no-pad Ed25519 seed. Empty means the operator named none,
    /// which the configuration boundary refuses with a diagnostic; the request must be
    /// able to hold it in order to refuse it.
    pub seed_path: String,
}
