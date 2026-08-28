// SPDX-License-Identifier: Apache-2.0
//! The mechanism payload for a signing key read from the process environment.

/// Which environment variable a development signing key is read from.
///
/// A NAME, never a path: the distinction is why this is its own mechanism rather than a
/// mode of [`FileSigningSourceRequest`](super::FileSigningSourceRequest). A consumer that
/// stat'ed one as a path got a check that passed for the wrong reason.
///
/// Development and CI only, and honoured only in a `dev_env_key_source` build.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EnvironmentSigningSourceRequest {
    /// Name of the variable holding the Base64URL-no-pad Ed25519 seed. Empty means the
    /// operator named none, which the configuration boundary refuses.
    pub seed_var: String,
}
