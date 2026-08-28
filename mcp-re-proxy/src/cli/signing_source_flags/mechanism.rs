// SPDX-License-Identifier: Apache-2.0
//! Which mechanism `--key-source` named, and the spelling that names it.

/// Which mechanism `--key-source` named.
///
/// The parser's own selector, not the request's: the request has no separate kind field
/// beside its payload, and reintroducing one there is exactly what ADR-MCPRE-067 forbids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Mechanism {
    File,
    /// Development and CI only. The variant exists exactly where the `--key-source env`
    /// spelling does: a production build has no way to name it, so it has no way to be
    /// selected either.
    #[cfg(feature = "dev_env_key_source")]
    Environment,
    Pkcs11,
    AwsKms,
    GcpKms,
}

impl Mechanism {
    /// The `--key-source` spelling that selects this mechanism.
    pub(super) fn spelling(self) -> &'static str {
        match self {
            Mechanism::File => "file",
            #[cfg(feature = "dev_env_key_source")]
            Mechanism::Environment => "env",
            Mechanism::Pkcs11 => "pkcs11",
            Mechanism::AwsKms => "aws-kms",
            Mechanism::GcpKms => "gcp-kms",
        }
    }
}

/// Which mechanism a `--key-source` spelling names.
///
/// Env key material is a development-only downgrade — it is visible to the process tree —
/// and it EXISTS ONLY in a build with the `dev_env_key_source` feature. A production build
/// has no `env` spelling at all, so there is no runtime knob to enable it.
pub(super) fn mechanism(value: &str) -> Result<Mechanism, String> {
    match value {
        "file" => Ok(Mechanism::File),
        #[cfg(feature = "dev_env_key_source")]
        "env" => Ok(Mechanism::Environment),
        "pkcs11" => Ok(Mechanism::Pkcs11),
        "aws-kms" => Ok(Mechanism::AwsKms),
        "gcp-kms" => Ok(Mechanism::GcpKms),
        other => Err(format!(
            "unknown --key-source '{other}' (file|pkcs11|aws-kms|gcp-kms)"
        )),
    }
}
