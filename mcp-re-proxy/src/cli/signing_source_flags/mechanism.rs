// SPDX-License-Identifier: Apache-2.0
//! Which mechanism `--key-source` named, and the spelling that names it.

/// Which mechanism `--key-source` named.
///
/// The parser's own selector, not the request's: the request has no separate kind field
/// beside its payload, and reintroducing one there is exactly what ADR-MCPRE-067 forbids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Mechanism {
    File,
    Pkcs11,
    AwsKms,
    GcpKms,
}

impl Mechanism {
    /// The `--key-source` spelling that selects this mechanism.
    pub(super) fn spelling(self) -> &'static str {
        match self {
            Mechanism::File => "file",
            Mechanism::Pkcs11 => "pkcs11",
            Mechanism::AwsKms => "aws-kms",
            Mechanism::GcpKms => "gcp-kms",
        }
    }
}

/// Which mechanism a `--key-source` spelling names.
///
/// Every mechanism reads secret key material from a file or keeps it on a device; none
/// reads it from the process environment, so `env` is an unknown spelling like any other.
pub(super) fn mechanism(value: &str) -> Result<Mechanism, String> {
    match value {
        "file" => Ok(Mechanism::File),
        "pkcs11" => Ok(Mechanism::Pkcs11),
        "aws-kms" => Ok(Mechanism::AwsKms),
        "gcp-kms" => Ok(Mechanism::GcpKms),
        other => Err(format!(
            "unknown --key-source '{other}' (file|pkcs11|aws-kms|gcp-kms)"
        )),
    }
}
