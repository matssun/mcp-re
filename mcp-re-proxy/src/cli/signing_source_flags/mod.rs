// SPDX-License-Identifier: Apache-2.0
//! The signing-source flag family, parsed as one — ADR-MCPRE-067 §16.
//!
//! The command line is flat because a command line is flat: an operator reads
//! `--aws-kms-region` and needs the qualifier to know which region is meant. The REQUEST
//! is not, and this is the adapter between them. Flags accumulate into parser-local
//! drafts; [`SigningSourceFlags::finish`] assembles the one selected mechanism's payload
//! and DISCARDS the drafts belonging to the others.
//!
//! **Discarding them is not silence.** A value belonging to an unselected mechanism was
//! previously carried into the request and refused there, by a nine-entry table explaining
//! that `--aws-kms-region` belongs to a different custody source. Those refusals are
//! restated in [`stray_value`], at the one place that can still see both the selection and
//! the stray value — the parser — because after assembly the type makes the combination
//! unstatable (ADR-MCPRE-067 §7). Nothing became silently accepted; what changed is that
//! the configuration boundary no longer has to know these flags exist.
//!
//! [`endpoint_guard`] is here for that same reason and no other: an endpoint override
//! belonging to an unselected mechanism is discarded a few lines later, so it is held to
//! the endpoint-authority rule as the flag is read. Everything else is the configuration
//! boundary's, which a programmatically built request also passes through.
//!
//! The channel key object is deliberately NOT held to the selection here. The two are
//! separate ROLES, so it reaches the request whatever `--key-source` says, and X2a reports
//! a mismatch at the boundary alongside every other violation rather than cutting the parse
//! short at the first one.

mod channel_role;
mod endpoint_guard;
mod mechanism;
mod stray_value;

use endpoint_guard::guarded_endpoint;
use mechanism::{mechanism, Mechanism};

#[cfg(feature = "dev_env_key_source")]
use crate::deployment_request::EnvironmentSigningSourceRequest;
use crate::deployment_request::{
    AwsKmsSigningSourceRequest, ChannelCredentialRequest, FileSigningSourceRequest,
    GcpKmsSigningSourceRequest, Pkcs11SigningSourceRequest, ResponseSigningRequest,
    SigningSourceRequest,
};

/// The signing-source inputs, as they accumulate across the argument list.
pub(super) struct SigningSourceFlags {
    mechanism: Mechanism,
    seed: Option<String>,
    pkcs11: Pkcs11SigningSourceRequest,
    pkcs11_channel_key_label: Option<String>,
    aws: AwsKmsSigningSourceRequest,
    aws_channel_key_id: Option<String>,
    gcp: GcpKmsSigningSourceRequest,
    gcp_channel_key_version: Option<String>,
}

impl SigningSourceFlags {
    /// A file-backed source naming nothing, which is what an operator who set no
    /// signing-source flag has asked for.
    pub(super) fn new() -> Self {
        SigningSourceFlags {
            mechanism: Mechanism::File,
            seed: None,
            pkcs11: Pkcs11SigningSourceRequest::default(),
            pkcs11_channel_key_label: None,
            aws: AwsKmsSigningSourceRequest::default(),
            aws_channel_key_id: None,
            gcp: GcpKmsSigningSourceRequest::default(),
            gcp_channel_key_version: None,
        }
    }

    /// Whether this value-taking flag belongs to the family.
    pub(super) fn owns(flag: &str) -> bool {
        matches!(
            flag,
            "--key-source"
                | "--signing-key-seed"
                | "--pkcs11-module"
                | "--pkcs11-pin-file"
                | "--pkcs11-token-label"
                | "--pkcs11-key-label"
                | "--pkcs11-tls-key-label"
                | "--aws-kms-region"
                | "--aws-kms-key-id"
                | "--aws-kms-endpoint"
                | "--aws-kms-tls-key-id"
                | "--aws-sts-endpoint"
                | "--gcp-kms-key-version"
                | "--gcp-kms-endpoint"
                | "--gcp-kms-tls-key-version"
        )
    }

    /// Read one value-taking flag of the family. [`Self::owns`] decided it is one.
    pub(super) fn take(&mut self, flag: &str, value: &str) -> Result<(), String> {
        let held = || Some(value.to_string());
        match flag {
            "--key-source" => self.mechanism = mechanism(value)?,
            "--signing-key-seed" => self.seed = held(),
            "--pkcs11-module" => self.pkcs11.module = held(),
            // The PIN is read from a FILE, never argv: a process command line is
            // world-readable via `ps` and `/proc/<pid>/cmdline`.
            "--pkcs11-pin-file" => self.pkcs11.pin_file = held(),
            "--pkcs11-token-label" => self.pkcs11.token_label = held(),
            "--pkcs11-key-label" => self.pkcs11.key_label = held(),
            "--pkcs11-tls-key-label" => self.pkcs11_channel_key_label = held(),
            "--aws-kms-region" => self.aws.region = held(),
            "--aws-kms-key-id" => self.aws.key_id = held(),
            "--aws-kms-endpoint" => self.aws.endpoint = Some(guarded_endpoint(flag, value)?),
            "--aws-kms-tls-key-id" => self.aws_channel_key_id = held(),
            "--aws-sts-endpoint" => self.aws.sts_endpoint = Some(guarded_endpoint(flag, value)?),
            "--gcp-kms-key-version" => self.gcp.key_version = held(),
            "--gcp-kms-endpoint" => self.gcp.endpoint = Some(guarded_endpoint(flag, value)?),
            _ => self.gcp_channel_key_version = held(),
        }
        Ok(())
    }

    /// Read one valueless flag of the family, reporting whether it was one.
    pub(super) fn take_switch(&mut self, flag: &str) -> bool {
        match flag {
            "--aws-kms-use-web-identity" => self.aws.use_web_identity = true,
            "--gcp-kms-use-metadata" => self.gcp.use_metadata = true,
            _ => return false,
        }
        true
    }

    /// The two roles, as the request carries them.
    ///
    /// The seed is required only where it is READ. Under a non-exporting mechanism the
    /// response-signing key never leaves the device, and the payload assembled for it has
    /// no seed field at all — so an operator is no longer asked to provision an Ed25519
    /// root seed into every pod in exactly the mode chosen because no key should land in
    /// the pod.
    pub(super) fn finish(
        self,
    ) -> Result<(ResponseSigningRequest, ChannelCredentialRequest), String> {
        self.stray_value_refusal()?;
        let channel = ChannelCredentialRequest {
            delegated: self.channel_key(),
        };
        let source = match self.mechanism {
            Mechanism::File => SigningSourceRequest::File(FileSigningSourceRequest {
                seed_path: self.required_seed()?,
            }),
            #[cfg(feature = "dev_env_key_source")]
            Mechanism::Environment => {
                SigningSourceRequest::Environment(EnvironmentSigningSourceRequest {
                    seed_var: self.required_seed()?,
                })
            }
            Mechanism::Pkcs11 => SigningSourceRequest::Pkcs11(self.pkcs11.clone()),
            Mechanism::AwsKms => SigningSourceRequest::AwsKms(self.aws.clone()),
            Mechanism::GcpKms => SigningSourceRequest::GcpKms(self.gcp.clone()),
        };
        Ok((ResponseSigningRequest { source }, channel))
    }

    /// The seed under a mechanism that reads one.
    fn required_seed(&self) -> Result<String, String> {
        self.seed
            .clone()
            .ok_or_else(|| "missing required --signing-key-seed".to_string())
    }
}
