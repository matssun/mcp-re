// SPDX-License-Identifier: Apache-2.0
//! One fact: an operator-supplied KMS/STS endpoint override is held to the
//! endpoint-authority rule wherever it appears.
//!
//! Three callers share it — the argument parser as the flag is read, the configuration
//! boundary for a request built in code, and the key-source constructors — so the rule
//! lives in one place and they cannot drift into disagreeing about it. The decision itself
//! is [`crate::kms_endpoint_policy::kms_endpoint_authority`]; this is only how a
//! [`DeploymentRequest`] answers it, and how the offending flag is named in the refusal.
//!
//! Why it is worth an owner rather than a line inside the custody machine: an overridden
//! endpoint substitutes the root verify key that verify-before-return is measured against,
//! and on GCP every request to one also carries a live workload-identity bearer token. The
//! payload fields are public, so a config built in code must not be able to name a
//! plaintext or attacker-chosen authority for them.

use crate::deployment_request::{DeploymentRequest, SigningSourceRequest};

/// The endpoint override a state is allowed to carry.
///
/// `None` both when no override was named and when the named one failed the
/// endpoint-authority guard, so no built state ever holds an authority
/// [`kms_endpoint_refusals`] refused. A refused override is still reported there; dropping
/// it here only keeps the state's own field honest about what it contains.
pub(crate) fn guarded_endpoint(flag: &str, value: Option<&str>) -> Option<String> {
    validated_kms_endpoint(flag, value?).ok()
}

/// The KMS/STS endpoint overrides a [`DeploymentRequest`] carries, held to the rule wherever
/// the config came from.
///
/// [`validated_kms_endpoint`] is the decision; this is only how a `DeploymentRequest`
/// answers it, so the two call sites cannot drift into disagreeing about the rule. The
/// fields are public, and they carry the ROOT-KEY trust bootstrap — on GCP every request to
/// them also carries a live workload-identity bearer token — so a config built in code must
/// not be able to name a plaintext or attacker-chosen authority for them.
///
/// Only the selected mechanism's endpoints are examined, and that is not a narrowing: an
/// unselected mechanism has no endpoint field to carry one.
pub(crate) fn kms_endpoint_refusals(config: &DeploymentRequest) -> Vec<String> {
    let overrides: Vec<(&str, Option<&str>)> = match &config.response_signing.source {
        SigningSourceRequest::AwsKms(kms) => vec![
            ("--aws-kms-endpoint", kms.endpoint.as_deref()),
            ("--aws-sts-endpoint", kms.sts_endpoint.as_deref()),
        ],
        SigningSourceRequest::GcpKms(kms) => vec![("--gcp-kms-endpoint", kms.endpoint.as_deref())],
        SigningSourceRequest::File(_)
        | SigningSourceRequest::Environment(_)
        | SigningSourceRequest::Pkcs11(_) => Vec::new(),
    };
    overrides
        .into_iter()
        .filter_map(|(flag, value)| validated_kms_endpoint(flag, value?).err())
        .collect()
}

/// Validate an operator-supplied KMS endpoint override before anything is sent to it.
///
/// The decision itself is [`crate::kms_endpoint_policy::kms_endpoint_authority`]; this only prefixes the offending
/// flag onto its refusal, so the command line, the validation boundary
/// ([`kms_endpoint_refusals`]) and the three key-source constructors cannot drift into
/// disagreeing about the rule.
pub(crate) fn validated_kms_endpoint(flag: &str, value: &str) -> Result<String, String> {
    crate::kms_endpoint_policy::kms_endpoint_authority(value)
        .map(|_| value.to_string())
        .map_err(|why| format!("{flag} {why}"))
}
