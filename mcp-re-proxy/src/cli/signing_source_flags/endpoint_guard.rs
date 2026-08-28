// SPDX-License-Identifier: Apache-2.0
//! The endpoint-authority rule, applied to an override as the flag carrying it is read.

/// Hold an operator-supplied KMS/STS endpoint override to the endpoint-authority rule.
///
/// Applied here, as the flag is read, rather than only to the selected mechanism's
/// payload: an overridden endpoint substitutes the root verify key that verify-before-
/// return is measured against, and on GCP every request to it also carries a live
/// workload-identity bearer token. Nothing about that depends on which `--key-source` the
/// rest of the command line happens to name.
///
/// The rule itself lives in [`crate::config_state::kms_endpoint`], shared with the
/// configuration boundary, so the two cannot drift into disagreeing about it.
pub(super) fn guarded_endpoint(flag: &str, value: &str) -> Result<String, String> {
    crate::config_state::kms_endpoint::validated_kms_endpoint(flag, value)
}
