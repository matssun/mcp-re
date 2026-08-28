// SPDX-License-Identifier: Apache-2.0
//! The mechanism payloads for keys held in AWS KMS.

/// Which AWS KMS key signs responses, where it lives, and how this deployment reaches KMS.
///
/// `region` rather than `aws_kms_region`: the parent variant already supplies the
/// qualifier (ADR-MCPRE-067 §16.2).
///
/// The credential inputs stay as the two an operator states, rather than as the sum
/// [`AwsCredentialMode`](crate::config_state::AwsCredentialMode) they classify into. That
/// sum is the VALIDATED fact and belongs to the configuration boundary; the request must
/// be able to hold `sts_endpoint` without `use_web_identity` in order to refuse it as an
/// endpoint nothing would contact.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AwsKmsSigningSourceRequest {
    /// The region the key lives in.
    pub region: Option<String>,
    /// Key id, ARN or alias of the Ed25519 response-signing key.
    pub key_id: Option<String>,
    /// A non-default KMS endpoint (emulator/test). Held to the endpoint-authority guard
    /// before anything is sent to it: an overridden endpoint substitutes the root verify
    /// key that verify-before-return is measured against.
    pub endpoint: Option<String>,
    /// Take credentials from IRSA — exchange the projected service-account token at
    /// `AWS_WEB_IDENTITY_TOKEN_FILE` through STS — instead of the static
    /// `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` pair. The flag that lets an EKS
    /// deployment hold no long-lived IAM key material at all. Never a fallback: a
    /// deployment that asked for web identity and cannot mint through it must fail rather
    /// than quietly sign with whatever keys are in the process environment.
    pub use_web_identity: bool,
    /// A non-default STS endpoint for that exchange, defaulting to the regional
    /// `https://sts.<region>.amazonaws.com`. Held to the same endpoint-authority guard.
    pub sts_endpoint: Option<String>,
}

/// The second, distinct KMS key that custodies the channel-establishment key.
///
/// Independent of the response-signing key id and a separate security principal an
/// operator should scope with its own authorization policy. It reuses this deployment's
/// region, endpoint and credential mode — the channel key takes the SAME custody path as
/// the response-signing key, so a deployment cannot end up with one KMS principal reached
/// through IRSA and the other through static keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsKmsChannelKeyRequest {
    /// Key id, ARN or alias of the Ed25519 channel key. Its presence is what selects
    /// non-exporting channel custody.
    pub key_id: String,
}
