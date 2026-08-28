// SPDX-License-Identifier: Apache-2.0
//! Which mechanism holds a signing key, and what that mechanism needs.
//!
//! ADR-MCPRE-067 §7. One selector determines which subordinate values are meaningful, so
//! the selection and those values are ONE tagged value rather than a selector beside a
//! flat cloud of provider-qualified siblings:
//!
//! ```text
//! semantic role          ResponseSigningRequest / ChannelCredentialRequest
//!         |
//! mechanism selection    SigningSourceRequest / DelegatedChannelKeyRequest
//!         |
//! mechanism payload      AwsKmsSigningSourceRequest, Pkcs11ChannelKeyRequest, ...
//! ```
//!
//! **What that buys is a deleted rule, not a tidier struct.** The previous representation
//! could express `key_source = GcpKms` beside `aws_kms_region = Some(..)`, and a table of
//! nine "belongs to a different custody source" refusals existed to explain why such a
//! request did not mean what it said. Here an AWS selection has nowhere to put a GCP or
//! PKCS#11 value, so the type states the rule and no validator restates it.
//!
//! **What stays representable is deliberate.** Absences INSIDE a payload — an AWS
//! selection with no region, an STS endpoint with no web-identity mode — are meaningful
//! operator input the configuration boundary must refuse with a useful diagnostic, so the
//! payload holds them (ADR-MCPRE-067 §7.2). A request that cannot express an illegal
//! deployment cannot refuse one.

mod aws_kms_source;
mod channel_role;
mod environment_source;
mod file_source;
mod gcp_kms_source;
mod pkcs11_source;
mod response_role;

pub use aws_kms_source::{AwsKmsChannelKeyRequest, AwsKmsSigningSourceRequest};
pub use channel_role::{ChannelCredentialRequest, DelegatedChannelKeyRequest};
pub use environment_source::EnvironmentSigningSourceRequest;
pub use file_source::FileSigningSourceRequest;
pub use gcp_kms_source::{GcpKmsChannelKeyRequest, GcpKmsSigningSourceRequest};
pub use pkcs11_source::{Pkcs11ChannelKeyRequest, Pkcs11SigningSourceRequest};
pub use response_role::ResponseSigningRequest;

/// Which mechanism a deployment asks to hold a signing key, with the material that
/// mechanism needs.
///
/// The variant IS the selection: there is no separate kind field beside it, because a kind
/// and a payload that can disagree is the flat shape this replaces.
///
/// Which of these a BUILD can honour is a different question, answered downstream — a
/// PKCS#11 request is coherent in a build without the `pkcs11_keysource` feature and is
/// refused at key-source construction, which is a statement about the executable rather
/// than about the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningSourceRequest {
    /// A seed file on disk. Private key material is readable by this process.
    File(FileSigningSourceRequest),
    /// A seed in an environment variable — development and CI only.
    Environment(EnvironmentSigningSourceRequest),
    /// A PKCS#11 token: the key is exercised via `C_Sign` and never leaves the device.
    Pkcs11(Pkcs11SigningSourceRequest),
    /// AWS KMS: the key is exercised via `Sign` and never leaves KMS.
    AwsKms(AwsKmsSigningSourceRequest),
    /// GCP Cloud KMS: the key is exercised via `asymmetricSign`.
    GcpKms(GcpKmsSigningSourceRequest),
}

impl Default for SigningSourceRequest {
    /// A file-backed source naming no seed.
    ///
    /// The default is the mechanism whose absent material the boundary reports most
    /// usefully, and it is the CLI's default selection. It is not a legal deployment: the
    /// empty seed path is refused.
    fn default() -> Self {
        Self::File(FileSigningSourceRequest::default())
    }
}
