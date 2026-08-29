// SPDX-License-Identifier: Apache-2.0
//! The channel credential's own identity field.

use crate::transport::IdentityPolicy;

/// Which field of the peer's credential is its identity.
///
/// A mechanism payload: the choice is between X.509 SAN kinds, and it means nothing
/// without a certificate to read them from. The form above it — *the channel credential
/// carries the identity* — survives that certificate being replaced by something else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ChannelCredentialIdentityRequest {
    /// The authoritative identity field. No implicit fallback: a credential that does not
    /// carry this field carries no identity here.
    pub field: IdentityPolicy,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default is the URI SAN, which is the recommended, unambiguous form.
    #[test]
    fn the_default_identity_field_is_the_uri_san() {
        assert_eq!(
            ChannelCredentialIdentityRequest::default().field,
            IdentityPolicy::UriSan
        );
    }
}
