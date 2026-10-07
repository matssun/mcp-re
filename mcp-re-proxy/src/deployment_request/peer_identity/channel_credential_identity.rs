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
    /// The authoritative identity field the operator named, or `None` where they named
    /// none. The default field is the classifying owner's to apply, so an omitted field and
    /// an explicit `uri_san` stay two requests. No implicit fallback at serving: a
    /// credential that does not carry the field carries no identity here.
    pub field: Option<IdentityPolicy>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A request that names no field records that it named none, rather than the field a
    /// default would have chosen for it.
    #[test]
    fn a_default_request_names_no_field() {
        assert_eq!(ChannelCredentialIdentityRequest::default().field, None);
        assert_ne!(
            ChannelCredentialIdentityRequest::default(),
            ChannelCredentialIdentityRequest {
                field: Some(IdentityPolicy::UriSan)
            }
        );
    }
}
