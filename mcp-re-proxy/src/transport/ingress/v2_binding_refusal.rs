// SPDX-License-Identifier: Apache-2.0
//! Why a Mode-C verifier could not be built from its configuration.

/// A configuration [`super::LbAssertionV2Binding::new`] refuses to build a verifier
/// from. Each variant is a trust set that would admit more, or less, than it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LbAssertionV2BindingRefusal {
    /// No attestor key: every assertion would fail closed with nothing to say why.
    NoAttestorKey,
    /// Two keys under one id: which one verifies would depend on insertion order.
    DuplicateKeyId(String),
    /// No trusted ingress identity: every assertion would fail closed.
    NoIngressIdentity,
    /// A trusted ingress identity that is blank matches an assertion that names none.
    BlankIngressIdentity,
    /// The audience is blank, or padded so that the verbatim comparison never matches
    /// the route an attestor mints for.
    UnusableAudience,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_duplicate_key_refusal_names_the_key_id() {
        let refusal = LbAssertionV2BindingRefusal::DuplicateKeyId("attestor-1".to_string());
        assert_eq!(
            refusal,
            LbAssertionV2BindingRefusal::DuplicateKeyId("attestor-1".to_string())
        );
        assert_ne!(refusal, LbAssertionV2BindingRefusal::NoAttestorKey);
    }
}
