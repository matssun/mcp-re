// SPDX-License-Identifier: Apache-2.0
//! The attested-ingress form (ADR-MCPS-023 §C, Mode C).

/// The attestor's material, and the channel guarantee the form rests on.
///
/// Mode C is *attested delegation*, not end-to-end mTLS: the attestor witnesses the
/// client's proof-of-possession and stays in the trusted computing base. What makes that
/// safe is the pinned attestor→node hop (§C2), and the operator has to say so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedIngressRequest {
    /// What KIND of name the assertion carries. Not a certificate field to read — this
    /// form reads no certificate — but the provenance stamped on the identity the
    /// assertion yields, which is why it lives here and not beside the form.
    pub asserted_identity_kind: crate::transport::IdentityPolicy,
    /// `(key_id, base64url-ed25519-pub)` of the attestors this node verifies. An empty set
    /// verifies nothing, which the boundary refuses.
    pub attestor_keys: Vec<(String, String)>,
    /// The ingress identities whose assertions this node trusts. An empty set rejects every
    /// assertion and an empty-string identity matches an assertion that names none; the
    /// boundary refuses both.
    pub identities: Vec<String>,
    /// The audience an assertion must name — this node's own route. Empty binds an
    /// assertion to every node that also named none, which the boundary refuses.
    pub audience: String,
    /// The operator's acknowledgement that the attestor→node hop is pinned.
    pub pinned_channel: PinnedChannelAcknowledgement,
}

/// The operator's acknowledgement that the attestor→node hop is a pinned, mutually
/// authenticated channel (ADR-MCPS-023 §C2).
///
/// **A required member of [`AttestedIngressRequest`], and that is the point.** The
/// guarantee is load-bearing — Mode C's whole safety argument rests on it — and it used to
/// be a `bool` beside the selector, with a boundary clause refusing attested ingress when
/// the operator had not set it. Making it a value that must be *named* moves the
/// acknowledgement into the act of selecting the form: there is no attested-ingress request
/// without one, in code or on a command line, so the clause has nothing left to refuse.
///
/// It carries no data deliberately. Nothing here verifies the channel is pinned — nothing
/// could — so what this type holds is the statement, not evidence for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinnedChannelAcknowledgement {
    /// Private, so the only way to obtain one is [`Self::acknowledged`].
    stated: (),
}

impl PinnedChannelAcknowledgement {
    /// The operator states that the attestor→node hop is a pinned mTLS channel.
    ///
    /// Named rather than derived: an acknowledgement produced by `Default` would be an
    /// acknowledgement nobody made.
    pub fn acknowledged() -> Self {
        PinnedChannelAcknowledgement { stated: () }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether `T` implements `Default`, read at run time so the assertion below is not a
    /// constant: an inherent method on the probe wins method resolution exactly when
    /// `T: Default`, and the trait fallback answers `false` otherwise.
    struct DefaultProbe<T>(std::marker::PhantomData<T>);

    trait NoDefault {
        fn implements_default(&self) -> bool {
            false
        }
    }

    impl<T> NoDefault for DefaultProbe<T> {}

    // The inherent method deliberately shadows the trait method of the same name: that
    // shadowing is how the probe tells `T: Default` from its absence at method resolution.
    #[allow(clippy::same_name_method)]
    impl<T: Default> DefaultProbe<T> {
        fn implements_default(&self) -> bool {
            true
        }
    }

    /// The acknowledgement has to be written: neither it nor the attested form has a
    /// `Default`, so no request comes into existence with an acknowledgement nobody wrote.
    /// The positive control proves the probe can answer `true`.
    #[test]
    fn an_attested_form_cannot_exist_without_the_acknowledgement() {
        let probe = |_: std::marker::PhantomData<String>| {
            DefaultProbe::<String>(std::marker::PhantomData).implements_default()
        };
        assert!(
            probe(std::marker::PhantomData),
            "the probe can see a Default"
        );
        assert!(
            !DefaultProbe::<PinnedChannelAcknowledgement>(std::marker::PhantomData)
                .implements_default(),
            "the acknowledgement must not be defaultable"
        );
        assert!(
            !DefaultProbe::<AttestedIngressRequest>(std::marker::PhantomData).implements_default(),
            "the attested form must not be defaultable"
        );
    }
}
