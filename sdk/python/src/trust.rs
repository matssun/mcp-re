// SPDX-License-Identifier: Apache-2.0
//! The binding's trust-resolution half.
//!
//! Both verification entry points anchor on one pinned root issuer. The anchor is the
//! audited core's `TrustedIssuerSet`, evaluated at the caller's `now`: a root the caller
//! declares retired resolves through its overlap deadline and not after it, by the core's
//! own lifecycle rule rather than one restated here.

use mcp_re_client_core::ActorIdentity;
use mcp_re_client_core::ResolvedActor;
use mcp_re_client_core::SignerSlot;
use mcp_re_client_core::TrustedIssuerSet;
use mcp_re_core::VerificationKey;

/// The root issuer a caller pins, as the strings the published API takes.
pub(crate) struct PinnedIssuer<'a> {
    pub(crate) key_id: &'a str,
    pub(crate) role: &'a str,
    pub(crate) trust_domain: &'a str,
    pub(crate) subject: &'a str,
}

/// The trusted ROOT ISSUER anchor for the Response slot. The credential chains to this
/// issuer, whose role, trust domain and subject must equal the server signer the
/// credential names; the delegated key itself is authorized by the credential and is
/// never enrolled.
///
/// Refuses an identity with an empty field, naming it: the core compares the pinned
/// principal with the credential's by equality, so an empty pin would match an empty
/// claim. With `retired_until`, the root is RETIRED and trusted only while
/// `now <= retired_until`; without it, it is CURRENT.
pub(crate) fn root_anchor(
    issuer: &PinnedIssuer<'_>,
    key: VerificationKey,
    retired_until: Option<i64>,
) -> Result<TrustedIssuerSet, String> {
    for (name, value) in [
        ("issuer_key_id", issuer.key_id),
        ("issuer_role", issuer.role),
        ("issuer_trust_domain", issuer.trust_domain),
        ("issuer_subject", issuer.subject),
    ] {
        if value.trim().is_empty() {
            return Err(format!("invalid issuer identity: {name} is empty"));
        }
    }
    let root = ResolvedActor {
        identity: ActorIdentity {
            role: issuer.role.to_owned(),
            trust_domain: issuer.trust_domain.to_owned(),
            subject: issuer.subject.to_owned(),
            keyid: issuer.key_id.to_owned(),
        },
        verification_key: key,
        slot: SignerSlot::Response,
    };
    Ok(match retired_until {
        Some(deadline) => TrustedIssuerSet::new().with_retired(root, deadline),
        None => TrustedIssuerSet::new().with_current(root),
    })
}

#[cfg(test)]
mod tests {
    use super::root_anchor;
    use super::PinnedIssuer;
    use mcp_re_client_core::DelegatedResponseTrust;
    use mcp_re_client_core::ResolverOutcome;
    use mcp_re_client_core::SignerSlot;
    use mcp_re_client_core::TrustedIssuerSet;
    use mcp_re_core::SigningKey;

    const NOW: i64 = 1_000;

    fn anchor(
        issuer: &PinnedIssuer<'_>,
        retired_until: Option<i64>,
    ) -> Result<TrustedIssuerSet, String> {
        let key = SigningKey::from_seed_bytes(&[7u8; 32]).public_key();
        root_anchor(issuer, key, retired_until)
    }

    fn pinned<'a>(
        key_id: &'a str,
        role: &'a str,
        domain: &'a str,
        subject: &'a str,
    ) -> PinnedIssuer<'a> {
        PinnedIssuer {
            key_id,
            role,
            trust_domain: domain,
            subject,
        }
    }

    fn resolves(set: &TrustedIssuerSet, now: i64) -> bool {
        matches!(
            set.resolve_issuer("root-1", SignerSlot::Response, now),
            ResolverOutcome::Resolved(_)
        )
    }

    #[test]
    fn an_empty_issuer_field_is_refused_by_name() {
        let named = [
            ("issuer_key_id", 0),
            ("issuer_role", 1),
            ("issuer_trust_domain", 2),
            ("issuer_subject", 3),
        ];
        for (name, index) in named {
            for blank in ["", "  "] {
                let mut fields = ["root-1", "server", "example.com", "did:example:server-1"];
                fields[index] = blank;
                let issuer = pinned(fields[0], fields[1], fields[2], fields[3]);
                let Err(refusal) = anchor(&issuer, None) else {
                    panic!("{name} = {blank:?} must be refused");
                };
                assert_eq!(refusal, format!("invalid issuer identity: {name} is empty"));
            }
        }
    }

    #[test]
    fn a_retired_root_resolves_through_its_deadline_and_not_after() {
        let issuer = pinned("root-1", "server", "example.com", "did:example:server-1");
        let retired = anchor(&issuer, Some(NOW)).expect("a retired root builds");
        assert!(resolves(&retired, NOW));
        assert!(!resolves(&retired, NOW + 1));
        let current = anchor(&issuer, None).expect("a current root builds");
        assert!(resolves(&current, NOW + 1_000_000));
    }
}
