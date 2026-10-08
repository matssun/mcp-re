// SPDX-License-Identifier: Apache-2.0
//! The binding's trust-resolution half.
//!
//! Both verification entry points anchor on one pinned root issuer. The anchor is the
//! audited core's `TrustedIssuerSet`, evaluated at the caller's `now`: a root the caller
//! declares retired resolves through its overlap deadline and not after it, by the core's
//! own lifecycle rule rather than one restated here.

use mcp_re_client_core::ActorIdentity;
use mcp_re_client_core::DelegatedResponseTrust;
use mcp_re_client_core::ResolvedActor;
use mcp_re_client_core::ResolverOutcome;
use mcp_re_client_core::SignerSlot;
use mcp_re_client_core::TrustedIssuerSet;
use mcp_re_core::VerificationKey;

/// The root issuer a caller pins, as the values the published API takes.
pub(crate) struct PinnedIssuer {
    pub(crate) key_id: String,
    pub(crate) pubkey_b64url: String,
    pub(crate) role: String,
    pub(crate) trust_domain: String,
    pub(crate) subject: String,
    /// `issuerRetiredUntil`: with it the root is RETIRED and trusted only while
    /// `now <= retired_until`; without it, CURRENT.
    pub(crate) retired_until: Option<f64>,
}

/// The trusted ROOT ISSUER anchor for the Response slot, as the resolver half of a
/// `CompositeResponseTrust`. The credential chains to this issuer, whose role, trust
/// domain and subject must equal the server signer the credential names; the delegated
/// key itself is authorized by the credential and is never enrolled.
///
/// Refuses an identity with an empty field, naming it: the core compares the pinned
/// principal with the credential's by equality, so an empty pin would match an empty
/// claim.
pub(crate) fn root_resolver(
    issuer: PinnedIssuer,
) -> napi::Result<impl Fn(&str, SignerSlot, i64) -> ResolverOutcome + Send + Sync> {
    for (name, value) in [
        ("issuerKeyId", &issuer.key_id),
        ("issuerRole", &issuer.role),
        ("issuerTrustDomain", &issuer.trust_domain),
        ("issuerSubject", &issuer.subject),
    ] {
        if value.trim().is_empty() {
            return Err(napi::Error::from_reason(format!(
                "invalid issuer identity: {name} is empty"
            )));
        }
    }
    let key = VerificationKey::from_b64url(&issuer.pubkey_b64url)
        .map_err(|_| napi::Error::from_reason("invalid issuer public key"))?;
    let retired_until = issuer
        .retired_until
        .map(|t| crate::whole_seconds(t, "issuerRetiredUntil"))
        .transpose()?;
    let root = ResolvedActor {
        identity: ActorIdentity {
            role: issuer.role,
            trust_domain: issuer.trust_domain,
            subject: issuer.subject,
            keyid: issuer.key_id,
        },
        verification_key: key,
        slot: SignerSlot::Response,
    };
    let anchor = match retired_until {
        Some(deadline) => TrustedIssuerSet::new().with_retired(root, deadline),
        None => TrustedIssuerSet::new().with_current(root),
    };
    Ok(move |kid: &str, slot: SignerSlot, now: i64| anchor.resolve_issuer(kid, slot, now))
}

#[cfg(test)]
mod tests {
    use super::root_resolver;
    use super::PinnedIssuer;
    use mcp_re_client_core::ResolverOutcome;
    use mcp_re_client_core::SignerSlot;
    use mcp_re_core::SigningKey;

    const NOW: i64 = 1_000;

    type Setter = fn(&mut PinnedIssuer, String);

    fn issuer(retired_until: Option<f64>) -> PinnedIssuer {
        let key = SigningKey::from_seed_bytes(&[7u8; 32]);
        PinnedIssuer {
            key_id: "root-1".to_owned(),
            pubkey_b64url: key.public_key().to_b64url(),
            role: "server".to_owned(),
            trust_domain: "example.com".to_owned(),
            subject: "did:example:server-1".to_owned(),
            retired_until,
        }
    }

    fn resolves(resolve: &impl Fn(&str, SignerSlot, i64) -> ResolverOutcome, now: i64) -> bool {
        matches!(
            resolve("root-1", SignerSlot::Response, now),
            ResolverOutcome::Resolved(_)
        )
    }

    #[test]
    fn an_empty_issuer_field_is_refused_by_name() {
        let named: [(&str, Setter); 4] = [
            ("issuerKeyId", |i, v| i.key_id = v),
            ("issuerRole", |i, v| i.role = v),
            ("issuerTrustDomain", |i, v| i.trust_domain = v),
            ("issuerSubject", |i, v| i.subject = v),
        ];
        for (name, set) in named {
            for blank in ["", "  "] {
                let mut pinned = issuer(None);
                set(&mut pinned, blank.to_owned());
                let Err(refusal) = root_resolver(pinned) else {
                    panic!("{name} = {blank:?} must be refused");
                };
                assert_eq!(
                    refusal.reason,
                    format!("invalid issuer identity: {name} is empty")
                );
            }
        }
    }

    #[test]
    fn a_retired_root_resolves_through_its_deadline_and_not_after() {
        let retired = root_resolver(issuer(Some(NOW as f64))).expect("a retired root builds");
        assert!(resolves(&retired, NOW));
        assert!(!resolves(&retired, NOW + 1));
        let current = root_resolver(issuer(None)).expect("a current root builds");
        assert!(resolves(&current, NOW + 1_000_000));
    }
}
