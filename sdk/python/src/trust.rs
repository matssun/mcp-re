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
