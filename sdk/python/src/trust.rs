// SPDX-License-Identifier: Apache-2.0
//! The binding's trust-resolution half.
//!
//! Split out under MCPRE-172: both verification entry points build the same pinned
//! root resolver, and it is one half of a `CompositeResponseTrust` rather than a
//! detail of either entry point.

use mcp_re_client_core::ActorIdentity;
use mcp_re_client_core::ResolvedActor;
use mcp_re_client_core::ResolverOutcome;
use mcp_re_client_core::SignerSlot;
use mcp_re_core::VerificationKey;

/// The trusted ROOT ISSUER anchor for the Response slot, as a resolver half of a
/// [`CompositeResponseTrust`]. The credential chains to this issuer; the delegated key
/// itself is authorized by the credential and is never enrolled.
///
/// One pinned issuer, so it has no use for `now` — it takes the argument because
/// MCPRE-172 made trust resolution time-aware for the sets that DO have an overlap
/// window, and one shape serves both.
pub(crate) fn pinned_root_resolver(
    issuer_key_id: &str,
    issuer_role: &str,
    issuer_trust_domain: &str,
    issuer_subject: &str,
    issuer_pub: VerificationKey,
) -> impl Fn(&str, SignerSlot, i64) -> ResolverOutcome + Send + Sync {
    let ikid = issuer_key_id.to_owned();
    let iident = ActorIdentity {
        role: issuer_role.to_owned(),
        trust_domain: issuer_trust_domain.to_owned(),
        subject: issuer_subject.to_owned(),
        keyid: issuer_key_id.to_owned(),
    };
    move |kid: &str, slot: SignerSlot, _now: i64| {
        match slot {
            SignerSlot::Response if kid == ikid => Some(ResolvedActor {
                identity: iident.clone(),
                verification_key: issuer_pub.clone(),
                slot,
            }),
            _ => None,
        }
        .into()
    }
}
