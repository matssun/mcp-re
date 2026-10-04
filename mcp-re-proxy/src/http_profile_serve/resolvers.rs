// SPDX-License-Identifier: Apache-2.0
//! The two TRUST SEAMS a deployment supplies, and why they are two.
//!
//! Both answer "is this keyid one we trust?", and they are deliberately not one seam,
//! because admitting a workload and signing a message are different authorities.
//!
//! The two seams have disjoint signatures, `(&str, SignerSlot) -> ResolverOutcome` and
//! `(&str) -> Option<VerificationKey>`, so one resolver cannot be installed in both. Which
//! key material backs each is the composition root's decision: the actor seam answers from
//! the trust store and the response anchor (`app::build_actor_resolver`), the admission
//! seam from the configured admission authority
//! (`serving_capabilities::admission_currency`). That is why the two live beside each
//! other rather than beside the stage that calls each.

use std::sync::Arc;

use mcp_re_core::VerificationKey;
use mcp_re_http_profile::ResolverOutcome;
use mcp_re_http_profile::SignerSlot;

/// The signing trust seam: resolve a presented keyid FOR a signing slot to a structured
/// actor (identity + verification key). Returns a [`ResolverOutcome`] so a store OUTAGE
/// (`Unavailable`) is distinguishable from an UNKNOWN KEYID (`NotTrusted`) (C079): both
/// fail closed, but only one of them is a statement about the caller's key.
/// `Send + Sync` so one `HttpProfileProxy` serves every core.
pub type ActorResolver = Box<dyn Fn(&str, SignerSlot) -> ResolverOutcome + Send + Sync>;

/// Resolves an admission assertion's `issuer_kid` to the admission authority's root
/// key. `None` means the issuer is not one this deployment trusts to admit anything —
/// a kid never introduces trust, so an assertion naming an unresolvable issuer is
/// refused exactly as an unknown request keyid is.
///
/// Two-valued, unlike [`ActorResolver`]: its one producer (`serving_capabilities::admission_currency`)
/// compares the presented kid against the authority key configured at startup, in memory,
/// so it has no outage to report. The same resolver verifies both the admission assertion
/// and the authoritative admission record.
///
/// Separate from [`ActorResolver`] because admitting a workload and signing a message
/// are different authorities: a key trusted for one must not be usable for the other
/// by sharing a seam.
pub type AdmissionAuthorityResolver = Arc<dyn Fn(&str) -> Option<VerificationKey> + Send + Sync>;
